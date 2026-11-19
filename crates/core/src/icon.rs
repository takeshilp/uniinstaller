//! Program icons for the GUI: the registered icon (or the uninstaller exe) read as data and encoded as a small PNG. Nothing is run.
use crate::command::parse_uninstall;
use crate::env::Env;
use crate::inventory::icon_path;
use crate::model::InstalledApp;
use crate::paths::{is_inside, is_local_abs};
use std::os::windows::ffi::OsStrExt;
use std::path::{Path, PathBuf};
use windows::Win32::Foundation::S_OK;
use windows::Win32::Graphics::Gdi::{BI_RGB, BITMAP, BITMAPINFO, BITMAPINFOHEADER, CreateCompatibleDC, DIB_RGB_COLORS, DeleteDC, DeleteObject, GetDIBits, GetObjectW, HBITMAP, HDC};
use windows::Win32::UI::Shell::SHDefExtractIconW;
use windows::Win32::UI::WindowsAndMessaging::{DestroyIcon, GetIconInfo, HICON, ICONINFO};
use windows::core::PCWSTR;

/// Edge of the extracted icon in pixels: the list shows it at 32 px and the card at 48 px, so HiDPI screens stay sharp.
const SIZE: u32 = 64;

/// The file and icon index to show for a program: the DisplayIcon file (`path[,index]`, a negative index is a resource id) when it is
/// a local file, else the uninstaller when it is an `.exe` outside the Windows folder (never msiexec, rundll32 or another system binary).
// shortcut: MSI entries without DisplayIcon keep the letter; Apps & Features also reads `Installer\Products\<packed code>\ProductIcon`
// (5 of the 16 such visible entries on the owner's machine, 2026-11-19), read it if users miss those icons.
pub fn source(app: &InstalledApp, env: &Env) -> Option<(PathBuf, i32)> {
    // Local files only: a UNC DisplayIcon would make the program list connect to a network share.
    if let Some(p) = icon_path(app).filter(|p| is_local_abs(p) && p.is_file()) {
        return Some((p, index(app.display_icon.as_deref()?)));
    }
    let l = parse_uninstall(app.uninstall_string.as_deref()?, &env.folders.system_dir, app.product_code.as_deref()).ok()?;
    let exe = l.exe.extension().is_some_and(|x| x.eq_ignore_ascii_case("exe"));
    (exe && l.msi_product.is_none() && !is_inside(&l.exe, &env.folders.windows_dir)).then_some((l.exe, 0))
}

/// The number after the last comma of a DisplayIcon value, 0 when there is none.
fn index(display_icon: &str) -> i32 {
    display_icon.rsplit_once(',').and_then(|(_, i)| i.trim().parse().ok()).unwrap_or(0)
}

/// The icon at `index` of an `.ico`, `.exe` or `.dll` as a 64 px RGBA PNG; None when there is no usable icon.
/// The file is loaded as data by SHDefExtractIconW, never run; every GDI handle is freed here.
pub fn extract(path: &Path, index: i32) -> Option<Vec<u8>> {
    let w: Vec<u16> = path.as_os_str().encode_wide().chain(Some(0)).collect();
    let mut icon = HICON::default();
    // SAFETY: `w` is NUL-terminated; on S_OK `icon` is a new icon owned here and destroyed below.
    let hr = unsafe { SHDefExtractIconW(PCWSTR(w.as_ptr()), index, 0, Some(&raw mut icon), None, SIZE) };
    if hr != S_OK || icon.is_invalid() {
        return None;
    }
    let px = rgba(icon);
    // SAFETY: `icon` came from SHDefExtractIconW above and is not used afterwards.
    let _ = unsafe { DestroyIcon(icon) };
    let (side, px) = px?;
    let mut out = Vec::new();
    let mut e = png::Encoder::new(&mut out, side, side);
    e.set_color(png::ColorType::Rgba);
    e.set_depth(png::BitDepth::Eight);
    let mut wr = e.write_header().ok()?;
    wr.write_image_data(&px).ok()?;
    wr.finish().ok()?;
    Some(out)
}

/// The icon's pixels as straight RGBA, top row first. Icons without any alpha take it from the AND mask (black = opaque).
// shortcut: monochrome icons (no color bitmap) give None and keep the letter; add a mask-only conversion if one shows up.
fn rgba(icon: HICON) -> Option<(u32, Vec<u8>)> {
    let mut ii = ICONINFO::default();
    // SAFETY: GetIconInfo hands over copies of the icon's bitmaps; both and the memory DC are deleted before leaving the block.
    let (color, mask) = unsafe {
        GetIconInfo(icon, &mut ii).ok()?;
        let dc = CreateCompatibleDC(None);
        let r = (bits(dc, ii.hbmColor), bits(dc, ii.hbmMask));
        let _ = DeleteDC(dc);
        let _ = DeleteObject(ii.hbmColor.into());
        let _ = DeleteObject(ii.hbmMask.into());
        r
    };
    let (side, mut px) = color?;
    if px.as_chunks::<4>().0.iter().all(|p| p[3] == 0) {
        let (_, m) = mask.filter(|(s, _)| *s == side)?;
        for (p, m) in px.as_chunks_mut::<4>().0.iter_mut().zip(m.as_chunks::<4>().0) {
            p[3] = if m[0] == 0 { 255 } else { 0 };
        }
    }
    for p in px.as_chunks_mut::<4>().0 {
        p.swap(0, 2); // BGRA to RGBA
    }
    Some((side, px))
}

/// A square bitmap as 32-bit top-down BGRA; None for a null, non-square (monochrome icon mask) or oversized one.
fn bits(dc: HDC, bm: HBITMAP) -> Option<(u32, Vec<u8>)> {
    let mut b = BITMAP::default();
    // SAFETY: `b` is a BITMAP and its size is passed; a null handle makes the call fail.
    if unsafe { GetObjectW(bm.into(), size_of::<BITMAP>() as i32, Some((&raw mut b).cast())) } == 0 {
        return None;
    }
    let side = b.bmWidth;
    if side <= 0 || side != b.bmHeight || side > 256 {
        return None;
    }
    let mut bi = BITMAPINFO {
        bmiHeader: BITMAPINFOHEADER { biSize: size_of::<BITMAPINFOHEADER>() as u32, biWidth: side, biHeight: -side, biPlanes: 1, biBitCount: 32, biCompression: BI_RGB.0, ..Default::default() },
        ..Default::default()
    };
    let mut px = vec![0u8; (side * side * 4) as usize];
    // SAFETY: `px` holds side * side 32-bit pixels as `bi` describes; 32-bpp BI_RGB writes no color table.
    let rows = unsafe { GetDIBits(dc, bm, 0, side as u32, Some(px.as_mut_ptr().cast()), &mut bi, DIB_RGB_COLORS) };
    (rows == side).then_some((side as u32, px))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::registry;

    fn app(icon: Option<String>, un: Option<String>) -> InstalledApp {
        InstalledApp {
            id: "x".into(), key_name: "x".into(), sources: vec![], display_name: "n".into(), display_version: None, publisher: None,
            install_location: None, display_icon: icon, uninstall_string: un, quiet_uninstall_string: None,
            modify_path: None, install_date: None, estimated_size_kb: None, windows_installer: false, product_code: None, per_user: true, hidden: None,
        }
    }

    fn decode(bytes: &[u8]) -> Vec<u8> {
        assert!(bytes.starts_with(b"\x89PNG\r\n\x1a\n"));
        let mut r = png::Decoder::new(std::io::Cursor::new(bytes)).read_info().unwrap();
        let mut buf = vec![0; r.output_buffer_size().unwrap()];
        let info = r.next_frame(&mut buf).unwrap();
        assert_eq!((info.width, info.height, info.color_type), (64, 64, png::ColorType::Rgba));
        buf
    }

    #[test]
    fn source_forms() {
        let d = tempfile::tempdir().unwrap();
        let env = Env::sandbox(d.path(), "icon");
        let ico = d.path().join("a b.ico");
        let exe = d.path().join("un.exe");
        std::fs::write(&ico, b"x").unwrap();
        std::fs::write(&exe, b"MZ").unwrap();
        let run = format!("\"{}\" /S", exe.display());
        assert_eq!(source(&app(Some(format!("\"{}\",-3", ico.display())), None), &env), Some((ico, -3)));
        assert_eq!(source(&app(Some(r"\\server\share\a.ico".into()), None), &env), None);
        assert_eq!(source(&app(None, Some(run.clone())), &env), Some((exe.clone(), 0)));
        assert_eq!(source(&app(Some(r"C:\missing\x.ico".into()), Some(run)), &env), Some((exe, 0)));
        let msi = "MsiExec.exe /X{8B1E2B3A-0000-4C4C-9999-ABCDEF012345}".to_string();
        assert_eq!(source(&app(None, Some(msi)), &env), None);
        let rundll = r"%SystemRoot%\System32\rundll32.exe x.dll,Uninstall".to_string();
        assert_eq!(source(&app(None, Some(rundll)), &env), None);
        for (s, i) in [(r#""C:\A B\app.exe",1"#, 1), (r"C:\x\app.exe,-101", -101), (r"C:\x\app.exe, 2 ", 2), (r"C:\x\a.ico", 0), (r"C:\App, Inc\app.exe", 0)] {
            assert_eq!(index(s), i, "{s}");
        }
    }

    #[test]
    fn extracts_png_from_real_files() {
        let repo = Path::new(env!("CARGO_MANIFEST_DIR")).join(r"..\..\src-tauri\icons\icon.ico");
        let shell = PathBuf::from(registry::expand_env(r"%SystemRoot%\System32\shell32.dll"));
        for (p, i) in [(repo, 0), (shell, 4)] {
            let px = decode(&extract(&p, i).unwrap_or_else(|| panic!("no icon in {}", p.display())));
            assert!(px.as_chunks::<4>().0.iter().any(|p| p[3] > 0), "{}", p.display());
        }
    }

    #[test]
    fn legacy_icon_takes_alpha_from_mask() {
        let mut ico: Vec<u8> = vec![0, 0, 1, 0, 1, 0, 16, 16, 0, 0, 1, 0, 24, 0];
        ico.extend(872u32.to_le_bytes());
        ico.extend(22u32.to_le_bytes());
        ico.extend(40u32.to_le_bytes());
        ico.extend(16i32.to_le_bytes());
        ico.extend(32i32.to_le_bytes());
        ico.extend(1u16.to_le_bytes());
        ico.extend(24u16.to_le_bytes());
        ico.extend([0u8; 24]);
        ico.extend((0..256).flat_map(|_| [0u8, 0, 255]));
        // AND mask, bottom-up: the first 8 stored rows (the bottom half) are opaque, the last 8 (the top half) transparent.
        ico.extend((0..16).flat_map(|r| if r < 8 { [0u8, 0, 0, 0] } else { [0xFF, 0xFF, 0, 0] }));
        let d = tempfile::tempdir().unwrap();
        let f = d.path().join("legacy.ico");
        std::fs::write(&f, ico).unwrap();
        let px = decode(&extract(&f, 0).expect("legacy icon"));
        let at = |x: usize, y: usize| &px[(y * 64 + x) * 4..][..4];
        assert_eq!(at(0, 0)[3], 0, "top-left is masked out");
        assert_eq!(at(63, 63), [255, 0, 0, 255], "bottom-right is opaque red");
    }

    #[test]
    fn fake_or_missing_files_give_none() {
        let d = tempfile::tempdir().unwrap();
        let (exe, ico) = (d.path().join("fake.exe"), d.path().join("bad.ico"));
        std::fs::write(&exe, b"MZ fake").unwrap();
        std::fs::write(&ico, b"not an icon").unwrap();
        for p in [exe, ico, d.path().join("missing.exe"), d.path().to_path_buf()] {
            assert!(extract(&p, 0).is_none(), "{}", p.display());
        }
    }
}
