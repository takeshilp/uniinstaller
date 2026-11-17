//! Path helpers: lexical comparison, canonical form, file identity, safe walk, move and restore.
use crate::model::{DirPrint, FileId, ItemStatus, RestoreStatus};
use crate::safety::{DATA_DIR_NAMES, DOC_EXT};
use std::ffi::OsString;
use std::fs;
use std::io;
use std::os::windows::ffi::OsStrExt;
use std::os::windows::fs::{MetadataExt, OpenOptionsExt};
use std::os::windows::io::AsRawHandle;
use std::path::{Path, PathBuf};
use windows::Win32::Foundation::HANDLE;
use windows::Win32::Storage::FileSystem::{BY_HANDLE_FILE_INFORMATION, GetFileInformationByHandle, MOVE_FILE_FLAGS, MoveFileExW};
use windows::core::PCWSTR;

pub const REPARSE_ATTR: u32 = 0x400;

fn strip_verbatim(s: &str) -> String {
    if let Some(r) = s.strip_prefix(r"\\?\UNC\") {
        format!(r"\\{r}")
    } else if let Some(r) = s.strip_prefix(r"\\?\") {
        r.to_string()
    } else {
        s.to_string()
    }
}

/// Normal form for comparison only: separators, verbatim prefix, `.`/`..`, trailing `\`, lowercase.
pub fn norm(p: &Path) -> String {
    let s = strip_verbatim(&p.to_string_lossy().replace('/', "\\"));
    let unc = s.starts_with(r"\\");
    let mut stack: Vec<&str> = Vec::new();
    for part in s.split('\\').filter(|x| !x.is_empty() && *x != ".") {
        if part == ".." {
            if stack.len() > 1 {
                stack.pop();
            }
        } else {
            stack.push(part);
        }
    }
    let mut out = stack.join("\\");
    if unc {
        out = format!(r"\\{out}");
    } else if stack.len() == 1 && out.ends_with(':') {
        out.push('\\');
    }
    out.to_lowercase()
}

fn prefix_of(parent: &Path) -> String {
    let n = norm(parent);
    if n.ends_with('\\') { n } else { format!("{n}\\") }
}

/// Strict: `C:\App` is not inside `C:\Apple`, and a path is not inside itself.
pub fn is_inside(child: &Path, parent: &Path) -> bool {
    norm(child).starts_with(&prefix_of(parent))
}

pub fn same_or_inside(child: &Path, parent: &Path) -> bool {
    norm(child) == norm(parent) || is_inside(child, parent)
}

/// `X:\...` only. UNC and relative paths are false.
pub fn is_local_abs(p: &Path) -> bool {
    let b = norm(p).into_bytes();
    b.len() >= 3 && b[0].is_ascii_alphabetic() && b[1] == b':' && b[2] == b'\\'
}

pub fn is_drive_root(p: &Path) -> bool {
    is_local_abs(p) && norm(p).len() == 3
}

/// Any reparse tag counts (junction, symlink, cloud placeholder, mount point).
pub fn is_reparse(p: &Path) -> io::Result<bool> {
    Ok(fs::symlink_metadata(p)?.file_attributes() & REPARSE_ATTR != 0)
}

/// `fs::canonicalize` of the deepest existing ancestor, remaining components appended verbatim, `\\?\` stripped.
pub fn canonical(p: &Path) -> io::Result<PathBuf> {
    let mut rest: Vec<OsString> = Vec::new();
    let mut cur = p.to_path_buf();
    let base = loop {
        match fs::canonicalize(&cur) {
            Ok(c) => break c,
            Err(e) if e.kind() == io::ErrorKind::NotFound => {
                let name = cur.file_name().ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "no existing ancestor"))?.to_os_string();
                rest.push(name);
                cur = cur.parent().ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "no existing ancestor"))?.to_path_buf();
            }
            Err(e) => return Err(e),
        }
    };
    let mut out = PathBuf::from(strip_verbatim(&base.to_string_lossy()));
    for r in rest.iter().rev() {
        out.push(r);
    }
    Ok(out)
}

/// False for `.`/`..` components, components ending with `.` or a space, and any path whose canonical
/// form differs from itself (8.3 names, junctions, symlinks, SUBST).
pub fn is_canonical(p: &Path) -> bool {
    let s = strip_verbatim(&p.to_string_lossy());
    for part in s.split(['\\', '/']).filter(|x| !x.is_empty()) {
        if part == "." || part == ".." || part.ends_with('.') || part.ends_with(' ') {
            return false;
        }
    }
    match canonical(p) {
        Ok(c) => norm(&c) == norm(p),
        Err(_) => false,
    }
}

pub fn file_id(p: &Path) -> io::Result<FileId> {
    let f = fs::OpenOptions::new()
        .access_mode(0x80) // FILE_READ_ATTRIBUTES
        .share_mode(7)
        .custom_flags(0x0200_0000 | 0x0020_0000) // BACKUP_SEMANTICS | OPEN_REPARSE_POINT
        .open(p)?;
    let mut info = BY_HANDLE_FILE_INFORMATION::default();
    // SAFETY: the handle is valid for the lifetime of `f`.
    unsafe { GetFileInformationByHandle(HANDLE(f.as_raw_handle()), &mut info)? };
    Ok(FileId { volume: info.dwVolumeSerialNumber, index: ((info.nFileIndexHigh as u64) << 32) | info.nFileIndexLow as u64 })
}

pub fn mtime_ms(md: &fs::Metadata) -> u64 {
    md.modified().ok().and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok()).map(|d| d.as_millis() as u64).unwrap_or(0)
}

#[derive(Debug, Default, Clone)]
pub struct Walk {
    pub files: u64,
    pub bytes: u64,
    pub newest_mtime: u64,
    pub user_data: bool,
    /// First 10 files named like an uninstaller (`unins*.exe`).
    pub uninstallers: Vec<PathBuf>,
    pub truncated: bool,
}

impl Walk {
    pub fn print(&self) -> DirPrint {
        DirPrint { files: self.files, bytes: self.bytes, newest_mtime: self.newest_mtime }
    }
}

pub fn is_uninstaller_name(name: &str) -> bool {
    let n = name.to_lowercase();
    n.starts_with("unins") && n.ends_with(".exe")
}

/// Iterative walk. A reparse entry is counted but never descended.
pub fn walk(dir: &Path, limit: u64) -> io::Result<Walk> {
    let mut w = Walk::default();
    let mut stack = vec![dir.to_path_buf()];
    while let Some(d) = stack.pop() {
        for entry in fs::read_dir(&d)? {
            let entry = entry?;
            let md = fs::symlink_metadata(entry.path())?;
            w.files += 1;
            if w.files > limit {
                w.truncated = true;
                return Ok(w);
            }
            w.bytes += md.len();
            w.newest_mtime = w.newest_mtime.max(mtime_ms(&md));
            let name = entry.file_name().to_string_lossy().to_lowercase();
            if md.file_attributes() & REPARSE_ATTR != 0 {
                continue;
            }
            if md.is_dir() {
                if DATA_DIR_NAMES.contains(&name.as_str()) {
                    w.user_data = true;
                }
                stack.push(entry.path());
            } else {
                if has_doc_ext(&name) {
                    w.user_data = true;
                }
                if is_uninstaller_name(&name) && w.uninstallers.len() < 10 {
                    w.uninstallers.push(entry.path());
                }
            }
        }
    }
    Ok(w)
}

pub fn has_doc_ext(name: &str) -> bool {
    Path::new(name).extension().and_then(|e| e.to_str()).map(|e| DOC_EXT.contains(&e.to_lowercase().as_str())).unwrap_or(false)
}

// shortcut: path leftovers on another volume than data_dir are Blocked (OtherVolume), add a per-volume quarantine folder if users need it.
/// `MoveFileExW(src, dst, 0)`: never replaces an existing target and never copies across volumes.
pub fn move_path(src: &Path, dst: &Path) -> io::Result<()> {
    let w = |p: &Path| -> Vec<u16> { p.as_os_str().encode_wide().chain(std::iter::once(0)).collect() };
    let (s, d) = (w(src), w(dst));
    // SAFETY: both buffers are NUL-terminated and outlive the call.
    unsafe { MoveFileExW(PCWSTR(s.as_ptr()), PCWSTR(d.as_ptr()), MOVE_FILE_FLAGS(0)) }.map_err(|_| io::Error::last_os_error())
}

/// Moves the quarantined payload `q` back to `original`. Never overwrites.
pub fn restore_path(q: &Path, original: &Path) -> (RestoreStatus, Option<String>) {
    if let Some(parent) = original.parent()
        && let Err(e) = fs::create_dir_all(parent)
    {
        return (RestoreStatus::Failed, Some(e.to_string()));
    }
    match move_path(q, original) {
        Ok(()) => (RestoreStatus::Restored, None),
        Err(e) if matches!(e.raw_os_error(), Some(80) | Some(183)) => merge_dirs(q, original),
        Err(e) => (RestoreStatus::Failed, Some(e.to_string())),
    }
}

fn is_real_dir(p: &Path) -> bool {
    fs::symlink_metadata(p).map(|m| m.is_dir() && m.file_attributes() & REPARSE_ATTR == 0).unwrap_or(false)
}

fn merge_dirs(q: &Path, original: &Path) -> (RestoreStatus, Option<String>) {
    if !(is_real_dir(q) && is_real_dir(original)) {
        return (RestoreStatus::Conflict, Some("target exists".into()));
    }
    let Ok(rd) = fs::read_dir(q) else {
        return (RestoreStatus::Failed, Some("cannot read quarantine dir".into()));
    };
    let mut conflict = false;
    for e in rd.flatten() {
        let (st, _) = restore_path(&e.path(), &original.join(e.file_name()));
        conflict |= st != RestoreStatus::Restored;
    }
    if !conflict && fs::remove_dir(q).is_ok() {
        (RestoreStatus::Restored, None)
    } else {
        (RestoreStatus::Conflict, Some("some entries already exist; kept in quarantine".into()))
    }
}

pub fn io_status(e: &io::Error) -> ItemStatus {
    match e.raw_os_error() {
        Some(5) => ItemStatus::AccessDenied,
        Some(32) | Some(33) => ItemStatus::Locked,
        Some(2) | Some(3) => ItemStatus::NotFound,
        _ => ItemStatus::Failed,
    }
}

/// Creates a directory junction with `cmd /C mklink /J` (no admin needed). Used by the sandbox and tests.
pub fn make_junction(link: &Path, target: &Path) -> io::Result<()> {
    let fix = |p: &Path| p.to_string_lossy().replace('/', "\\");
    let out = std::process::Command::new("cmd").arg("/C").arg("mklink").arg("/J").arg(fix(link)).arg(fix(target)).output()?;
    if out.status.success() { Ok(()) } else { Err(io::Error::other(String::from_utf8_lossy(&out.stderr).to_string())) }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn norm_and_inside() {
        assert_eq!(norm(Path::new(r"C:\App\")), r"c:\app");
        assert_eq!(norm(Path::new("C:/App/./x/../y")), r"c:\app\y");
        assert_eq!(norm(Path::new(r"\\?\C:\App")), r"c:\app");
        assert_eq!(norm(Path::new(r"\\?\UNC\srv\sh")), r"\\srv\sh");
        assert_eq!(norm(Path::new(r"C:\")), r"c:\");
        assert!(is_inside(Path::new(r"C:\App\x"), Path::new(r"c:\APP\")));
        assert!(!is_inside(Path::new(r"C:\Apple"), Path::new(r"C:\App")));
        assert!(!is_inside(Path::new(r"C:\App"), Path::new(r"C:\App")));
        assert!(same_or_inside(Path::new(r"C:\App"), Path::new(r"C:\App")));
        assert!(is_inside(Path::new(r"C:\x"), Path::new(r"C:\")));
        assert!(is_local_abs(Path::new(r"C:\x")));
        assert!(!is_local_abs(Path::new(r"\\srv\sh\x")));
        assert!(!is_local_abs(Path::new(r"x\y")));
        assert!(is_drive_root(Path::new(r"D:\")));
        assert!(!is_drive_root(Path::new(r"D:\x")));
    }

    #[test]
    fn canonical_detects_alias() {
        let t = tempfile::tempdir().unwrap();
        let root = canonical(t.path()).unwrap();
        let real = root.join("real");
        fs::create_dir_all(real.join("sub")).unwrap();
        assert!(is_canonical(&real));
        assert!(is_canonical(&real.join("missing").join("deeper")));
        let alias = root.join("alias");
        make_junction(&alias, &real).unwrap();
        assert!(!is_canonical(&alias));
        assert!(!is_canonical(&alias.join("sub")));
        assert!(!is_canonical(&root.join("real.")));
        assert!(!is_canonical(&root.join("real ")));
        assert!(!is_canonical(&root.join("a").join("..").join("real")));
    }

    #[test]
    fn file_id_works_for_dirs_and_junctions() {
        let t = tempfile::tempdir().unwrap();
        let root = canonical(t.path()).unwrap();
        let real = root.join("real");
        fs::create_dir_all(&real).unwrap();
        fs::write(root.join("f.txt"), b"x").unwrap();
        let link = root.join("link");
        make_junction(&link, &real).unwrap();
        let d = file_id(&real).unwrap();
        let l = file_id(&link).unwrap();
        let f = file_id(&root.join("f.txt")).unwrap();
        assert_eq!(d.volume, f.volume);
        assert_ne!(d.index, l.index, "junction is opened as itself, not followed");
        assert_ne!(d.index, f.index);
        assert!(is_reparse(&link).unwrap());
        assert!(!is_reparse(&real).unwrap());
    }

    #[test]
    fn move_never_overwrites_and_restore_merges() {
        let t = tempfile::tempdir().unwrap();
        let r = canonical(t.path()).unwrap();
        fs::write(r.join("a"), b"1").unwrap();
        fs::write(r.join("b"), b"2").unwrap();
        assert!(move_path(&r.join("a"), &r.join("b")).is_err());
        assert_eq!(fs::read(r.join("b")).unwrap(), b"2");
        // dir merge: original already has one of the two children
        fs::create_dir_all(r.join("q/d")).unwrap();
        fs::write(r.join("q/d/x"), b"q").unwrap();
        fs::write(r.join("q/d/y"), b"q").unwrap();
        fs::create_dir_all(r.join("o/d")).unwrap();
        fs::write(r.join("o/d/x"), b"orig").unwrap();
        let (st, _) = restore_path(&r.join("q/d"), &r.join("o/d"));
        assert_eq!(st, RestoreStatus::Conflict);
        assert_eq!(fs::read(r.join("o/d/x")).unwrap(), b"orig");
        assert_eq!(fs::read(r.join("o/d/y")).unwrap(), b"q");
        assert!(r.join("q/d/x").exists());
    }

    #[test]
    fn walk_counts_flags_and_skips_links() {
        let t = tempfile::tempdir().unwrap();
        let r = canonical(t.path()).unwrap();
        fs::create_dir_all(r.join("app/Saves")).unwrap();
        fs::create_dir_all(r.join("outside")).unwrap();
        fs::write(r.join("outside/keep.txt"), b"keep").unwrap();
        fs::write(r.join("app/a.exe"), b"abc").unwrap();
        fs::write(r.join("app/unins000.exe"), b"").unwrap();
        make_junction(&r.join("app/link"), &r.join("outside")).unwrap();
        let w = walk(&r.join("app"), 1000).unwrap();
        assert!(w.user_data);
        assert_eq!(w.uninstallers.len(), 1);
        assert_eq!(w.files, 4); // a.exe, unins000.exe, Saves, link
        assert!(!w.truncated);
        assert!(walk(&r.join("app"), 2).unwrap().truncated);
    }
}
