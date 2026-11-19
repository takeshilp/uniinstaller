//! Forced removal ("remove by path"): a program the Windows program list does not know is named by the user; the scan then looks
//! for its leftovers around the picked folder and name. `check` decides, read-only, whether a path may be treated as a program of its
//! own; nothing here ever runs a program or changes anything (version info is read as data).
use crate::command::parse_uninstall;
use crate::env::Env;
use crate::inventory::{icon_path, list_apps};
use crate::model::*;
use crate::paths::{REPARSE_ATTR, file_id, is_canonical, is_drive_root, is_inside, is_local_abs, norm, same_or_inside};
use crate::registry::{self, read_string};
use crate::safety::{canon_if_exists, real_folders, text_refers_to};
use crate::scan::{anchors_of, data_volume, dir_problem, links_into, name_variants};
use crate::{Error, Result};
use std::collections::BTreeSet;
use std::fs;
use std::os::windows::fs::MetadataExt;
use std::path::{Path, PathBuf};
use winreg::enums::{KEY_QUERY_VALUE, KEY_READ};

/// Ids of forced targets start with this; a listed program's id always starts with a hive (`HKLM64:`...), so they never collide.
pub const ID_PREFIX: &str = "force:";
/// A name shorter than this is used to look for settings only when it is exact evidence (spec 1.5).
pub const MIN_NAME: usize = 4;
/// `NT SERVICE\TrustedInstaller`, the owner of Windows' own files and folders.
const TRUSTED_INSTALLER: &str = "S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464";

/// Name variants usable to look for settings (spec 1.5: a short inexact name matches too much): each variant of
/// `scan::name_variants(name)` with at least MIN_NAME characters, or equal (any case) to exact evidence: the product name, the
/// picked exe's stem (exe pick) or the picked folder's name (folder pick). A parent folder's name is never evidence.
pub fn search_names(name: &str, picked: &Path, folder: Option<&Path>, product: Option<&str>) -> Vec<String> {
    let folder_pick = folder.is_some_and(|f| norm(f) == norm(picked));
    let own = if folder_pick { picked.file_name() } else { picked.file_stem() };
    let evidence: Vec<String> = own.map(|n| n.to_string_lossy().to_lowercase()).into_iter().chain(product.map(str::to_lowercase)).collect();
    name_variants(name).into_iter().filter(|v| v.chars().count() >= MIN_NAME || evidence.contains(&v.to_lowercase())).collect()
}

/// The stand-in `InstalledApp` the scan works on: no registry source, the install folder is the picked folder, and a file-only
/// pick names the file as the icon so scan section B offers it.
pub fn app_for(f: &Forced, name: &str, publisher: Option<&str>, version: Option<&str>) -> InstalledApp {
    InstalledApp {
        id: format!("{ID_PREFIX}{}", norm(&f.picked)),
        key_name: String::new(),
        sources: vec![],
        display_name: name.to_string(),
        display_version: version.map(str::to_string),
        publisher: publisher.map(str::to_string),
        install_location: f.folder.clone(),
        display_icon: f.folder.is_none().then(|| f.picked.display().to_string()),
        uninstall_string: None,
        quiet_uninstall_string: None,
        modify_path: None,
        install_date: None,
        estimated_size_kb: None,
        windows_installer: false,
        product_code: None,
        per_user: false,
        hidden: None,
    }
}

/// In a sandbox every forced path must lie inside the sandbox folder (the forced folder extends `path_blocks`' allowed zone, so a
/// debug sandbox GUI could otherwise quarantine real files). Always true for the real system.
pub(crate) fn in_sandbox(env: &Env, p: &Path) -> bool {
    !env.sandbox || env.data_dir.parent().is_some_and(|r| is_inside(p, r))
}

fn refuse(code: ForceRefusal, detail: impl Into<String>) -> Result<ForceCheck> {
    Ok(ForceCheck::Refused { code, detail: detail.into() })
}

fn listed(app: &InstalledApp, how: ListedHow) -> Result<ForceCheck> {
    Ok(ForceCheck::Listed { app: Box::new(app.clone()), how })
}

/// Whether registry text names the folder (a folder pick) or the file (file-only).
fn names(text: &str, folder: Option<&Path>, anchor: &Path) -> bool {
    match folder {
        Some(f) => text_refers_to(text, f),
        None => text.replace('/', "\\").to_lowercase().contains(&norm(anchor)),
    }
}

/// A listed program's folder by the scan's own rule (`find_anchor`, `anchors_of`): InstallLocation, else the uninstaller's
/// folder when the DisplayIcon sits in it (outside Windows). Drive roots, protected roots and above are never a program's folder.
fn program_folder(env: &Env, a: &InstalledApp, rootish: &dyn Fn(&Path) -> bool) -> Option<PathBuf> {
    let d = match a.install_location.as_deref().filter(|d| !d.as_os_str().is_empty()) {
        Some(d) => is_local_abs(d).then(|| canon_if_exists(d))?,
        None => {
            let l = a.uninstall_string.as_deref().and_then(|s| parse_uninstall(s, &env.folders.system_dir, a.product_code.as_deref()).ok())?;
            let p = l.exe.parent()?;
            let beside = icon_path(a).as_deref().and_then(Path::parent).is_some_and(|ip| norm(ip) == norm(p));
            (beside && is_local_abs(p) && !is_inside(p, &env.folders.windows_dir)).then(|| canon_if_exists(p))?
        }
    };
    (!rootish(&d)).then_some(d)
}

/// `.exe` files directly in `folder` (`DirEntry::file_type().is_file()`), names not starting with `unins`.
fn top_exes(folder: &Path) -> Vec<PathBuf> {
    let Ok(rd) = fs::read_dir(folder) else { return vec![] };
    let mut v: Vec<PathBuf> = rd
        .flatten()
        .filter(|e| e.file_type().is_ok_and(|t| t.is_file()))
        .map(|e| e.path())
        .filter(|p| p.extension().is_some_and(|x| x.eq_ignore_ascii_case("exe")) && !lower_name(p).starts_with("unins"))
        .collect();
    v.sort();
    v
}

fn lower_name(p: &Path) -> String {
    p.file_name().map(|n| n.to_string_lossy().to_lowercase()).unwrap_or_default()
}

/// An exe stands for its folder only when nothing else there looks like another program: no other exe (uninstallers aside), or
/// every other exe carries the pick's own ProductName. Otherwise only the file is used (a shared `bin` or `Scripts` folder).
// shortcut: an exe whose siblings lack version info gives a file-only identity; the user picks the folder to take it whole.
fn widen(exe: &Path, folder: &Path) -> bool {
    let others: Vec<PathBuf> = top_exes(folder).into_iter().filter(|o| norm(o) != norm(exe)).collect();
    let low = |s: String| s.trim().to_lowercase();
    others.is_empty() || version_info(exe).0.map(low).is_some_and(|p| others.iter().all(|o| version_info(o).0.map(low).as_ref() == Some(&p)))
}

/// The program's main exe in a picked folder: the only `.exe` directly inside, else the one whose stem equals the folder's name.
fn main_exe(folder: &Path) -> Option<PathBuf> {
    let exes = top_exes(folder);
    if let [only] = exes.as_slice() {
        return Some(only.clone());
    }
    let alnum = |s: &str| s.chars().filter(|c| c.is_alphanumeric()).collect::<String>().to_lowercase();
    let fname = alnum(&folder.file_name()?.to_string_lossy());
    exes.into_iter().find(|e| e.file_stem().is_some_and(|s| alnum(&s.to_string_lossy()) == fname))
}

/// Files directly in `folder` that look like the program's own uninstaller: a name starting with `unins` (`unins000`, `uninst`,
/// `uninstall`). Real system: `.exe`; sandbox: `.cmd` or `.bat`, so a sandbox GUI can never be pointed at a real program.
// shortcut: uninstallers are found only by `unins*` names directly in the folder; deeper folders and other names (`remove.exe`,
// `setup.exe /uninstall`) are missed, widen this if users report misses.
fn uninstallers_in(env: &Env, folder: &Path) -> Vec<PathBuf> {
    let exts: &[&str] = if env.sandbox { &["cmd", "bat"] } else { &["exe"] };
    let Ok(rd) = fs::read_dir(folder) else { return vec![] };
    let mut v: Vec<PathBuf> = rd
        .flatten()
        .filter(|e| e.file_type().is_ok_and(|t| t.is_file()))
        .map(|e| e.path())
        .filter(|p| lower_name(p).starts_with("unins") && p.extension().is_some_and(|x| exts.iter().any(|e| x.eq_ignore_ascii_case(e))))
        .collect();
    v.sort();
    v
}

/// `{XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX}` from the squished form Windows Installer uses as a registry key name (the digits of the
/// first three groups reversed, the last eight pairs swapped), or None.
fn unsquish(s: &str) -> Option<String> {
    if s.len() != 32 || !s.bytes().all(|b| b.is_ascii_hexdigit()) {
        return None;
    }
    let mut groups = Vec::new();
    let mut at = 0;
    for n in [8, 4, 4, 2, 2, 2, 2, 2, 2, 2, 2] {
        groups.push(s[at..at + n].chars().rev().collect::<String>());
        at += n;
    }
    Some(format!("{{{}-{}-{}-{}{}-{}}}", groups[0], groups[1], groups[2], groups[3], groups[4], groups[5..].concat()).to_uppercase())
}

/// The local path a component key path names; registry (`00:`...`22:`), assembly (`>...`, `<...`) and empty forms name none.
fn keypath(kp: &str) -> Option<&Path> {
    let p = Path::new(kp.trim());
    is_local_abs(p).then_some(p)
}

/// The folder a component claims: the key path itself when it ends with `\` (a folder component), else its parent.
fn keypath_dir(kp: &str) -> Option<PathBuf> {
    let p = keypath(kp)?;
    if kp.trim().ends_with('\\') { Some(p.to_path_buf()) } else { p.parent().map(Path::to_path_buf) }
}

/// Product codes with a component at or below `anchor` (downward), or whose component folder holds `anchor` (upward; never a
/// drive root, protected root or above). All values are read; the all-zero name (a permanent component) is skipped.
// shortcut: reads every component key on each check (25,087 keys, 25,418 values on the owner's machine); cache per session if slow.
// shortcut: the upward rule gives a whole folder to a product that put one file in it (fail closed: refusals in vendor folders).
fn msi_products(env: &Env, anchor: &Path, rootish: &dyn Fn(&Path) -> bool) -> Result<BTreeSet<String>> {
    let mut out = BTreeSet::new();
    let root = match registry::open(&env.installer_data, KEY_READ) {
        Ok(k) => k,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(out),
        Err(e) => return Err(Error(format!("cannot read the Windows Installer registrations: {e}"))),
    };
    for sid in root.enum_keys() {
        let sid = sid?;
        let comps = match root.open_subkey_with_flags(format!(r"{sid}\Components"), KEY_READ) {
            Ok(k) => k,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => continue,
            Err(e) => return Err(Error(format!("cannot read the Windows Installer registrations: {e}"))),
        };
        for c in comps.enum_keys() {
            let ck = comps.open_subkey_with_flags(c?, KEY_QUERY_VALUE)?;
            for v in ck.enum_values() {
                let (name, value) = v?;
                if name.bytes().all(|b| b == b'0') {
                    continue;
                }
                let Some(kp) = registry::raw_text(&value) else { continue };
                let hit = keypath(&kp).is_some_and(|f| same_or_inside(f, anchor)) || keypath_dir(&kp).is_some_and(|d| !rootish(&d) && same_or_inside(anchor, &d));
                if hit {
                    out.insert(unsquish(&name).unwrap_or(name));
                }
            }
        }
    }
    Ok(out)
}

/// An Uninstall key outside the program list whose InstallLocation, icon or uninstall command points at the pick and whose uninstaller
/// still exists: the pick belongs to installed software (nameless InstallShield entries, for instance).
// shortcut: unlisted Uninstall keys whose uninstaller is gone are ignored, adopt them as the target's own entry if they show up as leftovers.
fn unlisted_owner(env: &Env, apps: &[InstalledApp], folder: Option<&Path>, anchor: &Path, rootish: &dyn Fn(&Path) -> bool) -> Option<String> {
    for root in &env.uninstall_roots {
        let Ok(rk) = registry::open(root, KEY_READ) else { continue };
        for name in rk.enum_keys().flatten() {
            let key = root.child(&name);
            if apps.iter().any(|a| a.sources.iter().any(|s| s.same(&key))) {
                continue;
            }
            let Ok(k) = rk.open_subkey_with_flags(&name, KEY_READ) else { continue };
            let loc = read_string(&k, "InstallLocation", true).map(|l| PathBuf::from(l.trim().trim_matches('"')));
            let loc_hit = loc.is_some_and(|l| is_local_abs(&l) && !rootish(&l) && (same_or_inside(&l, anchor) || same_or_inside(anchor, &l)));
            let cmd = read_string(&k, "UninstallString", true);
            let text_hit = [read_string(&k, "DisplayIcon", true), cmd.clone()].into_iter().flatten().any(|t| names(&t, folder, anchor));
            if !(loc_hit || text_hit) {
                continue;
            }
            if let Some(cmd) = cmd
                && parse_uninstall(&cmd, &env.folders.system_dir, None).is_ok()
            {
                let who = read_string(&k, "DisplayName", false).unwrap_or_else(|| "a nameless entry".into());
                return Some(format!("{} ({who}) is not in the program list and its uninstaller exists: {cmd}", key.display()));
            }
        }
    }
    None
}

/// A registered Windows service whose command line runs from the pick.
// shortcut: `ServiceDll` (svchost) services, drivers given as `\SystemRoot\...` and scheduled tasks are not checked; the services
// feature will offer removal instead of a refusal.
fn service_in(env: &Env, folder: Option<&Path>, anchor: &Path) -> Result<Option<String>> {
    let root = match registry::open(&env.services, KEY_READ) {
        Ok(k) => k,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(Error(format!("cannot read the services: {e}"))),
    };
    for name in root.enum_keys().flatten() {
        let Ok(k) = root.open_subkey_with_flags(&name, KEY_READ) else { continue };
        let Some(image) = read_string(&k, "ImagePath", true) else { continue };
        let image = image.trim();
        let image = image.strip_prefix(r"\??\").unwrap_or(image);
        if names(image, folder, anchor) {
            return Ok(Some(format!("{name}: {image}")));
        }
    }
    Ok(None)
}

/// The owner of a file or folder as an SID string (GetNamedSecurityInfoW + ConvertSidToStringSidW, both freed with LocalFree).
// shortcut: only the pick and its folder are checked; SYSTEM-owned tool folders that other installers manage (C:\Program Files\MSBuild)
// pass, add their owners or names if users force-remove one by mistake.
fn owner_sid(p: &Path) -> Option<String> {
    use std::os::windows::ffi::OsStrExt;
    use windows::Win32::Foundation::{HLOCAL, LocalFree, WIN32_ERROR};
    use windows::Win32::Security::Authorization::{ConvertSidToStringSidW, GetNamedSecurityInfoW, SE_FILE_OBJECT};
    use windows::Win32::Security::{OWNER_SECURITY_INFORMATION, PSECURITY_DESCRIPTOR, PSID};
    use windows::core::{PCWSTR, PWSTR};
    let w: Vec<u16> = p.as_os_str().encode_wide().chain(Some(0)).collect();
    let mut owner = PSID::default();
    let mut sd = PSECURITY_DESCRIPTOR::default();
    // SAFETY: `w` is NUL-terminated; the owner SID points into the security descriptor, which is freed with LocalFree after the
    // string form has been copied; the string returned by ConvertSidToStringSidW is freed with LocalFree as well.
    unsafe {
        let rc = GetNamedSecurityInfoW(PCWSTR(w.as_ptr()), SE_FILE_OBJECT, OWNER_SECURITY_INFORMATION, Some(&mut owner), None, None, None, &mut sd);
        if rc != WIN32_ERROR(0) {
            return None;
        }
        let mut text = PWSTR::null();
        let s = if !owner.0.is_null() && ConvertSidToStringSidW(owner, &mut text).is_ok() { text.to_string().ok() } else { None };
        if !text.is_null() {
            let _ = LocalFree(Some(HLOCAL(text.0 as *mut _)));
        }
        let _ = LocalFree(Some(HLOCAL(sd.0)));
        s
    }
}

/// ProductName, CompanyName and FileVersion of a file's version resource, read as data (the file is never run).
// shortcut: the first translation only; the strings of another language are not read.
fn version_info(exe: &Path) -> (Option<String>, Option<String>, Option<String>) {
    use std::os::windows::ffi::OsStrExt;
    use windows::Win32::Storage::FileSystem::{GetFileVersionInfoSizeW, GetFileVersionInfoW, VerQueryValueW};
    use windows::core::PCWSTR;
    let w: Vec<u16> = exe.as_os_str().encode_wide().chain(Some(0)).collect();
    // SAFETY: `w` is NUL-terminated; the buffer is sized by GetFileVersionInfoSizeW and outlives every pointer taken from it; each
    // queried value is a pointer into that buffer, read within the length VerQueryValueW reports.
    unsafe {
        let size = GetFileVersionInfoSizeW(PCWSTR(w.as_ptr()), None);
        if size == 0 || size > 16 << 20 {
            return (None, None, None);
        }
        let mut buf = vec![0u8; size as usize];
        if GetFileVersionInfoW(PCWSTR(w.as_ptr()), None, size, buf.as_mut_ptr().cast()).is_err() {
            return (None, None, None);
        }
        let query = |sub: &str| -> Option<(*mut std::ffi::c_void, u32)> {
            let s: Vec<u16> = sub.encode_utf16().chain(Some(0)).collect();
            let (mut p, mut n) = (std::ptr::null_mut(), 0u32);
            (VerQueryValueW(buf.as_ptr().cast(), PCWSTR(s.as_ptr()), &mut p, &mut n).as_bool() && !p.is_null() && n > 0).then_some((p, n))
        };
        let lang = match query(r"\VarFileInfo\Translation") {
            Some((p, n)) if n >= 4 => {
                let pair = std::slice::from_raw_parts(p as *const u16, 2);
                format!("{:04x}{:04x}", pair[0], pair[1])
            }
            _ => "040904b0".to_string(),
        };
        let get = |name: &str| -> Option<String> {
            let (p, n) = query(&format!(r"\StringFileInfo\{lang}\{name}"))?;
            let text = String::from_utf16_lossy(std::slice::from_raw_parts(p as *const u16, n as usize));
            let text = text.trim_matches('\0').trim().to_string();
            (!text.is_empty() && !text.chars().any(char::is_control)).then_some(text)
        };
        (get("ProductName"), get("CompanyName"), get("FileVersion"))
    }
}

/// Decides, read-only, whether `picked` (a program file or a folder) may be removed by force. Every refusal is `Ok(Refused)`;
/// `Err` is only for an unexpected read failure. The rules run in this order (see `docs/architecture.md`).
pub fn check(env: &Env, picked: &Path) -> Result<ForceCheck> {
    use ForceRefusal::*;
    // Rule 1: sanity.
    let picked: PathBuf = picked.components().collect();
    if !is_local_abs(&picked) {
        return refuse(BadPath, "not a local absolute path");
    }
    if !in_sandbox(env, &picked) {
        return refuse(OutsideSandbox, picked.display().to_string());
    }
    let Ok(md) = fs::symlink_metadata(&picked) else { return refuse(BadPath, "does not exist") };
    if md.file_attributes() & REPARSE_ATTR != 0 {
        return refuse(BadPath, "a junction or symbolic link");
    }
    if !is_canonical(&picked) {
        return refuse(BadPath, "an alias: 8.3 name, trailing dot or space, junction or SUBST in the path");
    }
    // the file dialog resolves shortcuts itself (rfd does not set FOS_NODEREFERENCELINKS), so a `.lnk` is never a pick
    let is_dir = md.is_dir();
    if !is_dir && !picked.extension().is_some_and(|e| e.eq_ignore_ascii_case("exe")) {
        return refuse(BadPath, "pick a program (.exe) or a folder");
    }

    // Rule 2: the folder the pick stands for.
    let real = match real_folders() {
        Ok(r) => r,
        Err(e) => return refuse(NotAllowed, format!("cannot verify: {e}")),
    };
    let roots: Vec<&PathBuf> = env.folders.protected_roots.iter().chain(&real.protected_roots).collect();
    // True when `d` is a protected or zone root, or above one (the exclusion `Anchors::referenced_in` uses).
    let rootish = |d: &Path| is_drive_root(d) || roots.iter().any(|r| same_or_inside(r, d));
    let folder: Option<PathBuf> = if is_dir {
        Some(picked.clone())
    } else {
        picked.parent().filter(|p| !rootish(p) && widen(&picked, p)).map(Path::to_path_buf)
    };
    let anchor: PathBuf = folder.clone().unwrap_or_else(|| picked.clone());

    // Rule 3: other users' profiles.
    for f in [&env.folders, real] {
        if f.user_profiles.as_deref().is_some_and(|u| is_inside(&anchor, u)) && !f.profile.as_deref().is_some_and(|p| same_or_inside(&anchor, p)) {
            return refuse(NotAllowed, "inside another user's profile");
        }
    }

    // Rule 4: a listed program's folder (hidden ones included) owns the pick.
    let apps = list_apps(env, true)?;
    let owners: Vec<(&InstalledApp, PathBuf)> = apps.iter().filter_map(|a| program_folder(env, a, &rootish).map(|d| (a, d))).filter(|(_, d)| same_or_inside(&anchor, d)).collect();
    let deepest = owners.iter().map(|(_, d)| norm(d).len()).max();
    let owners: Vec<&(&InstalledApp, PathBuf)> = owners.iter().filter(|(_, d)| Some(norm(d).len()) == deepest).collect();
    match owners.as_slice() {
        [] => {}
        [(a, d)] => return listed(a, if norm(d) == norm(&anchor) { ListedHow::Folder } else { ListedHow::Inside }),
        many => {
            let list: Vec<&str> = many.iter().map(|(a, _)| a.display_name.as_str()).collect();
            return refuse(OtherPrograms, format!("several programs claim this folder: {}", list.join(", ")));
        }
    }

    // Rule 5: the gate of a registry InstallLocation.
    let anchors = anchors_of(env, &apps);
    if let Some(why) = dir_problem(env, &anchor, &anchors) {
        return refuse(NotAllowed, why);
    }

    // Rule 6: Windows' own files.
    for p in [&anchor, &picked] {
        match owner_sid(p) {
            None => return refuse(NotAllowed, "cannot read the owner"),
            Some(s) if s == TRUSTED_INSTALLER => return refuse(NotAllowed, "a Windows component (owned by TrustedInstaller)"),
            Some(_) => {}
        }
    }

    // Rule 7: the pick equals or holds another program's files, folder or settings.
    if let Some(why) = anchors.covering(&anchor, Some(&anchor)) {
        return refuse(OtherPrograms, why);
    }

    // Rule 8: an Uninstall key outside the list with a working uninstaller.
    if let Some(why) = unlisted_owner(env, &apps, folder.as_deref(), &anchor, &rootish) {
        return refuse(Installed, why);
    }

    // Rule 9: Windows Installer components, downward and upward.
    let products = msi_products(env, &anchor, &rootish)?;
    if !products.is_empty() {
        let owner_of = |code: &str| apps.iter().find(|a| a.product_code.as_deref().is_some_and(|c| c.eq_ignore_ascii_case(code)));
        let unlisted: Vec<&String> = products.iter().filter(|c| owner_of(c).is_none()).collect();
        if !unlisted.is_empty() {
            let codes: Vec<&str> = unlisted.iter().map(|c| c.as_str()).collect();
            return refuse(Installed, format!("Windows Installer products not in the program list: {}", codes.join(", ")));
        }
        let mut owned: Vec<&InstalledApp> = products.iter().filter_map(|c| owner_of(c)).collect();
        owned.sort_by(|a, b| a.id.cmp(&b.id));
        owned.dedup_by(|a, b| a.id == b.id);
        match owned.as_slice() {
            [one] => return listed(one, ListedHow::Installer),
            many => {
                let list: Vec<&str> = many.iter().map(|a| a.display_name.as_str()).collect();
                return refuse(OtherPrograms, format!("Windows Installer products of several programs: {}", list.join(", ")));
            }
        }
    }

    // Rule 10: a listed program found through a shortcut named after it (programs that register no path).
    let links = links_into(env, &anchor);
    let mut by_link: Vec<&InstalledApp> = apps
        .iter()
        .filter(|a| {
            let variants: Vec<String> = name_variants(&a.display_name).iter().map(|v| v.to_lowercase()).collect();
            links.iter().any(|(l, _)| l.file_stem().is_some_and(|s| variants.contains(&s.to_string_lossy().to_lowercase())))
        })
        .collect();
    by_link.sort_by(|a, b| a.id.cmp(&b.id));
    match by_link.as_slice() {
        [] => {}
        [one] => return listed(one, ListedHow::Shortcut),
        many => {
            let list: Vec<&str> = many.iter().map(|a| a.display_name.as_str()).collect();
            return refuse(OtherPrograms, format!("shortcuts name several programs: {}", list.join(", ")));
        }
    }

    // Rule 11: a registered service runs from here.
    if let Some(why) = service_in(env, folder.as_deref(), &anchor)? {
        return refuse(Service, why);
    }

    // Rule 12: what we found.
    let uninstallers = folder.as_deref().map(|f| uninstallers_in(env, f)).unwrap_or_default();
    let exe = if is_dir { main_exe(&picked) } else { Some(picked.clone()) };
    let (product, company, file_version) = exe.as_deref().map(version_info).unwrap_or_default();
    let own_name = if is_dir { picked.file_name() } else { picked.file_stem() }.map(|n| n.to_string_lossy().to_string());
    let name = product.clone().or(own_name).unwrap_or_default();
    let other_volume = !matches!(data_volume(env), Ok(v) if file_id(&picked).is_ok_and(|i| i.volume == v));
    let outside_zones = !env.folders.program_files.iter().chain(&env.folders.app_data).any(|z| is_inside(&anchor, z));
    let forced = Forced { search_names: search_names(&name, &picked, folder.as_deref(), product.as_deref()), picked, folder };
    Ok(ForceCheck::Ok {
        found: Box::new(ForceFound {
            forced,
            name,
            publisher: company,
            product,
            file_version,
            uninstallers,
            shortcuts: links.into_iter().map(|(l, _)| l).collect(),
            other_volume,
            outside_zones,
        }),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn names_for(name: &str, picked: &str, folder: Option<&str>, product: Option<&str>) -> Vec<String> {
        search_names(name, &PathBuf::from(picked), folder.map(Path::new), product)
    }

    #[test]
    fn search_names_rule() {
        // Stop words and path characters are not usable at all.
        for n in ["App", "Tools", "Setup", "Update", "  ", r"Foo\Bar"] {
            assert!(names_for(n, r"C:\X\app.exe", None, None).is_empty(), "{n}");
        }
        // A short name is used only when it is exact evidence; a longer one always.
        assert_eq!(names_for("Abc 2", r"C:\X\other.exe", Some(r"C:\X"), None), vec!["Abc 2"], "the stripped `Abc` is 3 characters and not evidence");
        assert_eq!(names_for("Abc", r"C:\X\abc.exe", None, None), vec!["Abc"], "the exe's stem is evidence");
        assert!(names_for("Abc", r"C:\X\other.exe", None, None).is_empty());
        assert_eq!(names_for("Abc", r"C:\X\Abc", Some(r"C:\X\Abc"), None), vec!["Abc"], "the picked folder's name is evidence");
        // A parent folder's name is never evidence.
        assert!(names_for("Bin", r"C:\X\Bin\f2py.exe", Some(r"C:\X\Bin"), None).is_empty());
        assert!(names_for("Bin", r"C:\X\Bin\f2py.exe", None, None).is_empty());
        assert_eq!(names_for("f2py", r"C:\X\Bin\f2py.exe", None, None), vec!["f2py"]);
        assert_eq!(names_for("mpv", r"C:\Program Files\MPV\mpv.exe", Some(r"C:\Program Files\MPV"), Some("mpv")), vec!["mpv"]);
        assert_eq!(names_for("Lab Portable", r"C:\X\labportable.exe", None, None), vec!["Lab Portable"]);
    }

    #[test]
    fn app_for_shapes() {
        let f = Forced { picked: PathBuf::from(r"C:\X\a.exe"), folder: None, search_names: vec![] };
        let a = app_for(&f, "Foo", Some("Bar"), Some("1.0"));
        assert_eq!((a.id.as_str(), a.install_location.as_ref(), a.display_icon.as_deref(), a.sources.len()), ("force:c:\\x\\a.exe", None, Some(r"C:\X\a.exe"), 0));
        let f = Forced { picked: PathBuf::from(r"C:\X"), folder: Some(PathBuf::from(r"C:\X")), search_names: vec![] };
        let a = app_for(&f, "Foo", None, None);
        assert_eq!((a.install_location.as_deref(), a.display_icon.as_deref()), (Some(Path::new(r"C:\X")), None));
    }

    #[test]
    fn unsquish_product_codes() {
        // The real Node.js product, and a synthetic one.
        assert_eq!(unsquish("BDC6334C04C08B84F92B32335DE85C5C").as_deref(), Some("{C4336CDB-0C40-48B8-9FB2-2333D58EC5C5}"));
        assert_eq!(unsquish("87654321CBA90FED21436587A9CBED0F").as_deref(), Some("{12345678-9ABC-DEF0-1234-56789ABCDEF0}"));
        assert_eq!(unsquish("87654321CBA90FED21436587A9CBED0"), None, "31 digits");
        assert_eq!(unsquish("87654321CBA90FED21436587A9CBED0FF"), None, "33 digits");
        assert_eq!(unsquish("87654321CBA90FED21436587A9CBED0G"), None, "not hex");
        assert_eq!(unsquish(""), None);
    }

    #[test]
    fn component_key_paths() {
        // Registry, assembly and empty forms name no file.
        for kp in [r"02:\SOFTWARE\Foo", r"20:\x", r"00:\", "", r">\policy.8.0.x", r"<\Microsoft.VC90", r"C?\x"] {
            assert!(keypath(kp).is_none(), "{kp}");
            assert!(keypath_dir(kp).is_none(), "{kp}");
        }
        assert_eq!(keypath_dir(r"C:\Program Files\nodejs\node.exe").unwrap(), PathBuf::from(r"C:\Program Files\nodejs"));
        assert_eq!(keypath_dir(r"C:\Program Files\nodejs\").unwrap(), PathBuf::from(r"C:\Program Files\nodejs"));
        assert_eq!(keypath(r" C:\x\y.dll ").unwrap(), Path::new(r"C:\x\y.dll"));
    }

    #[test]
    fn owner_of_system_files() {
        let sys = std::env::var_os("SystemRoot").map(PathBuf::from).unwrap().join(r"System32\cmd.exe");
        assert_eq!(owner_sid(&sys).as_deref(), Some(TRUSTED_INSTALLER), "Windows' own files");
        let t = tempfile::NamedTempFile::new().unwrap();
        let mine = owner_sid(t.path()).unwrap();
        assert_ne!(mine, TRUSTED_INSTALLER);
        assert!(mine.starts_with("S-1-5-"), "{mine}");
        assert_eq!(owner_sid(Path::new(r"C:\definitely\not\here")), None);
    }

    #[test]
    fn version_info_is_read_as_data() {
        let sys = std::env::var_os("SystemRoot").map(PathBuf::from).unwrap().join(r"System32\whoami.exe");
        let (product, company, version) = version_info(&sys);
        assert!(product.is_some_and(|p| !p.is_empty()));
        assert!(company.is_some_and(|c| c.contains("Microsoft")));
        assert!(version.is_some());
        let t = tempfile::NamedTempFile::new().unwrap();
        assert_eq!(version_info(t.path()), (None, None, None), "a file without a version resource");
    }
}
