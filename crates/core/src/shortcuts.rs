//! `.lnk` enumeration and COM-based resolution. Resolution never calls `Resolve()`, which can modify a link.
use crate::paths::{REPARSE_ATTR, is_local_abs};
use crate::{Error, Result};
use std::ffi::OsString;
use std::fs;
use std::os::windows::ffi::{OsStrExt, OsStringExt};
use std::os::windows::fs::MetadataExt;
use std::path::{Path, PathBuf};
use windows::Win32::Storage::FileSystem::WIN32_FIND_DATAW;
use windows::Win32::System::Com::*;
use windows::Win32::UI::Shell::{IShellLinkW, ShellLink};
use windows::core::{Interface, PCWSTR};

/// Calls `CoUninitialize` on drop only if this guard's `CoInitializeEx` succeeded (RPC_E_CHANGED_MODE is fine).
pub struct ComGuard(bool);

impl ComGuard {
    pub fn new() -> ComGuard {
        // SAFETY: plain COM initialisation for the current thread.
        ComGuard(unsafe { CoInitializeEx(None, COINIT_APARTMENTTHREADED | COINIT_DISABLE_OLE1DDE) }.is_ok())
    }
}
impl Default for ComGuard {
    fn default() -> Self {
        Self::new()
    }
}
impl Drop for ComGuard {
    fn drop(&mut self) {
        if self.0 {
            // SAFETY: paired with the successful CoInitializeEx above.
            unsafe { CoUninitialize() };
        }
    }
}

fn wide(p: &Path) -> Vec<u16> {
    p.as_os_str().encode_wide().chain(std::iter::once(0)).collect()
}

/// Recursive `.lnk` search; reparse entries are never descended. Depth 4 for the Start Menu, 1 for desktops.
pub fn list_links(roots: &[PathBuf], max_depth: usize) -> Vec<PathBuf> {
    fn rec(dir: &Path, depth: usize, max: usize, out: &mut Vec<PathBuf>) {
        let Ok(rd) = fs::read_dir(dir) else { return };
        for e in rd.flatten() {
            let Ok(md) = fs::symlink_metadata(e.path()) else { continue };
            if md.file_attributes() & REPARSE_ATTR != 0 {
                continue;
            }
            if md.is_dir() {
                if depth < max {
                    rec(&e.path(), depth + 1, max, out);
                }
            } else if e.path().extension().is_some_and(|x| x.eq_ignore_ascii_case("lnk")) {
                out.push(e.path());
            }
        }
    }
    let mut out = Vec::new();
    for r in roots {
        rec(r, 1, max_depth, &mut out);
    }
    out
}

/// The link's target path (fully expanded long path). None for advertised MSI shortcuts or unreadable links.
pub fn resolve(lnk: &Path) -> Option<PathBuf> {
    let _com = ComGuard::new();
    let w = wide(lnk);
    // SAFETY: COM calls on interfaces created here; buffers outlive the calls.
    unsafe {
        let link: IShellLinkW = CoCreateInstance(&ShellLink, None, CLSCTX_INPROC_SERVER).ok()?;
        let pf = link.cast::<IPersistFile>().ok()?;
        pf.Load(PCWSTR(w.as_ptr()), STGM(0)).ok()?; // STGM_READ
        let mut buf = [0u16; 1024];
        link.GetPath(&mut buf, std::ptr::null_mut::<WIN32_FIND_DATAW>(), 0).ok()?;
        let n = buf.iter().position(|&c| c == 0).unwrap_or(buf.len());
        if n == 0 {
            return None;
        }
        let p = PathBuf::from(OsString::from_wide(&buf[..n]));
        is_local_abs(&p).then_some(p)
    }
}

/// Creates a link (sandbox and tests only).
pub fn create(lnk: &Path, target: &Path) -> Result<()> {
    let _com = ComGuard::new();
    let (l, t) = (wide(lnk), wide(target));
    let dir = wide(target.parent().unwrap_or(Path::new("")));
    // SAFETY: as in `resolve`.
    unsafe {
        let link: IShellLinkW = CoCreateInstance(&ShellLink, None, CLSCTX_INPROC_SERVER).map_err(|e| Error(e.to_string()))?;
        link.SetPath(PCWSTR(t.as_ptr()))?;
        link.SetWorkingDirectory(PCWSTR(dir.as_ptr()))?;
        link.cast::<IPersistFile>()?.Save(PCWSTR(l.as_ptr()), true)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn create_resolve_and_list() {
        let t = tempfile::tempdir().unwrap();
        let root = crate::paths::canonical(t.path()).unwrap();
        let target = root.join("app.exe");
        fs::write(&target, b"x").unwrap();
        fs::create_dir_all(root.join("sub")).unwrap();
        let lnk = root.join("sub").join("App.lnk");
        create(&lnk, &target).unwrap();
        assert_eq!(resolve(&lnk).unwrap(), target);
        assert_eq!(list_links(std::slice::from_ref(&root), 4), vec![lnk.clone()]);
        assert!(list_links(std::slice::from_ref(&root), 1).is_empty());
    }
}
