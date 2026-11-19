//! Restart Manager: which processes hold a locked item's files (read-only) and a graceful close of exactly the processes the user saw.
//! Never `RmForceShutdown`, never `TerminateProcess`.
use crate::model::{Holder, HolderBlock, HolderKind, PathKind, ProcInfo};
use crate::native::{ft, processes};
use std::collections::HashMap;
use std::fs;
use std::io;
use std::os::windows::ffi::OsStrExt;
use std::os::windows::fs::{MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};
use windows::Win32::System::RestartManager::*;
use windows::core::{PCWSTR, PWSTR};

// shortcut: at most 64 blocking files per item are registered with the Restart Manager (about 0.5 s per held file, about 240 ms per
// registered file under Program Files) and at most 20,000 entries of an item are probed; raise them if users meet bigger locked folders.
pub const MAX_FILES: usize = 64;
pub const MAX_PROBE: usize = 20_000;

const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x400;
const ERROR_MORE_DATA: u32 = 234;

/// What blocks an item's move: files whose open handles stop it, how many folders are open, and whether the probe stopped at the cap.
#[derive(Debug, Default, PartialEq)]
pub struct Blocked {
    pub files: Vec<PathBuf>,
    pub folders: usize,
    pub truncated: bool,
}

/// Whether an open handle stops moving `p`. `inside`: an entry below a folder item. Any open handle there stops the folder's move (measured:
/// the move fails with 5 even for a share-all handle), so it is opened with no sharing. The item itself (a file, or the folder's own handle,
/// such as a current folder) conflicts only with handles that do not share delete, so it is opened with full sharing. DELETE access, the link
/// itself is opened, nothing is changed.
// shortcut: the probe opens for DELETE (with no sharing inside a folder item), so for that instant another program's open can fail with 32
// and an oplock can break, and a handle opened only for attributes is not seen; upgrade to per-file attribution in the stage-2 helper.
fn held(p: &Path, dir: bool, inside: bool) -> bool {
    let flags = 0x0020_0000 | if dir { 0x0200_0000 } else { 0 };
    let r = fs::OpenOptions::new().access_mode(0x0001_0000).share_mode(if inside { 0 } else { 7 }).custom_flags(flags).open(p);
    matches!(r, Err(e) if matches!(e.raw_os_error(), Some(32 | 33)))
}

/// Probes the item for open handles (read-only), looking at no more than `cap` entries of a folder.
pub fn blockers(path: &Path, kind: PathKind, cap: usize) -> Blocked {
    let mut b = Blocked::default();
    match kind {
        PathKind::Link => {}
        PathKind::File => {
            if held(path, false, false) {
                b.files.push(path.to_path_buf());
            }
        }
        PathKind::Dir => {
            if held(path, true, false) {
                b.folders += 1;
            }
            let (mut stack, mut seen) = (vec![path.to_path_buf()], 0usize);
            'walk: while let Some(d) = stack.pop() {
                let Ok(rd) = fs::read_dir(&d) else { continue };
                for e in rd.flatten() {
                    if seen >= cap {
                        b.truncated = true;
                        break 'walk;
                    }
                    seen += 1;
                    let p = e.path();
                    let Ok(m) = fs::symlink_metadata(&p) else { continue };
                    if m.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
                        continue;
                    }
                    if m.is_dir() {
                        if held(&p, true, true) {
                            b.folders += 1;
                        }
                        stack.push(p);
                    } else if held(&p, false, true) {
                        b.files.push(p);
                    }
                }
            }
        }
    }
    b
}

/// A Restart Manager session, ended on drop.
struct Session(u32);

impl Session {
    fn start() -> io::Result<Session> {
        let mut h = 0u32;
        let mut key = [0u16; CCH_RM_SESSION_KEY as usize + 1];
        // SAFETY: `key` has the room the API documents (CCH_RM_SESSION_KEY + 1 characters).
        let rc = unsafe { RmStartSession(&mut h, None, PWSTR(key.as_mut_ptr())) };
        if rc.0 != 0 {
            return Err(io::Error::from_raw_os_error(rc.0 as i32));
        }
        Ok(Session(h))
    }
}

impl Drop for Session {
    fn drop(&mut self) {
        // SAFETY: the session was started by `start` and is ended exactly once.
        unsafe {
            let _ = RmEndSession(self.0);
        }
    }
}

fn os_err(code: u32) -> io::Error {
    io::Error::from_raw_os_error(code as i32)
}

/// The two-call `RmGetList` pattern: the affected applications and the reboot-reason bits.
fn list(s: &Session) -> io::Result<(Vec<RM_PROCESS_INFO>, u32)> {
    let (mut need, mut n, mut reasons) = (0u32, 0u32, 0u32);
    // SAFETY: the first call has no buffer (it only reports the size needed); the later ones pass a buffer of `n` entries.
    let mut rc = unsafe { RmGetList(s.0, &mut need, &mut n, None, &mut reasons) };
    let mut buf: Vec<RM_PROCESS_INFO> = Vec::new();
    for _ in 0..4 {
        if rc.0 == 0 {
            buf.truncate(n as usize);
            return Ok((buf, reasons));
        }
        if rc.0 != ERROR_MORE_DATA {
            return Err(os_err(rc.0));
        }
        buf = vec![RM_PROCESS_INFO::default(); need as usize + 4];
        n = buf.len() as u32;
        // SAFETY: `buf` holds `n` entries.
        rc = unsafe { RmGetList(s.0, &mut need, &mut n, Some(buf.as_mut_ptr()), &mut reasons) };
    }
    Err(os_err(rc.0))
}

fn utf16_to_nul(s: &[u16]) -> String {
    String::from_utf16_lossy(&s[..s.iter().position(|&c| c == 0).unwrap_or(s.len())])
}

fn kind_of(t: i32) -> HolderKind {
    match t {
        1 => HolderKind::MainWindow,
        2 => HolderKind::OtherWindow,
        3 => HolderKind::Service,
        4 => HolderKind::Explorer,
        5 => HolderKind::Console,
        1000 => HolderKind::Critical,
        _ => HolderKind::Unknown,
    }
}

fn wide(p: &Path) -> Vec<u16> {
    p.as_os_str().encode_wide().chain(std::iter::once(0)).collect()
}

/// The processes holding any of `files` (at most `MAX_FILES` are asked about) and the reboot-reason bits.
/// Never pass a folder: `RmGetList` then fails with error 5 and the whole answer is lost (the caller passes `Blocked::files` only).
// shortcut: folders are never registered, so a folder held as a current folder or by a watcher is reported only as "a folder is open",
// without a name; upgrade to a handle enumeration in the stage-2 helper.
pub fn holders(files: &[PathBuf]) -> io::Result<(Vec<Holder>, u32)> {
    let s = Session::start()?;
    let bufs: Vec<Vec<u16>> = files.iter().take(MAX_FILES).map(|p| wide(p)).collect();
    let ptrs: Vec<PCWSTR> = bufs.iter().map(|b| PCWSTR(b.as_ptr())).collect();
    // SAFETY: the wide strings in `bufs` outlive the call.
    let rc = unsafe { RmRegisterResources(s.0, Some(&ptrs), None, None) };
    if rc.0 != 0 {
        return Err(os_err(rc.0));
    }
    let (infos, reasons) = list(&s)?;
    let images: HashMap<u32, String> = if infos.is_empty() { HashMap::new() } else { processes().into_iter().map(|(pid, _, exe)| (pid, exe)).collect() };
    let hs = infos
        .iter()
        .map(|e| {
            let pid = e.Process.dwProcessId;
            let image = images.get(&pid).cloned().unwrap_or_default();
            // An exe without a version resource comes back with the name " ".
            let name = utf16_to_nul(&e.strAppName).trim().to_string();
            let service = Some(utf16_to_nul(&e.strServiceShortName)).filter(|x| !x.is_empty());
            Holder { pid, started: ft(e.Process.ProcessStartTime), name: if name.is_empty() { image.clone() } else { name }, image, service, kind: kind_of(e.ApplicationType.0), block: None }
        })
        .collect();
    Ok((hs, reasons))
}

/// Why this holder is not closed from here, if it is not. Our own process and any WebView2 process come first, then the recorded
/// uninstaller, then the application type.
// shortcut: only window programs are closed. Refused: console programs (RM would send Ctrl+C to every program in that console and attach
// to it from inside our process), services, Explorer, critical, unknown-type, elevated or other-session holders, any WebView2 process and
// the recorded uninstaller; upgrade to per-kind handling if users ask.
pub fn block(h: &Holder, own_pid: u32, uninstaller: &[ProcInfo]) -> Option<HolderBlock> {
    if h.pid == own_pid || h.image.eq_ignore_ascii_case("msedgewebview2.exe") {
        return Some(HolderBlock::Ours);
    }
    if uninstaller.iter().any(|p| p.pid == h.pid && p.created == h.started) {
        return Some(HolderBlock::Uninstaller);
    }
    match h.kind {
        HolderKind::Critical => Some(HolderBlock::Critical),
        HolderKind::Service => Some(HolderBlock::Service),
        HolderKind::Explorer => Some(HolderBlock::Explorer),
        HolderKind::Console => Some(HolderBlock::Console),
        HolderKind::Unknown => Some(HolderBlock::NeedsForce),
        HolderKind::MainWindow | HolderKind::OtherWindow => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs::OpenOptions;

    fn holder(pid: u32, started: u64, image: &str, kind: HolderKind) -> Holder {
        Holder { pid, started, name: image.into(), image: image.into(), service: None, kind, block: None }
    }

    #[test]
    fn kind_mapping() {
        use HolderKind::*;
        for (t, k) in [(0, Unknown), (1, MainWindow), (2, OtherWindow), (3, Service), (4, Explorer), (5, Console), (1000, Critical), (7, Unknown)] {
            assert_eq!(kind_of(t), k, "{t}");
        }
    }

    #[test]
    fn block_table() {
        use HolderKind::*;
        let own = 100;
        let b = |h: &Holder, un: &[ProcInfo]| block(h, own, un);
        assert_eq!(b(&holder(100, 1, "a.exe", MainWindow), &[]), Some(HolderBlock::Ours));
        assert_eq!(b(&holder(5, 1, "MSEdgeWebView2.EXE", MainWindow), &[]), Some(HolderBlock::Ours));
        let un = [ProcInfo { pid: 7, image: "unins.exe".into(), created: 50, exit_code: None }];
        assert_eq!(b(&holder(7, 50, "unins.exe", MainWindow), &un), Some(HolderBlock::Uninstaller));
        assert_eq!(b(&holder(7, 51, "other.exe", MainWindow), &un), None, "the same pid with another creation time is another process");
        for (k, want) in [
            (Critical, Some(HolderBlock::Critical)),
            (Service, Some(HolderBlock::Service)),
            (Explorer, Some(HolderBlock::Explorer)),
            (Console, Some(HolderBlock::Console)),
            (Unknown, Some(HolderBlock::NeedsForce)),
            (MainWindow, None),
            (OtherWindow, None),
        ] {
            assert_eq!(b(&holder(9, 1, "x.exe", k), &[]), want, "{k:?}");
        }
    }

    fn open(p: &Path, share: u32) -> fs::File {
        OpenOptions::new().read(true).share_mode(share).open(p).unwrap()
    }

    #[test]
    fn blockers_probe() {
        let t = tempfile::tempdir().unwrap();
        let d = t.path().join("d");
        fs::create_dir_all(d.join("s")).unwrap();
        for n in ["a.txt", "b.txt", "c.txt"] {
            fs::write(d.join(n), "x").unwrap();
        }
        let _a = open(&d.join("a.txt"), 0);
        let _b = open(&d.join("b.txt"), 7);
        // a folder handle that shares everything, opened with backup semantics
        let _s = OpenOptions::new().read(true).share_mode(7).custom_flags(0x0200_0000).open(d.join("s")).unwrap();
        let r = blockers(&d, PathKind::Dir, MAX_PROBE);
        assert!(r.files.contains(&d.join("a.txt")), "{r:?}");
        assert!(r.files.contains(&d.join("b.txt")), "a share-all handle inside a folder item still stops its move: {r:?}");
        assert!(!r.files.contains(&d.join("c.txt")), "{r:?}");
        assert!(r.folders >= 1, "{r:?}");
        assert!(!r.truncated);

        // the folder itself held like a current folder (no delete sharing)
        let cur = t.path().join("cur");
        fs::create_dir(&cur).unwrap();
        let _c = OpenOptions::new().read(true).share_mode(3).custom_flags(0x0200_0000).open(&cur).unwrap();
        assert!(blockers(&cur, PathKind::Dir, MAX_PROBE).folders >= 1);

        // a file item: a share-all handle does not stop its move, a no-share handle does
        let f1 = t.path().join("f1");
        let f2 = t.path().join("f2");
        fs::write(&f1, "x").unwrap();
        fs::write(&f2, "x").unwrap();
        let _f1 = open(&f1, 7);
        assert_eq!(blockers(&f1, PathKind::File, MAX_PROBE).files, Vec::<PathBuf>::new());
        let _f2 = open(&f2, 0);
        assert_eq!(blockers(&f2, PathKind::File, MAX_PROBE).files, vec![f2.clone()]);
        let free = t.path().join("free");
        fs::write(&free, "x").unwrap();
        assert_eq!(blockers(&free, PathKind::File, MAX_PROBE), Blocked::default());
        assert_eq!(blockers(&f2, PathKind::Link, MAX_PROBE), Blocked::default());

        // a cap of 2 on 5 entries
        let big = t.path().join("big");
        fs::create_dir(&big).unwrap();
        for i in 0..5 {
            fs::write(big.join(format!("{i}")), "x").unwrap();
        }
        assert!(blockers(&big, PathKind::Dir, 2).truncated);
        assert!(!blockers(&big, PathKind::Dir, 5).truncated);
    }

    #[test]
    fn blockers_do_not_follow_a_junction() {
        let t = tempfile::tempdir().unwrap();
        let target = t.path().join("target");
        let outer = t.path().join("outer");
        fs::create_dir_all(&target).unwrap();
        fs::create_dir_all(&outer).unwrap();
        fs::write(target.join("held.txt"), "x").unwrap();
        let _h = open(&target.join("held.txt"), 0);
        let link = outer.join("link");
        let ok = std::process::Command::new("cmd").args(["/C", "mklink", "/J"]).arg(&link).arg(&target).stdout(std::process::Stdio::null()).status().unwrap().success();
        assert!(ok, "mklink /J failed");
        let r = blockers(&outer, PathKind::Dir, MAX_PROBE);
        assert!(r.files.is_empty(), "a junction must not be followed: {r:?}");
    }
}
