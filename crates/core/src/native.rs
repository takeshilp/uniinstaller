//! Runs the program's own uninstaller and waits for its whole process tree.
//! `ShellExecuteExW` handles UAC for `requireAdministrator` uninstallers; descendants are found by Toolhelp polling.
//! Every process handle stays open until the end, so PIDs cannot be reused. Nothing is ever terminated.
// shortcut: Toolhelp polling every 150 ms can miss a grandchild that is spawned and orphaned within one interval,
// upgrade to a job object in the elevated helper (stage 2).
// shortcut: on timeout or "stop waiting" nothing is killed, and scanning is allowed once the uninstall entry is gone
// even if recorded processes still run (the UI warns); revisit when there is a batch queue.
use crate::model::{Launch, NativeRun, ProcInfo};
use crate::now_ms;
use crate::shortcuts::ComGuard;
use std::os::windows::ffi::OsStrExt;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};
use windows::Win32::Foundation::{CloseHandle, FILETIME, HANDLE, WAIT_OBJECT_0, WAIT_TIMEOUT};
use windows::Win32::System::Diagnostics::ToolHelp::*;
use windows::Win32::System::Threading::*;
use windows::Win32::UI::Shell::{SEE_MASK_FLAG_NO_UI, SEE_MASK_NOASYNC, SEE_MASK_NOCLOSEPROCESS, SHELLEXECUTEINFOW, ShellExecuteExW};
use windows::Win32::UI::WindowsAndMessaging::{SW_HIDE, SW_SHOWNORMAL};
use windows::core::{PCWSTR, w};

pub type PollCallback = Box<dyn Fn(&[ProcInfo]) + Send + Sync>;

pub struct RunOptions {
    pub timeout: Duration,
    pub poll: Duration,
    pub show_window: bool,
    /// Set by the UI: stop waiting, kill nothing.
    pub stop: Arc<AtomicBool>,
    /// Called after every poll with the live tracked processes.
    pub on_poll: Option<PollCallback>,
}

impl Default for RunOptions {
    fn default() -> Self {
        RunOptions { timeout: Duration::from_secs(60 * 60), poll: Duration::from_millis(150), show_window: true, stop: Arc::new(AtomicBool::new(false)), on_poll: None }
    }
}

pub fn reboot_required(code: Option<u32>) -> bool {
    matches!(code, Some(3010) | Some(1641))
}

struct Tracked {
    pid: u32,
    handle: HANDLE,
    created: u64,
    exited: Option<u64>,
    exit_code: Option<u32>,
    image: String,
}

impl Drop for Tracked {
    fn drop(&mut self) {
        // SAFETY: the handle was opened by us and is closed exactly once.
        unsafe {
            let _ = CloseHandle(self.handle);
        }
    }
}

pub(crate) fn ft(f: FILETIME) -> u64 {
    ((f.dwHighDateTime as u64) << 32) | f.dwLowDateTime as u64
}

fn times(h: HANDLE) -> Option<(u64, u64)> {
    let (mut c, mut e, mut k, mut u) = (FILETIME::default(), FILETIME::default(), FILETIME::default(), FILETIME::default());
    // SAFETY: valid handle and out-pointers.
    unsafe { GetProcessTimes(h, &mut c, &mut e, &mut k, &mut u).ok()? };
    Some((ft(c), ft(e)))
}

fn is_signaled(h: HANDLE) -> bool {
    // SAFETY: valid handle.
    unsafe { WaitForSingleObject(h, 0) == WAIT_OBJECT_0 }
}

fn track(pid: u32, handle: HANDLE, image: String) -> Option<Tracked> {
    let Some((created, _)) = times(handle) else {
        // SAFETY: we own this handle.
        unsafe {
            let _ = CloseHandle(handle);
        }
        return None;
    };
    Some(Tracked { pid, handle, created, exited: None, exit_code: None, image })
}

fn mark_exits(t: &mut [Tracked]) {
    for p in t.iter_mut().filter(|p| p.exited.is_none()) {
        if is_signaled(p.handle) {
            let mut code = 0u32;
            // SAFETY: valid handle and out-pointer.
            if unsafe { GetExitCodeProcess(p.handle, &mut code) }.is_ok() {
                p.exit_code = Some(code);
            }
            p.exited = times(p.handle).map(|x| x.1).or(Some(u64::MAX));
        }
    }
}

/// Every running process as (pid, parent pid, image name), from one Toolhelp snapshot; empty if the snapshot fails.
pub(crate) fn processes() -> Vec<(u32, u32, String)> {
    let mut found = Vec::new();
    // SAFETY: Toolhelp snapshot walk with a properly sized entry; the snapshot handle is closed.
    unsafe {
        let Ok(snap) = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0) else { return found };
        let mut e = PROCESSENTRY32W { dwSize: std::mem::size_of::<PROCESSENTRY32W>() as u32, ..Default::default() };
        let mut ok = Process32FirstW(snap, &mut e).is_ok();
        while ok {
            let n = e.szExeFile.iter().position(|&c| c == 0).unwrap_or(e.szExeFile.len());
            found.push((e.th32ProcessID, e.th32ParentProcessID, String::from_utf16_lossy(&e.szExeFile[..n])));
            ok = Process32NextW(snap, &mut e).is_ok();
        }
        let _ = CloseHandle(snap);
    }
    found
}

/// Adds processes whose parent is tracked and which were created after it (and, if the parent already exited,
/// before it exited). Returns whether anything new was added.
fn add_descendants(t: &mut Vec<Tracked>) -> bool {
    let mut added = false;
    for (pid, ppid, image) in processes() {
        if t.iter().any(|p| p.pid == pid) {
            continue;
        }
        let Some(parent) = t.iter().find(|p| p.pid == ppid) else { continue };
        let (pcreated, pexited) = (parent.created, parent.exited);
        // SAFETY: opens a process for synchronisation and limited queries; works on elevated children too.
        let Ok(h) = (unsafe { OpenProcess(PROCESS_SYNCHRONIZE | PROCESS_QUERY_LIMITED_INFORMATION, false, pid) }) else { continue };
        let Some(child) = track(pid, h, image) else { continue };
        let ok = child.created >= pcreated && pexited.is_none_or(|x| child.created <= x);
        if ok {
            t.push(child);
            added = true;
        }
    }
    added
}

fn info<'a>(t: impl Iterator<Item = &'a Tracked>) -> Vec<ProcInfo> {
    t.map(|p| ProcInfo { pid: p.pid, image: p.image.clone(), created: p.created, exit_code: p.exit_code }).collect()
}

fn wide(s: &std::ffi::OsStr) -> Vec<u16> {
    s.encode_wide().chain(std::iter::once(0)).collect()
}

pub fn run_uninstaller(launch: &Launch, opts: &RunOptions) -> NativeRun {
    let mut run = NativeRun { started_ms: now_ms(), ..Default::default() };
    let _com = ComGuard::new();
    let file = wide(launch.exe.as_os_str());
    let params = wide(std::ffi::OsStr::new(&launch.args));
    let dir = launch.exe.parent().map(|p| wide(p.as_os_str()));
    let mut sei = SHELLEXECUTEINFOW {
        cbSize: std::mem::size_of::<SHELLEXECUTEINFOW>() as u32,
        fMask: SEE_MASK_NOCLOSEPROCESS | SEE_MASK_NOASYNC | SEE_MASK_FLAG_NO_UI,
        lpVerb: w!("open"),
        lpFile: PCWSTR(file.as_ptr()),
        lpParameters: if launch.args.is_empty() { PCWSTR::null() } else { PCWSTR(params.as_ptr()) },
        lpDirectory: dir.as_ref().map_or(PCWSTR::null(), |d| PCWSTR(d.as_ptr())),
        nShow: if opts.show_window { SW_SHOWNORMAL.0 } else { SW_HIDE.0 },
        ..Default::default()
    };
    // SAFETY: all string buffers outlive the call.
    if let Err(e) = unsafe { ShellExecuteExW(&mut sei) } {
        run.launch_error = Some(if (e.code().0 as u32 & 0xFFFF) == 1223 { "cancelled at UAC prompt".to_string() } else { e.message() });
        run.ended_ms = now_ms();
        return run;
    }
    if sei.hProcess.is_invalid() {
        run.launch_error = Some("no process handle".into());
        run.ended_ms = now_ms();
        return run;
    }
    // SAFETY: a valid process handle returned by ShellExecuteExW.
    let pid = unsafe { GetProcessId(sei.hProcess) };
    let image = launch.exe.file_name().map(|n| n.to_string_lossy().to_string()).unwrap_or_default();
    let Some(root) = track(pid, sei.hProcess, image) else {
        run.launch_error = Some("cannot query the process".into());
        run.ended_ms = now_ms();
        return run;
    };
    let mut tracked = vec![root];
    let start = Instant::now();
    loop {
        mark_exits(&mut tracked);
        add_descendants(&mut tracked);
        mark_exits(&mut tracked);
        if let Some(cb) = &opts.on_poll {
            let live = info(tracked.iter().filter(|p| p.exited.is_none()));
            cb(&live);
        }
        if tracked.iter().all(|p| p.exited.is_some()) {
            // A final look: NSIS-style launchers start the real uninstaller and exit.
            if !add_descendants(&mut tracked) {
                break;
            }
            continue;
        }
        if opts.stop.load(Ordering::Relaxed) {
            run.stopped_by_user = true;
            break;
        }
        if start.elapsed() >= opts.timeout {
            run.timed_out = true;
            break;
        }
        std::thread::sleep(opts.poll);
    }
    run.exit_code = tracked[0].exit_code;
    run.reboot_required = reboot_required(run.exit_code);
    run.processes = info(tracked.iter());
    run.ended_ms = now_ms();
    run
}

/// True while the recorded process is still running (same PID and creation time).
pub fn alive(p: &ProcInfo) -> bool {
    // SAFETY: opens, queries and closes a process handle.
    unsafe {
        let Ok(h) = OpenProcess(PROCESS_SYNCHRONIZE | PROCESS_QUERY_LIMITED_INFORMATION, false, p.pid) else { return false };
        let same = times(h).is_some_and(|(c, _)| c == p.created);
        let running = WaitForSingleObject(h, 0) == WAIT_TIMEOUT;
        let _ = CloseHandle(h);
        same && running
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reboot_codes() {
        assert!(reboot_required(Some(3010)));
        assert!(reboot_required(Some(1641)));
        assert!(!reboot_required(Some(0)));
        assert!(!reboot_required(Some(1602)));
        assert!(!reboot_required(None));
    }
}
