//! Administrator rights: detection and a "restart as administrator" helper.
// shortcut: once accepted, the whole UI is elevated and there is no privilege separation, upgrade to a narrow
// elevated helper with structured commands in stage 2.
// shortcut: elevating with a different admin account changes %LOCALAPPDATA%, so history appears empty there;
// fixed by the stage-2 helper.
use crate::{Error, Result};
use std::os::windows::ffi::OsStrExt;
use windows::Win32::Foundation::{CloseHandle, HANDLE};
use windows::Win32::Security::{GetTokenInformation, TOKEN_ELEVATION, TOKEN_QUERY, TokenElevation};
use windows::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};
use windows::Win32::UI::Shell::{SHELLEXECUTEINFOW, ShellExecuteExW};
use windows::Win32::UI::WindowsAndMessaging::SW_SHOWNORMAL;
use windows::core::{PCWSTR, w};

pub fn is_elevated() -> bool {
    // SAFETY: token handle is opened, queried and closed here.
    unsafe {
        let mut token = HANDLE::default();
        if OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token).is_err() {
            return false;
        }
        let mut e = TOKEN_ELEVATION::default();
        let mut len = 0u32;
        let ok = GetTokenInformation(token, TokenElevation, Some(&mut e as *mut _ as *mut _), std::mem::size_of::<TOKEN_ELEVATION>() as u32, &mut len).is_ok();
        let _ = CloseHandle(token);
        ok && e.TokenIsElevated != 0
    }
}

/// Starts this exe again with the `runas` verb (UAC prompt). The caller exits afterwards.
pub fn relaunch_elevated() -> Result<()> {
    let exe = std::env::current_exe()?;
    let file: Vec<u16> = exe.as_os_str().encode_wide().chain(Some(0)).collect();
    let mut sei = SHELLEXECUTEINFOW {
        cbSize: std::mem::size_of::<SHELLEXECUTEINFOW>() as u32,
        lpVerb: w!("runas"),
        lpFile: PCWSTR(file.as_ptr()),
        nShow: SW_SHOWNORMAL.0,
        ..Default::default()
    };
    // SAFETY: the file buffer outlives the call.
    unsafe { ShellExecuteExW(&mut sei) }.map_err(|e| Error(if (e.code().0 as u32 & 0xFFFF) == 1223 { "cancelled at UAC prompt".into() } else { e.message() }))
}
