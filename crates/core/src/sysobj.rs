//! Windows services and scheduled tasks as leftovers: readers (read-only) and the system calls that remove or recreate them.
//!
//! On the real system services are read from `Env.services` (the registry) and the Service Control Manager (`QueryServiceStatus`),
//! tasks through the Task Scheduler 2.0 COM API. In a sandbox both live under the sandbox registry key: a service is
//! `env.services\<name>` (the same layout as the real Services keys, so one reader serves both) and a task is a key
//! `env.tasks\<folder>\<name>` with the values `Xml`, `Actions` (multi-string), `Other` and `Enabled`.
//! Every destructive function branches on `env.sandbox` at the bottom (the house pattern); the real branch is unreachable from tests
//! on the host and runs only through the Windows Sandbox lab.
use crate::command::split_command;
use crate::env::Env;
use crate::model::*;
use crate::registry::{self, expand_env, read_dword};
use std::io;
use std::path::{Path, PathBuf};
use winreg::RegKey;
use winreg::RegValue;
use winreg::enums::*;

/// `Type & TYPE_DRIVERS`: kernel and file-system drivers.
pub const TYPE_DRIVERS: u32 = 0x0F;
/// `Type & TYPE_WIN32`: own-process and shared-process services.
pub const TYPE_WIN32: u32 = 0x30;
/// `Type & TYPE_USER`: per-user services (user-own, user-share).
pub const TYPE_USER: u32 = 0xC0;
/// Why a removed service is still listed: the SCM only marked it for deletion.
pub const DEFERRED: &str = "marked for deletion: Windows removes it when the last open handle closes, at the latest after a restart";

/// A service as the registry says it (one key under `Services`).
#[derive(Debug, Clone, PartialEq)]
pub struct Svc {
    pub name: String,
    /// `Type`, 0 when missing.
    pub kind: u32,
    /// `ImagePath`, normalised by `image_text` (empty when missing).
    pub image: String,
    /// `Parameters\ServiceDll` (svchost services), normalised.
    pub dll: Option<String>,
    pub group: Option<String>,
    /// `DependOnService` names and `DependOnGroup` names prefixed with `+`.
    pub depends: Vec<String>,
    /// `DeleteFlag` = 1: the SCM removes the key when the last handle closes.
    pub marked: bool,
}

/// A scheduled task: its path (`\Vendor\Name`), the command line of every exec action, the number of other actions
/// (COM handlers, e-mail, message boxes) and whether it is enabled.
#[derive(Debug, Clone, PartialEq)]
pub struct Task {
    pub path: String,
    pub actions: Vec<String>,
    pub other: u32,
    pub enabled: bool,
}

fn io_err(e: windows::core::Error) -> io::Error {
    let c = e.code().0 as u32;
    if c >> 16 == 0x8007 { io::Error::from_raw_os_error((c & 0xFFFF) as i32) } else { io::Error::other(e.message()) }
}

fn utf16(bytes: &[u8]) -> String {
    let u: Vec<u16> = bytes.as_chunks::<2>().0.iter().map(|c| u16::from_le_bytes(*c)).collect();
    String::from_utf16_lossy(&u)
}

fn multi_text(vtype: RegType, bytes: &[u8]) -> Vec<String> {
    if !matches!(vtype, RegType::REG_MULTI_SZ | RegType::REG_SZ) {
        return vec![];
    }
    utf16(bytes).split('\0').filter(|s| !s.is_empty()).map(str::to_string).collect()
}

fn multi(k: &RegKey, name: &str) -> Vec<String> {
    k.get_raw_value(name).map(|v| multi_text(v.vtype, &v.bytes)).unwrap_or_default()
}

pub(crate) fn check_name(name: &str) -> io::Result<()> {
    if name.is_empty() || name.len() > 256 || name.contains(['\\', '/']) {
        return Err(io::Error::other("invalid service name"));
    }
    Ok(())
}

pub(crate) fn check_path(path: &str) -> io::Result<()> {
    let bad = !path.starts_with('\\') || path[1..].split('\\').any(|c| c.is_empty() || c == "." || c == "..") || path.len() > 520;
    if bad {
        return Err(io::Error::other("invalid task path"));
    }
    Ok(())
}

/// The program text of a service as a path: environment expanded, `\??\` and `\\?\` prefixes dropped (also right after an opening
/// quote), `\SystemRoot\...` and a relative `system32\...` turned into the Windows folder. Pure apart from the expansion.
// shortcut: `%VAR%` expands in our environment, and another user's per-user paths are matched against ours; read each user's environment
// in stage 2.
pub fn image_text(raw: &str, windows_dir: &Path) -> String {
    let s = expand_env(raw);
    let s = s.trim();
    let (quote, rest) = match s.strip_prefix('"') {
        Some(r) => ("\"", r),
        None => ("", s),
    };
    let lower = rest.to_lowercase();
    let win = windows_dir.display().to_string();
    let win = win.trim_end_matches('\\');
    let rest = if lower.starts_with(r"\??\") || lower.starts_with(r"\\?\") && !lower.starts_with(r"\\?\unc\") {
        rest[4..].to_string()
    } else if lower.starts_with(r"\systemroot\") {
        format!("{win}\\{}", &rest[12..])
    } else if lower.starts_with(r"system32\") {
        format!("{win}\\{rest}")
    } else {
        rest.to_string()
    };
    format!("{quote}{rest}")
}

/// The program a service runs: its ServiceDll, else the exe `split_command` finds in its command line (a bare name resolves to System32),
/// else the command line's first token (quoted, or up to the first space) when no such file exists (a removed program).
pub fn service_binary(s: &Svc, system_dir: &Path) -> PathBuf {
    if let Some(d) = &s.dll {
        return PathBuf::from(d.trim().trim_matches('"'));
    }
    if let Ok((exe, _)) = split_command(&s.image, system_dir, &|p| p.is_file()) {
        return exe;
    }
    let t = s.image.trim();
    PathBuf::from(match t.strip_prefix('"') {
        Some(r) => r.split('"').next().unwrap_or(r),
        None => t.split(' ').next().unwrap_or(t),
    })
}

/// True when the first component of the task path is `Microsoft` (any case): Windows' own tasks. Compared by component, so
/// `\Microsoft Office\x` is not Windows'.
pub fn is_windows_task(path: &str) -> bool {
    path.trim_start_matches('\\').split('\\').next().is_some_and(|c| c.eq_ignore_ascii_case("Microsoft"))
}

fn dword(v: &RegVal) -> Option<u32> {
    (v.kind == 4 && v.data.len() == 4).then(|| u32::from_le_bytes([v.data[0], v.data[1], v.data[2], v.data[3]]))
}

fn node_text(n: &RegNode, name: &str) -> Option<String> {
    let v = n.values.iter().find(|v| v.name.eq_ignore_ascii_case(name))?;
    matches!(v.kind, 1 | 2).then(|| utf16(&v.data).trim_end_matches('\0').to_string())
}

/// A `Svc` from a captured key (a backup): the same fields `read_svc` reads from the live key; no dependencies, never marked.
pub fn svc_of_node(name: &str, node: &RegNode, windows_dir: &Path) -> Svc {
    let kind = node.values.iter().find(|v| v.name.eq_ignore_ascii_case("Type")).and_then(dword).unwrap_or(0);
    let dll = node.keys.iter().find(|k| k.name.eq_ignore_ascii_case("Parameters")).and_then(|p| node_text(p, "ServiceDll")).map(|d| image_text(&d, windows_dir));
    Svc {
        name: name.to_string(),
        kind,
        image: node_text(node, "ImagePath").map(|i| image_text(&i, windows_dir)).unwrap_or_default(),
        dll,
        group: node_text(node, "Group").filter(|g| !g.is_empty()),
        depends: vec![],
        marked: false,
    }
}

fn read_svc(name: &str, k: &RegKey, windows_dir: &Path) -> Svc {
    let dll = k
        .open_subkey_with_flags("Parameters", KEY_READ)
        .ok()
        .and_then(|p| registry::read_string(&p, "ServiceDll", false))
        .map(|d| image_text(&d, windows_dir));
    let mut depends = multi(k, "DependOnService");
    depends.extend(multi(k, "DependOnGroup").into_iter().map(|g| format!("+{g}")));
    Svc {
        name: name.to_string(),
        kind: read_dword(k, "Type").unwrap_or(0),
        image: registry::read_string(k, "ImagePath", false).map(|i| image_text(&i, windows_dir)).unwrap_or_default(),
        dll,
        group: registry::read_string(k, "Group", false).filter(|g| !g.is_empty()),
        depends,
        marked: read_dword(k, "DeleteFlag") == Some(1),
    }
}

/// Every service key under `Env.services` (marked ones included) and how many keys could not be opened (skipped).
fn read_services(env: &Env) -> io::Result<(Vec<Svc>, usize)> {
    let root = match registry::open(&env.services, KEY_READ) {
        Ok(k) => k,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok((vec![], 0)),
        Err(e) => return Err(io::Error::new(e.kind(), format!("cannot read the services: {e}"))),
    };
    let (mut out, mut unreadable) = (Vec::new(), 0);
    for name in root.enum_keys() {
        let Ok(name) = name else {
            unreadable += 1;
            continue;
        };
        match root.open_subkey_with_flags(&name, KEY_READ) {
            Ok(k) => out.push(read_svc(&name, &k, &env.folders.windows_dir)),
            Err(_) => unreadable += 1,
        }
    }
    Ok((out, unreadable))
}

/// Lenient: detection and force rule 11 (a key we cannot open is not offered).
// shortcut: each scan enumerates all services and tasks once; cache them per session if previews get slow (timings in docs/services.md).
pub fn services(env: &Env) -> io::Result<Vec<Svc>> {
    read_services(env).map(|x| x.0)
}

/// Strict: a service is offered only when every other key could be read (fail closed).
// shortcut: any dependent blocks, including one of the same program and a group dependency; remove the program that owns the dependent
// first. After a first apply the operation offers no rescan.
pub fn dependents(env: &Env, s: &Svc) -> io::Result<Vec<String>> {
    let (all, unreadable) = read_services(env)?;
    dependents_of(&all, unreadable, s)
}

/// Pure: names of non-marked services that depend on `s` by name (DependOnService) or on its group (DependOnGroup, stored as `+group`).
fn dependents_of(all: &[Svc], unreadable: usize, s: &Svc) -> io::Result<Vec<String>> {
    if unreadable > 0 {
        return Err(io::Error::other(format!("{unreadable} service keys cannot be read")));
    }
    Ok(all
        .iter()
        .filter(|o| !o.marked && !o.name.eq_ignore_ascii_case(&s.name))
        .filter(|o| {
            o.depends.iter().any(|d| d.eq_ignore_ascii_case(&s.name) || s.group.as_deref().is_some_and(|g| d.strip_prefix('+').is_some_and(|x| x.eq_ignore_ascii_case(g))))
        })
        .map(|o| o.name.clone())
        .collect())
}

/// One service, `None` when its key is absent or marked for deletion.
pub fn service(env: &Env, name: &str) -> io::Result<Option<Svc>> {
    check_name(name)?;
    match registry::open(&env.services.child(name), KEY_READ) {
        Ok(k) => Ok(Some(read_svc(name, &k, &env.folders.windows_dir)).filter(|s| !s.marked)),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(e),
    }
}

/// Whether the service is not stopped. Sandbox stand-ins never run.
pub fn running(env: &Env, name: &str) -> io::Result<bool> {
    check_name(name)?;
    if env.sandbox {
        return Ok(false);
    }
    real::running(name)
}

/// Every task the scheduler lists (hidden ones too). Errors of single tasks and folders are skipped.
pub fn tasks(env: &Env) -> io::Result<Vec<Task>> {
    let mut out = match &env.tasks {
        Some(root) => stand_in_tasks(root)?,
        None => real::tasks().map_err(io_err)?,
    };
    out.sort_by_key(|t| t.path.to_lowercase());
    Ok(out)
}

/// One task and its XML, `None` when it does not exist.
pub fn task(env: &Env, path: &str) -> io::Result<Option<(Task, String)>> {
    check_path(path)?;
    match &env.tasks {
        Some(root) => stand_in_task(root, path),
        None => real::task(path).map_err(io_err),
    }
}

// ---------- sandbox stand-ins ----------

fn stand_in_key(root: &RegPath, path: &str) -> RegPath {
    path.split('\\').filter(|c| !c.is_empty()).fold(root.clone(), |k, c| k.child(c))
}

fn task_of_key(path: &str, k: &RegKey) -> Option<(Task, String)> {
    let xml = registry::read_string(k, "Xml", false)?;
    let actions = multi(k, "Actions");
    let task = Task { path: path.to_string(), actions, other: read_dword(k, "Other").unwrap_or(0), enabled: read_dword(k, "Enabled").unwrap_or(1) != 0 };
    Some((task, xml))
}

fn stand_in_task(root: &RegPath, path: &str) -> io::Result<Option<(Task, String)>> {
    match registry::open(&stand_in_key(root, path), KEY_READ) {
        Ok(k) => Ok(task_of_key(path, &k)),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(e),
    }
}

fn stand_in_tasks(root: &RegPath) -> io::Result<Vec<Task>> {
    fn walk(k: &RegKey, folder: &str, out: &mut Vec<Task>) {
        for n in k.enum_keys().flatten() {
            let Ok(sub) = k.open_subkey_with_flags(&n, KEY_READ) else { continue };
            let path = format!("{folder}\\{n}");
            match task_of_key(&path, &sub) {
                Some((t, _)) => out.push(t),
                None => walk(&sub, &path, out),
            }
        }
    }
    let k = match registry::open(root, KEY_READ) {
        Ok(k) => k,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(vec![]),
        Err(e) => return Err(e),
    };
    let mut out = Vec::new();
    walk(&k, "", &mut out);
    Ok(out)
}

/// Writes a task stand-in under the sandbox's task key (seed and tests). Refuses a real environment. The XML is a fixed comment: the
/// stand-in has no scheduler behind it.
pub fn sandbox_task(env: &Env, path: &str, actions: &[String], other: u32) -> crate::Result<()> {
    let Some(root) = env.tasks.as_ref().filter(|_| env.sandbox) else { return Err("task stand-ins exist only in a sandbox".into()) };
    check_path(path)?;
    Ok(write_stand_in(root, path, &format!("<Task><!-- sandbox stand-in: {path} --></Task>"), actions, other, true)?)
}

fn write_stand_in(root: &RegPath, path: &str, xml: &str, actions: &[String], other: u32, enabled: bool) -> io::Result<()> {
    let k = registry::create(&stand_in_key(root, path), KEY_ALL_ACCESS)?;
    registry::set_string(&k, "Xml", xml, false)?;
    let mut bytes: Vec<u8> = actions.iter().flat_map(|a| a.encode_utf16().chain(Some(0))).flat_map(u16::to_le_bytes).collect();
    bytes.extend([0, 0]);
    k.set_raw_value("Actions", &RegValue { bytes: std::borrow::Cow::Owned(bytes), vtype: RegType::REG_MULTI_SZ })?;
    registry::set_dword(&k, "Other", other)?;
    registry::set_dword(&k, "Enabled", u32::from(enabled))
}

// ---------- removing and recreating ----------
// Callers: `ops::apply` and `ops::restore` only, both behind `ops::guard`. The real branches never run in a debug build and, in a
// release build, are exercised only inside Windows Sandbox through the lab (`lab/lab.ps1`).

/// A real service or task is never changed by a debug build, whatever the caller does (tests and `tauri dev` run in debug).
fn real_guard() -> io::Result<()> {
    if cfg!(debug_assertions) {
        return Err(io::Error::other("debug build: real services and tasks are never changed"));
    }
    Ok(())
}

/// How long a running service is given to stop.
// shortcut: the stop waits 30 s with no stop button and never kills; a service that does not stop ends Locked. Add Restart Manager or a
// "stop waiting" button when users meet one.
const STOP_WAIT: std::time::Duration = std::time::Duration::from_secs(30);

/// Stops the service if it runs (never kills it: after `STOP_WAIT` the call fails with 1053 and nothing is deleted) and deletes it
/// through the Service Control Manager. Returns true when the SCM only marked it for deletion and the key is still there.
// shortcut: a service the SCM only marked for deletion ends `Removed` with the `DEFERRED` detail; there is no per-item PendingReboot status.
pub fn remove_service(env: &Env, name: &str) -> io::Result<bool> {
    check_name(name)?;
    if env.sandbox {
        registry::delete_key(&env.services.child(name))?;
        return Ok(false);
    }
    real_guard()?;
    real::remove_service(name, &env.services.child(name))
}

/// Deletes the task through the Task Scheduler (its emptied folder stays).
// shortcut: emptied task folders, the TaskCache tree entry and the svchost group list entries stay.
pub fn delete_task(env: &Env, path: &str) -> io::Result<()> {
    check_path(path)?;
    match &env.tasks {
        Some(root) if env.sandbox => registry::delete_key(&stand_in_key(root, path)),
        _ => {
            real_guard()?;
            real::delete_task(path).map_err(io_err)
        }
    }
}

type Restored = (RestoreStatus, Option<String>);

/// Names of the values (and "subkeys") in which two captures of a service key differ.
fn differs(a: &RegNode, b: &RegNode) -> Vec<String> {
    let find = |n: &RegNode, name: &str| n.values.iter().find(|v| v.name.eq_ignore_ascii_case(name)).cloned();
    let mut out: Vec<String> = a.values.iter().chain(&b.values).filter(|v| find(a, &v.name) != find(b, &v.name)).map(|v| v.name.clone()).collect();
    out.dedup();
    if a.keys != b.keys {
        out.push("(subkeys)".into());
    }
    out
}

/// Recreates a service from its key backup: `CreateServiceW` for the fields the SCM owns, then the key's values and subkeys are merged
/// back (existing values are kept, so the exact bytes land), then the key is compared with the backup. Nothing is started.
// shortcut: restore sets only the CreateServiceW fields and delayed start through the API; the other values (description, failure
// actions, triggers, parameters, security descriptor) are written into the key and apply at the latest after a restart. Account
// passwords are not restored.
pub fn recreate_service(env: &Env, name: &str, node: &RegNode) -> Restored {
    let fail = |m: String| (RestoreStatus::Failed, Some(m));
    if let Err(e) = check_name(name) {
        return fail(e.to_string());
    }
    let key = env.services.child(name);
    match registry::open(&key, KEY_READ) {
        Ok(k) => {
            if read_dword(&k, "DeleteFlag") == Some(1) {
                return fail("the removed service is still marked for deletion; restart Windows and restore again".into());
            }
            return match registry::capture(&key) {
                Ok(now) if &now == node => (RestoreStatus::Restored, None),
                Ok(_) => (RestoreStatus::Conflict, Some("a service with this name exists again; it was not changed".into())),
                Err(e) => fail(e.to_string()),
            };
        }
        Err(e) if e.kind() == io::ErrorKind::NotFound => {}
        Err(e) => return fail(e.to_string()),
    }
    let made = if env.sandbox {
        Ok(())
    } else {
        real_guard().and_then(|()| real::create_service(name, node))
    };
    match made {
        Ok(()) => {}
        Err(e) if matches!(e.raw_os_error(), Some(1073 | 1078)) => return (RestoreStatus::Conflict, Some("a service with this name exists again; it was not changed".into())),
        Err(e) if e.raw_os_error() == Some(1072) => return fail("the removed service is still marked for deletion; restart Windows and restore again".into()),
        Err(e) => return fail(e.to_string()),
    }
    if let Err(e) = registry::restore_node(&key, node) {
        return fail(e.to_string());
    }
    match registry::capture(&key) {
        Ok(now) if &now == node => {
            let account = node_text(node, "ObjectName").filter(|a| !a.eq_ignore_ascii_case("LocalSystem") && !a.to_uppercase().starts_with("NT AUTHORITY\\") && !a.to_uppercase().starts_with("NT SERVICE\\"));
            (RestoreStatus::Restored, account.map(|a| format!("recreated; set the password of account {a} again")))
        }
        // shortcut: a recreated service or task that differs from its backup ends Conflict although it exists again.
        Ok(now) => {
            let d: Vec<String> = differs(node, &now).into_iter().take(3).collect();
            (RestoreStatus::Conflict, Some(format!("recreated, but it differs from the backup in: {}", d.join(", "))))
        }
        Err(e) => fail(e.to_string()),
    }
}

/// The first differing line of two task definitions, each cut to 120 characters.
fn first_diff(a: &str, b: &str) -> String {
    let cut = |s: &str| s.chars().take(120).collect::<String>();
    let (mut x, mut y) = (a.lines(), b.lines());
    loop {
        match (x.next(), y.next()) {
            (Some(p), Some(q)) if p == q => {}
            (None, None) => return "(line endings or trailing text)".into(),
            (p, q) => return format!("backup `{}` now `{}`", cut(p.unwrap_or("")), cut(q.unwrap_or(""))),
        }
    }
}

/// Recreates a task from its backup XML through `RegisterTask` (the XML is registered as it is). A task that ran with a stored
/// password cannot be recreated. The live definition is compared with the backup afterwards.
// shortcut: tasks with a stored password cannot be recreated, and a task's security descriptor is not backed up.
pub fn recreate_task(env: &Env, path: &str, xml: &str, actions: &[String], enabled: bool) -> Restored {
    let fail = |m: String| (RestoreStatus::Failed, Some(m));
    if let Err(e) = check_path(path) {
        return fail(e.to_string());
    }
    match task(env, path) {
        Ok(Some((_, live))) if live == xml => return (RestoreStatus::Restored, None),
        Ok(Some(_)) => return (RestoreStatus::Conflict, Some("a task with this name exists again; it was not changed".into())),
        Ok(None) => {}
        Err(e) => return fail(e.to_string()),
    }
    let conflict = || (RestoreStatus::Conflict, Some("a task with this name exists again; it was not changed".into()));
    match &env.tasks {
        Some(root) if env.sandbox => {
            if let Err(e) = write_stand_in(root, path, xml, actions, 0, enabled) {
                return fail(e.to_string());
            }
        }
        _ => match real_guard().and_then(|()| real::create_task(path, xml).map_err(io_err)) {
            Ok(real::Made::Done) => {}
            Ok(real::Made::Password) => return fail("the task runs with a stored password; recreate it by hand from the backup in the operation's manifest".into()),
            Ok(real::Made::Exists) => return conflict(),
            Err(e) => return fail(e.to_string()),
        },
    }
    match task(env, path) {
        Ok(Some((_, live))) if live == xml => (RestoreStatus::Restored, None),
        Ok(Some((_, live))) => (RestoreStatus::Conflict, Some(format!("recreated, but its definition differs from the backup: {}", first_diff(xml, &live)))),
        Ok(None) => fail("the task was not found after it was created".into()),
        Err(e) => fail(e.to_string()),
    }
}

// ---------- the real system ----------

mod real {
    use super::*;
    use crate::shortcuts::ComGuard;
    use windows::Win32::System::Com::{CLSCTX_INPROC_SERVER, CoCreateInstance};
    use windows::Win32::System::Services::*;
    use windows::Win32::System::TaskScheduler::*;
    use windows::Win32::System::Variant::VARIANT;
    use windows::core::{BSTR, Interface, PCWSTR};

    fn wide(s: &str) -> Vec<u16> {
        s.encode_utf16().chain(Some(0)).collect()
    }

    /// RAII for an SCM or service handle.
    struct Sc(SC_HANDLE);
    impl Drop for Sc {
        fn drop(&mut self) {
            // SAFETY: the handle came from OpenSCManagerW or OpenServiceW and is closed exactly once.
            unsafe {
                let _ = CloseServiceHandle(self.0);
            }
        }
    }

    pub fn running(name: &str) -> io::Result<bool> {
        let n = wide(name);
        // SAFETY: `n` is NUL-terminated and outlives the calls; the handles are closed by `Sc`.
        unsafe {
            let scm = Sc(OpenSCManagerW(PCWSTR::null(), PCWSTR::null(), SC_MANAGER_CONNECT).map_err(io_err)?);
            let svc = Sc(OpenServiceW(scm.0, PCWSTR(n.as_ptr()), SERVICE_QUERY_STATUS).map_err(io_err)?);
            let mut st = SERVICE_STATUS::default();
            QueryServiceStatus(svc.0, &mut st).map_err(io_err)?;
            Ok(st.dwCurrentState != SERVICE_STOPPED)
        }
    }

    fn scheduler() -> windows::core::Result<ITaskService> {
        // SAFETY: plain COM activation of the in-process Task Scheduler proxy; Connect with empty arguments is the local machine.
        unsafe {
            let s: ITaskService = CoCreateInstance(&TaskScheduler, None, CLSCTX_INPROC_SERVER)?;
            s.Connect(&VARIANT::default(), &VARIANT::default(), &VARIANT::default(), &VARIANT::default())?;
            Ok(s)
        }
    }

    /// The task and its exec action command lines; `None` when its definition cannot be read.
    fn describe(t: &IRegisteredTask) -> Option<Task> {
        // SAFETY: COM calls on live interfaces owned by this thread's apartment.
        unsafe {
            let path = t.Path().ok()?.to_string();
            let enabled = t.Enabled().ok()?.as_bool();
            let acts = t.Definition().ok()?.Actions().ok()?;
            let mut n = 0;
            acts.Count(&mut n).ok()?;
            let (mut actions, mut other) = (Vec::new(), 0);
            for i in 1..=n {
                let a = acts.get_Item(i).ok()?;
                let mut kind = TASK_ACTION_TYPE(0);
                a.Type(&mut kind).ok()?;
                if kind != TASK_ACTION_EXEC {
                    other += 1;
                    continue;
                }
                let e: IExecAction = a.cast().ok()?;
                let (mut p, mut args) = (BSTR::new(), BSTR::new());
                e.Path(&mut p).ok()?;
                e.Arguments(&mut args).ok()?;
                actions.push(expand_env(&format!("{p} {args}")).trim().to_string());
            }
            Some(Task { path, actions, other, enabled })
        }
    }

    pub fn tasks() -> windows::core::Result<Vec<Task>> {
        let _com = ComGuard::new();
        let svc = scheduler()?;
        let mut out = Vec::new();
        // SAFETY: COM calls on live interfaces owned by this thread's apartment.
        unsafe {
            let mut stack = vec![svc.GetFolder(&BSTR::from("\\"))?];
            while let Some(f) = stack.pop() {
                if let Ok(ts) = f.GetTasks(TASK_ENUM_HIDDEN.0) {
                    let n = ts.Count().unwrap_or(0);
                    for i in 1..=n {
                        if let Some(t) = ts.get_Item(&VARIANT::from(i)).ok().and_then(|t| describe(&t)) {
                            out.push(t);
                        }
                    }
                }
                if let Ok(subs) = f.GetFolders(0) {
                    let n = subs.Count().unwrap_or(0);
                    stack.extend((1..=n).filter_map(|i| subs.get_Item(&VARIANT::from(i)).ok()));
                }
            }
        }
        Ok(out)
    }

    pub fn remove_service(name: &str, key: &RegPath) -> io::Result<bool> {
        use std::time::{Duration, Instant};
        let n = wide(name);
        // SAFETY: `n` is NUL-terminated and outlives the calls; the handles are closed by `Sc`. Nothing is killed: a service that
        // does not stop within STOP_WAIT is left alone and the call fails.
        unsafe {
            let scm = Sc(OpenSCManagerW(PCWSTR::null(), PCWSTR::null(), SC_MANAGER_CONNECT).map_err(io_err)?);
            let svc = match OpenServiceW(scm.0, PCWSTR(n.as_ptr()), SERVICE_STOP | SERVICE_QUERY_STATUS | 0x0001_0000 /* DELETE */) {
                Ok(h) => Sc(h),
                Err(e) => {
                    let e = io_err(e);
                    // 1060: the SCM does not know it. Gone for real only when its key is gone too.
                    return Err(if e.raw_os_error() == Some(1060) && !registry::exists(key) { io::Error::from_raw_os_error(2) } else { e });
                }
            };
            let mut st = SERVICE_STATUS::default();
            QueryServiceStatus(svc.0, &mut st).map_err(io_err)?;
            if st.dwCurrentState != SERVICE_STOPPED {
                if let Err(e) = ControlService(svc.0, SERVICE_CONTROL_STOP, &mut st) {
                    let e = io_err(e);
                    if e.raw_os_error() != Some(1062) {
                        return Err(e);
                    }
                }
                let deadline = Instant::now() + super::STOP_WAIT;
                loop {
                    QueryServiceStatus(svc.0, &mut st).map_err(io_err)?;
                    if st.dwCurrentState == SERVICE_STOPPED {
                        break;
                    }
                    if Instant::now() >= deadline {
                        return Err(io::Error::from_raw_os_error(1053));
                    }
                    std::thread::sleep(Duration::from_millis(250));
                }
            }
            DeleteService(svc.0).map_err(io_err)?;
            drop(svc);
            drop(scm);
        }
        for _ in 0..10 {
            if !registry::exists(key) {
                return Ok(false);
            }
            std::thread::sleep(std::time::Duration::from_millis(100));
        }
        Ok(true)
    }

    pub fn create_service(name: &str, node: &RegNode) -> io::Result<()> {
        let val = |n: &str| node.values.iter().find(|v| v.name.eq_ignore_ascii_case(n));
        let num = |n: &str, default: u32| val(n).and_then(super::dword).unwrap_or(default);
        let text = |n: &str| node_text(node, n).filter(|t| !t.is_empty());
        let list = |n: &str| val(n).and_then(|v| registry::to_regtype(v.kind).map(|t| multi_text(t, &v.data))).unwrap_or_default();
        let image = text("ImagePath").ok_or_else(|| io::Error::other("the backup has no ImagePath"))?;
        let (n, img) = (wide(name), wide(&image));
        let display = text("DisplayName").map(|d| wide(&d));
        let group = text("Group").map(|g| wide(&g));
        let account = text("ObjectName").map(|a| wide(&a));
        let mut deps: Vec<u16> = list("DependOnService").into_iter().chain(list("DependOnGroup").into_iter().map(|g| format!("+{g}"))).flat_map(|d| d.encode_utf16().chain(Some(0)).collect::<Vec<u16>>()).collect();
        if !deps.is_empty() {
            deps.push(0);
        }
        let opt = |v: &Option<Vec<u16>>| v.as_ref().map_or(PCWSTR::null(), |w| PCWSTR(w.as_ptr()));
        // SAFETY: every buffer is NUL-terminated (the dependency list is double-NUL-terminated) and outlives the call; the handles are
        // closed by `Sc`. The password is None: an account other than a built-in one needs it set again by hand.
        unsafe {
            let scm = Sc(OpenSCManagerW(PCWSTR::null(), PCWSTR::null(), SC_MANAGER_CONNECT | SC_MANAGER_CREATE_SERVICE).map_err(io_err)?);
            let svc = Sc(CreateServiceW(
                scm.0,
                PCWSTR(n.as_ptr()),
                opt(&display),
                SERVICE_ALL_ACCESS,
                ENUM_SERVICE_TYPE(num("Type", 0x10)),
                SERVICE_START_TYPE(num("Start", 3)),
                SERVICE_ERROR(num("ErrorControl", 1)),
                PCWSTR(img.as_ptr()),
                opt(&group),
                None,
                if deps.is_empty() { PCWSTR::null() } else { PCWSTR(deps.as_ptr()) },
                opt(&account),
                PCWSTR::null(),
            )
            .map_err(io_err)?);
            if num("DelayedAutostart", 0) == 1 {
                let info = SERVICE_DELAYED_AUTO_START_INFO { fDelayedAutostart: windows::core::BOOL(1) };
                ChangeServiceConfig2W(svc.0, SERVICE_CONFIG_DELAYED_AUTO_START_INFO, Some(&info as *const _ as *const core::ffi::c_void)).map_err(io_err)?;
            }
        }
        Ok(())
    }

    pub fn delete_task(path: &str) -> windows::core::Result<()> {
        let _com = ComGuard::new();
        let svc = scheduler()?;
        let (parent, leaf) = path.rsplit_once('\\').unwrap_or(("", path));
        let parent = if parent.is_empty() { "\\" } else { parent };
        // SAFETY: COM calls on live interfaces owned by this thread's apartment.
        unsafe { svc.GetFolder(&BSTR::from(parent))?.DeleteTask(&BSTR::from(leaf), 0) }
    }

    pub enum Made {
        Done,
        /// The task runs with a stored password (logon type 1 or 6): it cannot be recreated without it.
        Password,
        Exists,
    }

    /// Registers the XML as it is (`TASK_CREATE`: never overwrites). `NewTask` + `SetXmlText` are used only to read the logon type.
    pub fn create_task(path: &str, xml: &str) -> windows::core::Result<Made> {
        let _com = ComGuard::new();
        let svc = scheduler()?;
        let (parent, leaf) = path.rsplit_once('\\').unwrap_or(("", path));
        let parent = if parent.is_empty() { "\\" } else { parent };
        // SAFETY: COM calls on live interfaces owned by this thread's apartment.
        unsafe {
            let def = svc.NewTask(0)?;
            def.SetXmlText(&BSTR::from(xml))?;
            let mut lt = TASK_LOGON_TYPE(0);
            def.Principal()?.LogonType(&mut lt)?;
            if lt == TASK_LOGON_PASSWORD || lt == TASK_LOGON_INTERACTIVE_TOKEN_OR_PASSWORD {
                return Ok(Made::Password);
            }
            let folder = match svc.GetFolder(&BSTR::from(parent)) {
                Ok(f) => f,
                Err(e) if e.code().0 as u32 == 0x8007_0002 => svc.GetFolder(&BSTR::from("\\"))?.CreateFolder(&BSTR::from(parent.trim_start_matches('\\')), &VARIANT::default())?,
                Err(e) => return Err(e),
            };
            match folder.RegisterTask(&BSTR::from(leaf), &BSTR::from(xml), TASK_CREATE.0, &VARIANT::default(), &VARIANT::default(), lt, &VARIANT::default()) {
                Ok(_) => Ok(Made::Done),
                Err(e) if e.code().0 as u32 == 0x8007_00B7 => Ok(Made::Exists),
                Err(e) => Err(e),
            }
        }
    }

    pub fn task(path: &str) -> windows::core::Result<Option<(Task, String)>> {
        let _com = ComGuard::new();
        let svc = scheduler()?;
        // SAFETY: COM calls on live interfaces owned by this thread's apartment.
        unsafe {
            let root = svc.GetFolder(&BSTR::from("\\"))?;
            match root.GetTask(&BSTR::from(path)) {
                Ok(t) => {
                    let xml = t.Xml()?.to_string();
                    Ok(describe(&t).map(|d| (d, xml)))
                }
                Err(e) if e.code().0 as u32 == 0x8007_0002 || e.code().0 as u32 == 0x8007_0003 => Ok(None),
                Err(e) => Err(e),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn win() -> PathBuf {
        PathBuf::from(r"C:\Windows")
    }

    fn svc(image: &str, dll: Option<&str>, group: Option<&str>, depends: &[&str]) -> Svc {
        Svc { name: "S".into(), kind: 0x10, image: image.into(), dll: dll.map(str::to_string), group: group.map(str::to_string), depends: depends.iter().map(|d| d.to_string()).collect(), marked: false }
    }

    #[test]
    fn image_forms() {
        let f = |s: &str| image_text(s, &win());
        assert_eq!(f(r"\??\C:\x\y.sys"), r"C:\x\y.sys");
        assert_eq!(f(r"\\?\C:\x\y.exe"), r"C:\x\y.exe");
        assert_eq!(f(r#""\??\C:\x\y.exe" -a"#), r#""C:\x\y.exe" -a"#);
        assert_eq!(f(r"\SystemRoot\System32\drivers\a.sys"), r"C:\Windows\System32\drivers\a.sys");
        assert_eq!(f(r"\systemroot\x.sys"), r"C:\Windows\x.sys");
        assert_eq!(f(r"system32\drivers\a.sys"), r"C:\Windows\system32\drivers\a.sys");
        assert_eq!(f(r#""System32\svchost.exe" -k x"#), r#""C:\Windows\System32\svchost.exe" -k x"#);
        assert_eq!(f(r"C:\Program Files\A\a.exe /s"), r"C:\Program Files\A\a.exe /s");
        assert_eq!(f(r"\\srv\share\a.exe"), r"\\srv\share\a.exe", "UNC is not a device prefix");
        assert_eq!(f(""), "");
        let root = std::env::var("SystemRoot").unwrap();
        assert_eq!(f(r"%SystemRoot%\System32\svchost.exe -k x"), format!(r"{root}\System32\svchost.exe -k x"));
        assert_eq!(f(r#"  "C:\a b\c.exe"  "#), r#""C:\a b\c.exe""#);
    }

    #[test]
    fn windows_task_rule() {
        for t in [r"\Microsoft\Windows\X", r"\MICROSOFT\x", r"\Microsoft", r"Microsoft\x"] {
            assert!(is_windows_task(t), "{t}");
        }
        for t in [r"\Microsoft Office\x", r"\Lab Vendor\x", r"\x", r"\Vendor\Microsoft\x", ""] {
            assert!(!is_windows_task(t), "{t}");
        }
    }

    #[test]
    fn service_binary_forms() {
        let sys = PathBuf::from(r"C:\Windows\System32");
        assert_eq!(service_binary(&svc(r"C:\x\a.exe", Some(r#""C:\d\w.dll""#), None, &[]), &sys), PathBuf::from(r"C:\d\w.dll"), "the dll wins");
        assert_eq!(service_binary(&svc(r#""C:\Program Files\X\x.exe" --service"#, None, None, &[]), &sys), PathBuf::from(r"C:\Program Files\X\x.exe"), "quoted");
        let dir = tempfile::tempdir().unwrap();
        let exe = dir.path().join("a b").join("x.exe");
        std::fs::create_dir_all(exe.parent().unwrap()).unwrap();
        std::fs::write(&exe, b"x").unwrap();
        assert_eq!(service_binary(&svc(&format!("{} /s", exe.display()), None, None, &[]), &sys), exe, "an unquoted existing path with spaces");
        assert_eq!(service_binary(&svc(r"C:\gone dir\x.exe /s", None, None, &[]), &sys), PathBuf::from(r"C:\gone"), "a missing unquoted path gives its first token");
        // a bare name resolves to System32 only when the file exists there
        let real = std::env::var("SystemRoot").map(|r| PathBuf::from(r).join("System32")).unwrap();
        assert_eq!(service_binary(&svc("svchost.exe -k x", None, None, &[]), &real), real.join("svchost.exe"));
    }

    #[test]
    fn dependents_rule() {
        let s = svc("x", None, Some("Grp"), &[]);
        let mut a = svc("a", None, None, &["Other", "S"]);
        a.name = "A".into();
        let mut b = svc("b", None, None, &["+grp"]);
        b.name = "B".into();
        let mut m = svc("m", None, None, &["s"]);
        m.name = "M".into();
        m.marked = true;
        let mut me = svc("me", None, None, &["S", "+Grp"]);
        me.name = "s".into();
        let mut c = svc("c", None, None, &["+Elsewhere", "Else"]);
        c.name = "C".into();
        let all = [a, b, m, me, c];
        assert_eq!(dependents_of(&all, 0, &s).unwrap(), vec!["A", "B"], "by name in any case, by group; marked and itself ignored");
        assert!(dependents_of(&all, 1, &s).unwrap_err().to_string().contains("1 service keys"), "an unreadable key fails closed");
        assert!(dependents_of(&[], 0, &s).unwrap().is_empty());
    }

    #[test]
    fn shape_checks() {
        assert!(check_name("LabSvc").is_ok());
        for bad in ["", "a\\b", "a/b"] {
            assert!(check_name(bad).is_err(), "{bad:?}");
        }
        assert!(check_name(&"x".repeat(257)).is_err());
        for ok in [r"\a", r"\a\b c"] {
            assert!(check_path(ok).is_ok(), "{ok}");
        }
        for bad in ["", "a", r"\", r"\a\", r"\\a", r"\a\..\b", r"\.", r"\a\.\b"] {
            assert!(check_path(bad).is_err(), "{bad:?}");
        }
    }

    #[test]
    fn node_to_svc() {
        let sz = |n: &str, kind: u32, t: &str| RegVal { name: n.into(), kind, data: t.encode_utf16().chain(Some(0)).flat_map(u16::to_le_bytes).collect() };
        let node = RegNode {
            name: "S".into(),
            values: vec![RegVal { name: "Type".into(), kind: 4, data: 0x20u32.to_le_bytes().to_vec() }, sz("ImagePath", 2, r"\SystemRoot\System32\svchost.exe -k a"), sz("Group", 1, "Grp")],
            keys: vec![RegNode { name: "parameters".into(), values: vec![sz("ServiceDll", 2, r"C:\d\w.dll")], keys: vec![] }],
        };
        let s = svc_of_node("S", &node, &win());
        assert_eq!((s.kind, s.group.as_deref(), s.dll.as_deref(), s.marked), (0x20, Some("Grp"), Some(r"C:\d\w.dll"), false));
        assert_eq!(s.image, r"C:\Windows\System32\svchost.exe -k a");
    }

    /// Read-only: the readers' data shapes on the real machine (nothing is changed).
    #[test]
    fn real_readers_see_windows_objects() {
        let env = Env::system().unwrap();
        let s = service(&env, "EventLog").unwrap().expect("EventLog exists");
        assert_eq!(s.kind & TYPE_WIN32, 0x20, "a share-process Win32 service");
        let dll = s.dll.as_deref().expect("a ServiceDll");
        assert!(dll.to_lowercase().contains(r"\system32\"), "{dll}");
        assert!(!s.marked);
        let bin = service_binary(&s, &env.folders.system_dir);
        assert!(crate::safety::program_protected(&env, &bin).is_some(), "Windows' own program is protected: {bin:?}");
        assert!(running(&env, "EventLog").unwrap());
        assert!(service(&env, "No Such Service 4711").unwrap().is_none());
        assert!(services(&env).unwrap().len() > 100);
        let all = tasks(&env).unwrap();
        let ms = all.iter().find(|t| is_windows_task(&t.path)).expect("a \\Microsoft task");
        let (t, xml) = task(&env, &ms.path).unwrap().expect("it can be read again");
        assert_eq!(t.path.to_lowercase(), ms.path.to_lowercase());
        assert!(xml.contains("<Task"), "{xml:.80}");
        assert!(task(&env, r"\No Such Folder 4711\No Such Task").unwrap().is_none());
    }

    #[test]
    fn stand_ins_roundtrip() {
        let dir = tempfile::tempdir().unwrap();
        let env = Env::sandbox(dir.path(), "sysobj1");
        struct Cleanup(RegPath);
        impl Drop for Cleanup {
            fn drop(&mut self) {
                let _ = registry::delete_key(&self.0);
            }
        }
        let _clean = Cleanup(RegPath::new(Hive::Hkcu, View::V64, format!(r"{}\sysobj1", crate::env::TEST_KEY_PREFIX)));
        sandbox_task(&env, r"\Lab Vendor\Update", &[r#""C:\a\b.exe" --x"#.to_string(), "c.exe".into()], 1).unwrap();
        sandbox_task(&env, r"\Top", &[], 0).unwrap();
        let all = tasks(&env).unwrap();
        assert_eq!(all.iter().map(|t| t.path.as_str()).collect::<Vec<_>>(), vec![r"\Lab Vendor\Update", r"\Top"]);
        assert_eq!((all[0].actions.clone(), all[0].other, all[0].enabled), (vec![r#""C:\a\b.exe" --x"#.to_string(), "c.exe".to_string()], 1, true));
        let (t, xml) = task(&env, r"\lab vendor\UPDATE").unwrap().unwrap();
        assert_eq!(t.actions.len(), 2);
        assert!(xml.contains("sandbox stand-in"));
        assert!(task(&env, r"\Lab Vendor\Nope").unwrap().is_none());
        assert!(task(&env, r"\Lab Vendor").unwrap().is_none(), "a folder is not a task");
        assert!(sandbox_task(&env, r"Lab", &[], 0).is_err(), "a bad path");
        let k = registry::create(&env.services.child("StandIn"), KEY_ALL_ACCESS).unwrap();
        registry::set_string(&k, "ImagePath", r"\??\C:\x\d.sys", true).unwrap();
        registry::set_dword(&k, "Type", 1).unwrap();
        let s = service(&env, "standin").unwrap().unwrap();
        assert_eq!((s.kind, s.image.as_str()), (1, r"C:\x\d.sys"));
        registry::set_dword(&k, "DeleteFlag", 1).unwrap();
        assert!(service(&env, "StandIn").unwrap().is_none(), "marked means absent");
        assert!(services(&env).unwrap().iter().any(|s| s.marked), "but listed by services()");
        assert!(!running(&env, "StandIn").unwrap());
    }
}
