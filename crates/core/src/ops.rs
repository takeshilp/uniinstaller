//! Operations: describe, preview, uninstall flow, apply, restore, history.
//! Every destructive step is journalled in `manifest.json` before it happens, so an interrupted run can be restored.
use crate::command::parse_uninstall;
use crate::env::Env;
use crate::inventory::{entry_state, find_app, list_apps};
use crate::model::*;
use crate::native::{RunOptions, alive, run_uninstaller};
use crate::paths::{self, io_status, is_canonical, is_inside, norm, restore_path};
use crate::registry;
use crate::safety::{Anchors, path_blocks, program_protected, real_folders, registry_blocks, service_blocks, task_blocks, zone_root_of};
use crate::scan::{Ctx, anchors_of, data_volume, evaluate};
use crate::sysobj;
use crate::trace;
use crate::{Error, Result, now_ms};
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::{Mutex, MutexGuard, PoisonError, TryLockError};

// shortcut: OP_LOCK is per process, so two app instances could still race; add a lock file when a second
// instance or a CLI apply exists.
static OP_LOCK: Mutex<()> = Mutex::new(());

pub(crate) fn lock() -> MutexGuard<'static, ()> {
    OP_LOCK.lock().unwrap_or_else(PoisonError::into_inner)
}

/// True while a mutating operation is running (used to refuse an update install).
pub fn is_busy() -> bool {
    matches!(OP_LOCK.try_lock(), Err(TryLockError::WouldBlock))
}

// shortcut: destructive operations refuse any non-sandbox Env in debug builds, so `tauri dev` and `cargo run` never
// uninstall real programs; this is intended, keep it.
pub(crate) fn guard(env: &Env) -> Result<()> {
    if cfg!(debug_assertions) && !env.sandbox {
        return Err(Error("debug build: destructive operations run only in sandbox mode".into()));
    }
    Ok(())
}

/// `^op-[0-9]{1,20}$` without a regex crate.
pub fn valid_op_id(id: &str) -> Result<()> {
    match id.strip_prefix("op-") {
        Some(n) if (1..=20).contains(&n.len()) && n.bytes().all(|b| b.is_ascii_digit()) => Ok(()),
        _ => Err(Error("invalid operation id".into())),
    }
}

fn ops_dir(env: &Env) -> PathBuf {
    env.data_dir.join("operations")
}
fn op_dir(env: &Env, id: &str) -> PathBuf {
    ops_dir(env).join(id)
}
fn manifest_path(env: &Env, id: &str) -> PathBuf {
    op_dir(env, id).join("manifest.json")
}

// shortcut: manifests store registry backups in clear text; encrypt with DPAPI if settings keys with tokens become common.
// shortcut: quarantine, manifests, plans and reports are never purged; add a "delete backup" action and a retention
// policy before 1.0.
// shortcut: quarantine and HKLM backups made while elevated live in the user-writable profile, and the app is a
// per-user install, so same-user malware could tamper with them before an elevated restore (a service or task backup could make it create
// a LocalSystem service or a SYSTEM task; `restore_system` re-checks the blocks); upgrade to a per-machine install, a helper and a
// protected ProgramData store in stage 2.
pub fn save(env: &Env, op: &Operation) -> Result<()> {
    valid_op_id(&op.id)?;
    let dir = op_dir(env, &op.id);
    fs::create_dir_all(&dir)?;
    let tmp = dir.join("manifest.json.tmp");
    let mut f = fs::File::create(&tmp)?;
    f.write_all(serde_json::to_string_pretty(op)?.as_bytes())?;
    f.sync_all()?;
    drop(f);
    fs::rename(&tmp, manifest_path(env, &op.id))?;
    Ok(())
}

pub fn load(env: &Env, op_id: &str) -> Result<Operation> {
    valid_op_id(op_id)?;
    let text = fs::read_to_string(manifest_path(env, op_id))?;
    let op: Operation = serde_json::from_str(&text)?;
    if op.id != op_id {
        return Err(Error("manifest id does not match its folder".into()));
    }
    if op.schema > SCHEMA {
        return Err(Error("written by a newer version of Uniinstaller".into()));
    }
    Ok(op)
}

pub fn describe(env: &Env, app_id: &str) -> Result<AppDetails> {
    let app = find_app(env, app_id)?;
    let (launch, launch_error) = match app.uninstall_string.as_deref() {
        None => (None, Some("no uninstall command".to_string())),
        Some(raw) => match parse_uninstall(raw, &env.folders.system_dir, app.product_code.as_deref()) {
            Ok(l) => (Some(l), None),
            Err(e) => (None, Some(e)),
        },
    };
    let trace = trace::find_for(env, &app, false).map(|x| x.1);
    Ok(AppDetails { app, launch, launch_error, trace })
}

/// Every other listed program, hidden ones included (an entry Apps & Features hides is still installed software that may own what we
/// would remove): the app itself (same id or an intersecting source) is removed.
fn others(env: &Env, app: &InstalledApp) -> Result<Vec<InstalledApp>> {
    Ok(list_apps(env, true)?.into_iter().filter(|a| a.id != app.id && !a.sources.iter().any(|s| app.sources.iter().any(|x| x.same(s)))).collect())
}

/// Dry run, read-only.
pub fn preview(env: &Env, app_id: &str) -> Result<Plan> {
    let d = describe(env, app_id)?;
    let others = others(env, &d.app)?;
    let tr = trace::find_for(env, &d.app, false);
    let mut plan = crate::scan::scan(env, &d.app, d.launch.as_ref(), &others, true, tr.as_ref().filter(|(_, u)| u.trusted).map(|(j, _)| j), None)?;
    plan.trace = tr.map(|(_, u)| u);
    Ok(plan)
}

/// Stable id of a target; the same across rescans.
pub fn target_key(t: &Target) -> String {
    let rp = |k: &RegPath| {
        let h = if k.hive == Hive::Hklm { "hklm" } else { "hkcu" };
        let v = if k.view == View::V64 { "64" } else { "32" };
        format!("{h}{v}:{}", k.path.to_lowercase())
    };
    match t {
        Target::Path { path, .. } => format!("path:{}", norm(path)),
        Target::RegKey { key } => format!("key:{}", rp(key)),
        Target::RegValue { key, name } => format!("value:{}|{}", rp(key), name.to_lowercase()),
        Target::RegRevert { key, name, .. } => format!("revert:{}|{}", rp(key), name.to_lowercase()),
        Target::Service { name } => format!("service:{}", name.to_lowercase()),
        Target::Task { path } => format!("task:{}", path.to_lowercase()),
    }
}

pub fn safe_file_name(s: &str) -> String {
    s.chars().map(|c| if c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-') { c } else { '_' }).take(80).collect()
}

fn strip_payloads(i: &Ident) -> Ident {
    match i {
        Ident::Key { .. } | Ident::Value { .. } | Ident::Service { .. } | Ident::Task { .. } => Ident::None {},
        other => other.clone(),
    }
}

/// Exports never carry registry data: a revert's previous value is cleared like the identity payloads.
fn strip_target(t: &mut Target) {
    if let Target::RegRevert { previous, .. } = t {
        previous.data.clear();
    }
}

fn write_json(path: &Path, value: &impl serde::Serialize) -> Result<()> {
    if let Some(d) = path.parent() {
        fs::create_dir_all(d)?;
    }
    fs::write(path, serde_json::to_string_pretty(value)?)?;
    Ok(())
}

/// `data_dir\plans\<app>-<ms>.json`, registry payloads stripped.
pub fn export_plan(env: &Env, plan: &Plan) -> Result<PathBuf> {
    let mut p = plan.clone();
    for c in &mut p.candidates {
        c.ident = strip_payloads(&c.ident);
        strip_target(&mut c.target);
    }
    let path = env.data_dir.join("plans").join(format!("{}-{}.json", safe_file_name(&plan.app_id), now_ms()));
    write_json(&path, &p).map_err(|e| Error(format!("cannot write the plan: {e}")))?;
    Ok(path)
}

/// `data_dir\reports\<op>.json`, registry backups and payloads stripped.
pub fn export_report(env: &Env, op_id: &str) -> Result<PathBuf> {
    let mut op = load(env, op_id)?;
    for i in &mut op.items {
        i.reg_backup = None;
        strip_target(&mut i.target);
    }
    if let Some(p) = &mut op.plan {
        for c in &mut p.candidates {
            c.ident = strip_payloads(&c.ident);
            strip_target(&mut c.target);
        }
    }
    let path = env.data_dir.join("reports").join(format!("{}.json", safe_file_name(op_id)));
    write_json(&path, &op).map_err(|e| Error(format!("cannot write the report: {e}")))?;
    Ok(path)
}

/// Creates the operation record. The captured `app` is the pre-uninstall anchor snapshot. A hidden entry needs `hidden_ok`, the caller's
/// proof that the user confirmed it.
pub fn begin(env: &Env, app_id: &str, hidden_ok: bool) -> Result<Operation> {
    guard(env)?;
    let _g = lock();
    let d = describe(env, app_id)?;
    // shortcut: every hidden entry gets the same single confirmation; there is no publisher or bundle check (Visual C++ and .NET runtimes,
    // WiX Burn packages, the WebView2 Runtime), add per-kind warnings if users remove runtimes by mistake.
    if d.app.hidden.is_some() && !hidden_ok {
        return Err(Error("a hidden component is uninstalled only after an explicit confirmation".into()));
    }
    let launch = d.launch.ok_or_else(|| Error(d.launch_error.unwrap_or_else(|| "no usable uninstall command".into())))?;
    if let Some(dir) = d.app.install_location.as_deref()
        && let Ok(exe) = std::env::current_exe()
        && paths::same_or_inside(&exe, dir)
    {
        return Err(Error("refusing to uninstall Uniinstaller itself".into()));
    }
    create(env, d.app, launch, None)
}

/// Writes the operation record; the id is the first free `op-<ms>`.
fn create(env: &Env, app: InstalledApp, launch: Launch, forced: Option<Forced>) -> Result<Operation> {
    let mut ms = now_ms();
    while op_dir(env, &format!("op-{ms}")).exists() {
        ms += 1;
    }
    let mut op = Operation {
        schema: SCHEMA,
        id: format!("op-{ms}"),
        created_ms: ms,
        app,
        launch,
        native: None,
        entry_after: None,
        plan: None,
        items: vec![],
        empty_dirs_removed: vec![],
        verify: None,
        status: OpStatus::Running,
        status_detail: None,
        forced,
    };
    (op.status, op.status_detail) = overall_status(&op);
    save(env, &op)?;
    Ok(op)
}

/// Starts a forced removal ("remove by path"): re-checks the pick (`force::check` must still say Ok), takes the name and publisher the
/// user confirmed, and, if the user chose one of the uninstallers found in the folder, records it as the operation's launch;
/// otherwise the launch is the empty placeholder and the operation goes straight to the leftover search.
pub fn begin_forced(env: &Env, picked: &Path, name: &str, publisher: Option<&str>, uninstaller: Option<&Path>) -> Result<Operation> {
    guard(env)?;
    let _g = lock();
    let ForceCheck::Ok { found } = crate::force::check(env, picked)? else {
        return Err(Error("this path cannot be removed by force; check it again".into()));
    };
    let found = *found;
    let text = |s: &str, what: &str| -> Result<String> {
        let s = s.trim();
        if s.chars().count() > 200 || s.chars().any(char::is_control) {
            return Err(Error(format!("the {what} is too long or has control characters")));
        }
        Ok(s.to_string())
    };
    let name = text(name, "name")?;
    if name.is_empty() {
        return Err(Error("the program needs a name".into()));
    }
    let publisher = text(publisher.unwrap_or(""), "publisher")?;
    let publisher = (!publisher.is_empty()).then_some(publisher);
    let launch = match uninstaller {
        Some(u) => {
            let exe = found.uninstallers.iter().find(|x| norm(x) == norm(u)).ok_or_else(|| Error("not an uninstaller found in this folder".into()))?;
            Launch { raw: format!("\"{}\"", exe.display()), exe: exe.clone(), args: String::new(), argv: vec![], msi_product: None }
        }
        None => Launch { raw: String::new(), exe: PathBuf::new(), args: String::new(), argv: vec![], msi_product: None },
    };
    let mut forced = found.forced;
    forced.search_names = crate::force::search_names(&name, &forced.picked, forced.folder.as_deref(), found.product.as_deref());
    let app = crate::force::app_for(&forced, &name, publisher.as_deref(), found.file_version.as_deref());
    create(env, app, launch, Some(forced))
}

/// A forced operation in a sandbox must still point inside the sandbox folder (a manifest copied in cannot aim at real folders).
fn forced_in_scope(env: &Env, op: &Operation) -> Result<()> {
    match &op.forced {
        Some(f) if !crate::force::in_sandbox(env, f.folder.as_deref().unwrap_or(&f.picked)) => Err(Error("this forced operation points outside the sandbox folder".into())),
        _ => Ok(()),
    }
}

/// A forced operation without an uninstaller to run (`launch` is the empty placeholder): it goes straight to the leftover search.
fn skips_native(op: &Operation) -> bool {
    op.forced.is_some() && op.launch.exe.as_os_str().is_empty()
}

pub fn run_native(env: &Env, op_id: &str, opts: &RunOptions) -> Result<Operation> {
    guard(env)?;
    valid_op_id(op_id)?;
    let _g = lock();
    let mut op = load(env, op_id)?;
    if op.native.is_some() {
        return Err(Error("the uninstaller was already run for this operation".into()));
    }
    if op.launch.exe.as_os_str().is_empty() {
        return Err(Error("no uninstaller was chosen for this operation".into()));
    }
    let run = run_uninstaller(&op.launch, opts);
    op.entry_after = Some(entry_state(&op.app, &op.launch, run.exit_code, &env.folders.windows_dir));
    op.native = Some(run);
    (op.status, op.status_detail) = overall_status(&op);
    save(env, &op)?;
    Ok(op)
}

/// Finds leftovers with live preconditions; stores the plan.
pub fn scan_leftovers(env: &Env, op_id: &str) -> Result<Operation> {
    valid_op_id(op_id)?;
    let _g = lock();
    let mut op = load(env, op_id)?;
    forced_in_scope(env, &op)?;
    let native = op.native.clone();
    match &native {
        Some(n) => {
            if let Some(e) = &n.launch_error {
                return Err(Error(format!("the uninstaller did not start: {e}")));
            }
            if n.reboot_required {
                // shortcut: "rebooted since" comes from uptime only; there is no automatic continuation, add resume in stage 2.
                let boot_ms = now_ms().saturating_sub(unsafe { windows::Win32::System::SystemInformation::GetTickCount64() });
                if boot_ms <= n.ended_ms {
                    return Err(Error("a reboot is required before leftovers can be searched".into()));
                }
            }
        }
        None if skips_native(&op) => {}
        None => return Err(Error("the uninstaller has not run yet".into())),
    }
    let live = entry_state(&op.app, &op.launch, native.as_ref().and_then(|n| n.exit_code), &env.folders.windows_dir);
    if live == EntryState::Present {
        return Err(Error("the program is still installed".into()));
    }
    op.entry_after = Some(live);
    let others = others(env, &op.app)?;
    // The program's own uninstaller has run: a hidden component it left installed makes the journal untrusted.
    let tr = trace::find_for(env, &op.app, true);
    let mut plan = crate::scan::scan(env, &op.app, Some(&op.launch), &others, false, tr.as_ref().filter(|(_, u)| u.trusted).map(|(j, _)| j), op.forced.as_ref())?;
    plan.trace = tr.map(|(_, u)| u);
    plan.still_running = native.iter().flat_map(|n| &n.processes).filter(|p| alive(p)).map(|p| p.image.clone()).collect();
    op.plan = Some(plan);
    (op.status, op.status_detail) = overall_status(&op);
    save(env, &op)?;
    Ok(op)
}

// shortcut: a locked file is reported as Locked and retried by hand, there is no Restart Manager; add it in stage 2.
fn is_final(s: ItemStatus) -> bool {
    matches!(s, ItemStatus::Removed | ItemStatus::NotFound | ItemStatus::Reverted)
}

/// A service or task that cannot be read counts as existing (fail closed): nothing is then reported as "already gone".
fn target_exists(env: &Env, t: &Target) -> bool {
    match t {
        Target::Path { path, .. } => fs::symlink_metadata(path).is_ok(),
        Target::RegKey { key } => registry::exists(key),
        Target::RegValue { key, name } | Target::RegRevert { key, name, .. } => registry::read_value(key, name).is_ok(),
        Target::Service { name } => sysobj::service(env, name).map(|s| s.is_some()).unwrap_or(true),
        Target::Task { path } => sysobj::task(env, path).map(|t| t.is_some()).unwrap_or(true),
    }
}

/// Services and tasks first (a running service holds its files and a task could start the program during the apply), then reverts
/// (a revert and a delete of the same value cannot both apply), then values, then keys shallow first, then paths deep first.
fn target_rank(t: &Target) -> (u8, usize) {
    match t {
        Target::Service { .. } | Target::Task { .. } => (0, 0),
        Target::RegRevert { .. } => (1, 0),
        Target::RegValue { .. } => (1, 1),
        Target::RegKey { key } => (2, key.path.matches('\\').count()),
        Target::Path { path, .. } => (3, usize::MAX - norm(path).matches('\\').count()),
    }
}

/// Identity for revalidation: a service's running state is display-only (a stop that timed out, a demand start or a crash between the
/// stop and DeleteService change it); its whole registry key is what must be unchanged.
fn same_ident(a: &Ident, b: &Ident) -> bool {
    match (a, b) {
        (Ident::Service { node: x, .. }, Ident::Service { node: y, .. }) => x == y,
        _ => a == b,
    }
}

/// An interrupted apply leaves `InProgress` records: if the action completed, close the record.
fn recover_in_progress(env: &Env, op: &mut Operation) {
    for i in op.items.iter_mut().filter(|i| i.status == ItemStatus::InProgress) {
        let done = match &i.target {
            Target::Path { .. } => i.quarantine.as_deref().is_some_and(Path::exists),
            Target::RegRevert { key, name, previous } => registry::read_value(key, name).is_ok_and(|v| registry::same_data(&v, previous)),
            t => !target_exists(env, t),
        };
        if done {
            i.status = if matches!(i.target, Target::RegRevert { .. }) { ItemStatus::Reverted } else { ItemStatus::Removed };
            i.detail = Some("recovered after an interruption".into());
        }
    }
}

fn first_block(blocks: &[Block]) -> String {
    blocks.first().map(|b| format!("{:?}: {}", b.code, b.detail)).unwrap_or_default()
}

pub fn apply(env: &Env, op_id: &str, candidate_ids: &[String]) -> Result<Operation> {
    guard(env)?;
    valid_op_id(op_id)?;
    let _g = lock();
    let mut op = load(env, op_id)?;
    forced_in_scope(env, &op)?;
    let plan = op.plan.clone().ok_or_else(|| Error("no plan: search for leftovers first".into()))?;
    let others = others(env, &op.app)?;
    let anchors = anchors_of(env, &others);
    let confirmed: Option<PathBuf> = if matches!(plan.install_dir_status, DirStatus::Confirmed {}) { plan.install_dir.clone() } else { None };
    let (app, launch) = (op.app.clone(), op.launch.clone());
    let ctx = Ctx { env, app: &app, launch: Some(&launch), install_dir: confirmed.as_deref(), anchors: &anchors, data_volume: data_volume(env) };
    recover_in_progress(env, &mut op);

    let mut chosen: Vec<&Candidate> = Vec::new();
    for id in candidate_ids {
        if let Some(c) = plan.candidates.iter().find(|c| &c.id == id)
            && !chosen.iter().any(|x| x.id == c.id)
        {
            chosen.push(c);
        }
    }
    chosen.sort_by_key(|c| target_rank(&c.target));

    let qdir = op_dir(env, op_id).join("q");
    let mut moved: Vec<PathBuf> = Vec::new();
    for c in chosen {
        if op.items.iter().any(|i| i.candidate_id == c.id && is_final(i.status)) {
            continue;
        }
        let mut rec = ItemRecord {
            candidate_id: c.id.clone(),
            target: c.target.clone(),
            status: ItemStatus::InProgress,
            detail: None,
            quarantine: None,
            reg_backup: None,
            restore: None,
            restore_detail: None,
            at_ms: now_ms(),
        };
        // Revalidate right before acting; fail closed.
        let refuse = |rec: &mut ItemRecord, status: ItemStatus, detail: String| {
            rec.status = status;
            rec.detail = Some(detail);
        };
        if c.ident == (Ident::None {}) {
            refuse(&mut rec, ItemStatus::Blocked, "identity could not be verified".into());
        } else if matches!(c.target, Target::RegRevert { .. }) && !target_exists(env, &c.target) {
            // A vanished value is a change, not "already gone": the previous value is never written into a missing value.
            refuse(&mut rec, ItemStatus::Changed, "the value no longer exists; the previous value was not written".into());
        } else if !target_exists(env, &c.target) {
            refuse(&mut rec, ItemStatus::NotFound, "already gone".into());
        } else {
            let e = evaluate(&ctx, c.group, &c.target);
            if !e.blocks.is_empty() {
                refuse(&mut rec, ItemStatus::Blocked, first_block(&e.blocks));
            } else if !same_ident(&e.ident, &c.ident) {
                refuse(&mut rec, ItemStatus::Changed, "changed since the scan; left untouched".into());
            }
        }
        let slot = op.items.iter().position(|i| i.candidate_id == c.id);
        let idx = match slot {
            Some(i) => i,
            None => {
                op.items.push(rec.clone());
                op.items.len() - 1
            }
        };
        if rec.status != ItemStatus::InProgress {
            op.items[idx] = rec;
            save(env, &op)?;
            continue;
        }
        // Journal first: the record (with the quarantine path or registry backup) is saved before anything is touched.
        match &c.target {
            Target::Path { path, .. } => {
                fs::create_dir_all(&qdir)?;
                let name = path.file_name().map(|n| safe_file_name(&n.to_string_lossy())).unwrap_or_default();
                let mut n = op.items.len();
                let mut dst = qdir.join(format!("{n}_{name}"));
                while dst.exists() {
                    n += 1;
                    dst = qdir.join(format!("{n}_{name}"));
                }
                rec.quarantine = Some(dst);
            }
            Target::RegKey { .. } | Target::RegValue { .. } | Target::RegRevert { .. } | Target::Service { .. } | Target::Task { .. } => rec.reg_backup = Some(c.ident.clone()),
        }
        op.items[idx] = rec.clone();
        save(env, &op)?;
        let mut deferred = false;
        let result: std::io::Result<()> = match &c.target {
            Target::Path { path, .. } => paths::move_path(path, rec.quarantine.as_ref().expect("set above")),
            Target::Service { name } => sysobj::remove_service(env, name).map(|d| deferred = d),
            Target::Task { path } => sysobj::delete_task(env, path),
            Target::RegKey { key } => registry::delete_key(key),
            Target::RegValue { key, name } => registry::delete_value(key, name),
            Target::RegRevert { key, name, previous } => registry::write_value(key, &RegVal { name: name.clone(), ..previous.clone() }),
        };
        match result {
            Ok(()) => {
                rec.status = if matches!(c.target, Target::RegRevert { .. }) { ItemStatus::Reverted } else { ItemStatus::Removed };
                if let Target::Path { path, .. } = &c.target {
                    moved.push(path.clone());
                }
                if deferred {
                    rec.detail = Some(sysobj::DEFERRED.into());
                }
            }
            Err(e) => {
                rec.status = io_status(&e);
                rec.detail = Some(e.to_string());
                if matches!(c.target, Target::Path { .. }) {
                    rec.quarantine = None; // nothing was moved
                }
            }
        }
        rec.at_ms = now_ms();
        op.items[idx] = rec;
        save(env, &op)?;
    }

    // Remove folders that became empty, bottom-up, never above a zone root or a protected root.
    for p in &moved {
        let mut cur = p.parent().map(Path::to_path_buf);
        while let Some(d) = cur {
            if zone_root_of(env, confirmed.as_deref(), &d).is_none() || is_protected_root(env, &d) || !is_canonical(&d) {
                break;
            }
            let empty = fs::read_dir(&d).is_ok_and(|mut r| r.next().is_none());
            if !empty || fs::remove_dir(&d).is_err() {
                break;
            }
            if !op.empty_dirs_removed.contains(&d) {
                op.empty_dirs_removed.push(d.clone());
            }
            cur = d.parent().map(Path::to_path_buf);
        }
    }

    // Verify.
    let listed = list_apps(env, true)?;
    let app_still_listed = listed.iter().any(|a| a.id == op.app.id || a.sources.iter().any(|s| op.app.sources.iter().any(|x| x.same(s))));
    let reappeared = op.items.iter().filter(|i| i.status == ItemStatus::Removed && target_exists(env, &i.target)).map(|i| i.candidate_id.clone()).collect();
    op.verify = Some(Verify { app_still_listed, reappeared });
    if let Some(n) = &op.native {
        op.entry_after = Some(entry_state(&op.app, &op.launch, n.exit_code, &env.folders.windows_dir));
    }
    (op.status, op.status_detail) = overall_status(&op);
    save(env, &op)?;
    Ok(op)
}

fn is_protected_root(env: &Env, d: &Path) -> bool {
    let hit = |f: &crate::env::Folders| f.protected_roots.iter().any(|r| norm(r) == norm(d));
    hit(&env.folders) || real_folders().as_ref().map(hit).unwrap_or(true)
}

/// Blocks that matter when putting something back: protected, outside the zones, aliased, unverifiable.
fn restore_block(env: &Env, path: &Path, group: Group, install_dir: Option<&Path>) -> Option<String> {
    use BlockCode::*;
    let blocks = path_blocks(env, path, group, install_dir, &Anchors::default());
    let hit: Vec<Block> = blocks.into_iter().filter(|b| matches!(b.code, ProtectedPath | OutsideAllowedZone | NonCanonicalPath | Unverifiable)).collect();
    (!hit.is_empty()).then(|| format!("blocked: {}", first_block(&hit)))
}

pub fn restore(env: &Env, op_id: &str) -> Result<Operation> {
    guard(env)?;
    valid_op_id(op_id)?;
    let _g = lock();
    let mut op = load(env, op_id)?;
    let install_dir: Option<PathBuf> = op.plan.as_ref().filter(|p| matches!(p.install_dir_status, DirStatus::Confirmed {})).and_then(|p| p.install_dir.clone());
    let q_root = op_dir(env, op_id).join("q");
    let group_of = |op: &Operation, id: &str, path: &Path| -> Group {
        op.plan.as_ref().and_then(|p| p.candidates.iter().find(|c| c.id == id)).map(|c| c.group).unwrap_or_else(|| {
            if path.extension().is_some_and(|e| e.eq_ignore_ascii_case("lnk")) { Group::Shortcuts } else { Group::ProgramFiles }
        })
    };

    // Recreate the empty folders that were removed, shallowest first.
    let mut dirs = op.empty_dirs_removed.clone();
    dirs.sort_by_key(|d| norm(d).matches('\\').count());
    for d in &dirs {
        if restore_block(env, d, Group::ProgramFiles, install_dir.as_deref()).is_none() {
            let _ = fs::create_dir_all(d);
        }
    }

    for idx in (0..op.items.len()).rev() {
        let item = op.items[idx].clone();
        let outcome: Option<(RestoreStatus, Option<String>)> = match &item.target {
            Target::Path { path, .. } => match &item.quarantine {
                None => None,
                Some(q) => {
                    let group = group_of(&op, &item.candidate_id, path);
                    if q.exists() {
                        if !is_inside(q, &q_root) || !q.parent().is_some_and(is_canonical) {
                            Some((RestoreStatus::Failed, Some("blocked: quarantine path is outside this operation".into())))
                        } else if let Some(why) = restore_block(env, path, group, install_dir.as_deref()) {
                            Some((RestoreStatus::Failed, Some(why)))
                        } else {
                            Some(restore_path(q, path))
                        }
                    } else if fs::symlink_metadata(path).is_ok() {
                        Some((RestoreStatus::Restored, Some("was not moved".into())))
                    } else {
                        Some((RestoreStatus::Missing, Some("no payload and nothing at the original location".into())))
                    }
                }
            },
            Target::Service { .. } | Target::Task { .. } => item.reg_backup.as_ref().map(|b| restore_system(env, &item.target, b)),
            t => match &item.reg_backup {
                None => None,
                Some(backup) => {
                    if !registry_blocks(env, t).is_empty() {
                        Some((RestoreStatus::Failed, Some(format!("blocked: {}", first_block(&registry_blocks(env, t))))))
                    } else {
                        Some(restore_registry(t, backup))
                    }
                }
            },
        };
        if let Some((st, detail)) = outcome {
            op.items[idx].restore = Some(st);
            op.items[idx].restore_detail = detail;
        }
    }
    (op.status, op.status_detail) = overall_status(&op);
    save(env, &op)?;
    Ok(op)
}

/// Recreates a removed service or task from its backup. A backup is recreated only if it would have been offered: the same name, a
/// Win32 service, a program that is not Windows', a task outside `\Microsoft`. A manifest is user-writable (see `save`), so these
/// checks run again here and nothing is created when one fails.
fn restore_system(env: &Env, t: &Target, backup: &Ident) -> (RestoreStatus, Option<String>) {
    let blocked = |bs: Vec<Block>| (RestoreStatus::Failed, Some(format!("blocked: {}", first_block(&bs))));
    match (t, backup) {
        (Target::Service { name }, Ident::Service { node, .. }) => {
            if !node.name.eq_ignore_ascii_case(name) {
                return (RestoreStatus::Failed, Some("blocked: the backup is of another service".into()));
            }
            let s = sysobj::svc_of_node(name, node, &env.folders.windows_dir);
            let bs = service_blocks(&s, &[], program_protected(env, &sysobj::service_binary(&s, &env.folders.system_dir)));
            if !bs.is_empty() {
                return blocked(bs);
            }
            sysobj::recreate_service(env, name, node)
        }
        (Target::Task { path }, Ident::Task { xml, actions, enabled }) => {
            let bs = task_blocks(&sysobj::Task { path: path.clone(), actions: actions.clone(), other: 0, enabled: *enabled });
            if !bs.is_empty() {
                return blocked(bs);
            }
            sysobj::recreate_task(env, path, xml, actions, *enabled)
        }
        _ => (RestoreStatus::Failed, Some("backup does not match the target".into())),
    }
}

fn restore_registry(t: &Target, backup: &Ident) -> (RestoreStatus, Option<String>) {
    let fail = |e: std::io::Error| (RestoreStatus::Failed, Some(e.to_string()));
    match (t, backup) {
        (Target::RegKey { key }, Ident::Key { node }) => match registry::restore_node(key, node) {
            Err(e) => fail(e),
            Ok(()) => match registry::capture(key) {
                Ok(now) if &now == node => (RestoreStatus::Restored, None),
                Ok(_) => (RestoreStatus::Conflict, Some("the key has other contents now; existing values were kept".into())),
                Err(e) => fail(e),
            },
        },
        (Target::RegValue { key, .. }, Ident::Value { val }) => match registry::restore_value(key, val) {
            Ok(RestoreStatus::Conflict) => (RestoreStatus::Conflict, Some("the value exists with different data".into())),
            Ok(s) => (s, None),
            Err(e) => fail(e),
        },
        (Target::RegRevert { key, name, previous }, Ident::Value { val }) => match registry::read_value(key, name) {
            Ok(cur) if registry::same_data(&cur, val) => (RestoreStatus::Restored, None),
            Ok(cur) if registry::same_data(&cur, previous) => match registry::write_value(key, val) {
                Ok(()) => (RestoreStatus::Restored, None),
                Err(e) => fail(e),
            },
            Ok(_) => (RestoreStatus::Conflict, Some("the value was changed after the previous value was restored; kept".into())),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => (RestoreStatus::Conflict, Some("the value or its key no longer exists; not recreated".into())),
            Err(e) => fail(e),
        },
        _ => (RestoreStatus::Failed, Some("backup does not match the target".into())),
    }
}

/// Pure status rules, evaluated in order.
pub fn overall_status(op: &Operation) -> (OpStatus, Option<String>) {
    let restorable: Vec<&ItemRecord> = op.items.iter().filter(|i| i.quarantine.is_some() || i.reg_backup.is_some()).collect();
    if !restorable.is_empty() && restorable.iter().all(|i| i.restore.is_some()) {
        return if restorable.iter().all(|i| i.restore == Some(RestoreStatus::Restored)) {
            (OpStatus::Restored, None)
        } else {
            (OpStatus::PartiallyRestored, Some("some items could not be restored".into()))
        };
    }
    // A forced operation may have no native run at all (nothing was chosen to run): then only the items decide.
    let n = match &op.native {
        Some(n) => Some(n),
        None if skips_native(op) => None,
        None => return (OpStatus::Running, None),
    };
    if let Some(n) = n {
        if let Some(e) = &n.launch_error {
            return (OpStatus::Failed, Some(format!("launch: {e}")));
        }
        let present = op.entry_after == Some(EntryState::Present);
        if (n.timed_out || n.stopped_by_user) && present {
            return (OpStatus::Running, Some("uninstaller may still be running".into()));
        }
        if present {
            return (OpStatus::Failed, Some("program still installed".into()));
        }
        if n.reboot_required && op.items.is_empty() {
            return (OpStatus::PendingReboot, None);
        }
    }
    if op.items.is_empty() {
        return (OpStatus::AwaitingReview, None);
    }
    use ItemStatus::*;
    // InProgress is included on purpose: a record that never finished is a problem, not a success.
    if op.items.iter().any(|i| matches!(i.status, Changed | Blocked | AccessDenied | Locked | Failed | InProgress)) {
        return if op.items.iter().any(|i| matches!(i.status, Removed | Reverted)) {
            (OpStatus::PartiallyCompleted, Some("some items were not removed".into()))
        } else {
            (OpStatus::Failed, Some("nothing could be removed".into()))
        };
    }
    let bad_exit = n.is_some_and(|n| !matches!(n.exit_code, Some(0) | Some(3010) | Some(1641)));
    let unfinished = n.is_some_and(|n| n.timed_out || n.stopped_by_user);
    if op.verify.as_ref().is_some_and(|v| v.app_still_listed || !v.reappeared.is_empty()) || op.entry_after == Some(EntryState::Orphaned) || bad_exit || unfinished {
        return (OpStatus::CompletedWithWarnings, Some("verification found something to look at".into()));
    }
    (OpStatus::Completed, None)
}

/// Newest first. Unreadable manifests are listed as `Broken`, never skipped.
pub fn history(env: &Env) -> Result<Vec<HistoryEntry>> {
    let mut out: Vec<(u64, HistoryEntry)> = Vec::new();
    let Ok(rd) = fs::read_dir(ops_dir(env)) else { return Ok(vec![]) };
    for e in rd.flatten() {
        let id = e.file_name().to_string_lossy().to_string();
        if valid_op_id(&id).is_err() || !e.path().is_dir() {
            continue;
        }
        let num: u64 = id[3..].parse().unwrap_or(0);
        match load(env, &id) {
            Ok(op) => out.push((op.created_ms, HistoryEntry::Ok { op: Box::new(op) })),
            Err(err) => out.push((num, HistoryEntry::Broken { id, path: manifest_path(env, &e.file_name().to_string_lossy()), error: err.0 })),
        }
    }
    out.sort_by_key(|x| std::cmp::Reverse(x.0));
    Ok(out.into_iter().map(|x| x.1).collect())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn app() -> InstalledApp {
        InstalledApp {
            id: "HKCU64:X".into(), key_name: "X".into(), sources: vec![], display_name: "X".into(), display_version: None, publisher: None,
            install_location: None, display_icon: None, uninstall_string: None, quiet_uninstall_string: None, modify_path: None,
            install_date: None, estimated_size_kb: None, windows_installer: false, product_code: None, per_user: true, hidden: None,
        }
    }

    fn item(status: ItemStatus) -> ItemRecord {
        ItemRecord {
            candidate_id: "c".into(),
            target: Target::Path { path: PathBuf::from(r"C:\x"), kind: PathKind::File },
            status,
            detail: None,
            quarantine: None,
            reg_backup: None,
            restore: None,
            restore_detail: None,
            at_ms: 0,
        }
    }

    fn op(native: Option<NativeRun>, entry: Option<EntryState>, items: Vec<ItemRecord>) -> Operation {
        Operation {
            schema: 1, id: "op-1".into(), created_ms: 1, app: app(),
            launch: Launch { raw: String::new(), exe: PathBuf::new(), args: String::new(), argv: vec![], msi_product: None },
            native, entry_after: entry, plan: None, items, empty_dirs_removed: vec![], verify: None, status: OpStatus::Running, status_detail: None, forced: None,
        }
    }

    fn run() -> NativeRun {
        NativeRun { exit_code: Some(0), ..Default::default() }
    }

    /// A forced operation with no uninstaller (`launch.exe` is empty, as `op()` builds it).
    fn forced(native: Option<NativeRun>, items: Vec<ItemRecord>) -> Operation {
        let mut o = op(native, None, items);
        o.forced = Some(Forced { picked: PathBuf::from(r"C:\x"), folder: None, search_names: vec![] });
        o
    }

    fn st(o: &Operation) -> OpStatus {
        overall_status(o).0
    }

    #[test]
    fn overall_status_table() {
        use EntryState::*;
        use ItemStatus::*;
        // no native run yet
        assert_eq!(st(&op(None, None, vec![])), OpStatus::Running);
        // launch failure, with and without items: Failed, never Restored
        let launch_fail = NativeRun { launch_error: Some("x".into()), ..run() };
        assert_eq!(st(&op(Some(launch_fail), None, vec![])), OpStatus::Failed);
        // stopped or timed out while the entry is still present: Running
        let stopped = NativeRun { stopped_by_user: true, ..run() };
        assert_eq!(st(&op(Some(stopped.clone()), Some(Present), vec![])), OpStatus::Running);
        assert_eq!(st(&op(Some(NativeRun { timed_out: true, ..run() }), Some(Present), vec![])), OpStatus::Running);
        // stopped but the entry is gone: leftovers can be searched
        assert_eq!(st(&op(Some(stopped), Some(Gone), vec![])), OpStatus::AwaitingReview);
        // still installed
        assert_eq!(st(&op(Some(run()), Some(Present), vec![])), OpStatus::Failed);
        // reboot required, no items yet
        let reboot = NativeRun { exit_code: Some(3010), reboot_required: true, ..run() };
        assert_eq!(st(&op(Some(reboot.clone()), Some(Gone), vec![])), OpStatus::PendingReboot);
        // reboot is ignored once items exist
        assert_eq!(st(&op(Some(reboot), Some(Gone), vec![item(Removed)])), OpStatus::Completed);
        assert_eq!(st(&op(Some(run()), Some(Gone), vec![])), OpStatus::AwaitingReview);
        // item problems
        assert_eq!(st(&op(Some(run()), Some(Gone), vec![item(Removed), item(Locked)])), OpStatus::PartiallyCompleted);
        assert_eq!(st(&op(Some(run()), Some(Gone), vec![item(Blocked), item(Changed)])), OpStatus::Failed);
        assert_eq!(st(&op(Some(run()), Some(Gone), vec![item(NotFound), item(AccessDenied)])), OpStatus::Failed);
        // warnings
        let mut o = op(Some(run()), Some(Gone), vec![item(Removed)]);
        o.verify = Some(Verify { app_still_listed: true, reappeared: vec![] });
        assert_eq!(st(&o), OpStatus::CompletedWithWarnings);
        o.verify = Some(Verify { app_still_listed: false, reappeared: vec!["c".into()] });
        assert_eq!(st(&o), OpStatus::CompletedWithWarnings);
        assert_eq!(st(&op(Some(run()), Some(Orphaned), vec![item(Removed)])), OpStatus::CompletedWithWarnings);
        assert_eq!(st(&op(Some(NativeRun { exit_code: Some(1), ..run() }), Some(Gone), vec![item(Removed)])), OpStatus::CompletedWithWarnings);
        assert_eq!(st(&op(Some(NativeRun { timed_out: true, ..run() }), Some(Gone), vec![item(Removed)])), OpStatus::CompletedWithWarnings);
        // clean
        let mut o = op(Some(run()), Some(Gone), vec![item(Removed), item(NotFound)]);
        o.verify = Some(Verify { app_still_listed: false, reappeared: vec![] });
        assert_eq!(st(&o), OpStatus::Completed);
        // restore: requires at least one restorable item, all with a restore result
        let mut a = item(Removed);
        a.quarantine = Some(PathBuf::from(r"C:\q\1_a"));
        a.restore = Some(RestoreStatus::Restored);
        let mut b = a.clone();
        assert_eq!(st(&op(Some(run()), Some(Gone), vec![a.clone(), item(Removed)])), OpStatus::Restored);
        b.restore = Some(RestoreStatus::Conflict);
        assert_eq!(st(&op(Some(run()), Some(Gone), vec![a.clone(), b.clone()])), OpStatus::PartiallyRestored);
        b.restore = None;
        assert_ne!(st(&op(Some(run()), Some(Gone), vec![a, b])), OpStatus::Restored);
        // no restorable items and a launch failure stays Failed
        assert_eq!(st(&op(Some(NativeRun { launch_error: Some("x".into()), ..run() }), None, vec![item(Failed)])), OpStatus::Failed);
        // forced, nothing to run: the items decide
        assert_eq!(st(&forced(None, vec![])), OpStatus::AwaitingReview);
        let mut o = forced(None, vec![item(Removed)]);
        o.verify = Some(Verify { app_still_listed: false, reappeared: vec![] });
        assert_eq!(st(&o), OpStatus::Completed);
        assert_eq!(st(&forced(None, vec![item(Removed), item(Locked)])), OpStatus::PartiallyCompleted);
        assert_eq!(st(&forced(None, vec![item(Blocked)])), OpStatus::Failed);
        // forced with a chosen uninstaller (exe set) and no native run yet: Running; a launch error: Failed
        let mut o = forced(None, vec![]);
        o.launch.exe = PathBuf::from(r"C:\x\unins000.exe");
        assert_eq!(st(&o), OpStatus::Running);
        o.native = Some(NativeRun { launch_error: Some("x".into()), ..run() });
        assert_eq!(st(&o), OpStatus::Failed);
        // not forced and no native run: still Running even with an empty launch
        assert_eq!(st(&op(None, None, vec![item(Removed)])), OpStatus::Running);
    }

    #[test]
    fn target_key_is_stable() {
        let k = RegPath::new(Hive::Hkcu, View::V32, r"Software\Foo\Bar");
        let k2 = RegPath::new(Hive::Hkcu, View::V32, r"SOFTWARE\foo\BAR");
        assert_eq!(target_key(&Target::RegKey { key: k.clone() }), target_key(&Target::RegKey { key: k2.clone() }));
        assert_eq!(target_key(&Target::RegKey { key: k.clone() }), r"key:hkcu32:software\foo\bar");
        assert_eq!(target_key(&Target::RegValue { key: k, name: "Run".into() }), r"value:hkcu32:software\foo\bar|run");
        let p = |s: &str| Target::Path { path: PathBuf::from(s), kind: PathKind::File };
        assert_eq!(target_key(&p(r"C:\A\B\")), target_key(&p("c:/a/b")));
        assert_eq!(target_key(&p(r"C:\A\B")), r"path:c:\a\b");
        // Services and tasks: any case is the same id.
        let svc = |n: &str| Target::Service { name: n.into() };
        assert_eq!(target_key(&svc("LabSvcTool")), "service:labsvctool");
        assert_eq!(target_key(&svc("LabSvcTool")), target_key(&svc("LABSVCTOOL")));
        let task = |n: &str| Target::Task { path: n.into() };
        assert_eq!(target_key(&task(r"\Lab Vendor\Update")), r"task:\lab vendor\update");
        assert_eq!(target_key(&task(r"\Lab Vendor\Update")), target_key(&task(r"\LAB vendor\UPDATE")));
    }

    #[test]
    fn same_ident_ignores_running() {
        let node = |v: &str| RegNode { name: "S".into(), values: vec![RegVal { name: "ImagePath".into(), kind: 1, data: v.as_bytes().to_vec() }], keys: vec![] };
        let svc = |n: &str, running| Ident::Service { node: node(n), running };
        assert!(same_ident(&svc("a", None), &svc("a", Some(true))), "only the running state differs");
        assert!(same_ident(&svc("a", Some(false)), &svc("a", Some(true))));
        assert!(!same_ident(&svc("a", None), &svc("b", None)), "a different key");
        let task = |x: &str| Ident::Task { xml: x.into(), actions: vec![], enabled: true };
        assert!(same_ident(&task("a"), &task("a")));
        assert!(!same_ident(&task("a"), &task("b")));
        assert!(!same_ident(&task("a"), &Ident::None {}));
    }

    #[test]
    fn export_names_are_sanitized() {
        assert_eq!(safe_file_name("HKLM64:{AB}*?"), "HKLM64__AB___");
        assert_eq!(safe_file_name(&"x".repeat(200)).len(), 80);
        assert_eq!(safe_file_name(r"..\evil/name"), ".._evil_name");
    }

    #[test]
    fn op_id_validation() {
        assert!(valid_op_id("op-1").is_ok());
        assert!(valid_op_id("op-1731800000000").is_ok());
        for bad in [r"..\x", "op-", "op-12a", "op-123456789012345678901", "", "x-1", "op--1", "OP-1", r"op-1\..\x"] {
            assert_eq!(valid_op_id(bad), Err(Error("invalid operation id".into())), "{bad}");
        }
    }
}
