#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]
//! Thin Tauri commands over `uni-core`. All logic lives in the core crate.
use serde::Serialize;
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use std::collections::HashMap;
use std::os::windows::process::CommandExt;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use tauri::{AppHandle, Emitter, Manager, State};
use tauri_plugin_dialog::DialogExt;
use uni_core::env::Env;
use uni_core::model::*;
use uni_core::native::RunOptions;
use uni_core::{elevation, force, icon, inventory, ops, paths, trace};

struct StopFlag(Arc<AtomicBool>);

/// The install trace in progress: the installer the user picked and, once begun, the session (the "before" snapshot).
#[derive(Default)]
struct TraceState {
    picked: Option<PathBuf>,
    session: Option<trace::Session>,
}

struct TraceSlot(Mutex<TraceState>);

/// The program file or folder the user picked for a forced removal ("remove by path"); the UI never sends a path back.
struct ForceSlot(Mutex<Option<PathBuf>>);

impl ForceSlot {
    fn get(&self) -> MutexGuard<'_, Option<PathBuf>> {
        self.0.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

/// Program icons: the apps of every `list_apps` answer by id (the UI sends only ids), and PNG data URLs by icon file and index
/// (many hidden entries share one); None means no usable icon and the UI keeps the letter tile.
// shortcut: the cache lives for the session, so an updated program shows its old icon until the app restarts; key it by file time if that matters.
#[derive(Default)]
struct Icons {
    apps: HashMap<String, InstalledApp>,
    urls: HashMap<(PathBuf, i32), Option<String>>,
}

#[derive(Clone, Default)]
struct IconSlot(Arc<Mutex<Icons>>);

impl IconSlot {
    fn get(&self) -> MutexGuard<'_, Icons> {
        self.0.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

impl TraceSlot {
    fn get(&self) -> MutexGuard<'_, TraceState> {
        self.0.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct TraceBegun {
    objects: u64,
    ms: u64,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct AppInfo {
    version: String,
    elevated: bool,
    sandbox: bool,
    data_dir: PathBuf,
}

type Res<T> = Result<T, String>;

async fn blocking<T: Send + 'static>(f: impl FnOnce() -> Res<T> + Send + 'static) -> Res<T> {
    tauri::async_runtime::spawn_blocking(f).await.map_err(|e| e.to_string())?
}

fn s<T>(r: uni_core::Result<T>) -> Res<T> {
    r.map_err(|e| e.0)
}

#[tauri::command]
fn app_info(env: State<Env>) -> AppInfo {
    AppInfo { version: env!("CARGO_PKG_VERSION").into(), elevated: elevation::is_elevated(), sandbox: env.sandbox, data_dir: env.data_dir.clone() }
}

#[tauri::command]
async fn list_apps(env: State<'_, Env>, icons: State<'_, IconSlot>, include_hidden: bool) -> Res<Vec<InstalledApp>> {
    let env = env.inner().clone();
    let apps = blocking(move || s(inventory::list_apps(&env, include_hidden))).await?;
    // extend, not replace: ids from an earlier hidden list keep working
    icons.get().apps.extend(apps.iter().map(|a| (a.id.clone(), a.clone())));
    Ok(apps)
}

/// The program's icon as a PNG data URL, or None (the UI keeps the letter tile). Read-only: icon resources are read as data.
#[tauri::command]
async fn app_icon(env: State<'_, Env>, icons: State<'_, IconSlot>, id: String) -> Res<Option<String>> {
    let env = env.inner().clone();
    let icons = icons.inner().clone();
    blocking(move || {
        let Some(app) = icons.get().apps.get(&id).cloned() else { return Ok(None) };
        let Some(src) = icon::source(&app, &env) else { return Ok(None) };
        if let Some(url) = icons.get().urls.get(&src) {
            return Ok(url.clone());
        }
        let url = icon::extract(&src.0, src.1).map(|b| format!("data:image/png;base64,{}", STANDARD.encode(b)));
        icons.get().urls.insert(src, url.clone());
        Ok(url)
    })
    .await
}

#[tauri::command]
async fn describe_app(env: State<'_, Env>, id: String) -> Res<AppDetails> {
    let env = env.inner().clone();
    blocking(move || s(ops::describe(&env, &id))).await
}

#[tauri::command]
async fn preview_plan(env: State<'_, Env>, id: String) -> Res<Plan> {
    let env = env.inner().clone();
    blocking(move || s(ops::preview(&env, &id))).await
}

/// Re-runs the dry run and writes it to disk (the UI never sends a plan back, so no large ids lose precision in JS).
#[tauri::command]
async fn export_plan(env: State<'_, Env>, id: String) -> Res<PathBuf> {
    let env = env.inner().clone();
    blocking(move || {
        let plan = s(ops::preview(&env, &id))?;
        s(ops::export_plan(&env, &plan))
    })
    .await
}

#[tauri::command]
async fn export_report(env: State<'_, Env>, op_id: String) -> Res<PathBuf> {
    let env = env.inner().clone();
    blocking(move || s(ops::export_report(&env, &op_id))).await
}

/// begin + run_native in one blocking call; progress goes out as `native-progress` events.
#[tauri::command]
async fn uninstall(app: AppHandle, env: State<'_, Env>, stop: State<'_, StopFlag>, id: String, hidden_ok: bool) -> Res<Operation> {
    let env = env.inner().clone();
    let flag = stop.0.clone();
    flag.store(false, Ordering::SeqCst);
    blocking(move || {
        let op = s(ops::begin(&env, &id, hidden_ok))?;
        let opts = RunOptions {
            stop: flag,
            on_poll: Some(Box::new(move |p| {
                let _ = app.emit("native-progress", p.to_vec());
            })),
            ..Default::default()
        };
        s(ops::run_native(&env, &op.id, &opts))
    })
    .await
}

#[tauri::command]
fn stop_waiting(stop: State<StopFlag>) {
    stop.0.store(true, Ordering::SeqCst);
}

#[tauri::command]
async fn scan_leftovers(env: State<'_, Env>, op_id: String) -> Res<Operation> {
    let env = env.inner().clone();
    blocking(move || s(ops::scan_leftovers(&env, &op_id))).await
}

#[tauri::command]
async fn apply(env: State<'_, Env>, op_id: String, ids: Vec<String>) -> Res<Operation> {
    let env = env.inner().clone();
    blocking(move || s(ops::apply(&env, &op_id, &ids))).await
}

#[tauri::command]
async fn restore(env: State<'_, Env>, op_id: String) -> Res<Operation> {
    let env = env.inner().clone();
    blocking(move || s(ops::restore(&env, &op_id))).await
}

#[tauri::command]
async fn history(env: State<'_, Env>) -> Res<Vec<HistoryEntry>> {
    let env = env.inner().clone();
    blocking(move || s(ops::history(&env))).await
}

#[tauri::command]
fn open_in_explorer(path: String) -> Res<()> {
    let p = PathBuf::from(&path);
    // Trust boundary: the string goes into a raw command line.
    if path.contains('"') || path.chars().any(|c| (c as u32) < 0x20) || !paths::is_local_abs(&p) {
        return Err("invalid path".into());
    }
    let mut cmd = std::process::Command::new("explorer.exe");
    if p.exists() {
        cmd.raw_arg(format!("/select,\"{path}\""));
    } else {
        cmd.raw_arg(format!("\"{}\"", p.parent().map(|x| x.display().to_string()).unwrap_or(path.clone())));
    }
    cmd.spawn().map(|_| ()).map_err(|e| e.to_string())
}

#[tauri::command]
fn restart_as_admin(app: AppHandle, env: State<Env>) -> Res<()> {
    if env.sandbox {
        return Err("not available in sandbox mode: the elevated process would lose UNIINSTALLER_SANDBOX".into());
    }
    s(elevation::relaunch_elevated())?;
    app.exit(0);
    Ok(())
}

/// Asks for the installer to trace. Runs on a worker thread (the dialog blocks); the path stays here, so the UI never sends one back.
/// In sandbox mode the dialog offers only `.cmd` and `.bat` files and starts in the sandbox's `installers` folder.
#[tauri::command]
async fn pick_installer(app: AppHandle, env: State<'_, Env>, slot: State<'_, TraceSlot>, title: String, filter: String) -> Res<Option<PathBuf>> {
    let sandbox_dir = env.sandbox.then(|| env.data_dir.parent().map(|r| r.join("installers"))).flatten();
    let exts: &'static [&'static str] = if env.sandbox { &["cmd", "bat"] } else { &["exe", "msi"] };
    let picked = blocking(move || {
        let mut d = app.dialog().file().set_title(title).add_filter(filter, exts);
        if let Some(w) = app.get_webview_window("main") {
            d = d.set_parent(&w);
        }
        if let Some(dir) = sandbox_dir {
            d = d.set_directory(dir);
        }
        Ok(d.blocking_pick_file().and_then(|f| f.into_path().ok()))
    })
    .await?;
    let mut st = slot.get();
    if picked.is_some() {
        st.picked = picked; // Cancel keeps the earlier pick
    }
    Ok(st.picked.clone())
}

/// Asks for the program (or its folder) to remove by path. Runs on a worker thread (the dialog blocks). Returns the new pick, or None
/// when the dialog was cancelled (the earlier pick stays in the slot). The file dialog resolves shortcuts itself. In sandbox mode it
/// starts in the sandbox folder, and `force::check` refuses anything outside it anyway.
#[tauri::command]
async fn force_pick(app: AppHandle, env: State<'_, Env>, slot: State<'_, ForceSlot>, folder: bool, title: String, filter: String) -> Res<Option<PathBuf>> {
    let sandbox_dir = env.sandbox.then(|| env.data_dir.parent().map(PathBuf::from)).flatten();
    let picked = blocking(move || {
        let mut d = app.dialog().file().set_title(title);
        if !folder {
            d = d.add_filter(filter, &["exe", "lnk"]);
        }
        if let Some(w) = app.get_webview_window("main") {
            d = d.set_parent(&w);
        }
        if let Some(dir) = sandbox_dir {
            d = d.set_directory(dir);
        }
        Ok(if folder { d.blocking_pick_folder() } else { d.blocking_pick_file() }.and_then(|f| f.into_path().ok()))
    })
    .await?;
    if picked.is_some() {
        *slot.get() = picked.clone();
    }
    Ok(picked)
}

/// Read-only identity check of the picked path (`force::check`).
#[tauri::command]
async fn force_check(env: State<'_, Env>, slot: State<'_, ForceSlot>) -> Res<ForceCheck> {
    let env = env.inner().clone();
    let path = slot.get().clone().ok_or("choose a program or a folder first")?;
    blocking(move || s(force::check(&env, &path))).await
}

/// begin_forced, then the uninstaller the user chose (if any); progress goes out as `native-progress` events.
#[tauri::command]
async fn force_run(app: AppHandle, env: State<'_, Env>, stop: State<'_, StopFlag>, slot: State<'_, ForceSlot>, name: String, publisher: Option<String>, uninstaller: Option<PathBuf>) -> Res<Operation> {
    let env = env.inner().clone();
    let flag = stop.0.clone();
    flag.store(false, Ordering::SeqCst);
    let path = slot.get().clone().ok_or("choose a program or a folder first")?;
    blocking(move || {
        let op = s(ops::begin_forced(&env, &path, &name, publisher.as_deref(), uninstaller.as_deref()))?;
        if op.launch.exe.as_os_str().is_empty() {
            return Ok(op);
        }
        let opts = RunOptions {
            stop: flag,
            on_poll: Some(Box::new(move |p| {
                let _ = app.emit("native-progress", p.to_vec());
            })),
            ..Default::default()
        };
        s(ops::run_native(&env, &op.id, &opts))
    })
    .await
}

/// Takes the "before" snapshot of the picked installer's trace (read-only).
#[tauri::command]
async fn trace_begin(env: State<'_, Env>, slot: State<'_, TraceSlot>) -> Res<TraceBegun> {
    let env = env.inner().clone();
    let path = {
        let st = slot.get();
        if st.session.is_some() {
            return Err("a trace is already in progress".into());
        }
        st.picked.clone().ok_or("choose an installer first")?
    };
    let session = blocking(move || {
        let launch = s(trace::installer_launch(&env, &path))?;
        s(trace::begin(&env, launch))
    })
    .await?;
    let begun = TraceBegun { objects: session.before.objects, ms: session.before.ms };
    slot.get().session = Some(session);
    Ok(begun)
}

/// Runs the installer and waits for its whole process tree; progress goes out as `native-progress` events.
#[tauri::command]
async fn trace_install(app: AppHandle, env: State<'_, Env>, stop: State<'_, StopFlag>, slot: State<'_, TraceSlot>) -> Res<NativeRun> {
    let env = env.inner().clone();
    let flag = stop.0.clone();
    flag.store(false, Ordering::SeqCst);
    let mut session = slot.get().session.take().ok_or("no trace in progress")?;
    let (session, result) = tauri::async_runtime::spawn_blocking(move || {
        let opts = RunOptions {
            stop: flag,
            on_poll: Some(Box::new(move |p| {
                let _ = app.emit("native-progress", p.to_vec());
            })),
            ..Default::default()
        };
        let r = trace::install(&env, &mut session, &opts);
        (session, r)
    })
    .await
    .map_err(|e| e.to_string())?;
    let run = session.native.clone();
    slot.get().session = Some(session);
    s(result)?;
    run.ok_or_else(|| "the installer did not run".to_string())
}

/// Takes the "after" snapshot, saves the journal and returns what it holds. The session is consumed either way.
#[tauri::command]
async fn trace_finish(env: State<'_, Env>, slot: State<'_, TraceSlot>) -> Res<TraceSummary> {
    let env = env.inner().clone();
    let session = slot.get().session.take().ok_or("no trace in progress")?;
    if session.native.is_none() {
        slot.get().session = Some(session);
        return Err("the installer has not run yet".into());
    }
    blocking(move || Ok(trace::summary(&s(trace::finish(&env, session))?))).await
}

#[tauri::command]
fn trace_cancel(slot: State<TraceSlot>) {
    *slot.get() = TraceState::default();
}

/// The UI ignores errors here (offline, no release yet).
#[tauri::command]
async fn update_check(app: AppHandle) -> Res<Option<String>> {
    use tauri_plugin_updater::UpdaterExt;
    let u = app.updater().map_err(|e| e.to_string())?.check().await.map_err(|e| e.to_string())?;
    Ok(u.map(|u| u.version))
}

/// On Windows the plugin launches the NSIS installer and exits the process itself.
// shortcut: the updater has no rollback and its end-to-end check (0.1.0 -> 0.1.1) is manual,
// add a rollback path if a broken release ever ships.
#[tauri::command]
async fn update_install(app: AppHandle, slot: State<'_, TraceSlot>) -> Res<()> {
    use tauri_plugin_updater::UpdaterExt;
    if ops::is_busy() || slot.get().session.is_some() {
        return Err("operation in progress".into());
    }
    if let Some(u) = app.updater().map_err(|e| e.to_string())?.check().await.map_err(|e| e.to_string())? {
        u.download_and_install(|_, _| {}, || {}).await.map_err(|e| e.to_string())?;
    }
    Ok(())
}

fn main() {
    let env = match Env::from_process_env() {
        Ok(e) => e,
        Err(e) => {
            // Fail closed: an invalid sandbox variable never falls back to the real system.
            eprintln!("{e}");
            std::process::exit(2);
        }
    };
    tauri::Builder::default()
        .plugin(tauri_plugin_updater::Builder::new().build())
        .plugin(tauri_plugin_dialog::init())
        .manage(env)
        .manage(StopFlag(Arc::new(AtomicBool::new(false))))
        .manage(TraceSlot(Mutex::new(TraceState::default())))
        .manage(ForceSlot(Mutex::new(None)))
        .manage(IconSlot::default())
        .invoke_handler(tauri::generate_handler![
            app_info,
            list_apps,
            app_icon,
            describe_app,
            preview_plan,
            export_plan,
            export_report,
            uninstall,
            stop_waiting,
            scan_leftovers,
            apply,
            restore,
            history,
            open_in_explorer,
            restart_as_admin,
            pick_installer,
            force_pick,
            force_check,
            force_run,
            trace_begin,
            trace_install,
            trace_finish,
            trace_cancel,
            update_check,
            update_install
        ])
        .run(tauri::generate_context!())
        .expect("error while running the application");
}

#[cfg(test)]
mod tests {
    /// The core protects the WebView2 profile folder named after the Tauri identifier; keep both equal.
    #[test]
    fn identifier_matches_core() {
        let conf: serde_json::Value = serde_json::from_str(include_str!("../tauri.conf.json")).unwrap();
        assert_eq!(conf["identifier"], uni_core::env::APP_IDENTIFIER);
    }
}
