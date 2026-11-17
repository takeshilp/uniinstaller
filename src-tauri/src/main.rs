#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]
//! Thin Tauri commands over `uni-core`. All logic lives in the core crate.
use serde::Serialize;
use std::os::windows::process::CommandExt;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use tauri::{AppHandle, Emitter, State};
use uni_core::env::Env;
use uni_core::model::*;
use uni_core::native::RunOptions;
use uni_core::{elevation, inventory, ops, paths};

struct StopFlag(Arc<AtomicBool>);

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
async fn list_apps(env: State<'_, Env>) -> Res<Vec<InstalledApp>> {
    let env = env.inner().clone();
    blocking(move || s(inventory::list_apps(&env))).await
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
async fn uninstall(app: AppHandle, env: State<'_, Env>, stop: State<'_, StopFlag>, id: String) -> Res<Operation> {
    let env = env.inner().clone();
    let flag = stop.0.clone();
    flag.store(false, Ordering::SeqCst);
    blocking(move || {
        let op = s(ops::begin(&env, &id))?;
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

/// The UI ignores errors here (offline, no release yet).
#[tauri::command]
async fn update_check(app: AppHandle) -> Res<Option<String>> {
    use tauri_plugin_updater::UpdaterExt;
    let u = app.updater().map_err(|e| e.to_string())?.check().await.map_err(|e| e.to_string())?;
    Ok(u.map(|u| u.version))
}

/// On Windows the plugin launches the NSIS installer and exits the process itself.
// shortcut: the updater is verifiable end to end only after two published releases and has no rollback,
// do a manual check at the second release.
#[tauri::command]
async fn update_install(app: AppHandle) -> Res<()> {
    use tauri_plugin_updater::UpdaterExt;
    if ops::is_busy() {
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
        .manage(env)
        .manage(StopFlag(Arc::new(AtomicBool::new(false))))
        .invoke_handler(tauri::generate_handler![
            app_info,
            list_apps,
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
            update_check,
            update_install
        ])
        .run(tauri::generate_context!())
        .expect("error while running the application");
}
