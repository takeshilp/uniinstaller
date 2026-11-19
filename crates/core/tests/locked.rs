//! Locked files on the fixture sandbox: who holds them (Restart Manager), a confirmed close and retry, the restart marker.
//! The holders are programs this test starts itself; the Restart Manager is asked about the fixture's files only, and a close runs only
//! on the compiled `lockholder.exe` window program this test spawned, after the test asserted its pid and kind. Nothing is ever killed.
mod common;
use common::Fixture;
use std::fs;
use std::os::windows::fs::OpenOptionsExt;
use std::os::windows::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};
use uni_core::model::*;
use uni_core::native::RunOptions;
use uni_core::ops;
use uni_core::sandbox::*;

const NOTES: &str = "HKCU64:SandboxNotes";

fn opts() -> RunOptions {
    RunOptions { show_window: false, poll: Duration::from_millis(50), ..Default::default() }
}

fn uninstalled(f: &Fixture) -> Operation {
    let op = ops::begin(&f.env, NOTES, false).unwrap();
    let op = ops::run_native(&f.env, &op.id, &opts()).unwrap();
    assert!(op.native.as_ref().unwrap().launch_error.is_none(), "{:?}", op.native);
    ops::scan_leftovers(&f.env, &op.id).unwrap()
}

fn selectable(op: &Operation) -> Vec<String> {
    op.plan.as_ref().unwrap().candidates.iter().filter(|c| c.blocks.is_empty()).map(|c| c.id.clone()).collect()
}

fn item<'a>(op: &'a Operation, suffix: &str) -> &'a ItemRecord {
    let s = suffix.to_lowercase();
    op.items.iter().find(|i| i.candidate_id.ends_with(&s)).unwrap_or_else(|| panic!("no item ending with {suffix}"))
}

fn ini_id(op: &Operation) -> String {
    item(op, "config.ini").candidate_id.clone()
}

fn powershell() -> PathBuf {
    PathBuf::from(std::env::var("SystemRoot").unwrap()).join(r"System32\WindowsPowerShell\v1.0\powershell.exe")
}

/// `lab/apps/lockholder.cs` compiled once per test run by Windows PowerShell 5.1.
fn holder_exe() -> &'static Path {
    static EXE: std::sync::OnceLock<PathBuf> = std::sync::OnceLock::new();
    EXE.get_or_init(|| {
        let dir = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join(format!("lockholder-{}", std::process::id()));
        fs::create_dir_all(&dir).unwrap();
        let exe = dir.join("lockholder.exe");
        let src = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(r"..\..\lab\apps\lockholder.cs");
        assert!(!src.display().to_string().contains('\'') && !exe.display().to_string().contains('\''));
        let cmd = format!("Add-Type -Path '{}' -OutputAssembly '{}' -OutputType WindowsApplication -ReferencedAssemblies System.Windows.Forms", src.display(), exe.display());
        let ok = Command::new(powershell()).args(["-NoProfile", "-NonInteractive", "-Command", &cmd]).stdin(Stdio::null()).status().unwrap().success();
        assert!(ok && exe.is_file(), "compiling the lock holder failed");
        exe
    })
}

fn wait_ready(ready: &Path) {
    let t = Instant::now();
    while !ready.exists() {
        assert!(t.elapsed() < Duration::from_secs(30), "the holder did not start");
        std::thread::sleep(Duration::from_millis(100));
    }
}

fn wait_exit(c: &mut Child, secs: u64) -> bool {
    let t = Instant::now();
    while t.elapsed() < Duration::from_secs(secs) {
        if c.try_wait().unwrap().is_some() {
            return true;
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    false
}

/// The window holder (`file` None = a bystander that holds nothing). It closes itself after 60 s; nothing ever kills it.
fn window_holder(file: Option<&Path>, ready: &Path) -> Child {
    let f = file.map(|p| p.display().to_string()).unwrap_or_else(|| "-".into());
    let c = Command::new(holder_exe()).args([f.as_str(), &ready.display().to_string(), "60"]).stdin(Stdio::null()).stdout(Stdio::null()).stderr(Stdio::null()).spawn().unwrap();
    wait_ready(ready);
    c
}

/// A console program holding `file` in its own hidden console (`CREATE_NEW_CONSOLE`, never ours). The product must refuse to close it.
/// It ends by itself after 60 s; nothing ever kills it.
fn console_holder(file: &Path, ready: &Path) -> Child {
    let (f, r) = (file.display().to_string(), ready.display().to_string());
    assert!(!f.contains('\'') && !r.contains('\''));
    let cmd = format!("$f = [IO.File]::Open('{f}', 'Open', 'Read', 'None'); Set-Content -LiteralPath '{r}' ok; Start-Sleep 60");
    let c = Command::new(powershell())
        .args(["-NoProfile", "-WindowStyle", "Hidden", "-Command", &cmd])
        .creation_flags(0x10)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    wait_ready(ready);
    c
}

#[test]
fn close_and_retry_closes_only_the_confirmed_holder() {
    let f = Fixture::new();
    let op = uninstalled(&f);
    let ini = notes_dir(&f.env).join("config.ini");
    let mut holder = window_holder(Some(&ini), &f.second_dir().join("ready1"));
    let mut bystander = window_holder(None, &f.second_dir().join("ready2"));
    let applied = ops::apply(&f.env, &op.id, &selectable(&op)).unwrap();
    assert_eq!(item(&applied, "config.ini").status, ItemStatus::Locked);

    let t = Instant::now();
    let locks = ops::lock_holders(&f.env, &op.id).unwrap();
    println!("lock_holders: {} ms, {locks:?}", t.elapsed().as_millis());
    let hs: Vec<Holder> = locks.iter().flat_map(|l| l.holders.clone()).collect();
    assert_eq!(hs.len(), 1, "{locks:?}");
    let h = &hs[0];
    assert_eq!(h.pid, holder.id());
    assert_eq!(h.kind, HolderKind::MainWindow, "{h:?}");
    assert_eq!(h.block, None);
    assert!(!h.name.trim().is_empty());
    assert_eq!((locks[0].reasons, locks[0].files), (0, 1));

    // nothing confirmed, or a different process identity: refused, and the holder is untouched
    let e = ops::close_and_retry(&f.env, &op.id, &[]).unwrap_err();
    assert!(e.0.contains("confirmed"), "{e}");
    assert!(holder.try_wait().unwrap().is_none());
    let wrong = Holder { started: h.started + 1, ..h.clone() };
    ops::close_and_retry(&f.env, &op.id, &[wrong]).unwrap_err();
    assert!(holder.try_wait().unwrap().is_none());
    assert!(ini.exists());

    let t = Instant::now();
    let r = ops::close_and_retry(&f.env, &op.id, &hs).unwrap();
    println!("close_and_retry: {} ms, shutdown_error {:?}, restart_error {:?}, closed {:?}", t.elapsed().as_millis(), r.shutdown_error, r.restart_error, r.closed.iter().map(|h| h.pid).collect::<Vec<_>>());
    assert_eq!(r.closed.iter().map(|h| h.pid).collect::<Vec<_>>(), vec![holder.id()]);
    assert!(r.still_running.is_empty(), "{:?}", r.still_running);
    assert!(wait_exit(&mut holder, 10), "the holder did not exit");
    assert!(bystander.try_wait().unwrap().is_none(), "a process that held nothing survives");
    assert_eq!(item(&r.op, "config.ini").status, ItemStatus::Removed);
    assert!(!ini.exists());
    assert_eq!(r.op.status, OpStatus::Completed, "{:?}", r.op.status_detail);

    let restored = ops::restore(&f.env, &op.id).unwrap();
    assert_eq!(restored.status, OpStatus::Restored);
    assert!(ini.exists());
    // ends by itself; the bystander was never ours to stop except by its own timer, so leave it to that
    drop(bystander);
}

#[test]
fn console_holder_is_refused() {
    let f = Fixture::new();
    let op = uninstalled(&f);
    let ini = notes_dir(&f.env).join("config.ini");
    let mut child = console_holder(&ini, &f.second_dir().join("ready"));
    let applied = ops::apply(&f.env, &op.id, &selectable(&op)).unwrap();
    assert_eq!(item(&applied, "config.ini").status, ItemStatus::Locked);
    let locks = ops::lock_holders(&f.env, &op.id).unwrap();
    let hs: Vec<Holder> = locks.iter().flat_map(|l| l.holders.clone()).collect();
    println!("console holders: {hs:?} reasons {:?}", locks.iter().map(|l| l.reasons).collect::<Vec<_>>());
    assert_eq!(hs.len(), 1, "{locks:?}");
    assert_eq!(hs[0].pid, child.id());
    assert_eq!(hs[0].kind, HolderKind::Console, "{:?}", hs[0]);
    assert_eq!(hs[0].block, Some(HolderBlock::Console));
    let e = ops::close_and_retry(&f.env, &op.id, &hs).unwrap_err();
    assert!(e.0.contains("cannot be closed"), "{e}");
    assert!(child.try_wait().unwrap().is_none(), "the console program was not touched");
    assert!(ini.exists());
    let again = ops::load(&f.env, &op.id).unwrap();
    assert_eq!(item(&again, "config.ini").status, ItemStatus::Locked);
}

#[test]
fn own_process_is_never_closed() {
    let f = Fixture::new();
    let op = uninstalled(&f);
    let ini = notes_dir(&f.env).join("config.ini");
    let _held = fs::OpenOptions::new().read(true).share_mode(0).open(&ini).unwrap();
    let applied = ops::apply(&f.env, &op.id, &selectable(&op)).unwrap();
    assert_eq!(item(&applied, "config.ini").status, ItemStatus::Locked);
    let locks = ops::lock_holders(&f.env, &op.id).unwrap();
    println!("own process: {locks:?}");
    let hs: Vec<Holder> = locks.iter().flat_map(|l| l.holders.clone()).collect();
    let me = hs.iter().find(|h| h.pid == std::process::id()).unwrap_or_else(|| panic!("our own pid is not listed: {locks:?}"));
    assert_eq!(me.block, Some(HolderBlock::Ours));
    assert!(locks[0].reasons & 0x10 != 0, "RM reports DetectedSelf: {:#x}", locks[0].reasons);
    ops::close_and_retry(&f.env, &op.id, &hs).unwrap_err();
    assert!(ini.exists());
    assert_eq!(item(&ops::load(&f.env, &op.id).unwrap(), "config.ini").status, ItemStatus::Locked);
}

#[test]
fn remind_after_reboot_is_journalled_and_cleared() {
    let f = Fixture::new();
    let op = uninstalled(&f);
    let ini = notes_dir(&f.env).join("config.ini");
    let held = fs::OpenOptions::new().read(true).share_mode(0).open(&ini).unwrap();
    let applied = ops::apply(&f.env, &op.id, &selectable(&op)).unwrap();
    assert_eq!(item(&applied, "config.ini").status, ItemStatus::Locked);
    assert!(applied.continue_after_reboot.is_none());
    let o = ops::remind_after_reboot(&f.env, &op.id, true).unwrap();
    let t = o.continue_after_reboot.expect("the marker is set");
    assert_eq!(o.status, OpStatus::PendingReboot, "{:?}", o.status_detail);
    assert_eq!(ops::load(&f.env, &op.id).unwrap().continue_after_reboot, Some(t));
    assert!(!ops::continues_after_reboot(&o, ops::boot_ms()), "no restart since the marker");
    assert!(ops::continues_after_reboot(&o, t + 1));
    let retry = vec![ini_id(&o)];
    // retried while still locked: the marker stays
    let o = ops::apply(&f.env, &op.id, &retry).unwrap();
    assert_eq!(o.continue_after_reboot, Some(t));
    assert_eq!(o.status, OpStatus::PendingReboot);
    drop(held);
    let o = ops::apply(&f.env, &op.id, &retry).unwrap();
    assert_eq!(o.continue_after_reboot, None);
    assert_eq!(o.status, OpStatus::Completed, "{:?}", o.status_detail);
    ops::remind_after_reboot(&f.env, &op.id, true).unwrap_err();
    // a fresh operation's manifest has no marker
    let g = Fixture::new();
    let fresh = ops::begin(&g.env, NOTES, false).unwrap();
    let text = fs::read_to_string(g.env.data_dir.join("operations").join(&fresh.id).join("manifest.json")).unwrap();
    assert!(!text.contains("continueAfterReboot"));
}
