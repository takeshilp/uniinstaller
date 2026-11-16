mod common;
use common::Fixture;
use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use uni_core::model::*;
use uni_core::native::*;
use uni_core::registry;
use winreg::enums::*;

fn cmd() -> PathBuf {
    PathBuf::from(std::env::var("SystemRoot").unwrap()).join(r"System32\cmd.exe")
}

fn launch(args: &str) -> Launch {
    Launch { raw: format!("cmd {args}"), exe: cmd(), args: args.to_string(), argv: vec![], msi_product: None }
}

fn opts() -> RunOptions {
    RunOptions { show_window: false, poll: Duration::from_millis(50), ..Default::default() }
}

#[test]
fn waits_for_child_after_root_exits() {
    let f = Fixture::new();
    let key = RegPath::new(Hive::Hkcu, View::V64, format!(r"Software\uniinstaller-tests\{}\NativeTest", f.tag));
    registry::create(&key, KEY_ALL_ACCESS).unwrap();
    let bat = f.second_dir().join("child.bat");
    std::fs::write(&bat, format!("@echo off\r\nping -n 3 127.0.0.1 >nul\r\nreg delete \"HKCU\\{}\" /f\r\n", key.path)).unwrap();
    let t = Instant::now();
    let run = run_uninstaller(&launch(&format!("/c start \"\" /b cmd /c \"{}\"", bat.display())), &opts());
    assert_eq!(run.launch_error, None);
    assert!(t.elapsed() >= Duration::from_millis(1800), "returned after {:?}", t.elapsed());
    assert!(run.processes.len() >= 2, "{:?}", run.processes);
    assert!(!registry::exists(&key), "the child finished its work before we returned");
    assert!(!run.timed_out && !run.stopped_by_user);
}

#[test]
fn exit_code_and_reboot() {
    let run = run_uninstaller(&launch("/c exit 3010"), &opts());
    assert_eq!(run.exit_code, Some(3010));
    assert!(run.reboot_required);
    let run = run_uninstaller(&launch("/c exit 0"), &opts());
    assert_eq!(run.exit_code, Some(0));
    assert!(!run.reboot_required);
    assert!(run.ended_ms >= run.started_ms);
}

#[test]
fn timeout_does_not_kill() {
    let o = RunOptions { timeout: Duration::from_secs(1), ..opts() };
    let t = Instant::now();
    let run = run_uninstaller(&launch("/c ping -n 4 127.0.0.1 >nul"), &o);
    assert!(run.timed_out);
    assert!(t.elapsed() < Duration::from_millis(2500));
    assert!(run.processes.iter().any(alive), "the uninstaller was not killed");
    std::thread::sleep(Duration::from_secs(4)); // let it finish so nothing outlives the test
}

#[test]
fn stop_flag_returns_without_killing() {
    let seen = Arc::new(AtomicUsize::new(0));
    let s2 = seen.clone();
    let o = RunOptions { on_poll: Some(Box::new(move |p| { s2.fetch_max(p.len(), Ordering::SeqCst); })), ..opts() };
    let stop = o.stop.clone();
    std::thread::spawn(move || {
        std::thread::sleep(Duration::from_millis(300));
        stop.store(true, Ordering::SeqCst);
    });
    let t = Instant::now();
    let run = run_uninstaller(&launch("/c ping -n 4 127.0.0.1 >nul"), &o);
    assert!(t.elapsed() < Duration::from_secs(2), "{:?}", t.elapsed());
    assert!(run.stopped_by_user);
    assert!(!run.timed_out);
    assert!(seen.load(Ordering::SeqCst) >= 1, "on_poll saw a live process");
    assert!(run.processes.iter().any(alive), "the child is still alive");
    std::thread::sleep(Duration::from_secs(4));
}

#[test]
fn missing_exe_is_launch_error() {
    let l = Launch { raw: "x".into(), exe: PathBuf::from(r"C:\nonexistent dir\un.exe"), args: "/S".into(), argv: vec![], msi_product: None };
    let run = run_uninstaller(&l, &opts());
    assert!(run.launch_error.is_some());
    assert!(run.processes.is_empty());
    let _ = Mutex::new(());
}
