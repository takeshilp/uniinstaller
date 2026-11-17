//! The binary refuses every non-check command outside Windows Sandbox, even with a forged %USERNAME%
//! and a valid lab folder: the guard reads the process token, not the environment.
use std::process::Command;

#[test]
fn refuses_outside_the_guest_even_with_a_forged_environment() {
    let lab = tempfile::tempdir().unwrap();
    std::fs::write(lab.path().join(".uniinstaller-lab"), b"").unwrap();
    let cmds: [&[&str]; 7] = [&["list"], &["begin", "HKCU64:X"], &["native", "op-1"], &["scan", "op-1"],
        &["apply", "op-1", "default"], &["restore", "op-1"], &["show", "op-1"]];
    for args in cmds {
        let out = Command::new(env!("CARGO_BIN_EXE_uni-lab")).args(args)
            .env_remove("UNIINSTALLER_SANDBOX").env("UNIINSTALLER_LAB", lab.path()).env("USERNAME", "WDAGUtilityAccount")
            .output().unwrap();
        let err = String::from_utf8_lossy(&out.stderr);
        assert_eq!(out.status.code(), Some(2), "{args:?}: {err}");
        assert!(err.contains("not a Windows Sandbox guest"), "{args:?}: {err}");
    }
    let out = Command::new(env!("CARGO_BIN_EXE_uni-lab")).arg("check").env("UNIINSTALLER_LAB", lab.path()).output().unwrap();
    assert_eq!(out.status.code(), Some(2));
}
