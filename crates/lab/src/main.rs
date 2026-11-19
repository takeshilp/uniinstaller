//! uni-lab: lab-only driver over `uni_core::ops`, run inside Windows Sandbox by `lab/guest/run.ps1`. Never shipped.
//! Every command except `check` needs the fixture sandbox (`UNIINSTALLER_SANDBOX`) or a Windows Sandbox guest.
use std::ffi::OsString;
use std::path::PathBuf;
use std::time::Duration;
use uni_core::env::{Env, SANDBOX_VAR};
use uni_core::model::{EvidenceCode, ForceCheck, Group, Plan};
use uni_core::native::RunOptions;
use uni_core::{elevation, force, inventory, ops, paths, trace};
use windows::Win32::System::Threading::{GetCurrentProcess, TerminateProcess};
use windows::Win32::System::WindowsProgramming::GetUserNameW;
use windows::core::PWSTR;

const GUEST_USER: &str = "WDAGUtilityAccount";
const LAB_VAR: &str = "UNIINSTALLER_LAB";
const LAB_MARKER: &str = ".uniinstaller-lab";
const REFUSED: i32 = 2;
const CRASH_CODE: u32 = 99;
/// `force` found the path Listed or Refused: the check result is printed instead of an operation.
const CHECK_REFUSED: i32 = 3;
const USAGE: &str = "usage: uni-lab check | list | trace <installer> | begin <app-id> | force <path> <name> [--publisher <p>] [--run] | native <op> | scan <op> | apply <op> default|default+reverts|unblocked [--crash-after-first-move] | restore <op> | show <op>";

/// Pure. The token user must be the Windows Sandbox account (it exists disabled on a normal host) and
/// UNIINSTALLER_LAB must name a local folder with the lab marker (explicit intent, not a location proof).
fn check_guest(user: &str, lab: Option<OsString>) -> Result<(), String> {
    if !user.eq_ignore_ascii_case(GUEST_USER) {
        return Err(format!("not a Windows Sandbox guest (token user is '{user}')"));
    }
    let lab = lab.ok_or(format!("{LAB_VAR} is not set"))?;
    let p = PathBuf::from(&lab);
    if lab.is_empty() || !paths::is_local_abs(&p) || !p.join(LAB_MARKER).is_file() {
        return Err(format!("{LAB_VAR} must be a local absolute folder containing {LAB_MARKER}"));
    }
    Ok(())
}

/// The process token's user (GetUserNameW), never %USERNAME%. Empty on failure, which fails the check.
fn token_user() -> String {
    let mut buf = [0u16; 257];
    let mut len = buf.len() as u32;
    // SAFETY: `buf` outlives the call and `len` holds its capacity in characters.
    match unsafe { GetUserNameW(Some(PWSTR(buf.as_mut_ptr())), &mut len) } {
        Ok(()) => String::from_utf16_lossy(&buf[..(len as usize).saturating_sub(1)]),
        Err(_) => String::new(),
    }
}

/// Fixture sandbox when UNIINSTALLER_SANDBOX is set (same rule as the GUI and `uni`); otherwise the real system, guest only.
fn lab_env() -> Result<Env, String> {
    if std::env::var_os(SANDBOX_VAR).is_some() {
        return Env::from_process_env().map_err(|e| e.0);
    }
    check_guest(&token_user(), std::env::var_os(LAB_VAR))?;
    Env::system().map_err(|e| e.0)
}

/// `default`: the product's preselection. `default+reverts`: the preselection plus every unblocked revert, like a user who also
/// confirms the "previous values" group. `unblocked`: every candidate without a hard block and without a user-data warning, i.e. a
/// user who ticks everything the product does not warn about.
fn select(plan: &Plan, policy: &str) -> Result<Vec<String>, String> {
    if !matches!(policy, "default" | "default+reverts" | "unblocked") {
        return Err(format!("unknown policy '{policy}'"));
    }
    Ok(plan
        .candidates
        .iter()
        .filter(|c| match policy {
            "default" => c.selected,
            "default+reverts" => c.selected || (c.group == Group::Revert && c.blocks.is_empty()),
            _ => c.blocks.is_empty() && !c.evidence.iter().any(|e| e.code == EvidenceCode::UserDataLikely),
        })
        .map(|c| c.id.clone())
        .collect())
}

/// Traces one installer: snapshot, install (waits for the whole process tree), snapshot, journal. Fails when the installer did not
/// start, timed out or exited with an error, because nothing can be measured from such a run.
fn trace_install(env: &Env, installer: &str) -> Result<String, String> {
    let core = |e: uni_core::Error| e.0;
    let launch = trace::installer_launch(env, std::path::Path::new(installer)).map_err(core)?;
    let mut session = trace::begin(env, launch).map_err(core)?;
    let opts = RunOptions { timeout: Duration::from_secs(300), ..Default::default() };
    trace::install(env, &mut session, &opts).map_err(core)?;
    let run = session.native.clone().ok_or("the installer did not run")?;
    if let Some(e) = &run.launch_error {
        return Err(format!("the installer did not start: {e}"));
    }
    if run.timed_out || run.exit_code != Some(0) {
        return Err(format!("the installer did not finish cleanly (exit {:?}, timed out {})", run.exit_code, run.timed_out));
    }
    pretty(&trace::finish(env, session).map_err(core)?)
}

/// Kills this process as soon as the first payload lands in `operations\<op>\q`, mid-apply, like an external kill.
// shortcut: the kill point is only "after the first quarantined path", add a registry-phase point if resume bugs appear there.
fn crash_after_first_move(env: &Env, op_id: &str) {
    let q = env.data_dir.join("operations").join(op_id).join("q");
    std::thread::spawn(move || {
        loop {
            if std::fs::read_dir(&q).is_ok_and(|mut r| r.next().is_some()) {
                // SAFETY: terminates the current process immediately.
                unsafe {
                    let _ = TerminateProcess(GetCurrentProcess(), CRASH_CODE);
                }
            }
            std::thread::sleep(Duration::from_millis(1));
        }
    });
}

fn pretty(v: &impl serde::Serialize) -> Result<String, String> {
    serde_json::to_string_pretty(v).map_err(|e| e.to_string())
}

fn run(args: &[String]) -> Result<i32, String> {
    let arg = |i: usize| args.get(i).map(String::as_str).ok_or_else(|| USAGE.to_string());
    let cmd = arg(0)?;
    if cmd == "check" {
        let user = token_user();
        let res = check_guest(&user, std::env::var_os(LAB_VAR));
        let guest = res.is_ok();
        let v = serde_json::json!({ "user": user, "guest": guest, "reason": res.err(),
            "elevated": elevation::is_elevated(), "release": !cfg!(debug_assertions) });
        println!("{v}");
        return Ok(if guest { 0 } else { REFUSED });
    }
    let env = match lab_env() {
        Ok(e) => e,
        Err(e) => {
            eprintln!("refused: {e}");
            return Ok(REFUSED);
        }
    };
    let core = |e: uni_core::Error| e.0;
    let out = match cmd {
        "list" => pretty(&inventory::list_apps(&env, true).map_err(core)?), // a hidden target is found by name like any other
        "trace" => trace_install(&env, arg(1)?),
        "begin" => pretty(&ops::begin(&env, arg(1)?, true).map_err(core)?), // the lab acts as a user who ticked the hidden-component confirmation; the refusal is tested in tests/ops.rs
        // Forced removal of a program the list does not know: the check result (exit 3) when the path is Listed or Refused, else the new
        // operation; `--run` chooses the first uninstaller found in the folder.
        "force" => {
            let path = PathBuf::from(arg(1)?);
            let publisher = args.iter().position(|a| a == "--publisher").and_then(|i| args.get(i + 1)).map(String::as_str);
            match force::check(&env, &path).map_err(core)? {
                ForceCheck::Ok { found } => {
                    let uninstaller = if args.iter().any(|a| a == "--run") { Some(found.uninstallers.first().cloned().ok_or("--run: no uninstaller was found in the folder")?) } else { None };
                    pretty(&ops::begin_forced(&env, &path, arg(2)?, publisher, uninstaller.as_deref()).map_err(core)?)
                }
                other => {
                    println!("{}", pretty(&other)?);
                    return Ok(CHECK_REFUSED);
                }
            }
        }
        "native" => {
            let opts = RunOptions { timeout: Duration::from_secs(300), ..Default::default() };
            pretty(&ops::run_native(&env, arg(1)?, &opts).map_err(core)?)
        }
        "scan" => pretty(&ops::scan_leftovers(&env, arg(1)?).map_err(core)?),
        "apply" => {
            let id = arg(1)?;
            let plan = ops::load(&env, id).map_err(core)?.plan.ok_or("no plan: run scan first")?;
            let ids = select(&plan, arg(2)?)?;
            if args.iter().any(|a| a == "--crash-after-first-move") {
                ops::valid_op_id(id).map_err(core)?;
                crash_after_first_move(&env, id);
            }
            pretty(&ops::apply(&env, id, &ids).map_err(core)?)
        }
        "restore" => pretty(&ops::restore(&env, arg(1)?).map_err(core)?),
        "show" => pretty(&ops::load(&env, arg(1)?).map_err(core)?),
        _ => Err(USAGE.to_string()),
    }?;
    println!("{out}");
    Ok(0)
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let code = run(&args).unwrap_or_else(|e| {
        eprintln!("error: {e}");
        1
    });
    std::process::exit(code);
}

#[cfg(test)]
mod tests {
    use super::*;
    use uni_core::model::*;

    fn lab_dir() -> tempfile::TempDir {
        let d = tempfile::tempdir().unwrap();
        std::fs::write(d.path().join(LAB_MARKER), b"").unwrap();
        d
    }

    #[test]
    fn guest_check_needs_the_sandbox_account_and_the_lab_folder() {
        let d = lab_dir();
        let ok = || Some(d.path().as_os_str().to_owned());
        assert!(check_guest("WDAGUtilityAccount", ok()).is_ok());
        assert!(check_guest("wdagutilityaccount", ok()).is_ok());
        for user in ["theme", "", "WDAGUtilityAccount2", r"x\WDAGUtilityAccount", "Administrator"] {
            let e = check_guest(user, ok()).unwrap_err();
            assert!(e.contains("not a Windows Sandbox guest"), "{user}: {e}");
        }
        let bare = tempfile::tempdir().unwrap();
        let missing = d.path().join("nope");
        for lab in [None, Some(OsString::new()), Some(OsString::from(r"relative\lab")), Some(bare.path().as_os_str().to_owned()), Some(missing.into_os_string())] {
            assert!(check_guest("WDAGUtilityAccount", lab.clone()).is_err(), "{lab:?}");
        }
    }

    #[test]
    fn this_machine_is_not_a_guest() {
        let user = token_user();
        assert!(!user.is_empty());
        if !user.eq_ignore_ascii_case(GUEST_USER) {
            let d = lab_dir();
            assert!(check_guest(&user, Some(d.path().as_os_str().to_owned())).is_err());
        }
    }

    fn cand(id: &str, selected: bool, blocks: Vec<Block>, evidence: Vec<Evidence>) -> Candidate {
        Candidate {
            id: id.to_string(),
            group: Group::ProgramFiles,
            target: Target::Path { path: PathBuf::from(id), kind: PathKind::File },
            size: 0,
            evidence,
            blocks,
            score: 0,
            tier: Tier::Review,
            selected,
            ident: Ident::None {},
        }
    }

    #[test]
    fn select_policies() {
        let doc = Evidence { code: EvidenceCode::UserDataLikely, points: -50, detail: String::new() };
        let block = Block { code: BlockCode::ProtectedPath, detail: String::new() };
        let mut revert = cand("revert", false, vec![], vec![]);
        revert.group = Group::Revert;
        let mut blocked_revert = cand("blocked-revert", false, vec![block.clone()], vec![]);
        blocked_revert.group = Group::Revert;
        let plan = Plan {
            schema: SCHEMA,
            created_ms: 0,
            app_id: "x".into(),
            dry_run: false,
            install_dir: None,
            install_dir_status: DirStatus::NotSet {},
            corroborated: false,
            still_running: vec![],
            trace: None,
            candidates: vec![
                cand("safe", true, vec![], vec![]),
                cand("review", false, vec![], vec![]),
                cand("doc", false, vec![], vec![doc]),
                cand("blocked", false, vec![block], vec![]),
                revert,
                blocked_revert,
            ],
        };
        assert_eq!(select(&plan, "default").unwrap(), ["safe"]);
        assert_eq!(select(&plan, "default+reverts").unwrap(), ["safe", "revert"], "only an unblocked revert is added");
        assert_eq!(select(&plan, "unblocked").unwrap(), ["safe", "review", "revert"]);
        assert!(select(&plan, "all").is_err());
    }
}
