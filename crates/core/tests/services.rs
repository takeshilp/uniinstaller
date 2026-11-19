//! Windows services and scheduled tasks as leftovers, on the fixture sandbox: the stand-ins live under the sandbox registry key
//! (`sysobj`), so nothing here touches the real Service Control Manager or Task Scheduler.
mod common;
use common::Fixture;
use std::fs;
use std::path::Path;
use std::time::Duration;
use uni_core::model::*;
use uni_core::native::RunOptions;
use uni_core::sandbox::*;
use uni_core::{ops, registry, sysobj};
use winreg::enums::KEY_ALL_ACCESS;

const NOTES: &str = "HKCU64:SandboxNotes";
const NOTES_SVC: &str = "service:sandboxnotessvc";
const NOTES_TASK: &str = r"task:\sandbox soft\sandbox notes update";
const NOTES_TASK_PATH: &str = r"\Sandbox Soft\Sandbox Notes Update";

fn opts() -> RunOptions {
    RunOptions { show_window: false, poll: Duration::from_millis(50), ..Default::default() }
}

fn uninstalled(f: &Fixture) -> Operation {
    let op = ops::begin(&f.env, NOTES, false).unwrap();
    let op = ops::run_native(&f.env, &op.id, &opts()).unwrap();
    assert!(op.native.as_ref().unwrap().launch_error.is_none(), "{:?}", op.native);
    ops::scan_leftovers(&f.env, &op.id).unwrap()
}

fn plan(op: &Operation) -> &Plan {
    op.plan.as_ref().unwrap()
}

fn selectable(op: &Operation) -> Vec<String> {
    plan(op).candidates.iter().filter(|c| c.blocks.is_empty()).map(|c| c.id.clone()).collect()
}

fn find<'a>(p: &'a Plan, id: &str) -> Option<&'a Candidate> {
    p.candidates.iter().find(|c| c.id == id.to_lowercase())
}

fn must<'a>(p: &'a Plan, id: &str) -> &'a Candidate {
    find(p, id).unwrap_or_else(|| panic!("no candidate {id}: {:?}", p.candidates.iter().map(|c| &c.id).collect::<Vec<_>>()))
}

fn item<'a>(op: &'a Operation, id: &str) -> &'a ItemRecord {
    op.items.iter().find(|i| i.candidate_id == id).unwrap_or_else(|| panic!("no item {id}"))
}

fn has_block(c: &Candidate, code: BlockCode, text: &str) -> bool {
    c.blocks.iter().any(|b| b.code == code && b.detail.contains(text))
}

fn set_str(key: &RegPath, name: &str, value: &str) {
    registry::set_string(&registry::create(key, KEY_ALL_ACCESS).unwrap(), name, value, false).unwrap();
}

fn set_dword(key: &RegPath, name: &str, value: u32) {
    registry::set_dword(&registry::create(key, KEY_ALL_ACCESS).unwrap(), name, value).unwrap();
}

/// A service stand-in: `Services\<name>` with Type, Start and ImagePath (REG_EXPAND_SZ, as the SCM writes it).
fn put_svc(f: &Fixture, name: &str, kind: u32, image: &str) -> RegPath {
    let k = f.env.services.child(name);
    let rk = registry::create(&k, KEY_ALL_ACCESS).unwrap();
    registry::set_dword(&rk, "Type", kind).unwrap();
    registry::set_dword(&rk, "Start", 3).unwrap();
    registry::set_string(&rk, "ImagePath", image, true).unwrap();
    k
}

fn put_multi(key: &RegPath, name: &str, items: &[&str]) {
    let mut bytes: Vec<u8> = items.iter().flat_map(|a| a.encode_utf16().chain(Some(0)).collect::<Vec<u16>>()).flat_map(u16::to_le_bytes).collect();
    bytes.extend([0, 0]);
    registry::create(key, KEY_ALL_ACCESS).unwrap().set_raw_value(name, &winreg::RegValue { bytes: std::borrow::Cow::Owned(bytes), vtype: winreg::enums::RegType::REG_MULTI_SZ }).unwrap();
}

fn task(f: &Fixture, path: &str, actions: &[String], other: u32) {
    sysobj::sandbox_task(&f.env, path, actions, other).unwrap();
}

fn q(p: &Path) -> String {
    format!("\"{}\"", p.display())
}

/// The whole sandbox registry subtree: services, tasks and everything else the operation could touch.
fn reg_tree(f: &Fixture) -> RegNode {
    registry::capture(&RegPath::new(Hive::Hkcu, View::V64, format!(r"Software\uniinstaller-tests\{}", f.tag))).unwrap()
}

#[test]
fn notes_service_and_task_offered_not_preselected() {
    let f = Fixture::new();
    let nd = notes_dir(&f.env);
    // The program file is still there: the references are corroborated (65, Review), nothing is missing.
    let p = ops::preview(&f.env, NOTES).unwrap();
    for id in [NOTES_SVC, NOTES_TASK] {
        let c = must(&p, id);
        assert_eq!((c.score, c.tier, c.selected, c.group), (65, Tier::Review, false, Group::Services), "{id}: {:?}", c.evidence);
        assert!(c.blocks.is_empty(), "{:?}", c.blocks);
        assert!(!c.evidence.iter().any(|e| e.code == EvidenceCode::TargetMissing));
    }
    assert!(matches!(&must(&p, NOTES_SVC).ident, Ident::Service { running: Some(false), .. }));
    assert!(matches!(&must(&p, NOTES_TASK).ident, Ident::Task { enabled: true, actions, .. } if actions.len() == 1));
    // After the uninstaller removed the program file the references are stale: Safe (80), and still never preselected.
    fs::remove_file(nd.join("Sandbox Notes.exe")).unwrap();
    let p = ops::preview(&f.env, NOTES).unwrap();
    for id in [NOTES_SVC, NOTES_TASK] {
        let c = must(&p, id);
        assert_eq!((c.score, c.tier, c.selected, c.group), (80, Tier::Safe, false, Group::Services), "{id}: {:?}", c.evidence);
        assert!(c.evidence.iter().any(|e| e.code == EvidenceCode::TargetMissing));
    }
    // Another program's plan does not list them.
    let other = ops::preview(&f.env, "HKCU64:SandboxSuite").unwrap();
    assert!(find(&other, NOTES_SVC).is_none() && find(&other, NOTES_TASK).is_none());
}

#[test]
fn service_and_task_blocks() {
    let f = Fixture::new();
    let (nd, suite, pf) = (notes_dir(&f.env), suite_dir(&f.env), pf(&f.env));
    let win = f.env.folders.windows_dir.clone();
    let dll = nd.join("w.dll");

    put_svc(&f, "Drv", 0x01, &format!(r"\??\{}", nd.join("drv.sys").display()));
    let host = put_svc(&f, "HostSvc", 0x20, r"%SystemRoot%\System32\svchost.exe -k LabGrp");
    set_str(&host.child("Parameters"), "ServiceDll", &dll.to_string_lossy());
    put_svc(&f, "Rundll", 0x10, &format!(r#"%SystemRoot%\System32\rundll32.exe "{}",Run"#, nd.join("x.dll").display()));
    put_svc(&f, "SuiteArg", 0x10, &format!(r#"{} --data "{}""#, q(&suite.join("suite.exe")), nd.join("x").display()));
    put_svc(&f, "Dependee", 0x10, &q(&nd.join("dependee.exe")));
    put_multi(&put_svc(&f, "DepSvc", 0x10, r"C:\elsewhere\d.exe"), "DependOnService", &["dependee"]);
    put_svc(&f, "PerUser", 0x50, &q(&nd.join("pu.exe")));
    put_svc(&f, "NoType", 0, &q(&nd.join("nt.exe")));
    put_svc(&f, "Marked", 0x10, &q(&nd.join("marked.exe")));
    set_dword(&f.env.services.child("Marked"), "DeleteFlag", 1);
    fs::create_dir_all(nd.join("sub dir")).unwrap();
    fs::write(nd.join(r"sub dir\x y.exe"), b"MZ").unwrap();
    put_svc(&f, "Spaces", 0x10, &format!("{} --a", nd.join(r"sub dir\x y.exe").display()));
    let srv = put_svc(&f, "SrvanyApp", 0x10, &q(&nd.join("srvany.exe")));
    set_str(&srv.child("Parameters"), "Application", &suite.join("suite.exe").to_string_lossy());

    task(&f, r"\Microsoft\Lab\T", &[q(&nd.join("x.exe"))], 0);
    task(&f, r"\Lab\OtherAction", &[q(&nd.join("x.exe"))], 1);
    task(&f, r"\Lab\Cmd", &[format!(r#"{}\System32\cmd.exe /c "{}""#, win.display(), nd.join("x.bat").display())], 0);
    task(&f, r"\Lab\Two", &[q(&nd.join("a.exe")), format!("{} --x", q(&suite.join("suite.exe")))], 0);
    let other = pf.join(r"Other Vendor\Other App");
    fs::create_dir_all(&other).unwrap();
    task(&f, r"\Lab\Elsewhere", &[format!(r#"{} --data "{}""#, q(&nd.join("Sandbox Notes.exe")), other.join("x").display())], 0);

    let p = ops::preview(&f.env, NOTES).unwrap();
    let bs = |id: &str| must(&p, id).blocks.iter().map(|b| (b.code, b.detail.as_str())).collect::<Vec<_>>();
    let d = must(&p, "service:drv");
    assert!(d.blocks.len() == 1 && has_block(d, BlockCode::Unsupported, "driver"), "a driver: {:?}", d.blocks);
    assert!(bs("service:hostsvc").is_empty(), "a svchost service whose ServiceDll lies in the folder is offered: {:?}", bs("service:hostsvc"));
    assert_eq!(must(&p, "service:hostsvc").tier, Tier::Safe, "its dll is missing: 80");
    let r = must(&p, "service:rundll");
    assert!(has_block(r, BlockCode::ProtectedPath, "its program is in a protected Windows folder"), "{:?}", r.blocks);
    assert!(has_block(must(&p, "service:suitearg"), BlockCode::SharedWithOtherApp, ""), "{:?}", bs("service:suitearg"));
    assert!(has_block(must(&p, "service:dependee"), BlockCode::SharedWithOtherApp, "other services depend on it: DepSvc"), "{:?}", bs("service:dependee"));
    assert!(find(&p, "service:depsvc").is_none(), "the dependent itself does not run from the folder");
    assert!(has_block(must(&p, "service:peruser"), BlockCode::Unsupported, "per-user"));
    assert!(has_block(must(&p, "service:notype"), BlockCode::Unsupported, "not a service process"));
    assert!(find(&p, "service:marked").is_none(), "a service marked for deletion is not offered");
    let sp = must(&p, "service:spaces");
    assert!(sp.blocks.is_empty() && sp.score == 65, "an unquoted image with spaces: {:?} {:?}", sp.blocks, sp.evidence);
    assert!(has_block(must(&p, "service:srvanyapp"), BlockCode::SharedWithOtherApp, ""), "srvany Parameters\\Application: {:?}", bs("service:srvanyapp"));
    let n = must(&p, NOTES_SVC);
    assert!(n.blocks.is_empty(), "the seeded service stays clean: {:?}", n.blocks);

    let t = must(&p, r"task:\microsoft\lab\t");
    assert!(t.blocks.len() == 1 && has_block(t, BlockCode::ProtectedPath, "Windows task"), "{:?}", t.blocks);
    assert!(has_block(must(&p, r"task:\lab\otheraction"), BlockCode::Unsupported, "other than a program"));
    let c = must(&p, r"task:\lab\cmd");
    assert!(c.blocks.is_empty() && (c.score, c.tier) == (65, Tier::Review), "cmd.exe /c script in the folder: {:?} {:?}", c.blocks, c.evidence);
    assert!(has_block(must(&p, r"task:\lab\two"), BlockCode::SharedWithOtherApp, ""), "{:?}", bs(r"task:\lab\two"));
    assert!(has_block(must(&p, r"task:\lab\elsewhere"), BlockCode::SharedWithOtherApp, "outside the program's folder"), "{:?}", bs(r"task:\lab\elsewhere"));
    assert!(must(&p, NOTES_TASK).blocks.is_empty());
    // Whatever the blocks, none of them is preselected, and a blocked one is never offered.
    for c in p.candidates.iter().filter(|c| c.group == Group::Services) {
        assert!(!c.selected, "{}", c.id);
        assert_eq!(c.tier == Tier::Blocked, !c.blocks.is_empty(), "{}", c.id);
    }
}

fn applied(f: &Fixture) -> Operation {
    let op = uninstalled(f);
    let applied = ops::apply(&f.env, &op.id, &selectable(&op)).unwrap();
    assert_eq!(applied.status, OpStatus::Completed, "{:?} {:#?}", applied.status_detail, applied.items);
    applied
}

#[test]
fn apply_and_restore_service_and_task() {
    let f = Fixture::new();
    let scanned = uninstalled(&f);
    let before = reg_tree(&f);
    let op = ops::apply(&f.env, &scanned.id, &selectable(&scanned)).unwrap();
    assert_eq!(op.status, OpStatus::Completed, "{:?} {:#?}", op.status_detail, op.items);
    for id in [NOTES_SVC, NOTES_TASK] {
        let i = item(&op, id);
        assert_eq!(i.status, ItemStatus::Removed, "{id}: {:?}", i.detail);
        assert!(i.quarantine.is_none());
    }
    assert!(matches!(item(&op, NOTES_SVC).reg_backup, Some(Ident::Service { .. })));
    assert!(matches!(item(&op, NOTES_TASK).reg_backup, Some(Ident::Task { .. })));
    assert!(sysobj::service(&f.env, "SandboxNotesSvc").unwrap().is_none(), "the service key is gone");
    assert!(sysobj::task(&f.env, NOTES_TASK_PATH).unwrap().is_none(), "the task is gone");
    assert!(sysobj::tasks(&f.env).unwrap().is_empty());
    assert_ne!(before, reg_tree(&f));

    let restored = ops::restore(&f.env, &op.id).unwrap();
    assert_eq!(restored.status, OpStatus::Restored, "{:#?}", restored.items.iter().map(|i| (&i.candidate_id, i.restore, &i.restore_detail)).collect::<Vec<_>>());
    for id in [NOTES_SVC, NOTES_TASK] {
        assert_eq!(item(&restored, id).restore, Some(RestoreStatus::Restored), "{id}");
    }
    assert_eq!(before, reg_tree(&f), "the service key and the task stand-in are back, byte for byte");
    assert!(sysobj::service(&f.env, "SandboxNotesSvc").unwrap().is_some());
    // A second restore is idempotent.
    let again = ops::restore(&f.env, &op.id).unwrap();
    assert_eq!(again.status, OpStatus::Restored);
    assert_eq!(item(&again, NOTES_SVC).restore, Some(RestoreStatus::Restored));
    assert_eq!(item(&again, NOTES_TASK).restore, Some(RestoreStatus::Restored));
    assert_eq!(before, reg_tree(&f));
}

fn edit_backup(f: &Fixture, op: &Operation, edit: impl FnOnce(&mut Vec<ItemRecord>)) {
    let mut o = ops::load(&f.env, &op.id).unwrap();
    edit(&mut o.items);
    ops::save(&f.env, &o).unwrap();
}

fn set_node_value(node: &mut RegNode, name: &str, kind: u32, data: Vec<u8>) {
    let v = node.values.iter_mut().find(|v| v.name == name).unwrap();
    (v.kind, v.data) = (kind, data);
}

fn utf16z(s: &str) -> Vec<u8> {
    s.encode_utf16().chain(Some(0)).flat_map(u16::to_le_bytes).collect()
}

#[test]
fn restore_conflicts() {
    // A service with this name exists again: not touched.
    let f = Fixture::new();
    let op = applied(&f);
    put_svc(&f, "SandboxNotesSvc", 0x10, r"C:\elsewhere\new.exe");
    let live = reg_tree(&f);
    let r = ops::restore(&f.env, &op.id).unwrap();
    let i = item(&r, NOTES_SVC);
    assert_eq!(i.restore, Some(RestoreStatus::Conflict), "{:?}", i.restore_detail);
    assert!(i.restore_detail.as_deref().unwrap().contains("exists again"));
    assert_eq!(item(&r, NOTES_TASK).restore, Some(RestoreStatus::Restored));
    assert_eq!(registry::read_value(&f.env.services.child("SandboxNotesSvc"), "ImagePath").unwrap().data, utf16z(r"C:\elsewhere\new.exe"), "untouched");
    let after = reg_tree(&f);
    assert!(after != live, "only the task came back");
    assert_eq!(r.status, OpStatus::PartiallyRestored);

    // A different task with this name exists again: not touched.
    let f = Fixture::new();
    let op = applied(&f);
    task(&f, NOTES_TASK_PATH, &["x.exe".into()], 0);
    let tk = f.env.tasks.as_ref().unwrap().child("Sandbox Soft").child("Sandbox Notes Update");
    set_str(&tk, "Xml", "<Task>somebody else's</Task>");
    let r = ops::restore(&f.env, &op.id).unwrap();
    assert_eq!(item(&r, NOTES_TASK).restore, Some(RestoreStatus::Conflict), "{:?}", item(&r, NOTES_TASK).restore_detail);
    assert_eq!(sysobj::task(&f.env, NOTES_TASK_PATH).unwrap().unwrap().1, "<Task>somebody else's</Task>");
    assert_eq!(item(&r, NOTES_SVC).restore, Some(RestoreStatus::Restored));

    // The removed service is still marked for deletion: a restart is needed, nothing is written.
    let f = Fixture::new();
    let op = applied(&f);
    let k = put_svc(&f, "SandboxNotesSvc", 0x10, r"C:\x.exe");
    set_dword(&k, "DeleteFlag", 1);
    let r = ops::restore(&f.env, &op.id).unwrap();
    let i = item(&r, NOTES_SVC);
    assert_eq!(i.restore, Some(RestoreStatus::Failed));
    assert!(i.restore_detail.as_deref().unwrap().contains("restart Windows"), "{:?}", i.restore_detail);
    assert_eq!(registry::read_value(&k, "ImagePath").unwrap().data, utf16z(r"C:\x.exe"));

    // Tampered backups (a manifest is user-writable): nothing is created.
    for case in ["driver", "windows image", "windows task"] {
        let f = Fixture::new();
        let op = applied(&f);
        edit_backup(&f, &op, |items| match case {
            "driver" => {
                let Some(Ident::Service { node, .. }) = &mut items.iter_mut().find(|i| i.candidate_id == NOTES_SVC).unwrap().reg_backup else { panic!() };
                set_node_value(node, "Type", 4, 1u32.to_le_bytes().to_vec());
            }
            "windows image" => {
                let Some(Ident::Service { node, .. }) = &mut items.iter_mut().find(|i| i.candidate_id == NOTES_SVC).unwrap().reg_backup else { panic!() };
                set_node_value(node, "ImagePath", 2, utf16z(r"%SystemRoot%\System32\cmd.exe /c x"));
            }
            _ => {
                let i = items.iter_mut().find(|i| i.candidate_id == NOTES_TASK).unwrap();
                i.target = Target::Task { path: r"\Microsoft\X".into() };
                i.candidate_id = ops::target_key(&i.target);
            }
        });
        let r = ops::restore(&f.env, &op.id).unwrap();
        let (id, code, text) = match case {
            "driver" => (NOTES_SVC.to_string(), "Unsupported", "driver"),
            "windows image" => (NOTES_SVC.to_string(), "ProtectedPath", "protected Windows folder"),
            _ => (r"task:\microsoft\x".to_string(), "ProtectedPath", "Windows task"),
        };
        let i = item(&r, &id);
        assert_eq!(i.restore, Some(RestoreStatus::Failed), "{case}");
        let d = i.restore_detail.as_deref().unwrap();
        assert!(d.starts_with(&format!("blocked: {code}")) && d.contains(text), "{case}: {d}");
        assert!(sysobj::service(&f.env, "SandboxNotesSvc").unwrap().is_none() || case == "windows task", "{case}: no service was created");
        assert!(sysobj::task(&f.env, r"\Microsoft\X").unwrap().is_none(), "{case}: no task was created");
    }
}

#[test]
fn apply_revalidates_services_and_tasks() {
    let f = Fixture::new();
    let nd = notes_dir(&f.env);
    put_svc(&f, "SvcMarked", 0x10, &q(&nd.join("m.exe")));
    put_svc(&f, "SvcDepended", 0x10, &q(&nd.join("d.exe")));
    let op = uninstalled(&f);
    let ids: Vec<String> = ["service:svcmarked", "service:svcdepended", NOTES_SVC, NOTES_TASK].iter().map(|s| s.to_string()).collect();
    for id in &ids {
        assert!(must(plan(&op), id).blocks.is_empty(), "{id}");
    }
    // After the scan: the image changes, the task vanishes, a service gets marked, and another service starts to depend on one.
    set_str(&f.env.services.child("SandboxNotesSvc"), "ImagePath", &q(&nd.join("other.exe")));
    sysobj::delete_task(&f.env, NOTES_TASK_PATH).unwrap();
    set_dword(&f.env.services.child("SvcMarked"), "DeleteFlag", 1);
    put_multi(&put_svc(&f, "LateDependent", 0x10, r"C:\elsewhere\l.exe"), "DependOnService", &["SvcDepended"]);

    let a = ops::apply(&f.env, &op.id, &ids).unwrap();
    assert_eq!(item(&a, NOTES_SVC).status, ItemStatus::Changed, "{:?}", item(&a, NOTES_SVC).detail);
    assert_eq!(item(&a, NOTES_TASK).status, ItemStatus::NotFound);
    assert_eq!(item(&a, "service:svcmarked").status, ItemStatus::NotFound);
    let d = item(&a, "service:svcdepended");
    assert_eq!(d.status, ItemStatus::Blocked);
    assert!(d.detail.as_deref().unwrap().contains("other services depend on it: LateDependent"), "{:?}", d.detail);
    for n in ["SandboxNotesSvc", "SvcDepended"] {
        assert!(sysobj::service(&f.env, n).unwrap().is_some(), "{n} was left alone");
    }
}

#[test]
fn tampered_plan_service_is_blocked() {
    let f = Fixture::new();
    let op = uninstalled(&f);
    let other = pf(&f.env).join("Other");
    put_svc(&f, "OtherSvc", 0x10, &q(&other.join("o.exe")));
    task(&f, r"\Other\T", &[q(&other.join("o.exe"))], 0);
    let mut o = ops::load(&f.env, &op.id).unwrap();
    let p = o.plan.as_mut().unwrap();
    let si = p.candidates.iter().position(|c| c.id == NOTES_SVC).unwrap();
    let ti = p.candidates.iter().position(|c| c.id == NOTES_TASK).unwrap();
    p.candidates[si].target = Target::Service { name: "OtherSvc".into() };
    p.candidates[si].id = ops::target_key(&p.candidates[si].target);
    p.candidates[si].ident = Ident::Service { node: registry::capture(&f.env.services.child("OtherSvc")).unwrap(), running: Some(false) };
    let (t, xml) = sysobj::task(&f.env, r"\Other\T").unwrap().unwrap();
    p.candidates[ti].target = Target::Task { path: r"\Other\T".into() };
    p.candidates[ti].id = ops::target_key(&p.candidates[ti].target);
    p.candidates[ti].ident = Ident::Task { xml, actions: t.actions, enabled: true };
    let ids = [p.candidates[si].id.clone(), p.candidates[ti].id.clone()];
    ops::save(&f.env, &o).unwrap();
    let a = ops::apply(&f.env, &op.id, &ids).unwrap();
    assert_eq!(a.items.len(), 2);
    for i in &a.items {
        assert_eq!(i.status, ItemStatus::Blocked, "{:?}", i);
        assert!(i.detail.as_deref().unwrap().starts_with("OutsideAllowedZone: no longer refers"), "{:?}", i.detail);
    }
    assert!(sysobj::service(&f.env, "OtherSvc").unwrap().is_some());
    assert!(sysobj::task(&f.env, r"\Other\T").unwrap().is_some());
}

#[test]
fn running_state_does_not_flap() {
    let f = Fixture::new();
    let op = uninstalled(&f);
    let mut o = ops::load(&f.env, &op.id).unwrap();
    let c = o.plan.as_mut().unwrap().candidates.iter_mut().find(|c| c.id == NOTES_SVC).unwrap();
    let Ident::Service { running, .. } = &mut c.ident else { panic!() };
    assert_eq!(*running, Some(false));
    *running = Some(true);
    ops::save(&f.env, &o).unwrap();
    let a = ops::apply(&f.env, &op.id, &[NOTES_SVC.to_string()]).unwrap();
    assert_eq!(item(&a, NOTES_SVC).status, ItemStatus::Removed, "{:?}", item(&a, NOTES_SVC).detail);
}

#[test]
fn interrupted_service_item_recovers() {
    let f = Fixture::new();
    let op = uninstalled(&f);
    let mut o = ops::load(&f.env, &op.id).unwrap();
    let c = must(o.plan.as_ref().unwrap(), NOTES_SVC).clone();
    // The record was journalled InProgress and the key was deleted, but the process died before the status was written.
    o.items.push(ItemRecord {
        candidate_id: c.id.clone(),
        target: c.target.clone(),
        status: ItemStatus::InProgress,
        detail: None,
        quarantine: None,
        reg_backup: Some(c.ident.clone()),
        restore: None,
        restore_detail: None,
        at_ms: 0,
    });
    ops::save(&f.env, &o).unwrap();
    registry::delete_key(&f.env.services.child("SandboxNotesSvc")).unwrap();
    let a = ops::apply(&f.env, &op.id, &[]).unwrap();
    let i = item(&a, NOTES_SVC);
    assert_eq!((i.status, i.detail.as_deref()), (ItemStatus::Removed, Some("recovered after an interruption")));
    // and the backup it journalled restores the service
    let r = ops::restore(&f.env, &op.id).unwrap();
    assert_eq!(item(&r, NOTES_SVC).restore, Some(RestoreStatus::Restored));
    assert!(sysobj::service(&f.env, "SandboxNotesSvc").unwrap().is_some());
}

#[test]
fn forced_scan_offers_tasks() {
    let f = Fixture::new();
    let pd = portable_dir(&f.env);
    let exe = pd.join("portable.exe");
    task(&f, r"\Portable Vendor\Portable Update", &[format!("{} --update", q(&exe))], 0);
    let op = ops::begin_forced(&f.env, &exe, "Sandbox Portable", None, None).unwrap();
    let op = ops::scan_leftovers(&f.env, &op.id).unwrap();
    let t = must(plan(&op), r"task:\portable vendor\portable update");
    assert_eq!((t.group, t.tier, t.selected), (Group::Services, Tier::Weak, false), "{:?}", t.evidence);
    assert_eq!(t.score, 30, "a forced target is never corroborated");
    fs::remove_file(&exe).unwrap();
    let again = ops::scan_leftovers(&f.env, &op.id).unwrap();
    let t = must(plan(&again), r"task:\portable vendor\portable update");
    assert_eq!((t.tier, t.selected, t.score), (Tier::Review, false, 45), "the program file is gone: Review, still never Safe");
    assert!(plan(&again).candidates.iter().all(|c| !c.selected && c.tier != Tier::Safe));
}

#[test]
fn manifests_stay_compatible_with_services() {
    // Without a service or task the manifest is what older builds write: schema 2, no new variants.
    let f = Fixture::new();
    registry::delete_key(&f.env.services.child("SandboxNotesSvc")).unwrap();
    sysobj::delete_task(&f.env, NOTES_TASK_PATH).unwrap();
    let op = uninstalled(&f);
    let text = fs::read_to_string(f.env.data_dir.join("operations").join(&op.id).join("manifest.json")).unwrap();
    assert_eq!(op.schema, 2);
    assert!(!text.contains("\"service\"") && !text.contains("\"task\"") && !text.contains("\"services\""), "an older build can read it");

    // With them: it saves and loads equal, and a report carries no backup of the service or the task.
    let f = Fixture::new();
    let op = applied(&f);
    assert_eq!(op.schema, 2);
    let loaded = ops::load(&f.env, &op.id).unwrap();
    assert_eq!(serde_json::to_value(&loaded).unwrap(), serde_json::to_value(&op).unwrap());
    let text = fs::read_to_string(f.env.data_dir.join("operations").join(&op.id).join("manifest.json")).unwrap();
    assert!(text.contains("\"type\": \"service\"") && text.contains("\"type\": \"task\"") && text.contains("sandbox stand-in"), "the manifest holds the backups");
    let report = fs::read_to_string(ops::export_report(&f.env, &op.id).unwrap()).unwrap();
    assert!(!report.contains("\"node\"") && !report.contains("sandbox stand-in"), "the report holds none");
    assert!(report.contains(NOTES_SVC) && report.contains("task:"), "but it still lists the items");
    let exported = fs::read_to_string(ops::export_plan(&f.env, plan(&op)).unwrap()).unwrap();
    assert!(!exported.contains("\"node\"") && !exported.contains("sandbox stand-in"), "nor does an exported plan");
}
