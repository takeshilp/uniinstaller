mod common;
use common::Fixture;
use std::collections::BTreeMap;
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::time::Duration;
use uni_core::env::APP_IDENTIFIER;
use uni_core::model::*;
use uni_core::native::RunOptions;
use uni_core::sandbox::*;
use uni_core::trace::{self, Differ, Snapshot};
use uni_core::{inventory, ops, paths, registry};

fn pid(p: &Path) -> String {
    format!("path:{}", paths::norm(p))
}

fn has(s: &Snapshot, p: &Path) -> bool {
    s.paths.contains_key(&pid(p))
}

#[derive(PartialEq, Debug)]
enum Node {
    File(Vec<u8>),
    Dir,
    Link,
}

fn tree(f: &Fixture) -> (BTreeMap<String, Node>, RegNode) {
    let mut out = BTreeMap::new();
    let mut stack = vec![f.root.clone()];
    while let Some(d) = stack.pop() {
        for e in fs::read_dir(&d).unwrap().flatten() {
            let p = e.path();
            let key = paths::norm(&p);
            if key == paths::norm(&f.env.data_dir) {
                continue;
            }
            if paths::is_reparse(&p).unwrap() {
                out.insert(key, Node::Link);
            } else if p.is_dir() {
                out.insert(key, Node::Dir);
                stack.push(p);
            } else {
                out.insert(key, Node::File(fs::read(&p).unwrap()));
            }
        }
    }
    let key = RegPath::new(Hive::Hkcu, View::V64, format!(r"Software\uniinstaller-tests\{}", f.tag));
    (out, registry::capture(&key).unwrap())
}

fn plant(p: &Path) {
    fs::create_dir_all(p.parent().unwrap()).unwrap();
    fs::write(p, b"planted").unwrap();
}

#[test]
fn capture_skips_protected_and_never_follows_links() {
    let f = Fixture::new();
    let mut env = f.env.clone();
    let nd = notes_dir(&env);
    let local = env.folders.app_data[1].clone();
    let microsoft = roaming(&env).join("Microsoft").join("planted.txt");
    let webview = local.join(APP_IDENTIFIER).join("x.txt");
    let desk_sub = desktop(&env).join("Sub").join("x.txt");
    // As on the real system the data dir sits under %LOCALAPPDATA% (a protected tree).
    env.data_dir = local.join("uniinstaller-data");
    env.folders.protected_trees.push(env.data_dir.clone());
    let data = env.data_dir.join("operations").join("op-1").join("manifest.json");
    // A registry key under a reserved first-level name of the Software root.
    let reserved = env.software_roots[0].child("Microsoft").child("Reserved");
    registry::set_string(&registry::create(&reserved, winreg::enums::KEY_ALL_ACCESS).unwrap(), "v", "x", false).unwrap();
    for p in [&microsoft, &webview, &desk_sub, &data] {
        plant(p);
    }
    let before = tree(&f);

    let s = trace::capture(&env).unwrap();
    assert!(s.objects > 30, "{}", s.objects);
    assert_eq!(s.objects as usize, s.paths.len() + s.reg.len());
    assert!(s.unreadable.is_empty(), "{:?}", s.unreadable);

    // Links are items and are never followed.
    assert_eq!(s.paths.get(&pid(&nd.join("link-out"))), Some(&Print::Link {}));
    let outside = pid(&outside_dir(&env));
    assert!(!s.paths.keys().any(|k| k.starts_with(&outside)), "nothing below the junction target");
    // Protected trees are skipped, but the Start Menu inside Roaming\Microsoft is its own root.
    assert!(!has(&s, &microsoft) && !has(&s, &roaming(&env).join("Microsoft")));
    assert!(has(&s, &start_menu(&env).join(r"Sandbox Soft\Sandbox Notes.lnk")));
    assert!(!has(&s, &webview) && !has(&s, webview.parent().unwrap()), "the GUI's own profile");
    assert!(!has(&s, &data) && !has(&s, &env.data_dir), "the data dir");
    // Desktops are walked one level: the folder is an item, its contents are not.
    assert!(has(&s, &desktop(&env).join("Sandbox Notes.lnk")));
    assert_eq!(s.paths.get(&pid(desk_sub.parent().unwrap())), Some(&Print::Dir {}));
    assert!(!has(&s, &desk_sub));
    // A root is never an item; its content is.
    assert!(!has(&s, &user_programs(&env)) && has(&s, &nd));
    assert!(has(&s, &nd.join(r"resources\app.dat")));
    // Registry: values and keys of the scope, nothing below a reserved name.
    let un = &env.uninstall_roots[0];
    let name = registry::read_value(&un.child("SandboxNotes"), "DisplayName").unwrap();
    let item = s.reg.get(&format!(r"value:{}|displayname", registry_prefix(un, "SandboxNotes"))).expect("the Uninstall value is captured");
    assert_eq!(item.val.as_ref(), Some(&name));
    assert_eq!(item.print, trace::value_print(&name).unwrap());
    assert!(s.reg.values().any(|i| matches!(&i.target, Target::RegValue { name, .. } if name == "SandboxNotes")), "the Run value");
    assert!(s.reg.values().any(|i| matches!(&i.target, Target::RegValue { name, .. } if name == "InstallDir")), "a vendor value");
    assert!(!s.reg.values().any(|i| matches!(&i.target, Target::RegKey { key } | Target::RegValue { key, .. } if key.same(&reserved))), "reserved names are skipped");
    assert!(s.reg.values().any(|i| matches!(&i.target, Target::RegKey { key } if key.path.ends_with("Sandbox Notes.exe"))), "App Paths");

    assert_eq!(before, tree(&f), "capture changed nothing");
}

/// The key prefix of `target_key` for a value below `root\name`.
fn registry_prefix(root: &RegPath, name: &str) -> String {
    format!("hkcu64:{}", root.child(name).path.to_lowercase())
}

/// Denies the current user read access to a folder; restores the ACL on drop, even when the test fails.
struct Deny(PathBuf);

impl Deny {
    fn new(dir: &Path) -> Deny {
        let user = std::env::var("USERNAME").unwrap();
        let out = std::process::Command::new("icacls").arg(dir).arg("/deny").arg(format!("{user}:(OI)(CI)(RX)")).output().unwrap();
        assert!(out.status.success(), "{}", String::from_utf8_lossy(&out.stdout));
        Deny(dir.to_path_buf())
    }
}

impl Drop for Deny {
    fn drop(&mut self) {
        let user = std::env::var("USERNAME").unwrap_or_default();
        let _ = std::process::Command::new("icacls").arg(&self.0).arg("/remove:d").arg(user).output();
    }
}

#[test]
fn unreadable_folder_is_not_deleted() {
    let f = Fixture::new();
    let res = notes_dir(&f.env).join("resources");
    let before = trace::capture(&f.env).unwrap();
    assert!(has(&before, &res.join("app.dat")));
    let _deny = Deny::new(&res);
    let mut d = Differ::new(before);
    let cap = trace::capture_with(&f.env, &mut |id, t, p, _| d.visit(id, t, p)).unwrap();
    let roots: Vec<PathBuf> = f.env.folders.zone_roots().cloned().collect();
    let (changes, unreadable) = d.finish(&cap.unreadable, &roots);
    assert!(unreadable.contains(&pid(&res)), "{unreadable:?}");
    assert!(changes.is_empty(), "no Deleted below an unreadable folder: {changes:#?}");
}

fn opts() -> RunOptions {
    RunOptions { show_window: false, poll: Duration::from_millis(50), ..Default::default() }
}

/// Runs the seeded demo installer under a trace.
fn traced(f: &Fixture) -> TraceJournal {
    let launch = trace::installer_launch(&f.env, &traced_setup(&f.env)).unwrap();
    let mut s = trace::begin(&f.env, launch).unwrap();
    trace::install(&f.env, &mut s, &opts()).unwrap();
    let n = s.native.as_ref().unwrap();
    assert!(n.launch_error.is_none() && n.exit_code == Some(0) && !n.timed_out, "{n:?}");
    assert!(trace::install(&f.env, &mut s, &opts()).unwrap_err().0.contains("already"), "an installer runs once per session");
    trace::finish(&f.env, s).unwrap()
}

fn change<'a>(j: &'a TraceJournal, suffix: &str) -> &'a TraceChange {
    let s = suffix.to_lowercase();
    j.changes.iter().find(|c| c.id.ends_with(&s)).unwrap_or_else(|| panic!("no change ending with {suffix}: {:#?}", j.changes.iter().map(|c| &c.id).collect::<Vec<_>>()))
}

fn app_of(f: &Fixture, id: &str) -> InstalledApp {
    inventory::find_app(&f.env, id).unwrap()
}

/// A hand-made journal linked to `app` (or to nothing).
fn journal(id: &str, link: TraceLink, changes: Vec<TraceChange>) -> TraceJournal {
    TraceJournal {
        schema: TRACE_SCHEMA,
        id: id.into(),
        created_ms: id[3..].parse().unwrap(),
        finished_ms: 0,
        installer: Launch { raw: String::new(), exe: PathBuf::new(), args: String::new(), argv: vec![], msi_product: None },
        native: None,
        link,
        objects: 0,
        before_ms: 0,
        after_ms: 0,
        unreadable: vec![],
        changes,
    }
}

fn linked(app: &InstalledApp) -> TraceLink {
    TraceLink::Linked { app: Box::new(app.clone()) }
}

#[test]
fn trace_journal_of_demo_install() {
    let f = Fixture::new();
    let j = traced(&f);
    let TraceLink::Linked { app } = &j.link else { panic!("{:?}", j.link) };
    assert_eq!(app.display_name, "Sandbox Traced", "the hidden runtime component does not count");
    assert!(j.unreadable.is_empty(), "{:?}", j.unreadable);
    assert_eq!(j.native.as_ref().unwrap().exit_code, Some(0));
    assert!(j.objects > 30 && j.id.starts_with("tr-"));

    // Values that existed before the install and now point into the program: the previous data is kept.
    let prev = |suffix: &str| change(&j, suffix).previous.as_ref().unwrap_or_else(|| panic!("{suffix}: no previous value")).clone();
    let text = |v: &RegVal| registry::val_text(v).unwrap();
    for (suffix, old) in [
        (r"\run|sandboxtraced", r#""C:\old\traced-helper.exe""#),
        (r"\apppaths\shared-tool.exe|", r"C:\old\shared-tool.exe"),
        (r"\software\shared soft\common|handler", r"C:\old\handler.exe"),
        (r"\software\sandbox soft\sandbox notes|installdir", &notes_dir(&f.env).to_string_lossy()),
    ] {
        assert_eq!(change(&j, suffix).change, Change::Modified, "{suffix}");
        assert_eq!(text(&prev(suffix)), old, "{suffix}");
    }
    // A background-style write that does not point into the program is reported without data.
    let bg = change(&j, r"\software\other soft\updater|lastcheck");
    assert_eq!((bg.change, bg.previous.is_none(), bg.noise), (Change::Modified, true, false));
    // New things.
    assert_eq!(change(&j, r"\uninstall\sandboxtracedruntime").change, Change::Created);
    assert_eq!(change(&j, r"\apppaths\traced.exe").change, Change::Created);
    assert_eq!(change(&j, r"pf\trace soft").change, Change::Created);
    assert_eq!(change(&j, r"pfx86\other updater").change, Change::Created);
    // A cache folder below the program's settings is kept as noise.
    assert!(change(&j, r"sandbox traced\cache").noise && change(&j, r"cache\blob.bin").noise);
    assert!(!change(&j, r"sandbox traced\settings.json").noise);
    assert!(j.changes.iter().filter(|c| c.noise).count() >= 2);
    // The journal never stores value data except as `previous`.
    fn data_keys(v: &serde_json::Value, under_previous: bool, bad: &mut Vec<String>) {
        match v {
            serde_json::Value::Object(m) => {
                for (k, x) in m {
                    if k == "data" && !under_previous {
                        bad.push(k.clone());
                    }
                    data_keys(x, under_previous || k == "previous", bad);
                }
            }
            serde_json::Value::Array(a) => a.iter().for_each(|x| data_keys(x, under_previous, bad)),
            _ => {}
        }
    }
    let mut bad = vec![];
    data_keys(&serde_json::to_value(&j).unwrap(), false, &mut bad);
    assert!(bad.is_empty(), "value data outside previous: {bad:?}");
    assert_eq!(serde_json::to_value(trace::load(&f.env, &j.id).unwrap()).unwrap(), serde_json::to_value(&j).unwrap(), "load returns the saved journal");
    let sm = trace::summary(&j);
    assert!(sm.created > 10 && sm.noise >= 2 && sm.restorable_values == 4 && sm.modified_values.len() == 5, "{sm:#?}");
    assert!(sm.deleted.is_empty() && sm.modified_files.is_empty());
    assert!(sm.modified_values.iter().any(|v| v.ends_with(r"\Shared Soft\Common\Handler")) || sm.modified_values.iter().any(|v| v.contains("Handler")), "{:?}", sm.modified_values);
}

#[test]
fn installer_launch_rules() {
    let f = Fixture::new();
    // Sandbox: only the seeded-style scripts inside the sandbox folder.
    let setup = traced_setup(&f.env);
    let l = trace::installer_launch(&f.env, &setup).unwrap();
    assert_eq!((l.exe.as_path(), l.args.as_str(), l.raw.as_str()), (setup.as_path(), "", setup.to_str().unwrap()));
    let exe = setup.with_file_name("fake.exe");
    fs::write(&exe, b"MZ").unwrap();
    let outside = f.second_dir().join("x.cmd");
    fs::write(&outside, b"@echo off").unwrap();
    let junction = f.root.join("link");
    paths::make_junction(&junction, f.second_dir()).unwrap();
    let e = |p: &Path| trace::installer_launch(&f.env, p).unwrap_err().0;
    assert!(e(&exe).contains("only .cmd and .bat"), "an .exe in the sandbox");
    assert!(e(&outside).contains("only .cmd and .bat"), "a .cmd outside the sandbox");
    assert!(e(&junction.join("x.cmd")).contains("only .cmd and .bat"), "a .cmd reached through a junction");
    assert!(e(&setup.parent().unwrap().join("..").join("installers").join("sandbox-traced-setup.cmd")).contains("only .cmd and .bat"), "a path with .. components");
    assert!(e(Path::new(r"installers\sandbox-traced-setup.cmd")).contains("local absolute"), "a relative path");
    assert!(e(&setup.with_file_name("missing.cmd")).contains("not a file"));
    assert!(e(setup.parent().unwrap()).contains("not a file"), "a folder");

    // The real environment: constructed only, nothing is run.
    let real = uni_core::env::Env::system().unwrap();
    let d = tempfile::tempdir().unwrap();
    let w = |name: &str| {
        let p = d.path().join(name);
        fs::write(&p, b"x").unwrap();
        p
    };
    let (a, b) = (w("a.exe"), w("b.MSI"));
    let l = trace::installer_launch(&real, &a).unwrap();
    assert_eq!((l.exe.as_path(), l.args.as_str()), (a.as_path(), ""));
    let l = trace::installer_launch(&real, &b).unwrap();
    assert_eq!(l.exe, real.folders.system_dir.join("msiexec.exe"));
    assert_eq!(l.args, format!("/i \"{}\"", b.display()));
    assert!(l.argv.is_empty() && l.msi_product.is_none());
    for bad in [w("c.cmd"), w("d.bat"), w("e.txt"), w("f.ps1")] {
        assert!(trace::installer_launch(&real, &bad).unwrap_err().0.contains("only .exe and .msi"), "{}", bad.display());
    }
    assert!(trace::installer_launch(&real, d.path()).is_err(), "a folder");
}

#[cfg(debug_assertions)]
#[test]
fn install_refuses_system_env_in_debug() {
    let real = uni_core::env::Env::system().unwrap();
    let launch = Launch { raw: String::new(), exe: PathBuf::from(r"C:\nonexistent\setup.exe"), args: String::new(), argv: vec![], msi_product: None };
    let mut s = trace::Session { launch, before: Snapshot::default(), started_ms: 0, native: None };
    let e = trace::install(&real, &mut s, &opts()).unwrap_err();
    assert!(e.0.contains("sandbox"), "{e}");
    assert!(s.native.is_none(), "nothing was run");
}

#[test]
fn newest_journal_supersedes() {
    let f = Fixture::new();
    let notes = app_of(&f, "HKCU64:SandboxNotes");
    let suite = app_of(&f, "HKCU64:SandboxSuite");
    for (id, link) in [("tr-100", linked(&notes)), ("tr-200", linked(&notes)), ("tr-400", linked(&suite)), ("tr-500", TraceLink::NoProgram {})] {
        trace::save(&f.env, &journal(id, link, vec![])).unwrap();
    }
    // a damaged newer journal is skipped, never used
    let dir = f.env.data_dir.join("traces");
    let mut bytes = fs::read(dir.join("tr-200.json")).unwrap();
    let last = bytes.len() - 3;
    bytes[last] ^= 1;
    fs::write(dir.join("tr-300.json"), &bytes).unwrap();
    fs::write(dir.join("tr-notanid.json"), b"x").unwrap();
    let (j, u) = trace::find_for(&f.env, &notes, false).unwrap();
    assert_eq!((j.id.as_str(), u.id.as_str(), u.trusted, u.created_ms), ("tr-200", "tr-200", true, 200));
    assert!(dir.join("tr-100.json").exists(), "older journals are never deleted");
    assert_eq!(trace::find_for(&f.env, &suite, false).unwrap().0.id, "tr-400");
    assert!(trace::find_for(&f.env, &app_of(&f, "HKCU64:SandboxOrphan"), false).is_none(), "an unlinked program has no journal");
}

#[test]
fn trust_follows_the_program_and_its_components() {
    let f = Fixture::new();
    let notes = app_of(&f, "HKCU64:SandboxNotes");
    let extra = f.env.uninstall_roots[0].child("SandboxExtra");
    let made = TraceChange {
        id: ops::target_key(&Target::RegKey { key: extra.clone() }),
        change: Change::Created,
        target: Target::RegKey { key: extra.clone() },
        before: None,
        after: Some(Print::Key {}),
        previous: None,
        noise: false,
    };
    // the program's own key is Created too and never counts as a leftover component
    let own = TraceChange { id: ops::target_key(&Target::RegKey { key: notes.sources[0].clone() }), target: Target::RegKey { key: notes.sources[0].clone() }, ..made.clone() };
    trace::save(&f.env, &journal("tr-100", linked(&notes), vec![made, own])).unwrap();
    let u = |app: &InstalledApp, uninstalled: bool| trace::find_for(&f.env, app, uninstalled).unwrap().1;
    // the component does not exist (yet)
    assert!(u(&notes, true).trusted);
    registry::create(&extra, winreg::enums::KEY_ALL_ACCESS).unwrap();
    assert!(u(&notes, false).trusted, "the card and the preview do not check components");
    let x = u(&notes, true);
    assert_eq!((x.trusted, x.distrust), (false, Some(Distrust::ComponentStillInstalled)));
    registry::delete_key(&extra).unwrap();
    assert!(u(&notes, true).trusted, "gone again");
    // the program itself changed
    let mut v = notes.clone();
    v.display_version = Some("9.9".into());
    assert_eq!(u(&v, false).distrust, Some(Distrust::VersionChanged));
    let mut v = notes.clone();
    v.install_location = Some(PathBuf::from(r"C:\Elsewhere"));
    assert_eq!(u(&v, false).distrust, Some(Distrust::FolderChanged));
    let mut v = notes.clone();
    v.uninstall_string = Some("cmd /c exit 1".into());
    assert_eq!(u(&v, false).distrust, Some(Distrust::UninstallerChanged));
}

/// begin + the program's own uninstaller + leftover scan.
fn uninstalled(f: &Fixture, id: &str) -> Operation {
    let op = ops::begin(&f.env, id).unwrap();
    let op = ops::run_native(&f.env, &op.id, &opts()).unwrap();
    assert!(op.native.as_ref().unwrap().launch_error.is_none(), "{:?}", op.native);
    ops::scan_leftovers(&f.env, &op.id).unwrap()
}

const TRACED: &str = "HKCU64:SandboxTraced";

fn cand<'a>(plan: &'a Plan, suffix: &str) -> &'a Candidate {
    let s = suffix.to_lowercase();
    plan.candidates.iter().find(|c| c.id.ends_with(&s)).unwrap_or_else(|| panic!("no candidate ending with {suffix}: {:#?}", plan.candidates.iter().map(|c| &c.id).collect::<Vec<_>>()))
}

fn has_cand(plan: &Plan, suffix: &str) -> bool {
    let s = suffix.to_lowercase();
    plan.candidates.iter().any(|c| c.id.ends_with(&s))
}

fn trace_points(c: &Candidate) -> Option<i32> {
    c.evidence.iter().find(|e| e.code == EvidenceCode::TraceCreated).map(|e| e.points)
}

fn sz(name: &str, text: &str) -> RegVal {
    RegVal { name: name.into(), kind: 1, data: text.encode_utf16().chain(std::iter::once(0)).flat_map(|c| c.to_le_bytes()).collect() }
}

#[test]
fn trace_install_uninstall_apply_restore() {
    let f = Fixture::new();
    let j = traced(&f);
    let d = ops::describe(&f.env, TRACED).unwrap();
    let u = d.trace.expect("the card knows the journal");
    assert_eq!((u.id.as_str(), u.trusted, u.distrust), (j.id.as_str(), true, None));
    assert_eq!(ops::preview(&f.env, TRACED).unwrap().trace.as_ref().map(|t| t.trusted), Some(true));

    let op = uninstalled(&f, TRACED);
    assert_eq!(op.entry_after, Some(EntryState::Gone));
    let plan = op.plan.as_ref().unwrap();
    assert!(plan.trace.as_ref().unwrap().trusted);
    let state = |c: &Candidate| (c.score, c.tier, c.selected);

    // Created and unchanged, near the program: Safe and preselected.
    let c = cand(plan, r"pf\trace soft");
    assert_eq!(state(c), (100, Tier::Safe, true), "{:?}", c.evidence);
    assert_eq!(c.group, Group::ProgramFiles);
    assert!(!has_cand(plan, r"sandbox traced\bin"), "the outer folder replaces its children");
    // Created and unchanged, but not near the program (a background writer looks the same): Review, not preselected.
    let c = cand(plan, r"pfx86\other updater");
    assert_eq!((state(c), trace_points(c)), ((50, Tier::Review, false), Some(50)), "{:?}", c.evidence);
    let c = cand(plan, r"roaming\trace soft");
    assert_eq!((state(c), trace_points(c), c.group), ((50, Tier::Review, false), Some(50), Group::Data), "despite its Cache child: {:?}", c.evidence);
    // App Paths: heuristic evidence plus the trace.
    let c = cand(plan, r"apppaths\traced.exe");
    assert_eq!((c.tier, c.selected, trace_points(c)), (Tier::Safe, true, Some(100)), "{:?}", c.evidence);
    // Settings keys the install created (Data group): offered, never preselected.
    for suffix in [r"\software\trace soft", r"\software\trace soft\sandbox traced"] {
        let c = cand(plan, suffix);
        assert!(c.blocks.is_empty() && !c.selected && c.group == Group::Data, "{suffix}: {c:?}");
    }
    // Values that existed before: no deletion of their key, a revert instead.
    assert!(!has_cand(plan, r"apppaths\shared-tool.exe"), "the key of an attributable value is never offered for deletion");
    assert!(!plan.candidates.iter().any(|c| c.id.starts_with("value:") && c.id.ends_with("run|sandboxtraced")), "the revert replaces the deletion of the Run value");
    let reverts: Vec<&Candidate> = plan.candidates.iter().filter(|c| c.group == Group::Revert).collect();
    assert_eq!(reverts.len(), 4, "{:#?}", reverts.iter().map(|c| &c.id).collect::<Vec<_>>());
    assert!(reverts.iter().all(|c| !c.selected && c.id.starts_with("revert:")));
    for r in &reverts {
        let blocked = r.id.ends_with(r"sandbox soft\sandbox notes|installdir");
        assert_eq!(!r.blocks.is_empty(), blocked, "{}: {:?}", r.id, r.blocks);
        if blocked {
            assert_eq!(r.blocks[0].code, BlockCode::SharedWithOtherApp, "{:?}", r.blocks);
            assert_eq!(r.tier, Tier::Blocked);
        } else {
            assert_eq!((r.score, r.tier), (50, Tier::Review), "{:?}", r.evidence);
        }
    }
    // Unattributed or foreign: nothing.
    assert!(!has_cand(plan, r"updater|lastcheck"));
    assert!(!has_cand(plan, r"sandboxtracedruntime"));

    let before = tree(&f);
    let ids: Vec<String> = plan.candidates.iter().filter(|c| c.blocks.is_empty()).map(|c| c.id.clone()).collect();
    let applied = ops::apply(&f.env, &op.id, &ids).unwrap();
    for i in &applied.items {
        assert!(matches!(i.status, ItemStatus::Removed | ItemStatus::NotFound | ItemStatus::Reverted), "{}: {:?} {:?}", i.candidate_id, i.status, i.detail);
    }
    assert_eq!(applied.items.iter().filter(|i| i.status == ItemStatus::Reverted).count(), 3);
    let nf: Vec<&str> = applied.items.iter().filter(|i| i.status == ItemStatus::NotFound).map(|i| i.candidate_id.as_str()).collect();
    assert_eq!(nf.len(), 1, "only the inner settings key is already gone with its parent: {nf:?}");
    assert!(nf[0].ends_with(r"software\trace soft\sandbox traced"));
    assert_eq!(applied.status, OpStatus::Completed, "{:?}", applied.status_detail);
    let un = |suffix: &str| registry::read_value(&f.env.run_roots[0], suffix).unwrap();
    assert_eq!(un("SandboxTraced"), sz("SandboxTraced", r#""C:\old\traced-helper.exe""#), "the old Run value is back");
    let sw = &f.env.software_roots[0];
    assert_eq!(registry::read_value(&sw.child("Shared Soft").child("Common"), "Handler").unwrap(), sz("Handler", r"C:\old\handler.exe"));
    assert_eq!(registry::read_value(&f.env.app_paths_roots[0].child("shared-tool.exe"), "").unwrap(), sz("", r"C:\old\shared-tool.exe"));
    assert!(registry::read_value(&sw.child("Other Soft").child("Updater"), "LastCheck").unwrap().data != sz("LastCheck", "old").data, "unattributed: left as it is");
    assert!(!pf(&f.env).join("Trace Soft").exists() && !roaming(&f.env).join("Trace Soft").exists());
    assert!(!f.env.folders.program_files[1].join("Other Updater").exists(), "offered at Review and ticked here, like a user who ticks everything unblocked");

    let restored = ops::restore(&f.env, &op.id).unwrap();
    assert_eq!(restored.status, OpStatus::Restored, "{:#?}", restored.items.iter().map(|i| (&i.candidate_id, i.restore, &i.restore_detail)).collect::<Vec<_>>());
    assert_eq!(before, tree(&f), "the file tree and the registry capture are back exactly as before the apply");
}

#[test]
fn changed_objects_lose_trace_evidence() {
    let f = Fixture::new();
    traced(&f);
    let dir = pf(&f.env).join(r"Trace Soft\Sandbox Traced");
    fs::OpenOptions::new().append(true).open(dir.join("data.bin")).unwrap().write_all(b"more").unwrap();
    fs::write(dir.join("user.txt"), b"mine").unwrap();
    let other = f.env.folders.program_files[1].join("Other Updater");
    fs::write(other.join("late.dat"), b"y").unwrap();
    let op = uninstalled(&f, TRACED);
    let plan = op.plan.as_ref().unwrap();
    assert!(plan.trace.as_ref().unwrap().trusted);
    assert!(!has_cand(plan, r"pf\trace soft") && !has_cand(plan, r"pf\trace soft\sandbox traced"), "a changed folder is not offered whole");
    for name in ["bin", "uninstall.cmd"] {
        let c = cand(plan, &format!(r"sandbox traced\{name}"));
        assert!(trace_points(c) == Some(100) && c.tier == Tier::Safe && c.selected, "{name}: {:?}", c.evidence);
    }
    for name in ["data.bin", "user.txt"] {
        let c = cand(plan, &format!(r"sandbox traced\{name}"));
        assert_eq!((trace_points(c), c.score, c.tier, c.selected), (None, 45, Tier::Review, false), "{name}: {:?}", c.evidence);
    }
    assert!(!has_cand(plan, r"pfx86\other updater") && !plan.candidates.iter().any(|c| c.id.contains("other updater")), "a changed folder away from the program is never entered");
}

#[test]
fn untrusted_trace_is_reported_not_used() {
    let f = Fixture::new();
    traced(&f);
    let key = f.env.uninstall_roots[0].child("SandboxTraced");
    let set = |name: &str, v: &str| registry::set_string(&registry::open(&key, winreg::enums::KEY_ALL_ACCESS).unwrap(), name, v, false).unwrap();
    set("DisplayVersion", "2.0");
    let plan = ops::preview(&f.env, TRACED).unwrap();
    let t = plan.trace.as_ref().unwrap();
    assert_eq!((t.trusted, t.distrust), (false, Some(Distrust::VersionChanged)));
    assert!(plan.candidates.iter().all(|c| trace_points(c).is_none() && c.group != Group::Revert && !c.evidence.iter().any(|e| e.code == EvidenceCode::TraceModified)), "no evidence and no reverts");
    assert_eq!(ops::describe(&f.env, TRACED).unwrap().trace.unwrap().distrust, Some(Distrust::VersionChanged));
    set("DisplayVersion", "1.0");
    assert!(ops::preview(&f.env, TRACED).unwrap().trace.unwrap().trusted);

    // A hidden component that is still installed after the program's own uninstaller ran.
    let op = ops::begin(&f.env, TRACED).unwrap();
    ops::run_native(&f.env, &op.id, &opts()).unwrap();
    let runtime = f.env.uninstall_roots[0].child("SandboxTracedRuntime");
    assert!(!registry::exists(&runtime), "the uninstall script removed it");
    registry::set_string(&registry::create(&runtime, winreg::enums::KEY_ALL_ACCESS).unwrap(), "DisplayName", "Sandbox Traced Runtime", false).unwrap();
    let op = ops::scan_leftovers(&f.env, &op.id).unwrap();
    let plan = op.plan.as_ref().unwrap();
    let t = plan.trace.as_ref().unwrap();
    assert_eq!((t.trusted, t.distrust), (false, Some(Distrust::ComponentStillInstalled)));
    assert!(plan.candidates.iter().all(|c| trace_points(c).is_none() && c.group != Group::Revert), "no evidence and no reverts");
    assert!(plan.candidates.iter().all(|c| !c.id.ends_with("sandboxtracedruntime")), "and the other program's entry is never offered");
}

#[test]
fn revert_respects_changes() {
    let f = Fixture::new();
    traced(&f);
    let common = f.env.software_roots[0].child("Shared Soft").child("Common");
    registry::set_string(&registry::open(&common, winreg::enums::KEY_ALL_ACCESS).unwrap(), "Handler", "changed after the install", false).unwrap();
    let op = uninstalled(&f, TRACED);
    let plan = op.plan.as_ref().unwrap();
    assert!(!has_cand(plan, r"common|handler"), "changed since the trace: no revert");
    let run_id = cand(plan, r"run|sandboxtraced").id.clone();
    assert!(run_id.starts_with("revert:"));
    // changed between the scan and the apply
    let run = f.env.run_roots[0].clone();
    registry::set_string(&registry::open(&run, winreg::enums::KEY_ALL_ACCESS).unwrap(), "SandboxTraced", "edited meanwhile", false).unwrap();
    let applied = ops::apply(&f.env, &op.id, std::slice::from_ref(&run_id)).unwrap();
    assert_eq!(applied.items[0].status, ItemStatus::Changed, "{:?}", applied.items[0].detail);
    assert_eq!(registry::read_value(&run, "SandboxTraced").unwrap(), sz("SandboxTraced", "edited meanwhile"), "untouched");
    // deleted between the scan and the apply
    registry::delete_value(&run, "SandboxTraced").unwrap();
    let applied = ops::apply(&f.env, &op.id, std::slice::from_ref(&run_id)).unwrap();
    let it = applied.items.iter().find(|i| i.candidate_id == run_id).unwrap();
    assert_eq!(it.status, ItemStatus::Changed);
    assert!(it.detail.as_deref().unwrap().contains("no longer exists"), "{:?}", it.detail);
    assert!(registry::read_value(&run, "SandboxTraced").is_err(), "not recreated");
}
