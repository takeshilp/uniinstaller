//! Forced removal ("remove by path"): the identity check, the operation flow and the refusals, all on the fixture sandbox.
mod common;
use common::Fixture;
use std::collections::BTreeMap;
use std::fs;
use std::path::Path;
use std::time::Duration;
use uni_core::model::*;
use uni_core::native::RunOptions;
use uni_core::sandbox::*;
use uni_core::{force, ops, paths, registry, shortcuts};
use winreg::enums::KEY_ALL_ACCESS;

const NOTES: &str = "HKCU64:SandboxNotes";

fn opts() -> RunOptions {
    RunOptions { show_window: false, poll: Duration::from_millis(50), ..Default::default() }
}

fn set(key: &RegPath, name: &str, value: &str) {
    registry::set_string(&registry::create(key, KEY_ALL_ACCESS).unwrap(), name, value, false).unwrap();
}

fn put(p: &Path, content: &[u8]) {
    fs::create_dir_all(p.parent().unwrap()).unwrap();
    fs::write(p, content).unwrap();
}

/// A listed program: a named Uninstall key (in the 64-bit view only), optionally with an install folder.
fn list_app(f: &Fixture, key: &str, name: &str, dir: Option<&Path>) {
    let k = f.env.uninstall_roots[0].child(key);
    set(&k, "DisplayName", name);
    if let Some(d) = dir {
        set(&k, "InstallLocation", &d.to_string_lossy());
    }
}

fn verdict(f: &Fixture, p: &Path) -> ForceCheck {
    force::check(&f.env, p).unwrap()
}

fn refused(c: ForceCheck) -> (ForceRefusal, String) {
    match c {
        ForceCheck::Refused { code, detail } => (code, detail),
        other => panic!("expected a refusal, got {other:?}"),
    }
}

fn listed(c: ForceCheck) -> (String, ListedHow) {
    match c {
        ForceCheck::Listed { app, how } => (app.id, how),
        other => panic!("expected Listed, got {other:?}"),
    }
}

fn found(c: ForceCheck) -> ForceFound {
    match c {
        ForceCheck::Ok { found } => *found,
        other => panic!("expected Ok, got {other:?}"),
    }
}

fn plan(op: &Operation) -> &Plan {
    op.plan.as_ref().unwrap()
}

fn selectable(op: &Operation) -> Vec<String> {
    plan(op).candidates.iter().filter(|c| c.blocks.is_empty()).map(|c| c.id.clone()).collect()
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
            if paths::norm(&p) == paths::norm(&f.env.data_dir) {
                continue;
            }
            let key = paths::norm(&p);
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

fn row<'a>(op: &'a Operation, suffix: &str) -> &'a Candidate {
    let s = suffix.to_lowercase();
    plan(op).candidates.iter().find(|c| c.id.ends_with(&s)).unwrap_or_else(|| panic!("no candidate ending with {suffix}: {:?}", plan(op).candidates.iter().map(|c| &c.id).collect::<Vec<_>>()))
}

fn expect(op: &Operation, suffix: &str, score: i32, tier: Tier) {
    let c = row(op, suffix);
    assert_eq!((c.score, c.tier, c.selected), (score, tier, false), "{suffix}: {:?} {:?}", c.evidence, c.blocks);
}

/// The portable program, found uninstaller chosen: native run, search, remove everything unblocked, restore.
#[test]
fn portable_flow_with_found_uninstaller() {
    let f = Fixture::new();
    let (pd, exe) = (portable_dir(&f.env), portable_dir(&f.env).join("portable.exe"));
    let fd = found(verdict(&f, &exe));
    assert_eq!(fd.forced.folder.as_deref(), Some(pd.as_path()), "the exe is the only program in its folder: the folder is taken whole");
    assert_eq!(fd.forced.picked, exe);
    assert_eq!(fd.uninstallers, vec![pd.join("unins000.cmd")]);
    assert_eq!(fd.shortcuts, vec![start_menu(&f.env).join("Sandbox Portable.lnk")]);
    assert_eq!(fd.name, "portable", "no version info: the exe's stem is suggested, never a parent folder's name");
    assert_eq!(fd.forced.search_names, vec!["portable"]);
    assert!(!fd.other_volume || !cfg!(test), "the fixture lives on the data volume");
    assert!(!fd.outside_zones);

    let op = ops::begin_forced(&f.env, &exe, "Sandbox Portable", None, Some(&pd.join("unins000.cmd"))).unwrap();
    assert_eq!(op.status, OpStatus::Running);
    assert!(op.native.is_none() && op.plan.is_none());
    assert!(op.app.id.starts_with("force:") && op.app.sources.is_empty());
    let forced = op.forced.clone().unwrap();
    assert_eq!((forced.picked.as_path(), forced.folder.as_deref(), forced.search_names.as_slice()), (exe.as_path(), Some(pd.as_path()), &["Sandbox Portable".to_string()][..]));
    let op = ops::run_native(&f.env, &op.id, &opts()).unwrap();
    assert_eq!(op.native.as_ref().unwrap().exit_code, Some(0), "{:?}", op.native);
    assert_eq!(op.entry_after, Some(EntryState::Gone));
    assert_eq!(op.status, OpStatus::AwaitingReview);
    assert!(!exe.exists(), "the found uninstaller ran");

    let op = ops::scan_leftovers(&f.env, &op.id).unwrap();
    let p = plan(&op);
    assert!(matches!(p.install_dir_status, DirStatus::Confirmed {}));
    assert!(!p.corroborated && p.trace.is_none());
    assert!(p.candidates.iter().all(|c| !c.selected), "a forced plan preselects nothing");
    expect(&op, r"sandbox portable\data", 45, Tier::Review);
    expect(&op, r"sandbox portable\unins000.cmd", 45, Tier::Review);
    expect(&op, r"sandbox portable.lnk", 65, Tier::Review);
    expect(&op, "|sandboxportable", 45, Tier::Review);
    expect(&op, r"roaming\sandbox portable", 20, Tier::Weak);
    expect(&op, r"software\sandbox portable", 50, Tier::Review);
    assert_eq!(p.candidates.len(), 6, "{:?}", p.candidates.iter().map(|c| &c.id).collect::<Vec<_>>());

    let before = tree(&f);
    let ids = selectable(&op);
    assert_eq!(ids.len(), 6, "nothing is blocked");
    let applied = ops::apply(&f.env, &op.id, &ids).unwrap();
    assert!(applied.items.iter().all(|i| i.status == ItemStatus::Removed), "{:#?}", applied.items);
    assert_eq!(applied.status, OpStatus::Completed, "{:?}", applied.status_detail);
    assert!(applied.forced.is_some());
    assert!(!pd.exists(), "the emptied folder is removed");
    let restored = ops::restore(&f.env, &op.id).unwrap();
    assert_eq!(restored.status, OpStatus::Restored, "{:#?}", restored.items.iter().map(|i| (&i.candidate_id, i.restore, &i.restore_detail)).collect::<Vec<_>>());
    assert!(tree(&f) == before, "restore brings back exactly what was removed");
}

/// Without an uninstaller the operation goes straight to the leftover search; nothing runs.
#[test]
fn portable_without_uninstaller() {
    let f = Fixture::new();
    let (pd, exe) = (portable_dir(&f.env), portable_dir(&f.env).join("portable.exe"));
    let op = ops::begin_forced(&f.env, &exe, "Sandbox Portable", Some("  Sandbox Soft "), None).unwrap();
    assert_eq!(op.status, OpStatus::AwaitingReview);
    assert!(op.native.is_none());
    assert_eq!(op.app.publisher.as_deref(), Some("Sandbox Soft"), "trimmed");
    assert!(op.launch.exe.as_os_str().is_empty());
    let e = ops::run_native(&f.env, &op.id, &opts()).unwrap_err();
    assert!(e.0.contains("no uninstaller"), "{e}");
    assert!(exe.exists());

    let op = ops::scan_leftovers(&f.env, &op.id).unwrap();
    assert_eq!(op.status, OpStatus::AwaitingReview);
    assert!(op.native.is_none() && plan(&op).candidates.iter().all(|c| !c.selected));
    // The exe is still there: offered like any other child.
    expect(&op, r"sandbox portable\portable.exe", 45, Tier::Review);
    let before = tree(&f);
    let applied = ops::apply(&f.env, &op.id, &selectable(&op)).unwrap();
    assert_eq!(applied.status, OpStatus::Completed, "{:?}", applied.status_detail);
    assert!(applied.native.is_none() && applied.forced.is_some());
    assert!(!pd.exists());
    let restored = ops::restore(&f.env, &op.id).unwrap();
    assert_eq!(restored.status, OpStatus::Restored);
    assert!(tree(&f) == before);
}

/// A program that is listed (hidden ones too) is never forced: the user is sent to the normal flow.
#[test]
fn listed_programs_redirect() {
    let f = Fixture::new();
    let notes = notes_dir(&f.env);
    assert_eq!(listed(verdict(&f, &notes)), (NOTES.to_string(), ListedHow::Folder));
    assert_eq!(listed(verdict(&f, &notes.join("resources"))), (NOTES.to_string(), ListedHow::Inside));
    assert_eq!(listed(verdict(&f, &notes.join("Sandbox Notes.exe"))), (NOTES.to_string(), ListedHow::Folder), "the exe stands for its folder");
    // The deepest folder wins: Shared Tool sits inside Suite.
    assert_eq!(listed(verdict(&f, &suite_dir(&f.env).join("Shared Tool"))), ("HKCU64:SandboxSharedTool".to_string(), ListedHow::Folder));
    assert_eq!(listed(verdict(&f, &suite_dir(&f.env))), ("HKCU64:SandboxSuite".to_string(), ListedHow::Folder));
    // Hidden from Apps & Features does not hide it from this check.
    for root in &f.env.uninstall_roots[..2] {
        registry::set_dword(&registry::create(&root.child("SandboxNotes"), KEY_ALL_ACCESS).unwrap(), "SystemComponent", 1).unwrap();
    }
    assert_eq!(listed(verdict(&f, &notes)).0, NOTES);
    let e = ops::begin_forced(&f.env, &notes, "Sandbox Notes", None, None).unwrap_err();
    assert!(e.0.contains("cannot be removed by force"), "{e}");
    assert!(ops::history(&f.env).unwrap().is_empty(), "a refused begin leaves no record");

    // Two programs with the same folder: not one of them.
    let twin = f.root.join("twin");
    put(&twin.join("a.dll"), b"x");
    list_app(&f, "TwinA", "Twin A", Some(&twin));
    list_app(&f, "TwinB", "Twin B", Some(&twin));
    let (code, detail) = refused(verdict(&f, &twin));
    assert_eq!(code, ForceRefusal::OtherPrograms);
    assert!(detail.contains("Twin A") && detail.contains("Twin B"), "{detail}");

    // A program that registers no path is found through the shortcut named after it.
    let so = f.root.join("so");
    put(&so.join("app.exe"), b"MZ");
    list_app(&f, "ShortcutOnly", "Shortcut Only", None);
    shortcuts::create(&start_menu(&f.env).join("Shortcut Only.lnk"), &so.join("app.exe")).unwrap();
    assert_eq!(listed(verdict(&f, &so)), ("HKCU64:ShortcutOnly".to_string(), ListedHow::Shortcut));
}

#[test]
fn refusals() {
    let f = Fixture::new();
    let c = |p: &Path| refused(verdict(&f, p));
    // Zone roots, the profile and the documents folder.
    assert_eq!(c(&pf(&f.env)).0, ForceRefusal::NotAllowed);
    assert_eq!(c(&f.root.join(r"users\me")).0, ForceRefusal::NotAllowed);
    fs::create_dir_all(documents(&f.env)).unwrap();
    assert_eq!(c(&documents(&f.env)).0, ForceRefusal::NotAllowed);
    // Another user's profile.
    let other = f.root.join(r"users\other\Tool\t.exe");
    put(&other, b"MZ");
    let (code, detail) = c(&other);
    assert_eq!((code, detail.as_str()), (ForceRefusal::NotAllowed, "inside another user's profile"));
    // Aliases and things that are not programs.
    let alias = f.root.join("pf-alias");
    paths::make_junction(&alias, &suite_dir(&f.env)).unwrap();
    assert_eq!(c(&alias).0, ForceRefusal::BadPath);
    let txt = f.root.join("notes.txt");
    put(&txt, b"x");
    assert_eq!(c(&txt).0, ForceRefusal::BadPath);
    let lnk = f.root.join("junk.lnk");
    put(&lnk, &[7u8; 64]);
    assert_eq!(c(&lnk).0, ForceRefusal::BadPath);
    assert_eq!(c(&f.root.join("missing")).0, ForceRefusal::BadPath);
    assert_eq!(c(Path::new(r"relative\dir")).0, ForceRefusal::BadPath);
    // Outside the sandbox folder.
    assert_eq!(c(&f.env.folders.windows_dir).0, ForceRefusal::OutsideSandbox);
    // A folder that holds another program's folder.
    let group = f.root.join("vendor-group");
    put(&group.join(r"Grouped App\g.exe"), b"MZ");
    list_app(&f, "Grouped", "Grouped", Some(&group.join("Grouped App")));
    assert_eq!(c(&group).0, ForceRefusal::OtherPrograms);

    // An Uninstall key outside the program list that still has a working uninstaller owns the folder; without one it is ignored.
    let comp = f.root.join("component");
    put(&comp.join("c.dll"), b"x");
    let key = f.env.uninstall_roots[0].child("InstallShieldNameless");
    set(&key, "InstallLocation", &comp.to_string_lossy());
    set(&key, "UninstallString", r"%SystemRoot%\System32\cmd.exe /c exit 0");
    assert_eq!(c(&comp).0, ForceRefusal::Installed);
    set(&key, "UninstallString", r"%SystemRoot%\System32\definitely-missing.exe /x");
    found(verdict(&f, &comp));
    // The same through the uninstall command alone (no InstallLocation): its icon sits in the folder.
    let cmd_only = f.root.join("cmd-only");
    put(&cmd_only.join("c.dll"), b"x");
    let key2 = f.env.uninstall_roots[0].child("CmdOnly");
    set(&key2, "UninstallString", &format!("\"{}\" /bin", std::env::var("SystemRoot").unwrap() + r"\System32\cmd.exe"));
    set(&key2, "DisplayIcon", &cmd_only.join("c.dll").to_string_lossy());
    assert_eq!(c(&cmd_only).0, ForceRefusal::Installed);

    // A Windows service that runs from the folder.
    let svc = f.root.join("svc-app");
    put(&svc.join("svc.exe"), b"MZ");
    set(&f.env.services.child("FakeSvc"), "ImagePath", &format!("\"{}\" -k", svc.join("svc.exe").display()));
    let (code, detail) = c(&svc);
    assert_eq!(code, ForceRefusal::Service);
    assert!(detail.starts_with("FakeSvc:"), "{detail}");
}

/// Windows Installer components tie a folder to a product, downward and upward.
#[test]
fn windows_installer_components() {
    let f = Fixture::new();
    let comps = f.env.installer_data.child(r"S-1-5-18\Components");
    let component = |name: &str, product_squished: &str, path: &str| set(&comps.child(name), product_squished, path);
    let app = f.root.join("msi-app");
    put(&app.join("x.dll"), b"x");
    put(&app.join(r"sub\y.exe"), b"y");
    let squished = "87654321CBA90FED21436587A9CBED0F"; // {12345678-9ABC-DEF0-1234-56789ABCDEF0}
    component("C1", squished, &app.join("x.dll").to_string_lossy());
    // The permanent-component name and registry-style key paths are skipped.
    component("C2", "00000000000000000000000000000000", &app.to_string_lossy());
    component("C3", "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", r"02:\SOFTWARE\Foo");

    // Downward and upward: the folder, a file in it, and a folder inside the component's folder.
    for p in [app.clone(), app.join("sub"), app.join(r"sub\y.exe")] {
        let (code, detail) = refused(verdict(&f, &p));
        assert_eq!(code, ForceRefusal::Installed, "{}", p.display());
        assert!(detail.contains("{12345678-9ABC-DEF0-1234-56789ABCDEF0}") && !detail.contains("AAAA"), "{detail}");
    }
    // The product is listed: the pick belongs to it.
    list_app(&f, "{12345678-9ABC-DEF0-1234-56789ABCDEF0}", "Msi App", None);
    assert_eq!(listed(verdict(&f, &app)), ("HKCU64:{12345678-9ABC-DEF0-1234-56789ABCDEF0}".to_string(), ListedHow::Installer));
    // A second listed product in the same folder: whose is it?
    component("C4", "11111111111111111111111111111111", &app.join("z.dll").to_string_lossy());
    list_app(&f, "{11111111-1111-1111-1111-111111111111}", "Other Msi App", None);
    let (code, detail) = refused(verdict(&f, &app));
    assert_eq!(code, ForceRefusal::OtherPrograms);
    assert!(detail.contains("Msi App") && detail.contains("Other Msi App"), "{detail}");
    // One listed, one unlisted: the unlisted one decides.
    component("C5", "22222222222222222222222222222222", &app.join("w.dll").to_string_lossy());
    assert_eq!(refused(verdict(&f, &app)).0, ForceRefusal::Installed);
}

/// An exe stands for its folder only when no other program sits there; Python's `Scripts` shape stays a single file.
#[test]
fn exe_widening() {
    let f = Fixture::new();
    // Two unrelated exes without version info: only the file.
    let bin = f.root.join("bin");
    put(&bin.join("a.exe"), b"MZ a");
    put(&bin.join("b.exe"), b"MZ b");
    let fd = found(verdict(&f, &bin.join("a.exe")));
    assert_eq!(fd.forced.folder, None);
    assert_eq!(fd.name, "a");
    assert!(fd.uninstallers.is_empty() && fd.forced.picked == bin.join("a.exe"));
    // Two copies of a system exe carry the same ProductName (they are only read, never run): the folder is taken.
    let twin = f.root.join("twinexe");
    fs::create_dir_all(&twin).unwrap();
    let whoami = Path::new(&std::env::var("SystemRoot").unwrap()).join(r"System32\whoami.exe");
    fs::copy(&whoami, twin.join("a.exe")).unwrap();
    fs::copy(&whoami, twin.join("b.exe")).unwrap();
    let fd = found(verdict(&f, &twin.join("a.exe")));
    assert_eq!(fd.forced.folder.as_deref(), Some(twin.as_path()));
    assert!(fd.product.is_some() && fd.publisher.as_deref().is_some_and(|c| c.contains("Microsoft")) && fd.file_version.is_some());
    // An uninstaller beside the exe does not count as another program.
    put(&bin.join("unins000.exe"), b"MZ u");
    fs::remove_file(bin.join("b.exe")).unwrap();
    let fd = found(verdict(&f, &bin.join("a.exe")));
    assert_eq!(fd.forced.folder.as_deref(), Some(bin.as_path()));
    assert!(fd.uninstallers.is_empty(), "sandbox mode looks only for .cmd and .bat");

    // Python's shape: scripts in `py\Scripts`, the interpreter registered by an installer in `py`.
    let py = f.root.join("py");
    put(&py.join(r"Scripts\a.exe"), b"MZ a");
    put(&py.join(r"Scripts\b.exe"), b"MZ b");
    set(&f.env.installer_data.child(r"S-1-5-18\Components\P1"), "87654321CBA90FED21436587A9CBED0F", &py.join("python.exe").to_string_lossy());
    assert_eq!(refused(verdict(&f, &py.join(r"Scripts\a.exe"))).0, ForceRefusal::Installed, "the upward rule reaches the file");
}

/// A file-only pick (a lone exe in a zone root) is removed with its own references only.
#[test]
fn file_only_round_trip() {
    let f = Fixture::new();
    let lonely = pf(&f.env).join("lonely.exe");
    put(&lonely, b"MZ lonely");
    put(&pf(&f.env).join("neighbour.dll"), b"x");
    let lnk = desktop(&f.env).join("Lonely.lnk");
    shortcuts::create(&lnk, &lonely).unwrap();
    let fd = found(verdict(&f, &lonely));
    assert_eq!(fd.forced.folder, None);
    assert_eq!(fd.name, "lonely");
    assert_eq!(fd.shortcuts, vec![lnk.clone()]);

    let op = ops::begin_forced(&f.env, &lonely, "Lonely", None, None).unwrap();
    assert_eq!(op.status, OpStatus::AwaitingReview);
    let op = ops::scan_leftovers(&f.env, &op.id).unwrap();
    assert!(matches!(plan(&op).install_dir_status, DirStatus::NotSet {}));
    expect(&op, r"pf\lonely.exe", 60, Tier::Review);
    expect(&op, r"desktop\lonely.lnk", 50, Tier::Review);
    assert_eq!(plan(&op).candidates.len(), 2, "{:?}", plan(&op).candidates.iter().map(|c| &c.id).collect::<Vec<_>>());
    let before = tree(&f);
    let applied = ops::apply(&f.env, &op.id, &selectable(&op)).unwrap();
    assert!(applied.items.iter().all(|i| i.status == ItemStatus::Removed), "{:#?}", applied.items);
    assert_eq!(applied.status, OpStatus::Completed, "{:?}", applied.status_detail);
    assert!(!lonely.exists() && !lnk.exists());
    assert!(pf(&f.env).join("neighbour.dll").exists() && pf(&f.env).exists());
    let restored = ops::restore(&f.env, &op.id).unwrap();
    assert_eq!(restored.status, OpStatus::Restored);
    assert!(tree(&f) == before);
}

#[test]
fn begin_validation() {
    let f = Fixture::new();
    let (pd, exe) = (portable_dir(&f.env), portable_dir(&f.env).join("portable.exe"));
    let err = |name: &str, un: Option<&Path>| ops::begin_forced(&f.env, &exe, name, None, un).unwrap_err().0;
    assert!(err("X", Some(&pd.join("data").join("cache.bin"))).contains("not an uninstaller"));
    assert!(err("X", Some(Path::new(r"C:\Windows\System32\cmd.exe"))).contains("not an uninstaller"));
    assert!(err("   ", None).contains("needs a name"));
    assert!(err(&"x".repeat(201), None).contains("too long"));
    assert!(err("bad\nname", None).contains("control"));
    assert!(ops::begin_forced(&f.env, &exe, "X", Some("p\u{7}"), None).is_err());
    assert!(ops::history(&f.env).unwrap().is_empty(), "no refusal leaves a record");
    let op = ops::begin_forced(&f.env, &exe, &"x".repeat(200), Some(""), None).unwrap();
    assert_eq!(op.app.publisher, None, "an empty publisher is none");
}

/// A forced manifest copied into a sandbox cannot aim at real folders: scan and apply refuse it.
#[test]
fn sandbox_scope_is_rechecked() {
    let f = Fixture::new();
    let exe = portable_dir(&f.env).join("portable.exe");
    let op = ops::begin_forced(&f.env, &exe, "Sandbox Portable", None, None).unwrap();
    let op = ops::scan_leftovers(&f.env, &op.id).unwrap();
    let mut bent = ops::load(&f.env, &op.id).unwrap();
    let real = f.env.folders.windows_dir.join("x.exe");
    bent.forced = Some(Forced { picked: real, folder: None, search_names: vec![] });
    ops::save(&f.env, &bent).unwrap();
    assert!(ops::scan_leftovers(&f.env, &op.id).unwrap_err().0.contains("outside the sandbox"));
    assert!(ops::apply(&f.env, &op.id, &selectable(&op)).unwrap_err().0.contains("outside the sandbox"));
}

/// Compatibility: a normal manifest has no `forced` key (older builds read it unchanged); a forced one carries only the three fields.
#[test]
fn manifests_stay_compatible() {
    let f = Fixture::new();
    let op = ops::begin(&f.env, NOTES, false).unwrap();
    let text = fs::read_to_string(f.env.data_dir.join("operations").join(&op.id).join("manifest.json")).unwrap();
    assert!(!text.contains("\"forced\""), "a normal manifest is unchanged");
    let exe = portable_dir(&f.env).join("portable.exe");
    let op = ops::begin_forced(&f.env, &exe, "Sandbox Portable", None, None).unwrap();
    let v: serde_json::Value = serde_json::from_str(&fs::read_to_string(f.env.data_dir.join("operations").join(&op.id).join("manifest.json")).unwrap()).unwrap();
    let forced = v["forced"].as_object().unwrap();
    let mut keys: Vec<&str> = forced.keys().map(String::as_str).collect();
    keys.sort();
    assert_eq!(keys, ["folder", "picked", "searchNames"]);
    assert_eq!(v["schema"], 2, "no schema bump");
    assert_eq!(ops::load(&f.env, &op.id).unwrap().forced, op.forced);
}

#[test]
fn debug_guard_refuses_forced_begin_on_the_real_system() {
    let env = uni_core::env::Env::system().unwrap();
    let e = ops::begin_forced(&env, Path::new(r"C:\x"), "X", None, None).unwrap_err();
    assert!(e.0.contains("sandbox"), "{e}");
}
