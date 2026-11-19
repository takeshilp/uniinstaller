mod common;
use common::Fixture;
use std::fs;
use std::path::{Path, PathBuf};
use uni_core::model::*;
use uni_core::sandbox::*;
use uni_core::{ops, paths, registry, scan};
use winreg::enums::KEY_ALL_ACCESS;

fn path_of(c: &Candidate) -> Option<&Path> {
    match &c.target {
        Target::Path { path, .. } => Some(path),
        _ => None,
    }
}

fn find_path<'a>(plan: &'a Plan, p: &Path) -> &'a Candidate {
    plan.candidates.iter().find(|c| path_of(c).is_some_and(|x| paths::norm(x) == paths::norm(p))).unwrap_or_else(|| panic!("no candidate for {}", p.display()))
}

fn find_key(plan: &Plan, f: impl Fn(&RegPath) -> bool) -> Vec<&Candidate> {
    plan.candidates.iter().filter(|c| matches!(&c.target, Target::RegKey { key } if f(key))).collect()
}

fn check(c: &Candidate, score: i32, tier: Tier, selected: bool) {
    assert_eq!((c.score, c.tier, c.selected), (score, tier, selected), "{:?} {:?}", c.target, c.evidence);
}

#[test]
fn sandbox_notes_plan() {
    let f = Fixture::new();
    let nd = notes_dir(&f.env);
    // Simulate the native uninstaller having removed the program file.
    fs::remove_file(nd.join("Sandbox Notes.exe")).unwrap();
    let plan = ops::preview(&f.env, "HKCU64:SandboxNotes").unwrap();
    assert!(matches!(plan.install_dir_status, DirStatus::Confirmed {}));
    assert!(plan.corroborated);
    assert!(plan.dry_run);
    assert_eq!(plan.install_dir.as_deref(), Some(nd.as_path()));

    for child in ["resources", "config.ini", "logs"] {
        let c = find_path(&plan, &nd.join(child));
        check(c, 45, Tier::Review, false);
        assert_eq!(c.group, Group::ProgramFiles);
    }
    let link = find_path(&plan, &nd.join("link-out"));
    check(link, 45, Tier::Review, false);
    assert!(matches!(link.target, Target::Path { kind: PathKind::Link, .. }));
    assert!(matches!(link.ident, Ident::Link { .. }));
    assert_eq!(link.size, 0);
    check(find_path(&plan, &nd.join("Saves")), -5, Tier::Weak, false);

    check(find_path(&plan, &start_menu(&f.env).join(r"Sandbox Soft\Sandbox Notes.lnk")), 110, Tier::Safe, true);
    check(find_path(&plan, &desktop(&f.env).join("Sandbox Notes.lnk")), 100, Tier::Safe, true);
    check(find_path(&plan, &roaming(&f.env).join(r"Sandbox Soft\Sandbox Notes")), 30, Tier::Weak, false);

    let run: Vec<_> = plan.candidates.iter().filter(|c| matches!(&c.target, Target::RegValue { name, .. } if name == "SandboxNotes")).collect();
    assert_eq!(run.len(), 1);
    check(run[0], 80, Tier::Safe, true);
    let ap = find_key(&plan, |k| k.path.ends_with("Sandbox Notes.exe"));
    assert_eq!(ap.len(), 1);
    check(ap[0], 80, Tier::Safe, true);
    let sw = find_key(&plan, |k| k.path.ends_with(r"Sandbox Soft\Sandbox Notes"));
    assert_eq!(sw.len(), 1);
    check(sw[0], 95, Tier::Safe, false);
    assert_eq!(sw[0].group, Group::Data);
    let own = find_key(&plan, |k| k.path.contains("Uninstall"));
    assert_eq!(own.len(), 2, "both views' keys");
    assert!(own.iter().all(|c| c.tier == Tier::Safe && c.blocks.is_empty()));

    // The program's Windows service and scheduled task (sandbox stand-ins): found by reference, the program file is gone (80, Safe), and
    // never preselected whatever the tier (group Services).
    let svc = plan.candidates.iter().find(|c| c.id == "service:sandboxnotessvc").expect("the service");
    check(svc, 80, Tier::Safe, false);
    assert_eq!(svc.group, Group::Services);
    assert!(svc.blocks.is_empty() && matches!(svc.ident, Ident::Service { .. }), "{:?}", svc.blocks);
    let task = plan.candidates.iter().find(|c| c.id == r"task:\sandbox soft\sandbox notes update").expect("the task");
    check(task, 80, Tier::Safe, false);
    assert_eq!(task.group, Group::Services);
    assert!(task.blocks.is_empty() && matches!(task.ident, Ident::Task { .. }), "{:?}", task.blocks);

    // Nothing else: 5 children (the exe is gone), 2 lnk, Run, App Paths, 2 own keys, AppData dir, Software key, the service, the task.
    assert_eq!(plan.candidates.len(), 15, "{:#?}", plan.candidates.iter().map(|c| &c.id).collect::<Vec<_>>());
    assert!(plan.candidates.iter().all(|c| !path_of(c).is_some_and(|p| p.ends_with("keep.txt"))), "outside keep.txt is not listed");
    assert!(plan.candidates.iter().all(|c| !path_of(c).is_some_and(|p| paths::is_inside(p, &documents(&f.env)))));
    assert!(!plan.candidates.iter().any(|c| matches!(&c.target, Target::RegValue { name, .. } if name == "SandboxSuite")), "another app's Run value");
    for c in &plan.candidates {
        assert!(["path:", "key:", "value:", "service:", "task:"].iter().any(|p| c.id.starts_with(p)), "{}", c.id);
        assert_ne!(c.ident, Ident::None {}, "Ident::None only with a block");
    }
}

#[test]
fn suite_blocks_shared_and_foreign_uninstaller_children() {
    let f = Fixture::new();
    let plan = ops::preview(&f.env, "HKCU64:SandboxSuite").unwrap();
    let sd = suite_dir(&f.env);
    let shared = find_path(&plan, &sd.join("Shared Tool"));
    assert_eq!(shared.tier, Tier::Blocked);
    assert!(shared.blocks.iter().any(|b| b.code == BlockCode::SharedWithOtherApp), "{:?}", shared.blocks);
    assert!(!shared.selected);
    let portable = find_path(&plan, &sd.join("Portable Thing"));
    assert_eq!(portable.tier, Tier::Blocked);
    assert!(portable.blocks.iter().any(|b| b.code == BlockCode::SharedWithOtherApp && b.detail.contains("unins000.exe")), "{:?}", portable.blocks);
    check(find_path(&plan, &sd.join("suite.exe")), 45, Tier::Review, false);
    assert!(plan.candidates.iter().filter(|c| c.tier == Tier::Blocked).all(|c| !c.selected));
}

fn bogus_app(loc: &Path) -> InstalledApp {
    InstalledApp {
        id: "HKCU64:Bogus".into(),
        key_name: "Bogus".into(),
        sources: vec![],
        display_name: "Bogus App".into(),
        display_version: None,
        publisher: None,
        install_location: Some(loc.to_path_buf()),
        display_icon: None,
        uninstall_string: None,
        quiet_uninstall_string: None,
        modify_path: None,
        install_date: None,
        estimated_size_kb: None,
        windows_installer: false,
        product_code: None,
        per_user: true,
        hidden: None,
    }
}

#[test]
fn outside_zone_children_are_weak() {
    let f = Fixture::new();
    let tool = f.root.join("elsewhere").join("Tool");
    fs::create_dir_all(&tool).unwrap();
    fs::write(tool.join("a.dll"), b"x").unwrap();
    fs::write(tool.join("Tool.exe"), b"x").unwrap();
    let plan = scan::scan(&f.env, &bogus_app(&tool), None, &[], true, None, None).unwrap();
    assert!(matches!(plan.install_dir_status, DirStatus::Confirmed {}), "{:?}", plan.install_dir_status);
    for n in ["a.dll", "Tool.exe"] {
        check(find_path(&plan, &tool.join(n)), 25, Tier::Weak, false);
    }
}

fn short_path(p: &Path) -> Option<PathBuf> {
    use std::os::windows::ffi::{OsStrExt, OsStringExt};
    let w: Vec<u16> = p.as_os_str().encode_wide().chain(Some(0)).collect();
    let mut buf = vec![0u16; 1024];
    // SAFETY: NUL-terminated input, output buffer sized.
    let n = unsafe { windows::Win32::Storage::FileSystem::GetShortPathNameW(windows::core::PCWSTR(w.as_ptr()), Some(&mut buf)) } as usize;
    (n > 0 && n < buf.len()).then(|| PathBuf::from(std::ffi::OsString::from_wide(&buf[..n])))
}

#[test]
fn rejects_bogus_install_dirs() {
    let f = Fixture::new();
    let alias = f.root.join("pf-alias");
    paths::make_junction(&alias, &suite_dir(&f.env)).unwrap();
    let mut cases = vec![
        ("documents", documents(&f.env)),
        ("zone root", pf(&f.env)),
        ("junction alias", alias),
        ("trailing dot", PathBuf::from(format!("{}.", notes_dir(&f.env).display()))),
    ];
    match short_path(&notes_dir(&f.env)) {
        Some(s) if paths::norm(&s) != paths::norm(&notes_dir(&f.env)) => cases.push(("8.3", s)),
        _ => println!("skipped 8.3 case: no short name"),
    }
    for (what, dir) in cases {
        let plan = scan::scan(&f.env, &bogus_app(&dir), None, &[], true, None, None).unwrap();
        assert!(matches!(plan.install_dir_status, DirStatus::Rejected { .. }), "{what}: {:?}", plan.install_dir_status);
        assert!(plan.candidates.iter().all(|c| !matches!(c.group, Group::ProgramFiles | Group::Shortcuts)), "{what}: no file candidates from a rejected dir");
    }
}

#[test]
fn odd_registry_type_blocks_candidate() {
    let f = Fixture::new();
    let reg = f.second_dir().join("odd.reg");
    fs::write(
        &reg,
        format!(
            "Windows Registry Editor Version 5.00\r\n\r\n[HKEY_CURRENT_USER\\Software\\uniinstaller-tests\\{}\\Software\\Sandbox Soft\\Sandbox Notes]\r\n\"Odd\"=hex(20):01,02\r\n",
            f.tag
        ),
    )
    .unwrap();
    let out = std::process::Command::new("reg").arg("import").arg(&reg).output().unwrap();
    assert!(out.status.success(), "reg import failed: {}", String::from_utf8_lossy(&out.stderr));
    let plan = ops::preview(&f.env, "HKCU64:SandboxNotes").unwrap();
    let sw = find_key(&plan, |k| k.path.ends_with(r"Sandbox Soft\Sandbox Notes"));
    assert_eq!(sw.len(), 1);
    assert_eq!(sw[0].tier, Tier::Blocked);
    assert!(sw[0].blocks.iter().any(|b| b.code == BlockCode::Unverifiable), "{:?}", sw[0].blocks);
    assert_eq!(sw[0].ident, Ident::None {});
    check(find_path(&plan, &notes_dir(&f.env).join("resources")), 45, Tier::Review, false);
    assert_eq!(find_key(&plan, |k| k.path.contains("Uninstall")).len(), 2);
}

fn snapshot(f: &Fixture) -> (Vec<(String, u64)>, RegNode) {
    let mut files = Vec::new();
    let mut stack = vec![f.root.clone()];
    while let Some(d) = stack.pop() {
        for e in fs::read_dir(&d).unwrap().flatten() {
            let md = fs::symlink_metadata(e.path()).unwrap();
            files.push((paths::norm(&e.path()), md.len() ^ paths::mtime_ms(&md)));
            if md.is_dir() && !paths::is_reparse(&e.path()).unwrap() {
                stack.push(e.path());
            }
        }
    }
    files.sort();
    let key = RegPath::new(Hive::Hkcu, View::V64, format!(r"Software\uniinstaller-tests\{}", f.tag));
    (files, registry::capture(&key).unwrap())
}

#[test]
fn dry_run_is_read_only() {
    let f = Fixture::new();
    let before = snapshot(&f);
    for id in ["HKCU64:SandboxNotes", "HKCU64:SandboxSuite", "HKCU64:SandboxOrphan", "HKCU64:SandboxBroken"] {
        ops::preview(&f.env, id).unwrap();
    }
    assert!(before == snapshot(&f), "preview changed the sandbox");
}

#[test]
fn other_volume_candidates_are_blocked() {
    let Some(f) = Fixture::other_volume() else {
        println!("skipped: fixture and data_dir on the same volume");
        return;
    };
    let plan = ops::preview(&f.env, "HKCU64:SandboxNotes").unwrap();
    let paths_: Vec<_> = plan.candidates.iter().filter(|c| path_of(c).is_some()).collect();
    assert!(!paths_.is_empty());
    for c in paths_ {
        assert_eq!(c.tier, Tier::Blocked, "{:?}", c.target);
        assert!(c.blocks.iter().any(|b| b.code == BlockCode::OtherVolume), "{:?}", c.blocks);
        assert!(!c.selected);
    }
    assert!(plan.candidates.iter().any(|c| c.group == Group::Registry && c.tier == Tier::Safe));
}

fn set(key: &RegPath, name: &str, value: &str) {
    registry::set_string(&registry::create(key, KEY_ALL_ACCESS).unwrap(), name, value, false).unwrap();
}

fn shared(c: &Candidate) -> bool {
    c.tier == Tier::Blocked && !c.selected && c.blocks.iter().any(|b| b.code == BlockCode::SharedWithOtherApp)
}

/// Two versions of one product share a version-neutral settings folder and key (lab `two-versions`).
#[test]
fn version_neutral_settings_are_shared() {
    let f = Fixture::new();
    let mut dirs = Vec::new();
    for n in [1, 2] {
        let dir = pf(&f.env).join(format!(r"Editor Vendor\Sandbox Editor {n}"));
        let exe = dir.join(format!("editor{n}.exe"));
        fs::create_dir_all(&dir).unwrap();
        fs::write(&exe, b"MZ fake").unwrap();
        let entry = f.env.uninstall_roots[0].child(&format!("SandboxEditor{n}"));
        set(&entry, "DisplayName", &format!("Sandbox Editor {n}"));
        set(&entry, "DisplayVersion", &format!("{n}.0"));
        set(&entry, "Publisher", "Editor Vendor");
        set(&entry, "InstallLocation", &dir.to_string_lossy());
        set(&entry, "DisplayIcon", &exe.to_string_lossy());
        dirs.push(dir);
    }
    let vendor = roaming(&f.env).join("Editor Vendor");
    fs::create_dir_all(vendor.join("Sandbox Editor 1")).unwrap();
    fs::write(vendor.join(r"Sandbox Editor 1\settings.ini"), b"[1]").unwrap();
    fs::create_dir_all(vendor.join("Sandbox Editor")).unwrap();
    fs::write(vendor.join(r"Sandbox Editor\settings-2.ini"), b"[2]").unwrap();
    let sw = f.env.software_roots[0].child("Editor Vendor");
    set(&sw.child("Sandbox Editor"), "Editor2", "1");
    set(&sw.child("Sandbox Editor 1"), "InstallDir", &dirs[0].to_string_lossy());

    let plan = ops::preview(&f.env, "HKCU64:SandboxEditor1").unwrap();
    assert!(matches!(plan.install_dir_status, DirStatus::Confirmed {}), "{:?}", plan.install_dir_status);
    let neutral = find_path(&plan, &vendor.join("Sandbox Editor"));
    assert!(shared(neutral), "{:?}", neutral.blocks);
    check(find_path(&plan, &vendor.join("Sandbox Editor 1")), 30, Tier::Weak, false);
    let key = find_key(&plan, |k| k.path.ends_with(r"Editor Vendor\Sandbox Editor"));
    assert_eq!(key.len(), 1);
    assert!(shared(key[0]), "{:?}", key[0].blocks);
    let own = find_key(&plan, |k| k.path.ends_with(r"Editor Vendor\Sandbox Editor 1"));
    assert_eq!(own.len(), 1);
    check(own[0], 95, Tier::Safe, false);
}

fn find_value<'a>(plan: &'a Plan, name: &str) -> &'a Candidate {
    plan.candidates.iter().find(|c| matches!(&c.target, Target::RegValue { name: n, .. } if n == name)).unwrap_or_else(|| panic!("no value {name}"))
}

/// A program installed inside the target's folder owns the registry entries that point into its folder (lab `shared-suite`).
#[test]
fn nested_app_registry_is_shared() {
    let f = Fixture::new();
    let sd = suite_dir(&f.env);
    let td = sd.join("Shared Tool");
    let tool = td.join("tool.exe");
    set(&f.env.run_roots[0], "SharedTool", &format!("\"{}\" /tray", tool.display()));
    set(&f.env.app_paths_roots[0].child("tool.exe"), "", &tool.to_string_lossy());
    set(&f.env.app_paths_roots[0].child("suite.exe"), "", &sd.join("suite.exe").to_string_lossy());
    let sw = f.env.software_roots[0].child("Sandbox Soft").child("Sandbox Suite");
    set(&sw, "InstallDir", &sd.to_string_lossy());
    set(&sw.child("Shared Tool"), "InstallDir", &td.to_string_lossy());
    let lnk = start_menu(&f.env).join(r"Sandbox Soft\Shared Tool.lnk");
    uni_core::shortcuts::create(&lnk, &tool).unwrap();
    // The target's own Uninstall entry may point into a nested app's folder (a launcher); that is not shared.
    let own_entry = f.env.uninstall_roots[0].child("SandboxSuite");
    set(&own_entry, "ModifyPath", &tool.to_string_lossy());

    let plan = ops::preview(&f.env, "HKCU64:SandboxSuite").unwrap();
    assert!(shared(find_value(&plan, "SharedTool")), "{:?}", find_value(&plan, "SharedTool").blocks);
    check(find_value(&plan, "SandboxSuite"), 65, Tier::Review, false);
    let tool_ap = find_key(&plan, |k| k.path.ends_with(r"AppPaths\tool.exe"));
    assert_eq!(tool_ap.len(), 1);
    assert!(shared(tool_ap[0]), "{:?}", tool_ap[0].blocks);
    check(find_key(&plan, |k| k.path.ends_with(r"AppPaths\suite.exe"))[0], 65, Tier::Review, false);
    let key = find_key(&plan, |k| k.path.ends_with(r"Sandbox Soft\Sandbox Suite"));
    assert_eq!(key.len(), 1);
    assert!(shared(key[0]), "{:?}", key[0].blocks);
    assert!(shared(find_path(&plan, &lnk)), "the shortcut rule still applies after its move");
    let own = find_key(&plan, |k| k.same(&own_entry));
    assert_eq!(own.len(), 1);
    assert!(own[0].blocks.iter().all(|b| b.code != BlockCode::SharedWithOtherApp), "own entry: {:?}", own[0].blocks);
}

/// A program Apps & Features hides (SystemComponent=1) is another app all the same.
#[test]
fn hidden_app_is_another_app() {
    let f = Fixture::new();
    let sd = suite_dir(&f.env);
    let hd = sd.join("Hidden Helper");
    let exe = hd.join("helper.exe");
    fs::create_dir_all(&hd).unwrap();
    fs::write(&exe, b"MZ fake").unwrap();
    let entry = f.env.uninstall_roots[0].child("HiddenHelper");
    set(&entry, "DisplayName", "Hidden Helper");
    set(&entry, "InstallLocation", &hd.to_string_lossy());
    registry::set_dword(&registry::create(&entry, KEY_ALL_ACCESS).unwrap(), "SystemComponent", 1).unwrap();
    set(&f.env.run_roots[0], "HiddenHelper", &format!("\"{}\" /tray", exe.display()));
    set(&f.env.app_paths_roots[0].child("helper.exe"), "", &exe.to_string_lossy());
    let lnk = start_menu(&f.env).join(r"Sandbox Soft\Hidden Helper.lnk");
    uni_core::shortcuts::create(&lnk, &exe).unwrap();
    assert!(!uni_core::inventory::list_apps(&f.env, false).unwrap().iter().any(|a| a.display_name == "Hidden Helper"), "it is hidden");

    let plan = ops::preview(&f.env, "HKCU64:SandboxSuite").unwrap();
    assert!(shared(find_path(&plan, &hd)), "{:?}", find_path(&plan, &hd).blocks);
    assert!(shared(find_value(&plan, "HiddenHelper")), "{:?}", find_value(&plan, "HiddenHelper").blocks);
    let ap = find_key(&plan, |k| k.path.ends_with(r"AppPaths\helper.exe"));
    assert_eq!(ap.len(), 1);
    assert!(shared(ap[0]), "{:?}", ap[0].blocks);
    assert!(shared(find_path(&plan, &lnk)), "{:?}", find_path(&plan, &lnk).blocks);
}

/// A nested app without InstallLocation is still seen through its uninstaller and icon folder.
#[test]
fn nested_app_without_install_location_is_shared() {
    let f = Fixture::new();
    let sd = suite_dir(&f.env);
    let bd = sd.join("Bare Tool");
    let exe = bd.join("bare.exe");
    fs::create_dir_all(&bd).unwrap();
    fs::write(&exe, b"MZ fake").unwrap();
    let entry = f.env.uninstall_roots[0].child("BareTool");
    set(&entry, "DisplayName", "Bare Tool");
    set(&entry, "DisplayIcon", &exe.to_string_lossy());
    set(&entry, "UninstallString", &format!("\"{}\" /uninstall", exe.display()));
    set(&f.env.run_roots[0], "BareTool", &format!("\"{}\" /tray", exe.display()));
    set(&f.env.app_paths_roots[0].child("bare.exe"), "", &exe.to_string_lossy());
    let sw = f.env.software_roots[0].child("Sandbox Soft").child("Sandbox Suite");
    set(&sw.child("Bare Tool"), "InstallDir", &bd.to_string_lossy());

    let plan = ops::preview(&f.env, "HKCU64:SandboxSuite").unwrap();
    assert!(shared(find_value(&plan, "BareTool")), "{:?}", find_value(&plan, "BareTool").blocks);
    let ap = find_key(&plan, |k| k.path.ends_with(r"AppPaths\bare.exe"));
    assert_eq!(ap.len(), 1);
    assert!(shared(ap[0]), "{:?}", ap[0].blocks);
    let key = find_key(&plan, |k| k.path.ends_with(r"Sandbox Soft\Sandbox Suite"));
    assert_eq!(key.len(), 1);
    assert!(shared(key[0]), "{:?}", key[0].blocks);
}

/// Another app whose folder is a drive root or a protected root must not claim every value of a target without a confirmed dir.
#[test]
fn broad_install_location_does_not_claim_references() {
    let f = Fixture::new();
    let mut target = bogus_app(&documents(&f.env));
    target.display_name = "Sandbox Notes".into();
    target.publisher = Some("Sandbox Soft".into());
    let drive: String = f.root.to_string_lossy().chars().take(2).collect();
    let mut others = Vec::new();
    for (i, dir) in [PathBuf::from(format!(r"{drive}\")), pf(&f.env)].into_iter().enumerate() {
        let mut o = bogus_app(&dir);
        o.id = format!("HKCU64:Broad{i}");
        o.display_name = format!("Broad {i}");
        others.push(o);
    }
    let plan = scan::scan(&f.env, &target, None, &others, true, None, None).unwrap();
    assert!(matches!(plan.install_dir_status, DirStatus::Rejected { .. }), "{:?}", plan.install_dir_status);
    let key = find_key(&plan, |k| k.path.ends_with(r"Sandbox Soft\Sandbox Notes"));
    assert_eq!(key.len(), 1);
    assert!(key[0].blocks.iter().all(|b| b.code != BlockCode::SharedWithOtherApp), "{:?}", key[0].blocks);
}

fn forced_of(picked: &Path, folder: Option<&Path>, names: &[&str]) -> Forced {
    Forced { picked: picked.to_path_buf(), folder: folder.map(Path::to_path_buf), search_names: names.iter().map(|n| n.to_string()).collect() }
}

/// A forced target is never corroborated and never preselected; its settings are looked for only by the names it carries (spec 1.5).
#[test]
fn forced_target_rules() {
    let f = Fixture::new();
    let dir = user_programs(&f.env).join("Forced Tool");
    let exe = dir.join("tool.exe");
    fs::create_dir_all(&dir).unwrap();
    fs::write(&exe, b"MZ fake").unwrap();
    fs::write(dir.join("data.bin"), b"bin").unwrap();
    let lnk = start_menu(&f.env).join("Forced Tool.lnk");
    uni_core::shortcuts::create(&lnk, &exe).unwrap();
    set(&f.env.run_roots[0], "ForcedTool", &format!("\"{}\" --tray", exe.display()));
    let settings = roaming(&f.env).join("Forced Tool");
    fs::create_dir_all(&settings).unwrap();
    fs::write(settings.join("s.ini"), b"[x]").unwrap();
    fs::create_dir_all(roaming(&f.env).join("Abc")).unwrap();
    fs::create_dir_all(roaming(&f.env).join("Abc 2")).unwrap();

    let forced = forced_of(&dir, Some(&dir), &["Forced Tool"]);
    let mut app = uni_core::force::app_for(&forced, "Forced Tool", None, None);
    // The icon sits in the folder: a listed program with this icon is corroborated (b), a forced target never is (a).
    app.display_icon = Some(exe.to_string_lossy().to_string());
    let plan = scan::scan(&f.env, &app, None, &[], true, None, Some(&forced)).unwrap();
    assert!(matches!(plan.install_dir_status, DirStatus::Confirmed {}), "{:?}", plan.install_dir_status);
    assert!(!plan.corroborated);
    assert!(plan.candidates.iter().all(|c| !c.selected), "a forced plan preselects nothing");
    check(find_path(&plan, &exe), 45, Tier::Review, false);
    check(find_path(&plan, &dir.join("data.bin")), 45, Tier::Review, false);
    check(find_path(&plan, &lnk), 50, Tier::Review, false);
    check(find_value(&plan, "ForcedTool"), 30, Tier::Weak, false);
    let s = find_path(&plan, &settings);
    check(s, 20, Tier::Weak, false);
    assert_eq!(s.group, Group::Data);
    assert!(!plan.candidates.iter().any(|c| path_of(c).is_some_and(|p| p.ends_with("Abc"))));

    // (b) the same app as a listed program: corroborated, the shortcut is preselected.
    let plan = scan::scan(&f.env, &app, None, &[], true, None, None).unwrap();
    assert!(plan.corroborated);
    check(find_path(&plan, &lnk), 85, Tier::Safe, true);

    // (c) no search names: no settings folder by name.
    let none = forced_of(&dir, Some(&dir), &[]);
    let plan = scan::scan(&f.env, &app, None, &[], true, None, Some(&none)).unwrap();
    assert!(plan.candidates.iter().all(|c| c.group != Group::Data), "{:?}", plan.candidates.iter().map(|c| &c.id).collect::<Vec<_>>());
    check(find_path(&plan, &lnk), 50, Tier::Review, false);

    // (e) only the names it carries: `Abc 2`, not the version-free `Abc`.
    let abc = forced_of(&dir, Some(&dir), &["Abc 2"]);
    let mut app2 = uni_core::force::app_for(&abc, "Abc 2", None, None);
    app2.display_icon = None;
    let plan = scan::scan(&f.env, &app2, None, &[], true, None, Some(&abc)).unwrap();
    check(find_path(&plan, &roaming(&f.env).join("Abc 2")), 20, Tier::Weak, false);
    assert!(!plan.candidates.iter().any(|c| path_of(c).is_some_and(|p| paths::norm(p) == paths::norm(&roaming(&f.env).join("Abc")))));

    // (d) file-only: no folder, the picked file is the anchor of the references.
    let lonely = pf(&f.env).join("lonely.exe");
    fs::write(&lonely, b"MZ fake").unwrap();
    fs::write(pf(&f.env).join("neighbour.dll"), b"x").unwrap();
    let dlnk = desktop(&f.env).join("Lonely.lnk");
    uni_core::shortcuts::create(&dlnk, &lonely).unwrap();
    let file_only = forced_of(&lonely, None, &["Lonely"]);
    let app3 = uni_core::force::app_for(&file_only, "Lonely", None, None);
    let plan = scan::scan(&f.env, &app3, None, &[], true, None, Some(&file_only)).unwrap();
    assert!(matches!(plan.install_dir_status, DirStatus::NotSet {}), "{:?}", plan.install_dir_status);
    let c = find_path(&plan, &lonely);
    check(c, 60, Tier::Review, false);
    assert_eq!(c.group, Group::ProgramFiles);
    check(find_path(&plan, &dlnk), 50, Tier::Review, false);
    assert!(!plan.candidates.iter().any(|c| path_of(c).is_some_and(|p| p.ends_with("neighbour.dll"))), "files next to the picked one are not offered");
    assert!(plan.candidates.iter().all(|c| !c.selected));
}
