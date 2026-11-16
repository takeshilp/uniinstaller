mod common;
use common::Fixture;
use std::fs;
use std::path::{Path, PathBuf};
use uni_core::model::*;
use uni_core::sandbox::*;
use uni_core::{ops, paths, registry, scan};

fn path_of(c: &Candidate) -> Option<&Path> {
    match &c.target {
        Target::Path { path, .. } => Some(path),
        _ => None,
    }
}

fn find_path<'a>(plan: &'a Plan, p: &Path) -> &'a Candidate {
    plan.candidates.iter().find(|c| path_of(c).is_some_and(|x| paths::norm(x) == paths::norm(p))).unwrap_or_else(|| panic!("no candidate for {}", p.display()))
}

fn find_key<'a>(plan: &'a Plan, f: impl Fn(&RegPath) -> bool) -> Vec<&'a Candidate> {
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

    // Nothing else: 5 children (the exe is gone), 2 lnk, Run, App Paths, 2 own keys, AppData dir, Software key.
    assert_eq!(plan.candidates.len(), 13, "{:#?}", plan.candidates.iter().map(|c| &c.id).collect::<Vec<_>>());
    assert!(plan.candidates.iter().all(|c| !path_of(c).is_some_and(|p| p.ends_with("keep.txt"))), "outside keep.txt is not listed");
    assert!(plan.candidates.iter().all(|c| !path_of(c).is_some_and(|p| paths::is_inside(p, &documents(&f.env)))));
    assert!(!plan.candidates.iter().any(|c| matches!(&c.target, Target::RegValue { name, .. } if name == "SandboxSuite")), "another app's Run value");
    for c in &plan.candidates {
        assert!(c.id.starts_with("path:") || c.id.starts_with("key:") || c.id.starts_with("value:"));
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
    }
}

#[test]
fn outside_zone_children_are_weak() {
    let f = Fixture::new();
    let tool = f.root.join("elsewhere").join("Tool");
    fs::create_dir_all(&tool).unwrap();
    fs::write(tool.join("a.dll"), b"x").unwrap();
    fs::write(tool.join("Tool.exe"), b"x").unwrap();
    let plan = scan::scan(&f.env, &bogus_app(&tool), None, &[], true).unwrap();
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
        let plan = scan::scan(&f.env, &bogus_app(&dir), None, &[], true).unwrap();
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
