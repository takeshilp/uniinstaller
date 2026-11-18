mod common;
use common::Fixture;
use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};
use uni_core::env::APP_IDENTIFIER;
use uni_core::model::*;
use uni_core::sandbox::*;
use uni_core::trace::{self, Differ, Snapshot};
use uni_core::{paths, registry};

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
