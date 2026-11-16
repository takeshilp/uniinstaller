mod common;
use common::Fixture;
use uni_core::inventory::list_apps;
use uni_core::model::*;
use uni_core::registry;
use winreg::enums::*;

fn names(f: &Fixture) -> Vec<String> {
    list_apps(&f.env).unwrap().into_iter().map(|a| a.display_name).collect()
}

#[test]
fn reads_both_roots_and_dedupes() {
    let f = Fixture::new();
    let apps = list_apps(&f.env).unwrap();
    let notes: Vec<_> = apps.iter().filter(|a| a.display_name == "Sandbox Notes").collect();
    assert_eq!(notes.len(), 1, "registered in both Uninstall roots, listed once");
    assert_eq!(notes[0].sources.len(), 2);
    assert_eq!(notes[0].id, "HKCU64:SandboxNotes");
    assert!(notes[0].per_user);
    assert_eq!(notes[0].publisher.as_deref(), Some("Sandbox Soft"));
    assert_eq!(notes[0].install_location.as_deref(), Some(uni_core::sandbox::notes_dir(&f.env).as_path()));
    assert_eq!(
        names(&f),
        ["Sandbox Broken", "Sandbox Notes", "Sandbox Orphan", "Sandbox Shared Tool", "Sandbox Suite"],
        "sorted case-insensitively"
    );
}

#[test]
fn skips_system_components_updates_and_nameless() {
    let f = Fixture::new();
    let n = names(&f);
    assert!(!n.iter().any(|x| x.contains("System Component") || x.contains("Patch") || x.is_empty()));
    // the raw keys do exist
    for k in ["SandboxSystemComponent", "SandboxPatchKB1", "SandboxNameless"] {
        assert!(registry::exists(&f.env.uninstall_roots[0].child(k)), "{k}");
    }
}

#[test]
fn expands_reg_expand_sz() {
    let f = Fixture::new();
    let k = registry::create(&f.env.uninstall_roots[0].child("ExpandMe"), KEY_ALL_ACCESS).unwrap();
    registry::set_string(&k, "DisplayName", "Expand Me", false).unwrap();
    registry::set_string(&k, "InstallLocation", r"%SystemRoot%\Fake", true).unwrap();
    let a = list_apps(&f.env).unwrap().into_iter().find(|a| a.display_name == "Expand Me").unwrap();
    let sr = std::env::var("SystemRoot").unwrap();
    assert_eq!(a.install_location.unwrap().to_string_lossy(), format!(r"{sr}\Fake"));
    let notes = list_apps(&f.env).unwrap().into_iter().find(|a| a.id == "HKCU64:SandboxNotes").unwrap();
    assert!(notes.uninstall_string.unwrap().starts_with("%SystemRoot%"), "raw string is kept as stored");
}

#[test]
fn hkcu_same_key_two_views_is_one_source() {
    let f = Fixture::new();
    let mut env = f.env.clone();
    let p64 = env.uninstall_roots[0].clone();
    env.uninstall_roots = vec![p64.clone(), RegPath { view: View::V32, ..p64 }];
    let apps = list_apps(&env).unwrap();
    let notes = apps.iter().find(|a| a.display_name == "Sandbox Notes").unwrap();
    assert_eq!(notes.sources.len(), 1, "HKCU is one physical key in both views");
    assert_eq!(apps.iter().filter(|a| a.display_name == "Sandbox Suite").count(), 1);
}
