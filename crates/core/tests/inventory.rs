mod common;
use common::Fixture;
use uni_core::inventory::{self, list_apps};
use uni_core::model::*;
use uni_core::registry;
use winreg::enums::*;

fn names(f: &Fixture) -> Vec<String> {
    list_apps(&f.env, false).unwrap().into_iter().map(|a| a.display_name).collect()
}

#[test]
fn reads_both_roots_and_dedupes() {
    let f = Fixture::new();
    let apps = list_apps(&f.env, false).unwrap();
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
    let a = list_apps(&f.env, false).unwrap().into_iter().find(|a| a.display_name == "Expand Me").unwrap();
    let sr = std::env::var("SystemRoot").unwrap();
    assert_eq!(a.install_location.unwrap().to_string_lossy(), format!(r"{sr}\Fake"));
    let notes = list_apps(&f.env, false).unwrap().into_iter().find(|a| a.id == "HKCU64:SandboxNotes").unwrap();
    assert!(notes.uninstall_string.unwrap().starts_with("%SystemRoot%"), "raw string is kept as stored");
}

#[test]
fn hkcu_same_key_two_views_is_one_source() {
    let f = Fixture::new();
    let mut env = f.env.clone();
    let p64 = env.uninstall_roots[0].clone();
    env.uninstall_roots = vec![p64.clone(), RegPath { view: View::V32, ..p64 }];
    let apps = list_apps(&env, false).unwrap();
    let notes = apps.iter().find(|a| a.display_name == "Sandbox Notes").unwrap();
    assert_eq!(notes.sources.len(), 1, "HKCU is one physical key in both views");
    assert_eq!(apps.iter().filter(|a| a.display_name == "Sandbox Suite").count(), 1);
}

fn set(key: &RegPath, name: &str, value: &str) {
    registry::set_string(&registry::create(key, KEY_ALL_ACCESS).unwrap(), name, value, false).unwrap();
}

fn set_dword(key: &RegPath, name: &str, value: u32) {
    registry::set_dword(&registry::create(key, KEY_ALL_ACCESS).unwrap(), name, value).unwrap();
}

#[test]
fn hidden_entries_listed_on_request() {
    let f = Fixture::new();
    let u = &f.env.uninstall_roots;
    let update = u[0].child("SandboxUpdateKB2");
    set(&update, "DisplayName", "Sandbox Update KB2");
    set(&update, "ReleaseType", "Security Update");
    let child = u[0].child("SandboxHiddenChild");
    set(&child, "DisplayName", "Sandbox Hidden Child");
    set(&child, "ParentKeyName", "SandboxNotes");
    set_dword(&child, "SystemComponent", 1);
    let shown = u[0].child("SandboxShown");
    set(&shown, "DisplayName", "Sandbox Shown");
    set_dword(&shown, "SystemComponent", 0);
    // A hidden twin of a listed program: the same name, version, uninstall command and folder.
    let visible = list_apps(&f.env, false).unwrap();
    let suite = visible.iter().find(|a| a.id == "HKCU64:SandboxSuite").unwrap();
    let twin = u[1].child("SandboxSuite");
    set(&twin, "DisplayName", &suite.display_name);
    set(&twin, "DisplayVersion", suite.display_version.as_deref().unwrap());
    set(&twin, "UninstallString", suite.uninstall_string.as_deref().unwrap());
    set(&twin, "InstallLocation", &suite.install_location.as_ref().unwrap().to_string_lossy());
    set_dword(&twin, "SystemComponent", 1);

    let all = list_apps(&f.env, true).unwrap();
    let shown_only: Vec<&InstalledApp> = all.iter().filter(|a| a.hidden.is_none()).collect();
    // Hidden entries never change what the default list holds.
    assert_eq!(serde_json::to_string(&shown_only).unwrap(), serde_json::to_string(&list_apps(&f.env, false).unwrap()).unwrap());
    let hidden: Vec<(&str, Option<HiddenReason>)> = all.iter().filter(|a| a.hidden.is_some()).map(|a| (a.display_name.as_str(), a.hidden)).collect();
    assert_eq!(hidden, [("Sandbox System Component", Some(HiddenReason::SystemComponent))]);
    assert_eq!(all.len(), visible.len() + 1);
    assert!(visible.iter().any(|a| a.display_name == "Sandbox Shown"), "SystemComponent=0 is a visible program");
    let suites: Vec<_> = all.iter().filter(|a| a.display_name == "Sandbox Suite").collect();
    assert_eq!(suites.len(), 1, "the hidden twin is dropped");
    assert_eq!(suites[0].sources.len(), 1);
    assert!(serde_json::to_value(suites[0]).unwrap().get("hidden").is_none(), "no hidden field for a visible program");
    assert_eq!(inventory::find_app(&f.env, "HKCU64:SandboxSystemComponent").unwrap().hidden, Some(HiddenReason::SystemComponent));
}
