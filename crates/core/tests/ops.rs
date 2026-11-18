mod common;
use common::Fixture;
use std::collections::BTreeMap;
use std::fs;
use std::path::PathBuf;
use std::time::Duration;
use uni_core::model::*;
use uni_core::native::RunOptions;
use uni_core::ops;
use uni_core::sandbox::*;
use uni_core::{paths, registry};

const NOTES: &str = "HKCU64:SandboxNotes";

fn opts() -> RunOptions {
    RunOptions { show_window: false, poll: Duration::from_millis(50), ..Default::default() }
}

/// begin + native uninstaller + leftover scan.
fn uninstalled(f: &Fixture, id: &str) -> Operation {
    let op = ops::begin(&f.env, id, false).unwrap();
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

fn id_ending(op: &Operation, suffix: &str) -> String {
    let s = suffix.to_lowercase();
    plan(op).candidates.iter().find(|c| c.id.ends_with(&s)).unwrap_or_else(|| panic!("no candidate ending with {suffix}")).id.clone()
}

fn item<'a>(op: &'a Operation, suffix: &str) -> &'a ItemRecord {
    let s = suffix.to_lowercase();
    op.items.iter().find(|i| i.candidate_id.ends_with(&s)).unwrap_or_else(|| panic!("no item ending with {suffix}"))
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

fn ops_dir(f: &Fixture) -> PathBuf {
    f.env.data_dir.join("operations")
}

fn q_files(f: &Fixture, op: &Operation) -> usize {
    fs::read_dir(ops_dir(f).join(&op.id).join("q")).map(|r| r.count()).unwrap_or(0)
}

#[test]
fn uninstall_scan_apply_restore_roundtrip() {
    let f = Fixture::new();
    let op = uninstalled(&f, NOTES);
    let native = op.native.as_ref().unwrap();
    assert_eq!(native.exit_code, Some(0));
    assert_eq!(op.entry_after, Some(EntryState::Gone));
    assert_eq!(op.status, OpStatus::AwaitingReview);
    assert!(!notes_dir(&f.env).join("Sandbox Notes.exe").exists(), "the native uninstaller removed the program file");

    let before = tree(&f);
    let ids = selectable(&op);
    assert!(ids.len() >= 10, "{ids:?}");
    let applied = ops::apply(&f.env, &op.id, &ids).unwrap();
    assert!(applied.items.iter().all(|i| i.status == ItemStatus::Removed), "{:#?}", applied.items);
    assert_eq!(applied.status, OpStatus::Completed, "{:?}", applied.status_detail);
    assert!(!notes_dir(&f.env).exists(), "the emptied install folder is removed");
    assert!(!start_menu(&f.env).join("Sandbox Soft").exists(), "the emptied Start Menu folder is removed");
    assert!(!applied.empty_dirs_removed.is_empty());
    assert!(outside_dir(&f.env).join("keep.txt").exists(), "the junction target is untouched");
    assert_eq!(fs::read(outside_dir(&f.env).join("keep.txt")).unwrap(), b"keep me");
    let v = applied.verify.as_ref().unwrap();
    assert!(!v.app_still_listed && v.reappeared.is_empty());

    let restored = ops::restore(&f.env, &op.id).unwrap();
    assert_eq!(restored.status, OpStatus::Restored, "{:#?}", restored.items.iter().map(|i| (&i.candidate_id, i.restore, &i.restore_detail)).collect::<Vec<_>>());
    let after = tree(&f);
    assert_eq!(before.0, after.0, "files byte-identical, folders recreated, the junction is still a link");
    assert_eq!(before.1, after.1, "registry capture equal");
    assert_eq!(fs::read(outside_dir(&f.env).join("keep.txt")).unwrap(), b"keep me");
}

#[test]
fn revalidation_skips_changed_file() {
    let f = Fixture::new();
    let op = uninstalled(&f, NOTES);
    let ini = notes_dir(&f.env).join("config.ini");
    fs::remove_file(&ini).unwrap();
    fs::write(&ini, b"a completely different file").unwrap();
    let applied = ops::apply(&f.env, &op.id, &selectable(&op)).unwrap();
    assert_eq!(item(&applied, "config.ini").status, ItemStatus::Changed);
    assert_eq!(fs::read(&ini).unwrap(), b"a completely different file", "untouched");
    assert_eq!(applied.status, OpStatus::PartiallyCompleted);
    assert_eq!(item(&applied, "resources").status, ItemStatus::Removed);
}

#[test]
fn revalidation_skips_dir_swapped_for_junction() {
    let f = Fixture::new();
    let op = uninstalled(&f, NOTES);
    let res = notes_dir(&f.env).join("resources");
    fs::remove_dir_all(&res).unwrap();
    fs::write(f.second_dir().join("precious.txt"), b"precious").unwrap();
    paths::make_junction(&res, f.second_dir()).unwrap();
    let applied = ops::apply(&f.env, &op.id, &selectable(&op)).unwrap();
    let it = item(&applied, "resources");
    assert!(matches!(it.status, ItemStatus::Changed | ItemStatus::Blocked), "{:?}", it.status);
    assert!(paths::is_reparse(&res).unwrap(), "the junction is untouched");
    assert_eq!(fs::read(f.second_dir().join("precious.txt")).unwrap(), b"precious");
}

#[test]
fn locked_file_reported_and_others_proceed() {
    use std::os::windows::fs::OpenOptionsExt;
    let f = Fixture::new();
    let op = uninstalled(&f, NOTES);
    let ini = notes_dir(&f.env).join("config.ini");
    let ids = selectable(&op);
    let held = fs::OpenOptions::new().read(true).share_mode(0).open(&ini).unwrap();
    let applied = ops::apply(&f.env, &op.id, &ids).unwrap();
    let it = item(&applied, "config.ini");
    assert!(matches!(it.status, ItemStatus::Locked | ItemStatus::AccessDenied), "{:?}", it.status);
    assert!(it.quarantine.is_none());
    assert!(ini.exists());
    assert_eq!(item(&applied, "resources").status, ItemStatus::Removed);
    assert_eq!(applied.status, OpStatus::PartiallyCompleted);
    // release the lock and retry the failed item only
    drop(held);
    let retried = ops::apply(&f.env, &op.id, &[id_ending(&op, "config.ini")]).unwrap();
    assert_eq!(item(&retried, "config.ini").status, ItemStatus::Removed);
    assert_eq!(retried.items.iter().filter(|i| i.candidate_id.ends_with("config.ini")).count(), 1, "the retry replaced the failed record");
    assert_eq!(retried.status, OpStatus::Completed, "{:?}", retried.status_detail);
}

#[test]
fn apply_twice_is_idempotent() {
    let f = Fixture::new();
    let op = uninstalled(&f, NOTES);
    let ids = selectable(&op);
    let a = ops::apply(&f.env, &op.id, &ids).unwrap();
    let q = q_files(&f, &a);
    let b = ops::apply(&f.env, &op.id, &ids).unwrap();
    assert_eq!(a.items, b.items);
    assert_eq!(q_files(&f, &b), q);
}

#[test]
fn rescan_keeps_ids_stable() {
    let f = Fixture::new();
    let op = uninstalled(&f, NOTES);
    let all = selectable(&op);
    let subset: Vec<String> = all.iter().filter(|i| i.contains("logs") || i.contains("config.ini")).cloned().collect();
    assert_eq!(subset.len(), 2);
    ops::apply(&f.env, &op.id, &subset).unwrap();
    let again = ops::scan_leftovers(&f.env, &op.id).unwrap();
    let new_ids: Vec<String> = plan(&again).candidates.iter().map(|c| c.id.clone()).collect();
    for id in &all {
        assert_eq!(new_ids.contains(id), !subset.contains(id), "{id}");
    }
    // ids are derived from targets
    for c in &plan(&again).candidates {
        assert_eq!(c.id, ops::target_key(&c.target));
    }
}

#[test]
fn restore_conflict_keeps_quarantine_copy() {
    let f = Fixture::new();
    let op = uninstalled(&f, NOTES);
    let applied = ops::apply(&f.env, &op.id, &selectable(&op)).unwrap();
    let ini = notes_dir(&f.env).join("config.ini");
    fs::create_dir_all(ini.parent().unwrap()).unwrap();
    fs::write(&ini, b"new file made after the uninstall").unwrap();
    let restored = ops::restore(&f.env, &op.id).unwrap();
    let it = item(&restored, "config.ini");
    assert_eq!(it.restore, Some(RestoreStatus::Conflict));
    assert_eq!(fs::read(&ini).unwrap(), b"new file made after the uninstall", "never overwritten");
    assert!(it.quarantine.as_ref().unwrap().exists(), "the quarantined copy stays");
    assert_eq!(restored.status, OpStatus::PartiallyRestored);
    assert_eq!(item(&applied, "resources").status, ItemStatus::Removed);
    assert!(notes_dir(&f.env).join("resources").exists(), "the other items came back");
}

#[test]
fn interrupted_apply_is_restorable() {
    let f = Fixture::new();
    let op = uninstalled(&f, NOTES);
    let before = tree(&f);
    let applied = ops::apply(&f.env, &op.id, &selectable(&op)).unwrap();
    let mut o = ops::load(&f.env, &applied.id).unwrap();
    // (a) interrupted after the move: InProgress with the payload in quarantine
    let a = o.items.iter().position(|i| i.candidate_id.ends_with("config.ini")).unwrap();
    o.items[a].status = ItemStatus::InProgress;
    // (b) interrupted before the move: InProgress, the payload is not in quarantine and the original is in place
    let b = o.items.iter().position(|i| i.candidate_id.ends_with("resources")).unwrap();
    o.items[b].status = ItemStatus::InProgress;
    let (Target::Path { path, .. }, Some(q)) = (&o.items[b].target, &o.items[b].quarantine) else { panic!() };
    fs::create_dir_all(path.parent().unwrap()).unwrap();
    fs::rename(q, path).unwrap();
    ops::save(&f.env, &o).unwrap();
    let restored = ops::restore(&f.env, &op.id).unwrap();
    assert_eq!(restored.status, OpStatus::Restored, "{:#?}", restored.items.iter().map(|i| (&i.candidate_id, i.restore, &i.restore_detail)).collect::<Vec<_>>());
    assert_eq!(item(&restored, "resources").restore_detail.as_deref(), Some("was not moved"));
    assert_eq!(before.0, tree(&f).0);
}

#[test]
fn restore_item_with_payload_regardless_of_status() {
    let f = Fixture::new();
    let op = uninstalled(&f, NOTES);
    ops::apply(&f.env, &op.id, &selectable(&op)).unwrap();
    let mut o = ops::load(&f.env, &op.id).unwrap();
    let i = o.items.iter().position(|i| i.candidate_id.ends_with("config.ini")).unwrap();
    o.items[i].status = ItemStatus::Locked;
    ops::save(&f.env, &o).unwrap();
    let restored = ops::restore(&f.env, &op.id).unwrap();
    assert_eq!(item(&restored, "config.ini").restore, Some(RestoreStatus::Restored));
    assert!(notes_dir(&f.env).join("config.ini").exists());
}

#[test]
fn restore_validates_quarantine_and_target() {
    let f = Fixture::new();
    let op = uninstalled(&f, NOTES);
    ops::apply(&f.env, &op.id, &selectable(&op)).unwrap();
    let mut o = ops::load(&f.env, &op.id).unwrap();
    // (a) quarantine rewritten to a folder outside this operation
    let evil = f.second_dir().join("evil_payload");
    fs::write(&evil, b"evil").unwrap();
    let a = o.items.iter().position(|i| i.candidate_id.ends_with("config.ini")).unwrap();
    o.items[a].quarantine = Some(evil.clone());
    // (b) target rewritten into the sandbox Documents folder
    let b = o.items.iter().position(|i| i.candidate_id.ends_with("logs")).unwrap();
    let docs_target = documents(&f.env).join("x");
    let payload_b = o.items[b].quarantine.clone().unwrap();
    o.items[b].target = Target::Path { path: docs_target.clone(), kind: PathKind::Dir };
    ops::save(&f.env, &o).unwrap();
    let restored = ops::restore(&f.env, &op.id).unwrap();
    assert_eq!(restored.items[a].restore, Some(RestoreStatus::Failed));
    assert_eq!(restored.items[b].restore, Some(RestoreStatus::Failed));
    assert!(restored.items[a].restore_detail.as_ref().unwrap().starts_with("blocked"));
    assert!(restored.items[b].restore_detail.as_ref().unwrap().starts_with("blocked"));
    assert_eq!(fs::read(&evil).unwrap(), b"evil", "the outside payload was not moved");
    assert!(!notes_dir(&f.env).join("config.ini").exists());
    assert!(!docs_target.exists(), "nothing was written to Documents");
    assert!(payload_b.exists(), "the payload stays in quarantine");
}

#[test]
fn still_installed_blocks_scan() {
    let f = Fixture::new();
    let op = ops::begin(&f.env, "HKCU64:SandboxSharedTool", false).unwrap();
    let op = ops::run_native(&f.env, &op.id, &opts()).unwrap();
    assert_eq!(op.entry_after, Some(EntryState::Present));
    assert_eq!(op.status, OpStatus::Failed);
    assert_eq!(op.status_detail.as_deref(), Some("program still installed"));
    let err = ops::scan_leftovers(&f.env, &op.id).unwrap_err();
    assert!(err.0.contains("still installed"), "{err}");
}

#[test]
fn orphan_entry_offered_after_batch_uninstaller() {
    let f = Fixture::new();
    let op = uninstalled(&f, "HKCU64:SandboxOrphan");
    assert_eq!(op.entry_after, Some(EntryState::Orphaned));
    let key = plan(&op).candidates.iter().find(|c| c.group == Group::Registry && c.id.contains("sandboxorphan")).expect("own key offered");
    assert_eq!((key.score, key.tier, key.selected), (140, Tier::Safe, true), "{:?}", key.evidence);
    let applied = ops::apply(&f.env, &op.id, std::slice::from_ref(&key.id)).unwrap();
    assert_eq!(item(&applied, "sandboxorphan").status, ItemStatus::Removed);
    assert!(!registry::exists(&f.env.uninstall_roots[0].child("SandboxOrphan")));
    assert_eq!(applied.status, OpStatus::Completed, "{:?}", applied.status_detail);
    // and it can be put back
    let restored = ops::restore(&f.env, &op.id).unwrap();
    assert_eq!(restored.status, OpStatus::Restored);
    assert!(registry::exists(&f.env.uninstall_roots[0].child("SandboxOrphan")));
}

#[test]
fn tampered_plan_outside_zone_is_blocked() {
    let f = Fixture::new();
    let op = uninstalled(&f, NOTES);
    let key = RegPath::new(Hive::Hkcu, View::V64, format!(r"Software\uniinstaller-tests\{}\Outside\X", f.tag));
    registry::create(&key, winreg::enums::KEY_ALL_ACCESS).unwrap();
    let file = f.second_dir().join("outside.txt");
    fs::write(&file, b"outside").unwrap();
    let mut o = ops::load(&f.env, &op.id).unwrap();
    let p = o.plan.as_mut().unwrap();
    let k = p.candidates.iter().position(|c| c.group == Group::Registry).unwrap();
    let fi = p.candidates.iter().position(|c| c.group == Group::ProgramFiles).unwrap();
    p.candidates[k].target = Target::RegKey { key: key.clone() };
    p.candidates[k].id = ops::target_key(&p.candidates[k].target);
    p.candidates[fi].target = Target::Path { path: file.clone(), kind: PathKind::File };
    p.candidates[fi].id = ops::target_key(&p.candidates[fi].target);
    let ids = [p.candidates[k].id.clone(), p.candidates[fi].id.clone()];
    ops::save(&f.env, &o).unwrap();
    let applied = ops::apply(&f.env, &op.id, &ids).unwrap();
    assert_eq!(applied.items.len(), 2);
    assert!(applied.items.iter().all(|i| i.status == ItemStatus::Blocked), "{:#?}", applied.items);
    assert!(registry::exists(&key));
    assert_eq!(fs::read(&file).unwrap(), b"outside");
}

#[test]
fn concurrent_apply_keeps_all_records() {
    let f = Fixture::new();
    let op = uninstalled(&f, NOTES);
    let ids = selectable(&op);
    std::thread::scope(|s| {
        let h: Vec<_> = (0..2).map(|_| s.spawn(|| ops::apply(&f.env, &op.id, &ids).unwrap())).collect();
        for t in h {
            t.join().unwrap();
        }
    });
    let o = ops::load(&f.env, &op.id).unwrap();
    assert_eq!(o.items.len(), ids.len());
    for id in &ids {
        let recs: Vec<_> = o.items.iter().filter(|i| &i.candidate_id == id).collect();
        assert_eq!(recs.len(), 1, "{id}");
        assert_eq!(recs[0].status, ItemStatus::Removed);
        if matches!(recs[0].target, Target::Path { .. }) {
            assert!(recs[0].quarantine.as_ref().unwrap().exists());
        }
    }
}

#[test]
fn broken_manifest_listed_in_history() {
    let f = Fixture::new();
    let bad = ops_dir(&f).join("op-5");
    fs::create_dir_all(&bad).unwrap();
    fs::write(bad.join("manifest.json"), b"{ not json").unwrap();
    let h = ops::history(&f.env).unwrap();
    assert!(h.iter().any(|e| matches!(e, HistoryEntry::Broken { id, .. } if id == "op-5")), "{h:?}");
}

#[test]
fn export_report_writes_sanitized_file() {
    let f = Fixture::new();
    let op = uninstalled(&f, NOTES);
    ops::apply(&f.env, &op.id, &selectable(&op)).unwrap();
    let path = ops::export_report(&f.env, &op.id).unwrap();
    assert!(paths::is_inside(&path, &f.env.data_dir));
    assert_eq!(path.file_name().unwrap().to_string_lossy(), format!("{}.json", op.id));
    let text = fs::read_to_string(&path).unwrap();
    let v: serde_json::Value = serde_json::from_str(&text).unwrap();
    assert!(v["items"].as_array().unwrap().iter().all(|i| i["regBackup"].is_null()));
    assert!(!text.contains("\"node\""), "registry payloads are stripped");
    assert!(ops::export_report(&f.env, r"..\x").is_err());
}

#[test]
fn history_lists_newest_first() {
    let f = Fixture::new();
    let a = ops::begin(&f.env, NOTES, false).unwrap();
    std::thread::sleep(Duration::from_millis(5));
    let b = ops::begin(&f.env, "HKCU64:SandboxSuite", false).unwrap();
    let h = ops::history(&f.env).unwrap();
    let ids: Vec<&str> = h.iter().filter_map(|e| if let HistoryEntry::Ok { op } = e { Some(op.id.as_str()) } else { None }).collect();
    assert_eq!(ids, [b.id.as_str(), a.id.as_str()]);
}

#[cfg(debug_assertions)]
#[test]
fn debug_guard_refuses_system_env() {
    // Env::system() is only constructed, never used for anything but the refused calls: the guard fires first.
    let env = uni_core::env::Env::system().unwrap();
    let e = ops::begin(&env, "nonexistent", false).unwrap_err();
    assert!(e.0.contains("sandbox"), "{e}");
    let e = ops::apply(&env, "op-1", &[]).unwrap_err();
    assert!(e.0.contains("sandbox"), "{e}");
    let e = ops::restore(&env, "op-1").unwrap_err();
    assert!(e.0.contains("sandbox"), "{e}");
    let e = ops::run_native(&env, "op-1", &opts()).unwrap_err();
    assert!(e.0.contains("sandbox"), "{e}");
}


fn set(key: &RegPath, name: &str, value: &str) {
    registry::set_string(&registry::create(key, winreg::enums::KEY_ALL_ACCESS).unwrap(), name, value, false).unwrap();
}

/// A block that only appears after the scan (another app is installed in between) is enforced at apply.
#[test]
fn apply_recomputes_shared_blocks() {
    let f = Fixture::new();
    let op = uninstalled(&f, NOTES);
    let key_id = plan(&op).candidates.iter().find(|c| c.id.starts_with("key:") && c.id.ends_with(r"sandbox soft\sandbox notes")).expect("settings key offered").id.clone();
    let lnk = desktop(&f.env).join("Sandbox Notes.lnk");
    let lnk_id = id_ending(&op, r"desktop\sandbox notes.lnk");
    let sw = f.env.software_roots[0].child("Sandbox Soft").child("Sandbox Notes");
    // Two programs appear after the scan: one uses the link's target as its icon, one derives the offered Software key.
    let helper = f.env.uninstall_roots[0].child("SandboxHelper");
    set(&helper, "DisplayName", "Sandbox Helper");
    set(&helper, "DisplayIcon", &notes_dir(&f.env).join("Sandbox Notes.exe").to_string_lossy());
    let second = f.env.uninstall_roots[0].child("SandboxNotes2");
    set(&second, "DisplayName", "Sandbox Notes 2");
    set(&second, "Publisher", "Sandbox Soft");
    let applied = ops::apply(&f.env, &op.id, &[key_id.clone(), lnk_id.clone()]).unwrap();
    for id in [&key_id, &lnk_id] {
        let it = applied.items.iter().find(|i| &i.candidate_id == id).unwrap();
        assert_eq!(it.status, ItemStatus::Blocked, "{id}: {:?}", it.detail);
        assert!(it.detail.as_deref().unwrap_or("").starts_with("SharedWithOtherApp"), "{id}: {:?}", it.detail);
    }
    assert!(registry::exists(&sw));
    assert!(lnk.exists());
}

/// Another program's Uninstall entry is never offered, even when a plan names it and the identity matches.
#[test]
fn other_apps_uninstall_entry_is_shared() {
    let f = Fixture::new();
    let op = uninstalled(&f, NOTES);
    let key = f.env.uninstall_roots[0].child("SandboxBroken");
    assert!(registry::exists(&key));
    let mut o = ops::load(&f.env, &op.id).unwrap();
    let p = o.plan.as_mut().unwrap();
    let k = p.candidates.iter().position(|c| c.group == Group::Registry).unwrap();
    p.candidates[k].target = Target::RegKey { key: key.clone() };
    p.candidates[k].id = ops::target_key(&p.candidates[k].target);
    p.candidates[k].ident = Ident::Key { node: registry::capture(&key).unwrap() };
    let id = p.candidates[k].id.clone();
    ops::save(&f.env, &o).unwrap();
    let applied = ops::apply(&f.env, &op.id, &[id]).unwrap();
    let it = &applied.items[0];
    assert_eq!(it.status, ItemStatus::Blocked, "{:?}", it.detail);
    assert!(it.detail.as_deref().unwrap_or("").starts_with("SharedWithOtherApp"), "{:?}", it.detail);
    assert!(registry::exists(&key));
}

fn sz(name: &str, text: &str) -> RegVal {
    RegVal { name: name.into(), kind: 1, data: text.encode_utf16().chain(std::iter::once(0)).flat_map(|c| c.to_le_bytes()).collect() }
}

/// Adds a revert candidate to the stored plan, as a trace would offer it; returns its id.
fn add_revert(f: &Fixture, op: &Operation, key: &RegPath, name: &str, previous: RegVal) -> String {
    let live = registry::read_value(key, name).unwrap();
    let target = Target::RegRevert { key: key.clone(), name: name.into(), previous };
    let id = ops::target_key(&target);
    let mut o = ops::load(&f.env, &op.id).unwrap();
    let c = Candidate { id: id.clone(), group: Group::Revert, target, size: 0, evidence: vec![], blocks: vec![], score: 50, tier: Tier::Review, selected: false, ident: Ident::Value { val: live } };
    o.plan.as_mut().unwrap().candidates.push(c);
    ops::save(&f.env, &o).unwrap();
    id
}

fn record<'a>(op: &'a Operation, id: &str) -> &'a ItemRecord {
    op.items.iter().find(|i| i.candidate_id == id).unwrap_or_else(|| panic!("no item {id}"))
}

#[test]
fn revert_item_apply_and_undo() {
    let f = Fixture::new();
    let op = uninstalled(&f, NOTES);
    let run = f.env.run_roots[0].clone();
    let original = registry::read_value(&run, "SandboxNotes").unwrap();
    let id = add_revert(&f, &op, &run, "SandboxNotes", sz("SandboxNotes", "old"));
    // A shape the product never reverts: another app's Uninstall entry.
    let un = f.env.uninstall_roots[0].child("SandboxSuite");
    let suite_name = registry::read_value(&un, "DisplayName").unwrap();
    let blocked = add_revert(&f, &op, &un, "DisplayName", sz("DisplayName", "x"));

    let applied = ops::apply(&f.env, &op.id, &[blocked.clone(), id.clone()]).unwrap();
    assert_eq!(record(&applied, &id).status, ItemStatus::Reverted, "{:?}", record(&applied, &id).detail);
    assert_eq!(record(&applied, &blocked).status, ItemStatus::Blocked);
    assert!(record(&applied, &blocked).detail.as_deref().unwrap_or("").starts_with("ProtectedRegistry"), "{:?}", record(&applied, &blocked).detail);
    assert_eq!(registry::read_value(&run, "SandboxNotes").unwrap(), sz("SandboxNotes", "old"));
    assert_eq!(registry::read_value(&un, "DisplayName").unwrap(), suite_name, "the blocked value is untouched");
    assert_eq!(applied.status, OpStatus::PartiallyCompleted, "{:?}", applied.status_detail);
    assert_eq!(record(&applied, &id).reg_backup, Some(Ident::Value { val: original.clone() }), "the current value is backed up first");

    // Exports never carry the previous value.
    let report = fs::read_to_string(ops::export_report(&f.env, &op.id).unwrap()).unwrap();
    let v: serde_json::Value = serde_json::from_str(&report).unwrap();
    let items = v["items"].as_array().unwrap().iter().map(|i| &i["target"]);
    let cands = v["plan"]["candidates"].as_array().unwrap().iter().map(|c| &c["target"]);
    let reverts: Vec<&serde_json::Value> = items.chain(cands).filter(|t| t["type"] == "regRevert").collect();
    assert_eq!(reverts.len(), 4, "two items and two candidates");
    assert!(reverts.iter().all(|t| t["previous"]["data"].as_array().unwrap().is_empty()), "{reverts:?}");
    let plan_json = fs::read_to_string(ops::export_plan(&f.env, applied.plan.as_ref().unwrap()).unwrap()).unwrap();
    let pv: serde_json::Value = serde_json::from_str(&plan_json).unwrap();
    let pc: Vec<_> = pv["candidates"].as_array().unwrap().iter().filter(|c| c["target"]["type"] == "regRevert").collect();
    assert_eq!(pc.len(), 2);
    assert!(pc.iter().all(|c| c["target"]["previous"]["data"].as_array().unwrap().is_empty()));

    let restored = ops::restore(&f.env, &op.id).unwrap();
    assert_eq!(record(&restored, &id).restore, Some(RestoreStatus::Restored), "{:?}", record(&restored, &id).restore_detail);
    assert_eq!(registry::read_value(&run, "SandboxNotes").unwrap(), original, "exactly the original value");
    assert_eq!(restored.status, OpStatus::Restored);
}

#[test]
fn revert_of_a_vanished_value_is_changed_not_written() {
    let f = Fixture::new();
    let op = uninstalled(&f, NOTES);
    let run = f.env.run_roots[0].clone();
    let id = add_revert(&f, &op, &run, "SandboxNotes", sz("SandboxNotes", "old"));
    registry::delete_value(&run, "SandboxNotes").unwrap();
    let applied = ops::apply(&f.env, &op.id, std::slice::from_ref(&id)).unwrap();
    let it = record(&applied, &id);
    assert_eq!(it.status, ItemStatus::Changed);
    assert!(it.detail.as_deref().unwrap().contains("no longer exists"), "{:?}", it.detail);
    assert!(registry::read_value(&run, "SandboxNotes").is_err(), "the previous value was not written into a missing value");
    assert_eq!(applied.status, OpStatus::Failed);
}

/// A reverted value, then `disturb`, then restore: the restore must refuse and keep what it finds.
fn reverted_then(disturb: impl Fn(&RegPath)) -> (Fixture, Operation, String) {
    let f = Fixture::new();
    let op = uninstalled(&f, NOTES);
    let run = f.env.run_roots[0].clone();
    let id = add_revert(&f, &op, &run, "SandboxNotes", sz("SandboxNotes", "old"));
    let applied = ops::apply(&f.env, &op.id, std::slice::from_ref(&id)).unwrap();
    assert_eq!(record(&applied, &id).status, ItemStatus::Reverted);
    disturb(&run);
    let restored = ops::restore(&f.env, &op.id).unwrap();
    (f, restored, id)
}

#[test]
fn revert_undo_conflicts() {
    let (f, restored, id) = reverted_then(|run| set(run, "SandboxNotes", "later"));
    assert_eq!(record(&restored, &id).restore, Some(RestoreStatus::Conflict));
    assert_eq!(registry::read_value(&f.env.run_roots[0], "SandboxNotes").unwrap(), sz("SandboxNotes", "later"), "a later change is kept");
    assert_eq!(restored.status, OpStatus::PartiallyRestored);

    let (f, restored, id) = reverted_then(|run| registry::delete_value(run, "SandboxNotes").unwrap());
    assert_eq!(record(&restored, &id).restore, Some(RestoreStatus::Conflict));
    assert!(record(&restored, &id).restore_detail.as_deref().unwrap().contains("not recreated"));
    assert!(registry::read_value(&f.env.run_roots[0], "SandboxNotes").is_err(), "a deleted value is not recreated");
    assert_eq!(restored.status, OpStatus::PartiallyRestored);

    let (f, restored, id) = reverted_then(|run| registry::delete_key(run).unwrap());
    assert_eq!(record(&restored, &id).restore, Some(RestoreStatus::Conflict));
    assert!(!registry::exists(&f.env.run_roots[0]), "a deleted key is not recreated");
    assert_eq!(restored.status, OpStatus::PartiallyRestored);
}

/// A manifest written by 0.1.1 (schema 1, no `trace` anywhere), kept as a template: the old format keeps loading and restoring.
#[test]
fn stage1_manifest_loads_and_restores() {
    let f = Fixture::new();
    let esc = |s: &str| s.replace('\\', "\\\\");
    let root = f.root.to_string_lossy().to_string();
    let text = include_str!("fixtures/manifest-0.1.1.json").replace("{ROOT_LC}", &esc(&root.to_lowercase())).replace("{ROOT}", &esc(&root)).replace("{TAG}", &f.tag);
    let dir = ops_dir(&f).join("op-1");
    fs::create_dir_all(&dir).unwrap();
    fs::write(dir.join("manifest.json"), &text).unwrap();
    let v: serde_json::Value = serde_json::from_str(&text).unwrap();
    assert_eq!(v["schema"], 1);
    assert!(!text.contains("\"trace\""), "no trace field in the old format");
    let items = v["items"].as_array().unwrap();
    let cfg = items.iter().find(|i| i["candidateId"].as_str().unwrap().ends_with("config.ini")).unwrap();
    let run_item = items.iter().find(|i| i["candidateId"].as_str().unwrap().contains("run|sandboxnotes")).unwrap();
    // The state after that apply: config.ini in quarantine, the Run value gone.
    let q = PathBuf::from(cfg["quarantine"].as_str().unwrap());
    fs::create_dir_all(q.parent().unwrap()).unwrap();
    fs::rename(notes_dir(&f.env).join("config.ini"), &q).unwrap();
    let run = f.env.run_roots[0].clone();
    registry::delete_value(&run, "SandboxNotes").unwrap();

    let op = ops::load(&f.env, "op-1").unwrap();
    assert_eq!(op.schema, 1);
    assert!(op.plan.as_ref().unwrap().trace.is_none());
    assert!(op.app.hidden.is_none(), "the old format has no hidden mark");
    assert!(matches!(&ops::history(&f.env).unwrap()[0], HistoryEntry::Ok { op } if op.id == "op-1"));
    let restored = ops::restore(&f.env, "op-1").unwrap();
    assert_eq!(restored.status, OpStatus::Restored, "{:#?}", restored.items.iter().map(|i| (&i.candidate_id, i.restore, &i.restore_detail)).collect::<Vec<_>>());
    assert_eq!(fs::read(notes_dir(&f.env).join("config.ini")).unwrap(), b"[x]\n");
    let bytes: Vec<u8> = run_item["regBackup"]["val"]["data"].as_array().unwrap().iter().map(|b| b.as_u64().unwrap() as u8).collect();
    assert_eq!(registry::read_value(&run, "SandboxNotes").unwrap().data, bytes, "the Run value is exactly the backed-up one");
}

#[test]
fn newer_manifest_schema_is_refused() {
    let f = Fixture::new();
    let op = ops::begin(&f.env, NOTES, false).unwrap();
    let mut o = ops::load(&f.env, &op.id).unwrap();
    o.schema = SCHEMA + 1;
    ops::save(&f.env, &o).unwrap();
    let e = ops::load(&f.env, &op.id).unwrap_err();
    assert!(e.0.contains("newer version"), "{e}");
    assert!(matches!(&ops::history(&f.env).unwrap()[0], HistoryEntry::Broken { .. }), "listed as Broken, not hidden");
}

fn set_dword(key: &RegPath, name: &str, value: u32) {
    registry::set_dword(&registry::create(key, winreg::enums::KEY_ALL_ACCESS).unwrap(), name, value).unwrap();
}

/// What a plan says about each candidate, with the fixture's own root and tag masked, so two fixtures can be compared.
fn shape(f: &Fixture, op: &Operation) -> Vec<(String, Tier, i32, bool, Vec<String>)> {
    let root = paths::norm(&f.root);
    let mut v: Vec<_> = plan(op)
        .candidates
        .iter()
        .map(|c| {
            let mut b: Vec<String> = c.blocks.iter().map(|b| format!("{:?}", b.code)).collect();
            b.sort();
            (c.id.replace(&root, "<root>").replace(&f.tag, "<tag>"), c.tier, c.score, c.selected, b)
        })
        .collect();
    v.sort_by(|a, b| a.0.cmp(&b.0));
    v
}

/// A hidden entry is uninstalled only with the explicit confirmation, and then it is the normal flow.
#[test]
fn hidden_program_roundtrip() {
    let f = Fixture::new();
    for root in &f.env.uninstall_roots[..2] {
        set_dword(&root.child("SandboxNotes"), "SystemComponent", 1);
    }
    let e = ops::begin(&f.env, NOTES, false).unwrap_err();
    assert!(e.0.contains("hidden"), "{e}");
    assert!(ops::history(&f.env).unwrap().is_empty(), "a refused begin leaves no record");

    let op = ops::begin(&f.env, NOTES, true).unwrap();
    assert_eq!(op.app.hidden, Some(HiddenReason::SystemComponent));
    let op = ops::run_native(&f.env, &op.id, &opts()).unwrap();
    let op = ops::scan_leftovers(&f.env, &op.id).unwrap();
    assert_eq!(op.entry_after, Some(EntryState::Gone));
    let ids = selectable(&op);
    assert!(ids.len() >= 10, "{ids:?}");

    let before = tree(&f);
    let applied = ops::apply(&f.env, &op.id, &ids).unwrap();
    assert_eq!(applied.status, OpStatus::Completed, "{:?}", applied.status_detail);
    assert!(!applied.verify.as_ref().unwrap().app_still_listed);
    assert_eq!(ops::load(&f.env, &op.id).unwrap().app.hidden, Some(HiddenReason::SystemComponent));
    let restored = ops::restore(&f.env, &op.id).unwrap();
    assert_eq!(restored.status, OpStatus::Restored);
    assert!(tree(&f) == before, "restore brings back exactly what was removed");

    let g = Fixture::new();
    let visible = uninstalled(&g, NOTES);
    assert_eq!(shape(&f, &op), shape(&g, &visible), "a hidden program gets the same plan as a visible one");
}
