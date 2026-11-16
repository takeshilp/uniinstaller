//! Read-only checks against the real machine. Run with:
//! `cargo test -p uni-core --test real_system -- --ignored --nocapture`
use uni_core::env::Env;
use uni_core::inventory::list_apps;
use uni_core::model::Tier;
use uni_core::ops;

#[test]
#[ignore = "reads the real registry and file system"]
fn real_system_list_and_preview() {
    let env = Env::system().unwrap();
    let apps = list_apps(&env).unwrap();
    assert!(!apps.is_empty());
    println!("{} programs", apps.len());
    for a in apps.iter().take(5) {
        let plan = ops::preview(&env, &a.id).unwrap();
        let selected = plan.candidates.iter().filter(|c| c.selected).count();
        assert!(plan.candidates.iter().all(|c| !(c.selected && c.tier != Tier::Safe)));
        println!("{}: {} candidates, {} selected", a.display_name, plan.candidates.len(), selected);
    }
}
