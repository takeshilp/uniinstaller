//! Read-only checks against the real machine. Run with:
//! `cargo test -p uni-core --test real_system -- --ignored --nocapture`
use std::collections::HashMap;
use std::path::PathBuf;
use std::time::Instant;
use uni_core::env::Env;
use uni_core::icon;
use uni_core::inventory::list_apps;
use uni_core::model::Tier;
use uni_core::ops;

#[test]
#[ignore = "reads the real registry and file system"]
fn real_system_list_and_preview() {
    let env = Env::system().unwrap();
    let apps = list_apps(&env, false).unwrap();
    assert!(!apps.is_empty());
    let hidden = list_apps(&env, true).unwrap().len() - apps.len();
    println!("{} programs, {hidden} hidden", apps.len());
    for a in apps.iter().take(5) {
        let plan = ops::preview(&env, &a.id).unwrap();
        let selected = plan.candidates.iter().filter(|c| c.selected).count();
        assert!(plan.candidates.iter().all(|c| !(c.selected && c.tier != Tier::Safe)));
        println!("{}: {} candidates, {} selected", a.display_name, plan.candidates.len(), selected);
    }
}

/// Read-only: writes the dry run of every listed program to the file named by `UNI_PREVIEW_DUMP`, one line per candidate (tier, score,
/// preselection, blocks) plus one for the install folder. Diff two dumps to see what a rule change does to real data:
/// `UNI_PREVIEW_HIDDEN=1` adds the hidden entries.
/// `UNI_PREVIEW_DUMP=<file> cargo test -p uni-core --test real_system real_system_preview_dump -- --ignored --nocapture`.
#[test]
#[ignore = "reads the real registry and file system"]
fn real_system_preview_dump() {
    let Some(out) = std::env::var_os("UNI_PREVIEW_DUMP") else {
        println!("UNI_PREVIEW_DUMP is not set: skipped");
        return;
    };
    let env = Env::system().unwrap();
    let t = std::time::Instant::now();
    let apps = list_apps(&env, std::env::var_os("UNI_PREVIEW_HIDDEN").is_some()).unwrap();
    let mut lines = Vec::new();
    for a in &apps {
        match ops::preview(&env, &a.id) {
            Err(e) => lines.push(format!("{}\tERROR\t{e}", a.id)),
            Ok(p) => {
                lines.push(format!("{}\tDIR\t{:?}", a.id, p.install_dir_status));
                for c in &p.candidates {
                    let mut b: Vec<String> = c.blocks.iter().map(|b| format!("{:?}: {}", b.code, b.detail)).collect();
                    b.sort();
                    lines.push(format!("{}\t{}\t{:?}\t{}\t{}\t{}", a.id, c.id, c.tier, c.score, c.selected, b.join(" | ")));
                }
            }
        }
    }
    std::fs::write(&out, lines.join("\n") + "\n").unwrap();
    println!("{} programs, {} lines, {} ms", apps.len(), lines.len(), t.elapsed().as_millis());
}

/// Read-only: two captures of the real machine (the second streamed through a `Differ`, as `trace::finish` does). Prints the
/// object counts, the milliseconds and the peak working-set growth that the budget in `docs/tracing.md` is measured by.
/// Run it alone: `cargo test -p uni-core --test real_system real_system_snapshot_cost -- --ignored --nocapture`.
#[test]
#[ignore = "reads the real registry and file system"]
fn real_system_snapshot_cost() {
    use uni_core::trace::{self, Differ};
    use windows::Win32::System::ProcessStatus::{GetProcessMemoryInfo, PROCESS_MEMORY_COUNTERS};
    use windows::Win32::System::Threading::GetCurrentProcess;
    let working_set = || {
        let mut c = PROCESS_MEMORY_COUNTERS { cb: std::mem::size_of::<PROCESS_MEMORY_COUNTERS>() as u32, ..Default::default() };
        // SAFETY: the pseudo handle is always valid and `c` is sized by `cb`.
        unsafe { GetProcessMemoryInfo(GetCurrentProcess(), &mut c, c.cb).unwrap() };
        (c.WorkingSetSize, c.PeakWorkingSetSize)
    };
    let env = Env::system().unwrap();
    let (base, _) = working_set();
    let before = trace::capture(&env).unwrap();
    let (held, peak1) = working_set();
    println!("before: {} objects ({} files and folders, {} registry), {} unreadable, {} ms", before.objects, before.paths.len(), before.reg.len(), before.unreadable.len(), before.ms);
    println!("before: working set +{} MB held, peak +{} MB", (held.saturating_sub(base)) >> 20, (peak1.saturating_sub(base)) >> 20);
    for u in before.unreadable.iter().take(10) {
        println!("  unreadable: {u}");
    }
    let objects = before.objects as usize;
    let mut d = Differ::new(before);
    let cap = trace::capture_with(&env, &mut |id, t, p, _| d.visit(id, t, p)).unwrap();
    let (_, peak2) = working_set();
    let roots: Vec<std::path::PathBuf> = env.folders.zone_roots().cloned().collect();
    let (changes, unreadable) = d.finish(&cap.unreadable, &roots);
    println!("after (streamed): {} objects, {} unreadable, {} ms", cap.objects, cap.unreadable.len(), cap.ms);
    println!("both captures: peak working set +{} MB over the start", (peak2.saturating_sub(base)) >> 20);
    println!("changes between the two captures: {} ({} noise), unreadable union {}", changes.len(), changes.iter().filter(|c| c.noise).count(), unreadable.len());
    for c in changes.iter().take(10) {
        println!("  {:?} {}", c.change, c.id);
    }
    assert!(objects < trace::MAX_OBJECTS);
}

/// Read-only: runs `force::check` (and, for an Ok result, the dry-run scan of the forced target) for each path in `UNI_FORCE_PATHS`
/// (`;`-separated, `%VAR%` expanded) and prints the verdicts. Nothing is run: version info is read as data. Asserts that no forced
/// candidate is preselected. `UNI_FORCE_PATHS=<paths> cargo test -p uni-core --test real_system real_system_force_probe -- --ignored --nocapture`.
#[test]
#[ignore = "reads the real registry and file system"]
fn real_system_force_probe() {
    use std::collections::BTreeMap;
    use uni_core::model::{ForceCheck, Tier};
    let Some(list) = std::env::var_os("UNI_FORCE_PATHS") else {
        println!("UNI_FORCE_PATHS is not set: skipped");
        return;
    };
    let env = Env::system().unwrap();
    for raw in list.to_string_lossy().split(';').filter(|p| !p.trim().is_empty()) {
        let path = std::path::PathBuf::from(uni_core::registry::expand_env(raw.trim()));
        let t = std::time::Instant::now();
        let verdict = uni_core::force::check(&env, &path);
        let ms = t.elapsed().as_millis();
        match verdict {
            Err(e) => println!("{}\tERROR\t{e}\t{ms} ms", path.display()),
            Ok(ForceCheck::Refused { code, detail }) => println!("{}\tREFUSED {code:?}\t{detail}\t{ms} ms", path.display()),
            Ok(ForceCheck::Listed { app, how }) => println!("{}\tLISTED {how:?}\t{} ({})\t{ms} ms", path.display(), app.display_name, app.id),
            Ok(ForceCheck::Ok { found }) => {
                let others = list_apps(&env, true).unwrap();
                let app = uni_core::force::app_for(&found.forced, &found.name, found.publisher.as_deref(), found.file_version.as_deref());
                let plan = uni_core::scan::scan(&env, &app, None, &others, true, None, Some(&found.forced)).unwrap();
                let mut tiers: BTreeMap<String, usize> = BTreeMap::new();
                let mut blocks: BTreeMap<String, usize> = BTreeMap::new();
                for c in &plan.candidates {
                    *tiers.entry(format!("{:?}", c.tier)).or_default() += 1;
                    for b in &c.blocks {
                        *blocks.entry(format!("{:?}", b.code)).or_default() += 1;
                    }
                    assert!(!c.selected, "a forced candidate is preselected: {}", c.id);
                    assert!(c.tier != Tier::Safe, "a forced candidate is Safe: {}", c.id);
                }
                println!(
                    "{}\tOK\tfolder={:?} name={:?} publisher={:?} version={:?} search_names={:?} uninstallers={} shortcuts={} other_volume={} outside_zones={} | dir={:?} candidates={} tiers={tiers:?} blocks={blocks:?} | {ms} ms",
                    path.display(),
                    found.forced.folder,
                    found.name,
                    found.publisher,
                    found.file_version,
                    found.forced.search_names,
                    found.uninstallers.len(),
                    found.shortcuts.len(),
                    found.other_volume,
                    found.outside_zones,
                    plan.install_dir_status,
                    plan.candidates.len(),
                );
            }
        }
    }
}

/// Read-only: extracts the icon of every listed program (hidden ones too) with the GUI's per-file cache, and prints the programs that
/// have a DisplayIcon but got none. Budget: all programs in at most 3 s on one thread (the GUI asks 4 at a time after the list is shown).
/// `cargo test -p uni-core --test real_system real_system_icons -- --ignored --nocapture`.
#[test]
#[ignore = "reads the real registry and file system"]
fn real_system_icons() {
    let env = Env::system().unwrap();
    let apps = list_apps(&env, true).unwrap();
    let mut cache: HashMap<(PathBuf, i32), Option<Vec<u8>>> = HashMap::new();
    let (mut hits, mut vhits) = (0, 0);
    let t = Instant::now();
    for a in &apps {
        let src = icon::source(a, &env);
        let got = src.as_ref().and_then(|s| cache.entry(s.clone()).or_insert_with(|| icon::extract(&s.0, s.1)).clone());
        if got.is_some() {
            hits += 1;
            vhits += usize::from(a.hidden.is_none());
        } else if let Some(d) = &a.display_icon {
            println!("letter: {} ({d} -> {:?})", a.display_name, src.map(|s| s.0));
        }
    }
    let ms = t.elapsed().as_millis();
    let visible = apps.iter().filter(|a| a.hidden.is_none()).count();
    println!(
        "{} programs ({visible} visible): {hits} icons ({vhits} visible), {} letters, {} distinct sources, {ms} ms",
        apps.len(),
        apps.len() - hits,
        cache.len()
    );
    assert!(hits > 0);
}
