//! Safety rules: protected paths, registry shapes, hard blocks, tiers. Single source of truth;
//! `docs/architecture.md` mirrors these tables. Pure functions, no side effects.
use crate::env::{Env, Folders};
use crate::model::*;
use crate::paths::{canonical, is_canonical, is_drive_root, is_inside, is_local_abs, norm, same_or_inside};
use crate::registry;
use std::path::{Path, PathBuf};
use std::sync::OnceLock;

// shortcut: weights, thresholds and the two lists below are not calibrated because there is no VM lab,
// recalibrate when the lab exists.
pub const DOC_EXT: &[&str] = &[
    "doc", "docx", "xls", "xlsx", "ppt", "pptx", "pdf", "odt", "ods", "odp", "rtf", "psd", "kra", "blend", "sav", "mp4", "mkv", "mov", "mp3",
    "flac", "wav",
];
// shortcut: user-data heuristic is extension and folder-name lists; a trace cannot tell user data from program data, add stage-3 adapters.
pub const DATA_DIR_NAMES: &[&str] = &[
    "saves", "savegames", "save", "projects", "documents", "backups", "backup", "profiles", "user data", "userdata", "screenshots", "mods",
    "worlds", "recordings",
];
/// First registry components under a software root that are never offered.
pub const RESERVED_SOFTWARE: &[&str] = &["microsoft", "classes", "policies", "wow6432node", "clients", "registeredapplications"];

pub const W_IN_INSTALL_DIR: i32 = 45;
pub const W_CORROBORATED: i32 = 35;
pub const W_REFERS: i32 = 30;
pub const W_TARGET_MISSING: i32 = 15;
pub const W_OWN_ENTRY: i32 = 60;
pub const W_EXACT_ANCHOR: i32 = 60;
pub const W_EXACT_NAME: i32 = 20;
pub const W_PUBLISHER: i32 = 10;
pub const W_USER_DATA: i32 = -50;
pub const W_OUTSIDE_ZONES: i32 = -20;
/// Created by a traced install, near the program's folder or backed by other evidence (calibration, not measured).
pub const W_TRACE_CREATED: i32 = 100;
/// Created by a traced install, away from the program's folder: Review, never preselected.
pub const W_TRACE_FAR: i32 = 50;
/// A revert candidate: the trace recorded the value before the install.
pub const W_TRACE_MODIFIED: i32 = 50;
pub const SAFE_AT: i32 = 80;
pub const REVIEW_AT: i32 = 40;

pub fn tier(score: i32, has_blocks: bool) -> Tier {
    if has_blocks {
        Tier::Blocked
    } else if score >= SAFE_AT {
        Tier::Safe
    } else if score >= REVIEW_AT {
        Tier::Review
    } else {
        Tier::Weak
    }
}

/// The settings and user-data group, previous-value reverts and anything that looks like user data are never preselected.
// shortcut: install-dir leftovers are never preselected unless a trace journal confirms them (they score at most Review otherwise),
// the user ticks them.
pub fn default_selected(tier: Tier, group: Group, user_data: bool) -> bool {
    tier == Tier::Safe && !matches!(group, Group::Data | Group::Revert) && !user_data
}

/// Folders of the real system, canonicalized, computed once. An `Err` makes every path `Unverifiable`.
pub fn real_folders() -> &'static Result<Folders, String> {
    static REAL: OnceLock<Result<Folders, String>> = OnceLock::new();
    REAL.get_or_init(|| {
        let local = std::env::var_os("LOCALAPPDATA").map(PathBuf::from).ok_or("LOCALAPPDATA is not set")?;
        Folders::system(&local.join("uniinstaller-data")).map_err(|e| e.0)
    })
}

/// Why `path` is protected under `f`, if it is. Pure.
/// `lnk_exception`: a Shortcuts-group `.lnk` file directly on a desktop or inside a Start Menu is exempt from the tree rule.
pub fn protected_reason(f: &Folders, path: &Path, group: Group) -> Option<String> {
    if !is_local_abs(path) {
        return Some("not a local absolute path".into());
    }
    if is_drive_root(path) {
        return Some("drive root".into());
    }
    for r in &f.protected_roots {
        if same_or_inside(r, path) {
            return Some(format!("equals or contains protected root {}", r.display()));
        }
    }
    let is_lnk = path.extension().is_some_and(|e| e.eq_ignore_ascii_case("lnk"));
    let lnk_exception = group == Group::Shortcuts
        && is_lnk
        && path.parent().is_some_and(|p| {
            f.desktops.iter().any(|d| norm(d) == norm(p)) || f.start_menu.iter().any(|s| same_or_inside(p, s))
        });
    if lnk_exception {
        return None;
    }
    for t in &f.protected_trees {
        if same_or_inside(t, path) || is_inside(path, t) {
            return Some(format!("inside or around protected tree {}", t.display()));
        }
    }
    None
}

/// What other installed apps own: install dirs, uninstaller exes and icons (canonical where they exist), plus their existing
/// settings folders and Software keys named by the scan's own rule (`scan::name_pairs`), plus derived install dirs.
#[derive(Debug, Default, Clone)]
pub struct Anchors {
    pub dirs: Vec<PathBuf>,
    pub files: Vec<PathBuf>,
    /// Existing `<AppData root>\[<publisher>\]<name>` folders of other apps, every name variant.
    pub data_dirs: Vec<PathBuf>,
    /// Existing `<Software root>\[<publisher>\]<name>` keys of other apps, every name variant, plus the Uninstall entries
    /// (`sources`) of every other listed app.
    pub keys: Vec<RegPath>,
    /// Install dirs derived for other apps that have no InstallLocation (uninstaller and icon share a folder, as `find_anchor`
    /// does for the target). Used only by `referenced_in`: as path anchors they would block the files of apps such as Steam.
    pub derived_dirs: Vec<PathBuf>,
}

impl Anchors {
    /// Why `path` (or a target it references) touches another app, if it does.
    pub fn covering(&self, path: &Path, own_dir: Option<&Path>) -> Option<String> {
        for a in self.dirs.iter().chain(&self.files) {
            if same_or_inside(a, path) {
                return Some(format!("contains another app's files: {}", a.display()));
            }
        }
        if let Some(a) = self.data_dirs.iter().find(|a| same_or_inside(a, path)) {
            return Some(format!("holds another app's settings folder {}", a.display()));
        }
        for d in &self.dirs {
            let ours_inside = own_dir.is_some_and(|o| same_or_inside(o, d));
            if is_inside(path, d) && !ours_inside {
                return Some(format!("inside another app's install dir {}", d.display()));
            }
        }
        None
    }

    /// Why a registry key is or holds another app's settings key, if it does (same hive and view).
    // shortcut: `RegPath::same` compares ASCII-case-insensitively while `below` lowercases Unicode, so two non-ASCII names that
    // differ only in case are not seen as equal; compare lowercased paths if such a vendor name shows up.
    pub fn key_holding(&self, key: &RegPath) -> Option<String> {
        self.keys.iter().find(|k| k.same(key) || k.below(key).is_some()).map(|k| format!("holds another app's settings key {}", k.display()))
    }

    /// Why a registry key is, or lies inside, another app's key (settings key or Uninstall entry), if it does (same hive and view).
    pub fn key_inside(&self, key: &RegPath) -> Option<String> {
        self.keys.iter().find(|k| k.same(key) || key.below(k).is_some()).map(|k| format!("inside another app's key {}", k.display()))
    }

    /// Why registry text (one path per line or `;` item) equals or points into another app's install dir, if it does.
    /// A drive root or a protected root is never an app's own folder here (it would claim every value that names any path under it);
    /// the path rule `covering` keeps blocking such folders.
    // shortcut: references are matched as normalized text, so 8.3 and other alias spellings of another app's folder are missed,
    // and so is a folder reached through a junction or SUBST (anchors are canonical, registry text is not); comma-separated lists,
    // a folder followed by arguments without a trailing backslash (`C:\PF\Plugin /S`) and unexpanded REG_MULTI_SZ items are missed
    // too; resolve each path-like token and keep the raw InstallLocation if a lab run or a user report shows one slipping through.
    pub fn referenced_in(&self, f: &Folders, text: &str, own_dir: Option<&Path>) -> Option<String> {
        // As in `covering`: an app whose dir holds ours (a host and its plugin) does not claim what we reference.
        let theirs: Vec<(&PathBuf, String)> = self
            .dirs
            .iter()
            .chain(&self.derived_dirs)
            .filter(|d| !own_dir.is_some_and(|o| same_or_inside(o, d)) && !is_drive_root(d) && !f.protected_roots.iter().any(|r| same_or_inside(r, d)))
            .map(|d| (d, format!("{}\\", norm(d).trim_end_matches('\\'))))
            .collect();
        let low = text.replace('/', "\\").to_lowercase();
        low.split(['\n', ';']).find_map(|part| {
            let bare = Path::new(part.trim().trim_matches('"'));
            theirs
                .iter()
                .find(|(d, needle)| same_or_inside(bare, d) || part.contains(needle.as_str()))
                .map(|(d, _)| format!("points into another app's install dir {}", d.display()))
        })
    }
}

/// Whether registry text (one path per line or `;` item) equals or points into `dir`. Used to attribute a changed value to a program.
pub fn text_refers_to(text: &str, dir: &Path) -> bool {
    let needle = format!("{}\\", norm(dir).trim_end_matches('\\'));
    text.replace('/', "\\").to_lowercase().split(['\n', ';']).any(|part| same_or_inside(Path::new(part.trim().trim_matches('"')), dir) || part.contains(&needle))
}

/// Hard blocks that depend only on the path itself and the environment.
pub fn path_blocks(env: &Env, path: &Path, group: Group, install_dir: Option<&Path>, anchors: &Anchors) -> Vec<Block> {
    let mut out = Vec::new();
    let mut add = |code, detail: String| out.push(Block { code, detail });
    match real_folders() {
        Err(e) => add(BlockCode::Unverifiable, format!("real system folders unavailable: {e}")),
        Ok(real) => {
            if let Some(why) = protected_reason(real, path, group) {
                add(BlockCode::ProtectedPath, why);
            }
        }
    }
    if let Some(why) = protected_reason(&env.folders, path, group) {
        add(BlockCode::ProtectedPath, why);
    }
    let in_zone = env.folders.zone_roots().any(|z| is_inside(path, z)) || install_dir.is_some_and(|d| is_inside(path, d));
    if !in_zone {
        add(BlockCode::OutsideAllowedZone, "not inside a known zone or the install dir".into());
    }
    if !path.parent().is_some_and(is_canonical) {
        add(BlockCode::NonCanonicalPath, "parent folder is an alias, short name or not canonical".into());
    }
    if let Some(why) = anchors.covering(path, install_dir) {
        add(BlockCode::SharedWithOtherApp, why);
    }
    out
}

/// Registry shapes the product may touch; anything else is blocked.
pub fn registry_blocks(env: &Env, target: &Target) -> Vec<Block> {
    let block = |code, d: &str| vec![Block { code, detail: d.to_string() }];
    match target {
        Target::Path { .. } => block(BlockCode::OutsideAllowedZone, "not a registry target"),
        Target::RegKey { key } => {
            for r in env.uninstall_roots.iter().chain(&env.app_paths_roots) {
                if let Some(c) = key.below(r) {
                    return if c.len() == 1 { vec![] } else { block(BlockCode::ProtectedRegistry, "must be exactly one level below Uninstall or App Paths") };
                }
            }
            for r in &env.software_roots {
                if let Some(c) = key.below(r) {
                    if c.len() > 2 {
                        return block(BlockCode::ProtectedRegistry, "deeper than two levels below Software");
                    }
                    if RESERVED_SOFTWARE.contains(&c[0].as_str()) {
                        return block(BlockCode::ProtectedRegistry, "reserved vendor key");
                    }
                    return vec![];
                }
            }
            let is_root = env
                .uninstall_roots
                .iter()
                .chain(&env.app_paths_roots)
                .chain(&env.software_roots)
                .chain(&env.run_roots)
                .any(|r| key.same(r));
            if is_root {
                block(BlockCode::ProtectedRegistry, "a whole root key is never touched")
            } else {
                block(BlockCode::OutsideAllowedZone, "registry key outside the allowed shapes")
            }
        }
        // shortcut: previous values are restored only in Run, App Paths and vendor keys; Classes (file associations), Services and Uninstall values
        // are report-only, add per-adapter rules in stage 3.
        Target::RegRevert { key, name, previous } => {
            if registry::to_regtype(previous.kind).is_none() {
                return block(BlockCode::Unverifiable, "the previous value has an unknown type");
            }
            let run = !name.is_empty() && env.run_roots.iter().any(|r| key.same(r));
            let app_paths = name.is_empty() && env.app_paths_roots.iter().any(|r| key.below(r).is_some_and(|c| c.len() == 1));
            let vendor = env.software_roots.iter().any(|r| key.below(r).is_some_and(|c| !RESERVED_SOFTWARE.contains(&c[0].as_str())));
            if run || app_paths || vendor {
                vec![]
            } else {
                block(BlockCode::ProtectedRegistry, "previous values are restored only in Run, App Paths and vendor keys")
            }
        }
        Target::RegValue { key, name } => {
            if !name.is_empty() && env.run_roots.iter().any(|r| key.same(r)) {
                vec![]
            } else {
                block(BlockCode::ProtectedRegistry, "only named values directly inside a Run key are allowed")
            }
        }
    }
}

/// The zone root (or install dir) that contains `path`, used to stop empty-folder cleanup.
pub fn zone_root_of(env: &Env, install_dir: Option<&Path>, path: &Path) -> Option<PathBuf> {
    env.folders.zone_roots().find(|z| is_inside(path, z)).cloned().or_else(|| install_dir.filter(|d| is_inside(path, d)).map(Path::to_path_buf))
}

/// Canonical form when the path exists, otherwise unchanged.
pub fn canon_if_exists(p: &Path) -> PathBuf {
    if p.exists() { canonical(p).unwrap_or_else(|_| p.to_path_buf()) } else { p.to_path_buf() }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fake() -> Folders {
        let p = |s: &str| PathBuf::from(s);
        Folders {
            program_files: vec![p(r"C:\Program Files")],
            app_data: vec![p(r"C:\Users\me\AppData\Roaming"), p(r"C:\ProgramData")],
            start_menu: vec![p(r"C:\Users\me\AppData\Roaming\Microsoft\Windows\Start Menu\Programs"), p(r"C:\ProgramData\Microsoft\Windows\Start Menu\Programs")],
            desktops: vec![p(r"C:\Users\me\Desktop")],
            protected_roots: vec![p(r"C:\Users"), p(r"C:\Users\me"), p(r"C:\Users\Other"), p(r"C:\Program Files"), p(r"C:\Temp"), p(r"C:\ProgramData")],
            protected_trees: vec![
                p(r"C:\Windows"),
                p(r"C:\Users\me\Documents"),
                p(r"C:\Users\me\Desktop"),
                p(r"C:\Users\me\OneDrive"),
                p(r"C:\ProgramData\Microsoft"),
                p(r"C:\Users\me\AppData\Roaming\Microsoft"),
            ],
            windows_dir: p(r"C:\Windows"),
            system_dir: p(r"C:\Windows\System32"),
        }
    }

    #[test]
    fn anchors_settings_rules() {
        let k = |v: View, s: &str| RegPath::new(Hive::Hklm, v, s);
        let a = Anchors { data_dirs: vec![PathBuf::from(r"C:\R\Vendor\Editor")], keys: vec![k(View::V64, r"SOFTWARE\Vendor\Editor")], ..Default::default() };
        let c = |s: &str| a.covering(Path::new(s), None).is_some();
        assert!(c(r"C:\R\Vendor\Editor"), "equal");
        assert!(c(r"C:\R\Vendor"), "a vendor folder holding another product");
        assert!(!c(r"C:\R\Vendor\Editor 1"), "sibling");
        assert!(!c(r"C:\R\Vendor\Editor\sub"), "a product folder inside a folder named after another app stays offered");
        assert!(a.key_holding(&k(View::V64, r"software\vendor\editor")).is_some(), "equal, any case");
        assert!(a.key_holding(&k(View::V64, r"SOFTWARE\Vendor")).is_some(), "a vendor key holding another product");
        assert!(a.key_holding(&k(View::V64, r"SOFTWARE\Vendor\Editor 1")).is_none());
        assert!(a.key_holding(&k(View::V64, r"SOFTWARE\Vendor\Editor\Sub")).is_none());
        assert!(a.key_holding(&k(View::V32, r"SOFTWARE\Vendor\Editor")).is_none(), "the other view is another key");
    }

    #[test]
    fn anchors_reference_rule() {
        let p = PathBuf::from;
        let f = fake();
        let a = Anchors { dirs: vec![p(r"C:\PF\Suite\Plugin"), p(r"C:\PF\Host"), p(r"C:\")], derived_dirs: vec![p(r"C:\PF\Bare")], ..Default::default() };
        let suite = Some(Path::new(r"C:\PF\Suite"));
        let r = |t: &str, own: Option<&Path>| a.referenced_in(&f, t, own).is_some();
        assert!(r(r#""C:\PF\Suite\Plugin\p.exe" /tray"#, suite), "command line into a nested app");
        assert!(r("c:/pf/suite/PLUGIN", suite), "equal, slashes and case");
        assert!(r("C:\\X\nC:\\PF\\Host\\h.dll", suite), "second line of a multi-string");
        assert!(r(r"C:\X;C:\PF\Host", suite), "path list");
        assert!(r(r"C:\PF\Bare\b.exe", suite), "a derived dir of an app without InstallLocation");
        assert!(!r(r"C:\PF\Suite\suite.exe", suite), "our file; a drive root is never an app's folder");
        assert!(!r(r"C:\X\y.exe", None), "a drive-root anchor claims nothing, even without a dir of our own");
        assert!(!r(r"C:\PF\Suite", suite), "our dir, although it holds the plugin");
        assert!(!r(r"C:\PF\Suite\Plugin2\x.exe", suite), "a name prefix is not containment");
        assert!(!r(r"C:\PF\Host\Ext\e.exe", Some(Path::new(r"C:\PF\Host\Ext"))), "a host does not claim its plugin's files");
        assert!(r(r"C:\PF\Suite\Plugin\p.exe", None), "no confirmed dir of our own: fail closed");
        let broad = Anchors { dirs: vec![p(r"C:\Program Files"), p(r"C:\Users")], ..Default::default() };
        assert!(broad.referenced_in(&f, r"C:\Program Files\V\x.exe", None).is_none(), "a protected root is never an app's folder");
        assert!(broad.referenced_in(&f, r"C:\Users\me\x.exe", None).is_none(), "nor an ancestor of one");
    }

    #[test]
    fn tiers_thresholds_and_block_overrides_any_score() {
        assert_eq!(tier(80, false), Tier::Safe);
        assert_eq!(tier(79, false), Tier::Review);
        assert_eq!(tier(40, false), Tier::Review);
        assert_eq!(tier(39, false), Tier::Weak);
        assert_eq!(tier(-5, false), Tier::Weak);
        assert_eq!(tier(200, true), Tier::Blocked);
    }

    #[test]
    fn data_group_never_preselected() {
        assert!(default_selected(Tier::Safe, Group::Shortcuts, false));
        assert!(default_selected(Tier::Safe, Group::Registry, false));
        assert!(!default_selected(Tier::Safe, Group::Data, false));
        assert!(!default_selected(Tier::Review, Group::Shortcuts, false));
        assert!(!default_selected(Tier::Blocked, Group::Registry, false));
        // Anything that looks like user data is never preselected, whatever its score, and a revert never is.
        assert!(!default_selected(Tier::Safe, Group::ProgramFiles, true));
        assert!(!default_selected(Tier::Safe, Group::Shortcuts, true));
        assert!(!default_selected(Tier::Safe, Group::Revert, false));
    }

    #[test]
    fn text_refers_to_rule() {
        let d = Path::new(r"C:\PF\Lab Trace");
        let r = |t: &str| text_refers_to(t, d);
        assert!(r(r#""C:\PF\Lab Trace\app.exe" /tray"#), "a command line");
        assert!(r(r"C:\PF\Lab Trace\app.exe /tray"), "an unquoted command line");
        assert!(r(r"C:\X;C:\PF\Lab Trace\bin"), "a list");
        assert!(r("C:\\X\nC:\\PF\\Lab Trace"), "a multi-line string, a bare folder");
        assert!(r("c:/pf/LAB TRACE/app.exe"), "slashes and case");
        assert!(!r(r"C:\PF\Lab Trace2\app.exe"), "a lookalike name prefix");
        assert!(!r(r"C:\PF\Lab Tracer"), "a lookalike bare name");
        assert!(!r(r"C:\old\app.exe"));
        assert!(!r(""));
    }

    #[test]
    fn key_inside_rule() {
        let k = |v: View, s: &str| RegPath::new(Hive::Hklm, v, s);
        let a = Anchors { keys: vec![k(View::V64, r"SOFTWARE\Vendor\Editor"), k(View::V64, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\Other")], ..Default::default() };
        let inside = |x: RegPath| a.key_inside(&x).is_some();
        assert!(inside(k(View::V64, r"software\vendor\editor")), "equal, any case");
        assert!(inside(k(View::V64, r"SOFTWARE\Vendor\Editor\Sub\Deep")), "inside");
        assert!(inside(k(View::V64, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\Other")), "another app's Uninstall entry");
        assert!(!inside(k(View::V64, r"SOFTWARE\Vendor")), "the parent is not inside (key_holding covers it)");
        assert!(!inside(k(View::V64, r"SOFTWARE\Vendor\Editor 2")), "a sibling");
        assert!(!inside(k(View::V32, r"SOFTWARE\Vendor\Editor")), "the other view is another key");
    }

    #[test]
    fn protected_roots_trees_and_desktop_lnk_exception() {
        let f = fake();
        let r = |s: &str, g: Group| protected_reason(&f, Path::new(s), g);
        // roots: equal or ancestor blocked, inside allowed
        assert!(r(r"C:\Program Files", Group::ProgramFiles).is_some());
        assert!(r(r"C:\Users", Group::Data).is_some());
        assert!(r(r"C:\", Group::Data).is_some());
        assert!(r(r"C:\Program Files\Vendor", Group::ProgramFiles).is_none());
        // other profile root and the temp root
        assert!(r(r"C:\Users\Other", Group::Data).is_some());
        assert!(r(r"C:\Temp", Group::Data).is_some());
        assert!(r(r"C:\Temp\x", Group::Data).is_none());
        // trees: equal, inside and ancestor blocked
        assert!(r(r"C:\Windows\System32\x.dll", Group::ProgramFiles).is_some());
        assert!(r(r"C:\Users\me\Documents\a.doc", Group::Data).is_some());
        assert!(r(r"C:\Users\me\OneDrive\x", Group::Data).is_some());
        assert!(r(r"C:\ProgramData\Microsoft\x", Group::Data).is_some());
        // not local absolute
        assert!(r(r"\\srv\share\x", Group::Data).is_some());
        assert!(r(r"relative\x", Group::Data).is_some());
        // lnk exception: desktop root and Start Menu, only for Shortcuts-group .lnk
        assert!(r(r"C:\Users\me\Desktop\App.lnk", Group::Shortcuts).is_none());
        assert!(r(r"C:\Users\me\Desktop\App.lnk", Group::Data).is_some());
        assert!(r(r"C:\Users\me\Desktop\App.txt", Group::Shortcuts).is_some());
        assert!(r(r"C:\Users\me\Desktop\Sub\App.lnk", Group::Shortcuts).is_some());
        assert!(r(r"C:\ProgramData\Microsoft\Windows\Start Menu\Programs\V\App.lnk", Group::Shortcuts).is_none());
        // a drive-root install dir is protected
        assert!(r(r"D:\", Group::ProgramFiles).is_some());
    }

    #[test]
    fn revert_shapes() {
        let t = tempfile::tempdir().unwrap();
        let env = Env::sandbox(t.path(), "shape2");
        let sz = |name: &str, kind: u32| RegVal { name: name.into(), kind, data: vec![] };
        let rev = |k: RegPath, name: &str| Target::RegRevert { key: k, name: name.into(), previous: sz(name, 1) };
        let ok = |t: Target| registry_blocks(&env, &t).is_empty();
        let code = |t: Target| registry_blocks(&env, &t)[0].code;
        let run = &env.run_roots[0];
        assert!(ok(rev(run.clone(), "App")), "a named Run value");
        assert_eq!(code(rev(run.clone(), "")), BlockCode::ProtectedRegistry, "the default value of Run");
        assert_eq!(code(rev(run.child("Sub"), "App")), BlockCode::ProtectedRegistry, "a value in a key below Run");
        let ap = &env.app_paths_roots[0];
        assert!(ok(rev(ap.child("tool.exe"), "")), "the default value of an App Paths child");
        assert_eq!(code(rev(ap.child("tool.exe"), "Path")), BlockCode::ProtectedRegistry, "a named value there");
        assert_eq!(code(rev(ap.child("a").child("b"), "")), BlockCode::ProtectedRegistry, "two levels below App Paths");
        assert_eq!(code(rev(ap.clone(), "")), BlockCode::ProtectedRegistry, "the App Paths root itself");
        let sw = &env.software_roots[0];
        assert!(ok(rev(sw.child("Vendor"), "Mode")), "a value in a vendor key");
        assert!(ok(rev(sw.child("A").child("B").child("C").child("D"), "Mode")), "any depth below a vendor key");
        assert_eq!(code(rev(sw.clone(), "Mode")), BlockCode::ProtectedRegistry, "the Software root itself");
        for reserved in ["Microsoft", "Classes", "Policies", "Wow6432Node", "Clients", "RegisteredApplications"] {
            assert_eq!(code(rev(sw.child(reserved).child("X"), "Mode")), BlockCode::ProtectedRegistry, "{reserved}");
        }
        assert_eq!(code(rev(env.uninstall_roots[0].child("App"), "DisplayName")), BlockCode::ProtectedRegistry, "an Uninstall entry");
        let outside = RegPath::new(Hive::Hkcu, View::V64, format!(r"{}\shape2\Outside\X", crate::env::TEST_KEY_PREFIX));
        assert_eq!(code(rev(outside, "Mode")), BlockCode::ProtectedRegistry, "outside every root");
        let weird = Target::RegRevert { key: run.clone(), name: "App".into(), previous: sz("App", 99) };
        assert_eq!(code(weird), BlockCode::Unverifiable, "an unknown value type");
    }

    #[test]
    fn registry_shapes() {
        let t = tempfile::tempdir().unwrap();
        let env = Env::sandbox(t.path(), "shape1");
        let u = &env.uninstall_roots[0];
        let key = |k: RegPath| Target::RegKey { key: k };
        assert!(registry_blocks(&env, &key(u.child("App"))).is_empty());
        assert!(registry_blocks(&env, &key(u.child("app"))).is_empty());
        assert_eq!(registry_blocks(&env, &key(u.clone()))[0].code, BlockCode::ProtectedRegistry);
        assert_eq!(registry_blocks(&env, &key(u.child("A").child("B")))[0].code, BlockCode::ProtectedRegistry);
        // wrong view for the same path is a different root
        let mut wrong = u.child("App");
        wrong.view = View::V32;
        assert!(!registry_blocks(&env, &key(wrong)).is_empty());
        let s = &env.software_roots[0];
        assert!(registry_blocks(&env, &key(s.child("Vendor").child("Prod"))).is_empty());
        assert!(registry_blocks(&env, &key(s.child("Vendor"))).is_empty());
        assert!(!registry_blocks(&env, &key(s.child("Vendor").child("Prod").child("Deep"))).is_empty());
        assert!(!registry_blocks(&env, &key(s.child("Microsoft").child("X"))).is_empty());
        assert!(!registry_blocks(&env, &key(s.clone())).is_empty());
        let run = &env.run_roots[0];
        let val = |k: RegPath, n: &str| Target::RegValue { key: k, name: n.into() };
        assert!(registry_blocks(&env, &val(run.clone(), "App")).is_empty());
        assert!(!registry_blocks(&env, &key(run.clone())).is_empty(), "a whole Run key is never removed");
        assert!(!registry_blocks(&env, &val(run.clone(), "")).is_empty());
        assert!(!registry_blocks(&env, &val(u.child("App"), "X")).is_empty());
        let outside = RegPath::new(Hive::Hkcu, View::V64, format!(r"{}\{}\Outside\X", crate::env::TEST_KEY_PREFIX, "shape1"));
        assert_eq!(registry_blocks(&env, &key(outside))[0].code, BlockCode::OutsideAllowedZone);
    }
}
