//! Install tracing: a read-only snapshot of the places a removal can ever be offered from, taken before and after an installer
//! runs. The difference is the trace journal (see `docs/architecture.md`, "Install tracing").
//!
//! Capturing is read-only and may run against the real system: directory listings, file metadata and `KEY_READ` registry opens.
// shortcut: no per-process attribution (no ETW or driver): every change in scope between the two snapshots enters the journal,
// background writers included; reverts need a reference to the program's folder and trace-only objects away from it score lower.
// Upgrade with ETW in the elevated helper (stage 2).
// shortcut: the "before" snapshot stays in memory for the whole session (about 190 B per object) and the second capture is
// streamed; an app restart or a reboot loses the session. Persist the "before" snapshot for installs that span a reboot.
// shortcut: files are compared by size and mtime only, so a same-size overwrite that keeps the mtime is missed; hash files in
// the install zones if a lab run shows a miss.
// shortcut: not captured: Classes, Services, scheduled tasks, HKCU\Environment, SOFTWARE\Microsoft (except Uninstall, Run, RunOnce
// and App Paths), desktop subfolders, protected trees, temp, other users and install folders outside the zones; add stage-3 adapters.
// shortcut: noise rules are folder names below the capture root; there are none for the registry.
use crate::env::Env;
use crate::model::*;
use crate::ops::target_key;
use crate::paths::{canonical, is_inside, mtime_ms, norm, REPARSE_ATTR};
use crate::registry;
use crate::safety::RESERVED_SOFTWARE;
use crate::{Error, Result};
use std::collections::{BTreeSet, HashMap, HashSet};
use std::fs;
use std::os::windows::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::time::Instant;
use windows::Win32::Security::Cryptography::{BCRYPT_SHA256_ALG_HANDLE, BCryptHash};
use winreg::enums::KEY_READ;

/// Hard cap per snapshot. Above it the capture fails; it never truncates silently.
pub const MAX_OBJECTS: usize = 1_000_000;

/// Folder names (lowercase) below a capture root whose changes are background noise: browser and GPU caches, crash dumps, profiles.
const NOISE_DIRS: &[&str] = &[
    "cache", "caches", "code cache", "gpucache", "cache2", "shadercache", "dxcache", "glcache", "d3dscache", "dawncache",
    "grshadercache", "crashpad", "crashdumps", "crash reports", "user data", "profiles", "connecteddevicesplatform",
];

/// A registry object in a snapshot: the full target and, for values, the full data (a revert may need it).
pub struct RegItem {
    pub target: Target,
    pub print: Print,
    pub val: Option<RegVal>,
}

/// File objects hold only id -> fingerprint (the path is in the id); registry objects hold everything.
#[derive(Default)]
pub struct Snapshot {
    pub paths: HashMap<String, Print>,
    pub reg: HashMap<String, RegItem>,
    pub unreadable: BTreeSet<String>,
    pub objects: u64,
    pub ms: u64,
}

pub struct Capture {
    pub unreadable: BTreeSet<String>,
    pub objects: u64,
    pub ms: u64,
}

type Visit<'a> = dyn FnMut(String, Target, Print, Option<RegVal>) + 'a;

/// The file roots: every zone root once, desktops only one level deep.
fn file_roots(env: &Env) -> Vec<(PathBuf, Option<u32>)> {
    let mut seen = HashSet::new();
    let mut out = Vec::new();
    for z in env.folders.zone_roots() {
        if seen.insert(norm(z)) {
            let desktop = env.folders.desktops.iter().any(|d| norm(d) == norm(z));
            out.push((z.clone(), desktop.then_some(1)));
        }
    }
    out
}

struct RegRoot {
    key: RegPath,
    /// None: the whole tree. Some(0): the values of the key itself.
    depth: Option<u32>,
    /// First-level children named in `RESERVED_SOFTWARE` are skipped.
    software: bool,
}

fn reg_roots(env: &Env) -> Vec<RegRoot> {
    let mut all: Vec<RegRoot> = Vec::new();
    let mut add = |key: &RegPath, depth: Option<u32>, software: bool| {
        if !all.iter().any(|r| r.key.same(key)) {
            all.push(RegRoot { key: key.clone(), depth, software });
        }
    };
    for r in &env.software_roots {
        add(r, None, true);
    }
    for r in env.uninstall_roots.iter().chain(&env.app_paths_roots) {
        add(r, None, false);
    }
    for r in &env.run_roots {
        add(r, Some(0), false);
        add(&RegPath { path: format!("{}Once", r.path), ..r.clone() }, Some(0), false);
    }
    // HKCU\Software is one physical key in both views.
    let v64: Vec<RegPath> = all.iter().filter(|r| r.key.hive == Hive::Hkcu && r.key.view == View::V64).map(|r| r.key.clone()).collect();
    all.retain(|r| !(r.key.hive == Hive::Hkcu && r.key.view == View::V32 && v64.iter().any(|k| k.path.eq_ignore_ascii_case(&r.key.path))));
    all
}

struct Walker<'a, 'b> {
    visit: &'a mut Visit<'b>,
    count: usize,
    unreadable: BTreeSet<String>,
}

impl Walker<'_, '_> {
    fn emit(&mut self, id: String, target: Target, print: Print, val: Option<RegVal>) -> Result<()> {
        self.count += 1;
        if self.count > MAX_OBJECTS {
            return Err(Error(format!("too many objects to trace (over {MAX_OBJECTS})")));
        }
        (self.visit)(id, target, print, val);
        Ok(())
    }

    fn files(&mut self, env: &Env) -> Result<()> {
        let roots = file_roots(env);
        let root_set: HashSet<String> = roots.iter().map(|r| norm(&r.0)).collect();
        let mut skip: HashSet<String> = env.folders.protected_trees.iter().map(|p| norm(p)).collect();
        if let Ok(t) = canonical(&std::env::temp_dir()) {
            skip.insert(norm(&t));
        }
        for (root, max_depth) in &roots {
            let mut stack = vec![(root.clone(), norm(root), 1u32)];
            while let Some((dir, dnorm, depth)) = stack.pop() {
                let is_root = depth == 1 && norm(&dir) == norm(root);
                let rd = match fs::read_dir(&dir) {
                    Ok(r) => r,
                    // An absent root is not an error; a folder that vanished mid-walk is blind, like an unreadable one.
                    Err(e) if is_root && e.kind() == std::io::ErrorKind::NotFound => continue,
                    Err(_) => {
                        self.unreadable.insert(format!("path:{dnorm}"));
                        continue;
                    }
                };
                for e in rd {
                    let Ok(e) = e else {
                        self.unreadable.insert(format!("path:{dnorm}"));
                        continue;
                    };
                    let name = e.file_name();
                    let Some(n) = name.to_str() else {
                        self.unreadable.insert(format!("path:{dnorm}"));
                        continue;
                    };
                    let child = format!("{dnorm}\\{}", n.to_lowercase());
                    if root_set.contains(&child) || skip.contains(&child) {
                        continue;
                    }
                    let Ok(md) = e.metadata() else {
                        self.unreadable.insert(format!("path:{dnorm}"));
                        continue;
                    };
                    let path = dir.join(n);
                    let (kind, print) = if md.file_attributes() & REPARSE_ATTR != 0 {
                        (PathKind::Link, Print::Link {})
                    } else if md.is_dir() {
                        (PathKind::Dir, Print::Dir {})
                    } else {
                        (PathKind::File, Print::File { size: md.len(), mtime: mtime_ms(&md) })
                    };
                    self.emit(format!("path:{child}"), Target::Path { path: path.clone(), kind }, print, None)?;
                    if kind == PathKind::Dir && max_depth.is_none_or(|m| depth < m) {
                        stack.push((path, child, depth + 1));
                    }
                }
            }
        }
        Ok(())
    }

    fn registry(&mut self, env: &Env) -> Result<()> {
        for root in reg_roots(env) {
            let mut stack = vec![(root.key.clone(), 0u32)];
            while let Some((key, level)) = stack.pop() {
                let kid = target_key(&Target::RegKey { key: key.clone() });
                let k = match registry::open(&key, KEY_READ) {
                    Ok(k) => k,
                    Err(e) if level == 0 && e.kind() == std::io::ErrorKind::NotFound => continue,
                    Err(_) => {
                        self.unreadable.insert(kid);
                        continue;
                    }
                };
                let mut ok = true;
                for item in k.enum_values() {
                    let Ok((name, v)) = item else {
                        ok = false; // a value type above 11 surfaces here too
                        break;
                    };
                    let val = registry::to_val(name.clone(), v);
                    let target = Target::RegValue { key: key.clone(), name };
                    let print = value_print(&val)?;
                    self.emit(target_key(&target), target, print, Some(val))?;
                }
                let mut names = Vec::new();
                if ok && root.depth.is_none_or(|m| level < m) {
                    for n in k.enum_keys() {
                        match n {
                            Ok(n) => names.push(n),
                            Err(_) => ok = false,
                        }
                    }
                }
                if !ok {
                    self.unreadable.insert(kid);
                    continue;
                }
                for n in names {
                    if root.software && level == 0 && RESERVED_SOFTWARE.contains(&n.to_lowercase().as_str()) {
                        continue;
                    }
                    let child = key.child(&n);
                    let target = Target::RegKey { key: child.clone() };
                    self.emit(target_key(&target), target, Print::Key {}, None)?;
                    stack.push((child, level + 1));
                }
            }
        }
        Ok(())
    }
}

/// Walks the scope and streams every object to `visit` (id, target, fingerprint, value data for registry values).
pub fn capture_with(env: &Env, visit: &mut Visit) -> Result<Capture> {
    let t = Instant::now();
    let mut w = Walker { visit, count: 0, unreadable: BTreeSet::new() };
    w.files(env)?;
    w.registry(env)?;
    Ok(Capture { objects: w.count as u64, unreadable: w.unreadable, ms: t.elapsed().as_millis() as u64 })
}

pub fn capture(env: &Env) -> Result<Snapshot> {
    let mut s = Snapshot::default();
    let cap = capture_with(env, &mut |id, target, print, val| match target {
        Target::Path { .. } => {
            s.paths.insert(id, print);
        }
        _ => {
            s.reg.insert(id, RegItem { target, print, val });
        }
    })?;
    (s.unreadable, s.objects, s.ms) = (cap.unreadable, cap.objects, cap.ms);
    Ok(s)
}

/// Compares a "before" snapshot with a streamed "after" capture; the "after" objects are never stored.
pub struct Differ {
    before: Snapshot,
    changes: Vec<TraceChange>,
}

impl Differ {
    pub fn new(before: Snapshot) -> Differ {
        Differ { before, changes: Vec::new() }
    }

    pub fn visit(&mut self, id: String, target: Target, print: Print) {
        let (old, prev) = if matches!(target, Target::Path { .. }) {
            (self.before.paths.remove(&id), None)
        } else {
            match self.before.reg.remove(&id) {
                Some(i) => (Some(i.print), i.val),
                None => (None, None),
            }
        };
        let change = match &old {
            None => Change::Created,
            Some(b) if *b != print => Change::Modified,
            Some(_) => return,
        };
        let previous = if change == Change::Modified { prev } else { None };
        self.changes.push(TraceChange { id, change, target, before: old, after: Some(print), previous, noise: false });
    }

    /// Adds the deletions, drops every change below a folder or key that could not be read (or whose type switched between a
    /// link and a folder), flags noise and sorts by id. Returns the changes and the union of both unreadable sets.
    pub fn finish(mut self, after_unreadable: &BTreeSet<String>, roots: &[PathBuf]) -> (Vec<TraceChange>, BTreeSet<String>) {
        for (id, print) in self.before.paths.drain() {
            let kind = match print {
                Print::Dir {} => PathKind::Dir,
                Print::Link {} => PathKind::Link,
                _ => PathKind::File,
            };
            let target = Target::Path { path: PathBuf::from(&id["path:".len()..]), kind };
            self.changes.push(TraceChange { id, change: Change::Deleted, target, before: Some(print), after: None, previous: None, noise: false });
        }
        for (id, i) in self.before.reg.drain() {
            self.changes.push(TraceChange { id, change: Change::Deleted, target: i.target, before: Some(i.print), after: None, previous: None, noise: false });
        }
        let unreadable: BTreeSet<String> = self.before.unreadable.union(after_unreadable).cloned().collect();
        let mut blind: HashSet<String> = unreadable.iter().cloned().collect();
        for c in &self.changes {
            if c.change == Change::Modified && matches!((&c.before, &c.after), (Some(Print::Link {}), Some(Print::Dir {})) | (Some(Print::Dir {}), Some(Print::Link {}))) {
                blind.insert(c.id.clone());
            }
        }
        let mut changes: Vec<TraceChange> = self.changes.into_iter().filter(|c| !has_blind_ancestor(&c.target, &blind)).collect();
        for c in &mut changes {
            if let Target::Path { path, .. } = &c.target {
                c.noise = is_noise(path, roots);
            }
        }
        changes.sort_by(|a, b| a.id.cmp(&b.id));
        (changes, unreadable)
    }
}

fn has_blind_ancestor(t: &Target, blind: &HashSet<String>) -> bool {
    let mut cur = parent_target(t);
    while let Some(p) = cur {
        if blind.contains(&target_key(&p)) {
            return true;
        }
        cur = parent_target(&p);
    }
    false
}

/// The parent as a target: a folder for a path, the key for a value, the key above for a key. Built from the target, never by
/// parsing an id (value names may hold `\` and `|`).
fn parent_target(t: &Target) -> Option<Target> {
    match t {
        Target::Path { path, .. } => path.parent().map(|p| Target::Path { path: p.to_path_buf(), kind: PathKind::Dir }),
        Target::RegValue { key, .. } | Target::RegRevert { key, .. } => Some(Target::RegKey { key: key.clone() }),
        Target::RegKey { key } => key.path.rsplit_once('\\').map(|(up, _)| Target::RegKey { key: RegPath::new(key.hive, key.view, up) }),
    }
}

/// The `target_key` of the parent target.
#[allow(dead_code)] // used by the scan in step 4
pub(crate) fn parent_id(t: &Target) -> Option<String> {
    parent_target(t).map(|p| target_key(&p))
}

/// Noise is decided only below the deepest capture root that contains the path, so a root such as `C:\Cache\x\AppData\Local`
/// does not make everything inside it noise.
fn is_noise(path: &Path, roots: &[PathBuf]) -> bool {
    let Some(root) = roots.iter().filter(|r| is_inside(path, r)).max_by_key(|r| norm(r).len()) else { return false };
    let (p, r) = (norm(path), norm(root));
    let rest = p.strip_prefix(r.trim_end_matches('\\')).unwrap_or(&p);
    rest.split('\\').any(|c| NOISE_DIRS.contains(&c))
}

fn sha256_hex(b: &[u8]) -> Result<String> {
    let mut out = [0u8; 32];
    // SAFETY: both slices are valid for the call; the pseudo handle needs no cleanup.
    let st = unsafe { BCryptHash(BCRYPT_SHA256_ALG_HANDLE, None, b, &mut out) };
    if st.is_err() {
        return Err(Error(format!("SHA-256 failed (status {:#x})", st.0)));
    }
    Ok(out.iter().map(|x| format!("{x:02x}")).collect())
}

/// Kind and SHA-256 of kind + data; the full data stays in the snapshot only.
pub fn value_print(v: &RegVal) -> Result<Print> {
    let mut b = v.kind.to_le_bytes().to_vec();
    b.extend_from_slice(&v.data);
    Ok(Print::Value { kind: v.kind, sha256: sha256_hex(&b)? })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn p(path: &str, kind: PathKind) -> (String, Target) {
        let t = Target::Path { path: PathBuf::from(path), kind };
        (target_key(&t), t)
    }
    fn file(size: u64, mtime: u64) -> Print {
        Print::File { size, mtime }
    }
    fn key(path: &str) -> RegPath {
        RegPath::new(Hive::Hkcu, View::V64, path)
    }
    fn val(name: &str, kind: u32, data: &[u8]) -> RegVal {
        RegVal { name: name.into(), kind, data: data.to_vec() }
    }
    fn reg_value(k: &RegPath, v: &RegVal) -> (String, RegItem) {
        let t = Target::RegValue { key: k.clone(), name: v.name.clone() };
        (target_key(&t), RegItem { target: t, print: value_print(v).unwrap(), val: Some(v.clone()) })
    }
    fn after_value(k: &RegPath, v: &RegVal) -> (String, Target, Print) {
        let (id, i) = reg_value(k, v);
        (id, i.target, i.print)
    }
    fn after_key(k: &RegPath) -> (String, Target, Print) {
        let (id, i) = reg_key(k);
        (id, i.target, i.print)
    }
    fn reg_key(k: &RegPath) -> (String, RegItem) {
        let t = Target::RegKey { key: k.clone() };
        (target_key(&t), RegItem { target: t, print: Print::Key {}, val: None })
    }

    /// Runs `after` through a Differ over `before`.
    fn diff(before: Snapshot, after: Vec<(String, Target, Print)>, after_unreadable: &[&str], roots: &[&str]) -> Vec<TraceChange> {
        let mut d = Differ::new(before);
        for (id, t, pr) in after {
            d.visit(id, t, pr);
        }
        let roots: Vec<PathBuf> = roots.iter().map(PathBuf::from).collect();
        d.finish(&after_unreadable.iter().map(|s| s.to_string()).collect(), &roots).0
    }

    fn change<'a>(cs: &'a [TraceChange], id_suffix: &str) -> &'a TraceChange {
        cs.iter().find(|c| c.id.ends_with(id_suffix)).unwrap_or_else(|| panic!("no change ending with {id_suffix}: {cs:#?}"))
    }

    #[test]
    fn differ_created_modified_deleted() {
        let mut before = Snapshot::default();
        let (a, ta) = p(r"C:\R\a.txt", PathKind::File);
        let (gone, _) = p(r"C:\R\Gone.TXT", PathKind::File);
        let (dir, tdir) = p(r"C:\R\d", PathKind::Dir);
        before.paths.insert(a.clone(), file(1, 10));
        before.paths.insert(gone.clone(), file(5, 5));
        before.paths.insert(dir.clone(), Print::Dir {});
        let k = key(r"Software\V");
        let (vid, vitem) = reg_value(&k, &val("Mode", 1, b"o\0"));
        before.reg.insert(vid.clone(), vitem);
        let (tid, titem) = reg_value(&k, &val("Typed", 4, &[1, 0, 0, 0]));
        before.reg.insert(tid.clone(), titem);
        let (did, ditem) = reg_value(&k, &val("Del", 1, b"x\0"));
        before.reg.insert(did, ditem);
        let after = vec![
            (a.clone(), ta, file(2, 10)),       // size changed
            (dir.clone(), tdir, Print::Dir {}), // a folder never counts as modified
            after_value(&k, &val("Mode", 1, b"n\0")),
            after_value(&k, &val("Typed", 3, &[1, 0, 0, 0])), // same bytes, other type
            after_key(&key(r"Software\V\New")),
        ];
        let cs = diff(before, after, &[], &[r"C:\R"]);
        let m = change(&cs, r"a.txt");
        assert_eq!((m.change, &m.before, &m.after), (Change::Modified, &Some(file(1, 10)), &Some(file(2, 10))));
        assert!(!cs.iter().any(|c| c.id == dir), "folder mtime is ignored");
        let m = change(&cs, "|mode");
        assert_eq!(m.change, Change::Modified);
        assert_eq!(m.previous, Some(val("Mode", 1, b"o\0")), "the full previous value");
        let m = change(&cs, "|typed");
        assert_eq!((m.change, m.previous.is_some()), (Change::Modified, true), "a type change counts");
        let m = change(&cs, "|del");
        assert_eq!(m.change, Change::Deleted);
        assert!(m.previous.is_none() && matches!(m.before, Some(Print::Value { kind: 1, .. })), "a deleted value keeps only kind and hash");
        assert!(m.after.is_none());
        let m = change(&cs, r"gone.txt");
        assert_eq!(m.change, Change::Deleted);
        assert_eq!(m.target, Target::Path { path: PathBuf::from(r"c:\r\gone.txt"), kind: PathKind::File }, "a deleted path is lowercase");
        let m = change(&cs, r"software\v\new");
        assert_eq!((m.change, &m.before), (Change::Created, &None));
        assert_eq!(cs.len(), 6, "{cs:#?}");
        assert!(cs.windows(2).all(|w| w[0].id < w[1].id), "sorted by id");
    }

    #[test]
    fn differ_case_and_views() {
        let mut before = Snapshot::default();
        let (a, _) = p(r"C:\R\Some File.TXT", PathKind::File);
        before.paths.insert(a, file(1, 1));
        let (id, t) = p(r"c:\r\some file.txt", PathKind::File);
        let k64 = RegPath::new(Hive::Hklm, View::V64, r"SOFTWARE\V");
        let k32 = RegPath::new(Hive::Hklm, View::V32, r"SOFTWARE\V");
        let (kid, kitem) = reg_key(&k64);
        before.reg.insert(kid, kitem);
        let (id32, t32) = (target_key(&Target::RegKey { key: k32.clone() }), Target::RegKey { key: k32 });
        let (id64, t64) = reg_key(&k64);
        let cs = diff(before, vec![(id, t, file(1, 1)), (id64, t64.target, Print::Key {}), (id32.clone(), t32, Print::Key {})], &[], &[]);
        assert_eq!(cs.len(), 1, "{cs:#?}");
        assert_eq!((cs[0].id.as_str(), cs[0].change), (id32.as_str(), Change::Created), "the 32-bit view is another key");
    }

    #[test]
    fn noise_only_below_root() {
        let roots = [PathBuf::from(r"C:\Users\me\AppData\Local"), PathBuf::from(r"C:\Users\me\AppData\Local\Programs"), PathBuf::from(r"C:\Cache\x\AppData\Local")];
        let n = |s: &str| is_noise(Path::new(s), &roots);
        assert!(n(r"C:\Users\me\AppData\Local\Google\Chrome\User Data\Default\x.bin"));
        assert!(n(r"C:\Users\me\AppData\Local\Vendor\App\GPUCache\data_0"));
        assert!(n(r"C:\Users\me\AppData\Local\Vendor\Cache"), "the folder itself");
        assert!(!n(r"C:\Users\me\AppData\Local\Vendor\App\settings.json"));
        assert!(!n(r"C:\Users\me\AppData\Local\Programs\Tool\bin\t.exe"));
        assert!(!n(r"C:\Cache\x\AppData\Local\Vendor\settings.json"), "a root whose own path holds a noise name");
        assert!(n(r"C:\Cache\x\AppData\Local\Vendor\Code Cache\js"));
        assert!(!n(r"C:\Elsewhere\Cache\x"), "no root contains the path");
        assert!(!n(r"C:\Users\me\AppData\Local"), "the root itself");
    }

    #[test]
    fn differ_blind_below_unreadable() {
        // unreadable in the "after" capture: the items below it are gone from the walk but are not Deleted
        let mut before = Snapshot::default();
        let (d, _) = p(r"C:\R\locked", PathKind::Dir);
        let (f1, _) = p(r"C:\R\locked\a\b.txt", PathKind::File);
        let (f2, _) = p(r"C:\R\open\c.txt", PathKind::File);
        before.paths.insert(d.clone(), Print::Dir {});
        before.paths.insert(f1, file(1, 1));
        before.paths.insert(f2.clone(), file(1, 1));
        let (d_id, d_t) = p(r"C:\R\locked", PathKind::Dir);
        let cs = diff(before, vec![(d_id, d_t, Print::Dir {})], &[d.as_str()], &[]);
        assert_eq!(cs.len(), 1, "{cs:#?}");
        assert_eq!((cs[0].id.as_str(), cs[0].change), (f2.as_str(), Change::Deleted));
        // unreadable in the "before" capture: what appears below it is not Created
        let mut before = Snapshot::default();
        before.unreadable.insert(d.clone());
        let (f3, t3) = p(r"C:\R\locked\new.txt", PathKind::File);
        let (f4, t4) = p(r"C:\R\fresh.txt", PathKind::File);
        let cs = diff(before, vec![(f3, t3, file(1, 1)), (f4.clone(), t4, file(1, 1))], &[], &[]);
        assert_eq!(cs.len(), 1, "{cs:#?}");
        assert_eq!(cs[0].id, f4);
        // the same for registry keys
        let mut before = Snapshot::default();
        let kd = key(r"Software\Locked");
        let (kid, _) = reg_key(&kd);
        let (vid, vitem) = reg_value(&key(r"Software\Locked\Deep"), &val("v", 1, b"x\0"));
        before.reg.insert(vid, vitem);
        let cs = diff(before, vec![], &[kid.as_str()], &[]);
        assert!(cs.is_empty(), "{cs:#?}");
    }

    #[test]
    fn differ_link_dir_switch_blinds_descendants() {
        let (l, tl) = p(r"C:\R\x", PathKind::Dir);
        // Link -> folder with children now visible: the children are not Created
        let mut before = Snapshot::default();
        before.paths.insert(l.clone(), Print::Link {});
        let (c, tc) = p(r"C:\R\x\kid.txt", PathKind::File);
        let cs = diff(before, vec![(l.clone(), tl.clone(), Print::Dir {}), (c, tc, file(1, 1))], &[], &[]);
        assert_eq!(cs.len(), 1, "{cs:#?}");
        assert_eq!((cs[0].id.as_str(), cs[0].change), (l.as_str(), Change::Modified));
        // folder with children -> link: the children are not Deleted
        let mut before = Snapshot::default();
        before.paths.insert(l.clone(), Print::Dir {});
        let (c, _) = p(r"C:\R\x\kid.txt", PathKind::File);
        before.paths.insert(c, file(1, 1));
        let cs = diff(before, vec![(l.clone(), tl, Print::Link {})], &[], &[]);
        assert_eq!(cs.len(), 1, "{cs:#?}");
        assert_eq!(cs[0].change, Change::Modified);
    }

    #[test]
    fn rename_is_delete_plus_create() {
        let mut before = Snapshot::default();
        let (old, _) = p(r"C:\R\old.txt", PathKind::File);
        before.paths.insert(old.clone(), file(3, 3));
        let (new, tn) = p(r"C:\R\new.txt", PathKind::File);
        let cs = diff(before, vec![(new.clone(), tn, file(3, 3))], &[], &[]);
        assert_eq!(cs.iter().map(|c| (c.id.as_str(), c.change)).collect::<Vec<_>>(), [(new.as_str(), Change::Created), (old.as_str(), Change::Deleted)]);
    }

    #[test]
    fn parent_id_from_targets() {
        let path = |s: &str| Target::Path { path: PathBuf::from(s), kind: PathKind::File };
        assert_eq!(parent_id(&path(r"C:\A\B.txt")).as_deref(), Some(r"path:c:\a"));
        assert_eq!(parent_id(&path(r"C:\A")).as_deref(), Some(r"path:c:\"));
        assert_eq!(parent_id(&path(r"C:\")), None);
        let k = RegPath::new(Hive::Hklm, View::V32, r"SOFTWARE\V\Sub");
        assert_eq!(parent_id(&Target::RegKey { key: k.clone() }).as_deref(), Some(r"key:hklm32:software\v"));
        assert_eq!(parent_id(&Target::RegKey { key: RegPath::new(Hive::Hklm, View::V32, "SOFTWARE") }), None);
        // a value name may hold the separators of the id form
        let v = Target::RegValue { key: k, name: r"a\b|c".into() };
        assert_eq!(parent_id(&v).as_deref(), Some(r"key:hklm32:software\v\sub"));
    }

    #[test]
    fn sha256_and_value_print() {
        assert_eq!(sha256_hex(b"abc").unwrap(), "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
        assert_eq!(sha256_hex(b"").unwrap(), "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
        let a = value_print(&val("n", 1, b"x\0")).unwrap();
        assert_eq!(a, value_print(&val("other name", 1, b"x\0")).unwrap(), "the name is the lookup key, not part of the print");
        assert_ne!(a, value_print(&val("n", 2, b"x\0")).unwrap(), "a kind change");
        assert_ne!(a, value_print(&val("n", 1, b"y\0")).unwrap(), "a data change");
        let Print::Value { kind, sha256 } = a else { panic!() };
        assert_eq!((kind, sha256.len()), (1, 64));
    }
}
