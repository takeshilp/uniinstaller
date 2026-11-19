//! Install tracing: a read-only snapshot of the places a removal can ever be offered from, taken before and after an installer
//! runs. The difference is the trace journal (see `docs/tracing.md`).
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
use crate::command::parse_uninstall;
use crate::env::Env;
use crate::inventory::{icon_path, list_apps};
use crate::model::*;
use crate::native::{self, RunOptions};
use crate::ops::{self, target_key};
use crate::paths::{REPARSE_ATTR, canonical, is_drive_root, is_inside, is_local_abs, mtime_ms, norm};
use crate::registry;
use crate::safety::{RESERVED_SOFTWARE, protected_reason, registry_blocks, text_refers_to};
use crate::{Error, Result, now_ms};
use std::collections::{BTreeSet, HashMap, HashSet};
use std::fs;
use std::io::Write;
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
                    let (kind, print) = print_of(&md);
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

/// The kind and fingerprint of one file system object; a link is never followed.
fn print_of(md: &fs::Metadata) -> (PathKind, Print) {
    if md.file_attributes() & REPARSE_ATTR != 0 {
        (PathKind::Link, Print::Link {})
    } else if md.is_dir() {
        (PathKind::Dir, Print::Dir {})
    } else {
        (PathKind::File, Print::File { size: md.len(), mtime: mtime_ms(md) })
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
    // shortcut: modified files and deleted objects are report-only (no content backup), and a deleted path is stored lowercase (only the
    // id is kept for a file); add backups and original-case paths if "undo what the installer replaced" is ever wanted.
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
        // Services and tasks are not traced (shortcut 4 in docs/architecture.md), so they have no parent in a journal.
        Target::Service { .. } | Target::Task { .. } => None,
    }
}

/// The `target_key` of the parent target.
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

// ---- sessions ----

/// A trace in progress: the installer to run and the "before" snapshot. Lives in memory only.
pub struct Session {
    pub launch: Launch,
    pub before: Snapshot,
    pub started_ms: u64,
    pub native: Option<NativeRun>,
}

/// The command that runs the installer at `path`. Trust boundary: the path comes from a file dialog.
/// Real environment: an `.exe` itself, an `.msi` through `msiexec /i` (the Windows folder's copy, so an association cannot
/// interfere). Sandbox: only `.cmd` and `.bat` files inside the sandbox folder, so the sandbox GUI can never run a real installer.
pub fn installer_launch(env: &Env, path: &Path) -> Result<Launch> {
    let bad = |why: &str| Err(Error(format!("cannot trace this file: {why}")));
    if !is_local_abs(path) {
        return bad("not a local absolute path");
    }
    if !path.is_file() {
        return bad("not a file");
    }
    let ext = path.extension().and_then(|e| e.to_str()).map(str::to_lowercase).unwrap_or_default();
    let raw = path.to_string_lossy().to_string();
    let launch = |exe: PathBuf, args: String| Launch { raw: raw.clone(), exe, args, argv: vec![], msi_product: None };
    if env.sandbox {
        let in_sandbox = env.data_dir.parent().is_some_and(|root| is_inside(path, root)) && crate::paths::is_canonical(path);
        return match ext.as_str() {
            "cmd" | "bat" if in_sandbox => Ok(launch(path.to_path_buf(), String::new())),
            _ => bad("in sandbox mode only .cmd and .bat files inside the sandbox folder can be traced"),
        };
    }
    match ext.as_str() {
        "exe" => Ok(launch(path.to_path_buf(), String::new())),
        "msi" if !raw.contains('"') => Ok(launch(env.folders.system_dir.join("msiexec.exe"), format!("/i \"{raw}\""))),
        _ => bad("only .exe and .msi files can be traced"),
    }
}

/// Takes the "before" snapshot. Read-only: allowed on the real system.
pub fn begin(env: &Env, launch: Launch) -> Result<Session> {
    let started_ms = now_ms();
    Ok(Session { launch, before: capture(env)?, started_ms, native: None })
}

/// Runs the installer and waits for its whole process tree. Destructive in effect (it installs), so the debug guard applies:
/// a debug build runs it only in the sandbox.
pub fn install(env: &Env, s: &mut Session, opts: &RunOptions) -> Result<()> {
    ops::guard(env)?;
    if s.native.is_some() {
        return Err(Error("the installer was already run".into()));
    }
    let _g = ops::lock();
    s.native = Some(native::run_uninstaller(&s.launch, opts));
    Ok(())
}

/// Takes the "after" snapshot (streamed through the differ), links the journal to a program and saves it. Only writes the journal.
pub fn finish(env: &Env, s: Session) -> Result<TraceJournal> {
    let before_ms = s.before.ms;
    let mut d = Differ::new(s.before);
    let cap = capture_with(env, &mut |id, t, p, _| d.visit(id, t, p))?;
    let roots: Vec<PathBuf> = file_roots(env).into_iter().map(|r| r.0).collect();
    let (mut changes, unreadable) = d.finish(&cap.unreadable, &roots);
    let link = link(env, &changes)?;
    let dirs = match &link {
        TraceLink::Linked { app } => app_dirs(env, app),
        _ => vec![],
    };
    for c in changes.iter_mut().filter(|c| c.previous.is_some()) {
        if !keep_previous(env, &dirs, c) {
            c.previous = None;
        }
    }
    let mut ms = now_ms();
    while traces_dir(env).join(format!("tr-{ms}.json")).exists() {
        ms += 1;
    }
    let j = TraceJournal {
        schema: TRACE_SCHEMA,
        id: format!("tr-{ms}"),
        created_ms: s.started_ms,
        finished_ms: now_ms(),
        installer: s.launch,
        native: s.native,
        link,
        objects: cap.objects,
        before_ms,
        after_ms: cap.ms,
        unreadable: unreadable.into_iter().collect(),
        changes,
    };
    save(env, &j)?;
    Ok(j)
}

// ---- linking ----

pub(crate) fn one_below_uninstall(env: &Env, key: &RegPath) -> bool {
    env.uninstall_roots.iter().any(|r| key.below(r).is_some_and(|c| c.len() == 1))
}

// shortcut: a journal is linked only when exactly one new visible Uninstall entry appears; updates, reinstalls and bundles stay
// unlinked and unused, add the update-merge rules when they are wanted.
/// Exactly one new visible program makes the journal usable; none or several leave it unlinked.
fn link(env: &Env, changes: &[TraceChange]) -> Result<TraceLink> {
    let new: Vec<&RegPath> = changes
        .iter()
        .filter(|c| c.change == Change::Created && !c.noise)
        .filter_map(|c| match &c.target {
            Target::RegKey { key } if one_below_uninstall(env, key) => Some(key),
            _ => None,
        })
        .collect();
    // visible programs only: a hidden component installed alongside never links (see components_left)
    let mut apps: Vec<InstalledApp> = list_apps(env, false)?.into_iter().filter(|a| a.sources.iter().any(|s| new.iter().any(|k| k.same(s)))).collect();
    Ok(match apps.len() {
        1 => TraceLink::Linked { app: Box::new(apps.remove(0)) },
        0 => TraceLink::NoProgram {},
        _ => TraceLink::SeveralPrograms { names: apps.into_iter().map(|a| a.display_name).collect() },
    })
}

/// The folders a program claims for itself: InstallLocation, the uninstaller's folder, the icon's folder.
/// A superset of what `scan` can confirm as the install folder, so a value that passes the scan check always carries `previous`.
fn app_dirs(env: &Env, app: &InstalledApp) -> Vec<PathBuf> {
    let un = app.uninstall_string.as_deref().and_then(|s| parse_uninstall(s, &env.folders.system_dir, app.product_code.as_deref()).ok());
    [app.install_location.clone(), un.and_then(|l| l.exe.parent().map(Path::to_path_buf)), icon_path(app).and_then(|i| i.parent().map(Path::to_path_buf))]
        .into_iter()
        .flatten()
        .filter(|d| is_local_abs(d) && !is_drive_root(d) && !is_inside(d, &env.folders.windows_dir) && protected_reason(&env.folders, d, Group::ProgramFiles).is_none())
        .collect()
}

/// Previous data is kept only where a revert could use it: an allowed shape whose new text points into the program's folders.
fn keep_previous(env: &Env, dirs: &[PathBuf], c: &TraceChange) -> bool {
    let (Change::Modified, Target::RegValue { key, name }, Some(prev)) = (c.change, &c.target, &c.previous) else { return false };
    registry_blocks(env, &Target::RegRevert { key: key.clone(), name: name.clone(), previous: prev.clone() }).is_empty()
        && registry::read_value(key, name).ok().and_then(|v| registry::val_text(&v)).is_some_and(|t| dirs.iter().any(|d| text_refers_to(&t, d)))
}

// ---- store ----

const HEADER: &str = "uniinstaller-trace";

/// `^tr-[0-9]{1,20}$` without a regex crate.
pub fn valid_trace_id(id: &str) -> Result<()> {
    match id.strip_prefix("tr-") {
        Some(n) if (1..=20).contains(&n.len()) && n.bytes().all(|b| b.is_ascii_digit()) => Ok(()),
        _ => Err(Error("invalid trace id".into())),
    }
}

fn traces_dir(env: &Env) -> PathBuf {
    env.data_dir.join("traces")
}

// shortcut: journals are user-writable and hold the previous data of attributable values in clear text; the checksum catches
// corruption, not tampering. Protected store and DPAPI in stage 2, together with the manifests.
/// Line 1: `uniinstaller-trace <version> sha256:<hex>`, then compact JSON; the hash covers exactly the JSON bytes. Written to
/// `.tmp`, synced, renamed.
pub fn save(env: &Env, j: &TraceJournal) -> Result<PathBuf> {
    valid_trace_id(&j.id)?;
    let body = serde_json::to_vec(j)?;
    let header = format!("{HEADER} {TRACE_SCHEMA} sha256:{}\n", sha256_hex(&body)?);
    let dir = traces_dir(env);
    fs::create_dir_all(&dir)?;
    let (path, tmp) = (dir.join(format!("{}.json", j.id)), dir.join(format!("{}.json.tmp", j.id)));
    let mut f = fs::File::create(&tmp)?;
    f.write_all(header.as_bytes())?;
    f.write_all(&body)?;
    f.sync_all()?;
    drop(f);
    fs::rename(&tmp, &path)?;
    Ok(path)
}

/// Rejects a bad or newer header, a checksum mismatch, invalid JSON and an id that does not match the file name.
pub fn load(env: &Env, id: &str) -> Result<TraceJournal> {
    valid_trace_id(id)?;
    let bytes = fs::read(traces_dir(env).join(format!("{id}.json")))?;
    let bad = || Error("not a trace journal (bad header)".into());
    let nl = bytes.iter().position(|&b| b == b'\n').ok_or_else(bad)?;
    let head = std::str::from_utf8(&bytes[..nl]).map_err(|_| bad())?;
    let mut parts = head.split(' ');
    let (Some(HEADER), Some(ver), Some(hash), None) = (parts.next(), parts.next(), parts.next(), parts.next()) else { return Err(bad()) };
    let ver: u32 = ver.parse().map_err(|_| bad())?;
    let hash = hash.strip_prefix("sha256:").ok_or_else(bad)?;
    if ver > TRACE_SCHEMA {
        return Err(Error("written by a newer version of Uniinstaller".into()));
    }
    let body = &bytes[nl + 1..];
    if sha256_hex(body)? != hash {
        return Err(Error("checksum mismatch: the journal is damaged".into()));
    }
    let j: TraceJournal = serde_json::from_slice(body)?;
    if j.schema > TRACE_SCHEMA {
        return Err(Error("written by a newer version of Uniinstaller".into()));
    }
    if j.id != id {
        return Err(Error("journal id does not match its file name".into()));
    }
    Ok(j)
}

// ---- use ----

/// Why the journal `t` was recorded for a program that no longer looks the same, if it does not: version, folder, uninstall command.
fn trust(t: &InstalledApp, app: &InstalledApp) -> Option<Distrust> {
    let folder = |a: &InstalledApp| a.install_location.as_deref().map(norm);
    let command = |a: &InstalledApp| a.uninstall_string.as_deref().map(|s| s.trim().to_lowercase());
    if t.display_version != app.display_version {
        Some(Distrust::VersionChanged)
    } else if folder(t) != folder(app) {
        Some(Distrust::FolderChanged)
    } else if command(t) != command(app) {
        Some(Distrust::UninstallerChanged)
    } else {
        None
    }
}

// shortcut: hidden components make a journal untrusted only after the program's own uninstaller ran (`find_for(.., true)`); the card
// and the preview do not check them, because that would flag a bundle while it is installed.
/// A hidden component the install created (an Uninstall key other than the program's own) is still installed.
fn components_left(env: &Env, j: &TraceJournal, t: &InstalledApp) -> bool {
    j.changes.iter().any(|c| {
        c.change == Change::Created
            && matches!(&c.target, Target::RegKey { key } if one_below_uninstall(env, key) && !t.sources.iter().any(|s| s.same(key)) && registry::exists(key))
    })
}

// shortcut: `find_for` parses every journal, newest first; add an index if users keep hundreds.
/// The newest loadable journal linked to `app` (same hive, view and key), whether it is still trusted and what it only reports.
/// `uninstalled`: the program's own uninstaller has run, so a hidden component that is still installed makes the journal untrusted.
pub fn find_for(env: &Env, app: &InstalledApp, uninstalled: bool) -> Option<(TraceJournal, TraceUse)> {
    let mut ids: Vec<(u64, String)> = fs::read_dir(traces_dir(env))
        .ok()?
        .flatten()
        .filter_map(|e| {
            let name = e.file_name().to_string_lossy().to_string();
            let id = name.strip_suffix(".json")?.to_string();
            valid_trace_id(&id).ok()?;
            Some((id[3..].parse().ok()?, id))
        })
        .collect();
    ids.sort_by_key(|x| std::cmp::Reverse(x.0));
    for (_, id) in ids {
        let Ok(j) = load(env, &id) else { continue };
        let distrust = {
            let TraceLink::Linked { app: t } = &j.link else { continue };
            if !t.sources.iter().any(|s| app.sources.iter().any(|x| x.same(s))) {
                continue;
            }
            trust(t, app).or_else(|| (uninstalled && components_left(env, &j, t)).then_some(Distrust::ComponentStillInstalled))
        };
        let reported = j.changes.iter().filter(|c| !c.noise && (c.change == Change::Deleted || (c.change == Change::Modified && matches!(c.target, Target::Path { .. })))).count();
        let u = TraceUse { id: j.id.clone(), created_ms: j.created_ms, trusted: distrust.is_none(), distrust, reported };
        return Some((j, u));
    }
    None
}

fn display(t: &Target) -> String {
    match t {
        Target::Path { path, .. } => path.display().to_string(),
        Target::RegKey { key } => key.display(),
        Target::RegValue { key, name } | Target::RegRevert { key, name, .. } => format!("{}\\{}", key.display(), if name.is_empty() { "@" } else { name }),
        Target::Service { name } => format!("service {name}"),
        Target::Task { path } => format!("task {path}"),
    }
}

pub fn summary(j: &TraceJournal) -> TraceSummary {
    let live = || j.changes.iter().filter(|c| !c.noise);
    let values: Vec<&TraceChange> = live().filter(|c| c.change == Change::Modified && matches!(c.target, Target::RegValue { .. })).collect();
    TraceSummary {
        id: j.id.clone(),
        created_ms: j.created_ms,
        link: j.link.clone(),
        native: j.native.clone(),
        objects: j.objects,
        before_ms: j.before_ms,
        after_ms: j.after_ms,
        created: live().filter(|c| c.change == Change::Created).count(),
        modified_values: values.iter().map(|c| display(&c.target)).collect(),
        restorable_values: values.iter().filter(|c| c.previous.is_some()).count(),
        modified_files: live().filter(|c| c.change == Change::Modified && matches!(c.target, Target::Path { .. })).map(|c| display(&c.target)).collect(),
        deleted: live().filter(|c| c.change == Change::Deleted).map(|c| display(&c.target)).collect(),
        noise: j.changes.iter().filter(|c| c.noise).count(),
        unreadable: j.unreadable.len(),
    }
}

/// Every Created change, noise included: a folder holding a browser cache is still "unchanged".
pub(crate) type Created<'a> = HashMap<&'a str, &'a TraceChange>;

pub(crate) fn created(j: &TraceJournal) -> Created<'_> {
    j.changes.iter().filter(|c| c.change == Change::Created).map(|c| (c.id.as_str(), c)).collect()
}

/// The path is exactly what the install created: same fingerprint, and (for a folder) every current child too. Entries that were
/// deleted since are fine; anything new or changed breaks the match. Fails closed on any read error and on unreadable ids.
pub(crate) fn unchanged_path(p: &Path, c: &Created, blind: &HashSet<&str>) -> bool {
    let id = format!("path:{}", norm(p));
    let Some(ch) = c.get(id.as_str()) else { return false };
    if blind.contains(id.as_str()) {
        return false;
    }
    let Ok(md) = fs::symlink_metadata(p) else { return false };
    let (kind, live) = print_of(&md);
    if Some(&live) != ch.after.as_ref() {
        return false;
    }
    if kind == PathKind::Dir {
        let Ok(rd) = fs::read_dir(p) else { return false };
        for e in rd {
            let Ok(e) = e else { return false };
            if !unchanged_path(&e.path(), c, blind) {
                return false;
            }
        }
    }
    true
}

/// The same for a key: every current value was created with the same data, every current subkey is unchanged too.
pub(crate) fn unchanged_key(k: &RegPath, c: &Created, blind: &HashSet<&str>) -> bool {
    let id = target_key(&Target::RegKey { key: k.clone() });
    if !c.contains_key(id.as_str()) || blind.contains(id.as_str()) {
        return false;
    }
    let Ok(key) = registry::open(k, KEY_READ) else { return false };
    for item in key.enum_values() {
        let Ok((name, v)) = item else { return false };
        let val = registry::to_val(name.clone(), v);
        let vid = target_key(&Target::RegValue { key: k.clone(), name });
        let (Some(ch), Ok(print)) = (c.get(vid.as_str()), value_print(&val)) else { return false };
        if ch.after.as_ref() != Some(&print) {
            return false;
        }
    }
    for n in key.enum_keys() {
        let Ok(n) = n else { return false };
        if !unchanged_key(&k.child(&n), c, blind) {
            return false;
        }
    }
    true
}

#[cfg(test)]
mod tests {
    use super::*;
    use winreg::enums::KEY_ALL_ACCESS;

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

    fn listed(key: &str, name: &str, version: &str) -> InstalledApp {
        InstalledApp {
            id: format!("HKCU64:{key}"),
            key_name: key.into(),
            sources: vec![key_path(key)],
            display_name: name.into(),
            display_version: Some(version.into()),
            publisher: None,
            install_location: Some(PathBuf::from(r"C:\PF\Lab Trace")),
            display_icon: None,
            uninstall_string: Some(r#""C:\PF\Lab Trace\unins.exe" /S"#.into()),
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
    fn key_path(key: &str) -> RegPath {
        RegPath::new(Hive::Hkcu, View::V64, format!(r"Software\Lab\Uninstall\{key}"))
    }
    fn journal(id: &str, link: TraceLink) -> TraceJournal {
        TraceJournal {
            schema: TRACE_SCHEMA,
            id: id.into(),
            created_ms: 5,
            finished_ms: 9,
            installer: Launch { raw: r"C:\x\setup.exe".into(), exe: PathBuf::from(r"C:\x\setup.exe"), args: String::new(), argv: vec![], msi_product: None },
            native: Some(NativeRun { exit_code: Some(0), ..Default::default() }),
            link,
            objects: 3,
            before_ms: 1,
            after_ms: 2,
            unreadable: vec![r"path:c:\locked".into()],
            changes: vec![TraceChange { id: "key:hkcu64:software\\v".into(), change: Change::Created, target: Target::RegKey { key: key("Software\\V") }, before: None, after: Some(Print::Key {}), previous: None, noise: false }],
        }
    }

    /// A sandbox environment under a temp dir whose test registry subtree is removed on drop.
    struct Sb {
        env: Env,
        _dir: tempfile::TempDir,
    }
    impl Sb {
        fn new(tag: &str) -> Sb {
            let dir = tempfile::tempdir().unwrap();
            Sb { env: Env::sandbox(dir.path(), &format!("trace_unit_{tag}_{}", std::process::id())), _dir: dir }
        }
    }
    impl Drop for Sb {
        fn drop(&mut self) {
            let root = self.env.software_roots[0].path.rsplit_once('\\').unwrap().0.to_string();
            let _ = registry::delete_key(&RegPath::new(Hive::Hkcu, View::V64, root));
        }
    }

    #[test]
    fn journal_integrity() {
        let sb = Sb::new("integrity");
        let env = &sb.env;
        let j = journal("tr-100", TraceLink::NoProgram {});
        let path = save(env, &j).unwrap();
        assert_eq!(serde_json::to_value(load(env, "tr-100").unwrap()).unwrap(), serde_json::to_value(&j).unwrap(), "roundtrip");
        let good = fs::read(&path).unwrap();
        let head_end = good.iter().position(|&b| b == b'\n').unwrap();
        assert!(good.starts_with(b"uniinstaller-trace 1 sha256:"));
        assert_eq!(head_end, "uniinstaller-trace 1 sha256:".len() + 64);
        let err = |env: &Env, id: &str| load(env, id).unwrap_err().0;
        // one flipped byte of the body
        let mut bad = good.clone();
        bad[head_end + 20] ^= 1;
        fs::write(&path, &bad).unwrap();
        assert!(err(env, "tr-100").contains("checksum"), "{}", err(env, "tr-100"));
        // a newer header version, even with a matching checksum
        let newer = [b"uniinstaller-trace 2".as_slice(), &good[b"uniinstaller-trace 1".len()..]].concat();
        fs::write(&path, &newer).unwrap();
        assert!(err(env, "tr-100").contains("newer"), "{}", err(env, "tr-100"));
        // a newer schema inside the body, with a matching checksum
        let mut jn = j.clone();
        jn.schema = TRACE_SCHEMA + 1;
        let body = serde_json::to_vec(&jn).unwrap();
        fs::write(&path, [format!("uniinstaller-trace 1 sha256:{}\n", sha256_hex(&body).unwrap()).as_bytes(), &body].concat()).unwrap();
        assert!(err(env, "tr-100").contains("newer"), "{}", err(env, "tr-100"));
        // not a journal at all
        fs::write(&path, b"{\"schema\":1}").unwrap();
        assert!(err(env, "tr-100").contains("bad header"));
        fs::write(&path, b"uniinstaller-trace 1 md5:00\n{}").unwrap();
        assert!(err(env, "tr-100").contains("bad header"));
        // valid JSON of the wrong shape, with a matching checksum
        fs::write(&path, [format!("uniinstaller-trace 1 sha256:{}\n", sha256_hex(b"{}").unwrap()).as_bytes(), b"{}"].concat()).unwrap();
        assert!(load(env, "tr-100").is_err());
        // a journal copied under another name
        fs::write(&path, &good).unwrap();
        fs::copy(&path, path.with_file_name("tr-101.json")).unwrap();
        assert!(err(env, "tr-101").contains("does not match"), "{}", err(env, "tr-101"));
        // ids
        for ok in ["tr-1", "tr-1731800000000"] {
            assert!(valid_trace_id(ok).is_ok(), "{ok}");
        }
        for bad in ["", "tr-", "tr-1a", r"..\x", "TR-1", "op-1", "tr-123456789012345678901", "tr--1", r"tr-1\..\x"] {
            assert!(valid_trace_id(bad).is_err(), "{bad}");
            assert!(load(env, bad).is_err());
        }
        assert!(!path.with_file_name("tr-100.json.tmp").exists(), "no temp file is left behind");
    }

    #[test]
    fn trust_rules() {
        let t = listed("A", "Lab Trace", "1.0");
        assert_eq!(trust(&t, &t), None);
        let mut a = t.clone();
        a.display_version = Some("1.1".into());
        assert_eq!(trust(&t, &a), Some(Distrust::VersionChanged));
        let mut a = t.clone();
        a.install_location = Some(PathBuf::from(r"c:\pf\lab trace\"));
        assert_eq!(trust(&t, &a), None, "the folder is compared normalised");
        a.install_location = Some(PathBuf::from(r"C:\PF\Other"));
        assert_eq!(trust(&t, &a), Some(Distrust::FolderChanged));
        a.install_location = None;
        assert_eq!(trust(&t, &a), Some(Distrust::FolderChanged));
        let mut a = t.clone();
        a.uninstall_string = Some(format!("  {}  ", t.uninstall_string.as_deref().unwrap().to_uppercase()));
        assert_eq!(trust(&t, &a), None, "trimmed and case-insensitive");
        a.uninstall_string = Some(r"C:\PF\Lab Trace\other.exe".into());
        assert_eq!(trust(&t, &a), Some(Distrust::UninstallerChanged));
        // the order: version, then folder, then the command
        a.display_version = Some("2".into());
        a.install_location = None;
        assert_eq!(trust(&t, &a), Some(Distrust::VersionChanged));
    }

    fn set(k: &RegPath, name: &str, text: &str) {
        registry::set_string(&registry::create(k, KEY_ALL_ACCESS).unwrap(), name, text, false).unwrap();
    }

    fn modified(k: &RegPath, name: &str, prev: RegVal) -> TraceChange {
        let t = Target::RegValue { key: k.clone(), name: name.into() };
        TraceChange { id: target_key(&t), change: Change::Modified, target: t, before: None, after: None, previous: Some(prev), noise: false }
    }

    #[test]
    fn previous_kept_only_when_attributable() {
        let sb = Sb::new("previous");
        let env = &sb.env;
        let dirs = [PathBuf::from(r"C:\PF\Lab Trace")];
        let prev = val("x", 1, b"o\0");
        let keep = |c: &TraceChange| keep_previous(env, &dirs, c);
        let run = &env.run_roots[0];
        set(run, "Tool", r#""C:\PF\Lab Trace\t.exe" /tray"#);
        assert!(keep(&modified(run, "Tool", prev.clone())), "a Run value that now points into the program's folder");
        set(run, "Other", r"C:\Elsewhere\o.exe");
        assert!(!keep(&modified(run, "Other", prev.clone())), "a Run value that points elsewhere");
        let vendor = env.software_roots[0].child("Vendor");
        set(&vendor, "Handler", r"C:\PF\Lab Trace\h.exe");
        set(&vendor, "Mode", "traced");
        assert!(keep(&modified(&vendor, "Handler", prev.clone())), "a vendor value that points into the folder");
        assert!(!keep(&modified(&vendor, "Mode", prev.clone())), "a vendor value with unrelated text");
        let entry = env.uninstall_roots[0].child("Foreign");
        set(&entry, "DisplayIcon", r"C:\PF\Lab Trace\i.ico");
        assert!(!keep(&modified(&entry, "DisplayIcon", prev.clone())), "an Uninstall entry is outside the allowed shapes");
        let mut c = modified(run, "Tool", prev.clone());
        c.change = Change::Created;
        assert!(!keep(&c), "only a Modified change");
        c.change = Change::Modified;
        c.previous = None;
        assert!(!keep(&c), "nothing to keep");
        assert!(!keep(&modified(run, "Gone", prev.clone())), "a value that cannot be read");
        assert!(!keep_previous(env, &[], &modified(run, "Tool", prev.clone())), "no folder, no attribution");
        assert!(!keep(&modified(run, "Tool", val("x", 99, b""))), "an unknown type");
    }

    #[test]
    fn app_dirs_are_the_programs_own_folders() {
        let sb = Sb::new("dirs");
        let env = &sb.env;
        let pf = env.folders.program_files[0].clone();
        let mut a = listed("A", "Lab Trace", "1");
        fs::create_dir_all(pf.join("Vendor").join("Lab Trace")).unwrap();
        fs::write(pf.join("Vendor").join("Lab Trace").join("unins.exe"), b"MZ").unwrap();
        a.install_location = Some(pf.join("Vendor").join("Lab Trace"));
        a.uninstall_string = Some(format!("\"{}\" /S", pf.join("Vendor").join("Lab Trace").join("unins.exe").display()));
        a.display_icon = Some(format!("{},0", pf.join("Vendor").join("Lab Trace").join("bin").join("t.exe").display()));
        let mut d = app_dirs(env, &a);
        d.sort();
        assert_eq!(d, [pf.join("Vendor").join("Lab Trace"), pf.join("Vendor").join("Lab Trace"), pf.join("Vendor").join("Lab Trace").join("bin")]);
        // a folder the program must not claim: a protected root, the Windows folder, a drive root, a relative path
        for bad in [pf.clone(), env.folders.windows_dir.join("System32"), PathBuf::from(r"C:\"), PathBuf::from(r"rel\dir")] {
            a.install_location = Some(bad.clone());
            a.uninstall_string = None;
            a.display_icon = None;
            assert!(app_dirs(env, &a).is_empty(), "{}", bad.display());
        }
    }

    #[test]
    fn unchanged_checks_fail_closed() {
        let t = tempfile::tempdir().unwrap();
        let root = canonical(t.path()).unwrap();
        let (dir, f1) = (root.join("app"), root.join("app").join("a.txt"));
        fs::create_dir_all(&dir).unwrap();
        fs::write(&f1, b"x").unwrap();
        let mk = |p: &Path| {
            let (kind, print) = print_of(&fs::symlink_metadata(p).unwrap());
            let target = Target::Path { path: p.to_path_buf(), kind };
            TraceChange { id: target_key(&target), change: Change::Created, target, before: None, after: Some(print), previous: None, noise: false }
        };
        let mut j = journal("tr-1", TraceLink::NoProgram {});
        j.changes = vec![mk(&dir), mk(&f1)];
        let c = created(&j);
        let none = HashSet::new();
        assert!(unchanged_path(&dir, &c, &none), "exactly what was created");
        assert!(unchanged_path(&f1, &c, &none));
        // blind: the folder id is unreadable in the journal
        let id = format!("path:{}", norm(&dir));
        let blind: HashSet<&str> = HashSet::from([id.as_str()]);
        assert!(!unchanged_path(&dir, &c, &blind));
        assert!(unchanged_path(&f1, &c, &blind), "a file below it is judged on its own id (the scan never emits it separately)");
        // a child that the install did not create
        fs::write(dir.join("new.txt"), b"y").unwrap();
        assert!(!unchanged_path(&dir, &c, &none), "a new child");
        fs::remove_file(dir.join("new.txt")).unwrap();
        assert!(unchanged_path(&dir, &c, &none));
        // a changed child, and a deleted one (subset semantics)
        fs::write(&f1, b"xx").unwrap();
        assert!(!unchanged_path(&dir, &c, &none), "a changed child");
        fs::remove_file(&f1).unwrap();
        assert!(unchanged_path(&dir, &c, &none), "entries deleted since are fine");
        assert!(!unchanged_path(&f1, &c, &none), "a missing path is not unchanged");
        assert!(!unchanged_path(&root.join("elsewhere"), &c, &none), "never created");

        // keys: every value and subkey must have been created
        let sb = Sb::new("unchanged");
        let k = sb.env.software_roots[0].child("Created");
        set(&k, "a", "1");
        set(&k.child("Sub"), "b", "2");
        let kt = |k: &RegPath| Target::RegKey { key: k.clone() };
        let ch = |t: Target, print: Print| TraceChange { id: target_key(&t), change: Change::Created, target: t, before: None, after: Some(print), previous: None, noise: false };
        let vt = |k: &RegPath, n: &str| (Target::RegValue { key: k.clone(), name: n.into() }, value_print(&registry::read_value(k, n).unwrap()).unwrap());
        let (va, pa) = vt(&k, "a");
        let (vb, pb) = vt(&k.child("Sub"), "b");
        let mut j = journal("tr-2", TraceLink::NoProgram {});
        j.changes = vec![ch(kt(&k), Print::Key {}), ch(kt(&k.child("Sub")), Print::Key {}), ch(va, pa), ch(vb, pb)];
        let c = created(&j);
        assert!(unchanged_key(&k, &c, &none));
        set(&k, "extra", "x");
        assert!(!unchanged_key(&k, &c, &none), "a value the install did not create");
        registry::delete_value(&k, "extra").unwrap();
        set(&k, "a", "changed");
        assert!(!unchanged_key(&k, &c, &none), "a value with other data");
        set(&k, "a", "1");
        assert!(unchanged_key(&k, &c, &none));
        set(&k.child("Sub").child("Deeper"), "z", "1");
        assert!(!unchanged_key(&k, &c, &none), "a subkey the install did not create");
        let sub_id = target_key(&kt(&k.child("Sub")));
        let blind: HashSet<&str> = HashSet::from([sub_id.as_str()]);
        registry::delete_key(&k.child("Sub").child("Deeper")).unwrap();
        assert!(!unchanged_key(&k, &c, &blind), "a blind subkey");
        assert!(!unchanged_key(&k.child("Missing"), &c, &none), "an unopenable key");
    }
}
