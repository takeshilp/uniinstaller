//! Leftover scan: install-dir anchor, candidate collection from evidence, hard blocks, scoring -> Plan.
//! Read-only: registry opens use KEY_READ, files are inspected through metadata and `FILE_READ_ATTRIBUTES`.
use crate::command::{parse_uninstall, split_command};
use crate::env::Env;
use crate::inventory::icon_path;
use crate::model::*;
use crate::ops::target_key;
use crate::paths::{self, file_id, has_doc_ext, is_canonical, is_drive_root, is_inside, is_local_abs, is_reparse, norm, same_or_inside};
use crate::registry::{self, read_string};
use crate::safety::*;
use crate::trace::{self, value_print};
use crate::{Result, now_ms, shortcuts};
use std::collections::HashSet;
use std::fs;
use std::path::{Path, PathBuf};
use winreg::enums::*;

// shortcut: little leftover coverage for MSI apps with an empty InstallLocation, add MSI component queries later.
// shortcut: install dirs given as 8.3, trailing-dot, junction or SUBST paths are rejected, so those apps get no
// file leftovers; accept the alias when its canonical form is fully verified, if users hit it.

const STOP_NAMES: &[&str] = &[
    "app", "application", "program", "programs", "setup", "tools", "update", "updater", "common", "shared", "runtime", "driver", "drivers",
    "microsoft", "windows", "data", "temp", "cache", "user", "users", "documents", "desktop", "system",
];
const ARCH_TOKENS: &[&str] = &["x64", "x86", "64-bit", "32-bit", "amd64"];
const PUBLISHER_SUFFIXES: &[&str] = &[", inc.", " inc.", " llc", " ltd.", " gmbh", " corporation", " corp."];

fn usable_name(s: &str) -> bool {
    let low = s.to_lowercase();
    s.chars().count() >= 3
        && !STOP_NAMES.contains(&low.as_str())
        && !s.contains(['\\', '/', ':', '*', '?', '"', '<', '>', '|'])
        && s != "."
        && s != ".."
        && !s.ends_with('.')
        && !s.ends_with(' ')
}

fn is_version_token(t: &str) -> bool {
    let t = t.strip_prefix(['v', 'V']).unwrap_or(t);
    !t.is_empty() && t.starts_with(|c: char| c.is_ascii_digit()) && t.chars().all(|c| c.is_ascii_digit() || c == '.')
}

fn push_unique(v: &mut Vec<String>, s: String) {
    if usable_name(&s) && !v.iter().any(|x| x.to_lowercase() == s.to_lowercase()) {
        v.push(s);
    }
}

/// Product names: the trimmed display name plus a variant without trailing `( ... )` groups, versions and arch tokens.
pub fn name_variants(display: &str) -> Vec<String> {
    let full = display.trim().to_string();
    let mut s = full.clone();
    loop {
        let t = s.trim_end().to_string();
        if t.ends_with(')')
            && let Some(i) = t.rfind('(')
        {
            s = t[..i].to_string();
            continue;
        }
        match t.rsplit_once(char::is_whitespace) {
            Some((head, last)) if is_version_token(last) || ARCH_TOKENS.contains(&last.to_lowercase().as_str()) => s = head.to_string(),
            _ => {
                s = t;
                break;
            }
        }
    }
    let mut out = Vec::new();
    push_unique(&mut out, full);
    push_unique(&mut out, s);
    out
}

/// Publisher names: trimmed, plus a variant without a trailing company suffix.
pub fn publisher_variants(p: &str) -> Vec<String> {
    let full = p.trim().to_string();
    let low = full.to_lowercase();
    let mut out = Vec::new();
    push_unique(&mut out, full.clone());
    for suf in PUBLISHER_SUFFIXES {
        if low.ends_with(suf) {
            push_unique(&mut out, full[..full.len() - suf.len()].trim_end_matches(',').trim().to_string());
        }
    }
    out
}

fn eq_any(s: &str, variants: &[String]) -> bool {
    variants.iter().any(|v| v.to_lowercase() == s.to_lowercase())
}

/// (publisher, name) pairs for settings locations `<root>\<name>` and `<root>\<publisher>\<name>`, every name variant.
/// The same pairs name the target's candidates and other apps' anchors.
fn name_pairs(app: &InstalledApp) -> Vec<(Option<String>, String)> {
    let names = name_variants(&app.display_name);
    let pubs = app.publisher.as_deref().map(publisher_variants).unwrap_or_default();
    let mut v: Vec<(Option<String>, String)> = names.iter().map(|n| (None, n.clone())).collect();
    v.extend(pubs.iter().flat_map(|p| names.iter().map(move |n| (Some(p.clone()), n.clone()))));
    v
}

fn data_dir(root: &Path, p: Option<&str>, n: &str) -> PathBuf {
    p.map_or_else(|| root.join(n), |p| root.join(p).join(n))
}

/// None when the first component is a reserved vendor key (Microsoft, Classes, ...).
fn data_key(root: &RegPath, p: Option<&str>, n: &str) -> Option<RegPath> {
    let first = p.unwrap_or(n);
    (!RESERVED_SOFTWARE.contains(&first.to_lowercase().as_str())).then(|| p.map_or_else(|| root.child(n), |p| root.child(p).child(n)))
}

fn ev(code: EvidenceCode, points: i32, detail: impl Into<String>) -> Evidence {
    Evidence { code, points, detail: detail.into() }
}

/// Other apps' anchors: install dir, uninstaller exe and icon (canonical where they exist), plus their existing settings
/// folders and Software keys under the same name rule as sections E/F, including the version-free variant.
// shortcut: a stale entry of an older version of the same product also blocks the target's version-free settings (fail closed).
pub fn anchors_of(env: &Env, others: &[InstalledApp]) -> Anchors {
    let mut a = Anchors::default();
    for o in others {
        if let Some(d) = o.install_location.as_deref().filter(|d| is_local_abs(d)) {
            a.dirs.push(canon_if_exists(d));
        }
        if let Some(l) = o.uninstall_string.as_deref().and_then(|s| parse_uninstall(s, &env.folders.system_dir, o.product_code.as_deref()).ok()) {
            a.files.push(canon_if_exists(&l.exe));
            // No InstallLocation: the uninstaller's folder when the icon sits beside it, as `find_anchor` does for the target.
            // shortcut: an app with neither InstallLocation nor such a folder is not seen by the reference rule; widen the
            // derivation (icon folder, Run or App Paths entries) if a lab run or a user report shows one slipping through.
            if o.install_location.as_deref().is_none_or(|d| d.as_os_str().is_empty())
                && let Some(p) = l.exe.parent()
                && icon_path(o).as_deref().and_then(Path::parent).is_some_and(|ip| norm(ip) == norm(p))
                && is_local_abs(p)
                && !is_inside(p, &env.folders.windows_dir)
            {
                a.derived_dirs.push(canon_if_exists(p));
            }
        }
        if let Some(i) = icon_path(o).filter(|i| is_local_abs(i)) {
            a.files.push(canon_if_exists(&i));
        }
        // Another app's Uninstall entry is its key too: a trace could otherwise propose it.
        a.keys.extend(o.sources.iter().cloned());
        for (p, n) in name_pairs(o) {
            a.data_dirs.extend(env.folders.app_data.iter().map(|r| data_dir(r, p.as_deref(), &n)).filter(|d| d.is_dir()));
            a.keys.extend(env.software_roots.iter().filter_map(|r| data_key(r, p.as_deref(), &n)).filter(registry::exists));
        }
    }
    a
}

struct Anchor {
    dir: Option<PathBuf>,
    status: DirStatus,
    corroborated: bool,
}

fn rejected(dir: &Path, reason: impl Into<String>) -> Anchor {
    Anchor { dir: Some(dir.to_path_buf()), status: DirStatus::Rejected { reason: reason.into() }, corroborated: false }
}

fn find_anchor(env: &Env, app: &InstalledApp, launch: Option<&Launch>, anchors: &Anchors) -> Anchor {
    let icon = icon_path(app);
    let dir = match app.install_location.as_deref().filter(|d| !d.as_os_str().is_empty()) {
        Some(d) => d.to_path_buf(),
        None => {
            let candidate = launch.and_then(|l| l.exe.parent()).filter(|p| icon.as_deref().and_then(Path::parent).is_some_and(|ip| norm(ip) == norm(p)) && !is_inside(p, &env.folders.windows_dir));
            match candidate {
                Some(p) => p.to_path_buf(),
                None => return Anchor { dir: None, status: DirStatus::NotSet {}, corroborated: false },
            }
        }
    };
    let d = dir.as_path();
    if !is_local_abs(d) {
        return rejected(d, "not a local absolute path");
    }
    if is_drive_root(d) {
        return rejected(d, "drive root");
    }
    match real_folders() {
        Err(e) => return rejected(d, format!("cannot verify: {e}")),
        Ok(real) => {
            if let Some(why) = protected_reason(real, d, Group::ProgramFiles) {
                return rejected(d, why);
            }
        }
    }
    if let Some(why) = protected_reason(&env.folders, d, Group::ProgramFiles) {
        return rejected(d, why);
    }
    if !is_canonical(d) {
        return rejected(d, "alias: 8.3 name, trailing dot or space, junction, symlink or SUBST in the path");
    }
    if is_reparse(d).unwrap_or(false) {
        return rejected(d, "reparse point");
    }
    if anchors.dirs.iter().any(|o| norm(o) == norm(d)) {
        return rejected(d, "another program has the same install folder");
    }
    if std::env::current_exe().ok().is_some_and(|e| same_or_inside(&e, d)) {
        return rejected(d, "contains Uniinstaller itself");
    }
    let corroborated = launch.and_then(|l| l.exe.parent()).is_some_and(|p| norm(p) == norm(d)) || icon.as_deref().and_then(Path::parent).is_some_and(|p| norm(p) == norm(d));
    Anchor { dir: Some(d.to_path_buf()), status: DirStatus::Confirmed {}, corroborated }
}

/// Evaluation context shared by scan and apply, so both apply identical rules.
pub struct Ctx<'a> {
    pub env: &'a Env,
    pub app: &'a InstalledApp,
    pub launch: Option<&'a Launch>,
    /// The confirmed install dir only.
    pub install_dir: Option<&'a Path>,
    pub anchors: &'a Anchors,
    pub data_volume: std::result::Result<u32, String>,
}

pub struct Eval {
    pub blocks: Vec<Block>,
    pub ident: Ident,
    pub size: u64,
    pub user_data: bool,
}

/// Volume serial of the drive that holds `data_dir` (the quarantine lives there).
// shortcut: other-volume leftovers are blocked (see paths::move_path), per-volume quarantine later.
pub fn data_volume(env: &Env) -> std::result::Result<u32, String> {
    let mut p = env.data_dir.clone();
    while !p.exists() {
        p = p.parent().ok_or("data dir has no existing ancestor")?.to_path_buf();
    }
    file_id(&p).map(|i| i.volume).map_err(|e| e.to_string())
}

fn block(code: BlockCode, detail: impl Into<String>) -> Block {
    Block { code, detail: detail.into() }
}

fn unverifiable(mut blocks: Vec<Block>, why: impl std::fmt::Display) -> Eval {
    blocks.push(block(BlockCode::Unverifiable, why.to_string()));
    Eval { blocks, ident: Ident::None {}, size: 0, user_data: false }
}

/// All hard blocks plus the identity snapshot for one target. Any failure fails closed (`Unverifiable`).
pub fn evaluate(ctx: &Ctx, group: Group, target: &Target) -> Eval {
    match target {
        Target::Path { path, .. } => eval_path(ctx, group, path),
        Target::RegKey { key } => {
            let mut blocks = registry_blocks(ctx.env, target);
            if ctx.app.sources.iter().any(|s| s.same(key))
                && let Some(l) = ctx.launch
                && l.exe.exists()
                && !is_inside(&l.exe, &ctx.env.folders.windows_dir)
            {
                blocks.push(block(BlockCode::AppStillInstalled, "the program's uninstaller still exists"));
            }
            if let Some(why) = ctx.anchors.key_holding(key) {
                blocks.push(block(BlockCode::SharedWithOtherApp, why));
            }
            match registry::capture(key) {
                Ok(node) => {
                    // The target's own Uninstall entry may name another app's folder (a launcher's uninstaller): not shared.
                    if !ctx.app.sources.iter().any(|s| s.same(key))
                        && let Some(why) = tree_refers(ctx, &node)
                    {
                        blocks.push(block(BlockCode::SharedWithOtherApp, why));
                    }
                    Eval { blocks, ident: Ident::Key { node }, size: 0, user_data: false }
                }
                Err(e) if e.kind() == std::io::ErrorKind::FileTooLarge => {
                    blocks.push(block(BlockCode::TooLarge, "more than 5000 values and subkeys"));
                    Eval { blocks, ident: Ident::None {}, size: 0, user_data: false }
                }
                Err(e) => unverifiable(blocks, e),
            }
        }
        Target::RegValue { key, name } | Target::RegRevert { key, name, .. } => {
            let mut blocks = registry_blocks(ctx.env, target);
            if let Some(why) = ctx.anchors.key_inside(key) {
                blocks.push(block(BlockCode::SharedWithOtherApp, why));
            }
            match registry::read_value(key, name) {
                Ok(val) => {
                    if let Some(why) = value_refers(ctx, &val) {
                        blocks.push(block(BlockCode::SharedWithOtherApp, why));
                    }
                    Eval { blocks, ident: Ident::Value { val }, size: 0, user_data: false }
                }
                Err(e) => unverifiable(blocks, e),
            }
        }
    }
}

fn eval_path(ctx: &Ctx, group: Group, path: &Path) -> Eval {
    let mut blocks = path_blocks(ctx.env, path, group, ctx.install_dir, ctx.anchors);
    // A shortcut whose target is another app's file or folder belongs to that app (recomputed at apply too).
    if group == Group::Shortcuts {
        match shortcuts::resolve(path) {
            Some(t) => {
                if let Some(why) = ctx.anchors.covering(&t, ctx.install_dir) {
                    blocks.push(block(BlockCode::SharedWithOtherApp, why));
                }
            }
            None => blocks.push(block(BlockCode::Unverifiable, "the shortcut's target cannot be read")),
        }
    }
    let md = match fs::symlink_metadata(path) {
        Ok(m) => m,
        Err(e) => return unverifiable(blocks, e),
    };
    let id = match file_id(path) {
        Ok(i) => i,
        Err(e) => return unverifiable(blocks, e),
    };
    match &ctx.data_volume {
        Ok(v) if *v != id.volume => blocks.push(block(BlockCode::OtherVolume, "backup on another drive is not supported yet")),
        Err(e) => blocks.push(block(BlockCode::Unverifiable, format!("data folder volume unknown: {e}"))),
        _ => {}
    }
    let name = path.file_name().map(|n| n.to_string_lossy().to_lowercase()).unwrap_or_default();
    use std::os::windows::fs::MetadataExt;
    if md.file_attributes() & paths::REPARSE_ATTR != 0 {
        return Eval { blocks, ident: Ident::Link { id }, size: 0, user_data: false };
    }
    if md.is_dir() {
        let w = match paths::walk(path, 200_000) {
            Ok(w) => w,
            Err(e) => return unverifiable(blocks, e),
        };
        if w.truncated {
            blocks.push(block(BlockCode::TooLarge, "more than 200000 entries"));
        }
        if group == Group::ProgramFiles
            && ctx.install_dir.is_some_and(|d| is_inside(path, d))
            && let Some(u) = w.uninstallers.iter().find(|u| ctx.launch.is_none_or(|l| norm(u) != norm(&l.exe)))
        {
            let rel = u.strip_prefix(path).unwrap_or(u);
            blocks.push(block(BlockCode::SharedWithOtherApp, format!("contains its own uninstaller {}", rel.display())));
        }
        let user_data = w.user_data || DATA_DIR_NAMES.contains(&name.as_str());
        Eval { blocks, ident: Ident::Dir { id, print: w.print() }, size: w.bytes, user_data }
    } else {
        let user_data = has_doc_ext(&name);
        Eval { blocks, ident: Ident::File { id, size: md.len(), mtime: paths::mtime_ms(&md) }, size: md.len(), user_data }
    }
}

fn path_kind(p: &Path) -> Option<PathKind> {
    use std::os::windows::fs::MetadataExt;
    let md = fs::symlink_metadata(p).ok()?;
    Some(if md.file_attributes() & paths::REPARSE_ATTR != 0 {
        PathKind::Link
    } else if md.is_dir() {
        PathKind::Dir
    } else {
        PathKind::File
    })
}

struct Raw {
    group: Group,
    target: Target,
    evidence: Vec<Evidence>,
}

fn display_key(t: &Target) -> String {
    match t {
        Target::Path { path, .. } => path.to_string_lossy().to_lowercase(),
        Target::RegKey { key } => key.display().to_lowercase(),
        Target::RegValue { key, name } | Target::RegRevert { key, name, .. } => format!("{}\\{}", key.display(), name).to_lowercase(),
    }
}

/// Why a registry value's text points into another app's install dir, if it does.
fn value_refers(ctx: &Ctx, v: &RegVal) -> Option<String> {
    registry::val_text(v).and_then(|s| ctx.anchors.referenced_in(&ctx.env.folders, &s, ctx.install_dir)).map(|why| format!("value '{}' {why}", v.name))
}

/// The same for every value of a captured key tree.
// shortcut: a key or settings folder shared with another app is blocked whole, so the target's own values and files inside it
// are not offered; add per-value and per-file candidates if lab recall asks for them.
fn tree_refers(ctx: &Ctx, n: &RegNode) -> Option<String> {
    n.values.iter().find_map(|v| value_refers(ctx, v)).or_else(|| n.keys.iter().find_map(|k| tree_refers(ctx, k)))
}

fn value_points_inside(k: &winreg::RegKey, dir: &Path) -> bool {
    let needle = format!("{}\\", norm(dir));
    k.enum_values().flatten().any(|(name, _)| {
        read_string(k, &name, true).is_some_and(|v| {
            let low = v.trim().trim_matches('"').replace('/', "\\").to_lowercase();
            same_or_inside(Path::new(v.trim().trim_matches('"')), dir) || low.contains(&needle)
        })
    })
}

/// Whether `p` is, holds or lies inside the confirmed install folder.
fn near_dir(confirmed: Option<&Path>, p: &Path) -> bool {
    confirmed.is_some_and(|d| same_or_inside(p, d) || is_inside(d, p))
}

// shortcut: a trace-created folder or key that is blocked as a whole hides the heuristic children inside it (same class as the shared
// containers above); add per-child candidates if lab recall asks for them.
/// Section G: what a trusted trace journal says the install created.
struct TraceScan<'a> {
    env: &'a Env,
    j: &'a TraceJournal,
    created: trace::Created<'a>,
    blind: HashSet<&'a str>,
    /// The Uninstall keys of the program the journal is linked to.
    linked: Vec<&'a RegPath>,
    confirmed: Option<&'a Path>,
    out: Vec<Raw>,
}

impl TraceScan<'_> {
    fn evidence(&self) -> Vec<Evidence> {
        vec![ev(EvidenceCode::TraceCreated, W_TRACE_CREATED, format!("created by the traced install {}", self.j.id))]
    }

    fn path_group(&self, p: &Path) -> Group {
        let f = &self.env.folders;
        let is_lnk = p.extension().is_some_and(|e| e.eq_ignore_ascii_case("lnk"));
        if is_lnk && (f.start_menu.iter().any(|s| is_inside(p, s)) || p.parent().is_some_and(|d| f.desktops.iter().any(|x| norm(x) == norm(d)))) {
            Group::Shortcuts
        } else if f.program_files.iter().any(|z| is_inside(p, z)) || self.confirmed.is_some_and(|d| same_or_inside(p, d)) {
            Group::ProgramFiles
        } else {
            Group::Data
        }
    }

    fn reg_group(&self, k: &RegPath) -> Group {
        let env = self.env;
        let under = |r: &RegPath| k.same(r) || k.below(r).is_some();
        if env.uninstall_roots.iter().chain(&env.app_paths_roots).chain(&env.run_roots).any(under) {
            Group::Registry
        } else if env.software_roots.iter().any(|r| k.below(r).is_some()) {
            Group::Data
        } else {
            Group::Registry
        }
    }

    /// A created file or folder: offered whole when it is exactly what the install made, otherwise (only near the install folder, or
    /// inside a protected folder such as a Start Menu) its created children are considered one by one.
    fn emit_path(&mut self, p: &Path) {
        let Some(kind) = path_kind(p) else { return };
        let group = self.path_group(p);
        let protected = protected_reason(&self.env.folders, p, group).is_some();
        if !protected && trace::unchanged_path(p, &self.created, &self.blind) {
            let evidence = self.evidence();
            self.out.push(Raw { group, target: Target::Path { path: p.to_path_buf(), kind }, evidence });
        } else if kind == PathKind::Dir && (protected || near_dir(self.confirmed, p)) {
            let Ok(rd) = fs::read_dir(p) else { return };
            for e in rd {
                let Ok(e) = e else { return };
                let child = e.path();
                if self.created.get(format!("path:{}", norm(&child)).as_str()).is_some_and(|c| !c.noise) {
                    self.emit_path(&child);
                }
            }
        }
    }

    fn emit_key(&mut self, k: &RegPath) {
        // Another program's Uninstall entry is never ours.
        if trace::one_below_uninstall(self.env, k) && !self.linked.iter().any(|s| s.same(k)) {
            return;
        }
        if !registry::exists(k) {
            return;
        }
        if trace::unchanged_key(k, &self.created, &self.blind) {
            let (group, evidence) = (self.reg_group(k), self.evidence());
            self.out.push(Raw { group, target: Target::RegKey { key: k.clone() }, evidence });
        } else if let Ok(rk) = registry::open(k, KEY_READ) {
            // A changed key's own values are never offered; its created subkeys are looked at one by one.
            let mut subs = Vec::new();
            for n in rk.enum_keys() {
                let Ok(n) = n else { return };
                subs.push(k.child(&n));
            }
            for s in subs {
                let id = target_key(&Target::RegKey { key: s.clone() });
                if self.created.get(id.as_str()).is_some_and(|c| !c.noise) {
                    self.emit_key(&s);
                }
            }
        }
    }

    fn emit(&mut self, c: &TraceChange) {
        match &c.target {
            Target::Path { path, .. } => self.emit_path(path),
            Target::RegKey { key } => self.emit_key(key),
            Target::RegValue { key, name } => {
                if let Ok(live) = registry::read_value(key, name)
                    && value_print(&live).ok() == c.after
                {
                    let (group, evidence) = (self.reg_group(key), self.evidence());
                    self.out.push(Raw { group, target: c.target.clone(), evidence });
                }
            }
            Target::RegRevert { .. } => {}
        }
    }
}

pub fn scan(env: &Env, app: &InstalledApp, launch: Option<&Launch>, others: &[InstalledApp], dry_run: bool, trace: Option<&TraceJournal>) -> Result<Plan> {
    let anchors = anchors_of(env, others);
    let anchor = find_anchor(env, app, launch, &anchors);
    let confirmed: Option<PathBuf> = matches!(anchor.status, DirStatus::Confirmed {}).then(|| anchor.dir.clone()).flatten();
    let corroborated = anchor.corroborated;
    let names = name_variants(&app.display_name);
    let pubs = app.publisher.as_deref().map(publisher_variants).unwrap_or_default();
    let mut raw: Vec<Raw> = Vec::new();

    let refers = |detail: String, missing: bool| -> Vec<Evidence> {
        let mut v = vec![ev(EvidenceCode::RefersToInstallDir, W_REFERS, detail)];
        if corroborated {
            v.push(ev(EvidenceCode::InstallDirCorroborated, W_CORROBORATED, "the install folder matches the uninstaller or icon location"));
        }
        if missing {
            v.push(ev(EvidenceCode::TargetMissing, W_TARGET_MISSING, "the referenced file no longer exists"));
        }
        v
    };

    // A. Install-dir children.
    if let Some(d) = &confirmed
        && d.is_dir()
        && let Ok(rd) = fs::read_dir(d)
    {
        let outside = !env.folders.program_files.iter().chain(&env.folders.app_data).any(|z| is_inside(d, z));
        for e in rd.flatten() {
            let p = e.path();
            let (Some(_), Some(kind)) = (p.to_str(), path_kind(&p)) else { continue };
            let mut evidence = vec![ev(EvidenceCode::InInstallDir, W_IN_INSTALL_DIR, "inside the program's install folder")];
            if outside {
                evidence.push(ev(EvidenceCode::OutsideKnownZones, W_OUTSIDE_ZONES, "the install folder is outside Program Files and AppData"));
            }
            raw.push(Raw { group: Group::ProgramFiles, target: Target::Path { path: p, kind }, evidence });
        }
    }

    // B. The DisplayIcon file outside the install dir. The uninstaller exe is never a candidate.
    if let Some(i) = icon_path(app)
        && is_local_abs(&i)
        && i.is_file()
        && confirmed.as_deref().is_none_or(|d| !is_inside(&i, d))
        && !is_inside(&i, &env.folders.windows_dir)
        && i.to_str().is_some()
    {
        raw.push(Raw {
            group: Group::ProgramFiles,
            target: Target::Path { path: i, kind: PathKind::File },
            evidence: vec![ev(EvidenceCode::ExactAnchor, W_EXACT_ANCHOR, "the program's registered icon file")],
        });
    }

    // C. Shortcuts that point into the install dir.
    if let Some(d) = &confirmed {
        let mut links = shortcuts::list_links(&env.folders.start_menu, 4);
        links.extend(shortcuts::list_links(&env.folders.desktops, 1));
        for lnk in links {
            if lnk.to_str().is_none() {
                continue;
            }
            let Some(target) = shortcuts::resolve(&lnk) else { continue };
            if !(same_or_inside(&target, d) || same_or_inside(&canon_if_exists(&target), d)) {
                continue;
            }
            let mut evidence = refers(format!("shortcut points to {}", target.display()), !target.exists());
            let stem = lnk.file_stem().map(|s| s.to_string_lossy().to_string()).unwrap_or_default();
            if eq_any(&stem, &names) {
                evidence.push(ev(EvidenceCode::ExactName, W_EXACT_NAME, "shortcut name equals the program name"));
            }
            let parent_name = lnk.parent().and_then(Path::file_name).map(|n| n.to_string_lossy().to_string()).unwrap_or_default();
            if eq_any(&parent_name, &pubs) {
                evidence.push(ev(EvidenceCode::PublisherMatch, W_PUBLISHER, "shortcut folder equals the publisher"));
            }
            raw.push(Raw { group: Group::Shortcuts, target: Target::Path { path: lnk, kind: PathKind::File }, evidence });
        }
    }

    // D. Registry: Run values, App Paths keys, the program's own uninstall keys.
    if let Some(d) = &confirmed {
        let needle = format!("{}\\", norm(d));
        for root in &env.run_roots {
            let Ok(k) = registry::open(root, KEY_READ) else { continue };
            let vnames: Vec<String> = k.enum_values().flatten().map(|(n, _)| n).filter(|n| !n.is_empty()).collect();
            for name in vnames {
                let Some(val) = read_string(&k, &name, true) else { continue };
                let hit = match split_command(&val, &env.folders.system_dir, &|p| p.is_file()) {
                    Ok((exe, _)) => same_or_inside(&exe, d).then(|| (exe.display().to_string(), !exe.exists())),
                    // No existing file matches any prefix: the referenced file is gone.
                    Err(_) => val.replace('/', "\\").to_lowercase().contains(&needle).then(|| (val.clone(), true)),
                };
                if let Some((what, missing)) = hit {
                    raw.push(Raw {
                        group: Group::Registry,
                        target: Target::RegValue { key: root.clone(), name },
                        evidence: refers(format!("autorun runs {what}"), missing),
                    });
                }
            }
        }
        for root in &env.app_paths_roots {
            let Ok(k) = registry::open(root, KEY_READ) else { continue };
            let mut subs: Vec<String> = k.enum_keys().flatten().collect();
            subs.sort();
            for s in subs {
                let Ok(sk) = k.open_subkey_with_flags(&s, KEY_READ) else { continue };
                let Some(def) = read_string(&sk, "", true) else { continue };
                let exe = PathBuf::from(def.trim().trim_matches('"'));
                if is_local_abs(&exe) && same_or_inside(&exe, d) {
                    raw.push(Raw {
                        group: Group::Registry,
                        target: Target::RegKey { key: root.child(&s) },
                        evidence: refers(format!("App Paths entry points to {}", exe.display()), !exe.exists()),
                    });
                }
            }
        }
    }
    for src in &app.sources {
        let Ok(k) = registry::open(src, KEY_READ) else { continue };
        let mut evidence = vec![ev(EvidenceCode::OwnUninstallEntry, W_OWN_ENTRY, "the program's own uninstall entry")];
        if let Some(d) = &confirmed {
            let loc = read_string(&k, "InstallLocation", true).map(PathBuf::from);
            let icon = read_string(&k, "DisplayIcon", true).map(|s| PathBuf::from(s.trim().trim_matches('"')));
            if [loc, icon].into_iter().flatten().any(|p| is_local_abs(&p) && same_or_inside(&p, d)) {
                evidence.extend(refers("the entry points into the install folder".into(), false));
            }
        }
        if launch.is_some_and(|l| !l.exe.exists()) {
            evidence.push(ev(EvidenceCode::TargetMissing, W_TARGET_MISSING, "the uninstaller no longer exists"));
        }
        raw.push(Raw { group: Group::Registry, target: Target::RegKey { key: src.clone() }, evidence });
    }

    // E and F. Settings and user data by exact name (Data group, never preselected).
    let pairs = name_pairs(app);
    for root in &env.folders.app_data {
        for (p, n) in &pairs {
            let path = data_dir(root, p.as_deref(), n);
            if path.to_str().is_none() || path_kind(&path) != Some(PathKind::Dir) {
                continue;
            }
            if let Some(d) = &confirmed
                && (same_or_inside(&path, d) || same_or_inside(d, &path))
            {
                continue;
            }
            let mut evidence = vec![ev(EvidenceCode::ExactName, W_EXACT_NAME, "folder name equals the program name")];
            if p.is_some() {
                evidence.push(ev(EvidenceCode::PublisherMatch, W_PUBLISHER, "parent folder equals the publisher"));
            }
            raw.push(Raw { group: Group::Data, target: Target::Path { path, kind: PathKind::Dir }, evidence });
        }
    }
    for root in &env.software_roots {
        for (p, n) in &pairs {
            let Some(key) = data_key(root, p.as_deref(), n) else { continue };
            let Ok(k) = registry::open(&key, KEY_READ) else { continue };
            let mut evidence = vec![ev(EvidenceCode::ExactName, W_EXACT_NAME, "key name equals the program name")];
            if p.is_some() {
                evidence.push(ev(EvidenceCode::PublisherMatch, W_PUBLISHER, "parent key equals the publisher"));
            }
            if let Some(d) = &confirmed
                && value_points_inside(&k, d)
            {
                evidence.extend(refers("a value points into the install folder".into(), false));
            }
            raw.push(Raw { group: Group::Data, target: Target::RegKey { key }, evidence });
        }
    }

    // G. A trusted trace journal: objects the traced install created and left unchanged (+100 near the install folder or with other
    // evidence, +50 elsewhere), and previous values it overwrote with a reference to this program (never preselected).
    if let Some(j) = trace {
        let created = trace::created(j);
        let mut topmost: Vec<&TraceChange> = created.values().copied().filter(|c| !c.noise && trace::parent_id(&c.target).is_none_or(|p| !created.contains_key(p.as_str()))).collect();
        topmost.sort_by(|a, b| a.id.cmp(&b.id));
        let linked: Vec<&RegPath> = match &j.link {
            TraceLink::Linked { app } => app.sources.iter().collect(),
            _ => vec![],
        };
        let mut g = TraceScan { env, j, created, blind: j.unreadable.iter().map(String::as_str).collect(), linked, confirmed: confirmed.as_deref(), out: vec![] };
        for c in topmost {
            g.emit(c);
        }
        for t in g.out {
            match raw.iter_mut().find(|r| target_key(&r.target) == target_key(&t.target)) {
                Some(r) => r.evidence.extend(t.evidence),
                None => raw.push(t),
            }
        }
        // Values the install overwrote: offered only while the live value is still the one the trace saw, and only when its text
        // points into this program's folder (anything else could be another program's write during the trace window).
        let mut protect: Vec<RegPath> = vec![];
        for m in j.changes.iter().filter(|m| m.change == Change::Modified && !m.noise) {
            let (Target::RegValue { key, name }, Some(prev)) = (&m.target, &m.previous) else { continue };
            let Ok(live) = registry::read_value(key, name) else { continue };
            if value_print(&live).ok() != m.after {
                continue; // changed since the trace
            }
            let Some(d) = confirmed.as_deref() else { continue };
            if !registry::val_text(&live).is_some_and(|t| text_refers_to(&t, d)) {
                continue; // not attributable: report only
            }
            protect.push(key.clone());
            // Windows shares App Paths between views (docs/bugs.md): the 64-bit copy is the same value.
            if key.view == View::V32
                && env.app_paths_roots.iter().any(|r| r.view == View::V32 && key.below(r).is_some())
                && env.app_paths_roots.iter().any(|r| r.hive == key.hive && r.view == View::V64)
            {
                continue;
            }
            raw.retain(|r| !matches!(&r.target, Target::RegValue { key: k, name: n } if k.same(key) && n.eq_ignore_ascii_case(name)));
            raw.push(Raw {
                group: Group::Revert,
                target: Target::RegRevert { key: key.clone(), name: name.clone(), previous: prev.clone() },
                evidence: vec![ev(EvidenceCode::TraceModified, W_TRACE_MODIFIED, "the trace recorded the value before the install")],
            });
        }
        // A key that held a value from before the install is not the program's: never offer to delete it.
        raw.retain(|r| !matches!(&r.target, Target::RegKey { key } if protect.iter().any(|p| p.same(key) || p.below(key).is_some())));
    }

    // Finish: drop nested path candidates (keep the outer one) and duplicates.
    let all_paths: Vec<PathBuf> = raw.iter().filter_map(|r| if let Target::Path { path, .. } = &r.target { Some(path.clone()) } else { None }).collect();
    raw.retain(|r| match &r.target {
        Target::Path { path, .. } => !all_paths.iter().any(|o| is_inside(path, o)),
        _ => true,
    });
    raw.sort_by_key(|r| (r.group, display_key(&r.target)));
    raw.dedup_by(|a, b| target_key(&a.target) == target_key(&b.target));

    let ctx = Ctx { env, app, launch, install_dir: confirmed.as_deref(), anchors: &anchors, data_volume: data_volume(env) };
    let candidates = raw
        .into_iter()
        .map(|r| {
            let e = evaluate(&ctx, r.group, &r.target);
            let mut evidence = r.evidence;
            if e.user_data {
                evidence.push(ev(EvidenceCode::UserDataLikely, W_USER_DATA, "looks like documents, saves or other user data"));
            }
            // Trace-only evidence away from the program's folder is Review, never preselected (a background writer looks the same).
            let heuristic = evidence.iter().any(|x| x.points > 0 && x.code != EvidenceCode::TraceCreated);
            let is_near = matches!(&r.target, Target::Path { path, .. } if near_dir(confirmed.as_deref(), path));
            if !heuristic && !is_near {
                for x in evidence.iter_mut().filter(|x| x.code == EvidenceCode::TraceCreated) {
                    x.points = W_TRACE_FAR;
                    x.detail.push_str(" (away from the program's folder)");
                }
            }
            let score: i32 = evidence.iter().map(|x| x.points).sum();
            let tier = tier(score, !e.blocks.is_empty());
            Candidate {
                id: target_key(&r.target),
                group: r.group,
                target: r.target,
                size: e.size,
                evidence,
                blocks: e.blocks,
                score,
                tier,
                selected: default_selected(tier, r.group, e.user_data),
                ident: e.ident,
            }
        })
        .collect();

    Ok(Plan {
        schema: SCHEMA,
        created_ms: now_ms(),
        app_id: app.id.clone(),
        dry_run,
        install_dir: anchor.dir,
        install_dir_status: anchor.status,
        corroborated,
        still_running: vec![],
        candidates,
        trace: None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn name_variants_strip_version_arch_and_stop_words() {
        assert_eq!(name_variants("7-Zip 26.05 (x64)"), vec!["7-Zip 26.05 (x64)", "7-Zip"]);
        assert_eq!(name_variants("Foo Bar v2.1 x64"), vec!["Foo Bar v2.1 x64", "Foo Bar"]);
        assert_eq!(name_variants("Sandbox Notes"), vec!["Sandbox Notes"]);
        assert_eq!(name_variants("Setup"), Vec::<String>::new());
        assert_eq!(name_variants("Updater 3.0"), vec!["Updater 3.0"], "the stripped variant is a stop word");
        assert_eq!(name_variants("Ab"), Vec::<String>::new());
        assert_eq!(publisher_variants("Acme, Inc."), vec!["Acme"], "a name ending with a dot is dropped");
        assert_eq!(publisher_variants("Acme Corporation"), vec!["Acme Corporation", "Acme"]);
        assert_eq!(publisher_variants("Sandbox Soft"), vec!["Sandbox Soft"]);
    }

    #[test]
    fn name_variants_reject_path_characters() {
        assert!(name_variants(r"Foo\Bar").is_empty());
        assert!(name_variants("Foo: Bar").is_empty());
        assert!(name_variants("a*b?c").is_empty());
        assert!(name_variants("Foo.").is_empty());
        assert!(name_variants("...").is_empty());
        assert_eq!(name_variants("Foo (beta)"), vec!["Foo (beta)", "Foo"]);
    }
}
