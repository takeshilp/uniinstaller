//! Serde types shared by the CLI and the GUI. Rust sends codes; the UI maps them to Russian.
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

/// Operations and plans. Schema-1 (0.1.x) manifests still load; a newer one is refused (`ops::load`).
// shortcut: there is no downgrade path: 0.1.x lists a schema-2 manifest that uses the new variants as Broken; keep new variants additive.
pub const SCHEMA: u32 = 2;
/// Trace journals (`trace::load` refuses a newer one).
pub const TRACE_SCHEMA: u32 = 1;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum Hive {
    Hklm,
    Hkcu,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum View {
    #[serde(rename = "64")]
    V64,
    #[serde(rename = "32")]
    V32,
}

/// A registry key: hive, WOW64 view and a path relative to the hive.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RegPath {
    pub hive: Hive,
    pub view: View,
    pub path: String,
}

impl RegPath {
    pub fn new(hive: Hive, view: View, path: impl Into<String>) -> RegPath {
        RegPath { hive, view, path: path.into() }
    }
    pub fn child(&self, name: &str) -> RegPath {
        let path = if self.path.is_empty() { name.to_string() } else { format!("{}\\{}", self.path, name) };
        RegPath { hive: self.hive, view: self.view, path }
    }
    /// `HKLM\SOFTWARE\...\X (64)`
    pub fn display(&self) -> String {
        let h = match self.hive {
            Hive::Hklm => "HKLM",
            Hive::Hkcu => "HKCU",
        };
        let v = match self.view {
            View::V64 => "64",
            View::V32 => "32",
        };
        format!("{h}\\{} ({v})", self.path)
    }
    pub fn same(&self, other: &RegPath) -> bool {
        self.hive == other.hive && self.view == other.view && self.path.eq_ignore_ascii_case(&other.path)
    }
    /// Lowercased components below `base`, if `self` is strictly inside `base` (same hive and view).
    pub fn below(&self, base: &RegPath) -> Option<Vec<String>> {
        if self.hive != base.hive || self.view != base.view {
            return None;
        }
        let a = self.path.to_lowercase();
        let b = base.path.to_lowercase();
        let rest = a.strip_prefix(&b)?.strip_prefix('\\')?;
        Some(rest.split('\\').map(str::to_string).collect())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct InstalledApp {
    pub id: String,
    pub key_name: String,
    pub sources: Vec<RegPath>,
    pub display_name: String,
    pub display_version: Option<String>,
    pub publisher: Option<String>,
    pub install_location: Option<PathBuf>,
    pub display_icon: Option<String>,
    pub uninstall_string: Option<String>,
    pub quiet_uninstall_string: Option<String>,
    pub modify_path: Option<String>,
    pub install_date: Option<String>,
    pub estimated_size_kb: Option<u32>,
    pub windows_installer: bool,
    pub product_code: Option<String>,
    pub per_user: bool,
    /// Only for entries Apps & Features hides; absent in manifests and journals of visible programs (0.2.0 ignores it).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub hidden: Option<HiddenReason>,
}

/// Why Apps & Features hides an Uninstall entry that the program list shows only on request.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum HiddenReason {
    /// `SystemComponent` = 1: runtimes, drivers, parts of bundles, and software that hides itself.
    SystemComponent,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Launch {
    pub raw: String,
    pub exe: PathBuf,
    pub args: String,
    pub argv: Vec<String>,
    pub msi_product: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AppDetails {
    pub app: InstalledApp,
    pub launch: Option<Launch>,
    pub launch_error: Option<String>,
    #[serde(default)]
    pub trace: Option<TraceUse>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ProcInfo {
    pub pid: u32,
    pub image: String,
    pub created: u64,
    pub exit_code: Option<u32>,
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct NativeRun {
    pub started_ms: u64,
    pub ended_ms: u64,
    pub exit_code: Option<u32>,
    pub timed_out: bool,
    pub stopped_by_user: bool,
    pub launch_error: Option<String>,
    pub reboot_required: bool,
    pub processes: Vec<ProcInfo>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum EntryState {
    Gone,
    Orphaned,
    Present,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum Group {
    ProgramFiles,
    Shortcuts,
    Registry,
    Data,
    /// Previous values of registry values an install changed (trace only), never preselected.
    Revert,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum Tier {
    Safe,
    Review,
    Weak,
    Blocked,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum PathKind {
    File,
    Dir,
    Link,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "camelCase", rename_all_fields = "camelCase")]
pub enum Target {
    Path { path: PathBuf, kind: PathKind },
    RegKey { key: RegPath },
    RegValue { key: RegPath, name: String },
    /// Write `previous` back into an existing value that a traced install changed.
    RegRevert { key: RegPath, name: String, previous: RegVal },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct FileId {
    pub volume: u32,
    pub index: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DirPrint {
    pub files: u64,
    pub bytes: u64,
    pub newest_mtime: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RegVal {
    pub name: String,
    pub kind: u32,
    pub data: Vec<u8>,
}

/// A captured registry key tree. Values and keys are sorted by lowercase name so `==` is deterministic.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RegNode {
    pub name: String,
    pub values: Vec<RegVal>,
    pub keys: Vec<RegNode>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "camelCase", rename_all_fields = "camelCase")]
pub enum Ident {
    None {},
    File { id: FileId, size: u64, mtime: u64 },
    Dir { id: FileId, print: DirPrint },
    Link { id: FileId },
    Key { node: RegNode },
    Value { val: RegVal },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum EvidenceCode {
    InInstallDir,
    InstallDirCorroborated,
    RefersToInstallDir,
    TargetMissing,
    OwnUninstallEntry,
    ExactAnchor,
    ExactName,
    PublisherMatch,
    UserDataLikely,
    OutsideKnownZones,
    TraceCreated,
    TraceModified,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Evidence {
    pub code: EvidenceCode,
    pub points: i32,
    pub detail: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum BlockCode {
    ProtectedPath,
    OutsideAllowedZone,
    NonCanonicalPath,
    SharedWithOtherApp,
    AppStillInstalled,
    ProtectedRegistry,
    TooLarge,
    Unverifiable,
    OtherVolume,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Block {
    pub code: BlockCode,
    pub detail: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Candidate {
    pub id: String,
    pub group: Group,
    pub target: Target,
    pub size: u64,
    pub evidence: Vec<Evidence>,
    pub blocks: Vec<Block>,
    pub score: i32,
    pub tier: Tier,
    pub selected: bool,
    pub ident: Ident,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "camelCase", rename_all_fields = "camelCase")]
pub enum DirStatus {
    Confirmed {},
    NotSet {},
    Rejected { reason: String },
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Plan {
    pub schema: u32,
    pub created_ms: u64,
    pub app_id: String,
    pub dry_run: bool,
    pub install_dir: Option<PathBuf>,
    pub install_dir_status: DirStatus,
    pub corroborated: bool,
    pub still_running: Vec<String>,
    pub candidates: Vec<Candidate>,
    /// The trace journal the plan used or skipped, if the program has one.
    #[serde(default)]
    pub trace: Option<TraceUse>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum ItemStatus {
    InProgress,
    Removed,
    NotFound,
    Changed,
    Blocked,
    AccessDenied,
    Locked,
    Failed,
    Reverted,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum RestoreStatus {
    Restored,
    Conflict,
    Missing,
    Failed,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ItemRecord {
    pub candidate_id: String,
    pub target: Target,
    pub status: ItemStatus,
    pub detail: Option<String>,
    pub quarantine: Option<PathBuf>,
    pub reg_backup: Option<Ident>,
    pub restore: Option<RestoreStatus>,
    pub restore_detail: Option<String>,
    pub at_ms: u64,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Verify {
    pub app_still_listed: bool,
    pub reappeared: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum OpStatus {
    Running,
    AwaitingReview,
    Completed,
    CompletedWithWarnings,
    PendingReboot,
    PartiallyCompleted,
    Failed,
    Restored,
    PartiallyRestored,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Operation {
    pub schema: u32,
    pub id: String,
    pub created_ms: u64,
    /// Anchors captured BEFORE the uninstaller runs.
    pub app: InstalledApp,
    pub launch: Launch,
    pub native: Option<NativeRun>,
    pub entry_after: Option<EntryState>,
    pub plan: Option<Plan>,
    pub items: Vec<ItemRecord>,
    pub empty_dirs_removed: Vec<PathBuf>,
    pub verify: Option<Verify>,
    pub status: OpStatus,
    pub status_detail: Option<String>,
    /// Only on a forced removal ("remove by path"); absent in every other manifest, so those stay byte-identical and older builds
    /// (0.2.0, hidden-apps) ignore it and list the operation as a normal one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub forced: Option<Forced>,
}

/// What is stored on a forced operation: only what the scan needs again. Absent on every other operation.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Forced {
    /// The program file or folder the user picked, canonical.
    pub picked: PathBuf,
    /// The folder treated as the install folder; None = file-only identity.
    pub folder: Option<PathBuf>,
    /// Name variants that settings folders and keys may be looked for by (`force::search_names`); empty = no name search.
    pub search_names: Vec<String>,
}

/// How a picked path belongs to a listed program (hidden ones included).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum ListedHow {
    Folder,
    Inside,
    Installer,
    Shortcut,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum ForceRefusal {
    BadPath,
    OutsideSandbox,
    NotAllowed,
    OtherPrograms,
    Installed,
    Service,
}

/// What `force::check` found for a usable path: shown on the confirm screen, never stored.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ForceFound {
    /// `search_names` here are for the suggested name; `begin_forced` recomputes them for the confirmed one.
    pub forced: Forced,
    pub name: String,
    pub publisher: Option<String>,
    pub product: Option<String>,
    pub file_version: Option<String>,
    pub uninstallers: Vec<PathBuf>,
    pub shortcuts: Vec<PathBuf>,
    pub other_volume: bool,
    pub outside_zones: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "camelCase", rename_all_fields = "camelCase")]
pub enum ForceCheck {
    Ok { found: Box<ForceFound> },
    Listed { app: Box<InstalledApp>, how: ListedHow },
    Refused { code: ForceRefusal, detail: String },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "camelCase", rename_all_fields = "camelCase")]
pub enum HistoryEntry {
    Ok { op: Box<Operation> },
    Broken { id: String, path: PathBuf, error: String },
}

/// Why a trace journal was found but not used.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum Distrust {
    VersionChanged,
    FolderChanged,
    UninstallerChanged,
    ComponentStillInstalled,
}

/// What a plan or a card says about the trace journal of a program.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TraceUse {
    pub id: String,
    pub created_ms: u64,
    pub trusted: bool,
    pub distrust: Option<Distrust>,
    /// Non-noise Modified files and Deleted objects: shown in the journal, never acted on.
    pub reported: usize,
}

/// What a traced install did to one object.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum Change {
    Created,
    Modified,
    Deleted,
}

/// A cheap fingerprint of one object in a snapshot. Directory times are ignored (they change with every child), links and keys
/// have no contents of their own, values carry their type and a SHA-256 of type + data.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "camelCase", rename_all_fields = "camelCase")]
pub enum Print {
    File { size: u64, mtime: u64 },
    Dir {},
    Link {},
    Key {},
    Value { kind: u32, sha256: String },
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TraceChange {
    /// `ops::target_key` of the target.
    pub id: String,
    pub change: Change,
    pub target: Target,
    pub before: Option<Print>,
    pub after: Option<Print>,
    /// Full value data from before the install; kept only where a revert could use it (`trace::finish`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub previous: Option<RegVal>,
    /// A browser cache, a GPU shader cache and the like: kept in the journal, never evidence.
    pub noise: bool,
}

/// Which program a trace journal belongs to. Only `Linked` journals are ever used.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "camelCase", rename_all_fields = "camelCase")]
pub enum TraceLink {
    /// Exactly one new visible Uninstall entry appeared: a copy of the program as it was listed right after the install.
    Linked { app: Box<InstalledApp> },
    /// No new visible entry (an update, a reinstall, a hidden component).
    NoProgram {},
    /// Several new visible entries: a bundle; we cannot tell what belongs to whom.
    SeveralPrograms { names: Vec<String> },
}

/// One traced install: the delta between two snapshots.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TraceJournal {
    pub schema: u32,
    /// `tr-<ms>`
    pub id: String,
    pub created_ms: u64,
    pub finished_ms: u64,
    pub installer: Launch,
    pub native: Option<NativeRun>,
    pub link: TraceLink,
    /// Objects in the "after" snapshot.
    pub objects: u64,
    pub before_ms: u64,
    pub after_ms: u64,
    /// Folders and keys that could not be read in either snapshot; nothing below them is in `changes`.
    pub unreadable: Vec<String>,
    pub changes: Vec<TraceChange>,
}

/// What the GUI shows after a trace.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TraceSummary {
    pub id: String,
    pub created_ms: u64,
    pub link: TraceLink,
    pub native: Option<NativeRun>,
    pub objects: u64,
    pub before_ms: u64,
    pub after_ms: u64,
    /// Non-noise Created objects.
    pub created: usize,
    /// Display strings of non-noise Modified registry values.
    pub modified_values: Vec<String>,
    /// How many of them carry their previous data (a revert could use it).
    pub restorable_values: usize,
    pub modified_files: Vec<String>,
    pub deleted: Vec<String>,
    pub noise: usize,
    pub unreadable: usize,
}
