# Architecture

## Crates and modules
`crates/core` (`uni_core`): `model` (serde types), `env` (Env, Folders, sandbox), `paths` (normalisation, canonical form, file id,
walk, move/restore), `safety` (protected paths, registry shapes, tiers), `registry` (view-aware access, capture, restore),
`inventory` (list apps, hidden entries, entry state), `command` (UninstallString to Launch), `native` (run uninstaller, process tree), `shortcuts` (.lnk),
`scan` (evidence, candidates, plan), `ops` (journalled flow), `elevation`, `sandbox`, `trace` (install tracing: snapshots, diff, journals). `crates/cli`: read-only `uni`. `crates/lab`: `uni-lab`, the lab-only driver (never shipped, see Lab). `src-tauri`: Tauri commands.

## Pipeline
`describe` parses the uninstall command; `begin` records the pre-uninstall snapshot; `run_native` runs the vendor uninstaller and waits for
the whole process tree (`ShellExecuteExW` plus Toolhelp polling; nothing is ever killed); `scan_leftovers` (live preconditions: entry not
present, reboot done) builds the plan; `apply` revalidates every item right before acting, journals it, moves files into quarantine or
deletes registry items after a structured backup; `restore` puts everything back without overwriting.
The GUI never sends a plan back to Rust (ids and file indices would lose precision in JS); it sends candidate ids.

## Storage
`%LOCALAPPDATA%\uniinstaller-data` (sandbox: `<root>\data`): `operations\op-<ms>\manifest.json` (+ `.tmp`, synced then renamed) and `q\<n>_<name>`
quarantine payloads; `plans\` and `reports\` exports (registry payloads and a revert's previous data stripped). Op ids match `^op-[0-9]{1,20}$`.
History is a directory listing; an unreadable manifest is shown as `Broken`.
`traces\tr-<ms>.json` (sandbox: `<root>\data\traces`): one install trace journal each, ids `^tr-[0-9]{1,20}$`. Line 1 is
`uniinstaller-trace <version> sha256:<hex>`, the rest is compact JSON and the hash covers exactly those bytes; written to `.tmp`, synced, renamed.
`trace::load` rejects a bad header, a newer header or schema, a checksum mismatch, invalid JSON and an id that differs from the file name.
Journals are never deleted; the newest journal linked to a program supersedes older ones.

## Data model
Rust sends codes (EvidenceCode, BlockCode, ItemStatus, OpStatus, Group); `ui/strings.js` maps them to Russian. Candidate ids are
`target_key(target)`: `path:<norm>`, `key:<hive><view>:<lower path>`, `value:<same>|<lower name>`, stable across rescans.
Schema 2 (stage 2) adds `Target::RegRevert { key, name, previous }` (ids `revert:<hive><view>:<lower path>|<lower name>`), `Group::Revert`,
`ItemStatus::Reverted`, `EvidenceCode::{TraceCreated, TraceModified}`, `Plan.trace` and `AppDetails.trace` (`TraceUse`, `serde(default)`), and the
trace types `Print`, `Change`, `TraceChange`, `TraceJournal`, `TraceLink`, `TraceSummary`, `Distrust`. Schema-1 manifests (0.1.x) still load and restore
(a test keeps a real 0.1.1 manifest as a fixture); a manifest with a newer schema is refused. Downgrade: 0.1.x lists a schema-2 manifest that uses
the new variants as `Broken`.
`InstalledApp.hidden` (`HiddenReason`, `serde(default, skip_serializing_if = "Option::is_none")`) marks an entry Apps & Features hides; visible
programs serialize byte-identically, so there is no schema bump and 0.2.0 ignores the field.
Statuses: ItemStatus InProgress, Removed, NotFound, Changed, Blocked, AccessDenied, Locked, Failed, Reverted; RestoreStatus Restored, Conflict,
Missing, Failed; OpStatus Running, AwaitingReview, Completed, CompletedWithWarnings, PendingReboot, PartiallyCompleted, Failed, Restored,
PartiallyRestored (`ops::overall_status`, a pure ordered rule list; InProgress counts as a problem).

## Safety rules (source: `safety.rs`)
Protected roots (equal or ancestor blocked): drive roots, UserProfiles and every child profile, Profile, Public, Program Files (both),
ProgramData, AppData roots, UserProgramFiles, Start Menu folders, Startup, `canonical(temp)`, every zone root.
Protected trees (equal, ancestor or inside): Windows, Common Files (both), WindowsApps, `ProgramData\Microsoft`, `ProgramData\Package Cache`,
`Roaming\Microsoft`, `Local\Microsoft`, `Local\Packages`, Documents, Pictures, Videos, Music, Downloads, Saved Games, Desktop, Public folders,
OneDrive, the data dir and the current exe's dir. Exception: a Shortcuts-group `.lnk` directly on a desktop or inside a Start Menu.
Checked against `env.folders` and the real system folders; if the real folders cannot be resolved every path is `Unverifiable`.

Registry: a key exactly one level below an Uninstall or App Paths root; a value directly inside a Run key (never the key);
a key one or two levels below a software root whose first component is not Microsoft, Classes, Policies, Wow6432Node, Clients, RegisteredApplications.
A revert (`RegRevert`, writes a recorded value back) is allowed only for: a named value directly in a Run key; the default value of a key exactly one
level below an App Paths root; any value in a key at any depth below a software root whose first component is not reserved. Everything else (Uninstall
entries, Classes, Services, Microsoft, Policies, outside every root) is `ProtectedRegistry`; an unknown value type is `Unverifiable`.

Hard blocks (never overridable, recomputed at apply): ProtectedPath, OutsideAllowedZone, NonCanonicalPath (parent is not canonical:
8.3 names, trailing dot or space, junctions, SUBST), SharedWithOtherApp, AppStillInstalled, ProtectedRegistry, TooLarge (over 200000 files or
5000 registry nodes), Unverifiable (any failure while computing identity: fail closed), OtherVolume (backups live on the data dir's volume).

SharedWithOtherApp (`safety::Anchors`, applied in `scan::evaluate`, so a scan and an apply use the same rule):
- Who counts as another app: every `list_apps(env, true)` entry except the target's own (`ops::others`), read live at scan and again at apply:
  visible programs and hidden (`SystemComponent`) ones; nameless entries, updates and `ParentKeyName` children are not seen.
- Their anchors: install folder, uninstaller exe and icon, plus their existing settings folders (`<AppData>\[<publisher>\]<name>`) and
  Software keys, named by the same rule as the target's own settings candidates (`scan::name_pairs`, every name variant including the
  version-free one). An app without InstallLocation also gets a derived folder (its uninstaller's folder when the icon sits beside it,
  outside the Windows folder, as `find_anchor` does for the target); that folder is used only by the reference rule below.
- A path is blocked when it equals or contains an anchor or settings folder, or lies inside another app's install folder that does not
  contain ours; an install-folder child holding an uninstaller other than ours is blocked; a shortcut whose target meets the path
  rule is blocked, and a shortcut whose target cannot be read is `Unverifiable`.
- A registry key is blocked when it equals or contains another app's settings key (same hive and view). Another app's Uninstall entry (its
  `sources`, hidden programs included) is such a key too, so a trace can never propose it.
- A registry value (a Run value or a revert) is blocked when its key equals or lies inside another app's settings key or Uninstall entry
  (`Anchors::key_inside`).
- A registry key or Run value is blocked when any REG_SZ, REG_EXPAND_SZ or REG_MULTI_SZ text in it (the whole captured tree for a key)
  equals or points into another app's install or derived folder. An app whose folder contains ours (a host and its plugin) claims
  nothing, a drive root or protected root is never counted as an app's folder here, and the target's own Uninstall entry is exempt
  (a launcher's uninstaller may live in another app's folder).

## Scoring (calibrations, not measured)
InInstallDir +45, InstallDirCorroborated +35 (reference candidates only, never install-dir children), RefersToInstallDir +30,
TargetMissing +15, OwnUninstallEntry +60, ExactAnchor +60, ExactName +20, PublisherMatch +10, UserDataLikely -50, OutsideKnownZones -20.
Trace evidence (a trusted journal only, see Install tracing): TraceCreated +100 (`W_TRACE_CREATED`) when the candidate is the confirmed install folder,
holds it or lies inside it, or also has positive heuristic evidence; +50 (`W_TRACE_FAR`) otherwise; TraceModified +50 (`W_TRACE_MODIFIED`) on reverts.
Tiers: any block Blocked; >=80 Safe; 40-79 Review; below 40 Weak. Preselected only if Safe, not in the Data or Revert group and without
`UserDataLikely` (`default_selected`), so install-dir children (at most 45 without a trace) are never preselected. Expected values are asserted in
`tests/scan.rs` and `tests/trace.rs`. The weights are calibrations, not measurements.

## Install tracing (`trace.rs`)
Purpose: know what an installer added, so that a later uninstall finds its leftovers with evidence instead of guesses, and can write back registry values
the installer overwrote. Flow: the GUI picks an installer (`pick_installer`: `tauri-plugin-dialog`, called from Rust, so JavaScript needs no permission;
the path stays in `TraceSlot`); `installer_launch` turns it into a `Launch` (real system: an `.exe` itself or an `.msi` through
`<system dir>\msiexec.exe /i`; sandbox: only `.cmd` and `.bat` files inside the sandbox folder, so the sandbox GUI can never run a real installer);
`begin` takes the "before" snapshot (read-only, allowed on the real system); `install` runs the installer (`ops::guard`, `ops::lock`, the same process-tree
wait and stop flag as an uninstall); `finish` streams the "after" capture through a `Differ`, links the journal and saves it. The session lives in memory.
- Scope. Files: every zone root once (Program Files x2, UserProgramFiles, AppData Roaming, Local, LocalLow, ProgramData, both Start Menu `Programs`, both
  Desktops), unlimited depth except desktops (one level: folders are items, their content is not). Never entered: another root (walked on its own),
  a protected tree (Windows, Common Files, WindowsApps, `ProgramData\Microsoft`, Package Cache, `Roaming\Microsoft`, `Local\Microsoft`, `Local\Packages`,
  Documents and the other user folders, the data dir, the exe's dir, the GUI's WebView2 profile `%LOCALAPPDATA%\<Tauri identifier>`) and temp. A link is an
  item and is never followed. Registry: software roots (full depth, first-level reserved names skipped), Uninstall and App Paths roots (full depth),
  Run and RunOnce (values only); HKCU is captured once.
- Fingerprints: file size + mtime (ms), folders and links carry none, a registry value is its type plus a SHA-256 of type + data (`BCryptHash`). The "before"
  snapshot keeps file ids with fingerprints and full data only for registry objects; the "after" capture is never stored. `MAX_OBJECTS` is 1,000,000 per
  capture, a hard error, never a truncation.
- Diff. Created, Modified (a different fingerprint) and Deleted (the value's data is not kept). A folder or key that could not be read, in either capture,
  blinds everything below it (never Deleted or Created), and so does a switch between a link and a folder. Noise (browser and GPU caches, crash dumps,
  profiles, `ConnectedDevicesPlatform`) is matched by folder name below the capture root, stays in the journal with `noise: true`, is counted on the result
  screen, never gives evidence, but still counts as "created" when a folder is checked for being unchanged.
- Link and trust. A journal is linked when exactly one new visible Uninstall entry (one level below an `uninstall_roots` entry) appears and the visible list (`list_apps(env, false)`) shows
  one program for it; none or several leave it unlinked and unused. `find_for` returns the newest loadable journal whose linked app shares a source key;
  it is trusted only while display version, install folder (normalised) and uninstall command (trimmed, lowercase) match, and, after the program's own
  uninstaller ran (`scan_leftovers`, not `describe` or `preview`), while no other Uninstall key the install created still exists
  (`ComponentStillInstalled`). An untrusted journal gives no evidence and no reverts and the plan says why (`Plan.trace`).
- Previous data. A Modified value keeps its previous data in the journal only if an allowed revert shape would accept it and its new text points into one
  of the program's own folders (InstallLocation, the uninstaller's and the icon's folder). The scan offers a revert only when the live value still equals the
  value the trace recorded after the install (compared by hash), its text still points into the confirmed install folder, and its key is not another
  app's. A key that holds an attributable value is never offered for deletion. The apply backs up the current value first, writes `previous` with `write_value` (which never creates a key) and
  ends `Reverted`; a value that vanished meanwhile ends `Changed`. The undo is compare-and-set: it writes only while the live value equals `previous`,
  and a changed, missing or deleted value or key is a `Conflict` that is never recreated.
- Scan section G (`scan.rs`). Only topmost created objects are emitted (their parent is not created): a path when `unchanged_path` holds (same fingerprint,
  every current child also unchanged, entries deleted since are fine) and it is not protected; otherwise a protected folder (a Start Menu) or a folder
  near the install folder is entered and its created children are considered one by one; a key likewise with `unchanged_key`; a created value only while
  it still has the recorded fingerprint. Another program's Uninstall entry is never emitted. The evidence merges into a heuristic candidate with the same id.
  Nothing in `evaluate` depends on the trace: every block is computed at scan and again at apply, so a trace never adds or removes a block.
- Measured on the owner's machine (read-only test `real_system_snapshot_cost`, debug build, warm cache, 2026-11-18): 221,335 objects (211,376 files and folders,
  9,959 registry), 11 unreadable folders and keys, 1.8 s for the first capture and 1.4 s for the second (streamed), peak working-set growth 54 MB for both.
  Budget: at most 10 s per capture warm and at most 100 MB growth; if the test ever shows more, stop and investigate instead of raising it.
  In the lab guest (fresh Windows): 4,138 objects in 143 ms. The critic's measurement of the discarded wider scope (Classes and Services, 338,252 objects, 175 MB
  with the old representation) is why those are not captured.
- Attribution: there is none per process. Everything that changed in scope between the two snapshots is in the journal, including other programs'
  background writes; the UI says so on the intro, result and review screens, and a background write is offered but not preselected unless it is the install folder.


## Hidden programs (`inventory.rs`, `ops.rs`)
- What is listed. `list_apps(env, include_hidden)` returns the programs Apps & Features lists; with `include_hidden` it adds entries with `SystemComponent=1`
  (`HiddenReason::SystemComponent`, the only variant). Nameless entries, updates (`ReleaseType` update, hotfix, security update) and `ParentKeyName` children stay
  invisible and are not other apps. Measured on the owner's machine (read-only, 2026-11-18): 344 Uninstall keys, 94 visible programs, 188 `SystemComponent`
  entries (Visual C++ and .NET runtimes, SDK parts, Visual Studio MSIs, ASUS and RGB HALs, 19 NVIDIA components, Python and PowerToys MSIs, the WebView2
  Runtime), 62 nameless keys, no named entry with `ParentKeyName` or an update `ReleaseType`, no hidden twin of a visible program and no hidden folder equal to,
  holding or inside a visible app's folder.
- Twin rule. Visible entries are deduplicated first; a hidden entry equal to a listed program (name, version, uninstall command, folder) is dropped, so
  `list_apps(env, true)` is the default list plus hidden extras and ids and sources of visible programs never change.
- Callers. `true`: `find_app` (so `describe`, `preview`, `begin` see hidden targets), `ops::others` (scan and apply) and the verify step of `apply`.
  `false`: the GUI list unless the toggle is on, `uni list` unless `--hidden`, and `trace::link` (a hidden component installed alongside never links).
- Guard. `ops::begin(env, id, hidden_ok)` refuses a hidden entry unless `hidden_ok`; the GUI sends it only after the user ticks the confirmation. One
  confirmation for every hidden entry; no publisher rule (publisher text can be spoofed and is localized) and no bundle rule.
- GUI. The programs screen has a per-session "Показать скрытые" toggle; hidden rows carry a warning pill, the card a warning strip, and the uninstall
  dialog a checkbox that keeps "Запустить деинсталлятор" disabled until ticked.
- Bundles. A hidden MSI of a WiX Burn bundle leaves the bundle installed and visible, so the bundle's anchors block shared leftovers; the MSI's own folder
  children are offered at Review and never preselected. A hidden target that is itself a `ParentKeyName` parent: its children are not other apps and only
  `app.sources` are offered.
- Effect of counting hidden programs as other apps (real data, preview dump of the 94 visible programs before and after, 2228 lines): one candidate changed,
  the PowerToys (Preview) x64 settings folder `...\AppData\Local\PowerToys` went from Weak to Blocked (`SharedWithOtherApp`, it contains the install folder of the
  hidden PowerToys MSI); nothing else, no install-folder status changed. Preview of the 188 hidden programs: 929 candidates, 15 preselected (all Safe), no errors.
- Lab proof: `shared-suite-hidden` (the nested plugin hidden) was FAIL before the change (run 20261118-235415, 7 unblocked offers removed) and PASS after
  (run 20261119-000039).

## Lab (`crates/lab`, `lab/`)
The lab runs real installers and the real `uni_core::ops` flow inside Windows Sandbox. Nothing in `crates/core` changed for it.
- `uni-lab` commands: `check`, `list`, `begin <app>`, `native <op>`, `scan <op>`, `apply <op> default|unblocked [--crash-after-first-move]`,
  `restore <op>`, `show <op>`. Exit codes: 2 = refused by the guard, 99 = the deliberate kill of `--crash-after-first-move`, 1 = error.
  `apply` policies: `default` is the product's preselection; `unblocked` ticks every candidate without a hard block and without
  `UserDataLikely`, like a user who ticks everything the product does not warn about.
- Guard: every command except `check` needs `UNIINSTALLER_SANDBOX` (the fixture sandbox, as in the GUI and `uni`) or a Windows Sandbox
  guest: the process token user (`GetUserNameW`, never `%USERNAME%`) is `WDAGUtilityAccount` AND `UNIINSTALLER_LAB` names a local absolute
  folder holding `.uniinstaller-lab`. The first is the proof (the account exists disabled on a normal host), the second is explicit intent.
  Otherwise exit 2 before any `Env` is built. The release build is required in the guest because the debug guard in `ops.rs` still refuses
  `Env::system()` in debug builds. `lab/guest/run.ps1` repeats the token check as its first statement and before `shutdown`.
- Host/guest split: the host (`lab/lab.ps1`) builds into `target\lab\build`, stages `target\lab\out\<run>\_in` (guest scripts, build output,
  marker), launches one sandbox per scenario and waits. The guest sees only `_in` (read-only as `C:\lab`) and its own output folder
  (read-write as `C:\out`); no host-executed script is ever mapped, the analyzer refuses reparse-point inputs and writes results outside
  every mapped folder (`_results`). The guest installs silently, records an independent inventory (`lab/guest/inventory.ps1`: scoped file
  and registry roots, ids in the product's `target_key` form, size+mtime or type+hash fingerprints) before and after every step, drives
  `uni-lab` and shuts down. `lab/analyze.ps1` compares the snapshots with the scenario's golden manifest on the host.
- Manifest classes: `owned` (left behind by the app, the product may remove it), `userdoc` and `control` (must survive), `gap` (known,
  not handled). Verdicts: ERROR, FAIL, RISK, PASS; the rules are in `lab/analyze.ps1` and summarised in `docs/development.md`.
- Snapshots: `s0` baseline, `s1` after installs, `st` (trace scenarios) right after the traced install, `s2` after the native uninstaller, `s3` after the scan,
  `s4a` after a killed apply, `s4` after apply, `s4r` after the rescan, `s5` after restore.
- Tracing in the lab: `uni-lab trace <installer>` runs `trace::installer_launch`, `begin`, `install` (timeout 300 s) and `finish` and prints the journal; it
  fails when the installer did not start, timed out or exited non-zero. A scenario with `"trace": true` has exactly one installer, may set pre-existing state
  with `before_install` (same actions as `after_install`, run before `s0`), the manifest class `revert` (values the install overwrites and the product should
  restore) and the policy `default+reverts` (the preselection plus every unblocked revert). The NSIS test app gets `MODIFY` (points two vendor values at
  itself) and `BACKGROUND` (creates `{PF86}\Other Updater` and changes an unrelated value, a stand-in for a background writer); both are used only by
  `labtrace.exe`. The inventory also covers `LocalLow`.
- Trace rules (`analyze.ps1`, trace scenarios): 15a ERROR when `trace.json` is missing or not linked to the target; 15b FAIL when an owned leftover that
  appeared during the install (`st` minus `s0`, independent of `trace.json`) is not offered; 15c FAIL when a preselected or Safe candidate covers a control,
  userdoc or revert object; 15d each revert value must end `reverted` and equal its pre-install state (ERROR when the install did not change it: a test-app
  bug); 15e FAIL when a control value the install changed is offered as a revert; 15f FAIL when a revert is preselected. Rule 17 (all scenarios) FAILs when a
  removed item covers a place the inventory skips but the product captures (`d3dscache`, `connecteddevicesplatform`). Metrics: `traceCreated`, `traceEvidence`,
  `reverted`.
- Hidden entries: the NSIS test app has a `HIDDEN` flag (`SystemComponent=1`); `labhidden.exe` is the scenario `hidden-user`, `labpluginhidden.exe` the nested
  plugin of `shared-suite-hidden`. `uni-lab list` includes hidden entries and `uni-lab begin` passes `hidden_ok = true` (the lab acts as a user who ticked
  the confirmation; the refusal is tested in `tests/ops.rs`).
- Lab shortcuts: see the list below (the ones marked "lab").

## Known shortcuts (each is also a `// shortcut:` comment)
- Elevation (`elevation.rs`, `main.rs`): the whole UI becomes elevated after "restart as administrator", no privilege separation; narrow helper in stage 2.
- Elevated backups are user-writable (`ops.rs`, README): same-user malware could tamper with them before an elevated restore; per-machine install and protected store in stage 2.
- Debug builds (`ops.rs`): destructive operations refuse non-sandbox Env; intended, keep.
- Process tree (`native.rs`): 150 ms polling can miss a short-lived orphaned grandchild; job object in the helper.
- Waiting (`native.rs`, `ops.rs`): on timeout or "stop waiting" nothing is killed and scanning is allowed once the entry is gone.
- Users (`env.rs`): only the current user's HKCU and profile; other users in stage 2.
- Registry backup (`registry.rs`): values, types, subkeys and view only; no ACLs.
- Other volumes (`scan.rs`, `paths.rs`): leftovers on another drive than the data dir are shown as Blocked.
- Aliased install dirs (`scan.rs`): 8.3, trailing-dot, junction or SUBST install paths are rejected.
- Shared references (`safety.rs`): registry text is matched as normalized text, so 8.3 and other alias spellings, folders reached through a junction or SUBST (anchors are canonical), comma-separated lists, a folder followed by arguments without a trailing backslash and unexpanded REG_MULTI_SZ items are missed; resolve each path-like token if a lab run or user report shows one slipping through.
- Shared containers (`scan.rs`): a key or settings folder shared with another app is blocked whole, so the target's own values and files inside it are not offered; add per-value and per-file candidates if lab recall asks for them.
- Shared apps without a folder (`scan.rs`): an app with no InstallLocation whose uninstaller and icon do not share a folder is not seen by the reference rule; a stale entry of an older version of the same product blocks the target's version-free settings (fail closed).
- Settings key case (`safety.rs`): `key_holding` compares with `RegPath::same` (ASCII case) and `below` (Unicode case), so non-ASCII names that differ only in case are not seen as equal; compare lowercased paths if one shows up.
- Install-dir leftovers are never preselected unless a trusted trace journal confirms them (`safety.rs`).
- Retention (`ops.rs`): quarantine, manifests, plans and reports are never purged.
- Locked files (`ops.rs`): reported as Locked, retry by hand; no Restart Manager.
- Scoring (`safety.rs`): weights and the DOC_EXT / DATA_DIR_NAMES lists are not calibrated.
- Reboot (`ops.rs`): "rebooted since" from uptime only.
- Concurrency (`ops.rs`): `OP_LOCK` is per process.
- MSI with empty InstallLocation (`scan.rs`): little leftover coverage.
- Icons (`ui/app.js`): letter tile instead of the program icon.
- WOW64 redirection (tests): only plumbing is tested because HKCU is not redirected. The lab's `msi-bare-x86` covers HKLM 32-bit removal and restore.
- Updater (`main.rs`, `release.yml`): no rollback; verified end to end 0.1.0 -> 0.1.1 only by hand (see `docs/development.md`).
- Secrets at rest (`ops.rs`): manifests hold registry backups in clear text.
- Signing key (docs): password next to the key; build scripts see both.
- Over-the-shoulder elevation (`env.rs`): a different admin account changes `%LOCALAPPDATA%`, history looks empty.
- Lab, UAC (`lab/`): the guest is a single elevated administrator with UAC off, so UAC prompts, standard-user AccessDenied paths and other profiles are not tested; add a `runas /trustlevel:0x20000` scenario with the stage-2 elevated helper.
- Lab, installers: no Inno Setup app (ISCC is not installed); add `lab/apps/app.iss` when it is available without elevation. NSIS uninstallers are silent by design, add a wizard-clicking scenario if real wizard uninstallers misbehave.
- Lab, clicker (`lab/guest/clicker.ps1`): only IDYES (6) and the MSI confirmation Yes (3001) in msiexec `#32770` dialogs; add other ids or processes when a scenario needs them.
- Lab, inventory (`lab/guest/inventory.ps1`): scoped roots (plus `LocalLow`), depth-1 names for Classes and Services, size+mtime fingerprints; widen the roots or hash contents when a product change touches new places. `analyze.ps1` folds the 32-bit view of `...\CurrentVersion\App Paths` onto the 64-bit one because Windows mirrors it.
- Lab, metrics: recall and precision are reported, not gated; set thresholds after at least 3 stable full runs and recalibrate the `safety.rs` weights from that data.
- Lab, crash point (`uni-lab`): the kill is only "after the first quarantined path"; add a registry-phase kill if resume bugs show up there.
- Lab, cost: one fresh sandbox per scenario (about 30 s of boot each) and a full `_in` copy per run (delete old runs by hand with `cmd /c rmdir /s /q`); batch scenarios if full runs get too slow.
- Lab, payload: an inert `whoami.exe` copy that never runs, so there is no "app running during uninstall" case; add a long-running payload when Restart Manager work starts.
- Lab, coverage: reboot, MSIX, several users, drivers and update-over-previous are not exercised; add them with their stage-2/3 features.
- Lab, detection: sandbox detection uses `wsb list` plus the `WindowsSandbox`, `WindowsSandboxClient` and `WindowsSandboxRemoteSession` processes; switch to `wsb start`/`connect` with known ids if it proves unreliable.
- Lab, build: WiX 5 comes from nuget.org on the first build; vendor a pinned copy if the lab must build offline.
- Install tracing (`trace.rs`, one comment per item in the code):
  1. Attribution: none per process (no ETW or driver); background writes in scope enter the delta. Reverts need a reference to the program's folder and
     trace-only objects away from it score +50. Upgrade with ETW in the elevated helper.
  2. Session memory: the "before" snapshot stays in memory for the whole session (about 190 B per object), the second capture is streamed; an app restart or a
     reboot loses the session. Persist the "before" snapshot for installs that span a reboot.
  3. File comparison by size + mtime only; hash files in the install zones if a lab run shows a miss.
  4. Not captured: Classes, Services, scheduled tasks, `HKCU\Environment`, `SOFTWARE\Microsoft` (except Uninstall, Run, RunOnce, App Paths), desktop subfolders,
     protected trees, temp, other users, install folders outside the zones. Add with the stage-3 adapters.
  5. Noise rules are folder names below the capture root; there are none for the registry.
  6. Linking needs exactly one new visible Uninstall entry; updates, reinstalls and bundles stay unlinked.
  7. Hidden components make a journal untrusted only after the program's own uninstaller ran; the card and the preview do not check them.
  8. `find_for` parses every journal, newest first; add an index if users keep hundreds.
  9. Journals are user-writable (the checksum catches corruption, not tampering) and hold the previous data of attributable values in clear text; protected
     store and DPAPI in stage 2, together with the manifests.
  10. Revert shapes: named Run values, App Paths default values and vendor keys only, and only when the new text points into the confirmed install folder; no
      reverts without a confirmed folder.
  11. Modified files and deleted objects are report-only (no content backup); deleted paths are stored in lowercase.
  12. A trace-created folder that is blocked as a whole hides the heuristic children inside it (same class as "Shared containers").
  13. The weights +100, +50 and +50 are not calibrated.
  14. Lab coverage: one per-machine NSIS trace scenario; add traced MSI and per-user scenarios. Mark-of-the-Web is checked by hand only
      (`docs/development.md`).
  15. Downgrade: 0.1.x lists schema-2 manifests that use the new variants as Broken.
- Hidden entries (`inventory.rs`): only `SystemComponent` entries are listed as hidden; nameless entries, updates (`ReleaseType`) and `ParentKeyName` children stay
  invisible and are not other apps either (none of the last two on the owner's machine, 2026-11-18); list them if unwanted software is seen hiding that way.
- Hidden twins (`inventory.rs`): a hidden twin of a listed program is dropped, not merged as a source; once the program is gone a leftover twin counts as
  another app and rejects the shared folder (fail closed). Merge it if such twins show up as leftovers.
- Hidden confirmation (`ops.rs`): every hidden entry gets the same single confirmation, no publisher or bundle check (runtimes, Burn packages, the WebView2
  Runtime); add per-kind warnings if users remove runtimes by mistake.
- Lab, analyzer: `analyze.ps1` has no unit tests; its rules are checked against the scenario verdicts, add a synthetic-run self-test if the rules change often.
