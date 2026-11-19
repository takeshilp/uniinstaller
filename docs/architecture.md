# Architecture

## Crates and modules
`crates/core` (`uni_core`): `model` (serde types), `env` (Env, Folders, sandbox), `paths` (normalisation, canonical form, file id,
walk, move/restore), `safety` (protected paths, registry shapes, tiers), `registry` (view-aware access, capture, restore),
`inventory` (list apps, hidden entries, entry state), `command` (UninstallString to Launch), `native` (run uninstaller, process tree), `shortcuts` (.lnk),
`scan` (evidence, candidates, plan), `ops` (journalled flow), `elevation`, `sandbox`, `trace` (install tracing: snapshots, diff, journals), `force` (forced removal by path), `icon` (program icons for the GUI: DisplayIcon or uninstaller exe read as data, 64 px PNG), `sysobj` (Windows services and scheduled tasks: readers, Service Control Manager and Task Scheduler calls, sandbox stand-ins). `crates/cli`: read-only `uni`. `crates/lab`: `uni-lab`, the lab-only driver (never shipped, see docs/lab.md). `src-tauri`: Tauri commands.

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
`Operation.forced` (`Forced { picked, folder, search_names }`, `serde(default, skip_serializing_if = "Option::is_none")`) marks a forced removal; normal manifests stay
byte-identical, there is no schema bump and no new `OpStatus` (0.2.0 and the hidden-apps build ignore the field, list the operation as a normal one and can restore it).
Downgrade: 0.2.0 lists a forced operation as a normal one and can restore it, but a rescan there treats the folder as corroborated (the found uninstaller sits in it)
and preselects shortcuts and Run values; do not rescan forced operations in an older version.
`Operation.continue_after_reboot` (`Option<u64>`, `serde(default, skip_serializing_if = "Option::is_none")`, JSON `continueAfterReboot`): when the operation started waiting for a restart. `run_native`
sets it when the uninstaller asked for one (`PendingReboot` with no items); "Повторить после перезагрузки" sets it on an operation with a `Locked` or `AccessDenied` item. Normal manifests stay byte-identical, there is
no schema bump, older builds ignore it. The transient `Holder`, `HolderKind`, `HolderBlock`, `ItemHolders` and `Closed` are answers of `ops::lock_holders` and `ops::close_and_retry`; they are never stored (docs/locked.md).
Statuses: ItemStatus InProgress, Removed, NotFound, Changed, Blocked, AccessDenied, Locked, Failed, Reverted; RestoreStatus Restored, Conflict,
Missing, Failed; OpStatus Running, AwaitingReview, Completed, CompletedWithWarnings, PendingReboot, PartiallyCompleted, Failed, Restored,
PartiallyRestored (`ops::overall_status`, a pure ordered rule list; InProgress counts as a problem). PendingReboot also covers an operation with the restart marker and a
`Locked` or `AccessDenied` item left; there is no per-item PendingReboot.

## Program icons
- `icon::source(app, env)`: the DisplayIcon file and index (`path[,index]`, negative = resource id) when it is a local existing file, else the uninstaller when it is an `.exe`
  outside the Windows folder (never msiexec, rundll32 or another system binary); otherwise None and the GUI keeps the letter tile. UNC values are skipped so the list never
  touches a network share. `inventory::icon_path` is not changed (scan, force and trace use it).
- `icon::extract(path, index)`: `SHDefExtractIconW` (64 px, loads the file as data, never runs it, no COM) then `GetIconInfo` + `GetDIBits` to BGRA, alpha from the AND mask
  for legacy icons without alpha, RGBA PNG through the `png` crate; every GDI handle is freed.
- GUI: `list_apps` remembers the apps by id (`IconSlot`), the new command `app_icon(id)` returns a PNG data URL (session cache by file and index); the JS queue fetches
  4 at a time in page order after each render, an error or None keeps the letter. The CSP was unchanged (`img-src 'self' data:` already allowed it). History rows keep the letter.
- Measured on the owner's machine, 2026-11-19 (`real_system_icons`, debug build, one thread): 282 programs (94 visible), 103 icons (75 visible), 179 letters, 89 distinct
  sources, 1.4 s. Every entry with a DisplayIcon got an icon. Discord (`Update.exe`) and rustup (`rustup.exe`) have no icon resources at all, so they keep the letter.

See docs/safety.md.

## Services and tasks
`Target::Service { name }` (id `service:<lower name>`) and `Target::Task { path }` (id `task:<lower path>`), `Ident::Service { node, running }` (the whole service key; `running` is display-only and ignored by `ops::same_ident`) and `Ident::Task { xml, actions, enabled }`, `Group::Services` (appended after Revert, never preselected), `BlockCode::Unsupported`, and `Env.tasks` (the sandbox's stand-in for the Task Scheduler; `None` on the real system). All additive: the schema stays 2, a manifest without a service or task is byte-identical, and an older build (0.2.0, hidden-apps, force, icons) lists an operation whose plan holds one as `Broken`. Do not rescan or restore such an operation in an older build. See docs/services.md.

See docs/tracing.md.

See docs/safety.md.

See docs/force.md.

See docs/lab.md.

## Known shortcuts (each is also a `// shortcut:` comment)
- Elevation (`elevation.rs`, `main.rs`): the whole UI becomes elevated after "restart as administrator", no privilege separation; narrow helper in stage 2.
- Elevated backups are user-writable (`ops.rs`, README): same-user malware could tamper with them before an elevated restore (a service or task backup could make it create a LocalSystem service or a SYSTEM task; `restore_system` re-checks the blocks); per-machine install and protected store in stage 2.
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
- Locked files (`rm.rs`, `ops.rs`): who holds them and a confirmed close-and-retry are in docs/locked.md; its shortcut list is below.
- Scoring (`safety.rs`): weights and the DOC_EXT / DATA_DIR_NAMES lists are not calibrated.
- Reboot (`ops.rs`): "rebooted since" comes from uptime, see "Locked files and restarts" below.
- Concurrency (`ops.rs`): `OP_LOCK` is per process.
- MSI with empty InstallLocation (`scan.rs`): little leftover coverage.
- Icons (`icon.rs`): MSI `ProductIcon` is not read (5 of 16 visible MSI entries without DisplayIcon) and monochrome icons get the letter.
- Icon cache (`main.rs`): it lasts the session, an updated program shows its old icon until restart.
- WOW64 redirection (tests): only plumbing is tested because HKCU is not redirected. The lab's `msi-bare-x86` covers HKLM 32-bit removal and restore.
- Updater (`main.rs`, `release.yml`): no rollback; verified end to end 0.1.0 -> 0.1.1 only by hand (see `docs/development.md`).
- Secrets at rest (`ops.rs`): manifests hold registry backups in clear text.
- Signing key (docs): password next to the key; build scripts see both.
- Over-the-shoulder elevation (`env.rs`): a different admin account changes `%LOCALAPPDATA%`, history looks empty.
- Lab, UAC (`lab/`): the guest is a single elevated administrator with UAC off, so UAC prompts, standard-user AccessDenied paths and other profiles are not tested; add a `runas /trustlevel:0x20000` scenario with the stage-2 elevated helper.
- Lab, installers: no Inno Setup app (ISCC is not installed); add `lab/apps/app.iss` when it is available without elevation. NSIS uninstallers are silent by design, add a wizard-clicking scenario if real wizard uninstallers misbehave.
- Lab, clicker (`lab/guest/clicker.ps1`): only IDYES (6) and the MSI confirmation Yes (3001) in msiexec `#32770` dialogs; add other ids or processes when a scenario needs them.
- Lab, inventory (`lab/guest/inventory.ps1`): scoped roots (plus `LocalLow`), depth-1 names for Classes and Services plus full keys of third-party services (image under {PF}/{PF86}/{PD}, no `Windows*`/`Microsoft*` folder), tasks outside `\Microsoft` through the Task Scheduler API (XML hashed; the task files are not listed), size+mtime fingerprints; widen the roots or hash contents when a product change touches new places. `analyze.ps1` folds the 32-bit view of `...\CurrentVersion\App Paths` onto the 64-bit one because Windows mirrors it.
- Lab, metrics: recall and precision are reported, not gated; set thresholds after at least 3 stable full runs and recalibrate the `safety.rs` weights from that data.
- Lab, crash point (`uni-lab`): the kill is only "after the first quarantined path"; add a registry-phase kill if resume bugs show up there.
- Lab, cost: one fresh sandbox per scenario (about 30 s of boot each) and a full `_in` copy per run (delete old runs by hand with `cmd /c rmdir /s /q`); batch scenarios if full runs get too slow.
- Lab, payload: an inert `whoami.exe` copy that never runs, so there is no "app running during uninstall" case; the locked-file scenario `nsis-user` uses a window program (`lab/apps/lockholder.cs`) as the holder, a long-running payload is still not used.
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
- Forced removal (`force.rs`, one comment per item in the code):
  1. No window picking ("Hunter mode"): a WebView cannot be a drag target over other windows; pick the exe instead, add a picker with a native overlay.
  2. Uninstallers are found only by `unins*` names directly in the folder; deeper folders and other names (`remove.exe`, `setup.exe /uninstall`) are missed, widen this if users report misses.
  3. A folder inside a listed program's folder is refused (`ListedHow::Inside`): plugins and mods dropped into a host cannot be forced.
  4. Unlisted Uninstall keys whose uninstaller is gone are ignored; adopt them as the target's own entry if they show up as leftovers.
  5. Services (including svchost `ServiceDll` services and drivers) refuse the pick; scheduled tasks are not checked, the scan offers them instead (never Safe, never preselected).
  6. The MSI component scan reads every component key on each check; cache it per session if it gets slow.
  7. Version info uses the first translation only; the main exe is the single exe in the folder or the one whose stem equals the folder's name.
  8. The identity check runs at begin; a program installed later around the folder is seen only by the usual scan and apply blocks.
  9. File-only identity has no neighbouring files; references are matched to the exact file only.
  10. A forced folder on another drive: every file candidate is Blocked `OtherVolume` (the existing shortcut above), and most portable programs on the owner's machine are on `D:`.
  11. The name rule runs at begin only; the GUI hint is static and the review strip says when name search was skipped.
  12. A listed program that owns the pick through none of its folder, its MSI components or a same-named shortcut is not seen.
  13. TrustedInstaller is checked on the pick and its folder only; SYSTEM-owned tool folders such as `C:\Program Files\MSBuild` pass; an unreadable owner refuses.
  14. The upward MSI rule claims a whole folder for one file (fail closed).
  15. An exe widens to its folder only with no other exe or the same ProductName; otherwise file-only, and outside the zones the file itself is then Blocked `OutsideAllowedZone`.
  16. Shortcuts are resolved by the file dialog only; core accepts an `.exe` or a folder.
  17. The clean-exit gate sees only the launcher's exit code (an NSIS uninstaller copies itself and the launcher exits 0).
  18. Lab, `force-*`: the 1-to-5 comparison of an `expect_force` scenario skips folders the inventory could not read; the real data shapes of the SCM and Windows Installer checks are proven by `force-service` and `force-msi-bare` only for one product each.
- Services and tasks (`sysobj.rs`, `scan.rs`, `ops.rs`, one comment per item in the code, details in docs/services.md):
  1. Detection is by reference only (image, `ServiceDll` or an exec action into the confirmed folder or picked file): no trace evidence (services and tasks are not captured), no name match, and an app without a confirmed folder gets none. Add a trace capture of service names and task paths when the budget allows.
  2. Never preselected (`default_selected`); the tier comes from the uncalibrated weights (65 Review, 80 Safe when the program is gone). Revisit with lab statistics.
  3. Any dependent blocks, including one of the same program and a group dependency; remove the program that owns the dependent first. After a first apply the operation offers no rescan.
  4. The stop waits 30 s with no stop button and never kills; services are not registered with the Restart Manager, so a service that does not stop ends Locked and can be retried by hand or after a restart (docs/locked.md). Add a "stop waiting" button.
  5. A service the SCM only marked for deletion ends `Removed` with a detail; there is no per-item PendingReboot status.
  6. Restore sets only the `CreateServiceW` fields and delayed start through the API; the other values (description, failure actions, triggers, parameters, security descriptor) are written into the key and apply at the latest after a restart. Account passwords are not restored.
  7. Tasks with a stored password cannot be recreated, and a task's security descriptor is not backed up.
  8. Emptied task folders, the `TaskCache` tree entry and the svchost group list entries stay.
  9. Non-exec task actions are not matched, and a task that has one is Unsupported. The working directory is not matched.
  10. Indirect display names show the key name.
  11. Non-elevated, a service with an unreadable `Security` subkey is Unverifiable (9 of 38 third-party services on the owner's machine) and tasks the user cannot read are not seen. The fix is to restart as administrator before removing anything; after a first apply the operation offers no rescan.
  12. Drivers and per-user services are report-only.
  13. Backups are user-writable (the shortcut above): an elevated restore could create a LocalSystem service or a SYSTEM task from a tampered manifest; the stage-2 helper and a protected store fix this.
  14. `%VAR%` expands in our environment; another user's per-user paths are matched against ours.
  15. A recreated service or task that differs from its backup ends Conflict although it exists again.
  16. Each scan enumerates all services and tasks once; cache per session if previews get slow (111 s for 282 programs in a debug build).
  17. Lab: a running service, a custom security descriptor and password tasks are not exercised (the payload is not a service binary).
  18. The "outside the program's folder" rule checks Program Files roots only and fails closed: the program's own second folder (its x86 half, the vendor's Common Files) blocks too; widen `own` to the program's other registered folders if users report blocked services of their own program.
  19. An existing program whose owner cannot be read blocks the service (fail closed); measure on real data before relaxing.
- Locked files and restarts (`rm.rs`, `ops.rs`, `sysobj.rs`, `main.rs`, `app.js`, `lab/`, one comment per item in the code, details in docs/locked.md):
  1. `rm::held`: the probe opens for DELETE (with no sharing inside a folder item). For that instant another program's open can fail with 32 and an oplock can break; a handle opened only for attributes is not seen. Upgrade: per-file attribution in the stage-2 helper.
  2. `rm::holders`: folders are never registered (`RmGetList` fails with 5). A folder held as a current folder or by a watcher is reported only as "a folder is open", without a name. Upgrade: handle enumeration in the helper.
  3. `rm::MAX_FILES` / `MAX_PROBE`: 64 files asked about, 20,000 entries probed per item.
  4. `ops::holders_of`: one Restart Manager query per item (about 0.5 s per held file, about 240 ms per registered file under Program Files). Upgrade: batch the queries.
  5. `sysobj` STOP_WAIT: services are not registered with the Restart Manager; a service that did not stop stays Locked, with the restart reminder.
  6. `rm::block`: only window programs are closed. Refused: console programs (RM would send Ctrl+C to every program in that console and attach to it from inside our process), services, Explorer, critical, unknown-type, elevated or other-session holders, any WebView2 process, and the recorded uninstaller.
  7. `ops::close_and_retry`: `RmShutdown` waits as long as the Restart Manager does; there is no cancel button. Upgrade: `RmCancelCurrentTask`.
  8. `main.rs` `HolderSlot`: the close needs the PIDs the modal showed to equal the last stored list.
  9. `ops::close_and_retry`: `RmRestart` restarts only programs registered for restart, and closing is not journalled: a crash between the shutdown and the restart leaves the programs closed.
  10. `app.js` `scanLabel`: an item that ends `Changed` after a close needs a rescan by hand.
  11. `ops::boot_ms`: restarts are detected from uptime, so a shutdown with Fast Startup is not a restart. Upgrade: `PrefetchParameters\BootId`, once it is measured to change on hybrid boots.
  12. `ops::mark_native_reboot`: operations from older builds have no marker and never show the banner; open them from History.
  13. `ops::remind_after_reboot`: no boot-time moves (`MoveFileEx` DELAY_UNTIL_REBOOT) and no RunOnce key. The user starts Uniinstaller after the restart and the banner offers to continue.
  14. `lab/guest/run.ps1`: one window holder plus one bystander in `nsis-user`. The console refusal is covered only by the fixture. Explorer, services, elevated holders, a refusing app and a real restart are not exercised.
- Lab, analyzer: `analyze.ps1` has no unit tests; its rules are checked against the scenario verdicts, add a synthetic-run self-test if the rules change often.
