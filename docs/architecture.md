# Architecture

## Crates and modules
`crates/core` (`uni_core`): `model` (serde types), `env` (Env, Folders, sandbox), `paths` (normalisation, canonical form, file id,
walk, move/restore), `safety` (protected paths, registry shapes, tiers), `registry` (view-aware access, capture, restore),
`inventory` (list apps, entry state), `command` (UninstallString to Launch), `native` (run uninstaller, process tree), `shortcuts` (.lnk),
`scan` (evidence, candidates, plan), `ops` (journalled flow), `elevation`, `sandbox`. `crates/cli`: read-only `uni`. `crates/lab`: `uni-lab`, the lab-only driver (never shipped, see Lab). `src-tauri`: Tauri commands.

## Pipeline
`describe` parses the uninstall command; `begin` records the pre-uninstall snapshot; `run_native` runs the vendor uninstaller and waits for
the whole process tree (`ShellExecuteExW` plus Toolhelp polling; nothing is ever killed); `scan_leftovers` (live preconditions: entry not
present, reboot done) builds the plan; `apply` revalidates every item right before acting, journals it, moves files into quarantine or
deletes registry items after a structured backup; `restore` puts everything back without overwriting.
The GUI never sends a plan back to Rust (ids and file indices would lose precision in JS); it sends candidate ids.

## Storage
`%LOCALAPPDATA%\uniinstaller-data` (sandbox: `<root>\data`): `operations\op-<ms>\manifest.json` (+ `.tmp`, synced then renamed) and `q\<n>_<name>`
quarantine payloads; `plans\` and `reports\` exports (registry payloads stripped). Op ids match `^op-[0-9]{1,20}$`. History is a directory
listing; an unreadable manifest is shown as `Broken`.

## Data model
Rust sends codes (EvidenceCode, BlockCode, ItemStatus, OpStatus, Group); `ui/strings.js` maps them to Russian. Candidate ids are
`target_key(target)`: `path:<norm>`, `key:<hive><view>:<lower path>`, `value:<same>|<lower name>`, stable across rescans.
Statuses: ItemStatus InProgress, Removed, NotFound, Changed, Blocked, AccessDenied, Locked, Failed; RestoreStatus Restored, Conflict,
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

Hard blocks (never overridable, recomputed at apply): ProtectedPath, OutsideAllowedZone, NonCanonicalPath (parent is not canonical:
8.3 names, trailing dot or space, junctions, SUBST), SharedWithOtherApp, AppStillInstalled, ProtectedRegistry, TooLarge (over 200000 files or
5000 registry nodes), Unverifiable (any failure while computing identity: fail closed), OtherVolume (backups live on the data dir's volume).

## Scoring (calibrations, not measured)
InInstallDir +45, InstallDirCorroborated +35 (reference candidates only, never install-dir children), RefersToInstallDir +30,
TargetMissing +15, OwnUninstallEntry +60, ExactAnchor +60, ExactName +20, PublisherMatch +10, UserDataLikely -50, OutsideKnownZones -20.
Tiers: any block Blocked; >=80 Safe; 40-79 Review; below 40 Weak. Preselected only if Safe and not in the Data group, so install-dir
children (at most 45) are never preselected. Expected values are asserted in `tests/scan.rs`.

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
- Snapshots: `s0` baseline, `s1` after installs, `s2` after the native uninstaller, `s3` after the scan, `s4a` after a killed apply, `s4` after
  apply, `s4r` after the rescan, `s5` after restore.
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
- Install-dir leftovers are never preselected (`safety.rs`) until trace logs give stronger evidence.
- Retention (`ops.rs`): quarantine, manifests, plans and reports are never purged.
- Locked files (`ops.rs`): reported as Locked, retry by hand; no Restart Manager.
- Scoring (`safety.rs`): weights and the DOC_EXT / DATA_DIR_NAMES lists are not calibrated.
- Reboot (`ops.rs`): "rebooted since" from uptime only.
- Concurrency (`ops.rs`): `OP_LOCK` is per process.
- MSI with empty InstallLocation (`scan.rs`): little leftover coverage.
- Icons (`ui/app.js`): letter tile instead of the program icon.
- WOW64 redirection (tests): only plumbing is tested because HKCU is not redirected. The lab's `msi-bare-x86` covers HKLM 32-bit removal and restore.
- Updater (`main.rs`, `release.yml`): verifiable only after two releases; no rollback.
- Secrets at rest (`ops.rs`): manifests hold registry backups in clear text.
- Signing key (docs): password next to the key; build scripts see both.
- Over-the-shoulder elevation (`env.rs`): a different admin account changes `%LOCALAPPDATA%`, history looks empty.
- Lab, UAC (`lab/`): the guest is a single elevated administrator with UAC off, so UAC prompts, standard-user AccessDenied paths and other profiles are not tested; add a `runas /trustlevel:0x20000` scenario with the stage-2 elevated helper.
- Lab, installers: no Inno Setup app (ISCC is not installed); add `lab/apps/app.iss` when it is available without elevation. NSIS uninstallers are silent by design, add a wizard-clicking scenario if real wizard uninstallers misbehave.
- Lab, clicker (`lab/guest/clicker.ps1`): only IDYES (6) and the MSI confirmation Yes (3001) in msiexec `#32770` dialogs; add other ids or processes when a scenario needs them.
- Lab, inventory (`lab/guest/inventory.ps1`): scoped roots, depth-1 names for Classes and Services, size+mtime fingerprints; widen the roots or hash contents when a product change touches new places. `analyze.ps1` folds the 32-bit view of `...\CurrentVersion\App Paths` onto the 64-bit one because Windows mirrors it.
- Lab, metrics: recall and precision are reported, not gated; set thresholds after at least 3 stable full runs and recalibrate the `safety.rs` weights from that data.
- Lab, crash point (`uni-lab`): the kill is only "after the first quarantined path"; add a registry-phase kill if resume bugs show up there.
- Lab, cost: one fresh sandbox per scenario (about 30 s of boot each) and a full `_in` copy per run (delete old runs by hand with `cmd /c rmdir /s /q`); batch scenarios if full runs get too slow.
- Lab, payload: an inert `whoami.exe` copy that never runs, so there is no "app running during uninstall" case; add a long-running payload when Restart Manager work starts.
- Lab, coverage: reboot, MSIX, several users, drivers and update-over-previous are not exercised; add them with their stage-2/3 features.
- Lab, detection: sandbox detection uses `wsb list` plus the `WindowsSandbox`, `WindowsSandboxClient` and `WindowsSandboxRemoteSession` processes; switch to `wsb start`/`connect` with known ids if it proves unreliable.
- Lab, build: WiX 5 comes from nuget.org on the first build; vendor a pinned copy if the lab must build offline.
- Lab, analyzer: `analyze.ps1` has no unit tests; its rules are checked against the scenario verdicts, add a synthetic-run self-test if the rules change often.
