# Safety, scoring and hidden programs

Hard blocks, the shared-with-other-app rules, the registry and path shapes they allow, the scoring weights and the hidden-program rules that decide what a scan may propose.

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
Trace evidence (a trusted journal only, see docs/tracing.md): TraceCreated +100 (`W_TRACE_CREATED`) when the candidate is the confirmed install folder,
holds it or lies inside it, or also has positive heuristic evidence; +50 (`W_TRACE_FAR`) otherwise; TraceModified +50 (`W_TRACE_MODIFIED`) on reverts.
Tiers: any block Blocked; >=80 Safe; 40-79 Review; below 40 Weak. Preselected only if Safe, not in the Data or Revert group and without
`UserDataLikely` (`default_selected`), so install-dir children (at most 45 without a trace) are never preselected. Expected values are asserted in
`tests/scan.rs` and `tests/trace.rs`. The weights are calibrations, not measurements.

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
