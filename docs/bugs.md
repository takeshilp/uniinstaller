# Bugs and pitfalls

Verified pitfalls and fixed bugs. Entry template: symptom, cause, fix, how it was verified.

## `start /b <file>.bat` leaves a `cmd /K` behind (test fixture)
- Symptom: `tests/native.rs::waits_for_child_after_root_exits` never finished.
- Cause: `cmd /c start "" /b child.bat` runs the batch file through `cmd /K`, which stays open forever.
- Fix: launch `start "" /b cmd /c "<bat>"`.
- Verified: the native test suite passes in about 5 s.

## windows-rs hides `ShellExecuteExW` behind a feature
- Symptom: `unresolved imports SHELLEXECUTEINFOW, ShellExecuteExW`.
- Cause: they need `Win32_System_Registry` as well as `Win32_UI_Shell`.
- Fix: add the feature to `crates/core/Cargo.toml`.

## Name variants ending with a dot are dropped
- `Acme, Inc.` is not usable as a folder-name variant (trailing dot is an alias vector); only the stripped `Acme` is kept. This is intended.

## Windows Sandbox `.wsb` `<Command>` breaks on `&` and `<`
- Symptom: the sandbox refuses the configuration ("Line 12, position 31").
- Cause: the LogonCommand text is XML, so an inline command line with `&` or `<` is not well-formed.
- Fix: the command is a bare script path (`C:\lab\guest\run.cmd`, which launches `run.ps1`); `lab.ps1` XML-escapes the two host paths.
- Verified: smoke test and every lab run.

## Launching the sandbox with `cmd /c start` from an agent shell
- Symptom: a `WindowsSandboxServer` process without a client window, and no guest.
- Cause: `cmd /c start ... WindowsSandbox.exe x.wsb` from a non-interactive shell.
- Fix: `Start-Process <file>.wsb`, plus the pre-launch check in `lab.ps1` that refuses while any sandbox is listed.
- Verified: all lab runs; `wsb list` and the `WindowsSandboxRemoteSession` process both show a `.wsb`-launched sandbox.

## One sandbox at a time, nothing persists
- Only one instance runs; a second launch attaches to the first. `shutdown /s /t 5` in the guest closes it. Nothing survives except the
  mapped output folder, so every scenario is a fresh machine (about 30 s boot).

## Lab observations in the guest (first runs)
- The LogonCommand token is elevated (`check.elevated: true`, admin role), UAC is disabled there (`EnableLUA=0`,
  `ConsentPromptBehaviorAdmin=5`). Per-machine installs run without a prompt; UAC behaviour is not testable in the lab.
- A `<ReadOnly>true</ReadOnly>` mapping is enforced: writing `C:\lab\.probe` fails, `env.json` records `labWritable: false`.
- `wsb list` prints the GUID of a sandbox launched from a `.wsb`; `wsb list --raw` gives JSON. The running guest has the processes
  `WindowsSandboxRemoteSession`, `vmmemWindowsSandbox` and `WindowsSandboxServer` (the server stays after the guest closes; there was
  no `WindowsSandboxClient`).
- `Add-MpPreference -ExclusionPath` fails in the guest (localized message); installers still run, so it is only logged.
- Inventory noise: unreadable `en-us` / `ru-ru` language folders and one Defender policy key throw in the inventory (`e` lines, listed
  as `inventoryErrors`); they are stable across snapshots and do not affect comparisons.
- Guest `Add-Content` without `-Encoding` writes localized text in ANSI; the lab logs use UTF-8.

## PowerShell 5.1 traps hit while writing the lab
- A scriptblock created in a function and called after the function returned does not see the function's variables: use `.GetNewClosure()`
  (`analyze.ps1` class lookup failed with "cannot call a method on a null-valued expression").
- `$false` cannot be reused as a variable name (read-only automatic variable).
- Lab files must be ASCII-only (no BOM, read as ANSI) and must not use two variable names that differ only in case.

## The msiexec uninstall confirmation is not a plain `IDYES` message box
- Symptom: `msi-*` scenarios ended `native.timedOut` after 300 s; `clicks.log` only said "seen 'Windows Installer' (#32770)".
- Cause: `command::parse_with` rewrites msiexec to `/X{GUID}` without `/quiet`, so Windows Installer shows its own confirmation dialog
  ("Are you sure you want to uninstall this product?"). Its buttons are controls 3001 (Yes) and 3002 (No), there is no control 6, and the
  texts follow the UI language (here Russian).
- Fix: `lab/guest/clicker.ps1` posts `WM_COMMAND` for control 6, or 3001 when 6 is absent, and logs the children of every dialog it does not answer.
- Verified: `msi-located` and `msi-bare-x86` finish; `clicks.log` shows "posted Yes (id 3001)". Note for the product: a real user sees this dialog too,
  and the running screen has no way to answer it for them.

## `HKLM\...\CurrentVersion\App Paths` is mirrored between registry views (lab analysis)
- Symptom: `nsis-machine-svc` FAIL "apply report does not match reality": two ids vanished that no item reported, plus an "unclassified" hklm32 object.
- Cause: the guest inventory lists the key in both the 64-bit and the 32-bit view with identical content, because Windows mirrors App Paths.
  The product offers both views as separate candidates; removing the 32-bit one removes the 64-bit one too, and the second item ends
  `notFound` ("already gone"). The Run key is not mirrored.
- Fix: `analyze.ps1` folds `hklm32:...\app paths\...` ids onto `hklm64` (inventory, manifest, candidates, items). The duplicate offer itself is harmless and not a finding.
- Verified: `nsis-machine-svc` PASS after the change; the other scenarios unchanged.

## Lab manifests: files of the app inside a folder that is "control" because of a neighbour
- Symptom: `shared-suite` and `two-versions` ERROR "control/userdoc object missing after the native uninstaller".
- Cause: `{PF}\Lab Vendor\Lab Suite` is `control` (it holds the plugin), so the suite's own `labsuite.exe`, `uninstall.exe` and the Start Menu
  link `Lab Vendor\Lab Suite.lnk` inherited the class, although the native uninstaller legitimately deletes them (same for `Lab Editor 1.lnk`).
- Fix: explicit longer `owned` patterns for those objects. The `control` entries (the plugin, Editor 2, shared folders, keys) are unchanged.

## `lab.ps1 -File ... -Scenario a,b` arrives as one string
- `powershell -File` does not split the comma list; `lab.ps1` now splits it itself.

## Registry of a nested app offered with the suite (lab `shared-suite`)
- Symptom: lab run `20261118-021251` ended RISK with 5 false deletions: the host suite's scan offered `HKLM\SOFTWARE\Lab Vendor\Lab Suite`
  (its tree holds a `Plugin` subkey with `InstallDir`), `App Paths\labplugin.exe` and the `Run|LabSuitePlugin` value without a block, and the
  `unblocked` policy removed the plugin's registry entries while the plugin was still installed.
- Cause: `scan::evaluate` checked registry targets only by shape (`registry_blocks`) plus `AppStillInstalled`. Nothing looked at what a key tree or
  a Run value points to, so entries that reference another installed app's folder passed. The shortcut-target check lived only in `scan()`
  (not in `evaluate`), so apply never recomputed it.
- Fix: `Anchors::referenced_in` (`safety.rs`) checks every REG_SZ, REG_EXPAND_SZ and REG_MULTI_SZ text of a key tree and of a Run value against other
  apps' install dirs, in `scan::evaluate`, so scan and apply share it. Exemptions: the target's own Uninstall entry (a launcher's uninstaller
  may live in another app's folder; the real-machine check showed Visual Studio Build Tools hit this), an app whose folder holds ours, and drive
  or protected roots. Other apps without InstallLocation are seen through a derived folder (uninstaller's folder when the icon sits beside it); using
  their file anchors instead would block Steam's own key. The shortcut-target check moved into `eval_path` and fails closed (`Unverifiable`)
  when the link cannot be read.
- Verified: tests `nested_app_registry_is_shared`, `nested_app_without_install_location_is_shared` and `broad_install_location_does_not_claim_references`
  (`tests/scan.rs`) and `apply_recomputes_shared_blocks` (`tests/ops.rs`: two apps registered between scan and apply, the offered key and link
  ended `Removed` before the fix and `Blocked` after). Before the fix the first two failed at their first assert with `[]` (no blocks) and the ops
  test with `left: Removed, right: Blocked`; the third guards the root exemption (it fails when the exemption is removed). Read-only run of every real
  app's preview before and after (92 apps, about 2250 candidates): no candidate changed. Lab runs `20261118-141244` (`shared-suite,two-versions`)
  and `20261118-141622` (all eight): `shared-suite` PASS, 0 false deletions, 4 found, 1 missed (the key's own `InstallDir` value, inside a key that is
  now blocked as a whole), 4 removed; the other six rows and their Candidates tables equal run `20261118-021251`.

## Version-neutral settings offered while another version is installed (lab `two-versions`)
- Symptom: lab run `20261118-021251` ended RISK with 4 false deletions: for "Lab Editor 1" the scan offered `%APPDATA%\Lab Vendor\Lab Editor` and
  `HKCU\Software\Lab Vendor\Lab Editor`, which "Lab Editor 2" uses, and the `unblocked` policy removed them.
- Cause: `scan::name_variants` strips the version, so "Lab Editor 1" and "Lab Editor 2" both derive the name `Lab Editor`, and sections E/F turn it into
  a settings folder and key. `anchors_of` only knew other apps' install folders, uninstaller exes and icons, so nothing said that another installed app
  derives the same location.
- Fix: `anchors_of` adds every other app's existing settings folders and Software keys, derived with the target's own rule (`scan::name_pairs`,
  shared by sections E/F). `covering` blocks a path that equals or holds such a folder, `Anchors::key_holding` a key that equals or holds such a key.
- Verified: tests `version_neutral_settings_are_shared` (`tests/scan.rs`, failed at `shared(neutral)` with `[]` before the fix), `anchors_settings_rules`
  (`safety.rs`) and the key part of `apply_recomputes_shared_blocks`; no real candidate changed (see above); lab run `20261118-141622`:
  `two-versions` PASS, 0 false deletions, 5 found, 2 missed (files and a value inside the now-blocked shared folder and key), 5 removed.

## Black window when the app is started from an agent shell
- Symptom: release 0.1.1 started with `Start-Process` from the Claude Code PowerShell tool showed an all-black window with no title bar or
  buttons; no `msedgewebview2.exe` child stayed alive.
- Cause: the WebView2 browser process crashed about 3 s after start (dump in `%LOCALAPPDATA%io.github.takeshilp.uniinstallerEBWebViewCrashpadeports`);
  the dump carries the agent session's environment (`CLAUDE_CODE_SESSION_ATTENDED=1`), so it inherited the restricted agent shell. Not an app defect:
  the same build started from the Start menu worked, and 0.1.0/0.1.1 rendered normally inside Windows Sandbox.
- Fix: none in code. Start the installed app from the Start menu (or ask the owner to); for dev runs use `npm run tauri dev`.
- Verified: 2026-11-18, the owner started 0.1.1 from the Start menu and the UI rendered; the elevation check ran in that instance.
