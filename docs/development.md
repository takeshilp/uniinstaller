# Development

## Prerequisites
Windows 11, Rust (stable, 1.90+; edition 2024), Node 24 with npm, Visual Studio 2022 Build Tools, Git, `gh` for releases.
Cargo lives in `%USERPROFILE%\.cargo\bin` and is not on PATH by default:
- Git Bash: `export PATH="$HOME/.cargo/bin:$PATH"`
- PowerShell: `$env:PATH = "$env:USERPROFILE\.cargo\bin;$env:PATH"`

Environment variables do not survive between separate shell calls; set what a command needs in the same call.

## Build, test, run
```bash
npm install                                   # only @tauri-apps/cli
cargo test --workspace                        # fixtures only: temp dirs and HKCU\Software\uniinstaller-tests\<tag>
cargo clippy --workspace --all-targets -- -D warnings
cargo test -p uni-core --test real_system -- --ignored --nocapture   # read-only, real machine
cargo test -p uni-core --test real_system real_system_snapshot_cost -- --ignored --nocapture   # install-trace snapshot cost: objects, ms, memory
npm run tauri dev                             # GUI; always through npm, plain `cargo run` gives a blank window
cargo run -p uni-cli -- list                  # read-only CLI on the real machine; `list --hidden` adds the SystemComponent entries
# dry run of every program to a file (diff two dumps to see what a rule change does to real data; UNI_PREVIEW_HIDDEN=1 adds hidden entries):
UNI_PREVIEW_DUMP=<file> cargo test -p uni-core --test real_system real_system_preview_dump -- --ignored --nocapture
```
`uni show <id>` prints the parsed uninstall command, `uni plan <id>` a dry-run plan. Neither changes anything
(`export_plan` and reports only write JSON under `%LOCALAPPDATA%\uniinstaller-data`).

## The sandbox (the only place destructive flows may run)
`UNIINSTALLER_SANDBOX=<absolute dir>` switches the whole app to fake folders under that directory and fake registry keys under
`HKCU\Software\uniinstaller-tests\sandbox`. A present but invalid value is an error, never a fallback to the real system.
```powershell
$env:UNIINSTALLER_SANDBOX = "$env:TEMP\uni-sandbox"; cargo run -p uni-cli -- sandbox-seed; npm run tauri dev
# ... walk through the flows; the title bar must show the ПЕСОЧНИЦА pill before any destructive click ...
$env:UNIINSTALLER_SANDBOX = "$env:TEMP\uni-sandbox"; cargo run -p uni-cli -- sandbox-clean
```
Seeded programs: Sandbox Notes (full flow), Sandbox Suite (shared and foreign-uninstaller blocks), Sandbox Shared Tool (stays
installed), Sandbox Orphan (batch uninstaller leaves its key), Sandbox Broken (launch error). "Sandbox System Component" is hidden and has no uninstall
command, so it appears only with "Показать скрытые". To walk the hidden flow on Notes, hide it first:
`reg add "HKCU\Software\uniinstaller-tests\sandbox\Uninstall\SandboxNotes" /v SystemComponent /t REG_DWORD /d 1 /f` (and the same for `Uninstall32`).
"Sandbox Portable" (folder `users\me\AppData\Local\Programs\Sandbox Portable`, no Uninstall entry; an `unins000.cmd`, a Start Menu link, a Run value, a settings folder and a key name it) is the demo for
"Удалить по пути". Read-only probe of the owner's machine for the identity check (nothing is run, version info is read as data; `%VAR%` is expanded):
`UNI_FORCE_PATHS='C:\Program Files\MPV;D:\2Programs' cargo test -p uni-core --test real_system real_system_force_probe -- --ignored --nocapture`.
Demo installer for install tracing: `<root>\installers\sandbox-traced-setup.cmd` (and `sandbox-traced-uninstall.cmd`), written by `sandbox-seed`. It
installs "Sandbox Traced" under `pf\Trace Soft`, adds settings (with a `Cache` folder), a hidden component (`SandboxTracedRuntime`), an App Paths key, a Run value and
vendor values, overwrites four values that exist before it runs (Run `SandboxTraced`, App Paths `shared-tool.exe`, `Shared Soft\Common|Handler`, and Sandbox
Notes' `InstallDir`), and stands in for a background writer (`pfx86\Other Updater`, `Other Soft\Updater|LastCheck`). In sandbox mode the GUI's "Отследить установку"
dialog starts in `installers\` and offers only `.cmd` and `.bat`; `trace::installer_launch` refuses anything else, so a real installer can never run from a sandbox GUI.
`sandbox-clean` refuses unless the folder carries the `.uniinstaller-sandbox` marker.
Debug builds refuse `begin`, `run_native`, `apply`, `restore` and `trace::install` for any non-sandbox environment, so `tauri dev` can never uninstall or install a real program.

## The lab (Windows Sandbox, real installers)
Purpose: run real installers and the product's real uninstall, scan, apply and restore flow inside Windows Sandbox and measure the
result with an independent inventory (recall, false deletions, restore, resume after a kill). This is the only place the
`Env::system()` destructive flow ever runs.
- Prerequisites: Windows Sandbox with the `wsb` CLI; .NET SDK 8 (`lab/build.ps1` installs WiX 5 into `target\lab\tools` from nuget.org
  on the first build); NSIS from the Tauri cache (`npm run tauri build` once) or from PATH.
- Run all scenarios: `powershell -NoProfile -ExecutionPolicy Bypass -File lab/lab.ps1`. One: add `-Scenario <name>[,<name>]`.
  Re-analyse an old run without a sandbox: `powershell -NoProfile -ExecutionPolicy Bypass -File lab/analyze.ps1 -RunDir target\lab\out\<run>`.
  `-TimeoutMin <n>` caps a scenario (default 20; a guest finishes in about 10 s, so only `-TimeoutMin 0` exercises the timeout path); `-StopStale` stops a Windows Sandbox that is already running (only Windows Sandbox
  processes and `wsb stop` are ever used).
- Runtime: a build takes about 30 s, a sandbox boot plus scenario about 30 s; a full run is a few minutes. Each launch opens a sandbox
  window on the desktop. Agents should run it in the background.
- Never run `target/lab/build/*` or `lab/guest/*` on the host: they install, delete and shut down. The only host-side call allowed is
  `target\lab\build\uni-lab.exe check`, which must refuse (exit 2). Real installs, uninstalls, applies and restores happen in the guest only.
- Outputs under `target\lab\out\<run>\`: `_in\` (staged guest input, mapped read-only as `C:\lab`), `<scenario>\` (raw guest output,
  mapped read-write as `C:\out`), `<scenario>.wsb`, `_results\` (`<scenario>.json`, `<scenario>.md`, `summary.md`).
- Delete old runs only with `cmd /c rmdir /s /q <run>`, never with PowerShell `Remove-Item -Recurse`: PowerShell 5.1 can follow reparse
  points the guest created.
- One lab run at a time; `target\lab\lab.lock` enforces it, and a second `lab.ps1` refuses ("another lab.ps1 run is active"). A Windows
  Sandbox that is already running makes `lab.ps1` refuse until it is closed or `-StopStale` is given.
- Lab scripts are ASCII-only and never use two variable names that differ only in case (PowerShell 5.1). Check with
  `grep -rnP '[^\x00-\x7F]' lab/`.
- Verdicts: ERROR (the run is not trustworthy: driver, guest or exit-code problem, nothing measured), FAIL (a product defect: false
  deletion, inconsistent apply report, inexact restore, changed scan, bad resume), RISK (a user-data or control object removed that the
  product offered without a block and the policy `unblocked` ticked), PASS. Recall and precision are reported, not gated. Known gaps
  (service, task, Classes, locked file, MSI with empty InstallLocation) are listed and never fail a scenario.
- Adding a scenario: `lab/scenarios/<name>.json` with `install` (files in `target\lab\build`, built by `lab/build.ps1`), `after_install`
  (`file`, `delete`, `regval` actions), `target` (the DisplayName), `select` (`default`, `default+reverts` or `unblocked`), optional `lock`, `crash`,
  `expect_begin_error`, `trace` (the single installer runs under `uni-lab trace`, see below), `before_install` (actions run before the baseline `s0`, for state that
  an install overwrites), and the manifest classes `owned`, `userdoc`, `control`, `gap` and `revert` (values the install overwrote and the product should write
  back; the analyzer maps `revert:<id>` candidates onto their `value:<id>`). Patterns start with `key:` or `value:` for
  registry ids, anything else is a path. Tokens: `{PF} {PF86} {CF} {PD} {APPDATA} {LOCALAPPDATA} {DESKTOP} {PUBDESKTOP} {PROGRAMS}
  {COMMONPROGRAMS} {DOCS} {TASKS}`. Matching is case-insensitive, the longest pattern wins, a `key:` pattern covers its subkeys and values.
  Spell `software\\microsoft\\windows\\currentversion` out in full. A RISK or FAIL is a product finding: never edit the manifest or the
  policy to turn it green.

- Hidden scenarios: `hidden-user` (per-user NSIS app with `SystemComponent=1`, expected PASS, 0 false deletions, restore ok) and `shared-suite-hidden`
  (`shared-suite` with the nested plugin hidden, expected PASS with the same Candidates table as `shared-suite`; before the anchor change it was FAIL).
- Forced-removal scenarios (`force-portable`, `force-broken`, `force-msi-bare`, `force-service`, manifest keys `force: { path, name, publisher, run }` and `expect_force`, action `delkey`):
  `force-portable` installs an NSIS app built with `NOARP` (no uninstaller, no Uninstall entry) and removes it by path without running anything (PASS, 7 leftovers found, 0 false
  deletions, restore ok); `force-broken` deletes the Uninstall key after the install and runs the found `uninstall.exe` (PASS, 5 found); `force-msi-bare` expects `listed:installer` and
  `force-service` `refused:service` (rule 16e). A RISK or FAIL is a product finding, never fixed by editing the manifest.
- Trace scenarios (`trace-machine`): the app is installed by `uni-lab trace` between two product snapshots, so the journal and the inventory are compared
  independently (rules 15a-15f and 17 in `docs/lab.md`). Expected: PASS, 3 reverted values, 0 false deletions, `{PF86}\Other Updater` offered at
  Review and not selected, no revert for the unrelated `LastCheck` value. A RISK or FAIL is a product finding, never fixed by editing the manifest.

## Screenshots
Keep the script outside the repo. Capture only the app window: find it by title, `SetProcessDPIAware`, then `PrintWindow(hwnd, hdc, 2)` into a bitmap (it
renders the window itself, so windows on top of it do not leak into the image; `CopyFromScreen` of the window rect does include them).
Driving the sandbox GUI without touching the mouse: UI Automation (`System.Windows.Automation`) reaches the app window; buttons and checkboxes answer
`InvokePattern` and `TogglePattern` by name; the native file dialog is a child `#32770` whose list items answer `InvokePattern` (the file-name field does
not). The expandable group headers are plain `div`s without a pattern: post `WM_MOUSEMOVE`, `WM_LBUTTONDOWN` and `WM_LBUTTONUP` (or `WM_MOUSEWHEEL`) to
the `Chrome_RenderWidgetHostHWND` child with `PostMessage` (client coordinates of the screenshot).
Real-system screenshots: list, card, confirmation modal (opened and cancelled) and preview only.

## Release
1. Bump `version` in `src-tauri/Cargo.toml` (and `tauri.conf.json`), commit.
2. `git tag vX.Y.Z && git push origin vX.Y.Z`. `.github/workflows/release.yml` runs the tests, builds a signed NSIS installer and
   publishes the release plus `latest.json`. The app checks `releases/latest/download/latest.json`.
3. Local signed build check (never run the release exe against the real system for testing):
```bash
TAURI_SIGNING_PRIVATE_KEY="$(cat "$HOME/.tauri/uniinstaller.key")" \
TAURI_SIGNING_PRIVATE_KEY_PASSWORD="$(cat "$HOME/.tauri/uniinstaller.key.password")" \
npm run tauri build     # target/release/bundle/nsis/Uniinstaller_<v>_x64-setup.exe and .sig
```

### Key management
- Key pair: `~/.tauri/uniinstaller.key` and `.key.password` (outside the repo, ignored by `.gitignore`); the public key is in `tauri.conf.json`.
- GitHub secrets `TAURI_SIGNING_PRIVATE_KEY` and `TAURI_SIGNING_PRIVATE_KEY_PASSWORD` were set with `gh secret set ... < file`.
- The password file sits next to the key, so at rest the key is protected only by the Windows account.
- During `tauri build`, locally and in CI, the key and password are in the environment of every dependency's build script.
- Rotating the key: generate a new pair, put the new pubkey into `tauri.conf.json`, reset both secrets. Installed versions signed with
  the old key cannot auto-update and must be reinstalled manually.

## Manual checks (not automated)
- Elevation: "Перезапустить от имени администратора" (UAC prompt on the secure desktop; unavailable in sandbox mode). Verified on
  2026-11-18 with release 0.1.1 on the owner's machine: from the 7-Zip card the app restarted elevated (title pill, warning strip gone,
  token elevated). The owner has to click and confirm UAC; Windows Sandbox runs with UAC off and cannot test it.
- Launch the installed app from the Start menu, never from an agent shell (see `docs/bugs.md`, black window).
- Updater: verified end to end on 2026-11-18 in Windows Sandbox with networking on: published 0.1.0 installed silently (`/S`),
  the banner offered 0.1.1 about 6 s after start, the update button (pressed through UI Automation) downloaded, verified and
  installed 0.1.1 in about 5 s. Repeat at a release that changes the updater config, the signing key or the NSIS install mode.
- Install tracing in the GUI (sandbox only; the title bar must show the ПЕСОЧНИЦА pill): `sandbox-seed`, `npm run tauri dev` with `UNIINSTALLER_SANDBOX` set, then
  "Отследить установку" -> choose `installers\sandbox-traced-setup.cmd` -> Начать -> Готово -> Открыть программу (card shows the journal strip) -> Предпросмотр
  остатков (strip, the "Прежние значения" group, a blocked row for Sandbox Notes' `InstallDir`) -> Запустить деинсталлятор -> tick "Прежние значения" ->
  Удалить выбранное (confirmation for 3 values) -> Восстановить всё. Verified on 2026-11-18: 26 created objects and 5 modified values, 3 values returned, the Run
  value exactly as the installer left it after the restore. Never pick a real installer, even in sandbox mode (the core refuses anyway).
- Hidden programs in the GUI (sandbox only, ПЕСОЧНИЦА pill): hide Notes with the `reg add` lines above, then: Notes is absent; tick "Показать скрытые" and Notes and
  "Sandbox System Component" appear with the "СКРЫТАЯ" pill; the Notes card shows the warning strip; "Запустить деинсталлятор" opens the dialog with the run
  button disabled; tick the confirmation and it is enabled; run, review, "Удалить выбранное", "Восстановить всё". Verified on 2026-11-19 with UI Automation: all of the above, Run disabled until the box is ticked; the restore returned everything.
- Forced removal in the GUI (sandbox only, ПЕСОЧНИЦА pill): "Удалить по пути" -> "Выбрать программу…" -> the native dialog (drive it with UI Automation: it is a child `Window` of the app
  window; the file-name box is a `ComboBoxEx32` > `Edit` with automation id 1148 (1152 in the folder dialog) that answers `WM_SETTEXT` but not `ValuePattern`, and "Открыть" answers
  `BM_CLICK`) -> `...\Local\Programs\Sandbox Portable\portable.exe`. The confirm screen suggests "portable" (no version info), shows `unins000.cmd` unselected and the run button
  disabled until it or "Не запускать" is chosen; run, review (forced strip, nothing ticked), tick the groups (Weak rows need their own tick), "Удалить выбранное", the result
  with the ПРИНУДИТЕЛЬНО pill, "Восстановить всё". Also: the folder dialog on the same folder, `pf\Sandbox Soft\Shared Tool` (Listed folder, "Открыть программу" opens its card),
  Sandbox Notes' `resources` (Listed inside, no open button), `pf` and the sandbox root (refused). Verified on 2026-11-19, see `docs/bugs.md`. UI Automation names of buttons with an icon glyph start with the glyph: match by suffix.
- Running screen with a slow uninstaller and "Не ждать дальше".
- Mark-of-the-Web on an installer (NOT run by the agent: it can pop a security dialog on the desktop). In the sandbox GUI: write
  `Set-Content -LiteralPath "<sandbox>\installers\sandbox-traced-setup.cmd" -Stream Zone.Identifier -Value "[ZoneTransfer]`r`nZoneId=3"`, trace the
  installer again and note whether a security prompt appears, whether the run fails or waits, and what the result screen shows; then
  `Remove-Item -LiteralPath <that file> -Stream Zone.Identifier`. `ShellExecuteExW` runs with `SEE_MASK_FLAG_NO_UI`, so a prompt may be suppressed and
  the run may end with a launch error; record the observed behaviour in `docs/bugs.md`.
