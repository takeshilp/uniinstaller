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
npm run tauri dev                             # GUI; always through npm, plain `cargo run` gives a blank window
cargo run -p uni-cli -- list                  # read-only CLI on the real machine
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
installed), Sandbox Orphan (batch uninstaller leaves its key), Sandbox Broken (launch error).
`sandbox-clean` refuses unless the folder carries the `.uniinstaller-sandbox` marker.
Debug builds refuse `begin`, `run_native`, `apply` and `restore` for any non-sandbox environment, so `tauri dev` can never uninstall a real program.

## Screenshots
Use a PowerShell `System.Drawing` `CopyFromScreen` script kept outside the repo (find the window by title, `SetProcessDPIAware`, capture its rect).
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
- Elevation: "Перезапустить от имени администратора" (UAC prompt on the secure desktop; unavailable in sandbox mode).
- Updater: needs two published releases; install the older one, publish the newer, check the banner and the update.
- Running screen with a slow uninstaller and "Не ждать дальше".
