# Uniinstaller

A safe Windows uninstaller. It runs a program's own uninstaller, waits for its whole process tree, then shows what is left behind
(files, shortcuts, autorun and registry entries, settings) with the evidence for each item. You review and tick what to remove.
Everything removed goes to a quarantine with a structured registry backup, so it can be restored from the history.

Stage-1 safe MVP: native uninstall plus conservative leftover review. Not included: services and scheduled tasks, MSIX packages, a
privileged helper, batch uninstall, Restart Manager.

## Safety model
- Nothing is removed without your confirmation; the uninstaller itself is started only after a confirmation dialog.
- Hard blocks that can never be overridden: protected folders (Windows, Program Files roots, user profile folders, Documents and other
  user folders, OneDrive), registry keys outside fixed shapes, anything that belongs to another installed program, aliased paths
  (junctions, 8.3 names), anything that cannot be verified, files on another drive.
- Evidence scoring decides what is preselected. Files from the install folder and the "settings and data" group are never preselected.
- Every item is revalidated immediately before it is touched and journalled before it is changed; an interrupted run can be restored.
- Restore never overwrites existing files or values.

## Install
Download the installer (`Uniinstaller_<version>_x64-setup.exe`) from the Releases page of this repository. It installs per user and updates itself from GitHub Releases.

## Build from source
```bash
npm install
cargo test --workspace
npm run tauri dev       # debug builds refuse destructive operations outside the sandbox
npm run tauri build     # release build; needs the signing key in the environment, see docs/development.md
```
Details: `docs/development.md`, `docs/architecture.md`.

## Security notes
When you restart Uniinstaller as administrator, the backups it creates are still stored in your user profile
(`%LOCALAPPDATA%\uniinstaller-data`), and Uniinstaller itself is installed per user. Another program running under your account could
tamper with them before an elevated restore. A separate privileged component with a protected store is planned.
