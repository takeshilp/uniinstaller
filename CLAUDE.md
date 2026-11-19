# Uniinstaller

Windows uninstaller in Rust: runs a program's own uninstaller, waits for its process tree, then lists evidence-scored leftovers
(files, shortcuts, registry, settings) for review. Removals go to a quarantine with a registry backup and can be restored.
Stage 1 plus install tracing (stage 2): core crate (`uni-core`), read-only CLI (`uni`), Tauri 2 GUI in plain HTML/CSS/JS (`ui/`).

## Layout
- `crates/core`: all logic, no UI. `crates/cli`: `uni list|show|plan|history|sandbox-seed|sandbox-clean`.
- `src-tauri`: thin Tauri commands plus updater. `ui/`: `index.html`, `styles.css`, `app.js`, `strings.js`.
- `crates/lab`: `uni-lab`, lab-only driver, never shipped. `lab/`: Windows Sandbox lab (test installers, guest runner, scenarios, host driver).

## Commands (Git Bash: `export PATH="$HOME/.cargo/bin:$PATH"` first)
- `cargo test --workspace` and `cargo clippy --workspace --all-targets -- -D warnings`
- `npm run tauri dev` (never plain `cargo run`: the window would be blank)
- Real-machine read-only check: `cargo test -p uni-core --test real_system -- --ignored --nocapture`
- Lab (real installs in Windows Sandbox, ~5 min per scenario): `powershell -NoProfile -ExecutionPolicy Bypass -File lab/lab.ps1 [-Scenario <name>]`

## Ground rules
1. Never run uninstall, apply, restore or a traced install against the real system. Destructive flows run only with `UNIINSTALLER_SANDBOX` set
   (seed it with `uni sandbox-seed`), inside tests, or inside Windows Sandbox through the lab (`lab/lab.ps1`). Enforced in code by the debug
   guard in `ops.rs`, `Env::from_sandbox_var` and `uni-lab`'s guest check (token user `WDAGUtilityAccount` plus `UNIINSTALLER_LAB`):
   do not weaken any of them. Never run anything from `target/lab/build` or `lab/guest` on the host.
2. Never print, `cat` or commit the signing key or its password (`~/.tauri/`, outside the repo).
3. Do not weaken a safety rule, threshold or test to make something pass.
4. Every known limit gets a comment `// shortcut: <the limit>, <when to upgrade>`; the list is in `docs/architecture.md`.
5. All UI strings are Russian and live in `ui/strings.js`; code comments and docs are English.
6. Commit on a `claude/<name>` branch; no push, tag, release or merge into `main` without the owner.

## Docs
- `docs/development.md`: setup, commands, sandbox, lab, screenshots, release and key management, manual checks.
- `docs/architecture.md`: crates, pipeline, data model, storage, statuses, known shortcuts.
- `docs/safety.md`: hard blocks, shared-with-other-app rules, scoring weights, hidden programs.
- `docs/tracing.md`: install tracing: capture, diff, trusted journals, reverts, budget.
- `docs/force.md`: forced removal by path: checks, scan rules, GUI, lab scenarios.
- `docs/lab.md`: Windows Sandbox lab: commands, guard, snapshots, trace and hidden-entry scenarios.
- `docs/locked.md`: locked files: who holds them (Restart Manager), close and retry, continuing after a restart, measurements.
- `docs/services.md`: Windows services and scheduled tasks as leftovers: detection, blocks, apply, restore, measurements.
- `docs/bugs.md`: verified pitfalls and fixed bugs.
