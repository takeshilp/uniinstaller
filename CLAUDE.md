# Uniinstaller

Windows uninstaller in Rust: runs a program's own uninstaller, waits for its process tree, then lists evidence-scored leftovers
(files, shortcuts, registry, settings) for review. Removals go to a quarantine with a registry backup and can be restored.
Stage-1 safe MVP: core crate (`uni-core`), read-only CLI (`uni`), Tauri 2 GUI in plain HTML/CSS/JS (`ui/`).

## Layout
- `crates/core`: all logic, no UI. `crates/cli`: `uni list|show|plan|history|sandbox-seed|sandbox-clean`.
- `src-tauri`: thin Tauri commands plus updater. `ui/`: `index.html`, `styles.css`, `app.js`, `strings.js`.

## Commands (Git Bash: `export PATH="$HOME/.cargo/bin:$PATH"` first)
- `cargo test --workspace` and `cargo clippy --workspace --all-targets -- -D warnings`
- `npm run tauri dev` (never plain `cargo run`: the window would be blank)
- Real-machine read-only check: `cargo test -p uni-core --test real_system -- --ignored --nocapture`

## Ground rules
1. Never run uninstall, apply or restore against the real system. Destructive flows run only with `UNIINSTALLER_SANDBOX` set
   (seed it with `uni sandbox-seed`) or inside tests. Enforced in code by the debug guard in `ops.rs` and `Env::from_sandbox_var`: do not weaken either.
2. Never print, `cat` or commit the signing key or its password (`~/.tauri/`, outside the repo).
3. Do not weaken a safety rule, threshold or test to make something pass.
4. Every known limit gets a comment `// shortcut: <the limit>, <when to upgrade>`; the list is in `docs/architecture.md`.
5. All UI strings are Russian and live in `ui/strings.js`; code comments and docs are English.
6. Commit on `claude/mvp`; no tag, release or merge into `main` without the owner.

## Docs
- `docs/development.md`: setup, commands, sandbox, screenshots, release and key management, manual checks.
- `docs/architecture.md`: crates, pipeline, data model, safety tables, scoring, storage, statuses, shortcuts.
- `docs/bugs.md`: verified pitfalls and fixed bugs.
