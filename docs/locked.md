# Locked files and restarts

Stage 2, feature 4: who holds a locked item (Restart Manager, read-only), a user-confirmed close and retry, and continuing after a restart.
Code: `crates/core/src/rm.rs`, `ops.rs` (`lock_holders`, `close_and_retry`, `remind_after_reboot`, `reboot_continuations`), `src-tauri/src/main.rs`, `ui/app.js`.

## What it does
1. Every `Locked` or `AccessDenied` path item gets a probe that finds the exact files and folders whose open handles block the move. The Restart Manager (RM) is asked only about those files. The result
   screen shows each holder (name, PID, kind) and, if Uniinstaller will not close it, why.
2. "Закрыть эти программы и повторить": a modal lists exactly the programs that will be closed. The core re-reads the holders (they must be a subset of the confirmed ones), RM closes exactly those processes
   gracefully, the locked items are retried through the journalled `apply`, then RM restarts what it can.
3. "Повторить после перезагрузки" writes `Operation.continue_after_reboot`; a banner on the next start after a restart offers to continue. No boot-time moves, no RunOnce key.

## The probe and the registered files
`rm::held(path, dir, inside)` opens with `CreateFile(DELETE, OPEN_REPARSE_POINT [+BACKUP_SEMANTICS])` and counts only errors 32 and 33 (error 5, for example Program Files without elevation, is not a lock).
| What is probed | Share mode | Why |
|---|---|---|
| a file item, or a folder item's own handle | all (7) | conflicts only with handles that do not share delete, which is what stops the move; an Explorer or watcher handle on the root is not a false "folder open" |
| an entry below a folder item | none (0) | any open handle below a folder stops the folder's move (error 5, measured, `bugs.md`), so any open handle must fail the probe |
Only failing files go to RM (at most 64 per item); folders are counted ("a folder is open") and never registered; reparse points are neither probed nor followed; at most 20,000 entries are probed.
Side effect: for that instant another program's open can fail with 32 and an oplock can break; a handle opened only for attributes is not seen.

Measurements (owner's machine, non-elevated, 2026-11-19, read-only RM calls):
| Query | `RmGetList` | Result |
|---|---|---|
| unheld file outside Program Files | 1 to 14 ms | none |
| unheld file under `C:\Program Files` | about 240 ms per file, linear | none |
| Discord `Local Storage\leveldb\LOCK` | 549 ms | `Discord`, type 1 (main window), not restartable |
| VS Code `LOCK`, `state.vscdb` | about 480 ms each | `Visual Studio Code`, type 1 |
| `NTUSER.DAT` | 484 to 528 ms | `System` (pid 4) and `Registry`, type 1000 (critical), reasons 0x3 |
| a folder, alone or next to a held file | fails with error 5 | the whole answer is lost, so folders are never registered |
Fixture (`tests/locked.rs`, a compiled window holder, same machine): `lock_holders` 506 ms; `close_and_retry` 558 ms with `shutdown_error` and `restart_error` none; the holder exited, a bystander copy stayed.

## Holders, blocks and reasons
`rm::holders` maps `RM_PROCESS_INFO` to `Holder { pid, started (FILETIME), name, image, service, kind, block }`; the identity is `(pid, started)`. An exe without a version resource gets the name `" "` from RM, so the name is
trimmed and falls back to the image. `rm::block`, in order:
| Block | When | Shown as |
|---|---|---|
| `Ours` | our pid, or any `msedgewebview2.exe` | the app itself or WebView2 |
| `Uninstaller` | `(pid, started)` equals a process recorded in `op.native.processes` | wait for the uninstaller |
| `Critical`, `Service`, `Explorer` | RM type 1000, 3, 4 | restart / stop the service / close Explorer windows |
| `Console` | RM type 5 | close the console window yourself |
| `NeedsForce` | any other type | close it yourself |
| none | type 1 or 2 (window programs) | closable |
Our own process: RM reports it as type 1000 with reason `DetectedSelf` (0x10), measured in `own_process_is_never_closed`. Reasons `PermissionDenied` (1), `SessionMismatch` (2), critical process (4) and
critical service (8) mean only a restart frees the item (`to_close` refuses; the text for 1 says to restart as administrator).
Why console programs are refused: to close one, RM attaches to its console from inside the calling process and sends a control signal that every program in that console receives. The measured PowerShell holder
is type 5, so it is refused.

## The close sequence (`ops::close_and_retry`, `OP_LOCK` held throughout)
1. `guard`, load, refuse a restored operation or one with no locked path items.
2. `holders_of` again (live), then `rm::to_close(live, confirmed)`: refuses on any reason bit, any blocked holder, any live holder whose `(pid, started)` is not in the confirmed list. The result may be empty (the holders left).
3. `rm::close`: refuses an empty list, our pid, a blocked or non-window holder before any RM call; registers the processes as `RM_UNIQUE_PROCESS`, re-reads `RmGetList` and refuses unless every entry is a confirmed
   main-window or other-window program with no reboot reason; then `RmShutdown(session, 0)`. Flags 0 is graceful: an app that asks to save or refuses stays open (shutdown error 351). `RmForceShutdown` and
   `TerminateProcess` are never used.
4. Who is still running is read (`native::alive`), then `apply_locked` retries every locked item (journal first, unchanged code), then `RmRestart`, then an apply error is propagated.
Closing is not journalled: a crash between the shutdown and the restart leaves the apps closed. The Tauri command needs the PIDs the modal showed to equal the last stored holder list (`HolderSlot`), so an unseen
holder is never confirmed. In the app, `Closed { op, closed, still_running, shutdown_error, restart_error }` becomes the strips "Закрыто", "Не закрылись" and "не удалось открыть снова".

## After a restart
`continue_after_reboot` is set by `run_native` when the uninstaller asked for a restart (no items yet) and by `remind_after_reboot(on)` for an operation with a `Locked` or `AccessDenied` item. It is cleared by
`scan_leftovers` (the search is the continuation), by `restore`, by "Не напоминать" and by an `apply` that leaves nothing `Locked` or `AccessDenied`. `overall_status` returns `PendingReboot` while the marker and such an
item exist. `reboot_continuations` returns the operations whose marker is older than `boot_ms()` (now minus uptime); the banner offers Продолжить (a rescan for a native run, the result screen otherwise), Позже and
Не напоминать. Why not `MoveFileEx(DELAY_UNTIL_REBOOT)`: it needs admin, cannot move across volumes into quarantine, runs at boot without revalidating identity or blocks, cannot be journalled, and would move a file
that was reinstalled meanwhile. Why not a RunOnce key: it writes an autostart entry and launches the app unasked. Fast Startup: a shutdown with it is not a restart by uptime, so the texts say "Перезагрузка".

## GUI (`ui/app.js`, `ui/strings.js`)
`state.locks` is loaded after every apply, retry, History open and close (`loadLocks`; a sequence counter drops stale answers). Rows show the holder lines (`lockLines`), the strip `locksStrip` offers the close
button only when every item is closable. The modal renders the frozen `closeList` and sends its PIDs. The result bar offers "Искать остатки" also for an item that ended `Changed`. Manual walk and screenshots:
`docs/development.md` ("Locked files in the GUI").

## Lab
`nsis-user` (key `close`): a compiled window holder and a bystander; rule 19 in `docs/lab.md`. The console refusal is covered only by the fixture.

## Shortcuts
The numbered list (each is a `// shortcut:` comment at the named place) is in `docs/architecture.md`, "Locked files and restarts" (14 items): the probe's side effect, folders never registered, the caps, one RM query per
item, services not registered, only window programs closed, no cancel button, the `HolderSlot` equality, no journal for the close, `scanLabel`, uptime-based restart detection, no marker on old operations, no
boot-time moves, the lab's single holder kind.

## Not checked
RM inside GitHub Actions (the fixture runs in `ci.yml` with the rest of `cargo test`); an app that asks to save or refuses (351); Explorer, a service or an elevated process as a holder; Fast Startup; a real restart.
