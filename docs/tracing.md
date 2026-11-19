# Install tracing

What an installer added, how the install trace is captured, diffed, linked and trusted, and how its reverts are applied.

## Install tracing (`trace.rs`)
Purpose: know what an installer added, so that a later uninstall finds its leftovers with evidence instead of guesses, and can write back registry values
the installer overwrote. Flow: the GUI picks an installer (`pick_installer`: `tauri-plugin-dialog`, called from Rust, so JavaScript needs no permission;
the path stays in `TraceSlot`); `installer_launch` turns it into a `Launch` (real system: an `.exe` itself or an `.msi` through
`<system dir>\msiexec.exe /i`; sandbox: only `.cmd` and `.bat` files inside the sandbox folder, so the sandbox GUI can never run a real installer);
`begin` takes the "before" snapshot (read-only, allowed on the real system); `install` runs the installer (`ops::guard`, `ops::lock`, the same process-tree
wait and stop flag as an uninstall); `finish` streams the "after" capture through a `Differ`, links the journal and saves it. The session lives in memory.
- Scope. Files: every zone root once (Program Files x2, UserProgramFiles, AppData Roaming, Local, LocalLow, ProgramData, both Start Menu `Programs`, both
  Desktops), unlimited depth except desktops (one level: folders are items, their content is not). Never entered: another root (walked on its own),
  a protected tree (Windows, Common Files, WindowsApps, `ProgramData\Microsoft`, Package Cache, `Roaming\Microsoft`, `Local\Microsoft`, `Local\Packages`,
  Documents and the other user folders, the data dir, the exe's dir, the GUI's WebView2 profile `%LOCALAPPDATA%\<Tauri identifier>`) and temp. A link is an
  item and is never followed. Registry: software roots (full depth, first-level reserved names skipped), Uninstall and App Paths roots (full depth),
  Run and RunOnce (values only); HKCU is captured once.
- Fingerprints: file size + mtime (ms), folders and links carry none, a registry value is its type plus a SHA-256 of type + data (`BCryptHash`). The "before"
  snapshot keeps file ids with fingerprints and full data only for registry objects; the "after" capture is never stored. `MAX_OBJECTS` is 1,000,000 per
  capture, a hard error, never a truncation.
- Diff. Created, Modified (a different fingerprint) and Deleted (the value's data is not kept). A folder or key that could not be read, in either capture,
  blinds everything below it (never Deleted or Created), and so does a switch between a link and a folder. Noise (browser and GPU caches, crash dumps,
  profiles, `ConnectedDevicesPlatform`) is matched by folder name below the capture root, stays in the journal with `noise: true`, is counted on the result
  screen, never gives evidence, but still counts as "created" when a folder is checked for being unchanged.
- Link and trust. A journal is linked when exactly one new visible Uninstall entry (one level below an `uninstall_roots` entry) appears and the visible list (`list_apps(env, false)`) shows
  one program for it; none or several leave it unlinked and unused. `find_for` returns the newest loadable journal whose linked app shares a source key;
  it is trusted only while display version, install folder (normalised) and uninstall command (trimmed, lowercase) match, and, after the program's own
  uninstaller ran (`scan_leftovers`, not `describe` or `preview`), while no other Uninstall key the install created still exists
  (`ComponentStillInstalled`). An untrusted journal gives no evidence and no reverts and the plan says why (`Plan.trace`).
- Previous data. A Modified value keeps its previous data in the journal only if an allowed revert shape would accept it and its new text points into one
  of the program's own folders (InstallLocation, the uninstaller's and the icon's folder). The scan offers a revert only when the live value still equals the
  value the trace recorded after the install (compared by hash), its text still points into the confirmed install folder, and its key is not another
  app's. A key that holds an attributable value is never offered for deletion. The apply backs up the current value first, writes `previous` with `write_value` (which never creates a key) and
  ends `Reverted`; a value that vanished meanwhile ends `Changed`. The undo is compare-and-set: it writes only while the live value equals `previous`,
  and a changed, missing or deleted value or key is a `Conflict` that is never recreated.
- Scan section G (`scan.rs`). Only topmost created objects are emitted (their parent is not created): a path when `unchanged_path` holds (same fingerprint,
  every current child also unchanged, entries deleted since are fine) and it is not protected; otherwise a protected folder (a Start Menu) or a folder
  near the install folder is entered and its created children are considered one by one; a key likewise with `unchanged_key`; a created value only while
  it still has the recorded fingerprint. Another program's Uninstall entry is never emitted. The evidence merges into a heuristic candidate with the same id.
  Nothing in `evaluate` depends on the trace: every block is computed at scan and again at apply, so a trace never adds or removes a block.
- Measured on the owner's machine (read-only test `real_system_snapshot_cost`, debug build, warm cache, 2026-11-18): 221,335 objects (211,376 files and folders,
  9,959 registry), 11 unreadable folders and keys, 1.8 s for the first capture and 1.4 s for the second (streamed), peak working-set growth 54 MB for both.
  Budget: at most 10 s per capture warm and at most 100 MB growth; if the test ever shows more, stop and investigate instead of raising it.
  In the lab guest (fresh Windows): 4,138 objects in 143 ms. The critic's measurement of the discarded wider scope (Classes and Services, 338,252 objects, 175 MB
  with the old representation) is why those are not captured.
- Attribution: there is none per process. Everything that changed in scope between the two snapshots is in the journal, including other programs'
  background writes; the UI says so on the intro, result and review screens, and a background write is offered but not preselected unless it is the install folder.
