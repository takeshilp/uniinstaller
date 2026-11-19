# Windows Sandbox lab

The lab that runs real installers inside Windows Sandbox: the commands, the guard, the host and guest split, snapshots, trace and hidden-entry scenarios.

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
- Snapshots: `s0` baseline, `s1` after installs, `st` (trace scenarios) right after the traced install, `s2` after the native uninstaller, `s3` after the scan,
  `s4a` after a killed apply, `s4` after apply, `s4r` after the rescan, `s5` after restore.
- Tracing in the lab: `uni-lab trace <installer>` runs `trace::installer_launch`, `begin`, `install` (timeout 300 s) and `finish` and prints the journal; it
  fails when the installer did not start, timed out or exited non-zero. A scenario with `"trace": true` has exactly one installer, may set pre-existing state
  with `before_install` (same actions as `after_install`, run before `s0`), the manifest class `revert` (values the install overwrites and the product should
  restore) and the policy `default+reverts` (the preselection plus every unblocked revert). The NSIS test app gets `MODIFY` (points two vendor values at
  itself) and `BACKGROUND` (creates `{PF86}\Other Updater` and changes an unrelated value, a stand-in for a background writer); both are used only by
  `labtrace.exe`. The inventory also covers `LocalLow`.
- Trace rules (`analyze.ps1`, trace scenarios): 15a ERROR when `trace.json` is missing or not linked to the target; 15b FAIL when an owned leftover that
  appeared during the install (`st` minus `s0`, independent of `trace.json`) is not offered; 15c FAIL when a preselected or Safe candidate covers a control,
  userdoc or revert object; 15d each revert value must end `reverted` and equal its pre-install state (ERROR when the install did not change it: a test-app
  bug); 15e FAIL when a control value the install changed is offered as a revert; 15f FAIL when a revert is preselected. Rule 17 (all scenarios) FAILs when a
  removed item covers a place the inventory skips but the product captures (`d3dscache`, `connecteddevicesplatform`). Metrics: `traceCreated`, `traceEvidence`,
  `reverted`.
- Hidden entries: the NSIS test app has a `HIDDEN` flag (`SystemComponent=1`); `labhidden.exe` is the scenario `hidden-user`, `labpluginhidden.exe` the nested
  plugin of `shared-suite-hidden`. `uni-lab list` includes hidden entries and `uni-lab begin` passes `hidden_ok = true` (the lab acts as a user who ticked
  the confirmation; the refusal is tested in `tests/ops.rs`).
- Lab shortcuts: see the list below (the ones marked "lab").
