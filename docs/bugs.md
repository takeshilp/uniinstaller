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
