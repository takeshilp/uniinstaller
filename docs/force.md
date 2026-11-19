# Forced removal

Removing a program by a path the user picks: the checks that refuse or allow it, the scan rules for a forced target, the GUI and the lab scenarios.

## Forced removal (`force.rs`, `ops::begin_forced`)
Purpose: remove a program the program list does not know (portable drops, broken installs, leftovers of a failed uninstall) by a path the user picks, without ever
treating a path as a program that something else owns. The GUI entry is "Удалить по пути" (file dialog for an exe or a folder; shortcuts are resolved by the dialog itself).
- Target. A stand-in `InstalledApp` (`force::app_for`: id `force:<norm(picked)>`, no sources, `install_location` = the folder, the picked exe as `display_icon` for a
  file-only pick) plus `Operation.forced`. `Operation.launch` is the found uninstaller, or the empty placeholder (`exe` empty) when none is chosen: `ops::skips_native`
  (forced and empty exe) makes `overall_status` and `scan_leftovers` work without a native run, `run_native` refuses an empty launch. `ForceCheck` (`Ok{found}`, `Listed{app, how}`,
  `Refused{code, detail}`) is only a message for the confirm screen and is never stored; `begin_forced` re-runs `check` and takes only the confirmed name, publisher
  and one of the uninstallers the check found.
- `force::check` rules, in order (every refusal is a result, `Err` only for an unexpected read failure): 1 sanity (local absolute path, inside the sandbox folder in
  sandbox mode, exists, no reparse point, canonical, an `.exe` or a folder; a `.lnk` is `BadPath`); 2 the folder the pick stands for (a folder pick is its own; an exe
  stands for its folder only when that folder is not a root and holds no other program: no other exe besides `unins*`, or every other exe has the same ProductName, else
  file-only); 3 another user's profile; 4 a listed program (hidden included) whose folder (`InstallLocation`, else the uninstaller's folder when the icon sits in it) is
  the pick (`Listed Folder`) or holds it (`Listed Inside`), deepest wins, a tie is `OtherPrograms`; 5 the InstallLocation gate (`scan::dir_problem`); 6 TrustedInstaller
  ownership of the pick and its folder (unreadable owner refuses); 7 `Anchors::covering` (the pick equals or holds another program's files, folder or settings);
  8 an Uninstall key outside the list whose InstallLocation, icon or uninstall command points into the pick and whose uninstaller exists (`Installed`; a key with a missing
  uninstaller is ignored); 9 Windows Installer component registrations (`Env::installer_data`) at or below the pick, or in a folder that holds it (never a root): any product
  not in the list is `Installed`, one listed program is `Listed Installer`, several are `OtherPrograms`; 10 a shortcut to the pick named after a listed program
  (`Listed Shortcut`); 11 a registered service (a driver too) whose `ImagePath` or `ServiceDll` runs from the pick (`Service`; scheduled tasks are not a refusal, the scan offers them, see docs/services.md); 12 what was found (uninstallers `unins*` directly in the folder, `.exe` in
  the real system and `.cmd`/`.bat` in the sandbox; version info read as data; shortcuts; other volume; outside the zones; suggested name = ProductName, else the exe's
  stem or the folder's name, never a parent folder's name).
- Scan rules for a forced target (`scan::scan(.., forced)`): never corroborated, nothing preselected, settings folders and keys looked for only by `Forced.search_names`
  (`force::search_names`: variants of at least `MIN_NAME` = 4 characters, or exactly the product name, the exe's stem or the picked folder's name), shortcuts and Run/App Paths
  references anchored at the picked file for a file-only pick. Every hard block applies unchanged at scan and apply; `ops::forced_in_scope` re-checks the sandbox root at scan and apply.
  Scores: folder child 45 (Review), shortcut 30 + exact name 20 (+ publisher 10, + missing 15), Run value or App Paths key 30 (+15), settings folder 20, settings key
  20 + 30 when a value points into the folder, file-only picked exe 60; the group checkboxes tick Safe and Review items, Weak ones need individual ticks.
- GUI. The confirm screen has no uninstaller preselected and keeps the run button disabled until one (or "do not run") is chosen; after a found uninstaller exits with a
  code other than 0, times out or is stopped, the flow does not go on to the leftovers by itself (spec 3.2). The review, result and history show a "ПРИНУДИТЕЛЬНО" pill.
- Cost. The component scan reads every `Installer\UserData\*\Components` key on each check: 25,087 keys and 25,418 values on the owner's machine, 1.8 s in a release build and
  9 to 11 s in a debug build (about 2.3 s for a whole check in release). A cache per session is the upgrade if it gets slow.
- Measured on the owner's machine (read-only probe `real_system_force_probe`, 2026-11-19): `C:\Program Files`, the profile and `C:\Users\Default` NotAllowed; Windows Mail and Internet
  Explorer NotAllowed (TrustedInstaller); `C:\Program Files\MSBuild` Ok (a residual, see shortcuts); 7-Zip Listed folder; nodejs and GitHub CLI Listed installer; dotnet and Python's
  `Scripts\f2py.exe` OtherPrograms (several MSI products); Perplexity Service; Razer and `Razer\RazerAppEngine` Listed shortcut (Razer Synapse); ASUS `AIOFanSDK` Listed inside; Steam
  ASPIS Listed folder, Jedi Fallen Order Listed inside (Steam); MPV (folder and exe) Ok with the name `mpv`; `D:\2Programs` OtherPrograms; `D:\2Programs\Chrome` and
  `D:\6Games\spartanport` Ok, every file candidate Blocked `OtherVolume`. A probe result that differs from the prediction is a finding, never a reason to loosen a rule.
- Lab. `uni-lab force <path> <name> [--publisher <p>] [--run]` prints the check result and exits 3 for Listed and Refused. Rule 16 in `analyze.ps1` (forced scenarios): ERROR when
  `op-begin.json` has no `forced`, FAIL for any selected candidate, FAIL when `op-apply.json` lost `forced`, FAIL when a run-less operation has a `native`; rule 16e: `expect_force`
  (`listed:<how>` or `refused:<code>`) must match and the system must be unchanged (the 1-to-5 snapshot comparison ignores the unreadable language folders the inventory lists
  unstably right after an MSI install). Scenarios: `force-portable` (NSIS `NOARP`, nothing run, 7 leftovers found, 0 false deletions, restore ok), `force-broken` (Uninstall key
  deleted after install, the found `uninstall.exe` is run, 5 leftovers found), `force-msi-bare` (`listed:installer`) and `force-service` (`refused:service`).
