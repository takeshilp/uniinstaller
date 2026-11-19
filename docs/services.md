# Windows services and scheduled tasks

Windows services and scheduled tasks as leftovers: how they are found, what blocks them, how they are removed and recreated, and what was measured. Code: `crates/core/src/sysobj.rs`, scan section H in `scan.rs`, the rules in `safety.rs`, the journalled flow in `ops.rs`.

## What it does
After a program's own uninstaller ran, the scan lists the services and scheduled tasks that still run something from the program's folder (or from the picked file of a forced removal). Each is a candidate in the new group `Group::Services` ("Службы и задачи"). Nothing is preselected. Apply stops a running service (never kills it) and deletes the service through the Service Control Manager, or deletes the task through the Task Scheduler, after saving a full backup in the operation manifest; "Восстановить всё" recreates them. Debug builds and tests never touch a real service or task: real calls run only in a release build, and the repository only exercises them inside Windows Sandbox through the lab.

## Detection (`sysobj.rs`, scan section H)
- Services: every key under `Env.services` (`HKLM\SYSTEM\CurrentControlSet\Services`, 64-bit view). Read: `Type`, `ImagePath` (environment expanded, `\??\`, `\\?\`, `\SystemRoot\` and a relative `system32\` normalised by `image_text`), `Parameters\ServiceDll`, `Group`, `DependOnService`, `DependOnGroup`, `DeleteFlag`. The running state comes from the SCM (`QueryServiceStatus`), for display only.
- Tasks: Task Scheduler 2.0 COM (`ITaskService`): recursive folders, `GetTasks(TASK_ENUM_HIDDEN)`, the exec actions of each definition (`<Path> <Arguments>`, environment expanded), the count of other actions, `Enabled`; the XML only for a candidate. The files under `System32\Tasks` are not read (listing them needs admin, and the API is authoritative).
- A service is a candidate when its image or `ServiceDll` text names the confirmed folder (`force::names`: a folder reference, or the exact file for a file-only forced target); a task when any exec action does. Evidence: `RefersToInstallDir` +30, `InstallDirCorroborated` +35, `TargetMissing` +15 (the program file, `service_binary` or the action's exe, is gone). Drivers, per-user services, Windows' own programs and `\Microsoft` tasks are emitted too and reported as Blocked.
- Services marked for deletion (`DeleteFlag=1`) are not offered; apply treats them as gone.

## Scoring and preselection
Corroborated, program present: 65 (Review). Corroborated, program gone (the normal state after an uninstall): 80 (Safe). Not corroborated (a forced target): 30 or 45, never Safe. `default_selected` excludes `Group::Services`, so even Safe rows are unticked; the group checkbox ticks the Safe and Review rows, Weak rows need their own tick. No trace evidence exists (services and tasks are not captured, see `docs/tracing.md`).

## Blocks (recomputed at apply)
| Rule | Code |
|---|---|
| A driver (`Type & 0x0F`), a per-user service (`& 0xC0`), a Type without a Win32 service bit, a task with an action other than a program | `Unsupported` |
| The program belongs to Windows: it lies in a protected tree of the env or the real folders (Windows, Common Files, `ProgramData\Microsoft`, WindowsApps, Package Cache), or it exists and is owned by TrustedInstaller, or its owner cannot be read (`program_protected`) | `ProtectedPath` |
| A task under `\Microsoft` (compared by component) | `ProtectedPath` |
| The command lines also name a Program Files place outside the program's folder (`names_elsewhere`; measured: the NVIDIA driver update task runs NvContainer with `-d "...\NVIDIA App\..."`) | `SharedWithOtherApp` |
| Every captured value of the service key points into another app's folder (`tree_refers`, like a registry key; covers `Parameters\Application` of srvany and nssm) | `SharedWithOtherApp` |
| Another non-marked service depends on it by name or by its group (`dependents`, fail closed when a key cannot be read) | `SharedWithOtherApp` |
| The command lines no longer refer to the program (a tampered plan names another service or task) | `OutsideAllowedZone` |
| The service key cannot be read (access denied without admin), or a dependency check failed | `Unverifiable` |
`Services` keys stay `ProtectedRegistry` as registry targets; a service is only removed as `Target::Service` through the SCM.

## Apply
`target_rank` puts services and tasks first (a running service holds its files, a task could start the program during the apply). The record is journalled with `reg_backup` (`Ident::Service` / `Ident::Task`) before anything happens. A service: `OpenServiceW(STOP|QUERY_STATUS|DELETE)`; if it is not stopped, `ControlService(STOP)` and a 30 s wait polled every 250 ms (never a kill: after the wait the call fails with 1053 and the item ends `Locked`, nothing deleted); then `DeleteService`. When the key is still there after 1 s the SCM only marked it, and the item ends `Removed` with the detail `sysobj::DEFERRED`. Error 1072 ends `NotFound`; 1060 is `NotFound` only when the key is gone too. A task: `ITaskFolder::DeleteTask`; its emptied folder stays. The running state is not part of the identity (`ops::same_ident`): the scan's whole key is compared, so a stop that timed out or a demand start does not make the item `Changed`.

## Backup and restore
The backup is the whole service key (`RegNode`: everything `QueryServiceConfig(2)` returns plus Parameters and Security) or the task XML plus its actions and `Enabled`. `ops::restore_system` first re-checks the blocks, because a manifest is user-writable: the backup must be of the same name, a Win32 service, a program that is not Windows', a task outside `\Microsoft`; otherwise the item ends `Failed` with `blocked: ...` and nothing is created. Then `sysobj::recreate_*`:
- Service: the key exists already: `DeleteFlag=1` is `Failed` ("restart Windows and restore again"), an equal capture is `Restored`, anything else is `Conflict` and untouched. Otherwise `CreateServiceW` (type, start, error control, raw `ImagePath`, group, dependencies, account without password, display name), delayed start through `ChangeServiceConfig2W`, then the key's values and subkeys are merged back (`registry::restore_node` keeps existing values), and the capture is compared with the backup (`Restored` or `Conflict` naming the first differing values). An account that is not LocalSystem, `NT AUTHORITY\*` or `NT SERVICE\*` adds the detail to set its password again. Nothing is started.
- Task: an equal live XML is `Restored`, a different one `Conflict`. Otherwise `NewTask` + `SetXmlText` only to read the logon type (stored-password types 1 and 6 end `Failed`), then `RegisterTask(TASK_CREATE)` of the original XML text (the folder is created when missing) and a comparison of the live XML.

## Elevation
Reading works without admin; removing needs it. Measured on the owner's machine non-elevated (2026-11-19): 866 service keys, 474 drivers, 340 Win32 services, 48 per-user, 65 without `ImagePath`, 233 with a `ServiceDll`, 1 marked for deletion; 38 third-party Win32 services, 9 of which have an unreadable `Security` subkey (DiscordSystemHelper, EasyAntiCheat_EOS, Elytra.Service, LGHUBUpdaterService, MDCoreSvc, NvContainerLocalSystem, PerplexitySandboxSvc, Steam Client Service, VSInstallerElevationService), so they are `Unverifiable` until the app runs as administrator; 197 visible tasks (180 under `\Microsoft`, 17 elsewhere) and 115 with non-exec actions. The review shows a warning strip with the restart button when not elevated; the wording tells the user to restart as administrator before removing anything, because after a first apply the operation offers no rescan. An elevated task count was not measured (the agent cannot elevate): the probe prints it when the owner runs it elevated.

## Sandbox stand-ins
In a sandbox (`Env.sandbox`) services are keys under `Env.services` (the same layout as the real keys, so one reader serves both) and tasks are keys `Env.tasks\<folder>\<name>` with `Xml`, `Actions` (multi-string), `Other` and `Enabled`. `sandbox-seed` creates `SandboxNotesSvc` and `\Sandbox Soft\Sandbox Notes Update` for Sandbox Notes. `sysobj::sandbox_task` refuses a real environment. Every destructive function branches on `env.sandbox` and the real branch starts with `real_guard` (refuses in a debug build).

## Forced removal
`force::check` rule 11 reads services through `sysobj::services`: a registered service (a driver too, a `ServiceDll` svchost service too) that runs from the pick still refuses it (`Service`), now also for `ServiceDll` and drivers, never weaker. Tasks are not a refusal: a forced scan offers them (30 or 45, never Safe, never selected).

## Real data
Read-only probe `real_system_services_tasks` (debug build, non-elevated, 2026-11-19): `services()` 32 ms for 866 keys, `tasks()` 332 ms for 197 tasks; a dry run of all 282 programs (hidden included) takes about 111 s in a debug build against 81 s before (each scan with a confirmed folder enumerates both lists once). Preview dump before and after (94 visible programs: 2227 to 2248 lines; 282 with the hidden ones: 3344 to 3368): no line changed or removed, only `service:` and `task:` lines added (21 and 24), none selected. The added candidates (tier, score, blocks):
- Armoury Crate Service `armourycrateservice` Review 65; ASUS Framework Service: tasks `\asus\acpowernotification`, `\asus\armourysocketserver`, `\asus\noisecancelingengine` Review 65, `\asus\p508poweragent_sdk` Safe 80 (its program is gone).
- Google Chrome `googlechromeelevationservice` Review 65; Microsoft Edge `microsoftedgeelevationservice` Weak 30.
- Malwarebytes `mbamservice` and `mbvpntunnelservice` Review 65.
- Microsoft OneDrive: the startup task (its name ends with the user SID), `filesynchelper` and `onedrive updater service`, Review 65.
- MSI Afterburner: task `\msiafterburner` Review 65; `rtcore64` Blocked `Unsupported` (a driver).
- NVIDIA Container: task `\nvdriverupdatecheckdaily_{...}` Blocked `SharedWithOtherApp` ("also refers to c:\program files\nvidia corporation\nvidia app\nvdriverupdatecheck outside the program's folder", as expected); service `nvcontainerlocalsystem` Blocked `Unverifiable` (access denied without admin).
- NVIDIA FrameView SDK `fvsvc` Weak 30; PowerToys task `\powertoys\autorun for theme` Weak 30.
- Logitech G HUB `lghubupdaterservice` and Visual Studio Installer `vsinstallerelevationservice` Blocked `Unverifiable` (access denied).
- Wallpaper Engine service (its binary is `C:\Windows\system32\wallpaperservice64.exe` with an argument into the Steam folder): Blocked `ProtectedPath` for Wallpaper Engine and Steam, and `SharedWithOtherApp` for Steam (the argument points into another app's folder). Fail closed and documented: a service whose program lies in the Windows folder is never offered.
- Yandex Telemost: task `\yandex telemost verify install` and `yandextelemostupdateservice` Weak 30.
The force probe verdicts (Perplexity Refused Service, MPV Ok, 7-Zip Listed, `D:\2Programs` Refused OtherPrograms) were byte-identical before and after the change.

## Lab (Windows Sandbox, the only place the real SCM and Task Scheduler calls run)
`nsis-machine-svc` (a per-machine NSIS app with a service created by `sc create` and a task by `schtasks /create`) runs with the policy `default+system`: both are found (80 Safe, not preselected, group Services), removed (`ControlService` is skipped because the service is stopped; `DeleteService` and `DeleteTask` through the real APIs), and the restore recreates them with `CreateServiceW` plus the merged key and `RegisterTask`: the task XML hash and the six service values (ImagePath stays `ExpandString`) are equal in the inventory before the apply and after the restore, and the scan and rescan changed nothing. Runs 20261119-180421 (`nsis-machine-svc`, `force-service`) and 20261119-180600 (all 15 scenarios) are PASS; the other 13 scenarios are unchanged apart from the new `systemRemoved` line. Not exercised: stopping a running service, a custom security descriptor, tasks with a stored password.

## Known shortcuts
Each is also a `// shortcut:` comment in the code; the list is in `docs/architecture.md`.
1. Detection by reference only; no trace evidence, no name match; an app without a confirmed folder gets none.
2. Never preselected; the tier comes from uncalibrated weights.
3. Any dependent blocks; remove the program that owns the dependent first. After a first apply the operation offers no rescan.
4. The stop waits 30 s, no stop button, never kills; a service that does not stop ends Locked, and Locked can be retried by hand or after a restart (docs/locked.md).
5. A service only marked for deletion ends `Removed` with a detail; there is no PendingReboot status per item.
6. Restore sets only the `CreateServiceW` fields and delayed start through the API; the other values apply at the latest after a restart; passwords are not restored.
7. Tasks with a stored password cannot be recreated; a task's security descriptor is not backed up.
8. Emptied task folders, the `TaskCache` entry and the svchost group list entries stay.
9. Non-exec task actions are not matched (such a task is Unsupported); the working directory is not matched.
10. Indirect display names show the key name.
11. Non-elevated, a service with an unreadable `Security` subkey is Unverifiable and tasks the user cannot read are not seen; restart as administrator before removing anything.
12. Drivers and per-user services are report-only.
13. Backups are user-writable (extends the existing shortcut): restore re-checks the blocks, but a tampered backup could still recreate a LocalSystem service of a program outside Windows; the stage-2 helper and a protected store fix this.
14. `%VAR%` expands in our environment; another user's per-user paths are matched against ours.
15. A recreated service or task that differs from its backup ends Conflict although it exists again.
16. Each scan enumerates all services and tasks once; cache per session if previews get slow.
17. Lab: a running service, a custom security descriptor and password tasks are not exercised (the payload is not a service binary).
18. Program Files roots only for the "outside the program's folder" rule; fail closed, the program's own second folder blocks too.
19. An existing program whose owner cannot be read blocks the service (fail closed).
