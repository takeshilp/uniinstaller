# Host driver for the Windows Sandbox lab: builds, stages the guest input, launches one sandbox per scenario, waits, analyses.
# It never runs an installer, a guest script or uni-lab on this machine, and never deletes anything under target\lab\out.
# Keep this file ASCII-only.
param([string[]]$Scenario, [int]$TimeoutMin = 20, [switch]$StopStale)
$ErrorActionPreference = 'Stop'
$root = Split-Path $PSScriptRoot -Parent
if (-not (Get-Command wsb -ErrorAction SilentlyContinue)) { throw 'wsb.exe (Windows Sandbox CLI) not found: enable Windows Sandbox and update it' }

# One run at a time (build.ps1 rebuilds target\lab\build). The handle closes when this process exits, so no stale lock.
New-Item "$root\target\lab" -ItemType Directory -Force | Out-Null
try { $runLock = [IO.File]::Open("$root\target\lab\lab.lock", 'OpenOrCreate', 'ReadWrite', 'None') }
catch { throw 'another lab.ps1 run is active (target\lab\lab.lock is held)' }

function Get-SandboxIds {
    $ErrorActionPreference = 'Continue'
    $raw = (wsb list 2>$null) -join "`n"
    @([regex]::Matches($raw, '[0-9a-fA-F]{8}-(?:[0-9a-fA-F]{4}-){3}[0-9a-fA-F]{12}') | ForEach-Object { $_.Value })
}
# WindowsSandboxServer runs permanently even with no sandbox open, so it is not listed here.
function Get-SandboxProcs { @(Get-Process -Name WindowsSandbox, WindowsSandboxClient, WindowsSandboxRemoteSession -ErrorAction SilentlyContinue) }
function Test-SandboxRunning { ((Get-SandboxIds).Count -gt 0) -or ((Get-SandboxProcs).Count -gt 0) }
function Stop-Sandbox {
    $ErrorActionPreference = 'Continue'
    foreach ($id in Get-SandboxIds) { wsb stop --id $id | Out-Null }
    Get-SandboxProcs | Stop-Process -Force -ErrorAction SilentlyContinue
}
function Assert-NoSandbox {
    if (-not (Test-SandboxRunning)) { return }
    if (-not $StopStale) { throw "Windows Sandbox is already running (ids: $(Get-SandboxIds); processes: $((Get-SandboxProcs).ProcessName)). Close it or rerun with -StopStale." }
    Stop-Sandbox; Start-Sleep 10
    if (Test-SandboxRunning) { throw 'a running Windows Sandbox could not be stopped; close it by hand' }
}
function Wait-Guest([string]$Dir) {
    $start = Get-Date
    while (-not (Test-Path "$Dir\started.txt")) {
        if (((Get-Date) - $start).TotalMinutes -gt 3) { return 'not-started' }
        Start-Sleep 1
    }
    # Only once started.txt exists can "no sandbox" mean the guest exited early.
    $missing = 0
    while (-not (Test-Path "$Dir\done.json")) {
        if (((Get-Date) - $start).TotalMinutes -gt $TimeoutMin) { return 'timeout' }
        if (Test-SandboxRunning) { $missing = 0 } else { $missing++ }
        if ($missing -ge 3) { return 'exited' }
        Start-Sleep 10
    }
    $doneAt = Get-Date
    while ((Test-SandboxRunning) -and ((Get-Date) - $doneAt).TotalSeconds -lt 120) { Start-Sleep 5 }
    return 'done'
}
function Escape-Xml([string]$text) { [Security.SecurityElement]::Escape($text) }

$all = @(Get-ChildItem "$PSScriptRoot\scenarios\*.json" | ForEach-Object { $_.BaseName })
if (-not $Scenario) { $Scenario = $all }
foreach ($name in $Scenario) { if ($all -notcontains $name) { throw "unknown scenario $name (known: $($all -join ', '))" } }
Assert-NoSandbox
& "$PSScriptRoot\build.ps1"
$run = Join-Path $root "target\lab\out\$(Get-Date -Format yyyyMMdd-HHmmss)"
$in = Join-Path $run '_in'   # the only folder the guest sees read-only; no host-executed script is ever in it
New-Item "$in\build" -ItemType Directory -Force | Out-Null
Copy-Item "$PSScriptRoot\guest" $in -Recurse
Copy-Item "$root\target\lab\build\*" "$in\build" -Recurse
Copy-Item "$PSScriptRoot\.uniinstaller-lab" $in
Copy-Item "$root\target\lab\build\build.txt" $run
$exitCode = 1
try {
    foreach ($name in $Scenario) {
        Assert-NoSandbox
        $dir = Join-Path $run $name
        New-Item $dir -ItemType Directory -Force | Out-Null
        Copy-Item "$PSScriptRoot\scenarios\$name.json" "$dir\scenario.json"
        $wsb = Join-Path $run "$name.wsb"   # outside every mapped folder
        $xml = @"
<Configuration>
  <vGPU>Disable</vGPU>
  <Networking>Disable</Networking>
  <ClipboardRedirection>Disable</ClipboardRedirection>
  <AudioInput>Disable</AudioInput>
  <MappedFolders>
    <MappedFolder>
      <HostFolder>$(Escape-Xml $in)</HostFolder>
      <SandboxFolder>C:\lab</SandboxFolder>
      <ReadOnly>true</ReadOnly>
    </MappedFolder>
    <MappedFolder>
      <HostFolder>$(Escape-Xml $dir)</HostFolder>
      <SandboxFolder>C:\out</SandboxFolder>
      <ReadOnly>false</ReadOnly>
    </MappedFolder>
  </MappedFolders>
  <LogonCommand>
    <Command>C:\lab\guest\run.cmd</Command>
  </LogonCommand>
</Configuration>
"@
        Set-Content $wsb $xml -Encoding UTF8
        Write-Host "[$name] launching Windows Sandbox"
        $launched = Get-Date
        Start-Process -FilePath $wsb   # never cmd /c start
        $status = Wait-Guest $dir
        if (Test-SandboxRunning) { Stop-Sandbox; Start-Sleep 10 }   # also after 'done' if the guest did not close within 120 s
        [ordered]@{ status = $status; seconds = [int]((Get-Date) - $launched).TotalSeconds } |
            ConvertTo-Json -Depth 10 | Set-Content "$dir\driver.json" -Encoding UTF8
        Write-Host "[$name] $status"
        if ($status -eq 'not-started') { Write-Host 'Windows Sandbox did not start; stopping the run'; break }
    }
} finally {
    & "$PSScriptRoot\analyze.ps1" -RunDir $run
    $exitCode = $LASTEXITCODE
    $runLock.Dispose()
}
exit $exitCode
