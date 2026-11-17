# Windows Sandbox guest runner (LogonCommand via run.cmd), one scenario per launch. Keep this file ASCII-only.
# It installs software, removes it with uni-lab and shuts the machine down, so the guard below must stay first.
$ErrorActionPreference = 'Stop'
function Test-Guest { [Security.Principal.WindowsIdentity]::GetCurrent().Name -match '\\WDAGUtilityAccount$' }
if (-not (Test-Guest)) { Write-Output 'refused: not a Windows Sandbox guest'; exit 3 }

# Never use two variable names that differ only in case: PowerShell treats them as one ($T holds the tokens).
$out = 'C:\out'; $lab = 'C:\lab'; $bin = 'C:\labbin'
$done = [ordered]@{ ok = $false; error = $null; exitCodes = [ordered]@{} }
function Step([string]$text) { Add-Content "$out\progress.log" "$(Get-Date -Format o) $text" -Encoding UTF8 }
function Read-Json([string]$file) { Get-Content "$out\$file" -Raw -Encoding UTF8 | ConvertFrom-Json }
# Start-Process -Wait also waits for descendants (a stuck msiexec client), so wait for the process itself only.
function Wait-Exit($proc, [int]$Minutes, [string]$What) {
    $null = $proc.Handle   # keeps the handle so ExitCode is available in PowerShell 5.1
    if (-not $proc.WaitForExit($Minutes * 60000)) { throw "$What did not finish within $Minutes min" }
    return $proc.ExitCode
}
function Lab([string]$file, [string[]]$argv) {
    $proc = Start-Process "$bin\uni-lab.exe" -ArgumentList $argv -NoNewWindow -PassThru `
        -RedirectStandardOutput "$out\$file" -RedirectStandardError "$out\$file.err"
    $code = Wait-Exit $proc 15 "uni-lab $($argv -join ' ')"
    $done.exitCodes[$file] = $code
    Step "uni-lab $($argv -join ' ') -> $code"
    return $code
}

try {
    Set-Content "$out\started.txt" (Get-Date -Format o)
    $sc = Read-Json 'scenario.json'
    $labWritable = $true
    try { Set-Content "$lab\.probe" 'probe' -ErrorAction Stop } catch { $labWritable = $false }
    New-Item $bin -ItemType Directory -Force | Out-Null
    try { Add-MpPreference -ExclusionPath $bin } catch { Step "defender exclusion not set: $_" }   # before the copy: scanning acts on write
    Copy-Item "$lab\build\*" $bin -Recurse -Force   # installers, msiexec and uni-lab run from the local disk
    $env:UNIINSTALLER_LAB = $lab
    . "$lab\guest\inventory.ps1"
    $T = Get-LabTokens
    function X([string]$text) { foreach ($key in $T.Keys) { $text = $text.Replace("{$key}", $T[$key]) }; $text }

    if ((Lab 'check.json' @('check')) -ne 0) { throw "uni-lab check refused: $(Get-Content "$out\check.json" -Raw)" }
    $check = Read-Json 'check.json'
    $uac = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'
    $admin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    [ordered]@{ tokens = $T; check = $check; labWritable = $labWritable; adminRole = $admin; enableLua = $uac.EnableLUA
        consentPromptBehaviorAdmin = $uac.ConsentPromptBehaviorAdmin; os = [Environment]::OSVersion.VersionString } |
        ConvertTo-Json -Depth 10 | Set-Content "$out\env.json" -Encoding UTF8
    if ($labWritable) { throw 'C:\lab is writable: the read-only mapping is not in effect' }
    if (-not $check.release) { throw 'uni-lab is a debug build' }
    if (-not $check.elevated) { throw 'the guest token is not elevated: per-machine installers would wait on a UAC prompt' }

    Save-Inventory $out 's0' $T; Step 's0'
    $n = 0
    foreach ($inst in $sc.install) {
        $n++
        $log = "$bin\install-$n.log"   # the Windows Installer service writes it; keep it off the mapped folder
        if ($inst -like '*.msi') { $proc = Start-Process msiexec.exe -ArgumentList '/i', "$bin\$inst", '/qn', '/l*v', $log -PassThru }
        else { $proc = Start-Process "$bin\$inst" -PassThru }
        $code = Wait-Exit $proc 10 "install $inst"
        if (Test-Path $log) { Copy-Item $log $out }
        Step "install $inst -> $code"
        if ($code -ne 0) { throw "install $inst failed with $code" }
    }
    foreach ($act in $sc.after_install) {
        if ($act.file) { $path = X $act.file; New-Item (Split-Path $path) -ItemType Directory -Force | Out-Null; Set-Content -LiteralPath $path 'lab' }
        elseif ($act.delete) { Remove-Item -LiteralPath (X $act.delete) -Force }
        elseif ($act.regval) {
            $m = [regex]::Match($act.regval, '^(hklm|hkcu)(64|32):(.+)\|(.+)$')
            if (-not $m.Success) { throw "bad regval $($act.regval)" }
            $hive = if ($m.Groups[1].Value -eq 'hklm') { 'LocalMachine' } else { 'CurrentUser' }
            $view = if ($m.Groups[2].Value -eq '32') { 'Registry32' } else { 'Registry64' }
            $rk = [Microsoft.Win32.RegistryKey]::OpenBaseKey($hive, $view).CreateSubKey($m.Groups[3].Value)
            $rk.SetValue($m.Groups[4].Value, (X $act.data)); $rk.Close()
        } else { throw "unknown after_install action: $($act | ConvertTo-Json -Compress)" }
        Step "after_install $($act | ConvertTo-Json -Compress)"
    }
    Save-Inventory $out 's1' $T; Step 's1'

    $null = Lab 'apps.json' @('list')
    $app = @((Read-Json 'apps.json') | Where-Object { $_.displayName -eq $sc.target })
    if ($app.Count -ne 1) { throw "expected one program named '$($sc.target)', found $($app.Count)" }
    $code = Lab 'op-begin.json' @('begin', $app[0].id)
    if ($sc.expect_begin_error) {
        Save-Inventory $out 's5' $T; Step 's5'
    } else {
        if ($code -ne 0) { throw 'begin failed' }
        $op = (Read-Json 'op-begin.json').id
        $q = "$env:LOCALAPPDATA\uniinstaller-data\operations\$op\q"
        $clicker = Start-Process powershell.exe -PassThru -WindowStyle Hidden -ArgumentList '-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', "$lab\guest\clicker.ps1", '-Log', "$out\clicks.log"
        try { $code = Lab 'op-native.json' @('native', $op) } finally { Stop-Process -Id $clicker.Id -Force -ErrorAction SilentlyContinue }
        if ($code -ne 0) { throw 'native failed' }
        Save-Inventory $out 's2' $T; Step 's2'
        if ((Lab 'op-scan.json' @('scan', $op)) -ne 0) { throw 'scan failed' }
        Save-Inventory $out 's3' $T; Step 's3'
        $locker = $null
        if ($sc.lock) {
            $lockPath = X $sc.lock; $ready = "$out\lock-ready.txt"
            $cmd = "`$f = [IO.File]::Open('$lockPath', 'Open', 'Read', 'None'); Set-Content '$ready' ok; Start-Sleep 3600"
            $enc = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($cmd))
            $locker = Start-Process powershell.exe -PassThru -WindowStyle Hidden -ArgumentList '-NoProfile', '-EncodedCommand', $enc
            $waited = 0
            while (-not (Test-Path $ready)) { Start-Sleep 1; $waited++; if ($waited -gt 30) { throw 'lock holder did not start' } }
        }
        try {
            if ($sc.crash) {
                $null = Lab 'op-apply-crash.json' @('apply', $op, $sc.select, '--crash-after-first-move')
                @(Get-ChildItem $q -Name -ErrorAction SilentlyContinue) | Set-Content "$out\q-after-crash.txt"
                Save-Inventory $out 's4a' $T; Step 's4a'
                $null = Lab 'op-after-crash.json' @('show', $op)
            }
            if ((Lab 'op-apply.json' @('apply', $op, $sc.select)) -ne 0) { throw 'apply failed' }
        } finally { if ($locker) { Stop-Process -Id $locker.Id -Force -ErrorAction SilentlyContinue } }
        @(Get-ChildItem $q -Name -ErrorAction SilentlyContinue) | Set-Content "$out\q-list.txt"
        Save-Inventory $out 's4' $T; Step 's4'
        if ((Lab 'op-rescan.json' @('scan', $op)) -ne 0) { throw 'rescan failed' }
        Save-Inventory $out 's4r' $T; Step 's4r'
        if ((Lab 'op-restore.json' @('restore', $op)) -ne 0) { throw 'restore failed' }
        Save-Inventory $out 's5' $T; Step 's5'
    }
    $done.ok = $true
} catch {
    $done.error = "$_"
    Step "error: $_"
} finally {
    $done | ConvertTo-Json -Depth 10 | Set-Content "$out\done.json" -Encoding UTF8
    if (Test-Guest) { shutdown.exe /s /t 5 }   # a timeout above 0 implies /f
}
