# Independent inventory for the lab (does not use the product's scanner). Read-only. Keep this file ASCII-only.
# One TSV line per object: <kind>`t<id>`t<fingerprint>. kind: d dir, f file, l link, k key, v value, e error.
# Ids use the product's target_key form in lowercase: path:<full path>, key:<hive><view>:<path>, value:<key>|<name>.
# shortcut: scoped roots, depth-1 names for Classes and Services plus full keys of third-party services (image under {PF}/{PF86}/{PD}, no
# Windows*/Microsoft* folder), tasks outside \Microsoft through the API, size|mtime for files; widen when a scenario needs more.
# A running service, a custom security descriptor and password tasks are not exercised (the payload is not a service binary).
$script:Sha = [Security.Cryptography.SHA256]::Create()
function Get-Hash([string]$s) { -join ($script:Sha.ComputeHash([Text.Encoding]::UTF8.GetBytes($s))[0..7] | ForEach-Object { $_.ToString('x2') }) }

function Get-LabTokens {
    $f = { param($n) [Environment]::GetFolderPath($n) }
    [ordered]@{
        PF = $env:ProgramFiles; PF86 = ${env:ProgramFiles(x86)}; CF = $env:CommonProgramFiles; PD = $env:ProgramData
        APPDATA = $env:APPDATA; LOCALAPPDATA = $env:LOCALAPPDATA
        DESKTOP = & $f 'Desktop'; PUBDESKTOP = & $f 'CommonDesktopDirectory'
        PROGRAMS = & $f 'Programs'; COMMONPROGRAMS = & $f 'CommonPrograms'; DOCS = & $f 'MyDocuments'
        TASKS = "$env:SystemRoot\System32\Tasks"
    }
}

function Add-Files([string]$Root, [string[]]$Skip, $Lines) {
    if (-not (Test-Path -LiteralPath $Root)) { return }
    $stack = New-Object 'System.Collections.Generic.Stack[string]'
    $stack.Push($Root)
    $Lines.Add("d`tpath:$($Root.ToLower())`t")
    while ($stack.Count -gt 0) {
        $dir = $stack.Pop()
        try { $items = (New-Object IO.DirectoryInfo $dir).GetFileSystemInfos() }
        catch { $Lines.Add("e`tpath:$($dir.ToLower())`t$($_.Exception.GetType().Name)"); continue }
        foreach ($i in $items) {
            $p = $i.FullName.ToLower()
            if ($Skip -contains $p) { continue }
            if ($i.Attributes -band [IO.FileAttributes]::ReparsePoint) {
                $target = (Get-Item -LiteralPath $i.FullName -Force).Target -join ';'
                $Lines.Add("l`tpath:$p`t$($target.ToLower())")
            } elseif ($i -is [IO.DirectoryInfo]) {
                $Lines.Add("d`tpath:$p`t"); $stack.Push($i.FullName)
            } else {
                $Lines.Add("f`tpath:$p`t$($i.Length)|$($i.LastWriteTimeUtc.Ticks)")
            }
        }
    }
}

function Add-Reg([string]$Hive, [string]$View, [string]$Path, [string[]]$Skip, [bool]$NamesOnly, $Lines) {
    $h = if ($Hive -eq 'hklm') { [Microsoft.Win32.RegistryHive]::LocalMachine } else { [Microsoft.Win32.RegistryHive]::CurrentUser }
    $v = if ($View -eq '32') { [Microsoft.Win32.RegistryView]::Registry32 } else { [Microsoft.Win32.RegistryView]::Registry64 }
    $base = [Microsoft.Win32.RegistryKey]::OpenBaseKey($h, $v)
    $pre = "$Hive$View"
    $stack = New-Object 'System.Collections.Generic.Stack[string]'
    $stack.Push($Path)
    while ($stack.Count -gt 0) {
        $kp = $stack.Pop(); $id = $kp.ToLower()
        try { $k = $base.OpenSubKey($kp) } catch { $Lines.Add("e`tkey:${pre}:$id`t$($_.Exception.GetType().Name)"); continue }
        if ($null -eq $k) { continue }
        $Lines.Add("k`tkey:${pre}:$id`t")
        if ($NamesOnly) {
            foreach ($s in $k.GetSubKeyNames()) { $Lines.Add("k`tkey:${pre}:$id\$($s.ToLower())`t") }
        } else {
            foreach ($n in $k.GetValueNames()) {
                $data = $k.GetValue($n, $null, [Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames)
                $text = if ($data -is [byte[]]) { [BitConverter]::ToString($data) } elseif ($data -is [string[]]) { $data -join "`n" } else { "$data" }
                $Lines.Add("v`tvalue:${pre}:$id|$($n.ToLower())`t$($k.GetValueKind($n))|$(Get-Hash $text)")
            }
            foreach ($s in $k.GetSubKeyNames()) { $c = "$kp\$s"; if ($Skip -notcontains $c.ToLower()) { $stack.Push($c) } }
        }
        $k.Close()
    }
}

# Full keys (values and subkeys) of third-party services only: the image lies under {PF}, {PF86} or {PD} and in no folder named Windows* or
# Microsoft* (Defender, Media Player, ATP and Edge are Windows'; their keys change with platform updates and would break unrelated scenarios).
function Add-Services($T, $Lines) {
    $roots = @("$($T.PF)\".ToLower(), "$($T.PF86)\".ToLower(), "$($T.PD)\".ToLower())
    $root = [Microsoft.Win32.RegistryKey]::OpenBaseKey('LocalMachine', 'Registry64').OpenSubKey('SYSTEM\CurrentControlSet\Services')
    foreach ($n in $root.GetSubKeyNames()) {
        $k = $null
        try { $k = $root.OpenSubKey($n) } catch { continue }
        if ($null -eq $k) { continue }
        $img = [string]$k.GetValue('ImagePath', '', [Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames)
        $k.Close()
        $x = [Environment]::ExpandEnvironmentVariables($img).Trim().TrimStart('"').ToLower()
        $under = @($roots | Where-Object { $x.StartsWith($_) }).Count -gt 0
        if ($under -and $x -notmatch '\\(windows|microsoft)[^\\]*\\') { Add-Reg 'hklm' '64' "SYSTEM\CurrentControlSet\Services\$n" @() $false $Lines }
    }
}

# Scheduled tasks outside \Microsoft through the Task Scheduler API (not the product's code): every folder (n) and task (t, its XML hashed).
# The task files under System32\Tasks are not listed: re-registering a task rewrites its file, the API view is the state.
function Add-Tasks($Lines) {
    $svc = New-Object -ComObject Schedule.Service
    $svc.Connect()
    $stack = New-Object 'System.Collections.Generic.Stack[object]'
    $stack.Push($svc.GetFolder('\'))
    while ($stack.Count -gt 0) {
        $f = $stack.Pop()
        if ($f.Path -ne '\') { $Lines.Add("n`ttask:$($f.Path.ToLower())`t") }
        try { foreach ($t in $f.GetTasks(1)) { $Lines.Add("t`ttask:$($t.Path.ToLower())`t$(Get-Hash $t.Xml)") } }
        catch { $Lines.Add("e`ttask:$($f.Path.ToLower())`t$($_.Exception.GetType().Name)") }
        foreach ($sub in $f.GetFolders(0)) { if ($sub.Path -ne '\Microsoft') { $stack.Push($sub) } }
    }
}

function Save-Inventory([string]$Dir, [string]$Name, $T) {
    $L = New-Object 'System.Collections.Generic.List[string]'
    $lp = $T.LOCALAPPDATA.ToLower(); $ap = $T.APPDATA.ToLower(); $pd = $T.PD.ToLower()
    Add-Files $T.PF @("$($T.PF.ToLower())\windowsapps") $L
    Add-Files $T.PF86 @() $L
    Add-Files $T.PD @("$pd\microsoft", "$pd\package cache") $L
    Add-Files $T.APPDATA @("$ap\microsoft") $L
    Add-Files $T.LOCALAPPDATA @("$lp\microsoft", "$lp\packages", "$lp\temp", "$lp\uniinstaller-data", "$lp\d3dscache", "$lp\connecteddevicesplatform") $L
    Add-Files "$env:USERPROFILE\AppData\LocalLow" @() $L
    foreach ($r in 'PROGRAMS', 'COMMONPROGRAMS', 'DESKTOP', 'PUBDESKTOP', 'DOCS') { Add-Files $T[$r] @() $L }
    Add-Files 'C:\LabOutside' @() $L
    Add-Tasks $L
    $cv = 'SOFTWARE\Microsoft\Windows\CurrentVersion'
    foreach ($hv in 'hklm64', 'hklm32', 'hkcu64') {
        $h = $hv.Substring(0, 4); $v = $hv.Substring(4)
        Add-Reg $h $v 'SOFTWARE' @('software\microsoft', 'software\classes', 'software\wow6432node') $false $L
        foreach ($s in 'Uninstall', 'App Paths', 'Run', 'RunOnce') { Add-Reg $h $v "$cv\$s" @() $false $L }
    }
    Add-Reg 'hklm' '64' "$cv\SharedDLLs" @() $false $L
    Add-Reg 'hklm' '64' 'SOFTWARE\Classes' @() $true $L
    Add-Reg 'hkcu' '64' 'Software\Classes' @() $true $L
    Add-Reg 'hklm' '64' 'SYSTEM\CurrentControlSet\Services' @() $true $L
    Add-Services $T $L
    $L.Sort([StringComparer]::Ordinal)
    [IO.File]::WriteAllLines((Join-Path $Dir "$Name.tsv"), $L)
}
