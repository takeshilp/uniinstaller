# Host: builds everything the guest needs into target\lab\build. It never runs any of it. Keep this file ASCII-only.
$ErrorActionPreference = 'Stop'
$root = Split-Path $PSScriptRoot -Parent
$build = Join-Path $root 'target\lab\build'
if ($build -notmatch '\\target\\lab\\build$') { throw "unexpected build dir $build" }
$tools = Join-Path $root 'target\lab\tools'
function Invoke-Native([string]$Exe, [string[]]$ArgList) {
    $ErrorActionPreference = 'Continue'  # PowerShell 5.1 turns native stderr into errors under Stop
    & $Exe @ArgList
    if ($LASTEXITCODE -ne 0) { throw "$Exe failed with exit code $LASTEXITCODE" }
}
Remove-Item $build -Recurse -Force -ErrorAction SilentlyContinue   # build output only; never mapped into a guest
New-Item "$build\payload" -ItemType Directory -Force | Out-Null
$payload = "$build\payload\labapp.exe"
Copy-Item "$env:SystemRoot\System32\whoami.exe" $payload
Set-Content "$build\payload\readme.txt" 'Uniinstaller lab test program. Inert.' -Encoding ascii

$makensis = @("$env:LOCALAPPDATA\tauri\NSIS\makensis.exe", (Get-Command makensis -ErrorAction SilentlyContinue).Source) |
    Where-Object { $_ -and (Test-Path $_) } | Select-Object -First 1
if (-not $makensis) { throw 'NSIS not found: run "npm run tauri build" once (Tauri downloads NSIS) or put makensis on PATH' }
$nsis = @(
    @{ Out = 'labnotes.exe';   D = @('NAME=Lab Notes', 'KEY=LabNotes', 'EXE=labnotes.exe', 'USER', 'DOCS', 'JUNCTION') },
    @{ Out = 'labmany.exe';    D = @('NAME=Lab Many', 'KEY=LabMany', 'EXE=labmany.exe', 'USER', 'LINKS') },
    @{ Out = 'labbroken.exe';  D = @('NAME=Lab Broken', 'KEY=LabBroken', 'EXE=labbroken.exe', 'USER') },
    @{ Out = 'labsvc.exe';     D = @('NAME=Lab Service Tool', 'KEY=LabServiceTool', 'EXE=labsvc.exe', 'SERVICE') },
    @{ Out = 'labsuite.exe';   D = @('NAME=Lab Suite', 'KEY=LabSuite', 'EXE=labsuite.exe', 'SHARED_DLL') },
    @{ Out = 'labplugin.exe';  D = @('NAME=Lab Suite Plugin', 'KEY=LabSuitePlugin', 'EXE=labplugin.exe', 'SHARED_DLL',
                                     'DIR=$PROGRAMFILES64\Lab Vendor\Lab Suite\Plugin', 'REGKEY=SOFTWARE\Lab Vendor\Lab Suite\Plugin') },
    @{ Out = 'labeditor1.exe'; D = @('NAME=Lab Editor 1', 'KEY=LabEditor1', 'EXE=labeditor1.exe', 'EDITOR', 'VERSION=1.0') },
    @{ Out = 'labeditor2.exe'; D = @('NAME=Lab Editor 2', 'KEY=LabEditor2', 'EXE=labeditor2.exe', 'EDITOR', 'VERSION=2.0') }
)
foreach ($app in $nsis) {
    $defs = @($app.D | ForEach-Object { "/D$_" }) + @("/DOUT=$build\$($app.Out)", "/DPAYLOAD=$payload", '/V2', "$PSScriptRoot\apps\app.nsi")
    Invoke-Native $makensis $defs
}

$wix = "$tools\wix\wix.exe"
if (-not (Test-Path $wix)) { Invoke-Native 'dotnet' @('tool', 'install', 'wix', '--version', '5.0.2', '--tool-path', "$tools\wix") }
$msis = @(
    @{ Out = 'labmsi-x64.msi'; Arch = 'x64'; D = @('Name=Lab Msi', 'Exe=labmsi.exe', 'RunName=LabMsi', 'SetLoc=1',
        'ProductCode={6C1A0B52-3D4E-4F60-9A71-0B2C3D4E5F01}', 'UpgradeCode={6C1A0B52-3D4E-4F60-9A71-0B2C3D4E5F11}') },
    @{ Out = 'labmsi-x86.msi'; Arch = 'x86'; D = @('Name=Lab Msi Bare', 'Exe=labmsibare.exe', 'RunName=LabMsiBare', 'SetLoc=0',
        'ProductCode={6C1A0B52-3D4E-4F60-9A71-0B2C3D4E5F02}', 'UpgradeCode={6C1A0B52-3D4E-4F60-9A71-0B2C3D4E5F12}') }
)
foreach ($msi in $msis) {
    $defs = @('build', '-arch', $msi.Arch)
    foreach ($def in $msi.D + "PayloadDir=$build\payload") { $defs += '-d'; $defs += $def }
    Invoke-Native $wix ($defs + @("$PSScriptRoot\apps\labmsi.wxs", '-o', "$build\$($msi.Out)"))
}

# Static CRT: a clean guest may lack vcruntime140.dll. --target keeps RUSTFLAGS away from build scripts and proc macros.
$env:PATH = "$env:USERPROFILE\.cargo\bin;$env:PATH"
$env:RUSTFLAGS = '-C target-feature=+crt-static'
$env:CARGO_TARGET_DIR = "$root\target\lab\cargo"
Invoke-Native 'cargo' @('build', '--release', '-p', 'uni-lab', '--target', 'x86_64-pc-windows-msvc', '--manifest-path', "$root\Cargo.toml")
Copy-Item "$root\target\lab\cargo\x86_64-pc-windows-msvc\release\uni-lab.exe" $build

$commit = git -C $root rev-parse HEAD
$dirty = [bool](git -C $root status --porcelain)
$lines = @("commit $commit", "dirty $dirty") + @(Get-ChildItem $build -Recurse -File | ForEach-Object { "$((Get-FileHash $_.FullName).Hash) $($_.FullName.Substring($build.Length + 1))" })
Set-Content "$build\build.txt" $lines -Encoding ascii
Write-Host "built into $build"
