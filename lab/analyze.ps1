# Host, read-only over guest output: manifest comparison, metrics and verdicts. Writes only under <RunDir>\_results.
# It parses JSON and TSV and never executes, deletes or follows anything from the guest folders. Keep this file ASCII-only.
# shortcut: no unit tests; the rules are checked against the expected first-run verdicts, add a synthetic-run self-test if they change often.
param([Parameter(Mandatory)][string]$RunDir)
$ErrorActionPreference = 'Stop'
$RunDir = (Resolve-Path -LiteralPath $RunDir).Path
$results = Join-Path $RunDir '_results'
$rank = @{ PASS = 0; RISK = 1; FAIL = 2; ERROR = 3 }
$unexpandedCv = 'software\microsoft\windows\currentversion'   # scenarios spell it out; kept only for readable messages

function Test-ReparsePoint([string]$Path) {
    $attr = (Get-Item -LiteralPath $Path -Force).Attributes
    return [bool]($attr -band [IO.FileAttributes]::ReparsePoint)
}
function Read-Json([string]$Path) { Get-Content -LiteralPath $Path -Raw -Encoding UTF8 | ConvertFrom-Json }
function Norm-Id([string]$id) { ($id.ToLower() -replace '^(key|value):hkcu32:', '$1:hkcu64:') }
function New-Map { New-Object 'System.Collections.Generic.Dictionary[string,string]' ([StringComparer]::Ordinal) }

function Load-Tsv([string]$Path, $Errors) {
    $map = New-Map
    if (-not (Test-Path -LiteralPath $Path)) { return $null }
    foreach ($line in [IO.File]::ReadAllLines($Path)) {
        $parts = $line.Split("`t")
        if ($parts.Count -lt 2) { continue }
        if ($parts[0] -eq 'e') { [void]$Errors.Add("$($parts[1]) $($parts[2])"); continue }
        $map[$parts[1]] = $parts[0] + "`t" + $(if ($parts.Count -gt 2) { $parts[2] } else { '' })
    }
    return $map
}

# Containment as defined by the lab: equal; path:X contains path:X\..; key:K contains key:K\.., value:K|* and value:K\..|*.
function Test-Contains([string]$Outer, [string]$Inner) {
    if ($Outer -ceq $Inner) { return $true }
    if ($Outer.StartsWith('path:', 'Ordinal')) { return $Inner.StartsWith($Outer + '\', 'Ordinal') }
    if ($Outer.StartsWith('key:', 'Ordinal')) {
        $k = $Outer.Substring(4)
        return $Inner.StartsWith("key:$k\", 'Ordinal') -or $Inner.StartsWith("value:$k|", 'Ordinal') -or $Inner.StartsWith("value:$k\", 'Ordinal')
    }
    return $false
}

function Compare-Maps($A, $B) {
    $added = New-Object System.Collections.Generic.List[string]
    $removed = New-Object System.Collections.Generic.List[string]
    $changed = New-Object System.Collections.Generic.List[string]
    foreach ($key in $A.Keys) {
        if (-not $B.ContainsKey($key)) { $removed.Add($key) } elseif ($A[$key] -cne $B[$key]) { $changed.Add($key) }
    }
    foreach ($key in $B.Keys) { if (-not $A.ContainsKey($key)) { $added.Add($key) } }
    $diffs = @()
    $diffs += @($added | Select-Object -First 50 | ForEach-Object { "added $_" })
    $diffs += @($removed | Select-Object -First 50 | ForEach-Object { "removed $_" })
    $diffs += @($changed | Select-Object -First 50 | ForEach-Object { "changed $_" })
    return [pscustomobject]@{ Equal = (($added.Count + $removed.Count + $changed.Count) -eq 0); Count = $added.Count + $removed.Count + $changed.Count; Diffs = @($diffs | Select-Object -First 50) }
}

function Get-Sel($Plan, [string]$Policy) {
    @($Plan.candidates | Where-Object {
        if ($Policy -eq 'default') { $_.selected }
        else { (@($_.blocks).Count -eq 0) -and -not (@($_.evidence | Where-Object { $_.code -eq 'userDataLikely' }).Count) }
    } | ForEach-Object { Norm-Id $_.id })
}

function Analyze-Scenario([string]$Dir, [string]$Name) {
    $reasons = New-Object System.Collections.Generic.List[object]
    function Add-Reason([string]$Level, [string]$Text) { $reasons.Add([pscustomobject]@{ level = $Level; text = $Text }) }
    $res = [ordered]@{ scenario = $Name; verdict = 'PASS'; reasons = @(); policy = $null; elevated = $null; labWritable = $null
        native = $null; installDirStatus = $null; selected = $null; leftovers = $null; found = $null; missed = $null; recall = $null
        offered = $null; precision = $null; precisionPreselected = $null; dangerousOffers = $null; removed = $null; falseDeletions = $null
        risks = $null; controlIntact = $null; scanReadOnly = $null; applyConsistent = $null; restoreOk = $null
        resume = $null; gaps = @(); itemProblems = @(); missedObjects = @(); unclassifiedInstalled = @(); inventoryErrors = @() }
    $finish = {
        $worst = 'PASS'
        foreach ($r in $reasons) { if ($rank[$r.level] -gt $rank[$worst]) { $worst = $r.level } }
        $res.verdict = $worst
        $res.reasons = @($reasons | ForEach-Object { "$($_.level): $($_.text)" })
        return $res
    }

    # Input safety: nothing is read from a folder that holds a reparse point (the guest can create them).
    if (Test-ReparsePoint $Dir) { Add-Reason 'ERROR' "input is a reparse point: $Dir"; return (& $finish) }
    $bad = @(Get-ChildItem -LiteralPath $Dir -Force | Where-Object { $_.Attributes -band [IO.FileAttributes]::ReparsePoint })
    if ($bad.Count) { Add-Reason 'ERROR' "input is a reparse point: $($bad[0].FullName)"; return (& $finish) }
    $f = { param($n) Join-Path $Dir $n }

    $sc = Read-Json (& $f 'scenario.json')
    $res.policy = $sc.select
    $drv = if (Test-Path (& $f 'driver.json')) { Read-Json (& $f 'driver.json') } else { $null }
    $dn = if (Test-Path (& $f 'done.json')) { Read-Json (& $f 'done.json') } else { $null }
    $envj = if (Test-Path (& $f 'env.json')) { Read-Json (& $f 'env.json') } else { $null }
    $chk = if (Test-Path (& $f 'check.json')) { Read-Json (& $f 'check.json') } else { $null }
    if ($envj) { $res.labWritable = $envj.labWritable }
    if ($chk) { $res.elevated = $chk.elevated }

    # Rule 1: ERROR conditions.
    if (-not $drv -or $drv.status -ne 'done') { Add-Reason 'ERROR' "driver status is '$(if ($drv) { $drv.status } else { 'missing' })'" }
    if (-not $dn) { Add-Reason 'ERROR' 'done.json is missing' } elseif (-not $dn.ok) { Add-Reason 'ERROR' "guest error: $($dn.error)" }
    if ($envj -and $envj.labWritable) { Add-Reason 'ERROR' 'C:\lab was writable in the guest: the read-only mapping is not in effect' }
    if ($chk -and (-not $chk.guest)) { Add-Reason 'ERROR' 'uni-lab check says guest:false' }
    if ($chk -and (-not $chk.elevated)) { Add-Reason 'ERROR' 'the guest token is not elevated' }
    if (($reasons | Where-Object { $_.level -eq 'ERROR' }).Count -and (-not $dn -or -not $dn.ok)) { return (& $finish) }

    $codes = $dn.exitCodes
    $broken = [bool]$sc.expect_begin_error
    $expect = [ordered]@{ 'op-begin.json' = $(if ($broken) { 1 } else { 0 }) }
    if (-not $broken) {
        $expect['op-native.json'] = 0; $expect['op-scan.json'] = 0; $expect['op-apply.json'] = 0; $expect['op-rescan.json'] = 0; $expect['op-restore.json'] = 0
        if ($sc.crash) { $expect['op-apply-crash.json'] = 99; $expect['op-after-crash.json'] = 0 }
    }
    if ($codes.'op-begin.json' -eq 2) { Add-Reason 'ERROR' 'op-begin exited 2: the guard refused in the guest' }
    foreach ($key in $expect.Keys) {
        $got = $codes.$key
        if ($null -eq $got) { Add-Reason 'ERROR' "no exit code recorded for $key" }
        elseif ($got -ne $expect[$key] -and -not ($key -eq 'op-begin.json' -and $got -eq 2)) { Add-Reason 'ERROR' "unexpected exit code for ${key}: $got (expected $($expect[$key]))" }
    }

    # Snapshots.
    $invErr = New-Object System.Collections.Generic.List[string]
    $snap = @{}
    foreach ($n in 's0', 's1', 's2', 's3', 's4a', 's4', 's4r', 's5') { $snap[$n] = Load-Tsv (& $f "$n.tsv") $invErr }
    $res.inventoryErrors = @($invErr | Select-Object -Unique | Select-Object -First 50)
    $need = if ($broken) { @('s0', 's1', 's5') } else { @('s0', 's1', 's2', 's3', 's4', 's4r', 's5') }
    foreach ($n in $need) { if ($null -eq $snap[$n]) { Add-Reason 'ERROR' "snapshot $n is missing" } }
    if (($reasons | Where-Object { $_.level -eq 'ERROR' }).Count) { return (& $finish) }

    # Manifest patterns, expanded with the guest's own tokens.
    $tok = @{}
    foreach ($p in $envj.tokens.PSObject.Properties) { $tok[$p.Name] = [string]$p.Value }
    $pats = New-Object System.Collections.Generic.List[object]
    foreach ($cls in 'owned', 'userdoc', 'control', 'gap') {
        foreach ($raw in @($sc.$cls)) {
            $t = [string]$raw
            foreach ($k in $tok.Keys) { $t = $t.Replace("{$k}", $tok[$k]) }
            $t = $t.ToLower().TrimEnd('\')
            if (-not ($t.StartsWith('key:') -or $t.StartsWith('value:'))) { $t = "path:$t" }
            $isKey = $t.StartsWith('key:'); $isPath = $t.StartsWith('path:')
            $k2 = if ($isKey) { $t.Substring(4) } else { '' }
            $pats.Add([pscustomobject]@{ Class = $cls; Text = $t; Path = $isPath; Key = $isKey; C1 = $(if ($isPath) { "$t\" } else { "key:$k2\" })
                C2 = "value:$k2|"; C3 = "value:$k2\" })
        }
    }
    $pats = @($pats | Sort-Object { $_.Text.Length } -Descending)
    $clsCache = @{}
    $classOf = {
        param([string]$id)
        if ($clsCache.ContainsKey($id)) { return $clsCache[$id] }
        $r = 'unclassified'
        foreach ($p in $pats) {
            if ($id -ceq $p.Text) { $r = $p.Class; break }
            if ($p.Path) { if ($id.StartsWith($p.C1, 'Ordinal')) { $r = $p.Class; break } }
            elseif ($p.Key) { if ($id.StartsWith($p.C1, 'Ordinal') -or $id.StartsWith($p.C2, 'Ordinal') -or $id.StartsWith($p.C3, 'Ordinal')) { $r = $p.Class; break } }
        }
        $clsCache[$id] = $r
        return $r
    }.GetNewClosure()   # the report code calls it after this function has returned

    # Broken scenario: begin must fail and nothing may change.
    if ($broken) {
        $cmp = Compare-Maps $snap['s1'] $snap['s5']
        if (-not $cmp.Equal) { Add-Reason 'FAIL' "a failed begin changed the system ($($cmp.Count) differences): $($cmp.Diffs -join '; ')" }
        return (& $finish)
    }

    # Rule 1 last bullet: a control or user-document object must survive the native uninstaller, otherwise the test app is wrong.
    $s1 = $snap['s1']; $s2 = $snap['s2']; $s3 = $snap['s3']; $s4 = $snap['s4']; $s5 = $snap['s5']
    $ctl = New-Object System.Collections.Generic.List[string]
    foreach ($id in $s2.Keys) { $c = & $classOf $id; if ($c -eq 'control' -or $c -eq 'userdoc') { $ctl.Add($id) } }
    $ctl1 = @($s1.Keys | Where-Object { $c = & $classOf $_; $c -eq 'control' -or $c -eq 'userdoc' })
    $lostByNative = @($ctl1 | Where-Object { -not $s2.ContainsKey($_) })
    if ($lostByNative.Count) { Add-Reason 'ERROR' "control/userdoc object missing after the native uninstaller (test-app bug): $($lostByNative[0]) (+$($lostByNative.Count - 1))" }

    $op = Read-Json (& $f 'op-begin.json')
    $nat = Read-Json (& $f 'op-native.json')
    $scan = Read-Json (& $f 'op-scan.json')
    $app = Read-Json (& $f 'op-apply.json')
    $rst = Read-Json (& $f 'op-restore.json')
    $plan = $scan.plan
    $natRun = $nat.native
    $res.native = [ordered]@{ exitCode = $natRun.exitCode; entryAfter = $nat.entryAfter; timedOut = $natRun.timedOut; processes = @($natRun.processes | ForEach-Object { $_.image }) }
    if ($natRun.timedOut) { Add-Reason 'ERROR' 'native uninstaller timed out (msiexec dialog not answered? see clicks.log)' }
    $res.installDirStatus = $plan.installDirStatus.type

    $cands = @($plan.candidates | ForEach-Object { $_ | Add-Member -NotePropertyName nid -NotePropertyValue (Norm-Id $_.id) -PassThru -Force })
    $items = @($app.items | ForEach-Object { $_ | Add-Member -NotePropertyName nid -NotePropertyValue (Norm-Id $_.candidateId) -PassThru -Force })
    $sel = @(Get-Sel $plan $sc.select)
    $L = @($s2.Keys | Where-Object { $k = $s2[$_].Split("`t")[0]; ($k -eq 'f' -or $k -eq 'l' -or $k -eq 'v') -and ((& $classOf $_) -eq 'owned') })
    $R = @($items | Where-Object { $_.status -eq 'removed' })
    $res.selected = $sel.Count; $res.leftovers = $L.Count; $res.removed = $R.Count

    # Rule 3: a scenario that measures nothing is an ERROR.
    if ($sel.Count -eq 0) { Add-Reason 'ERROR' 'scenario measures nothing: the selection is empty' }
    if ($L.Count -eq 0) { Add-Reason 'ERROR' 'scenario measures nothing: no owned leftovers after the native uninstaller' }
    if ($R.Count -eq 0) { Add-Reason 'ERROR' 'scenario measures nothing: apply removed no item' }

    # Rule 4: recall.
    $offered = @($cands | Where-Object { @($_.blocks).Count -eq 0 })
    $res.offered = $offered.Count
    $foundList = @($L | Where-Object { $m = $_; [bool]($offered | Where-Object { Test-Contains $_.nid $m } | Select-Object -First 1) })
    $missedList = @($L | Where-Object { $foundList -cnotcontains $_ })
    $res.found = $foundList.Count; $res.missed = $missedList.Count
    $res.recall = if ($L.Count -gt 0) { [math]::Round($foundList.Count / $L.Count, 3) } else { $null }
    $res.missedObjects = @($missedList | Select-Object -First 50)

    # Rule 5: precision (metrics only) and dangerous offers.
    $pool = @($offered | Where-Object { -not (@($_.evidence | Where-Object { $_.code -eq 'userDataLikely' }).Count) })
    $isGood = { param($c) $x = & $classOf $c.nid; $x -eq 'owned' -or $x -eq 'gap' }
    $good = @($pool | Where-Object { & $isGood $_ })
    $res.precision = if ($pool.Count) { [math]::Round($good.Count / $pool.Count, 3) } else { $null }
    $pre = @($cands | Where-Object { $_.selected })
    $res.precisionPreselected = if ($pre.Count) { [math]::Round((@($pre | Where-Object { & $isGood $_ })).Count / $pre.Count, 3) } else { $null }
    $res.dangerousOffers = @($pool | Where-Object { $c = $_; [bool]($ctl | Where-Object { Test-Contains $c.nid $_ } | Select-Object -First 1) } | ForEach-Object { $_.nid })

    # Rule 6: every selected candidate must have an item.
    $itemIds = @{}
    foreach ($i in $items) { $itemIds[$i.nid] = $i }
    foreach ($id in $sel) { if (-not $itemIds.ContainsKey($id)) { Add-Reason 'FAIL' "selected candidate not applied: $id" } }

    # Rule 7: item statuses.
    $lockId = $null
    if ($sc.lock) { $lt = [string]$sc.lock; foreach ($k in $tok.Keys) { $lt = $lt.Replace("{$k}", $tok[$k]) }; $lockId = 'path:' + $lt.ToLower().TrimEnd('\') }
    $gaps = New-Object System.Collections.Generic.List[string]
    $problems = New-Object System.Collections.Generic.List[string]
    foreach ($i in $items) {
        if ($i.status -eq 'removed') { continue }
        switch ($i.status) {
            'notFound' {
                $still = $s4.Keys | Where-Object { Test-Contains $i.nid $_ } | Select-Object -First 1
                if ($still) { Add-Reason 'FAIL' "reported notFound but present: $still"; $problems.Add("$($i.nid) notFound but present") }
            }
            { $_ -eq 'locked' -or $_ -eq 'accessDenied' } {
                # The locked file is inside the item's target (the product moves the folder that holds it, or the file itself).
                if ($lockId -and (Test-Contains $i.nid $lockId)) { $gaps.Add('locked file (no Restart Manager)'); $problems.Add("$($i.nid) $($i.status): $($i.detail)") }
                else { Add-Reason 'RISK' "$($i.nid) ended $($i.status): $($i.detail)"; $problems.Add("$($i.nid) $($i.status): $($i.detail)") }
            }
            { $_ -eq 'changed' -or $_ -eq 'inProgress' } { Add-Reason 'FAIL' "$($i.nid) ended $($i.status)"; $problems.Add("$($i.nid) $($i.status)") }
            default { Add-Reason 'RISK' "$($i.nid) ended $($i.status): $($i.detail)"; $problems.Add("$($i.nid) $($i.status): $($i.detail)") }
        }
    }
    $res.itemProblems = @($problems)

    # Rule 8: consistency and losses.
    $A = @($s3.Keys | Where-Object { -not $s4.ContainsKey($_) })
    $emptied = @($app.emptyDirsRemoved | ForEach-Object { 'path:' + (([string]$_) -replace '^\\\\\?\\', '').ToLower().TrimEnd('\') })
    $reported = @($s3.Keys | Where-Object { $id = $_; ($emptied -ccontains $id) -or [bool]($R | Where-Object { Test-Contains $_.nid $id } | Select-Object -First 1) })
    $aSet = @{}; foreach ($x in $A) { $aSet[$x] = 1 }
    $rSet = @{}; foreach ($x in $reported) { $rSet[$x] = 1 }
    $vanishedUnreported = @($A | Where-Object { -not $rSet.ContainsKey($_) })
    $reportedNotGone = @($reported | Where-Object { -not $aSet.ContainsKey($_) })
    $changed34 = @($s3.Keys | Where-Object { $s4.ContainsKey($_) -and $s3[$_] -cne $s4[$_] })
    $res.applyConsistent = (-not $vanishedUnreported.Count) -and (-not $reportedNotGone.Count) -and (-not $changed34.Count)
    if (-not $res.applyConsistent) {
        Add-Reason 'FAIL' "apply report does not match reality: vanished unreported $($vanishedUnreported.Count) [$(($vanishedUnreported | Select-Object -First 5) -join '; ')], reported but not gone $($reportedNotGone.Count) [$(($reportedNotGone | Select-Object -First 5) -join '; ')], changed $($changed34.Count) [$(($changed34 | Select-Object -First 5) -join '; ')]"
    }
    $falseCount = 0; $risk = 0
    foreach ($id in $A) {
        $c = & $classOf $id
        $containers = @($R | Where-Object { Test-Contains $_.nid $id })
        if ($c -eq 'control' -or $c -eq 'userdoc') {
            $falseCount++
            if (-not $containers.Count) { Add-Reason 'FAIL' "collateral damage: $c object vanished with no item covering it: $id" }
            elseif (@($containers | Where-Object { $cc = $_.nid; [bool]($cands | Where-Object { $_.nid -ceq $cc -and $_.selected }) }).Count) { Add-Reason 'FAIL' "$c object removed by a preselected item: $id" }
            else { $risk++; Add-Reason 'RISK' "$c object removed, offered without a block and ticked by policy $($sc.select): $id (via $($containers[0].nid))" }
        } elseif ($c -eq 'unclassified' -and $containers.Count) {
            $falseCount++; Add-Reason 'FAIL' "unclassified object removed: $id (via $($containers[0].nid))"
        }
    }
    $res.falseDeletions = $falseCount; $res.risks = $risk

    # Rule 9: control objects present after apply must be unchanged.
    $ctlChanged = @($ctl | Where-Object { $s4.ContainsKey($_) -and $s2[$_] -cne $s4[$_] })
    $res.controlIntact = ($ctlChanged.Count -eq 0)
    if ($ctlChanged.Count) { Add-Reason 'FAIL' "control object changed: $($ctlChanged[0]) (+$($ctlChanged.Count - 1))" }

    # Rule 10: scans are read-only.
    $c23 = Compare-Maps $s2 $s3
    $c44 = Compare-Maps $s4 $snap['s4r']
    $res.scanReadOnly = $c23.Equal -and $c44.Equal
    if (-not $c23.Equal) { Add-Reason 'FAIL' "the scan changed the system ($($c23.Count) differences): $(($c23.Diffs | Select-Object -First 5) -join '; ')" }
    if (-not $c44.Equal) { Add-Reason 'FAIL' "the rescan changed the system ($($c44.Count) differences): $(($c44.Diffs | Select-Object -First 5) -join '; ')" }

    # Rule 11: restore is exact.
    $c35 = Compare-Maps $s3 $s5
    $res.restoreOk = $c35.Equal -and ($rst.status -eq 'restored')
    if (-not $c35.Equal) { Add-Reason 'FAIL' "restore is not exact ($($c35.Count) differences): $(($c35.Diffs | Select-Object -First 8) -join '; ')" }
    if ($rst.status -ne 'restored') { Add-Reason 'FAIL' "restore status is '$($rst.status)': $($rst.statusDetail)" }

    # Rule 12: crash and resume.
    if ($sc.crash) {
        $after = $null
        try { $after = Read-Json (& $f 'op-after-crash.json') } catch { }
        if (-not $after -or -not $after.id) { Add-Reason 'FAIL' 'manifest unreadable after the kill' }
        else {
            $finalBefore = @($after.items | Where-Object { $_.status -eq 'removed' }).Count
            $inProg = @($after.items | Where-Object { $_.status -eq 'inProgress' })
            $qAfter = if (Test-Path (& $f 'q-after-crash.txt')) { @([IO.File]::ReadAllLines((& $f 'q-after-crash.txt')) | Where-Object { $_ }) } else { @() }
            $kill = if (-not $inProg.Count) { 'between items' }
                elseif ($inProg | Where-Object { $_.quarantine -and ($qAfter -contains (Split-Path ([string]$_.quarantine) -Leaf)) }) { 'after the move, before the journal update' }
                else { 'after the journal save, before the move' }
            if ($finalBefore -ge $sel.Count) { Add-Reason 'ERROR' 'kill came after the last item' }
            $qList = if (Test-Path (& $f 'q-list.txt')) { @([IO.File]::ReadAllLines((& $f 'q-list.txt')) | Where-Object { $_ }) } else { @() }
            $pathItems = @($R | Where-Object { $_.target.type -eq 'path' })
            $resumeProblems = @()
            if (@($items | Where-Object { $_.status -eq 'inProgress' }).Count) { $resumeProblems += 'an item is still inProgress' }
            if (@($items | Where-Object { $_.status -ne 'removed' -and $_.status -ne 'notFound' }).Count) { $resumeProblems += 'an item ended neither removed nor notFound' }
            if ($qList.Count -ne $pathItems.Count) { $resumeProblems += "quarantine holds $($qList.Count) payloads for $($pathItems.Count) removed path items" }
            if (-not $res.applyConsistent) { $resumeProblems += 'apply is not consistent with reality' }
            if (-not $res.restoreOk) { $resumeProblems += 'restore is not exact' }
            $res.resume = [ordered]@{ finalBefore = $finalBefore; killWindow = $kill; resumeOk = ($resumeProblems.Count -eq 0) }
            if ($resumeProblems.Count) { Add-Reason 'FAIL' "resume is not correct: $($resumeProblems -join '; ')" }
        }
    }

    # Rule 13: known gaps (never part of the verdict).
    foreach ($id in $s5.Keys) { if ((& $classOf $id) -eq 'gap') { $gaps.Add("left behind: $id") } }
    if ($res.installDirStatus -eq 'notSet' -and $op.app.windowsInstaller) { $gaps.Add('MSI with empty InstallLocation') }
    $gaps.Add("elevated admin, UAC EnableLUA=$($envj.enableLua), ConsentPromptBehaviorAdmin=$($envj.consentPromptBehaviorAdmin)")
    $res.gaps = @($gaps | Select-Object -Unique)

    # Rule 14: info only.
    $res.unclassifiedInstalled = @($s1.Keys | Where-Object { -not $snap['s0'].ContainsKey($_) -and ((& $classOf $_) -eq 'unclassified') } | Sort-Object | Select-Object -First 50)

    $res['_cands'] = $cands; $res['_items'] = $items; $res['_cls'] = $classOf
    return (& $finish)
}

if (Test-Path -LiteralPath $results) {
    if (Test-ReparsePoint $results) { throw "_results is a reparse point: $results" }
} else { New-Item -ItemType Directory -Path $results | Out-Null }

$all = @()
foreach ($d in Get-ChildItem -LiteralPath $RunDir -Directory -Force) {
    if ($d.Name -eq '_in' -or $d.Name -eq '_results') { continue }
    if (-not (Test-Path -LiteralPath (Join-Path $d.FullName 'scenario.json'))) { continue }
    $r = $null
    try { $r = Analyze-Scenario $d.FullName $d.Name }
    catch { $r = [ordered]@{ scenario = $d.Name; verdict = 'ERROR'; reasons = @("ERROR: analyzer failed: $($_.Exception.Message) at $($_.InvocationInfo.PositionMessage)") } }
    $cands = $r['_cands']; $items = $r['_items']; $classOf = $r['_cls']
    foreach ($tmp in '_cands', '_items', '_cls') { if ($r.Contains($tmp)) { $r.Remove($tmp) } }
    $r | ConvertTo-Json -Depth 10 | Set-Content -LiteralPath (Join-Path $results "$($d.Name).json") -Encoding UTF8

    $md = New-Object System.Collections.Generic.List[string]
    $md.Add("# $($d.Name): $($r.verdict)"); $md.Add('')
    foreach ($x in @($r.reasons)) { $md.Add("- $x") }
    if ($cands) {
        $md.Add(''); $md.Add('## Candidates'); $md.Add(''); $md.Add('| id | group | tier | score | blocks | selected | class |'); $md.Add('|---|---|---|---|---|---|---|')
        foreach ($c in $cands) { $md.Add("| ``$($c.nid)`` | $($c.group) | $($c.tier) | $($c.score) | $((@($c.blocks) | ForEach-Object { $_.code }) -join ',') | $($c.selected) | $(& $classOf $c.nid) |") }
    }
    if ($items) {
        $md.Add(''); $md.Add('## Applied items'); $md.Add(''); $md.Add('| id | status | detail | class |'); $md.Add('|---|---|---|---|')
        foreach ($i in $items) { $md.Add("| ``$($i.nid)`` | $($i.status) | $($i.detail) | $(& $classOf $i.nid) |") }
    }
    if ($r.Contains('gaps') -and @($r.gaps).Count) { $md.Add(''); $md.Add('## Known gaps'); foreach ($g in @($r.gaps)) { $md.Add("- $g") } }
    if ($r.Contains('missedObjects') -and @($r.missedObjects).Count) { $md.Add(''); $md.Add('## Missed leftovers'); foreach ($g in @($r.missedObjects)) { $md.Add("- ``$g``") } }
    if ($r.Contains('unclassifiedInstalled') -and @($r.unclassifiedInstalled).Count) { $md.Add(''); $md.Add('## Unclassified objects added by the install'); foreach ($g in @($r.unclassifiedInstalled)) { $md.Add("- ``$g``") } }
    Set-Content -LiteralPath (Join-Path $results "$($d.Name).md") $md -Encoding UTF8
    $all += , $r
}

$rows = New-Object System.Collections.Generic.List[string]
$rows.Add('| Scenario | Verdict | False del. | Leftovers | Found | Missed | Removed | Restore | Resume (killWindow) | Gaps |')
$rows.Add('|---|---|---|---|---|---|---|---|---|---|')
function Show($v) { if ($null -eq $v) { '-' } else { "$v" } }
foreach ($r in $all) {
    $restore = if ($null -eq $r['restoreOk']) { '-' } elseif ($r['restoreOk']) { 'ok' } else { 'FAIL' }
    $resume = if ($r['resume']) { "$(if ($r['resume'].resumeOk) { 'ok' } else { 'FAIL' }) ($($r['resume'].killWindow))" } else { '-' }
    $gapCount = if ($r['gaps']) { @($r['gaps'] | Where-Object { $_ -notlike 'elevated admin*' }).Count } else { '-' }
    $rows.Add("| $($r.scenario) | $($r.verdict) | $(Show $r['falseDeletions']) | $(Show $r['leftovers']) | $(Show $r['found']) | $(Show $r['missed']) | $(Show $r['removed']) | $restore | $resume | $gapCount |")
}
Set-Content -LiteralPath (Join-Path $results 'summary.md') $rows -Encoding UTF8
$all | ForEach-Object { [ordered]@{ scenario = $_.scenario; verdict = $_.verdict; reasons = $_.reasons } } | ConvertTo-Json -Depth 10 | Set-Content -LiteralPath (Join-Path $results 'summary.json') -Encoding UTF8
$rows | ForEach-Object { Write-Host $_ }
foreach ($r in $all) { if ($r.verdict -ne 'PASS') { Write-Host "[$($r.scenario)] $($r.verdict)"; foreach ($x in @($r.reasons)) { Write-Host "  $x" } } }
if (@($all | Where-Object { $_.verdict -eq 'FAIL' -or $_.verdict -eq 'ERROR' }).Count) { exit 1 } else { exit 0 }
