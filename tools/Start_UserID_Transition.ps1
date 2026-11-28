[CmdletBinding()]
param(
    [string]$Project = 'E:\P24\pishkhan24',
    [ValidateSet('Start','Present','Sample','PrepareDb','Shadow')][string]$Action = 'Start'
)
$ErrorActionPreference = 'Stop'
$Project = (Resolve-Path -LiteralPath $Project).Path
$py = Join-Path $Project '.venv\Scripts\python.exe'
if (-not (Test-Path -LiteralPath $py)) { throw 'Project Python environment was not found.' }
$release = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
$oldPath = $env:PYTHONPATH
$sourceTask = Get-ScheduledTask -TaskPath '\' -TaskName 'P24-CompactProduct' -ErrorAction SilentlyContinue
$sourceAction = @($sourceTask.Actions | Where-Object { $_ })
$oldCode = $release
$knownCore = $sourceAction.Count -eq 1 -and $sourceAction[0].WorkingDirectory -and (Test-Path -LiteralPath $sourceAction[0].WorkingDirectory)
if ($knownCore) { $oldCode = (Resolve-Path -LiteralPath $sourceAction[0].WorkingDirectory).Path }
$env:PYTHONPATH = $oldCode
$stateDir = Join-Path $Project 'compact_runtime\presentation'
$historyTask = Get-ScheduledTask -TaskPath '\' -TaskName 'P24-CompactHistory' -ErrorAction SilentlyContinue
$taskName = 'P24-CompactPresentation'
function Snapshot($task) {
    if ($null -eq $task) { return $null }
    return @{enabled=[bool]$task.Settings.Enabled;actions=@($task.Actions | Select-Object Execute,Arguments,WorkingDirectory)}
}
function Run-Python([string]$dir, [string[]]$arguments) {
    Push-Location -LiteralPath $dir
    try {
        & $py -X utf8 -B @arguments
        if ($LASTEXITCODE -ne 0) { throw "Project command exited with code $LASTEXITCODE" }
    } finally { Pop-Location }
}
function Save-Json($object, $dest) {
    $tmp = "$dest.$PID.tmp"
    [IO.File]::WriteAllText($tmp,($object | ConvertTo-Json -Depth 16),[Text.UTF8Encoding]::new($false))
    if ([IO.File]::Exists($dest)) {
        $last = "$tmp.previous"
        [IO.File]::Replace($tmp,$dest,$last)
        [IO.File]::Delete($last)
    }
    else { [IO.File]::Move($tmp,$dest) }
}
function Presentation {
    if (-not $knownCore) { throw 'Cannot identify the installed Compact release. Other preparation steps can continue.' }
    $principal = [Security.Principal.WindowsPrincipal]::new([Security.Principal.WindowsIdentity]::GetCurrent())
    if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) { throw 'Use an elevated PowerShell to change the installed scheduled tasks.' }
    $null = New-Item -ItemType Directory -Force -Path $stateDir
    $taskFile = Join-Path $stateDir 'task-input.local.json'
    Save-Json @{core=(Snapshot $sourceTask);history=(Snapshot $historyTask)} $taskFile
    $src = Join-Path $release 'tools\userid_transition\serve_preserved.py'
    $digest = (Get-FileHash -Algorithm SHA256 -LiteralPath $src).Hash
    $guardian = Join-Path $stateDir ("serve-" + $digest.Substring(0,16) + ".py")
    $roots = (Run-Python $release @('-m','tools.userid_transition.legacy_tasks','--tasks',$taskFile,'--project',$Project,'--guardian',$guardian)) | ConvertFrom-Json
    $previous = Get-ScheduledTask -TaskPath '\' -TaskName $taskName -ErrorAction SilentlyContinue
    if ($previous) {
        $pa = @($previous.Actions)
        if ($pa.Count -ne 1 -or $pa[0].Execute -ine $py -or $pa[0].Arguments -cne $roots.guardian_args -or $pa[0].WorkingDirectory -ine $oldCode) {
            throw 'Another task already owns the presentation task name.'
        }
    }
    if (Test-Path -LiteralPath $guardian) {
        if ((Get-FileHash -LiteralPath $guardian).Hash -ne $digest) { throw 'Presentation guardian content differs.' }
    } else { Copy-Item -LiteralPath $src -Destination $guardian }
    $receipt = Join-Path $stateDir 'switch.local.json'
    $saved = @{stage='VALIDATED';build=$roots.build;source_sha=$roots.sha}
    if (-not (Test-Path -LiteralPath (Join-Path $stateDir 'original-tasks.local.json'))) {
        Save-Json @{core=(Snapshot $sourceTask);history=(Snapshot $historyTask)} (Join-Path $stateDir 'original-tasks.local.json')
    }
    Save-Json $saved $receipt
    # Check the old web before changing task state. Reuse the original code's exact package and ports.
    $null = Run-Python $oldCode @('-m','compact_product','start','web','--project',$Project)
    $probe = (Run-Python $release @('-m','tools.userid_transition.check_web','--project',$Project,'--sha',$roots.sha)) | ConvertFrom-Json
    $saved['web_before'] = $probe
    if (-not $previous) {
        $a = New-ScheduledTaskAction -Execute $py -Argument $roots.guardian_args -WorkingDirectory $oldCode
        $tr = New-ScheduledTaskTrigger -AtStartup
        $settings = New-ScheduledTaskSettingsSet -RestartCount 999 -RestartInterval (New-TimeSpan -Minutes 1) -ExecutionTimeLimit ([TimeSpan]::Zero) -StartWhenAvailable -MultipleInstances IgnoreNew
        Register-ScheduledTask -TaskPath '\' -TaskName $taskName -Action $a -Trigger $tr -Principal $sourceTask.Principal -Settings $settings | Out-Null
    }
    Enable-ScheduledTask -TaskPath '\' -TaskName $taskName | Out-Null
    $fence = (Run-Python $release @('-m','tools.userid_transition.presentation','--project',$Project)) | ConvertFrom-Json
    $saved['fence'] = $fence
    $saved.stage = 'COMPACT_INPUT_FENCED'
    Save-Json $saved $receipt
    Write-Host 'Existing source publications are now blocked. Preserving web and analysis.'
    Start-ScheduledTask -TaskPath '\' -TaskName $taskName
    # Disable only verified project task actions. PostgreSQL, LAN proxy and web stay online.
    Disable-ScheduledTask -TaskPath '\' -TaskName 'P24-CompactProduct' | Out-Null
    if ($historyTask) { Disable-ScheduledTask -TaskPath '\' -TaskName 'P24-CompactHistory' | Out-Null }
    Run-Python $release @('-m','tools.userid_transition.quiet','--project',$Project)
    $live = (Run-Python $release @('-m','tools.userid_transition.check_web','--project',$Project,'--sha',$roots.sha,'--review',$fence.review_path)) | ConvertFrom-Json
    $t = Get-ScheduledTask -TaskPath '\' -TaskName $taskName
    if ([int]$t.State -ne 4 -or -not $t.Settings.Enabled) { throw 'Presentation task is not running yet; rerun to verify.' }
    if ((Get-ScheduledTask -TaskPath '\' -TaskName 'P24-CompactProduct').Settings.Enabled) { throw 'Old core task is enabled.' }
    if ($historyTask -and (Get-ScheduledTask -TaskPath '\' -TaskName 'P24-CompactHistory').Settings.Enabled) { throw 'Old history task is enabled.' }
    $after = (Run-Python $release @('-m','tools.userid_transition.presentation','--project',$Project,'--verify')) | ConvertFrom-Json
    if ([string]$after.cursor_ns -ne [string]$fence.cursor_ns -or [string]$after.epoch -ne [string]$fence.epoch) { throw 'Preserved source checkpoint changed.' }
    $heartbeatFile = Join-Path $stateDir 'guardian.local.json'
    $until = [DateTime]::UtcNow.AddSeconds(50)
    do {
        $beat = if (Test-Path $heartbeatFile) { Get-Content -Raw -LiteralPath $heartbeatFile | ConvertFrom-Json }
        $age = [DateTimeOffset]::UtcNow.ToUnixTimeSeconds() - [long]$beat.checked_unix_s
        if ($beat.source_sha -eq $roots.sha -and $beat.web -and $beat.analysis -and $age -ge 0 -and $age -lt 65) { break }
        if ([DateTime]::UtcNow -ge $until) { throw 'The presentation guardian has not verified the old web and analysis roles.' }
        Start-Sleep -Seconds 1
    } while ($true)
    $saved.stage='PRESENTATION_ACTIVE'
    $saved['web_after']=$live
    Save-Json $saved $receipt
    Write-Host ('PRESENTATION_ACTIVE build=' + $roots.build + ' date_link=' + $fence.review_path)
}
try {
    $presentFailed = $false
    if ($Action -in @('Start','Present')) {
        $null = New-Item -ItemType Directory -Force -Path $stateDir
        $switchLock = [IO.File]::Open((Join-Path $stateDir 'switch.lock'),'OpenOrCreate','ReadWrite','None')
        try { Presentation }
        catch {
            $presentFailed = $true
            Write-Warning ('PRESENTATION_NOT_CONFIRMED: ' + $_.Exception.Message)
            if ($Action -eq 'Present') { throw }
        } finally { $switchLock.Dispose() }
    }
    $step = switch ($Action) { 'Start' {'prepare'} 'Sample' {'sample'} 'PrepareDb' {'prepare-db'} 'Shadow' {'shadow'} }
    if ($step) { Run-Python $release @('-m','tools.userid_transition',$step,'--project',$Project) }
    if ($presentFailed) { throw 'Identity preparation was attempted. The old presentation switch still needs verification.' }
} finally {
    $env:PYTHONPATH = $oldPath
}
