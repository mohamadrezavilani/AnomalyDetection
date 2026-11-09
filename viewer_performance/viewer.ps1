param(
    [ValidateSet('Start','Worker','Web','Status','Check','Pilot','Resources','Smoke')]
    [string]$Action = 'Start',
    [string]$Config = '',
    [string]$Python = '',
    [switch]$ResumeCheckpoint
)
$ErrorActionPreference = 'Stop'
$viewerRoot = Split-Path -Parent $PSScriptRoot
Set-Location -LiteralPath $viewerRoot
if (-not $Config) { $Config = Join-Path $viewerRoot 'viewer_config.local.py' }
$viewerConfig = (Resolve-Path -LiteralPath $Config).Path
if ($viewerConfig -ine (Join-Path $viewerRoot 'viewer_config.local.py')) { throw 'The memory-profile launcher requires the original viewer_config.local.py.' }
$viewerPython = $Python
if ($viewerPython) {
    if (Test-Path -LiteralPath $viewerPython -PathType Leaf) {
        $viewerPython = (Resolve-Path -LiteralPath $viewerPython).Path
    } else {
        $viewerCommand = Get-Command -Name $viewerPython -CommandType Application -ErrorAction Stop |
            Select-Object -First 1
        $viewerPython = $viewerCommand.Source
    }
} else {
    $viewerCandidates = @()
    if ($env:VIRTUAL_ENV) {
        $viewerCandidates += Join-Path $env:VIRTUAL_ENV 'Scripts\python.exe'
    }
    $viewerCandidates += Join-Path $viewerRoot '.venv\Scripts\python.exe'
    $viewerCandidates += Join-Path (Split-Path -Parent $viewerRoot) '.venv\Scripts\python.exe'
    foreach ($viewerCandidate in $viewerCandidates) {
        if (Test-Path -LiteralPath $viewerCandidate -PathType Leaf) {
            $viewerPython = (Resolve-Path -LiteralPath $viewerCandidate).Path
            break
        }
    }
    if (-not $viewerPython) {
        # Windows can return several ApplicationInfo objects. Select one before
        # reading Source so the call operator never receives joined executables.
        $viewerCommand = Get-Command -Name python -CommandType Application -ErrorAction Stop |
            Select-Object -First 1
        $viewerPython = $viewerCommand.Source
    }
}
switch ($Action) {
    'Smoke' {
        & $viewerPython '.\tools\check_viewer_install.py' --config $viewerConfig
        if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
        & $viewerPython '.\tools\run_viewer_pilot.py' --config $viewerConfig --smoke --windows 2 --rechecks 1 --max-minutes 12 --out '.\validation\d2_prefetch_smoke.json'
        exit $LASTEXITCODE
    }
    'Resources' {
        & $viewerPython '.\tools\apply_postgres_resources.py' --config $viewerConfig --probe --out '.\validation\d2_resources_probe.json'
        exit $LASTEXITCODE
    }
    'Check' {
        & $viewerPython '.\tools\check_viewer_install.py' --config $viewerConfig
        exit $LASTEXITCODE
    }
    'Status' {
        & $viewerPython '.\tools\run_behavior_viewer.py' live-status --config $viewerConfig
        exit $LASTEXITCODE
    }
    'Worker' {
        $viewerStartup = @()
        if ($ResumeCheckpoint) { $viewerStartup += '--resume-checkpoint' }
        & $viewerPython '.\viewer_performance\Run_Viewer_Memory.py' --project-root $viewerRoot --worker @viewerStartup
        exit $LASTEXITCODE
    }
    'Web' {
        & $viewerPython '.\tools\run_behavior_viewer.py' serve --config $viewerConfig --progress
        exit $LASTEXITCODE
    }
    'Pilot' {
        & $viewerPython '.\tools\run_viewer_pilot.py' --config $viewerConfig --windows 6 --max-minutes 45 --out '.\validation\live_acceptance.json'
        exit $LASTEXITCODE
    }
    'Start' {
        & $viewerPython '.\tools\check_viewer_install.py' --config $viewerConfig
        if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
        foreach ($viewerMode in @('Worker','Web')) {
            $viewerArguments = @('-NoProfile','-ExecutionPolicy','Bypass','-NoExit',
                '-File', ('"' + $PSCommandPath + '"'), '-Action', $viewerMode,
                '-Config', ('"' + $viewerConfig + '"'), '-Python', ('"' + $viewerPython + '"'))
            if ($ResumeCheckpoint) { $viewerArguments += '-ResumeCheckpoint' }
            Start-Process -FilePath (Join-Path $PSHOME 'powershell.exe') -WorkingDirectory $viewerRoot -ArgumentList $viewerArguments
        }
        Write-Output 'Viewer started. Open http://127.0.0.1:5021/ . Stop each window with Ctrl+C.'
    }
}
