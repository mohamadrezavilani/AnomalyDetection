[CmdletBinding()]
param(
    [string]$Project = (Split-Path -Parent $PSScriptRoot),
    [string]$Python = '',
    [switch]$Run,
    [string]$CapturesZip = '',
    [int]$MaxSeconds = 1800,
    [string]$Counts = '16,64,256',
    [string]$HistoryRequests = '0,4096'
)
$ErrorActionPreference = 'Stop'
$Project = (Resolve-Path -LiteralPath $Project).Path
if (-not $Python) { $Python = Join-Path $Project '.venv\Scripts\python.exe' }
$Python = (Resolve-Path -LiteralPath $Python).Path
$entry = Join-Path $Project 'viewer_performance\Screen_Financial_Product.py'
$mode = if ($Run) { '--exclusive-run' } else { '--preflight' }
$screenArguments = @('-B', $entry, '--project', $Project, $mode,
    '--max-seconds', [string]$MaxSeconds, '--counts', $Counts, '--history-requests', $HistoryRequests)
if ($CapturesZip) { $screenArguments += @('--captures-zip', (Resolve-Path -LiteralPath $CapturesZip).Path) }
& $Python @screenArguments
if ($LASTEXITCODE -ne 0) {
    throw 'Screen blocked or incomplete. Send its JSON and preflight report. The maintenance receipt records any restore failure.'
}
