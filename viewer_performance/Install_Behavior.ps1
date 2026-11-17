param([string]$Project=(Get-Location).Path,[switch]$SkipBenchmark,[switch]$RestoreFull)
$ErrorActionPreference='Stop'
Set-Location -LiteralPath $Project
$adPython=(Resolve-Path .\.venv\Scripts\python.exe).Path
git fetch origin main
if($LASTEXITCODE -ne 0){throw 'Git fetch failed.'}
$adTarget=(git rev-parse FETCH_HEAD).Trim()
$adFolder=Join-Path $Project ('AnomalyDetection\reports\Behavior_Release_'+(Get-Date -Format 'yyyyMMdd_HHmmss'))
New-Item -ItemType Directory -Path $adFolder -ErrorAction Stop | Out-Null
$adReceipt=Join-Path $adFolder 'release.json'
$adStage=git show "${adTarget}:viewer_performance/Behavior_Release.py"
if($LASTEXITCODE -ne 0){throw 'Cannot read release controller.'}
$adStage | & $adPython -B - --project $Project --receipt $adReceipt --action prepare-update --reviewed-preflight (Join-Path $Project 'AnomalyDetection\reports\preflight_to_send.json')
if($LASTEXITCODE -ne 0){throw 'Prepare blocked. Send release.json; running roles were restored when stopping had started.'}
try {
    git merge --ff-only $adTarget
    if($LASTEXITCODE -ne 0){throw 'Fast-forward failed. No scope activation performed.'}
    $adAction='benchmark-install'
    if($SkipBenchmark){$adAction='install'}
    if($RestoreFull){$adAction='rollback'}
    & $adPython -B viewer_performance/Behavior_Release.py --project $Project --receipt $adReceipt --action $adAction
    if($LASTEXITCODE -ne 0){throw 'Release incomplete. Send release.json and benchmark.json.'}
} finally {
    $adState=Get-Content -LiteralPath $adReceipt -Raw | ConvertFrom-Json
    if($adState.status -eq 'PREPARED_FOR_MAIN_UPDATE'){
        if(Test-Path .\viewer_performance\Behavior_Release.py){
            & $adPython -B viewer_performance/Behavior_Release.py --project $Project --receipt $adReceipt --action restore
        } else {
            $adStage | & $adPython -B - --project $Project --receipt $adReceipt --action restore
        }
    }
    Invoke-Item -LiteralPath $adFolder
}
