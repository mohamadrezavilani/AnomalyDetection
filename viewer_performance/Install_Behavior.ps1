param(
    [string]$Project=(Get-Location).Path,
    [Parameter(Mandatory=$true)][ValidatePattern('^[0-9a-fA-F]{40}$')][string]$TargetCommit,
    [string]$ReviewedPreflight='',
    [switch]$SkipBenchmark,
    [switch]$RestoreFull,
    [ValidateRange(30,86400)][int]$MaxSeconds=21600
)
$ErrorActionPreference='Stop'
Set-Location -LiteralPath $Project
$Project=(Get-Location).Path
$adPython=(Resolve-Path .\.venv\Scripts\python.exe).Path
$adPrevious=(git rev-parse HEAD).Trim()
if($LASTEXITCODE -ne 0){throw 'Existing Git checkout required.'}
$adChanges=git status --porcelain --untracked-files=no
if($LASTEXITCODE -ne 0 -or $adChanges){throw 'Tracked files changed. Preserve and review them before upgrading.'}
$adRemote=(git remote get-url origin).Trim().TrimEnd('/').ToLowerInvariant()
if($adRemote -notin @('https://github.com/mohamadrezavilani/anomalydetection.git','https://github.com/mohamadrezavilani/anomalydetection')){throw 'Unexpected origin repository.'}
git fetch origin main
if($LASTEXITCODE -ne 0){throw 'Git fetch failed; no services stopped.'}
git merge-base --is-ancestor $TargetCommit FETCH_HEAD
if($LASTEXITCODE -ne 0){throw 'Target must already be reviewed and merged into origin/main.'}
git merge-base --is-ancestor $adPrevious $TargetCommit
if($LASTEXITCODE -ne 0){throw 'Only a fast-forward from the installed checkout is allowed.'}
$adStage=git show "${TargetCommit}:viewer_performance/Behavior_Release.py"
if($LASTEXITCODE -ne 0){throw 'Pinned target has no release controller.'}
$adFolder=Join-Path $Project ('AnomalyDetection\reports\Behavior_Release_'+(Get-Date -Format 'yyyyMMdd_HHmmss')+'_'+[guid]::NewGuid().ToString('N').Substring(0,8))
New-Item -ItemType Directory -Path $adFolder -ErrorAction Stop | Out-Null
$adReceipt=Join-Path $adFolder 'release.json'
if(-not $ReviewedPreflight){$ReviewedPreflight=Join-Path $Project 'AnomalyDetection\reports\preflight_to_send.json'}
$adOldPid=$env:P24_BEHAVIOR_INSTALLER_PID;$adOldPath=$env:P24_BEHAVIOR_INSTALLER_PATH
$adOldEncoding=$OutputEncoding;$adOldPythonEncoding=$env:PYTHONIOENCODING
$env:P24_BEHAVIOR_INSTALLER_PID=[string]$PID;$env:P24_BEHAVIOR_INSTALLER_PATH=$PSCommandPath
$OutputEncoding=New-Object System.Text.UTF8Encoding($false);$env:PYTHONIOENCODING='utf-8'
$adPrepared=$false
try {
    # Freeze using the OLD installed helpers before touching tracked source.
    $adStage | & $adPython -B - --project $Project --receipt $adReceipt --action prepare-update --reviewed-preflight $ReviewedPreflight
    if($LASTEXITCODE -ne 0){throw 'Prepare blocked. Read release.json; tracked source was not updated.'}
    $adPrepared=$true
    git merge --ff-only $TargetCommit
    if($LASTEXITCODE -ne 0){throw 'Fast-forward failed. No scope activation performed.'}
    $adAction='benchmark-install'
    if($SkipBenchmark){$adAction='install'}
    if($RestoreFull){$adAction='rollback'}
    & $adPython -B viewer_performance/Behavior_Release.py --project $Project --receipt $adReceipt --action $adAction --max-seconds $MaxSeconds
    if($LASTEXITCODE -ne 0){throw 'Release incomplete. Send release.json, scope-progress.json and benchmark.json when present.'}
} catch {
    # Code-only rollback is allowed only before scope activation. --keep refuses
    # to overwrite any concurrent tracked edit and leaves ignored evidence alone.
    if($adPrepared -and (Test-Path -LiteralPath $adReceipt)){
        $adState=Get-Content -LiteralPath $adReceipt -Raw -Encoding UTF8 | ConvertFrom-Json
        if($adState.status -eq 'PREPARED_FOR_MAIN_UPDATE' -and -not $adState.scope_command){
            git reset --keep $adPrevious
            if($LASTEXITCODE -ne 0){Write-Warning 'Code recovery blocked by a concurrent edit; use the receipt.'}
        }
    }
    throw
} finally {
    if($adPrepared -and (Test-Path -LiteralPath $adReceipt)){
        $adState=Get-Content -LiteralPath $adReceipt -Raw -Encoding UTF8 | ConvertFrom-Json
        if($adState.status -eq 'PREPARED_FOR_MAIN_UPDATE'){
            # The pinned controller also supports recovery with old helpers when
            # checkout failed or code-only rollback removed the new controller.
            $adStage | & $adPython -B - --project $Project --receipt $adReceipt --action restore
            if($LASTEXITCODE -ne 0){Write-Warning 'Role restoration incomplete. Send release.json; do not start supervisors manually.'}
        }
    }
    $OutputEncoding=$adOldEncoding;$env:PYTHONIOENCODING=$adOldPythonEncoding
    $env:P24_BEHAVIOR_INSTALLER_PID=$adOldPid;$env:P24_BEHAVIOR_INSTALLER_PATH=$adOldPath
    Write-Host ('Private release receipt: '+$adReceipt)
}
