[CmdletBinding()]
param(
    [ValidateSet('Install','Status','Stop','Worker','Version')][string]$Action='Status',
    [Parameter(Mandatory=$true)][string]$Project,
    [string]$Python='',
    [string]$From=''
)
$ErrorActionPreference='Stop'
$CodeRoot=(Resolve-Path -LiteralPath (Split-Path -Parent $PSScriptRoot)).Path
$Project=(Resolve-Path -LiteralPath $Project).Path
if(-not $Python){$Python=Join-Path $Project '.venv\Scripts\python.exe'}
$Python=(Resolve-Path -LiteralPath $Python).Path
Push-Location -LiteralPath $CodeRoot
try{
    if($Action -eq 'Version'){
        & $Python -X utf8 -B -m compact_product version --project $Project
    }else{
        $historyArgs=@('-X','utf8','-B','-m','compact_product',('history-'+$Action.ToLowerInvariant()),'--project',$Project)
        if($From){$historyArgs+=@('--history-from',$From)}
        if($Action -eq 'Worker'){
            $log=Join-Path $Project 'compact_runtime\history-launcher.log'
            & $Python @historyArgs *>> $log
        }else{& $Python @historyArgs}
    }
    if($LASTEXITCODE -ne 0){throw 'History operation incomplete. Send the printed JSON and Compact_History_Status.json when present.'}
}finally{Pop-Location}
