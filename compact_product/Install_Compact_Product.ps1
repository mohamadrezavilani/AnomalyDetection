[CmdletBinding()]
param(
    [ValidateSet('Trial','Install','Rollback','Observe','Status','Start','Stop','Version')][string]$Action='Trial',
    [string]$Project='',
    [string]$Python='',
    [string]$LegacyReceipt='',
    [string]$Receipt='',
    [ValidateRange(60,86400)][int]$Seconds=600
)
$ErrorActionPreference='Stop'
# Resolve defaults in the script body; PSScriptRoot can be empty in a param default.
$CodeRoot=(Resolve-Path -LiteralPath (Split-Path -Parent $PSScriptRoot)).Path
if([string]::IsNullOrWhiteSpace($Project)){$Project=$CodeRoot}
$Project=(Resolve-Path -LiteralPath $Project).Path
if([string]::IsNullOrWhiteSpace($Python)){$Python=Join-Path $Project '.venv\Scripts\python.exe'}
$Python=(Resolve-Path -LiteralPath $Python).Path
# Python -m imports from the release code directory, while --project selects data/config.
Push-Location -LiteralPath $CodeRoot
try{
    if($Action -in @('Trial','Install','Rollback')){
        $admin=([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
        if(-not $admin){throw 'Open PowerShell as Administrator.'}
    }
    & $Python -B -m compact_product version --project $Project
    if($LASTEXITCODE -ne 0){throw 'Compact package verification failed.'}
    if($Action -eq 'Version'){return}
    $compactArguments=@('-X','utf8','-B','-m','compact_product',$Action.ToLowerInvariant(),'--project',$Project,'--seconds',[string]$Seconds)
    if($LegacyReceipt){$compactArguments+=@('--legacy-receipt',(Resolve-Path -LiteralPath $LegacyReceipt).Path)}
    if($Receipt){$compactArguments+=@('--receipt',(Resolve-Path -LiteralPath $Receipt).Path)}
    & $Python @compactArguments
    if($LASTEXITCODE -ne 0){throw 'Compact operation incomplete. Send the JSON and receipt printed above.'}
}finally{Pop-Location}
