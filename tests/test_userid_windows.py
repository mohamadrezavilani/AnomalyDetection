"""Run the shipped PowerShell helpers under Windows PowerShell 5.1."""
import os
from pathlib import Path
import subprocess
import sys
import unittest


@unittest.skipUnless(os.name == 'nt','native Windows PowerShell required')
class PowerShellTransitionTests(unittest.TestCase):
    def test_actual_entry_parses_and_atomic_files_and_external_python_work(self):
        script = r"""
$ErrorActionPreference='Stop'
$tokens=$null
$errors=$null
$ast=[Management.Automation.Language.Parser]::ParseFile($env:ENTRY,[ref]$tokens,[ref]$errors)
if ($errors.Count) { throw ($errors -join ' ') }
foreach ($name in @('Run-Python','Save-Json','Snapshot')) {
    $f=$ast.Find({param($n) $n -is [Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -eq $name},$true)
    . ([scriptblock]::Create($f.Extent.Text))
}
$py=$env:TEST_PYTHON
$tmp=Join-Path $env:TEMP ([guid]::NewGuid().ToString()+' P24')
$null=New-Item -ItemType Directory -Path $tmp
try {
    $p=Join-Path $tmp 'receipt.json'
    Save-Json @{state='before'} $p
    Save-Json @{state='after'} $p
    if (((Get-Content $p -Raw | ConvertFrom-Json).state) -cne 'after') { throw 'atomic replace failed' }
    $got=Run-Python $tmp @('-c','import sys; print(sys.argv[1])','path with spaces')
    if ($got -cne 'path with spaces') { throw 'native argv roundtrip failed' }
    if ($null -ne (Snapshot $null)) { throw 'absent optional history task' }
} finally { Remove-Item $tmp -Recurse -Force }
"""
        root=Path(__file__).resolve().parents[1]
        run=subprocess.run(['powershell.exe','-NoProfile','-NonInteractive','-Command',script],
             env={**os.environ,'ENTRY':str(root/'tools/Start_UserID_Transition.ps1'),'TEST_PYTHON':sys.executable},
             capture_output=True,text=True,timeout=60)
        self.assertEqual(run.returncode,0,run.stderr)
