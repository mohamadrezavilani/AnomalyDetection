from contextlib import ExitStack
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch
from compact_behavior.extract import instant
from compact_product.config import Config
from compact_product.history import core_ready, task, control
from tests.test_compact_operations import healthy_observation


class HistoryControlTests(unittest.TestCase):
    def test_first_aban_is_an_explicit_tehran_midnight(self):
        self.assertEqual(instant("2026-10-23T00:00:00+03:30"),1792701000000000000)
        self.assertEqual(instant("2026-10-22T20:30:00Z"),1792701000000000000)

    def test_history_waits_for_source_analysis_reference_and_timing(self):
        ready = healthy_observation()["samples"][0]["health"]
        self.assertTrue(core_ready(ready))
        for field in ("source_backlog_windows","reference_pending_windows","analysis_pending_windows","dirty_keys","reanalysis_windows","analysis_timing_unconfirmed_windows"):
            with self.subTest(field=field):
                self.assertFalse(core_ready(dict(ready,**{field:1})))
                self.assertFalse(core_ready(dict(ready,**{field:None})))
        ready["roles"]["analysis"]["failure"]={"code":"source_timeout"}
        self.assertFalse(core_ready(ready))

    def test_history_task_is_separate_and_uses_the_new_code_directory(self):
        with patch("viewer_performance.financial_screen.host.powershell",return_value={}) as shell:
            task(Path("data project"),"register")
        script,environment=shell.call_args.args
        self.assertIn("P24-CompactHistory",script)
        self.assertNotIn("P24-CompactProduct",script)
        self.assertIn("-AtStartup",script)
        self.assertIn("-MultipleInstances IgnoreNew",script)
        self.assertIn("History_Compact_Product.ps1",environment["P24_HISTORY_ARGS"])
        self.assertEqual(environment["P24_HISTORY_CODE"],str(Path(__file__).resolve().parents[1]))

    def test_history_status_does_not_initialize_or_modify_database(self):
        with tempfile.TemporaryDirectory() as directory, ExitStack() as stack:
            root=Path(directory)
            stack.enter_context(patch("compact_product.history.load",return_value=(Config(),{"DATABASE":{}},"test")))
            store=stack.enter_context(patch("compact_product.history.Store")).return_value
            initialize=stack.enter_context(patch("compact_product.history.initialize"))
            stack.enter_context(patch("compact_product.history.progress",return_value=dict(status="COMPACT_HISTORY_STATUS",job=None,history_role={},core={},storage={})))
            control(root,"status")
            store.init.assert_not_called(); initialize.assert_not_called()

    @unittest.skipUnless(os.name=="nt","native Windows PowerShell required")
    def test_native_history_entry_and_persian_calendar_and_task_settings(self):
        with tempfile.TemporaryDirectory(prefix="history installer ") as directory:
            data=Path(directory)/"data without module"; data.mkdir()
            script=Path(__file__).resolve().parents[1]/"compact_product/History_Compact_Product.ps1"
            result=subprocess.run(["powershell.exe","-NoProfile","-ExecutionPolicy","Bypass","-File",str(script),"-Action","Version","-Project",str(data),"-Python",sys.executable],cwd=directory,capture_output=True,text=True,timeout=45)
            self.assertEqual(result.returncode,0,result.stdout+result.stderr)
            self.assertTrue(json.loads(result.stdout)["build_id"].startswith("COMPACT-PRODUCT-"))
            command="$c=New-Object System.Globalization.PersianCalendar; $d=$c.ToDateTime(1405,8,1,0,0,0,0).ToString('yyyy-MM-dd'); $s=New-ScheduledTaskSettingsSet -RestartCount 999 -RestartInterval (New-TimeSpan -Minutes 1) -ExecutionTimeLimit ([TimeSpan]::Zero); @{day=$d;restarts=$s.RestartCount}|ConvertTo-Json -Compress"
            result=subprocess.run(["powershell.exe","-NoProfile","-Command",command],capture_output=True,text=True,timeout=45)
            self.assertEqual(result.returncode,0,result.stdout+result.stderr)
            self.assertEqual(json.loads(result.stdout),dict(day="2026-10-23",restarts=999))


if __name__=="__main__": unittest.main()
