from pathlib import Path
import unittest
from tools.Upgrade_Compact_Context import upgrade

class ContextUpgradeTests(unittest.TestCase):
    def run_steps(self, responses):
        calls=[]
        def execute(args,cwd):
            calls.append((args,cwd));return responses[len(calls)-1]
        report=upgrade(Path('project'),Path('new'),Path('old'),Path('history-old'),'sha',execute=execute)
        return report,calls
    def test_core_failure_never_stops_history(self):
        result,calls=self.run_steps([(0,{'history_state':'ACTIVE'}),(2,{'status':'RESTORED'})])
        self.assertEqual(len(calls),2)
        self.assertEqual(result['status'],'COMPACT_CONTEXT_UPGRADE_INCOMPLETE')
    def test_owned_history_migrates_only_after_core_and_stop_succeed(self):
        result,calls=self.run_steps([(0,{'history_state':'ACTIVE'}),(0,{}),(0,{}),(0,{})])
        self.assertEqual(result['status'],'COMPACT_CONTEXT_CORE_AND_HISTORY_UPGRADED')
        self.assertEqual(calls[2][1],Path('history-old'))
        self.assertIn('history-stop',calls[2][0])
        self.assertEqual(calls[3][0][0],Path('new/tools/Repair_Compact_History_Task.py'))
    def test_stop_failure_and_completed_history(self):
        result,calls=self.run_steps([(0,{'history_state':'ACTIVE'}),(0,{}),(2,{})])
        self.assertEqual(len(calls),3)
        result,calls=self.run_steps([(0,{'history_state':'COMPLETE'}),(0,{})])
        self.assertEqual(len(calls),2)
        self.assertEqual(result['status'],'COMPACT_CONTEXT_CORE_UPGRADED_HISTORY_ALREADY_COMPLETE')
