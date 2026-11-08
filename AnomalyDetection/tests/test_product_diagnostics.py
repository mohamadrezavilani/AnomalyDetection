import json
import unittest
import tempfile
import zipfile
from pathlib import Path

from anomaly_detection.product_diagnostics import read_queue,tracked_targets
from anomaly_detection import FIVE_NS


class Rows:
    def __init__(self,rows):self.rows=rows
    def fetchone(self):return self.rows[0] if self.rows else None
    def fetchall(self):return self.rows


class DiagnosticTests(unittest.TestCase):
    def test_exact_selection_is_bounded_validated_and_kept_out_of_model_inputs(self):
        with tempfile.TemporaryDirectory() as folder:
            root=Path(folder);(root/'reports').mkdir()
            data={'scope':'EXACT_OWNER_REPORTED_CASES_NOT_A_RANDOM_QUEUE_SAMPLE','cases':[
                {'session_key':'a'*64,'target_ns':600*FIVE_NS},
                {'session_key':'../../not_a_key','target_ns':600*FIVE_NS},
                {'session_key':'b'*64,'target_ns':601*FIVE_NS+1}]}
            with zipfile.ZipFile(root/'reports/exact_anomaly_cases_fixture.zip','w') as z:
                z.writestr('exact_cases.json',json.dumps(data))
            self.assertEqual(tracked_targets(root),[('a'*64,600*FIVE_NS)])

    def test_read_only_report_separates_partial_window_from_ready_queue(self):
        target=600*FIVE_NS
        row={'session_key':'a'*64,'target_ns':target,'dirty':True,'version':2,'processed_version':1,
            'last_evaluated_ns':None,'due_ns':0,'window_body':json.dumps({'counts':{'Services.v1/WaterBills':60,'Services.v1/ElectricBills':60}}),
            'window_complete':False,'evaluation':None}
        statements=[]
        class Raw:
            def execute(self,sql,params=()):
                statements.append(sql);assert sql.startswith('SELECT ')
                if 'ORDER BY start_ns' in sql:return Rows([{'start_ns':target-FIVE_NS,'complete':True}])
                if 'j.dirty=TRUE' in sql:return Rows([row])
                return Rows([])
        raw=Raw();report=read_queue(raw,target+2*FIVE_NS)
        item=report['pending_recent_sample'][0]
        self.assertEqual(item['queue_state'],'WAITING_FOR_COMPLETE_WINDOW')
        self.assertEqual(item['total_observed_executions'],120)
        self.assertEqual(item['counts_by_service']['Services.v1/WaterBills'],60)
        self.assertFalse(report['models_executed']);self.assertFalse(report['database_modified'])
        row['window_complete']=True
        item=read_queue(raw,target+2*FIVE_NS)['pending_recent_sample'][0]
        self.assertEqual(item['queue_state'],'PENDING_FIRST_EVALUATION')

    def test_previous_result_is_explicitly_stale_and_model_is_not_copied(self):
        row={'session_key':'b'*64,'target_ns':600*FIVE_NS,'dirty':True,'version':2,'processed_version':1,
            'last_evaluated_ns':100,'due_ns':0,'window_body':None,'window_complete':True,
            'evaluation':json.dumps({'decisions':[{'family':'rate_5m','status':'CANDIDATE','model':{'trees':'not needed'}}]})}
        class Raw:
            def execute(self,sql,params=()):
                assert sql.startswith('SELECT ')
                if 'j.dirty=TRUE' in sql:return Rows([row])
                return Rows([])
        item=read_queue(Raw(),601*FIVE_NS)['pending_recent_sample'][0]
        self.assertEqual(item['queue_state'],'RECHECK_REQUIRED')
        self.assertFalse(item['evaluation_current']);self.assertIsNone(item['total_observed_executions'])
        self.assertNotIn('model',item['decisions'][0])


if __name__=='__main__':unittest.main()
