import json,tempfile,unittest,zipfile
from pathlib import Path
from unittest.mock import patch
from anomaly_detection.acceptance_report import collect


class AcceptanceReportTests(unittest.TestCase):
    def bundle(self,status,exit_code,has_file):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp)/'AnomalyDetection';reports=root/'reports';reports.mkdir(parents=True)
            worker=reports/'worker.zip';review=reports/'review.zip'
            with zipfile.ZipFile(worker,'w') as z:z.writestr('worker_status.json','{}')
            if has_file:
                with zipfile.ZipFile(review,'w') as z:z.writestr('review_manifest.json',json.dumps({'status':status}))
            def case_review(*,project):
                self.assertEqual(project,root.parent)
                print(json.dumps({'status':status,**({'output':str(review)} if has_file else {})}));return exit_code
            with patch('anomaly_detection.product_control.export_report',return_value=({'health':'RUNNING'},worker)) as observe,patch('anomaly_detection.case_export.main',side_effect=case_review),patch('anomaly_detection.web_diagnostics.probe',return_value={'status':'NOT_RUN_UNIT_FIXTURE'}):
                result=collect(root,'sha',seconds=60)
            observe.assert_called_once_with(root,'sha',observe_seconds=60)
            self.assertEqual(result['project_acceptance'],'NOT_ASSIGNED_BY_COLLECTOR')
            with zipfile.ZipFile(result['output']) as z:
                self.assertIn('worker_report.zip',z.namelist())
                self.assertEqual('case_review.zip' in z.namelist(),has_file)
                meta=json.loads(z.read('acceptance_manifest.json'))
                self.assertEqual(meta['review_status'],status);self.assertEqual(meta['review_exit_code'],exit_code)
                self.assertFalse(meta['models_executed_by_collector']);self.assertFalse(meta['database_modified'])
            return result
    def test_complete_reports_are_combined_without_granting_project_acceptance(self):
        self.assertEqual(self.bundle('COMPLETE_READ_ONLY_CASE_REVIEW',0,True)['status'],'EVIDENCE_BUNDLE_EXPORTED')
    def test_partial_review_is_retained_with_its_failure_status(self):
        self.assertEqual(self.bundle('PARTIAL_READ_ONLY_CASE_REVIEW',2,True)['review_status'],'PARTIAL_READ_ONLY_CASE_REVIEW')
    def test_failed_review_still_produces_a_worker_evidence_bundle(self):
        self.assertEqual(self.bundle('REVIEW_EXPORT_FAILED',1,False)['status'],'PARTIAL_EVIDENCE_BUNDLE_EXPORTED')
