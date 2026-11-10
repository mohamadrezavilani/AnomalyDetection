import errno,json,tempfile,unittest,zipfile
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

    def test_partial_review_is_labelled_as_a_partial_bundle(self):
        self.assertEqual(self.bundle('PARTIAL_READ_ONLY_CASE_REVIEW',2,True)['status'],'PARTIAL_EVIDENCE_BUNDLE_EXPORTED')

    def test_unreadable_real_process_metadata_still_exports_cases_with_an_explicit_partial_status(self):
        from anomaly_detection import process_control as processes
        original = processes.read_json
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)/'AnomalyDetection'; reports = root/'reports'; reports.mkdir(parents=True)
            review = reports/'review.zip'
            with zipfile.ZipFile(review,'w') as archive:
                archive.writestr('review_manifest.json','{}')
            def denied(path, default=None):
                if Path(path).name=='baseline_process.json':
                    raise PermissionError(errno.EACCES,'private-error-text','private-path')
                return original(path,default)
            def case_review(*,project):
                print(json.dumps({'status':'COMPLETE_READ_ONLY_CASE_REVIEW','output':str(review)}))
                return 0
            with processes.OwnedProcessLock(root,'baseline_worker','sha'):
                with patch.object(processes,'read_json',side_effect=denied), patch.object(processes.time,'sleep'), patch('anomaly_detection.case_export.main',side_effect=case_review), patch('anomaly_detection.web_diagnostics.probe',return_value={'status':'NOT_RUN_UNIT_FIXTURE'}), patch('anomaly_detection.product_diagnostics.snapshot',return_value={'status':'NOT_RUN_UNIT_FIXTURE'}):
                    result = collect(root,'sha',seconds=0)
                self.assertTrue(processes.process_owner(root)['locked'])
            self.assertEqual(result['status'],'PARTIAL_EVIDENCE_BUNDLE_EXPORTED')
            self.assertEqual(result['worker_health'],'PROCESS_IDENTITY_UNAVAILABLE')
            self.assertEqual(result['diagnostic_failures'][0]['stage'],'worker_identity')
            self.assertNotIn('private-',json.dumps(result))
            with zipfile.ZipFile(result['output']) as archive:
                self.assertIn('case_review.zip',archive.namelist())
                manifest = json.loads(archive.read('acceptance_manifest.json'))
            self.assertFalse(manifest['worker_identity_verified'])
            self.assertFalse(manifest['database_modified'])

    def test_unreadable_web_diagnostics_are_reported_without_losing_worker_and_case_exports(self):
        from anomaly_detection import process_control as processes
        original = processes.read_json
        def denied(path, default=None):
            if Path(path).name=='web_diagnostics.json':
                raise PermissionError(errno.EACCES,'private-error-text')
            return original(path,default)
        with patch.object(processes,'read_json',side_effect=denied),patch.object(processes.time,'sleep'):
            result = self.bundle('COMPLETE_READ_ONLY_CASE_REVIEW',0,True)
        self.assertEqual(result['status'],'PARTIAL_EVIDENCE_BUNDLE_EXPORTED')
        self.assertEqual(result['diagnostic_failures'][0]['stage'],'web_diagnostics')
