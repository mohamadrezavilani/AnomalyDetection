import gzip,hashlib,json,tempfile,unittest,zipfile
from copy import deepcopy
from datetime import datetime,timezone
from pathlib import Path
from anomaly_detection import FIVE_NS
from anomaly_detection.service_reference import reference,qualify_roots,MIN_SESSIONS

TARGET=1_800_000_000_000_000_000//FIVE_NS*FIVE_NS
SERVICE='Public.v1/ExchangeCrypto'

def points(n=120):
    return [{'session_key':str(i),'start_ns':TARGET-(i+1)*3*FIVE_NS,'value':1+i%3} for i in range(n)]

class ReferenceTests(unittest.TestCase):
    def test_sparse_single_session_windows_can_form_diverse_cross_time_reference(self):
        model=reference(points(),'new',TARGET,SERVICE,unit='canonical_service_executions',reference_id='fixture')
        self.assertEqual(model['status'],'READY_BASELINE');self.assertEqual(model['other_session_epochs'],120)
        self.assertEqual(model['upper'],3)
    def test_repeated_one_session_is_not_one_hundred_peers(self):
        values=[dict(p,session_key='one') for p in points(400)]
        model=reference(values,'new',TARGET,SERVICE,unit='x',reference_id='x')
        self.assertEqual(model['status'],'INSUFFICIENT_DATA');self.assertEqual(model['other_session_epochs'],1)
    def test_self_future_unqualified_and_zero_are_excluded(self):
        values=points()+[{'session_key':'self','start_ns':TARGET-FIVE_NS,'value':500},
            {'session_key':'future','start_ns':TARGET,'value':900},
            {'session_key':'bad','start_ns':TARGET-FIVE_NS,'value':400,'qualified':False},
            {'session_key':'zero','start_ns':TARGET-FIVE_NS,'value':0}]
        model=reference(values,'self',TARGET,SERVICE,unit='x',reference_id='x')
        self.assertEqual(model['upper'],3);self.assertEqual(model['other_session_epochs'],120)
        self.assertFalse(model['zero_filled'])
    def test_short_duration_or_small_sample_remains_insufficient(self):
        for values in (points(MIN_SESSIONS-1),[dict(p,start_ns=TARGET-FIVE_NS) for p in points()]):
            self.assertEqual(reference(values,'new',TARGET,SERVICE,unit='x',reference_id='x')['status'],'INSUFFICIENT_DATA')
    def test_maximum_per_session_avoids_heavy_actor_weighting(self):
        model=reference(points()+[{'session_key':'0','start_ns':TARGET-3*FIVE_NS,'value':7}]*100,'new',TARGET,SERVICE,unit='x',reference_id='x')
        self.assertEqual(model['other_session_epochs'],120);self.assertEqual(model['reference_values'].count(7),1)

class CensusQualificationTests(unittest.TestCase):
    def archive(self,folder,*,mutate_row=None,mutate_manifest=None):
        dates=['2026-11-01T07:55:01Z','2026-11-02T07:55:02Z','2026-11-03T07:56:00Z']
        rows=[{'_index':'fixture','_id':str(i),'_version':1,'selected_service_root':True,
            'partition':'history' if i<2 else 'holdout','_source':{'@timestamp':at,'CallPath':SERVICE+' Line:149',
                'RequestID':'r'+str(i),'Session':'s'+str(i),'message':'POST http://fixture.invalid/service'}} for i,at in enumerate(dates)]
        if mutate_row:mutate_row(rows)
        blob=gzip.compress(('\n'.join(json.dumps(r) for r in rows)+'\n').encode())
        meta={'format':'AD_SCOPED_HISTORY_EXPORT_1','source_fingerprint':'fixture-source','service':SERVICE,
            'history_from_tehran':'2026-10-27T11:25:00+03:30','training_before_tehran':'2026-11-03T11:25:00+03:30',
            'holdout_until_tehran':'2026-11-03T12:10:00+03:30','root_verification':{'complete_root_query_snapshot':True,
                'canonical_viewer_projection':False,'safe_for_direct_baseline_import':False,'selected_root_records':3,
                'capture_sha256':hashlib.sha256(blob).hexdigest(),
                'datasets':{'history':{'selected_client_rows':2},'holdout':{'selected_client_rows':1}}}}
        if mutate_manifest:mutate_manifest(meta)
        path=Path(folder)/'census.zip'
        with zipfile.ZipFile(path,'w') as z:z.writestr('manifest.json',json.dumps(meta));z.writestr('service_roots.jsonl.gz',blob)
        return path
    def qualify(self,path):
        return qualify_roots(path,lambda kind,v:hashlib.sha256((kind+v).encode()).hexdigest(),'fixture-source')
    def test_historical_roots_are_a_separate_metric_and_holdout_never_trains(self):
        with tempfile.TemporaryDirectory() as d:packet=self.qualify(self.archive(d))
        self.assertEqual(len(packet['calls']),2);self.assertEqual(len(packet['cases']),1)
        self.assertFalse(packet['qualification']['canonical_behavior_baseline'])
        self.assertFalse(packet['qualification']['full_request_context_claimed'])
        self.assertEqual(packet['qualification']['holdout_calls_excluded'],1)
    def test_hash_or_incomplete_census_is_rejected(self):
        for mutate in (lambda m:m['root_verification'].update(capture_sha256='bad'),
                       lambda m:m['root_verification'].update(complete_root_query_snapshot=False)):
            with tempfile.TemporaryDirectory() as d:
                with self.assertRaises(ValueError):self.qualify(self.archive(d,mutate_manifest=mutate))
    def test_duplicate_request_or_wrong_service_is_rejected(self):
        for mutate in (lambda r:r[1]['_source'].update(RequestID='r0'),
                       lambda r:r[1]['_source'].update(CallPath='Services.v1/InvoiceRegister')):
            with tempfile.TemporaryDirectory() as d:
                with self.assertRaises(ValueError):self.qualify(self.archive(d,mutate_row=mutate))
    def test_future_test_record_cannot_be_marked_as_history(self):
        with tempfile.TemporaryDirectory() as d:
            with self.assertRaisesRegex(ValueError,'PARTITION_OR_LEAKAGE'):
                self.qualify(self.archive(d,mutate_row=lambda r:r[2].update(partition='history')))
    def test_missing_session_is_excluded_without_zero_or_actor_inference(self):
        with tempfile.TemporaryDirectory() as d:
            packet=self.qualify(self.archive(d,mutate_row=lambda r:r[0]['_source'].update(Session='N/A')))
        self.assertEqual(len(packet['calls']),1);self.assertEqual(packet['qualification']['missing_session_rows_excluded'],1)
    def test_source_binding_cannot_be_substituted(self):
        with tempfile.TemporaryDirectory() as d:
            with self.assertRaisesRegex(ValueError,'SOURCE_MISMATCH'):
                self.qualify(self.archive(d,mutate_manifest=lambda m:m.update(source_fingerprint='other')))
    def test_provider_or_sql_text_is_not_a_client_root(self):
        with tempfile.TemporaryDirectory() as d:
            with self.assertRaisesRegex(ValueError,'CLIENT_ROOT_NOT_OBSERVED'):
                self.qualify(self.archive(d,mutate_row=lambda r:r[0]['_source'].update(message='Output:[provider]')))

if __name__=='__main__':unittest.main()
