import json
import multiprocessing
import os
from pathlib import Path
import tempfile
import unittest

from tests.test_viewer_minimal_pg import NativeMinimalPublicationTests,crash_publish
from tests.test_viewer_service_dispatch import ServiceDispatchTests
from tests.test_viewer_online import START,FIVE_NS,verified_file,iso
from p24_foundation.viewer_data import ViewerDB
from p24_foundation.viewer_online import initialize_live,bind_stream,publish_capture
from p24_foundation.viewer_product_scope import set_scope,BEHAVIOR,read,FULL


def crash_financial_restore(config,keys):
    from viewer_performance.Behavior_Control import change
    with ViewerDB(config=config,keys_path=keys) as db:
        change(db,'restore-full',progress=lambda value:os._exit(73) if value['stage']=='REBUILDING_FINANCIAL_CONTRACT' else None)
    os._exit(74)


@unittest.skipUnless(os.environ.get('P24_DELTA_PG_HOST'),'native PG18 required')
class NativeBehaviorTests(unittest.TestCase):
    setUpClass=classmethod(NativeMinimalPublicationTests.setUpClass.__func__)
    tearDownClass=classmethod(NativeMinimalPublicationTests.tearDownClass.__func__)
    setUp=NativeMinimalPublicationTests.setUp

    def test_real_repair_crash_stays_fenced_and_resumes_without_cursor_reset(self):
        from viewer_performance.Behavior_Control import change
        change(self.db,'enable')
        path=verified_file(self.root/'repair.gz',[dict(_source_id='behavior:repair',**{'@timestamp':iso(START+1_000_000_000)},RequestID='repair',Session='a'*32,IP='192.0.2.1',CallPath='Services.v1/WaterBills',message='POST (G00000 | successful)')],START)
        publish_capture(self.db,path,START,START+FIVE_NS)
        before=self.db.one('SELECT start_ns,next_ns,stream_key,keys_fingerprint FROM viewer_live_state');self.db.close()
        process=multiprocessing.get_context('spawn').Process(target=crash_financial_restore,args=(self.config,str(self.keys)))
        process.start();process.join(30);self.assertEqual(process.exitcode,73)
        with ViewerDB(config=self.config,keys_path=self.keys) as db:
            self.assertEqual(read(db,refresh=True)['state'],'RESTORING_FULL')
            with self.assertRaisesRegex(ValueError,'financial_restore_in_progress'):db.write_lock()
            db.conn.rollback();change(db,'restore-full')
            self.assertEqual(read(db,refresh=True)['contract'],FULL)
            self.assertEqual(db.one('SELECT start_ns,next_ns,stream_key,keys_fingerprint FROM viewer_live_state'),before)

    def test_native_dispatch_publication_crash_retry_and_financial_rollback(self):
        from p24_foundation.viewer_data import token
        from p24_foundation.privacy import generate_keys
        from viewer_performance.Behavior_Control import change
        fixture=ServiceDispatchTests();fixture.setUp()
        try:rows=fixture.flow('behavior-dispatch','1'*32,'result')
        finally:fixture.doCleanups()
        for i,row in enumerate(rows):row['@timestamp']=iso(START+(i+1)*1_000_000_000)
        path=verified_file(self.root/'behavior.gz',rows,START)
        with ViewerDB(config=self.config,keys_path=self.keys) as db:
            self.db.close()
            set_scope(db,BEHAVIOR);db.conn.commit()
        context=multiprocessing.get_context('spawn')
        process=context.Process(target=crash_publish,args=(self.config,str(self.keys),str(path),START,'before_commit'))
        process.start();process.join(30);self.assertEqual(process.exitcode,73)
        with ViewerDB(config=self.config,keys_path=self.keys) as db:
            self.assertEqual(db.one('SELECT COUNT(*) AS n FROM viewer_events')['n'],0)
            result=publish_capture(db,path,START,START+FIVE_NS)
            key=token(db.keys,'request','behavior-dispatch')
            semantic=db.one('SELECT root_call,state FROM viewer_semantic_occurrences WHERE request_key=?',(key,))
            self.assertEqual(semantic['root_call'],'Services.v1/SocialSecurityInsuranceElectronicPrescription')
            self.assertEqual(semantic['state'],'active')
            self.assertEqual(db.one('SELECT COUNT(*) AS n FROM viewer_contract_edges')['n'],0)
            later=verified_file(self.root/'after.gz',[],START+FIVE_NS)
            db.conn.rollback()
            killed=context.Process(target=crash_publish,args=(self.config,str(self.keys),str(later),START+FIVE_NS,'after_commit'))
            killed.start();killed.join(30);self.assertEqual(killed.exitcode,73)
            self.assertEqual(db.one('SELECT next_ns FROM viewer_live_state')['next_ns'],START+2*FIVE_NS)
            duplicate=publish_capture(db,later,START+FIVE_NS,START+2*FIVE_NS,mode='recheck')
            self.assertEqual(duplicate['new_events'],0)
            self.assertTrue(db.one("SELECT 1 AS yes FROM viewer_contract_observations WHERE axis='service_dispatch.inquiry_result'"))
            before=db.one('SELECT start_ns,next_ns,stream_key,keys_fingerprint FROM viewer_live_state')
            change(db,'restore-full')
            self.assertEqual(read(db,refresh=True)['contract'],FULL)
            self.assertEqual(db.one('SELECT start_ns,next_ns,stream_key,keys_fingerprint FROM viewer_live_state'),before)
            self.assertEqual(db.one('SELECT generation FROM viewer_live_state')['generation'],db.semantic_checkpoint()['generation'])
            self.assertTrue(db.one('SELECT 1 AS yes FROM viewer_contract_identifiers LIMIT 1'))


if __name__=='__main__':unittest.main()
