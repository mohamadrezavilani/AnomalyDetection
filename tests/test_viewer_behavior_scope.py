import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from p24_foundation.privacy import generate_keys
from p24_foundation.viewer_data import ViewerDB
from p24_foundation.viewer_online import initialize_live,bind_stream,publish_capture
from p24_foundation.viewer_product_scope import set_scope,BEHAVIOR,read
from viewer_performance.financial_screen.fixtures import corpus,FIVE


class BehaviorScopeTests(unittest.TestCase):
    def test_boundaries_late_conflict_and_preserved_identity(self):
        with tempfile.TemporaryDirectory() as folder:
            root=Path(folder);keys=root/'keys.json';generate_keys(keys)
            jobs=corpus(root,(3,4,5));databases=[]
            try:
                for mode in ('full','behavior'):
                    db=ViewerDB(sqlite_path=root/(mode+'.db'),keys_path=keys);databases.append(db)
                    db.init();initialize_live(db);bind_stream(db,start_ns=jobs[0]['start'],stream_key='same-source')
                    if mode=='behavior':set_scope(db,BEHAVIOR);db.conn.commit()
                for job in jobs:
                    results=[]
                    for db in databases:
                        results.append(publish_capture(db,job['path'],job['start'],job['start']+FIVE,mode=job['mode']))
                    self.assertEqual(results[0]['new_events'],results[1]['new_events'])
                    for table,cols,order in (
                        ('viewer_events','*','origin_key,version_key'),
                        ('viewer_raw_events','*','origin_key,version_key'),
                        ('viewer_requests','*','request_key'),
                        ('viewer_semantic_occurrences','request_key,anchor_key,session_key,anchor_ns,kind,root_call,root_code,state,revision','request_key')):
                        self.assertEqual(databases[0].all('SELECT '+cols+' FROM '+table+' ORDER BY '+order),
                                         databases[1].all('SELECT '+cols+' FROM '+table+' ORDER BY '+order),table)
                db=databases[1]
                self.assertEqual(db.one('SELECT COUNT(*) AS n FROM viewer_contract_edges')['n'],0)
                self.assertEqual(db.one("SELECT COUNT(*) AS n FROM viewer_links WHERE link_domain NOT IN ('access_session','query_parameters_hash')")['n'],0)
                self.assertEqual(read(db)['contract'],BEHAVIOR)
            finally:
                for db in databases:db.close()

    def test_disabled_finance_functions_not_called_and_commit_rolls_back(self):
        with tempfile.TemporaryDirectory() as folder:
            root=Path(folder);keys=root/'keys';generate_keys(keys);jobs=corpus(root,(1,1,1))
            with ViewerDB(sqlite_path=root/'db',keys_path=keys) as db:
                db.init();initialize_live(db);bind_stream(db,start_ns=jobs[0]['start'],stream_key='scope')
                set_scope(db,BEHAVIOR);db.conn.commit()
                before=db.one('SELECT next_ns,generation FROM viewer_live_state')
                def fail(stage):
                    if stage=='before_commit':raise RuntimeError('injected_crash')
                with patch.object(db,'_rebuild_payment_contract',side_effect=AssertionError('finance called')), \
                     patch.object(db,'_reconcile_payment_outcomes',side_effect=AssertionError('finance called')), \
                     patch.object(db,'_projection_payment_links_sql',side_effect=AssertionError('finance called')):
                    with self.assertRaises(RuntimeError):publish_capture(db,jobs[0]['path'],jobs[0]['start'],jobs[0]['start']+FIVE,fault=fail)
                    self.assertEqual(db.one('SELECT next_ns,generation FROM viewer_live_state'),before)
                    self.assertEqual(db.one('SELECT COUNT(*) AS n FROM viewer_events')['n'],0)
                    publish_capture(db,jobs[0]['path'],jobs[0]['start'],jobs[0]['start']+FIVE)

    def test_failed_restore_can_resume_without_leaking_repair_privilege(self):
        from viewer_performance.Behavior_Control import change
        from p24_foundation.viewer_product_scope import financial_enabled,FULL
        with tempfile.TemporaryDirectory() as folder:
            root=Path(folder);keys=root/'keys';generate_keys(keys);jobs=corpus(root,(1,1,1))
            with ViewerDB(sqlite_path=root/'db',keys_path=keys) as db:
                db.init();initialize_live(db);bind_stream(db,start_ns=jobs[0]['start'],stream_key='scope')
                change(db,'enable')
                self.assertFalse(financial_enabled(db));self.assertFalse(db._financial_repair)
                publish_capture(db,jobs[0]['path'],jobs[0]['start'],jobs[0]['start']+FIVE)
                before=db.one('SELECT start_ns,next_ns,stream_key,keys_fingerprint FROM viewer_live_state')
                with patch.object(db,'rebuild_payment_contract',side_effect=RuntimeError('injected repair failure')):
                    with self.assertRaises(RuntimeError):change(db,'restore-full')
                self.assertFalse(db._financial_repair);self.assertFalse(financial_enabled(db))
                self.assertEqual(read(db,refresh=True)['state'],'RESTORING_FULL')
                with self.assertRaisesRegex(ValueError,'financial_restore_in_progress'):db.write_lock()
                db.conn.rollback()
                change(db,'restore-full')
                self.assertEqual(read(db,refresh=True)['contract'],FULL)
                self.assertTrue(financial_enabled(db));self.assertFalse(db._financial_repair)
                self.assertEqual(db.one('SELECT start_ns,next_ns,stream_key,keys_fingerprint FROM viewer_live_state'),before)

    def test_old_financial_cards_hidden_but_observed_business_outcome_survives(self):
        from viewer_performance.Behavior_Control import change
        from p24_foundation.viewer_data import token
        from p24_foundation.viewer_ui import create_viewer_app
        with tempfile.TemporaryDirectory() as folder:
            root=Path(folder);keys=root/'keys';generate_keys(keys);jobs=corpus(root,(1,1,1))
            opts=dict(sqlite_path=root/'db',keys_path=keys)
            with ViewerDB(**opts) as db:
                db.init();initialize_live(db);bind_stream(db,start_ns=jobs[0]['start'],stream_key='scope')
                publish_capture(db,jobs[0]['path'],jobs[0]['start'],jobs[0]['start']+FIVE)
                key=token(db.keys,'request','w0-r0')
                db.sql("UPDATE viewer_actions SET current_outcome='no_payable_bill' WHERE action_key=?",(key,));db.conn.commit()
                change(db,'enable')
                self.assertEqual(db.action(key)['current_outcome'],'no_payable_bill')
                self.assertEqual(db.requests_page(request_id='w0-r0')['items'][0]['current_outcome'],'no_payable_bill')
                self.assertEqual(db.actions(token(db.keys,'session','a'*32),result='no_payable_bill')['total'],1)
                for call in (db.inquiry_payment_journey,db.bill_item_journey,db.service_payment_journey,db.service_journey,db.payment_contract_card):
                    self.assertIsNone(call(key))
            client=create_viewer_app(opts).test_client()
            result=client.get('/action/'+key)
            self.assertEqual(result.status_code,200)
            page=result.get_data(as_text=True)
            self.assertIn('خارج از دامنه',page)
            self.assertNotIn('مشاهدهٔ مستقل از Paid یا وب‌هوک ثبت نشده',page)

    def test_manual_refresh_has_no_timer_or_fetch(self):
        source=(Path(__file__).resolve().parents[1]/'review_ui/static/viewer_live.js').read_text()
        self.assertNotIn('setInterval(',source);self.assertNotIn('fetch(',source)


if __name__=='__main__':unittest.main()
