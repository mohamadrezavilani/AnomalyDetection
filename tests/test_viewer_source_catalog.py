"""Retained role/anchor upgrades are atomic, exact and respect operator reviews."""
import hashlib
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
from p24_foundation.privacy import generate_keys
from p24_foundation.viewer_data import ViewerDB,initial_service_role,OWNER_CONFIRMED,CANDIDATE_ROLES
from p24_foundation.viewer_service_catalog import source_catalog
from p24_foundation.viewer_online import initialize_live,bind_stream,publish_capture
from tests.test_viewer_online import START,FIVE_NS,verified_file
from tests.test_viewer_r6_service_journey import log


def old_initial(path):
    if path in OWNER_CONFIRMED:return (*OWNER_CONFIRMED[path],'owner_confirmed')
    if path in CANDIDATE_ROLES:return (CANDIDATE_ROLES[path],'unknown','inferred')
    return ('unknown','unknown','unclassified')


def snapshot(db):
    tables=('viewer_events','viewer_raw_events','viewer_files','viewer_event_captures','viewer_capture_projections',
        'viewer_requests','viewer_actions','viewer_service_roles','viewer_service_role_history','viewer_service_catalog_state',
        'viewer_contract_identifiers','viewer_contract_edges','viewer_contract_observations',
        'viewer_semantic_occurrences','viewer_semantic_transitions','viewer_semantic_session_heads','viewer_semantic_checkpoint',
        'viewer_live_state','viewer_live_receipts')
    return {name:sorted(repr(row) for row in db.all('SELECT * FROM '+name)) for name in tables}


class SourceCatalogTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup)
        self.root=Path(self.temp.name);generate_keys(self.root/'keys')
        self.db=ViewerDB(sqlite_path=self.root/'db',keys_path=self.root/'keys');self.addCleanup(self.db.close)
        self.db.init();initialize_live(self.db);bind_stream(self.db,start_ns=START,stream_key='source_catalog_test')

    def legacy(self):
        paths=['Services.v1/PostTrackingExtended','Services.v1/SfaraCouponGetOrderDetail',
               'Services.v1/TopUpProductsInternetPackage','Core.v2/DeviceRegister',
               'Files.Download','PaymentRedirect.PaymentRedirect','Services.v1/CellPhoneBillsDetails']
        rows=[log(n+1,'old_'+str(n),path+' Line:5','POST (G00000 | successful)') for n,path in enumerate(paths)]
        with patch('p24_foundation.viewer_data.initial_service_role',side_effect=old_initial),\
             patch('p24_foundation.service_journey.role_proposal',return_value=None):
            publish_capture(self.db,verified_file(self.root/'old.gz',rows),START,START+FIVE_NS)
        self.db.sql("UPDATE viewer_service_catalog_state SET fingerprint='old_catalog'");self.db.conn.commit()
        return paths

    def test_owner_main_market_services_are_business_without_manual_initiation_guess(self):
        from tools.build_viewer_service_catalog import decision
        for name in ('ExchangeCurrency','ExchangeGold','ExchangeCrypto'):
            path='Public.v1/'+name
            self.assertEqual(initial_service_role(path),('business','unknown','owner_confirmed'))
            self.assertEqual(source_catalog()['routes'][path]['role'],'business')
            self.assertEqual(decision(path,{})[:2],('business','unknown'))
            self.assertEqual(initial_service_role('Public.v99/'+name)[0],'unknown')

    def test_owner_background_homepage_calls_are_automatic_support(self):
        from tools.build_viewer_service_catalog import decision
        for name in ('Weather','AirPollution','CalendarToday','CalendarMonth','CalendarReligiousTimes'):
            path='Public.v1/'+name
            self.assertEqual(initial_service_role(path),('support','confirmed_automatic','owner_confirmed'))
            self.assertEqual(decision(path,{})[:2],('support','confirmed_automatic'))
        self.assertEqual(initial_service_role('Public.v1/ServiceIconUrls')[:2],('support','unknown'))
        self.assertEqual(initial_service_role('Public.v1/FutureService')[0],'unknown')

    def test_market_repeats_are_separate_executions_and_background_calls_are_not_anchors(self):
        paths=['Public.v1/'+name for name in ('ExchangeCurrency','ExchangeGold','ExchangeCrypto') for _ in range(2)]
        paths+=['Public.v1/'+name for name in ('Weather','AirPollution','CalendarToday','CalendarMonth','CalendarReligiousTimes')]
        rows=[log(i+1,'public_'+str(i),path+' Line:1','POST (G00000 | successful)') for i,path in enumerate(paths)]
        publish_capture(self.db,verified_file(self.root/'public.gz',rows),START,START+FIVE_NS)
        self.assertEqual(self.db.one("SELECT COUNT(*) AS n FROM viewer_semantic_occurrences WHERE state='active'")['n'],6)
        self.assertEqual(self.db.one('SELECT COUNT(*) AS n FROM viewer_requests')['n'],11)
        self.assertEqual(self.db.one("SELECT COUNT(*) AS n FROM viewer_actions WHERE category='support' AND initiation='confirmed_automatic'")['n'],5)
        self.assertEqual(self.db.one("SELECT COUNT(*) AS n FROM viewer_actions WHERE category='business' AND initiation='unknown'")['n'],6)

    def test_old_wrong_market_support_is_upgraded_atomically_without_raw_or_payment_changes(self):
        paths=['Public.v1/'+name for name in ('ExchangeCurrency','ExchangeGold','ExchangeCrypto')]
        rows=[log(i+1,'market_'+str(i),path+' Line:1','POST (G00000 | successful)') for i,path in enumerate(paths)]
        with patch('p24_foundation.viewer_data.initial_service_role',return_value=('support','unknown','source_backed')):
            publish_capture(self.db,verified_file(self.root/'market_old.gz',rows),START,START+FIVE_NS)
        self.db.sql("UPDATE viewer_service_catalog_state SET fingerprint='old_wrong_public_policy'");self.db.conn.commit()
        before=snapshot(self.db);self.db.sync_service_catalog();after=snapshot(self.db)
        for table in ('viewer_events','viewer_raw_events','viewer_requests','viewer_live_state',
                'viewer_contract_identifiers','viewer_contract_edges','viewer_contract_observations'):
            self.assertEqual(before[table],after[table],table)
        self.assertEqual(self.db.one("SELECT COUNT(*) AS n FROM viewer_actions WHERE category='business'")['n'],3)
        self.assertEqual(self.db.one("SELECT COUNT(*) AS n FROM viewer_semantic_occurrences WHERE state='active'")['n'],3)
        self.assertEqual(self.db.sync_service_catalog()['status'],'CURRENT')

    def test_registered_exact_versions_and_different_image_contracts(self):
        for path,role in [('Core.v2/DeviceRegister','support'),('Files.Download','support'),
            ('PaymentRedirect.PaymentRedirect','system'),('Services.v1/PostTrackingExtended','business'),
            ('Services.v1/TrafficFinesImages','support'),('Services.v2/TrafficFinesImages','business'),
            ('Services.v1/BankIbanInfoPrerequisites','support'),('Services.v3/ElectricBillsExport','business'),
            ('Proxy.GetCardOcrResult','support'),('Proxy.TechnicalExaminationCertificateCheckUserRegistrationStatus','support'),
            ('Core.v1/UserSurvey','support'),('Core.v1/UserWidgetsSetDefault','support')]:
            with self.subTest(path=path):self.assertEqual(initial_service_role(path)[0],role)
        for path in ('Services.v99/TrafficFinesImages','Services.v1/PostTrackingExtendedUnexpected','Core.v3/DeviceRegister','Public.v99/Weather'):
            self.assertEqual(initial_service_role(path)[0],'unknown')
        self.assertEqual(initial_service_role('Services.v1/GetUserData')[1],'confirmed_automatic')

    def test_every_source_proposal_has_references_without_confirmed_manual_claim(self):
        catalog=source_catalog()
        for row in catalog['routes'].values():
            self.assertNotEqual(row['initiation'],'confirmed_manual')
            if any('/Contracts/' in ref['file'] for ref in row['evidence']):
                self.assertNotIn(row['source_method'],(None,'Description'))
            for ref in row['evidence']:
                self.assertIn(ref['file'],catalog['source_files_sha256']);self.assertGreater(ref['line'],0)

    def test_sync_reclassifies_retained_actions_without_raw_or_cursor_rebuild(self):
        self.legacy();before=snapshot(self.db)
        key=self.db.lookup_request('old_0')['request_key'];old_anchor=self.db.one('SELECT * FROM viewer_semantic_occurrences WHERE request_key=?',(key,))
        with patch.object(self.db,'rebuild',side_effect=AssertionError('no full rebuild')),\
             patch.object(self.db,'rebuild_payment_contract',side_effect=AssertionError('no contract rebuild')),\
             patch.object(self.db,'build_semantic_index',side_effect=AssertionError('no full semantic bootstrap')):
            info=self.db.sync_service_catalog()
        self.assertEqual(info['status'],'UPDATED')
        after=snapshot(self.db)
        for table in ('viewer_events','viewer_raw_events','viewer_requests','viewer_live_state','viewer_live_receipts',
                      'viewer_contract_identifiers','viewer_contract_edges','viewer_contract_observations'):
            self.assertEqual(before[table],after[table],table)
        new_anchor=self.db.one('SELECT * FROM viewer_semantic_occurrences WHERE request_key=?',(key,))
        self.assertEqual(new_anchor['anchor_key'],old_anchor['anchor_key']);self.assertEqual(new_anchor['category'],'business')
        technical=self.db.lookup_request('old_1')['request_key']
        self.assertEqual(self.db.one('SELECT state FROM viewer_semantic_occurrences WHERE request_key=?',(technical,))['state'],'withdrawn')
        self.assertEqual(self.db.one('SELECT category FROM viewer_actions WHERE root_request_key=?',(self.db.lookup_request('old_3')['request_key'],))['category'],'support')

    def test_sync_faults_roll_back_roles_actions_heads_history_and_state(self):
        self.legacy();before=snapshot(self.db)
        for point in ('catalog_sync_after_roles','catalog_sync_after_actions','catalog_sync_after_semantics','catalog_sync_before_commit'):
            def fail(stage):
                if stage==point:raise RuntimeError('controlled_catalog_failure')
            with self.subTest(point=point),self.assertRaises(RuntimeError):self.db.sync_service_catalog(fault=fail)
            self.assertEqual(snapshot(self.db),before)

    def test_repeated_sync_creates_no_revisions_or_duplicate_history(self):
        self.legacy();self.db.sync_service_catalog();before=snapshot(self.db)
        self.assertEqual(self.db.sync_service_catalog()['status'],'CURRENT')
        self.assertEqual(snapshot(self.db),before)

    def test_explicit_operator_unknown_withdraws_all_behavior_views_and_survives_sync(self):
        self.legacy();self.db.sync_service_catalog()
        path='Services.v1/PostTrackingExtended';request=self.db.lookup_request('old_0');key=request['request_key']
        self.db.update_service_role(path,'unknown','unknown','owner requires further review')
        self.assertEqual(self.db.one('SELECT state FROM viewer_semantic_occurrences WHERE request_key=?',(key,))['state'],'withdrawn')
        self.db.sql("UPDATE viewer_service_catalog_state SET fingerprint='earlier'");self.db.conn.commit();self.db.sync_service_catalog()
        stored=self.db.one('SELECT * FROM viewer_service_roles WHERE service_path=?',(path,))
        self.assertEqual((stored['role'],stored['reviewed'],stored['source']),('unknown',1,'operator'))
        self.assertNotIn(key,{row['request_key'] for row in self.db.indexed_session_behavior(request['session_key'])['observed_occurrences']})
        self.assertNotIn(key,{row['anchor_request_key'] for row in self.db.session_behavior(request['session_key'])['observed_occurrences']})
        self.assertFalse(self.db.service_journey(key)['resolved_occurrences'])
        self.db.rebuild();self.db.build_semantic_index()
        self.assertEqual(self.db.one('SELECT state FROM viewer_semantic_occurrences WHERE request_key=?',(key,))['state'],'withdrawn')

    def test_operator_custom_role_is_preserved_and_sync_is_automatic_on_init(self):
        self.legacy();path='Core.v2/DeviceRegister'
        self.db.update_service_role(path,'user_management','confirmed_manual','reviewed by owner')
        key=self.db.lookup_request('old_3')['request_key'];self.db.init()
        self.assertEqual(self.db.one('SELECT category FROM viewer_actions WHERE root_request_key=?',(key,))['category'],'user_management')
        self.assertEqual(self.db.service_catalog_status()['status'],'CURRENT')

    def test_operator_source_is_protected_even_if_legacy_review_flag_is_zero(self):
        self.legacy();path='Services.v1/PostTrackingExtended'
        self.db.sql("UPDATE viewer_service_roles SET role='unknown',source='operator',reviewed=0 WHERE service_path=?",(path,));self.db.conn.commit()
        self.db.sync_service_catalog()
        stored=self.db.one('SELECT role,source,reviewed FROM viewer_service_roles WHERE service_path=?',(path,))
        self.assertEqual(stored,dict(role='unknown',source='operator',reviewed=0))
        key=self.db.lookup_request('old_0')['request_key']
        self.assertEqual(self.db.one('SELECT state FROM viewer_semantic_occurrences WHERE request_key=?',(key,))['state'],'withdrawn')

    def test_read_only_status_does_not_create_missing_catalog_state(self):
        self.db.sql('DROP TABLE viewer_service_catalog_state');self.db.conn.commit()
        self.db.sql('PRAGMA query_only=ON')
        self.assertEqual(self.db.service_catalog_status()['status'],'UPDATE_PENDING')
        self.assertIsNone(self.db.one("SELECT name FROM sqlite_master WHERE name='viewer_service_catalog_state'"))

    def test_management_page_shows_source_reason_without_writing_data(self):
        from p24_foundation.viewer_ui import create_viewer_app
        self.legacy();self.db.sync_service_catalog();before=snapshot(self.db)
        client=create_viewer_app(dict(sqlite_path=self.root/'db',keys_path=self.root/'keys')).test_client()
        response=client.get('/services?q=Core.v2/DeviceRegister')
        self.assertEqual(response.status_code,200)
        html=response.get_data(as_text=True)
        self.assertIn('مبنای پیشنهاد نقش',html);self.assertIn('مبتنی بر سورس',html);self.assertIn('ICore.cs',html)
        self.assertEqual(snapshot(self.db),before)
