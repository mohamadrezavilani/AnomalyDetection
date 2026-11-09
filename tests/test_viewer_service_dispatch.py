"""Dispatcher service intent is separate from HTTP transport and OTP attempts."""
import copy
import json
from pathlib import Path
import tempfile
import unittest

from p24_foundation.privacy import generate_keys
from p24_foundation.viewer_data import ViewerDB,token
from p24_foundation.service_dispatch import dispatch_facts
from p24_foundation.viewer_dispatch_sync import repair_captured_dispatches
from p24_foundation.viewer_online import initialize_live,bind_stream,publish_capture,FIVE_NS,SECOND_NS,iso
from p24_foundation.viewer_ui import create_viewer_app
from tests.test_viewer_online import START,verified_file,snapshot
from tests.test_viewer_r6_service_journey import log,sql

API='Services.v1/SocialSecurityInsuranceElectronicPrescription'
TRANSPORT='Services.v1/InvoiceRegister Line:17'


class ServiceDispatchTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup)
        self.root=Path(self.tmp.name);self.keys=self.root/'keys.json';generate_keys(self.keys)
        self.opts=dict(sqlite_path=self.root/'db.sqlite',keys_path=self.keys)
        self.db=ViewerDB(**self.opts);self.addCleanup(self.db.close)
        self.db.init();initialize_live(self.db);bind_stream(self.db,start_ns=START,stream_key='test')
        self.n=0

    def row(self,rid,call,message,*,session='a'*32):
        self.n+=1;return log(self.n,rid,call,message,session=session)

    def provider(self,rid,method,params=None,code='G00000',inp=None):
        return self.row(rid,'ClientAyanCoInquiry.'+method+' Line:1',
            'POST (G00000 | ok) Input:'+json.dumps(inp or {})+' Output:'+json.dumps([
              dict(Status=dict(Code=code),**({'Parameters':params} if params is not None else {}))]))

    def flow(self,rid,invoice,stage):
        rows=[self.row(rid,TRANSPORT,'POST (G00000 | successful)'),
              self.row(rid,'DBPath.a.ud_prc_userSessionHasAccess',sql('ud_prc_userSessionHasAccess',session='a'*32,action=API.split('.',1)[1])),
              self.row(rid,'DBPath.a.ud_prc_invoiceRequest',sql('ud_prc_invoiceRequest',serviceID=1517)),
              self.row(rid,'DBPath.a.ud_prc_invoiceExists',sql('ud_prc_invoiceExists',invoiceUniqueID=invoice))]
        rows.append(self.provider(rid,'MyGovRequestOtp',dict(OtpRequired=stage!='result')))
        if stage=='selection':
            rows.extend([self.provider(rid,'MyGovLogin',inp={'OtpCode':'98765','TraceNumber':invoice}),
                         self.provider(rid,'TaminUnderCoveredInquiry',dict(UnderCovered=[]))])
        if stage=='result':
            rows.extend([self.provider(rid,'ElectronicPrescriptionInquiry',dict(ElectronicPrescriptionInquiryDataList=[])),
                         self.row(rid,'DBPath.a.ud_prc_inquiryInvoiceResult2',sql('ud_prc_inquiryInvoiceResult2',invoiceUniqueID=invoice,statusCode='G00000'))])
        return rows

    def publish(self,rows,*,start=START,mode='forward',fault=None):
        rows=copy.deepcopy(rows)
        for i,row in enumerate(rows):row['@timestamp']=iso(start+(i+1)*SECOND_NS)
        p=verified_file(self.root/('capture'+str(len(list(self.root.glob('*.gz'))))+'.gz'),rows,start)
        return publish_capture(self.db,p,start,start+FIVE_NS,mode=mode,fault=fault)

    def test_three_attempts_one_completed_service_without_rewriting_transport_or_joining_invoices(self):
        self.publish(self.flow('otp','1'*32,'otp')+self.flow('selection','2'*32,'selection')+self.flow('final','3'*32,'result'))
        phases=[]
        for rid in ('otp','selection','final'):
            card=self.db.lookup_request(rid);phases.append(card['service_context']['phase'])
            self.assertEqual(card['root_call'],API)
            retained=self.db.one('SELECT root_call FROM viewer_requests WHERE request_key=?',(card['request_key'],))
            self.assertEqual(retained['root_call'],TRANSPORT)
            self.assertEqual(card['service_context']['cross_request_otp_link'],'NOT_ESTABLISHED')
        self.assertEqual(phases,['otp_required','selection_pending','inquiry_result_reported'])
        self.assertEqual(self.db.metrics()['requests'],3)
        self.assertEqual(self.db.one("SELECT COUNT(*) n FROM viewer_semantic_occurrences WHERE state='active'")['n'],1)
        sk=self.db.lookup_request('final')['session_key']
        self.assertEqual(len(self.db.session_behavior(sk)['observed_occurrences']),1)
        self.assertEqual(self.db.requests_page(service_path_filter=API)['total'],3)
        self.assertEqual(self.db.requests_page(service_path_filter=API,role='business')['total'],1)
        self.assertEqual(self.db.requests_page(service='ElectronicPrescription')['total'],3)
        role=self.db.one('SELECT role,initiation FROM viewer_service_roles WHERE service_path=?',('Services.v1/InvoiceRegister',))
        self.assertEqual(role,dict(role='support',initiation='confirmed_automatic'))
        catalog=self.db.service_roles(search='SocialSecurityInsuranceElectronicPrescription')['items']
        self.assertEqual(catalog[0]['requests'],3)
        self.assertEqual(self.db.service_journey(self.db.lookup_request('final')['request_key'])['observed_service_execution_count'],1)
        coverage=self.db.behavior_coverage()
        self.assertEqual(coverage['counts']['semantic_service_execution'],1)
        self.assertEqual(coverage['counts']['dispatcher_requests_with_selected_service'],3)

    def test_missing_access_or_invoice_request_or_unknown_service_never_promotes_transport(self):
        for variant in ('no_access','no_invoice_request','unknown'):
            rows=self.flow(variant,variant[0]*32,'result')
            if variant=='no_access':rows=[r for r in rows if not r['CallPath'].endswith('userSessionHasAccess')]
            elif variant=='no_invoice_request':rows=[r for r in rows if not r['CallPath'].endswith('invoiceRequest')]
            else:
                for r in rows:
                    if r['CallPath'].endswith('userSessionHasAccess'):r['message']=sql('ud_prc_userSessionHasAccess',action='v99/Unseen')
            self.publish(rows,start=START if variant=='no_access' else START+(1 if variant=='no_invoice_request' else 2)*FIVE_NS)
            self.assertEqual(self.db.lookup_request(variant)['root_call'],TRANSPORT)
        self.assertEqual(self.db.one("SELECT COUNT(*) n FROM viewer_semantic_occurrences WHERE state='active'")['n'],0)

    def test_ambiguous_dispatch_actions_are_unresolved(self):
        rows=self.flow('a','1'*32,'result')
        rows.append(self.row('a','DBPath.a.ud_prc_userSessionHasAccess',sql('ud_prc_userSessionHasAccess',action='v1/WaterBills')))
        self.publish(rows)
        self.assertIsNone(self.db.lookup_request('a').get('service_context'))

    def test_reviewed_unknown_inner_role_is_preserved_and_withdraws_same_anchor(self):
        self.publish(self.flow('a','1'*32,'result'))
        key=self.db.lookup_request('a')['request_key']
        anchor=self.db.one('SELECT anchor_key FROM viewer_semantic_occurrences WHERE request_key=?',(key,))['anchor_key']
        self.db.update_service_role(API,'unknown','unknown','owner review')
        card=self.db.lookup_request('a')
        self.assertEqual(card['service_context']['service_role'],'unknown')
        row=self.db.one('SELECT * FROM viewer_semantic_occurrences WHERE request_key=?',(key,))
        self.assertEqual(row['anchor_key'],anchor);self.assertEqual(row['state'],'withdrawn')
        self.assertEqual(self.db.one('SELECT category FROM viewer_actions WHERE action_key=?',(key,))['category'],'unknown')
        self.assertEqual(self.db.behavior_coverage()['counts'].get('semantic_service_execution',0),0)

    def test_unreviewed_unclassified_seed_can_use_existing_source_proposal_consistently(self):
        self.db.sql("INSERT INTO viewer_service_roles VALUES(?,'unknown','unknown','unclassified',0,'','old')",(API,));self.db.conn.commit()
        self.publish(self.flow('a','1'*32,'result'))
        key=self.db.lookup_request('a')['request_key']
        self.assertEqual(self.db.one('SELECT category FROM viewer_actions WHERE action_key=?',(key,))['category'],'business')
        self.assertEqual(self.db.one('SELECT role FROM viewer_service_roles WHERE service_path=?',(API,))['role'],'business')
        self.assertEqual(self.db.one('SELECT state FROM viewer_semantic_occurrences WHERE request_key=?',(key,))['state'],'active')

    def test_cross_request_origin_version_conflict_retracts_context(self):
        rows=self.flow('a','1'*32,'result');self.publish(rows)
        access=next(r for r in rows if r['CallPath'].endswith('userSessionHasAccess'))
        conflict=copy.deepcopy(access);conflict['RequestID']='outside';conflict['message']=sql('ud_prc_userSessionHasAccess',action='v1/GasBills')
        self.publish([conflict],start=START+FIVE_NS)
        card=self.db.lookup_request('a');self.assertTrue(card['conflicted'])
        self.assertIsNone(card.get('service_context'))
        self.assertEqual(self.db.one("SELECT COUNT(*) n FROM viewer_semantic_occurrences WHERE state='active'")['n'],0)

    def test_late_phase_change_keeps_anchor_cursor_and_incremental_full_parity(self):
        first=self.flow('a','1'*32,'otp');self.publish(first)
        key=self.db.lookup_request('a')['request_key'];before=self.db.one('SELECT next_ns FROM viewer_live_state')['next_ns']
        late=self.row('a','DBPath.a.ud_prc_inquiryInvoiceResult2',sql('ud_prc_inquiryInvoiceResult2',invoiceUniqueID='1'*32,statusCode='G00000'))
        self.publish([late],mode='manual_recheck')
        self.assertEqual(self.db.one('SELECT next_ns FROM viewer_live_state')['next_ns'],before)
        self.assertEqual(self.db.lookup_request('a')['service_context']['phase'],'inquiry_result_reported')
        initial=snapshot(self.db)
        self.publish([late],mode='manual_recheck')
        self.assertEqual(snapshot(self.db),initial)
        self.db.rebuild();self.db.rebuild_payment_contract();self.db.build_semantic_index()
        self.assertEqual(snapshot(self.db),initial)

    def test_context_actions_and_facts_rollback_with_publication(self):
        self.publish(self.flow('old','1'*32,'otp'));before=snapshot(self.db)
        def fail(stage):
            if stage=='after_relations':raise RuntimeError('controlled')
        with self.assertRaisesRegex(RuntimeError,'controlled'):
            self.publish(self.flow('new','2'*32,'result'),start=START+FIVE_NS,fault=fail)
        self.assertEqual(snapshot(self.db),before)
        self.assertIsNone(self.db.lookup_request('new'))

    def test_provider_fact_parser_is_exact_and_does_not_store_otp_or_pii(self):
        row=self.provider('a','MyGovLogin',inp={'OtpCode':'98765','MobileNumber':'09123456789'})
        facts=dispatch_facts(row)
        self.assertEqual(facts,[('service_dispatch.otp_validation','G00000','provider.Output.Status.Code')])
        self.assertNotIn('98765',json.dumps(facts))
        row['CallPath']='AnotherProvider.MyGovLogin';self.assertEqual(dispatch_facts(row),[])

    def test_duplicate_json_key_and_string_boolean_are_not_accepted_as_otp_requirement(self):
        row=self.provider('a','MyGovRequestOtp',dict(OtpRequired='true'))
        self.assertFalse(any(x[0].endswith('otp_required') for x in dispatch_facts(row)))
        row['message']='Output:{"Status":{"Code":"G00000"},"Parameters":{"OtpRequired":true,"OtpRequired":false}}'
        self.assertEqual(dispatch_facts(row),[])

    def test_duplicate_sql_action_is_not_selected_arbitrarily(self):
        row=self.row('a','DBPath.a.ud_prc_userSessionHasAccess',
            '(SQL Parameters: @action=v1/WaterBills @action=v1/GasBills)')
        self.assertEqual(dispatch_facts(row),[])

    def test_contradictory_otp_requirement_does_not_take_latest_timestamp(self):
        rows=self.flow('a','1'*32,'otp')
        rows.append(self.provider('a','MyGovRequestOtp',dict(OtpRequired=False)))
        self.publish(rows)
        c=self.db.lookup_request('a')['service_context']
        self.assertEqual(c['phase'],'prerequisite_conflict')
        self.assertEqual(c['otp_required_values'],['false','true'])
        self.assertEqual(self.db.one("SELECT COUNT(*) n FROM viewer_semantic_occurrences WHERE state='active'")['n'],0)

    def test_failed_otp_validation_does_not_claim_a_completed_inquiry(self):
        rows=self.flow('a','1'*32,'otp');rows.append(self.provider('a','MyGovLogin',code='GD2870'))
        self.publish(rows)
        c=self.db.lookup_request('a')['service_context']
        self.assertEqual(c['phase'],'otp_verification_failed')
        self.assertEqual(c['otp_validation_codes'],['GD2870'])
        self.assertEqual(self.db.one("SELECT COUNT(*) n FROM viewer_semantic_occurrences WHERE state='active'")['n'],0)

    def test_transport_failure_is_not_overwritten_by_successful_inquiry_report(self):
        rows=self.flow('a','1'*32,'result');rows[0]['message']='POST (GE4004 | failed)'
        self.publish(rows)
        card=self.db.lookup_request('a')
        self.assertEqual(card['root_code'],'GE4004')
        self.assertEqual(card['service_context']['inquiry_result_codes'],['G00000'])
        self.assertEqual(self.db.action(card['request_key'])['current_outcome'],'failure')

    def test_request_and_action_views_explain_transport_and_show_versioned_phase_proofs(self):
        self.publish(self.flow('a','1'*32,'result'));key=self.db.lookup_request('a')['request_key']
        with create_viewer_app(self.opts).test_client() as client:
            for path in ('/request/','/action/'):
                r=client.get(path+key);self.assertEqual(r.status_code,200)
                self.assertIn(b'id="service-dispatch-context"',r.data)
                self.assertIn(API.encode(),r.data)
                self.assertIn(b'Services.v1/InvoiceRegister',r.data)

    def test_bounded_repair_is_idempotent_preserves_cursor_and_can_rollback(self):
        self.publish(self.flow('a','1'*32,'result'));key=self.db.lookup_request('a')['request_key']
        self.db.sql("DELETE FROM viewer_contract_observations WHERE axis LIKE 'service_dispatch.%'")
        self.db.sql("UPDATE viewer_actions SET label='InvoiceRegister',name='InvoiceRegister',category='support'")
        self.db.reconcile_semantic_requests([key]);before=snapshot(self.db)
        cursor=self.db.one('SELECT next_ns,generation FROM viewer_live_state')
        def fail(stage):raise RuntimeError('controlled repair')
        with self.assertRaisesRegex(RuntimeError,'controlled repair'):
            repair_captured_dispatches(self.db,[key],fault=fail)
        self.assertEqual(snapshot(self.db),before)
        self.assertEqual(self.db.one('SELECT next_ns,generation FROM viewer_live_state'),cursor)
        result=repair_captured_dispatches(self.db,[key])
        self.assertEqual(result['status'],'UPDATED')
        self.assertEqual(result['checkpoint_after']['next_ns'],cursor['next_ns'])
        self.assertEqual(repair_captured_dispatches(self.db,[key])['status'],'NO_CHANGE')
        self.assertEqual(self.db.lookup_request('a')['service_context']['phase'],'inquiry_result_reported')

    def test_existing_correlation_upgrade_also_reconciles_dispatcher_semantics_atomically(self):
        from p24_foundation.viewer_correlation_sync import sync_payment_correlations
        from tests.test_viewer_payment_correlations import correlation
        rows=self.flow('a','1'*32,'result')
        rows.append(correlation(99,'a','InvoiceID-BillUniqueIDs',dict(InvoiceID='1'*32,BillUniqueIDs=[]),session='a'*32))
        self.publish(rows);key=self.db.lookup_request('a')['request_key']
        self.db.sql("DELETE FROM viewer_contract_observations WHERE axis LIKE 'service_dispatch.%'")
        self.db.sql("UPDATE viewer_actions SET label='InvoiceRegister',name='InvoiceRegister',category='support'")
        self.db.reconcile_semantic_requests([key])
        result=sync_payment_correlations(self.db,START)
        self.assertTrue(result['behavior_anchors_written'])
        self.assertEqual(self.db.one('SELECT state FROM viewer_semantic_occurrences WHERE request_key=?',(key,))['state'],'active')
        self.assertEqual(sync_payment_correlations(self.db,START)['status'],'NO_CHANGE')
