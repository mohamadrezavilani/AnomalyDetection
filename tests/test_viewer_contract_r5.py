"""R5 contract-oriented tests (synthetic). Does not certify the full 86-case specification."""
import gzip,json,tempfile,unittest
from pathlib import Path
from p24_foundation.privacy import generate_keys
from p24_foundation.viewer_data import ViewerDB
from p24_foundation.viewer_contract import canonical,typed_id,extract_identifiers,observed_states

K='ABCDEF0123456789ABCDEF0123456789'
T1='11111111111111111111111111111111'
T2='22222222222222222222222222222222'
B='33333333333333333333333333333333'

def row(i,request,call,message,session='11112222333344445555666677778888'):
    return dict(_source_id='logs-test-r5:'+str(i),**{'@timestamp':f'2026-10-24T04:18:{i:02d}Z'},
                RequestID=request,CallPath=call,message=message,Session=session,IP='192.0.2.1')

def sql(name,*args):
    return '(Command Text: '+name+')(Code: 1)(Result: Ok)(SQL Parameters: '+' '.join('@'+k+'='+str(v) for k,v in args)+')'

class R5ContractTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup)
        root=Path(self.tmp.name);self.root=root;key=root/'keys.json';generate_keys(key)
        self.db=ViewerDB(sqlite_path=root/'viewer.db',keys_path=key);self.addCleanup(self.db.close);self.db.init()
    def load(self,rows):
        path=self.root/'r5.json.gz'
        with gzip.open(path,'wt') as f:
            json.dump(dict(window_start='2026-10-24T04:15:00Z',window_end='2026-10-24T04:20:00Z',count=len(rows),logs=rows),f)
        self.assertEqual(self.db.ingest([path])[0]['status'],'IMPORTED')
        self.db.rebuild()
        return self.db.rebuild_payment_contract()

    def test_same_platform_object_separate_executions(self):
        rows=[row(1,'first','DBPath.pishkhan24.application.ud_prc_paymentGetInfo',sql('ud_prc_paymentGetInfo',('paymentKey',K))),
              row(2,'first','Core.v1/WalletPayment Line:1084','POST (G00000 | successful)'),
              row(3,'second','DBPath.pishkhan24.application.ud_prc_paymentGetInfo',sql('ud_prc_paymentGetInfo',('paymentKey',K))),
              row(4,'second','Core.v1/WalletPayment Line:1084','POST (GD9999 | failed)')]
        self.load(rows)
        objs=self.db.all("SELECT DISTINCT identity_key FROM viewer_contract_identifiers WHERE kind='internal_payment'")
        self.assertEqual(len(objs),1)
        edges=self.db.all("SELECT DISTINCT from_typed_id FROM viewer_contract_edges WHERE relation_type='execution_uses_payment_object'")
        self.assertEqual(len(edges),2)
        self.assertFalse(self.db.action(self.db.lookup_request('first')['request_key'])['payment_contract']['financial_confirmation']=='confirmed_per_approved_contract')

    def test_two_tokens_not_superseded_and_sessionless_webhook(self):
        rows=[row(1,'a','DBPath.pishkhan24.application.ud_prc_paymentServiceReportToken',sql('ud_prc_paymentServiceReportToken',('paymentKey',K),('token',T1))),
              row(2,'b','DBPath.pishkhan24.application.ud_prc_paymentServiceReportToken',sql('ud_prc_paymentServiceReportToken',('paymentKey',K),('token',T2))),
              row(3,'c','DBPath.pishkhan24.application.ud_prc_webhooksInformBillPaymentStatus_v1',sql('ud_prc_webhooksInformBillPaymentStatus_v1',('paymentKey',K),('billID','007'),('paymentID','001'),('description','پرداخت با موفقیت')),session='N/A')]
        self.load(rows)
        edges=self.db.all("SELECT to_typed_id FROM viewer_contract_edges WHERE relation_type='provider_binding'")
        self.assertEqual(len(edges),2)
        self.assertEqual(len({x['to_typed_id'] for x in edges}),2)
        r=self.db.lookup_request('c')['request_key']; card=self.db.payment_contract_card(r)
        self.assertIn('bill_item_notification',[x['axis'] for x in card['observations']])
        self.assertEqual(card['financial_confirmation'],'unverified')

    def test_provider_status_and_reversal_separate(self):
        message=('http://example (G00000 | successful)\nInput:[{"PaymentKey":"ext"}]\n'
                 'Output:[{"Parameters":{"Status":{"Name":"Paid"},"Gateway":{"Name":"MasterWallet_Ayan_Internal"}},"Status":{"Code":"G00000"}}]')
        result=self.load([row(1,'r1','ClientAyanCoTopUp.PaymentInfo Line:68',message),row(2,'r2','Core.v1/RequestPurchaseReverse Line:1','POST (G00000 | successful)')])
        self.assertGreater(result['observations'],0)
        a=self.db.payment_contract_card(self.db.lookup_request('r1')['request_key'])
        self.assertIn(('provider_financial_observation','Paid'),[(x['axis'],x['value']) for x in a['observations']])
        self.assertEqual(a['financial_confirmation'],'unverified')
        r=self.db.payment_contract_card(self.db.lookup_request('r2')['request_key'])
        self.assertEqual(r['observations'][0]['axis'],'compensation_process_observed')

    def test_opaque_case_and_bill_pairs_and_no_fuzzy_ids(self):
        self.assertNotEqual(canonical('ABCDEF0123456789ABCDEF0123456789'),canonical('abcdef0123456789abcdef0123456789'))
        self.assertEqual(canonical('ABCDABCD-1111-2222-3333-ABCDEFABCDEF'),'abcdabcd111122223333abcdefabcdef')
        self.assertNotEqual(typed_id('gateway','external_paymentkey','x'),typed_id('topup','external_paymentkey','x'))
        self.assertNotEqual(typed_id('platform','invoice','x'),typed_id('gateway','external_purchasekey','x'))
        raw=dict(CallPath='DBPath.pishkhan24.application.ud_prc_webhooksInformBillPaymentStatus_v1',message=sql('ud_prc_webhooksInformBillPaymentStatus_v1',('billID','00012'),('paymentID','00011')))
        self.assertEqual([x[-1] for x in extract_identifiers(raw) if x[1]=='natural_bill_pair'],['00012|00011'])
        self.assertNotIn('financial',str(observed_states(raw)))

    def test_multiple_bills_dont_cross_product_and_unsupported_status_not_success(self):
        message=('http://example (G00000 | successful)\nOutput:[{"Parameters":{"Bills":'
                '[{"BillID":"x","PaymentID":"p","Paid":true},'
                '{"BillID":"y","PaymentID":"q","Paid":false}]},"Status":{"Code":"G00000"}}]')
        states=observed_states(dict(CallPath='ClientAyanCoPaymentGateway.GetPaymentInfo Line:54',message=message))
        self.assertEqual([v for axis,v,path in states if axis=='provider_bill_item_report'],['Paid','Unpaid'])
        self.assertNotIn('confirmed',str(states))

if __name__=='__main__':unittest.main()

class R5CaptureTests(unittest.TestCase):
    def test_timezone_precision_projection_vs_material_change(self):
        from p24_foundation.viewer_capture import compatible_capture
        a={'@timestamp':'2026-10-24T04:15:20.1234567Z', 'RequestID':'r',
           'CallPath':'Core.v1/WalletPayment Line:1084','message':'G00000',
           '_es_export_meta':{'page':1},'Counter':42}
        b={'@timestamp':'2026-10-24T07:45:20.123+03:30','RequestID':'r',
           'CallPath':a['CallPath'],'message':'G00000','_source_id':'same:doc'}
        self.assertTrue(compatible_capture(a,b))
        self.assertFalse(compatible_capture(a,dict(b,message='GD0000')))
        self.assertFalse(compatible_capture(a,dict(b,CallPath='Core.v1/BillsPayment Line:1')))
        self.assertFalse(compatible_capture(a,dict(b,**{'@timestamp':'2026-10-24T07:45:21+03:30'})))

    def test_replay_compatible_capture_preserves_raw_and_does_not_conflict(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);key=root/'keys.json';generate_keys(key)
            with ViewerDB(sqlite_path=root/'x.db',keys_path=key) as d:
                d.init()
                base=row(1,'r','Core.v1/WalletPayment Line:1','POST (G00000 | successful)')
                replica={k:v for k,v in base.items() if k not in ('IP','level')}
                replica['@timestamp']='2026-10-24T07:48:01+03:30'
                # same UTC instant as synthetic row(1) = 04:18:01Z
                replica['@timestamp']='2026-10-24T07:48:01.0+03:30'
                paths=[]
                for n,rows in enumerate(([base],[replica])):
                    path=root/(str(n)+'.json.gz');paths.append(path)
                    with gzip.open(path,'wt') as f:json.dump(dict(window_start='2026-10-24T04:15:00Z',window_end='2026-10-24T04:20:00Z',count=1,logs=rows),f)
                result=d.ingest(paths)
                self.assertEqual(result[0]['new_events'],1)
                self.assertEqual(result[1]['duplicates'],1)
                self.assertEqual(result[1]['conflicts'],0)
                self.assertEqual(d.one('SELECT COUNT(*) AS n FROM viewer_capture_projections')['n'],1)
                self.assertEqual(d.rebuild()['requests'],1)

class R5ServiceBoundaryTests(unittest.TestCase):
    def test_nested_status_not_replaced_by_transport_success(self):
        raw={'CallPath':'ClientAyanCoPaymentGateway.PaymentInquiry Line:7',
             'message':'http://x (G00000 | successful)\nInput:[{"BillID":"123","PaymentID":"456"}]\nOutput:[{"Parameters":null,"Status":{"Code":"GE4004","Description":"not paid here"}}]'}
        self.assertIn(('provider_response_code','GE4004','provider.Output.Status.Code'),observed_states(raw))
        self.assertNotIn('Paid',str(observed_states(raw)))

    def test_provider_purchase_webhook_report_separate_from_financial(self):
        call='DBPath.pishkhan24.application.ud_prc_webhooksInformPurchaseStatus'
        raw={'CallPath':call,'message':sql('ud_prc_webhooksInformPurchaseStatus',
             ('invoiceUniqueID','INV-1'),('externalPurchaseKey','RES-1'),('paymentKey','K-1'),('status','Finalized'))}
        self.assertIn(('fulfillment_report','Finalized','sql.purchaseWebhook.status'),observed_states(raw))
        # R6.2 Core review: same SQL procedure can be used by CarAnnualTax.
        # Keep the opaque external reference until a family bridge is proven.
        self.assertEqual(len([v for v in extract_identifiers(raw) if v[1]=='external_reference_unresolved']),1)
        self.assertFalse(any(v[1]=='product_reservation' for v in extract_identifiers(raw)))
        self.assertNotIn('financial_confirmation',str(observed_states(raw)))

    def test_wallet_reporting_procedure_cannot_prove_debit(self):
        raw={'CallPath':'DBPath.pishkhan24.application.ud_prc_walletPaymentReportRequest',
             'message':sql('ud_prc_walletPaymentReportRequest',('paymentKey','k'),('session','session'))}
        self.assertEqual(observed_states(raw),[])
        self.assertEqual([x[1] for x in extract_identifiers(raw)],['internal_payment'])

    def test_no_universal_purchase_key_alias(self):
        a=typed_id('topup','product_reservation','pkey')
        b=typed_id('payment_gateway','external_purchasekey','pkey')
        c=typed_id('pishkhan24','invoice','pkey')
        self.assertEqual(len({a,b,c}),3)

    def test_legacy_code_and_snapshot_capture_has_no_auth_token_as_key(self):
        raw={'CallPath':'CacheCoreApi.HandleRequest Line:56','message':
             'https://cachecore/api/Cache/Get (G00000 | successful)\nInput:[{"Identity":{"Token":"SENSITIVE"},"Parameters":{"CacheKey":"C-1"}}]'}
        self.assertEqual(extract_identifiers(raw),[])

    def test_missing_or_unscoped_bill_item_not_financially_confirmed(self):
        r={'CallPath':'DBPath.pishkhan24.application.ud_prc_webhooksInformBillPaymentStatus_v2',
           'message':sql('ud_prc_webhooksInformBillPaymentStatus_v2',('paymentKey','K'),('bills',''))}
        self.assertEqual(len([x for x in extract_identifiers(r) if x[1]=='natural_bill_pair']),0)
        self.assertIn(('webhook_received_item_scope_unknown','reported_unknown','sql.logged_bills_incomplete'),observed_states(r))

class R5GraphTests(unittest.TestCase):
    def test_topup_order_notification_links_payment_to_reservation_without_bank_finality(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);key=root/'k.json';generate_keys(key)
            rows=[
              row(1,'purchase','DBPath.pishkhan24.application.ud_prc_invoiceRegister',
                  sql('ud_prc_invoiceRegister',('invoiceUniqueID','I-1'),('externalPurchaseKey','R-1'))),
              row(2,'notify','DBPath.pishkhan24.application.ud_prc_webhooksInformPurchaseStatus',
                  sql('ud_prc_webhooksInformPurchaseStatus',('invoiceUniqueID','I-1'),('externalPurchaseKey','R-1'),('paymentKey','K-1'),('status','Finalized')),session='N/A'),
              row(3,'notify','Webhook.v1/InformPurchaseStatus Line:79','POST (G00000 | successful)',session='N/A'),
            ]
            path=root/'events.json.gz'
            with gzip.open(path,'wt') as f:json.dump(dict(window_start='2026-10-24T04:15:00Z',window_end='2026-10-24T04:20:00Z',count=len(rows),logs=rows),f)
            with ViewerDB(sqlite_path=root/'v.db',keys_path=key) as db:
                db.init();db.ingest([path]);db.rebuild();db.rebuild_payment_contract()
                notif=db.payment_contract_card(db.lookup_request('notify')['request_key'])
                self.assertIn('purchase_status_notification',[x['relation_type'] for x in notif['edges']])
                self.assertEqual(notif['financial_confirmation'],'unverified')
                self.assertIn('Finalized',[x['value'] for x in notif['observations']])
                self.assertIn('same_invoice',[x['relation_type'] for x in notif['edges']])
                self.assertEqual(len(notif['related_requests']),1)
                purchase=db.payment_contract_card(db.lookup_request('purchase')['request_key'])
                self.assertEqual(len(purchase['related_requests']),1)
