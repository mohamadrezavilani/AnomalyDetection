"""R5 payment relationship projection: typed, sourced, deliberately conservative.

This is a *read model*, not a bank ledger or a payment executor. No inferred
settlement/finality and no cross-transaction joins based on IP, time, target,
amount or Session. The provenance of every occurrence is preserved.
"""
from __future__ import annotations
import hashlib
import json
import re
import time
from contextlib import contextmanager
from collections import defaultdict
from .parser import sql_parameters
from .viewer_projection_writes import CONTRACT_TABLES
from .payment_correlation import correlation_facts
from .service_dispatch import dispatch_facts

RULE_VERSION = 'p24-contract-R9-service-dispatch-otp-20261028'
CONTRACT_PATTERNS=(
    '%payment%', '%Payment%', '%invoice%', '%Invoice%', '%basket%', '%Basket%',
    '%ewano%', '%Ewano%', '%TopUp%', '%Purchase%', '%Reverse%', '%Return%', '%CacheCoreApi%', '%Webhook%',
    '%userSessionHasAccess%','%MyGovRequestOtp%','%MyGovLogin%','%TaminUnderCoveredInquiry%',
)
_UUID = re.compile(r'^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$')
_ALLOWED = re.compile(r'^[\w.|-]{1,160}$', re.ASCII)

# The issuer and kind are inseparable from the literal field name. In particular
# a payment ID of a *bill item* is not the PaymentID of a *provider payment*.
SQL_IDENTIFIERS = {
    'invoiceuniqueid': ('pishkhan24', 'invoice', 'sql.invoiceUniqueID'),
    'invoicesettlementkey': ('pishkhan24', 'invoice_settlement', 'sql.invoiceSettlementKey'),
    'invoicesettlementuniqueid': ('pishkhan24', 'invoice_settlement', 'sql.invoiceSettlementUniqueID'),
    'paymentkey': ('pishkhan24', 'internal_payment', 'sql.paymentKey'),
    'basketid': ('pishkhan24', 'basket', 'sql.basketID'),
    'paymentrequestid': ('pishkhan24', 'basket_payment_group', 'sql.paymentRequestID'),
    'queryuniqueid': ('pishkhan24', 'saved_query', 'sql.queryUniqueID'),
    # SQL invoiceRegister and purchase-status procedures serve multiple families
    # (including CarAnnualTax). A bare externalPurchaseKey is NOT a TopUp reservation.
    'externalpurchasekey': ('pishkhan24', 'external_reference_unresolved', 'sql.externalPurchaseKey'),
}
# SQL names for this evidence are precise; generic parameters with the same
# spelling are not automatically promoted into typed identifiers.
SQL_ITEM_NAMES = ('ud_prc_billsBelongs', 'ud_prc_BillsReview2', 'ud_prc_billsExists')


def canonical(value):
    if value is None or isinstance(value, bool): return None
    s = str(value).strip()
    if not s or s in ('N/A', 'null', 'None', '0') or not _ALLOWED.fullmatch(s): return None
    if _UUID.fullmatch(s): return s.replace('-', '').lower()
    return s


def typed_id(issuer, kind, value, *, scope=''):
    value = canonical(value)
    if value is None: return None
    return 'r5:' + hashlib.sha256(json.dumps([issuer, kind, scope, value], separators=(',', ':'), ensure_ascii=True).encode()).hexdigest()


def decode_block(message, label):
    if not isinstance(message,str) or label not in message:return None
    try:return json.JSONDecoder().raw_decode(message.split(label,1)[1].lstrip())[0]
    except (ValueError, TypeError):return None


def dict_first(data):
    if isinstance(data,list):return next((v for v in data if isinstance(v,dict)),{})
    return data if isinstance(data,dict) else {}


def parameter_result(output):
    d=dict_first(output)
    return d.get('Parameters') if isinstance(d.get('Parameters'),dict) else {}


def observed_states(raw):
    """Return source-scoped observations only, never financial finality."""
    call=str(raw.get('CallPath') or ''); msg=raw.get('message') or ''
    if not isinstance(msg,str):return []
    facts=correlation_facts(raw)
    result=(list(facts['states']) if facts else [])+dispatch_facts(raw)
    if 'Output:' in msg and call.startswith('Client'):
        outer=dict_first(decode_block(msg,'Output:'))
        stat=outer.get('Status')
        if isinstance(stat,dict) and isinstance(stat.get('Code'),str):
            result.append(('provider_response_code',stat['Code'],'provider.Output.Status.Code'))
    if 'ud_prc_webhooksInformPurchaseStatus' in call:
        try:
            p,_=sql_parameters(msg)
            val=p.get('status') or p.get('statusname') or p.get('orderstatus')
            if val:result.append(('fulfillment_report',val,'sql.purchaseWebhook.status'))
        except (ValueError,TypeError):pass
    if 'GetPurchaseInfo' in call and call.startswith('ClientAyanCoPaymentGateway.'):
        params=parameter_result(decode_block(msg,'Output:'))
        status=params.get('StatusName')
        if isinstance(status,str) and status:
            result.append(('provider_purchase_financial_observation',status,'provider.Parameters.StatusName'))
    if 'PaymentInfo' in call and ('ClientAyanCoTopUp.' in call or 'ClientAyanCoPaymentGateway.' in call):
        params=parameter_result(decode_block(msg,'Output:'))
        status=params.get('Status')
        if isinstance(status,dict) and isinstance(status.get('Name'),str):
            result.append(('provider_financial_observation',status['Name'], 'provider.Parameters.Status.Name'))
        if isinstance(params.get('Bills'),list):
            for n,b in enumerate(params['Bills']):
                if isinstance(b,dict) and isinstance(b.get('Paid'),bool):
                    if canonical(b.get('BillID')) and canonical(b.get('PaymentID')):
                        result.append(('provider_bill_item_report', 'Paid' if b['Paid'] else 'Unpaid',f'provider.Parameters.Bills[{n}].Paid'))
    if 'ud_prc_walletPaymentReportResult' in call:
        try:
            p,_=sql_parameters(msg)
            if p.get('statusname'):
                result.append(('platform_reported_result',p['statusname'],'sql.statusName'))
        except Exception:pass
    if 'ud_prc_webhooksInformBillPaymentStatus_v1' in call:
        try:
            p,_=sql_parameters(msg)
            if canonical(p.get('billid')) and canonical(p.get('paymentid')):
                result.append(('bill_item_notification', 'success_reported' if 'پرداخت با موفقیت' in str(p.get('description','')) else 'reported_unknown', 'sql.billID+paymentID+description'))
        except Exception:pass
    if 'ud_prc_webhooksInformBillPaymentStatus_v2' in call or 'ud_prc_webhooksInformBillPaymentStatus_v3' in call:
        result.append(('webhook_received_item_scope_unknown','reported_unknown','sql.logged_bills_incomplete'))
    if 'ud_prc_webhooksInformPurchaseStatus' in call or 'Webhook.v1/InformPurchaseStatus' in call:
        result.append(('purchase_notification','received','webhook.purchase'))
    if 'TopUpPurchaseInfo' in call or 'TopUpPurchaseInfo' in msg:
        params=parameter_result(decode_block(msg,'Output:'))
        status=params.get('Status')
        if isinstance(status,dict) and isinstance(status.get('Name'),str):
            result.append(('fulfillment_report',status['Name'],'provider.Parameters.Status.Name'))
    if 'ud_prc_paymentServiceReportStatus' in call:
        try:
            p,_=sql_parameters(msg)
            if p.get('status'):result.append(('internal_payment_stage_report',p['status'],'sql.status'))
        except Exception:pass
    if 'RequestPurchaseReverse' in call or 'JobPaymentReturn' in call:
        result.append(('compensation_process_observed','requested_or_processed','execution_callpath'))
    # Outer transport outcome is already stored in viewer_events.code. It is
    # explicitly NOT merged with nested business/financial status.
    return result


def extract_identifiers(raw):
    """Yield (issuer, kind, scope, field path, raw value). No fuzzy key search."""
    call=str(raw.get('CallPath') or '');msg=raw.get('message') or ''
    if not isinstance(msg,str):return []
    facts=correlation_facts(raw)
    found=list(facts['identifiers']) if facts else []
    for axis,value,path in dispatch_facts(raw):
        if axis=='service_dispatch.access':
            found.append(('pishkhan24','dispatcher_service',value,'sql.action.name',value.rsplit('/',1)[-1]))
    if call.startswith('DBPath.') and '(SQL Parameters:' in msg:
        try:p,_=sql_parameters(msg)
        except Exception:p={}
        for key,(issuer,kind,path) in SQL_IDENTIFIERS.items():
            v=canonical(p.get(key))
            # InvoiceSettlementKey only belongs to invoice settlement calls.
            if kind=='invoice_settlement' and not ('invoiceSettlement' in call or
                 (key=='invoicesettlementuniqueid' and 'ud_prc_inquiryInvoiceResult2' in call)):continue
            if key=='externalpurchasekey' and not any(c in call for c in ('invoiceRegister','webhooksInformPurchaseStatus')):continue
            if v:found.append((issuer,kind,'',path,v))
        if any(name in call for name in SQL_ITEM_NAMES):
            text=p.get('bills') or ''
            for val in re.findall(r'(?<![0-9a-fA-F])[0-9a-fA-F]{8}-[0-9a-fA-F-]{24,30}(?![0-9a-fA-F])|(?<![0-9a-fA-F])[0-9a-fA-F]{32}(?![0-9a-fA-F])',text):
                v=canonical(val)
                if v:found.append(('pishkhan24','snapshot_item','untyped_sql_bills','sql.bills[*]',v))
        # An explicit, same-row bridge between internal and external keys.
        if 'ud_prc_paymentServiceReportToken' in call:
            internal=canonical(p.get('paymentkey'));external=canonical(p.get('token'))
            if internal and external:
                found.append(('payment_provider','external_payment_or_purchase','report_token','sql.token',external))
        if 'ud_prc_webhooksInformBillPaymentStatus_v1' in call:
            bid=canonical(p.get('billid'));pid=canonical(p.get('paymentid'))
            if bid and pid:found.append(('bill_issuer','natural_bill_pair','v1.webhook','sql.billID+paymentID',bid+'|'+pid))
    if call.startswith('Client') and 'Input:' in msg:
        inp=dict_first(decode_block(msg,'Input:'));out=parameter_result(decode_block(msg,'Output:'))
        for key in ('PaymentKey','PurchaseKey'):
            if canonical(out.get(key)):
                iss='topup' if 'TopUp' in call else 'payment_gateway' if 'PaymentGateway' in call else 'provider'
                kind='product_reservation' if key=='PurchaseKey' and 'ProductReserve' in call and 'ClientAyanCoTopUp' in call else 'external_'+key.lower()
                scope='topup.ProductReserve' if kind=='product_reservation' else call.split(' Line:')[0]
                found.append((iss,kind,scope,'provider.Output.Parameters.'+key,canonical(out[key])))
        if 'UniqueKeyPurchase' in out:
            v=canonical(out.get('UniqueKeyPurchase'))
            if v and 'ClientAyanCoTopUp.PaymentInfo' in call:
                found.append(('topup','product_reservation','topup.ProductReserve','provider.Output.Parameters.UniqueKeyPurchase',v))
        if 'PaymentDirectByMasterWallet' in call:
            # This is a Provider rail, *not* proof of debiting customer wallet.
            pass
        if 'ReportNewPayment' in call or 'ReportNewPurchase' in call or 'ReportNewMasterCardBillPayment' in call:
            for key in ('TraceNumber','ExtraInfo'):
                v=canonical(inp.get(key))
                if v:found.append(('pishkhan24','internal_payment_candidate',call.split(' Line:')[0],'provider.Input.'+key,v))
        if 'PaymentInfo' in call:
            val=canonical(inp.get('PaymentKey'))
            if val:found.append(('provider','input_payment_key',call.split(' Line:')[0],'provider.Input.PaymentKey',val))
    return list(dict.fromkeys(found))


class PaymentContractMixin:
    def init_payment_contract(self):
        self.sql('''CREATE TABLE IF NOT EXISTS viewer_contract_identifiers(
          origin_key TEXT NOT NULL,version_key TEXT NOT NULL,request_key TEXT NOT NULL,
          issuer TEXT NOT NULL,kind TEXT NOT NULL,scope TEXT NOT NULL,field_path TEXT NOT NULL,
          identity_key TEXT NOT NULL,raw_value TEXT NOT NULL,
          PRIMARY KEY(origin_key,version_key,issuer,kind,scope,field_path,identity_key))''')
        self.sql('''CREATE TABLE IF NOT EXISTS viewer_contract_observations(
          origin_key TEXT NOT NULL,version_key TEXT NOT NULL,request_key TEXT NOT NULL,
          at_ns BIGINT,callpath TEXT NOT NULL,axis TEXT NOT NULL,value TEXT NOT NULL,
          field_path TEXT NOT NULL,authority TEXT NOT NULL DEFAULT 'reported',
          PRIMARY KEY(origin_key,version_key,axis,value,field_path))''')
        self.sql('''CREATE TABLE IF NOT EXISTS viewer_contract_edges(
          edge_key TEXT PRIMARY KEY,relation_type TEXT NOT NULL,from_typed_id TEXT NOT NULL,
          to_typed_id TEXT NOT NULL,scope TEXT NOT NULL,evidence_origin TEXT NOT NULL,
          evidence_version TEXT NOT NULL,evidence_path TEXT NOT NULL,request_key TEXT,
          eligibility TEXT NOT NULL,rule_version TEXT NOT NULL,confidence TEXT NOT NULL,
          observed_ns BIGINT)''')
        for q in (
          'CREATE INDEX IF NOT EXISTS vci_identity ON viewer_contract_identifiers(identity_key,kind)',
          'CREATE INDEX IF NOT EXISTS vci_req ON viewer_contract_identifiers(request_key)',
          'CREATE INDEX IF NOT EXISTS vco_req ON viewer_contract_observations(request_key)',
          'CREATE INDEX IF NOT EXISTS vce_from ON viewer_contract_edges(from_typed_id)',
          'CREATE INDEX IF NOT EXISTS vce_to ON viewer_contract_edges(to_typed_id)',
          'CREATE INDEX IF NOT EXISTS vce_req ON viewer_contract_edges(request_key)',
        ):self.sql(q)
        self.conn.commit()

    def _contract_read_query(self,*,scoped=False,payload=True,reuse_projection_events=False):
        if reuse_projection_events and not scoped:raise ValueError('contract_event_scope_requires_requests')
        scope=' AND e.request_key IN (SELECT request_key FROM viewer_projection_scope)' if scoped else ''
        clean=self._single_version_origin_sql('e',indexed=scoped and not self.sqlite)
        query='SELECT e.origin_key,e.version_key,e.request_key,e.at_ns,e.callpath'
        if payload:query+=',b.payload'
        if reuse_projection_events:
            query+=' FROM viewer_projection_events e'
        elif scoped and not self.sqlite:
            query+=''' FROM viewer_projection_scope s CROSS JOIN LATERAL
                (SELECT source.* FROM viewer_events source WHERE source.request_key=s.request_key OFFSET 0) e'''
        else:query+=' FROM viewer_events e'
        if payload:query+=' JOIN viewer_raw_events b USING(origin_key,version_key)'
        query+=' WHERE e.request_key IS NOT NULL'+scope+' AND '+clean+' AND ('+ ' OR '.join('e.callpath LIKE ?' for _ in CONTRACT_PATTERNS)+')'
        if payload:query+=' ORDER BY e.origin_key,e.version_key'
        elif scoped and not self.sqlite:
            query+=' AND (SELECT COUNT(*) FROM viewer_raw_events b WHERE b.origin_key=e.origin_key AND b.version_key=e.version_key)=1'
        else:query+=' AND EXISTS(SELECT 1 FROM viewer_raw_events b WHERE b.origin_key=e.origin_key AND b.version_key=e.version_key)'
        return query

    def init_contract_candidate_scope(self):
        self.sql('''CREATE TEMP TABLE IF NOT EXISTS viewer_contract_candidate_scope(
            origin_key TEXT NOT NULL,version_key TEXT NOT NULL,request_key TEXT NOT NULL,
            at_ns BIGINT,callpath TEXT NOT NULL,PRIMARY KEY(origin_key,version_key))''')

    @contextmanager
    def contract_event_batches(self,*,scoped=False,timings=None,prepared_scope=False,reuse_projection_events=False):
        """Stream all history, or fetch bodies only for bounded scoped keys.

        Scoped cursor planning must not walk/sort the global raw-body join
        for each FETCH. Materialize only matching metadata, then retrieve at
        most 400 exact origin/version bodies through their primary key.
        This reader changes only connection-local temporary tables.
        """
        timings=timings if timings is not None else {}
        timings.update(metadata_seconds=0.0,fetch_seconds=0.0)
        began=time.monotonic();params=CONTRACT_PATTERNS
        native=not self.sqlite and callable(getattr(self.conn,'pipeline',None))
        if scoped:
            self.progress('contract_select_candidates',scope='incremental')
            if not prepared_scope:self.init_contract_candidate_scope()
            self.sql(('TRUNCATE TABLE ' if native and not prepared_scope else 'DELETE FROM ')+'viewer_contract_candidate_scope')
            if native:self.sql('ANALYZE viewer_projection_scope')
            self.sql('INSERT INTO viewer_contract_candidate_scope '+self._contract_read_query(
                scoped=True,payload=False,reuse_projection_events=reuse_projection_events),params)
            timings['candidate_events']=self.one('SELECT COUNT(*) AS n FROM viewer_contract_candidate_scope')['n']
            query='SELECT * FROM viewer_contract_candidate_scope ORDER BY origin_key,version_key';params=()
        else:query=self._contract_read_query()
        if native:
            import uuid
            if scoped:self.sql('SET LOCAL cursor_tuple_fraction=1.0')
            cursor=self.conn.cursor(name='viewer_contract_'+uuid.uuid4().hex)
            cursor.execute(query.replace('?',self.param),params)
        else:cursor=self.sql(query,params)
        timings['metadata_seconds']=time.monotonic()-began
        def batches():
            while True:
                began=time.monotonic();batch=[dict(item) for item in cursor.fetchmany(400)]
                if not batch:return
                if scoped:
                    pairs=[(row['origin_key'],row['version_key']) for row in batch]
                    if native:
                        # Keep every raw-body lookup parameterized by one
                        # unique primary-key pair; OFFSET 0 prevents pulling
                        # the lateral subquery into a global raw-table join.
                        query=('''SELECT k.origin_key,k.version_key,body.payload FROM (VALUES '''+
                            ','.join('(?,?)' for _ in pairs)+''') AS k(origin_key,version_key)
                            CROSS JOIN LATERAL (SELECT r.payload FROM viewer_raw_events r
                              WHERE r.origin_key=k.origin_key AND r.version_key=k.version_key OFFSET 0) body''')
                    else:
                        where=' OR '.join('(origin_key=? AND version_key=?)' for _ in pairs)
                        query='SELECT origin_key,version_key,payload FROM viewer_raw_events WHERE '+where
                    bodies={(row['origin_key'],row['version_key']):row['payload'] for row in self.all(
                        query,[value for pair in pairs for value in pair])}
                    for row in batch:row['payload']=bodies[(row['origin_key'],row['version_key'])]
                timings['fetch_seconds']+=time.monotonic()-began
                yield batch
        try:yield batches()
        finally:cursor.close()

    def rebuild_payment_contract(self, *, max_events=None, request_keys=None, commit=True,reuse_projection_events=False):
        if reuse_projection_events and (request_keys is None or commit):
            raise ValueError('contract_event_reuse_requires_atomic_scoped_publication')
        if request_keys is None or getattr(self,'_legacy_projection_writes',False):
            return self._rebuild_payment_contract(max_events=max_events,request_keys=request_keys,commit=commit,
                reuse_projection_events=reuse_projection_events)
        if commit:self.init_payment_contract()
        self.write_lock()
        with self.finalized_projection(CONTRACT_TABLES):
            result=self._rebuild_payment_contract(max_events=max_events,request_keys=request_keys,commit=False,
                reuse_projection_events=reuse_projection_events)
        if commit:self.conn.commit()
        return result

    def _rebuild_payment_contract(self, *, max_events=None, request_keys=None, commit=True,reuse_projection_events=False):
        """Recreate only derived R5 projections from DB-resident raw evidence.

        Must be invoked only on the isolated p24_design_* DB. Processing is
        bounded by max_events for tests, not for final production projection.
        """
        if commit:self.init_payment_contract()
        self.write_lock()
        scoped=request_keys is not None
        for table in ('viewer_contract_edges','viewer_contract_observations','viewer_contract_identifiers'):
            self.sql('DELETE FROM '+table+(' WHERE request_key IN (SELECT request_key FROM viewer_projection_scope)' if scoped else ''))
        import zlib
        scanned=identifiers=observations=edges=0
        timings={};process_seconds=0.0
        with self.contract_event_batches(scoped=scoped,timings=timings,
                reuse_projection_events=reuse_projection_events) as batches:
            self.progress('contract_build',processed=0,total=timings.get('candidate_events'),
                          metadata_seconds=round(timings['metadata_seconds'],3))
            for batch in batches:
                began=time.monotonic()
                with self.bulk_writes():
                    for item in batch:
                        if max_events is not None and scanned>=max_events:break
                        e=dict(item);scanned+=1
                        try:raw=json.loads(zlib.decompress(bytes(e['payload'])).decode())
                        except (ValueError,TypeError,zlib.error):continue
                        occ=extract_identifiers(raw)
                        for issuer,kind,scope,path,value in occ:
                            key=typed_id(issuer,kind,value,scope=scope)
                            if not key:continue
                            self.sql('''INSERT INTO viewer_contract_identifiers VALUES(?,?,?,?,?,?,?,?,?) ON CONFLICT DO NOTHING''',
                               (e['origin_key'],e['version_key'],e['request_key'],issuer,kind,scope,path,key,value))
                            identifiers+=1
                            # Directed, evidence-specific membership, not a claim that
                            # an external operation is financially final.
                            rel={'internal_payment':'execution_uses_payment_object',
                                 'invoice':'same_invoice','basket':'basket_context_observed',
                                 'snapshot_item':'references_snapshot_item',
                                 'invoice_settlement':'invoice_settlement_observed',
                                 'product_reservation':'reservation_for'}.get(kind)
                            if rel:
                                from_id='request:'+e['request_key'];to_id=key
                                self._contract_edge(rel,from_id,to_id,scope,e,path,'eligible','A')
                                edges+=1
                        facts=correlation_facts(raw)
                        if facts:
                            for relation,from_kind,from_value,to_kind,to_value,path in facts['edges']:
                                self._contract_edge(relation,typed_id('pishkhan24',from_kind,from_value),
                                    typed_id('pishkhan24',to_kind,to_value),'core_explicit_correlation',e,
                                    path,'explicit_correlation','A')
                                edges+=1
                        # Preserve each internal→provider binding instance. A newer
                        # provider token is NEVER an overwrite of an older binding.
                        provider_call=str(raw.get('CallPath',''))
                        if ('ReportNewPayment' in provider_call or 'ReportNewPurchase' in provider_call or
                            'ReportNewMasterCardBillPayment' in provider_call):
                            input_obj=dict_first(decode_block(raw.get('message',''),'Input:'))
                            output_obj=parameter_result(decode_block(raw.get('message',''),'Output:'))
                            internal=canonical(input_obj.get('ExtraInfo')) or canonical(input_obj.get('TraceNumber'))
                            external=canonical(output_obj.get('PaymentKey')) or canonical(output_obj.get('PurchaseKey'))
                            k=typed_id('pishkhan24','internal_payment',internal)
                            provider='payment_gateway' if 'PaymentGateway' in provider_call else 'provider'
                            external_kind='external_paymentkey' if canonical(output_obj.get('PaymentKey')) else 'external_purchasekey'
                            t=typed_id(provider,external_kind,external,scope=provider_call.split(' Line:')[0])
                            if k and t and (canonical(input_obj.get('ExtraInfo'))==internal):
                                # Candidate until the local payment create→K witness
                                # exists. Matching an input string does not prove the
                                # funding of any particular customer execution.
                                self._contract_edge('candidate_provider_binding',k,t,provider_call.split(' Line:')[0],e,
                                     'provider.Input.ExtraInfo+Output.Parameters', 'needs_create_bridge','B');edges+=1
                        if 'ud_prc_paymentServiceReportToken' in str(raw.get('CallPath','')):
                            ps={}
                            try:ps,_=sql_parameters(raw.get('message',''))
                            except (ValueError,TypeError):pass
                            k=typed_id('pishkhan24','internal_payment',ps.get('paymentkey'))
                            t=typed_id('payment_provider','external_payment_or_purchase',ps.get('token'),scope='report_token')
                            if k and t:
                                self._contract_edge('provider_binding',k,t,'sql.report_token',e,
                                      'sql.paymentKey+token','eligible','A');edges+=1
                        if 'ud_prc_webhooksInformBillPaymentStatus_v1' in str(raw.get('CallPath','')):
                            try:p,_=sql_parameters(raw.get('message',''))
                            except (ValueError,TypeError):p={}
                            key=typed_id('pishkhan24','internal_payment',p.get('paymentkey'))
                            bill=canonical(p.get('billid'));payment=canonical(p.get('paymentid'))
                            item=typed_id('bill_issuer','natural_bill_pair',bill+'|'+payment,scope='v1.webhook') if bill and payment else None
                            if key and item:
                                self._contract_edge('notification_for_payment_item',key,item,'v1.bill_item',e,
                                                     'sql.paymentKey+billID+paymentID','reported_not_final','A');edges+=1
                        if 'ud_prc_webhooksInformPurchaseStatus' in str(raw.get('CallPath','')):
                            try:p,_=sql_parameters(raw.get('message',''))
                            except (ValueError,TypeError):p={}
                            key=typed_id('pishkhan24','internal_payment',p.get('paymentkey'))
                            external=typed_id('pishkhan24','external_reference_unresolved',p.get('externalpurchasekey'))
                            if key and external:
                                self._contract_edge('purchase_status_notification',key,external,'business_family_unresolved',e,
                                                  'sql.paymentKey+externalPurchaseKey+status','reported_not_final','A');edges+=1
                        for axis,value,path in observed_states(raw):
                            self.sql('''INSERT INTO viewer_contract_observations(origin_key,version_key,request_key,at_ns,callpath,axis,value,field_path,authority)
                                  VALUES(?,?,?,?,?,?,?,?,?) ON CONFLICT DO NOTHING''',
                                  (e['origin_key'],e['version_key'],e['request_key'],e['at_ns'],e['callpath'],axis,str(value),path,'reported'))
                            observations+=1
                process_seconds+=time.monotonic()-began
                if max_events is not None and scanned>=max_events:break
                if scanned%4000==0:self.progress('contract_build',processed=scanned,total=timings.get('candidate_events'),
                    fetch_seconds=round(timings['fetch_seconds'],3),process_write_seconds=round(process_seconds,3))
        self.progress('contract_build_complete',processed=scanned,fetch_seconds=round(timings['fetch_seconds'],3),
                      process_write_seconds=round(process_seconds,3))
        self.progress('service_dispatch_actions')
        # The private contract table initially has only its evidence PK. New
        # context lookups are by RequestID; index/analyze the bounded work table
        # once rather than scanning it again for every 200-request batch.
        stage=(getattr(self,'_projection_routes',None) or {}).get('viewer_contract_observations')
        if stage:
            self.sql('CREATE INDEX IF NOT EXISTS viewer_dispatch_fact_request ON '+stage+' (request_key,axis)')
            if not self.sqlite:self.sql('ANALYZE '+stage)
        self.reconcile_service_dispatches(request_keys=request_keys)
        if commit:self.conn.commit()
        return dict(scanned_events=scanned,identifier_occurrences=identifiers,observations=observations,edges=edges,
                    financial_finality='NOT_INFERRED',rule_version=RULE_VERSION)

    def _contract_edge(self,relation,from_id,to_id,scope,e,path,eligibility,confidence):
        sig=json.dumps([relation,from_id,to_id,scope,e['origin_key'],e['version_key'],path],ensure_ascii=True)
        key=hashlib.sha256(sig.encode()).hexdigest()
        self.sql('''INSERT INTO viewer_contract_edges VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?) ON CONFLICT DO NOTHING''',
             (key,relation,from_id,to_id,scope,e['origin_key'],e['version_key'],path,
             e['request_key'],eligibility,RULE_VERSION,confidence,e['at_ns']))

    def payment_contract_card(self,request_key):
        """Card for a single RequestID; does not merge unrelated attempts."""
        items=self.all('''SELECT issuer,kind,scope,field_path,raw_value,identity_key,origin_key,version_key
          FROM viewer_contract_identifiers WHERE request_key=? ORDER BY kind,field_path LIMIT 200''',(request_key,))
        obs=self.all('''SELECT at_ns,callpath,axis,value,field_path,authority,origin_key,version_key
          FROM viewer_contract_observations WHERE request_key=? ORDER BY at_ns,origin_key LIMIT 150''',(request_key,))
        edges=self.all('''SELECT relation_type,from_typed_id,to_typed_id,scope,evidence_origin,evidence_version,
                          evidence_path,eligibility,confidence,observed_ns FROM viewer_contract_edges
                       WHERE request_key=? ORDER BY observed_ns,edge_key LIMIT 150''',(request_key,))
        # Shared typed objects make related requests discoverable, but this is
        # NOT a claim that every RequestID is the same financial execution.
        related=[]
        used=set()
        for obj in items:
            if obj['kind'] not in ('internal_payment','invoice','basket','basket_payment_group'):continue
            kind=obj['kind'];identity=obj['identity_key']
            for row in self.all('''SELECT DISTINCT c.request_key, r.root_call,r.conflicted FROM viewer_contract_identifiers c
               JOIN viewer_requests r ON r.request_key=c.request_key
               WHERE c.identity_key=? AND c.kind=? AND c.request_key<>? ORDER BY c.request_key LIMIT 50''',
               (identity,kind,request_key)):
                if row['conflicted']:continue
                pair=(kind,row['request_key'])
                if pair in used:continue
                used.add(pair)
                related.append(dict(request_key=row['request_key'],root_call=row['root_call'],relation='shared_typed_'+kind,
                                    warning='same object/reference, NOT same execution or confirmed transfer'))
        rail='not_observed'
        # Bind LIKE patterns: literal '%' inside SQL is treated as a
        # placeholder prefix by psycopg3 (ProgrammingError: got '%P').
        explicit=self.all("""SELECT DISTINCT callpath FROM viewer_events e WHERE request_key=?
          AND NOT EXISTS(SELECT 1 FROM viewer_events bad WHERE bad.origin_key=e.origin_key AND bad.version_key<>e.version_key)
          AND (callpath LIKE ? OR callpath LIKE ? OR callpath LIKE ?)""",
          (request_key,'%PaymentDirectByMasterWallet%','%PaymentDirect%','%ReportNewMasterCardBillPayment%'))
        paths=[x['callpath'] for x in explicit]
        if any('PaymentDirectByMasterWallet' in x for x in paths):rail='provider_master_wallet'
        elif any('ReportNewMasterCardBillPayment' in x for x in paths):rail='provider_master_bill_payment'
        elif any('PaymentDirect' in x for x in paths):rail='provider_direct'
        return dict(identifiers=items,observations=obs,edges=edges,related_requests=related[:50],method_axes=dict(
          user_selected_channel='unknown',execution_route=rail,customer_funds_source='unknown',
          provider_funding_pool_or_rail=rail),financial_confirmation='unverified',
          completeness='not_established',rule_version=RULE_VERSION)
