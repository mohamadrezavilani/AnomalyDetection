"""LC3C isolated synthetic replay invariants, never the user's read-model DB.

Runs each synthetic witness in independent, temporary SQLite databases using
unchanged Viewer intake, reconstruction, service-journey and payment-contract
code. Order-independence here is not proof of late Elasticsearch arrival or
any authorized financial settlement. Private source values never leave temp.
"""
from __future__ import annotations

import gzip
import hashlib
import json
import tempfile
from pathlib import Path

from .privacy import generate_keys
from .viewer_data import ViewerDB

VERSION = 'p24-lc3c-replay-witness-v1'


def _log(n, request, call, message, clock, session='a'*32, *, origin=None):
    return {'_source_id':'lc3c-synthetic-'+str(n if origin is None else origin),
            '@timestamp':'2026-10-24T'+clock+'Z', 'RequestID':request,
            'Session':session, 'IP':'192.0.2.10', 'CallPath':call,
            'message':message,'level':'Info'}


def _sql(name, **values):
    return '(Command Text: '+name+')(Code: 1)(Result: Ok)(SQL Parameters: '+ ' '.join('@'+k+'='+str(v) for k,v in values.items())+')'


def _fixture_windows(base):
    windows = [
        ('w1','2026-10-24T04:15:00Z','2026-10-24T04:20:00Z',[
            _log(1,'q1','Services.v1/TrafficFinesCarNoDetails Line:302','POST (G00000 | successful)','04:19:59'),
            _log(2,'q2','Services.v1/TrafficFinesCarNoDetails Line:302','POST (G00000 | successful)','04:19:57'),
            _log(3,'charge','Core.v1/UserWalletCharge Line:8','POST (G00000 | successful)','04:19:58'),
            _log(4,'i','DBPath.pishkhan24.application.ud_prc_invoiceRegister', _sql('ud_prc_invoiceRegister',invoiceUniqueID='INV-LC3C'),'04:19:55'),
            _log(5,'i','Services.v1/InvoiceRegister Line:20','POST (G00000 | successful)','04:19:56'),
        ]),
        ('w2','2026-10-24T04:20:00Z','2026-10-24T04:25:00Z',[
            _log(6,'q1','DBPath.pishkhan24.application.ud_prc_inquiryInvoiceResult2',_sql('ud_prc_inquiryInvoiceResult2',invoiceUniqueID='INV-LC3C'),'04:20:01'),
            _log(7,'p1','DBPath.pishkhan24.application.ud_prc_paymentRequestForInvoiceSettlement',_sql('ud_prc_paymentRequestForInvoiceSettlement',invoiceUniqueID='INV-LC3C',paymentKey='K1'),'04:20:02'),
            _log(8,'p1','Core.v1/InvoicePayment Line:11','POST (G00000 | successful)','04:20:03'),
            _log(9,'p2','DBPath.pishkhan24.application.ud_prc_paymentRequestForInvoiceSettlement',_sql('ud_prc_paymentRequestForInvoiceSettlement',invoiceUniqueID='INV-LC3C',paymentKey='K2'),'04:20:04'),
            _log(10,'p2','Core.v1/InvoicePayment Line:11','POST (G00000 | successful)','04:20:05'),
            _log(11,'callback','PaymentCallback.PaymentCallback Line:20','POST (G00000 | successful)','04:20:06',session='N/A'),
        ]),
        ('w3','2026-10-24T04:25:00Z','2026-10-24T04:30:00Z',[
            # Late *file ingestion* is observed in the fixture but is not a
            # producer-verified arrival timestamp from Elasticsearch.
            _log(12,'q1','DBPath.pishkhan24.application.ud_prc_invoiceInfo',_sql('ud_prc_invoiceInfo',invoiceUniqueID='INV-LC3C'),'04:19:58'),
            _log(13,'w1','DBPath.pishkhan24.application.ud_prc_paymentGetInfo',_sql('ud_prc_paymentGetInfo',paymentKey='K1'),'04:20:07'),
            _log(14,'w1','Core.v1/WalletPayment Line:6','POST (G00000 | successful)','04:20:08'),
            _log(15,'w2','DBPath.pishkhan24.application.ud_prc_paymentGetInfo',_sql('ud_prc_paymentGetInfo',paymentKey='K2'),'04:20:09'),
            _log(16,'w2','Core.v1/WalletPayment Line:6','POST (G00000 | successful)','04:20:10'),
            _log(17,'n','DBPath.pishkhan24.application.ud_prc_webhooksInformPurchaseStatus',_sql('ud_prc_webhooksInformPurchaseStatus',invoiceUniqueID='INV-LC3C',paymentKey='K2',status='Finalized'),'04:20:12',session='N/A'),
            _log(18,'n','Webhook.v1/InformPurchaseStatus Line:8','POST (G00000 | successful)','04:20:13',session='N/A'),
        ])]
    files = []
    for label,start,end,rows in windows:
        path=base/(label+'.json.gz')
        with gzip.open(path,'wt',encoding='utf-8') as f:
            json.dump({'window_start':start,'window_end':end,'count':len(rows),'logs':rows},f,ensure_ascii=False)
        files.append(path)
    return files


def _snapshot(db):
    """Only deterministic derived facts; no raw data/user keys in the report."""
    requests=db.all('''SELECT request_key,session_key,identity_state,started_ns,ended_ns,
                         root_call,root_code,root_count,event_count,conflicted
                      FROM viewer_requests ORDER BY request_key''')
    actions=db.all('''SELECT action_key,category,initiation,current_outcome,
                        workflow_key,target_type,target_key FROM viewer_actions ORDER BY action_key''')
    identifiers=db.all('''SELECT origin_key,version_key,request_key,issuer,kind,scope,field_path,identity_key
                             FROM viewer_contract_identifiers ORDER BY origin_key,version_key,kind,field_path,identity_key''')
    edges=db.all('''SELECT edge_key,relation_type,from_typed_id,to_typed_id,scope,evidence_origin,
                       evidence_version,eligibility,rule_version
                    FROM viewer_contract_edges ORDER BY edge_key''')
    observations=db.all('''SELECT origin_key,version_key,request_key,axis,value,field_path,authority
                           FROM viewer_contract_observations ORDER BY origin_key,version_key,axis,value''')
    events=db.all('''SELECT origin_key,version_key,request_key,at_ns,callpath,kind,code,observation
                      FROM viewer_events ORDER BY origin_key,version_key''')
    # The stable output deliberately omits import file order, source filenames,
    # user-authored service role timestamps, and volatile import timestamps.
    obj={'requests':requests,'actions':actions,'identifiers':identifiers,
         'edges':edges,'observations':observations,'events':events}
    digest=hashlib.sha256(json.dumps(obj,sort_keys=True,ensure_ascii=True,
                                     separators=(',',':')).encode()).hexdigest()
    request_ids={r['request_key'] for r in requests}
    payment_objects={r['identity_key'] for r in identifiers if r['kind']=='internal_payment'}
    return {'digest':digest,
            'requests':len(requests),'actions':len(actions),
            'identifiers':len(identifiers),'edges':len(edges),
            'observations':len(observations),'events':len(events),
            'conflicted':sum(r['conflicted']!=0 for r in requests),
            'raw_request_keys':request_ids,'actions_rows':actions,
            'payment_objects':len(payment_objects),
            'request_rows':requests}


def _run(db_path,keys,files,order,*,duplicate=False,require_semantics=True):
    with ViewerDB(sqlite_path=db_path,keys_path=keys) as db:
        db.init()
        file_results=[]
        for offset in order:
            file_results.extend(db.ingest([files[offset]]))
            # Reconstruction at each receipt is deliberate: verify a partial
            # build can converge to the same final state.
            db.rebuild();db.rebuild_payment_contract()
        before=_snapshot(db)
        # Service root may arrive after a technical-only request fragment.
        # The final occurrence is resolved from its anchor (not from the
        # order the fragments happened to reach ingestion).
        if require_semantics:
            by_original={name:db.lookup_request(name)['request_key']
                         for name in ('q1','q2','charge','callback','p1','p2')}
            session_key=db.one('SELECT session_key FROM viewer_requests WHERE root_call IS NOT NULL AND session_key IS NOT NULL LIMIT 1')['session_key']
            visible=db.session_behavior(session_key)
            occ={x['anchor_request_key']:x['occurrence_key'] for x in visible['observed_occurrences']}
            if len(visible['observed_occurrences'])!=3 or any(k not in occ for k in
                                      (by_original['q1'],by_original['q2'],by_original['charge'])):
                raise AssertionError('incorrect_service_and_funding_occurrence_count')
            if by_original['callback'] in occ or occ[by_original['q1']]==occ[by_original['q2']]:
                raise AssertionError('technical_callback_or_repeated_inquiry_miscount')
            if before['payment_objects']!=2:
                raise AssertionError('multiple_internal_payment_objects_collapsed')
            if db.service_journey(by_original['callback'])['identity_status']!='provisional_technical':
                raise AssertionError('unowned_callback_was_auto_assigned')
            if by_original['charge'] in {r['request_key'] for r in db.service_journey(by_original['p1'])['steps']}:
                raise AssertionError('wallet_funding_tentatively_joined_by_session_or_time')
            if db.service_journey(by_original['q1'])['financial_confirmation']!='unverified':
                raise AssertionError('financial_confirmation_inferred_without_contract')
            before['semantic_occurrences']=sorted(occ.values())
        else:
            before['semantic_occurrences']=[]
        repeated=[]
        if duplicate:
            for path in files:
                repeated.extend(db.ingest([path]))
            db.rebuild();db.rebuild_payment_contract()
            after=_snapshot(db)
            if before['digest']!=after['digest']:
                raise AssertionError('repeated_import_changed_canonical_projection')
            if any(x['status']!='ALREADY_IMPORTED' for x in repeated):
                raise AssertionError('identical_file_not_idempotent')
        return before, file_results, repeated


def replay_witness(*, repeat=True):
    """Run independently with common keyed identities; no external DB config."""
    with tempfile.TemporaryDirectory(prefix='p24_lc3c_') as root:
        root=Path(root)
        keys=root/'isolated_keys.json'
        generate_keys(keys)
        files=_fixture_windows(root)
        cases={
            'chronological':(0,1,2),
            'reverse':(2,1,0),
            'out_of_order':(1,0,2),
        }
        results={}
        for name,order in cases.items():
            snapshot, receipts, repeats=_run(root/(name+'.sqlite'),keys,files,order,duplicate=(repeat and name=='chronological'))
            results[name]=snapshot
        digests={name:result['digest'] for name,result in results.items()}
        if len({tuple(x['semantic_occurrences']) for x in results.values()})!=1:
            raise AssertionError('replay_order_changed_behavior_occurrences')
        if len(set(digests.values()))!=1:
            raise AssertionError('replay_order_changed_derived_graph')
        first=results['chronological']
        if first['conflicted']:
            raise AssertionError('clean_fixture_should_have_no_origin_conflicts')
        return {
            'version':VERSION,'isolated':True,'synthetic_only':True,
            'did_not_connect_to_live_viewer_database':True,
            'orders_tested':list(cases),
            'order_independent_derived_snapshot':True,
            'repeated_file_import_idempotent':bool(repeat),
            'canonical_snapshot_sha256':first['digest'],
            'derived_counts':{k:first[k] for k in ('requests','actions','identifiers','edges','observations','events','conflicted','payment_objects')},
            'observed_semantic_occurrence_count':len(first['semantic_occurrences']),
            'callback_stayed_provisional':True,
            'independent_inquiries_not_merged':True,
            'different_internal_payments_preserved':True,
            'wallet_funding_not_joined_by_time_or_session':True,
            'financial_settlement_inferred':False,
            'confirmed_manual_actions_inferred':False,
            'full_r5_end_to_end_accepted_cases':0,
            'conflict_witness':conflict_witness(),
            'not_proven':['independent_Elasticsearch_arrival_order','real_PostgreSQL_projection_replay',
                          'authoritative_payment_capture_or_refund','full_86_R5_case_acceptance'],
        }


def conflict_witness():
    """Two payloads with same origin must remain conflicting in either order."""
    with tempfile.TemporaryDirectory(prefix='p24_lc3c_conflict_') as location:
        root=Path(location);keys=root/'keys';generate_keys(keys)
        first=_log(101,'conflicted', 'Services.v1/TrafficFinesCarNoDetails Line:302',
                   'POST (G00000 | successful)','04:19:59',origin='same')
        second=dict(first);second['message']='POST (GE4004 | failed)'
        files=[]
        for n,row in enumerate((first,second)):
            path=root/('revision'+str(n)+'.json.gz')
            with gzip.open(path,'wt',encoding='utf-8') as f:
                json.dump({'window_start':'2026-10-24T04:15:00Z',
                           'window_end':'2026-10-24T04:20:00Z',
                           'count':1,'logs':[row]},f)
            files.append(path)
        snapshots=[]
        for name,order in (('first',(0,1)),('reverse',(1,0))):
            snapshot,_,_=_run(root/(name+'.sqlite'),keys,files,order,require_semantics=False)
            if snapshot['conflicted']!=1 or snapshot['actions']!=0 or snapshot['events']!=2:
                raise AssertionError('conflicting_origin_was_silently_accepted')
            snapshots.append(snapshot['digest'])
        if len(set(snapshots))!=1:
            raise AssertionError('conflict_resolution_depends_on_arrival_order')
        return {'conflicted_origin_versions':2,'independent_arrival_orders':2,
                'conflict_quarantined_from_action_count':True,
                'conflict_order_independent':True}
