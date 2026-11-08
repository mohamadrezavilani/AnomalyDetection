"""Publication, re-audit and display of a verified input finding on PostgreSQL."""
from contextlib import contextmanager
import json
from pathlib import Path
from shutil import copytree
from tempfile import TemporaryDirectory
import zlib

from anomaly_detection import CATALOG_SHA, FIVE_NS
from anomaly_detection.audit_scope import keys
from anomaly_detection.case_summary import case_status
from anomaly_detection.cases import identity
from anomaly_detection.pg_source import BudgetQuery, installed_source_identity
from anomaly_detection.presentation_proof import collect
from anomaly_detection.product_pipeline import apply_window
from anomaly_detection.product_source import ProductSource
from anomaly_detection.product_store import ProductStore
from anomaly_detection.product_web import render
from anomaly_detection.snapshot import canonical
from check_revision10 import packet
from check_revision18 import primary
from check_revision16 import T
from transport import Engine

SERVICE = 'Services.v1/WaterBills'
ACTOR = 'a'*64
ROOT = Path(__file__).resolve().parents[2]


def seed_source(raw, incoming):
    schema=json.loads((ROOT/'reference/handoff_20261031/reference/viewer_schema_reference.json').read_text())['tables']
    names=('viewer_requests','viewer_semantic_occurrences','viewer_events','viewer_raw_events',
           'viewer_contract_edges','viewer_contract_observations','viewer_contract_identifiers',
           'viewer_live_state','viewer_live_windows','viewer_service_roles',
           'viewer_service_catalog_state','viewer_semantic_checkpoint')
    for name in names:
        columns=[]
        for col in schema[name]['columns']:
            kind={'INTEGER':'BIGINT','BLOB':'BYTEA','REAL':'DOUBLE PRECISION'}.get(col['declared_type'],col['declared_type'])
            columns.append('"'+col['name']+'" '+kind)
        raw.execute('CREATE TABLE public.'+name+'('+','.join(columns)+')')

    def add(name, row):
        values=tuple(v.hex() if isinstance(v,bytes) else v for v in row.values())
        params=','.join("decode(%s,'hex')" if isinstance(v,bytes) else '%s' for v in row.values())
        raw.execute('INSERT INTO public.'+name+'('+','.join(row)+') VALUES ('+params+')',values)

    add('viewer_live_state',{'id':1,'stream_key':'fixture','keys_fingerprint':'fixture','generation':100,'next_ns':T+FIVE_NS})
    add('viewer_live_windows',{'start_ns':T,'end_ns':T+FIVE_NS})
    add('viewer_service_catalog_state',{'id':1,'fingerprint':CATALOG_SHA})
    add('viewer_semantic_checkpoint',{'id':1,'generation':100,'state':'ready'})
    for i,row in enumerate(incoming['rows'],1):
        request,at=row['request_key'],row['anchor_ns']
        add('viewer_requests',{'request_key':request,'session_key':ACTOR,'identity_state':'assigned','conflicted':0,
            'root_call':SERVICE,'root_code':'G00000','started_ns':at,'ended_ns':at+1})
        add('viewer_semantic_occurrences',{key:value for key,value in row.items()
            if key in {'request_key','anchor_key','session_key','anchor_ns','kind','state','revision','root_call','root_code'}}
            |{'occurrence_key':'bo1:'+f'{10000+i:064x}'})
        origin,version=f'{20000+i:064x}',f'{30000+i:064x}'
        add('viewer_events',{'request_key':request,'session_key':ACTOR,'origin_key':origin,'version_key':version,
            'at_ns':at+1,'callpath':'ClientAyanCoInquiry.WaterBillInquiry Line: 180','kind':'provider'})
        message='Input: '+json.dumps([{'WaterBillID':f'000000{i:03d}'}])+' Output: '+json.dumps({'BillUniqueID':f'generated-{i}'})
        add('viewer_raw_events',{'origin_key':origin,'version_key':version,'payload':zlib.compress(json.dumps({'message':message}).encode())})


def verify(raw, project):
    raw.execute('CREATE SCHEMA anomaly_detection')
    store=ProductStore(raw)
    store.initialize()
    raw.execute("INSERT INTO anomaly_detection.adp_service_reference_points "
                "SELECT %s,'service_execution',lpad(to_hex(i),64,'0'),%s::bigint-(i%%371+2)*%s::bigint,"
                "CASE WHEN i=8216 THEN 38 WHEN i>8184 THEN 10 ELSE 1 END,TRUE "
                "FROM generate_series(1,8216) i",(SERVICE,T,FIVE_NS))
    incoming=packet(T,{SERVICE:10},offset=50000)
    for i,row in enumerate(incoming['rows']):
        row['anchor_ns']=T+1_000_000_000+i*1_300_000_000
    assert apply_window(store,incoming)['status']=='COMPLETE'
    seed_source(raw,incoming)
    for row in raw.execute('SELECT request_key,body FROM anomaly_detection.adp_facts ORDER BY request_key').fetchall():
        # Simulate R3's existing audits, which did not carry input proofs.
        event=json.loads(row['body'])
        fact={'source_present':True,'request_key':row['request_key'],'semantic':event,
              'quality':{'evidence_available':True,'conflicted':False,'identity_state':'assigned'},
              'transport':{'root_call':SERVICE},'identifiers':[],'observations':[],'relations':[],'evidence':[]}
        raw.execute('UPDATE anomaly_detection.adp_facts SET details=%s WHERE request_key=%s',(canonical(fact),row['request_key']))
    primary(store)
    rate_key=identity('actor',ACTOR,'activity',SERVICE)
    case_key=identity('actor',ACTOR,'subject_enumeration',SERVICE)
    assert case_status(store,rate_key)['bucket']=='WATCH' and case_status(store,case_key) is None
    now=T+20*FIVE_NS
    all_keys=keys(store,now,limit=20)
    assert len(all_keys)==10

    class IsolatedSource(ProductSource):
        def __init__(self):
            self.project=project

        @contextmanager
        def snapshot(self):
            with raw.transaction():
                raw.execute('SET TRANSACTION ISOLATION LEVEL REPEATABLE READ, READ ONLY')
                yield BudgetQuery(raw)

    source=IsolatedSource()
    for batch in (all_keys[:8],all_keys[8:]):
        snapshot=source.audit(batch)
        assert all(receipt['status']=='VERIFIED' for receipt in snapshot.input_subjects.values())
        serialized=json.dumps(snapshot.input_subjects)
        assert all(json.dumps(f'000000{i:03d}') not in serialized for i in range(1,11)), 'raw input leaked in a proof receipt'
        assert store.apply_audit(snapshot)['evidence_changes']==len(batch)
    assert keys(store,now+100,limit=20)==[]
    result=primary(store)
    assert result['status']=='APPLIED'
    finding=next(d for d in result['decisions'] if d['family']=='input_subject_burst')
    assert finding['status']=='CANDIDATE' and finding['observed']==10 and finding['verified_input_requests']==10
    assert case_status(store,rate_key)['bucket']=='WATCH'
    assert case_status(store,case_key)['bucket']=='READY'
    for view in ('services','actors','cases'):
        page=render(store,{},'/incidents',{'view':[view],'bucket':['READY']},'fixture-token')
        assert '/case/'+case_key in page and '10 موضوع ورودی متمایز' in page
    count=raw.execute('SELECT COUNT(DISTINCT request_key) AS n FROM anomaly_detection.adp_case_requests WHERE case_key=%s',(case_key,)).fetchone()['n']
    assert count==10
    with raw.transaction():
        raw.execute('SET TRANSACTION ISOLATION LEVEL REPEATABLE READ, READ ONLY')
        proof=collect(store,ACTOR,T)
    assert proof['status']=='PASS_REVIEWABLE_INPUT_SUBJECT_FINDING'
    assert proof['services'][0]['input_subject_finding']['case_key']==case_key
    assert proof['services'][0]['reference_sessions']==8216
    assert proof['services'][0]['reference_max']==38
    assert abs(finding['upper_bound_tail_rank']-33/8217)<1e-12
    from anomaly_detection.model_queue import reference_changed
    with store.transaction():
        reference_changed(store,[(SERVICE,T-2*FIVE_NS)])
    assert case_status(store,case_key)['bucket']=='RECHECK'
    return {'status':'PASS_ISOLATED_POSTGRESQL_WASM','synthetic_input_requests':10,'verified_input_subjects':10,
            'peer_sessions':8216,'reference_max':38,'conservative_tail_bound':finding['upper_bound_tail_rank'],
            'R3_existing_evidence_reaudit':'PASS','proof_matches_case_and_members':'PASS',
            'actual_pinned_viewer_raw_reader_and_audit':'PASS',
            'ready_case_rendered_in_service_actor_and_case_lists':'PASS',
            'reference_change_invalidates_input_finding':'PASS','native_server':'NOT_RUN'}


def main(reference=None):
    reference=Path(reference).resolve() if reference else ROOT.parent
    installed_source_identity(reference)
    engine=Engine()
    try:
        with TemporaryDirectory(prefix='ad-input-readonly-') as temporary:
            project=Path(temporary)
            copytree(reference/'p24_foundation',project/'p24_foundation')
            print(json.dumps(verify(engine.connect(),project),ensure_ascii=False))
    finally:
        engine.close()


if __name__=='__main__':main()
