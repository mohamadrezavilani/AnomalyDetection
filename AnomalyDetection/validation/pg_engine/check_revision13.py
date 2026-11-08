"""Bound page before identity lookup; inspect actual isolated SQL plan.

Only disposable synthetic PostgreSQL/WASM. No owner database or source DDL.
"""
from contextlib import contextmanager
from pathlib import Path
import json

from transport import Engine
from anomaly_detection import BUILD_ID,FIVE_NS
from anomaly_detection.product_source import ProductSource,bounded_semantic_select
from anomaly_detection.product_store import ProductStore
from anomaly_detection.product_dependencies import context_changed_many
from check_revision10 import packet as fixture_packet,TARGET,SERVICES

ROOT=Path(__file__).resolve().parents[2]


def nodes(plan):
    yield plan
    for child in plan.get('Plans',[]):yield from nodes(child)


def main():
    engine=Engine();checks={}
    try:
        raw=engine.connect()
        raw.execute('CREATE TABLE public.viewer_semantic_occurrences(request_key TEXT PRIMARY KEY,anchor_ns BIGINT,revision BIGINT,state TEXT)')
        raw.execute('CREATE TABLE public.viewer_requests(request_key TEXT PRIMARY KEY,identity_state TEXT,conflicted BIGINT,session_key TEXT)')
        raw.execute("INSERT INTO public.viewer_semantic_occurrences SELECT lpad(to_hex(g),64,'0'),g,1,'active' FROM generate_series(1,30000) g")
        raw.execute("INSERT INTO public.viewer_requests SELECT request_key,'assigned',0,repeat('a',64) FROM public.viewer_semantic_occurrences")
        raw.execute('ANALYZE public.viewer_semantic_occurrences');raw.execute('ANALYZE public.viewer_requests')
        captured=[]
        def query(sql,args=(),*,cap=100000):
            assert sql.startswith('SELECT ')
            captured.append((sql,tuple(args)+(cap+1,)))
            rows=raw.execute(sql+' LIMIT %s',(*args,cap+1)).fetchall()
            assert len(rows)<=cap
            return rows
        reader=ProductSource.__new__(ProductSource);reader.page_size=2048;reader.semantic_page_size=64
        @contextmanager
        def snapshot():yield query
        reader.snapshot=snapshot;reader.metadata=lambda q:{'namespace':'fixture'}
        first=reader.page();assert len(first['rows'])==64 and first['has_more']
        sql,args=captured[-1]
        plan=raw.execute('EXPLAIN (ANALYZE,FORMAT JSON) '+sql+' LIMIT %s',args).fetchone()['QUERY PLAN'][0]['Plan']
        request_nodes=[n for n in nodes(plan) if n.get('Relation Name')=='viewer_requests']
        semantic_nodes=[n for n in nodes(plan) if n.get('Relation Name')=='viewer_semantic_occurrences']
        assert request_nodes and all('Index' in n['Node Type'] for n in request_nodes),request_nodes
        assert all(n['Actual Loops']<=65 and n['Actual Rows']<=1 for n in request_nodes),request_nodes
        assert semantic_nodes and all(n['Actual Rows']<=65 for n in semantic_nodes),semantic_nodes
        checks['first_page_reads_at_most_65_semantic_rows_and_65_indexed_identity_lookups']='PASS_EXPLAIN_ANALYZE_SYNTHETIC_30000_ROWS'
        second=reader.page(first['after'])
        assert len(second['rows'])==64 and second['rows'][0]['request_key']>first['after']
        assert not {r['request_key'] for r in first['rows']} & {r['request_key'] for r in second['rows']}
        checks['keyset_continuation_is_ordered_without_duplicates']='PASS'
        absent=first['rows'][9]['request_key'];raw.execute('DELETE FROM public.viewer_requests WHERE request_key=%s',(absent,))
        missing=next(r for r in reader.page()['rows'] if r['request_key']==absent)
        assert missing['identity_state'] is None and missing['request_session_key'] is None
        checks['missing_identity_is_retained_as_unknown_not_dropped_or_assigned']='PASS'
        statement=bounded_semantic_select("WHERE s.state='active' AND s.anchor_ns>=%s AND s.anchor_ns<%s ",'s.anchor_ns,s.request_key')
        window=query('SELECT * FROM ('+statement+') AS window_page',(100,200,33),cap=33)
        assert len(window)==33 and min(r['anchor_ns'] for r in window)==100 and max(r['anchor_ns'] for r in window)==132
        checks['time_window_uses_same_bounded_join_with_exact_range_and_page_order']='PASS'
        reader.page_size=2048;reader.semantic_page_size=2048
        for _ in range(10):reader.reduce_page_size('semantic_keyset')
        assert reader.page_size==2048 and reader.semantic_page_size==64
        reader.reduce_page_size('fresh_cursor');assert reader.page_size==1024 and reader.semantic_page_size==64
        checks['ten_semantic_timeouts_cannot_reduce_window_throughput_by_32_times']='PASS_INDEPENDENT_PAGE_SIZES'
        raw.execute('CREATE SCHEMA anomaly_detection');store=ProductStore(raw);store.initialize()
        at=1000*FIVE_NS
        for i in range(200):
            session=f'{i+50000:064x}'
            raw.execute('INSERT INTO anomaly_detection.adp_jobs(session_key,target_ns,dirty) VALUES(%s,%s,FALSE)',(session,at))
            for service in ('context:service_a','context:service_b'):
                raw.execute('INSERT INTO anomaly_detection.adp_peer_dependencies VALUES(%s,%s,%s,%s,0)',(session,at,service,FIVE_NS))
        queries=[];original=engine.query
        def traced(role,sql,args):
            if 'adp_peer_epochs' in sql or 'UPDATE anomaly_detection.adp_jobs' in sql:queries.append(sql)
            return original(role,sql,args)
        engine.query=traced
        try:
            with store.transaction():context_changed_many(store,[('service_a',at-FIVE_NS),('service_b',at-2*FIVE_NS)])
        finally:engine.query=original
        assert len(queries)==2,queries
        states=raw.execute('SELECT version,dirty FROM anomaly_detection.adp_jobs').fetchall()
        assert len(states)==200 and all(r['version']==2 and r['dirty'] for r in states)
        checks['multi_service_dependency_page_uses_two_set_queries_and_one_version_change_per_consumer']='PASS_200_SHARED_CONSUMERS'
        sample=fixture_packet(TARGET,{SERVICES[0]:3},offset=900000)
        count=raw.execute('SELECT COUNT(*) AS n FROM anomaly_detection.adp_jobs').fetchone()['n']
        class Cancelled(Exception):sqlstate='57014'
        def cancel():raise Cancelled()
        try:store.apply_rows(sample['rows'],sample['source'],cursor_state=('cancelled_page',{'after':'must-not-commit'}),fault=cancel)
        except Cancelled:pass
        else:raise AssertionError('expected cancelled apply')
        assert not store.state('cancelled_page')
        assert raw.execute('SELECT COUNT(*) AS n FROM anomaly_detection.adp_facts').fetchone()['n']==0
        assert raw.execute('SELECT COUNT(*) AS n FROM anomaly_detection.adp_jobs').fetchone()['n']==count
        checks['cancelled_owned_page_rolls_back_facts_jobs_and_cursor_before_retry']='PASS'
        report={'build_id':BUILD_ID,'status':'PASS_ISOLATED_POSTGRESQL_WASM','checks':checks,
            'source_read_budgets':'UNCHANGED_1000MS_STATEMENT_3S_TOTAL_RR_RO','owner_connections':0,
            'native_query_plan_and_latency':'NOT_MEASURED','negative_control_native_result':'PENDING_WORKER_EVALUATION',
            'detector_criterion':'UNCHANGED_FROM_RELEASE12'}
        (ROOT/'validation/PRODUCT_revision13.json').write_text(json.dumps(report,indent=2)+'\n');print(json.dumps(report))
    finally:engine.close()


if __name__=='__main__':main()
