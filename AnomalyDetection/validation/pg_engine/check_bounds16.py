"""Exact large-actor and weekly SQL fallback, not a production capacity test."""
import json
from pathlib import Path
from transport import Engine
from anomaly_detection import BUILD_ID,FIVE_NS
from anomaly_detection.product_store import ProductStore
from anomaly_detection.product_pipeline import apply_window
from anomaly_detection.continuous import coverage_runs,database_peak,peak,reference,histogram_reference,evaluate
from anomaly_detection.snapshot import canonical
from check_revision16 import T,ACTOR,SERVICE,merged_packet
from check_revision10 import metadata

ROOT=Path(__file__).resolve().parents[2]


def main():
    engine=Engine();checks={}
    try:
        raw=engine.connect();raw.execute('CREATE SCHEMA anomaly_detection');store=ProductStore(raw);store.initialize()
        raw.execute("INSERT INTO anomaly_detection.adp_source_windows SELECT at,'coverage',%s,TRUE FROM generate_series(%s::bigint,%s::bigint,%s::bigint) at",
            (canonical(metadata(T)|{'peer_population_valid':True}),T-12*288*FIVE_NS,T+FIVE_NS,FIVE_NS))
        for k,at in enumerate((T-6*288*FIVE_NS,T)):
            apply_window(store,merged_packet(at,[(ACTOR,4150,at+1)],100000+k*10000),cursor_name='large'+str(k))
        others=[f'{i+1000:064x}' for i in range(100)]
        for k,at in enumerate((T-4*288*FIVE_NS,T-288*FIVE_NS)):
            apply_window(store,merged_packet(at,[(s,1,at+1) for s in others],200000+k*10000),cursor_name='past'+str(k))
        raw.execute("UPDATE anomaly_detection.adp_facts SET details=jsonb_build_object('source_present',true,'semantic',body::jsonb,'quality',jsonb_build_object('evidence_available',true))::text")
        runs=coverage_runs(raw.execute('SELECT start_ns,source,complete FROM anomaly_detection.adp_source_windows ORDER BY start_ns').fetchall())
        rows=[dict(r)|{'qualified':True} for r in raw.execute('SELECT request_key,at_ns FROM anomaly_detection.adp_facts WHERE session_key=%s ORDER BY at_ns',(ACTOR,)).fetchall()]
        week=7*288*FIVE_NS
        for span,total in ((FIVE_NS,4150),(week,8300)):
            sql=database_peak(store,SERVICE,ACTOR,T,span,runs);memory=peak(rows,span,T,T+FIVE_NS,runs)
            assert sql['observed']==memory['observed']==total and sql['begin_ns']==memory['begin_ns'] and sql['evidence_verified']
        checks['over_8192_actor_events_are_counted_exactly_by_database_not_clipped']='PASS_8300_CANONICAL_EXECUTIONS'
        checks['weekly_rolling_span_retains_six_day_old_events_and_matches_exact_in_memory_result']='PASS'
        raw.execute("UPDATE anomaly_detection.adp_facts SET details=jsonb_set(details::jsonb,'{quality,evidence_available}','false'::jsonb)::text WHERE request_key=%s",(rows[0]['request_key'],))
        assert database_peak(store,SERVICE,ACTOR,T,FIVE_NS,runs)['evidence_verified']
        assert not database_peak(store,SERVICE,ACTOR,T,week,runs)['evidence_verified']
        h=reference(store,SERVICE,ACTOR,T,week,runs,0)
        ref=histogram_reference(h,8300,1)
        assert ref['ready'] and ref['expected']==2 and ref['other_session_epochs']==100 and ref['high'],ref
        checks['weekly_reference_uses_same_duration_past_other_actors_and_full_span_evidence']='PASS'
        context={'windows':[{'start_ns':T,'counts':{SERVICE:4150}}]}
        decisions,_=evaluate(store,{'session_key':ACTOR,'target_ns':T},context)
        long=next(d for d in decisions if d['duration_ns']==week)
        assert long['observed']==8300 and not long['span_evidence_verified']
        assert long['status']=='INSUFFICIENT_DATA' and long['minimum_other_session_epochs']==399
        checks['production_detector_uses_exact_fallback_and_insufficient_rank_resolution_is_not_normal']='PASS'
        report={'build_id':BUILD_ID,'status':'PASS_LARGE_ACTOR_AND_WEEKLY_SQL_CONTRACT','checks':checks,
            'owner_connections':0,'production_capacity':'NOT_MEASURED','source_modified':False}
        (ROOT/'validation/PRODUCT_bounds16.json').write_text(json.dumps(report,indent=2)+'\n');print(json.dumps(report))
    finally:engine.close()


if __name__=='__main__':main()
