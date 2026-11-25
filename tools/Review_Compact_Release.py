"""Read-only post-install observations; no collectors, repairs or source replay."""
import argparse
from collections import Counter
from datetime import datetime, timezone
import json
from pathlib import Path
import time
from compact_behavior import FIVE, FEATURES
from compact_behavior.store import Store
from compact_product import BUILD, case_selection
from compact_product.config import load
from compact_product.health import health
from compact_product.version import verify
from compact_ad import MODEL, inquiry_breadth, longitudinal
from compact_ad.references import POLICY as ANALYSIS_POLICY


def snapshot(db,cfg,stream,baseline=None):
    s,a=cfg.source_schema,cfg.ad_schema
    now=time.time_ns()
    with db.conn.transaction():
        db.conn.execute('SET TRANSACTION ISOLATION LEVEL REPEATABLE READ READ ONLY')
        db.conn.execute("SET LOCAL statement_timeout='12s'")
        db.conn.execute("SET LOCAL lock_timeout='1s'")
        value=health(db.conn,cfg,stream)
        head=value.get('latest_received_end_ns')
        selected,signals,truncated=case_selection.select(db.conn,cfg,stream,(head or now)-288*FIVE,head or now)
        counts=Counter(method for case in selected for method in case['methods'])
        samples=[]
        for case in selected:
            for row in case['findings'][:3]:
                r=row['result']
                samples.append(dict(method=row['method'],service=row['service'],start_ns=row['start_ns'],
                    observed=r.get('observed'),threshold=r.get('threshold'),reference_windows=r.get('reference_windows'),
                    requests=r.get('requests'),covered_requests=r.get('covered_requests'),
                    distinct_targets=r.get('distinct_targets'),observed_is_lower_bound=r.get('observed_is_lower_bound'),
                    result_counts=r.get('result_counts'),reason=r.get('reason'),current_for_review=True,
                    witnesses=(r.get('evidence') or [])[:2]))
                if len(samples)>=20:break
            if len(samples)>=20:break
        states=db.conn.execute(f'SELECT state,count(*) AS n FROM {a}.long_runs WHERE stream_id=%s GROUP BY state',(stream,)).fetchall()
        limits=db.conn.execute(f'''SELECT service,end_ns,span,details->>'reason' AS reason,
            details->>'evaluation_policy' AS evaluation_policy,details->>'resume_index' AS resume_index
            FROM {a}.long_runs WHERE stream_id=%s AND state IN ('LIMIT','WAITING')
            ORDER BY end_ns DESC LIMIT 20''',(stream,)).fetchall()
        timings=db.conn.execute(f'''SELECT GREATEST(0,(r.analyzed_at_ns-r.work_cause_ns)/1e9::float) AS revision_seconds,
            GREATEST(0,(r.first_analyzed_ns-r.first_source_ns)/1e9::float) AS first_seconds
            FROM {a}.window_results r JOIN {s}.windows w USING(stream_id,start_ns)
            WHERE r.stream_id=%s AND r.model_version=%s AND r.feature_version=%s
            AND r.summary->>'inquiry_policy'=%s AND r.summary->>'analysis_policy'=%s AND r.timing_confirmed_revision=r.revision
            AND r.source_published_ns=w.published_at_ns ORDER BY r.analyzed_at_ns DESC LIMIT 96''',
            (stream,MODEL,FEATURES,inquiry_breadth.POLICY,ANALYSIS_POLICY)).fetchall()
        pending_sample=db.conn.execute(f'''WITH pending AS MATERIALIZED (
            SELECT start_ns,updated_at_ns FROM {a}.reanalysis WHERE stream_id=%s AND processed_version<version
            ORDER BY start_ns LIMIT 16)
            SELECT j.start_ns,j.updated_at_ns,r.summary->>'analysis_policy' AS analysis_policy,
                r.source_published_ns=w.published_at_ns AS source_current,r.analysis_seconds
            FROM pending j LEFT JOIN {a}.window_results r ON r.stream_id=%s AND r.start_ns=j.start_ns
            LEFT JOIN {s}.windows w ON w.stream_id=r.stream_id AND w.start_ns=r.start_ns
            ORDER BY j.start_ns''',(stream,stream)).fetchall()
        def percentile(field):
            import math
            values=sorted(v[field] for v in timings)
            return values[max(0,math.ceil(.95*len(values))-1)] if values else None
        fresh=0
        if baseline and baseline.get('latest_received_end_ns') is not None:
            fresh=db.conn.execute(f'''SELECT count(*) AS n FROM {s}.windows WHERE stream_id=%s
                AND start_ns>=%s AND first_published_ns>=%s''',(stream,baseline['latest_received_end_ns'],baseline['observed_ns'])).fetchone()['n']
    fields=('source_backlog_windows','analysis_pending_windows','dirty_keys','reanalysis_windows',
        'reference_pending_windows','analysis_timing_unconfirmed_windows','latest_received_end_ns',
        'latest_analyzed_end_ns','latest_analysis_timing_confirmed','latest_readiness','performance')
    return dict(observed_ns=now,observed_utc=datetime.fromtimestamp(now/1e9,timezone.utc).isoformat(),
        operator_status_latency={k:value.get(k) for k in (
            'analysis_processing_p95_seconds','analysis_latency_example','analysis_latency_samples',
            'analysis_latency_p95_seconds','first_analysis_latency_p95_seconds')},
        **{k:value.get(k) for k in fields},roles={role:{k:r.get(k) for k in ('running','state','heartbeat_age_seconds','build','failure')}
            for role,r in value['roles'].items()},operator_cases=len(selected),operator_methods=dict(counts),
        selected_signals=signals,operator_selection_truncated=truncated,finding_samples=samples,
        longitudinal_states={r['state']:r['n'] for r in states},longitudinal_waiting_or_limits=limits,
        oldest_reanalysis_sample=pending_sample,analysis_policy=ANALYSIS_POLICY,
        current_policy_timing_samples=len(timings),revision_latency_p95_seconds=percentile('revision_seconds'),
        first_analysis_latency_p95_seconds=percentile('first_seconds'),fresh_windows_since_first_observation=fresh,
        timing_scope='SOURCE_CURRENT_POSTCOMMIT_REVISIONS_WITH_CURRENT_INQUIRY_POLICY; REFERENCE_QUEUES_REPORTED_SEPARATELY')


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--project',type=Path,required=True)
    p.add_argument('--samples',type=int,default=3)
    p.add_argument('--interval',type=int,default=30)
    args=p.parse_args()
    if not 2<=args.samples<=12 or not 1<=args.interval<=300:p.error('samples 2..12; interval 1..300')
    package=verify()
    cfg,settings,stream=load(args.project)
    report=dict(status='READ_ONLY_COMPACT_RELEASE_REVIEW',build=BUILD,package=package,observations=[],
        complete=True,
        database_modified=False,workers_restarted=False,source_contacted=False,
        limitations=['Recent bounded post-commit measurements; not labeled detection accuracy.',
            'Throughput requires at least three newly published forward windows.',
            'Operator samples omit raw Session, IP, tokens and payload values.'])
    db=None
    try:
        db=Store(settings['DATABASE'],schema=cfg.source_schema,application='release-review')
        db.conn.execute('SET default_transaction_read_only=on')
        for n in range(args.samples):
            observed=snapshot(db,cfg,stream,report['observations'][0] if n else None)
            report['observations'].append(observed)
            print(json.dumps(dict(status='READ_ONLY_RELEASE_PROGRESS',sample=n+1,build=BUILD,
                source_backlog_windows=observed['source_backlog_windows'],analysis_pending_windows=observed['analysis_pending_windows'],
                operator_cases=observed['operator_cases'],longitudinal_states=observed['longitudinal_states'])),flush=True)
            if n+1<args.samples:time.sleep(args.interval)
    except Exception as exc:
        report.update(complete=False,failure=dict(type=type(exc).__name__,sqlstate=getattr(exc,'sqlstate',None)))
    finally:
        if db:db.close()
    report['measurement']=dict(capacity_status='INSUFFICIENT_SAMPLES')
    if len(report['observations'])>=2:
        first,last=report['observations'][0],report['observations'][-1]
        seconds=(last['observed_ns']-first['observed_ns'])/1e9
        count=last['fresh_windows_since_first_observation']
        report['measurement']=dict(seconds=seconds,fresh_forward_windows=count,
            fresh_forward_windows_per_hour=count*3600/seconds if count>=3 and seconds>0 else None,
            capacity_status='OBSERVED_FORWARD_PROGRESS' if count>=3 else 'INSUFFICIENT_FRESH_WINDOWS',
            analysis_queue_change=last['analysis_pending_windows']-first['analysis_pending_windows'])
    output=args.project/'AnomalyDetection/reports'/('Compact_Release_Review_'+time.strftime('%Y%m%d_%H%M%S')+'.json')
    output.parent.mkdir(parents=True,exist_ok=True)
    output.write_text(json.dumps(report,ensure_ascii=False,indent=2),encoding='utf-8')
    print(json.dumps(dict(status=report['status'],output=str(output),measurement=report['measurement'],complete=report['complete'],database_modified=False)))
    return 0 if report['complete'] else 2


if __name__=='__main__':raise SystemExit(main())
