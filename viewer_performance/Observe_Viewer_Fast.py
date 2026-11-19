"""Observe committed windows with a verified, unchanged writer implementation.

No full-table oracle, ingestion, model evaluation or settings change. Missing
identity and journal gaps are explicit failures, never a capacity acceptance.
"""
import argparse
from collections import Counter
from datetime import datetime,timezone
import json
from pathlib import Path
import sys
import time
import uuid

SECOND=10**9
FIVE=300*SECOND


def ad_status(project):
    from viewer_performance.Run_Viewer_Index_Probe_UTF8 import run_utf8
    child=run_utf8([sys.executable,'-B',str(project/'AnomalyDetection/run_anomaly.py'),'worker-status'],timeout=15)
    value=json.loads(child.stdout)
    owner=(value.get('process') or {}).get('owner') or {};worker=value.get('worker') or {};stats=worker.get('statistics',{})
    expected=json.loads((project/'AnomalyDetection/RELEASE_MANIFEST.json').read_text(encoding='utf-8-sig'))
    installed_match=all(owner.get(k)==expected.get(k) for k in ('build_id','source_sha256'))
    fresh=bool(not child.returncode and value.get('running') and value.get('observation_matches_process')
        and installed_match and type(value.get('heartbeat_age_seconds')) in (int,float) and value['heartbeat_age_seconds']<=30)
    return dict(identity={k:owner.get(k) for k in ('pid','instance_token','build_id','source_sha256')},
        fresh_and_verified=fresh,running=value.get('running'),observation_matches_process=value.get('observation_matches_process'),
        matches_installed_release=installed_match,installed_ad_identity={k:expected.get(k) for k in ('build_id','source_sha256')},
        status_read_exit_code=child.returncode,diagnostic_failure=value.get('failure'),
        heartbeat_age_seconds=value.get('heartbeat_age_seconds'),state=value.get('health',value.get('status')),
        heartbeat_ns=worker.get('heartbeat_ns'),phase=worker.get('phase'),
        input_contract=worker.get('input_contract'),input_contract_check=worker.get('input_contract_check'),
        behavior_scope_migration=worker.get('behavior_scope_migration'),
        counters={k:worker.get(k) for k in ('evaluated_jobs','scenario_evaluations','source_pages',
            'audited_requests','source_attempts','owned_apply_failures_total','scenario_failures_total',
            'source_failures_total','evaluation_timeouts_total')},
        window_lanes=worker.get('window_lanes',{}),statistics_at_ns=worker.get('statistics_at_ns'),
        statistics_status=worker.get('statistics_status'),
        jobs=stats.get('jobs'),population_queue=stats.get('population_queue'),
        latest_failures={k:worker.get(k) for k in ('last_source_failure','last_storage_failure','last_scenario_failure',
            'last_source_failure_event','last_owned_apply_failure_event','last_evaluation_failure_event','last_fatal_failure')},
        pending_counts_are_worker_cached_statistics=True)


def prefix_snapshot(reader):
    try:
        present=reader.rows("SELECT to_regclass('public.viewer_history_replay_state') IS NOT NULL AS present")[0]['present']
        if present:
            rows=reader.rows('SELECT next_ns,status FROM public.viewer_history_replay_state WHERE id=1')
            if rows and rows[0]['status']=='RUNNING':return dict(status='READ',source='committed_history_replay_prefix',next_ns=rows[0]['next_ns'])
        rows=reader.rows('SELECT next_ns FROM public.viewer_live_state WHERE id=1')
        return dict(status='READ',source='committed_live_prefix',next_ns=rows[0]['next_ns'])
    except Exception as exc:return dict(status='UNAVAILABLE',error_type=type(exc).__name__)


def ad_prefix_distance(source,ad):
    if (ad or {}).get('fresh_and_verified') is False:return None
    cursor=(ad or {}).get('window_lanes',{}).get('fresh_cursor',{}).get('cursor',{}).get('next_ns')
    return max(0,(source['next_ns']-cursor)//FIVE) if source.get('status')=='READ' and type(cursor)is int else None


def scope_snapshot(reader):
    try:
        rows=reader.rows('SELECT contract,epoch,state FROM public.viewer_product_scope WHERE id=1')
        return dict(status='READ',**rows[0]) if len(rows)==1 else dict(status='UNAVAILABLE')
    except Exception as exc:return dict(status='UNAVAILABLE',error_type=type(exc).__name__)


def scope_agreement(viewer,ad):
    contract=(ad or {}).get('input_contract') or {}
    if viewer.get('status')!='READ' or not contract:return 'UNAVAILABLE'
    return 'MATCH' if (viewer.get('state')=='READY' and contract.get('input_contract')==viewer.get('contract')
        and contract.get('scope_epoch')==viewer.get('epoch')) else 'MISMATCH'


class Measurement:
    def __init__(self,identity,sequence,started,baseline_generation=None):
        from viewer_performance.writer_identity import identity_key
        self.identity=identity_key(identity);self.sequence=sequence;self.started=started
        self.rows=[];self.failure=None
        self.first_seen=None;self.last_seen=None
        self.baseline_generation=baseline_generation

    def add(self,identity,rows,observed=None):
        from viewer_performance.writer_identity import identity_key
        if identity_key(identity)!=self.identity:
            self.failure='WRITER_IMPLEMENTATION_OR_PROCESS_CHANGED';return
        for row in rows:
            if row['sequence']<=self.sequence:continue
            if row['sequence']!=self.sequence+1:
                self.failure='WRITER_JOURNAL_GAP';return
            self.sequence=row['sequence']
            if row['status']!='PUBLISHED':
                self.failure='PUBLICATION_FAILURE_DURING_MEASUREMENT';return
            if self.baseline_generation is not None and row['generation']<=self.baseline_generation:
                continue
            if len(self.rows)>=10000:
                self.failure='OBSERVATION_PUBLICATION_BUDGET_EXCEEDED';return
            self.rows.append(row)
            if row.get('new_complete_window') and observed is not None:
                if self.first_seen is None:self.first_seen=observed
                self.last_seen=observed

    def summary(self,elapsed):
        # Count only actual receipts generated after the baseline. Skip and
        # staged windows never enter this journal; first completion may have
        # begun before observation and is excluded from cycle timing.
        fresh=[r for r in self.rows if r.get('new_complete_window')]
        timed=fresh[1:]
        total=sum(r['receive_through_commit_seconds'] for r in timed)
        writes=Counter()
        for row in timed:
            for table,value in row['writes'].items():writes[table]+=value['seconds']
        shares={table:seconds/total for table,seconds in writes.items()} if total else {}
        write_share=sum(shares.values())
        return dict(status='INVALID' if self.failure else 'FRESH_COMMIT_OBSERVATION' if len(timed)>=2 else 'INSUFFICIENT_FRESH_COMMITS',failure=self.failure,
            new_evidence_windows=len(fresh),new_evidence_history_windows=sum(r['mode']=='manual_recheck' for r in fresh),
            newly_complete_windows=len(fresh),publications_with_new_evidence=sum((r.get('new_events') or 0)>0 for r in self.rows),
            other_publications=len(self.rows)-len(fresh),observation_seconds=elapsed,
            committed_new_windows_per_observed_hour=len(fresh)*3600/elapsed if elapsed else None,
            complete_timed_cycles=len(timed),receive_through_commit_seconds=total,
            steady_cycle_windows_per_hour=len(timed)*3600/total if total else None,
            observed_steady_commit_windows_per_hour=(len(fresh)-1)*3600/(self.last_seen-self.first_seen)
                if self.first_seen is not None and self.last_seen>self.first_seen else None,
            observed_commit_timing_has_polling_uncertainty=True,
            publisher_timer_excludes_between_cycle_idle=True,
            capture_seconds=sum(r['capture_seconds'] for r in timed),
            commit_seconds=sum(r['commit_seconds'] for r in timed),
            final_write_seconds_by_table=dict(writes),final_write_share_by_table=shares,
            ideal_speedup_if_only_measured_final_writes_became_free=1/(1-write_share) if 0<=write_share<1 else None,
            final_write_instrumentation_scope='COPY/INSERT stage-to-permanent calls; not all UPDATE/DELETE/index maintenance',
            pending_ad_counts_are_not_proven_by_viewer_speed=True,capacity_acceptance='NOT_ASSIGNED')


def collect(project,reader,*,seconds,target=0,clock=time.monotonic,wait=time.sleep,ad=ad_status,progress=lambda value:None):
    from viewer_performance.fast_writer import verify_sources,BUILD,BASE_RUNTIME
    from viewer_performance.writer_identity import (LEASE_SQL,read_identity,recent_publications,identity_key)
    source=verify_sources(project)
    guard=reader.rows("SELECT current_database() AS database,current_setting('transaction_read_only') AS read_only")
    if guard!=[dict(database='p24_design_viewer',read_only='on')]:raise ValueError('read_only_database_guard_failed')
    def current():
        receipt=read_identity(project,reader.rows(LEASE_SQL))
        if (receipt['implementation_source_sha256']!=source or receipt['implementation_build']!=BUILD
                or receipt['canonical_runtime_source_sha256']!=BASE_RUNTIME):
            raise ValueError('running_writer_is_not_installed_implementation')
        return receipt
    ad_samples=[];ad_issues=set()
    def read_ad():
        try:value=ad(project)
        except Exception as exc:value=dict(fresh_and_verified=False,identity={},counters={},
            state='STATUS_READ_FAILED',diagnostic_failure={'error_type':type(exc).__name__})
        ad_samples.append(dict(observed_monotonic=clock(),value=value))
        if value.get('fresh_and_verified') is False:ad_issues.add('AD_HEARTBEAT_OR_IDENTITY_UNVERIFIED')
        return value
    identity=current();before=read_ad();prefix_before=prefix_snapshot(reader);scope_before=scope_snapshot(reader);old=recent_publications(project,identity)
    generation=reader.rows('SELECT generation FROM public.viewer_live_state WHERE id=1')[0]['generation']
    began=clock();measurement=Measurement(identity,old[-1]['sequence'] if old else 0,began,generation)
    samples=[];activity=Counter();failure=None;last_ad=before;next_ad=began+60
    from AnomalyDetection.validation.observe_viewer_live import ACTIVITY_SQL,activity_rows,source_inventory
    _,names=source_inventory(project)
    while True:
        try:
            now=current();rows=recent_publications(project,now)
            for row in rows:
                if row['sequence']<=measurement.sequence or row['status']!='PUBLISHED':continue
                saved=reader.rows('SELECT generation,records,new_events FROM public.viewer_live_receipts '
                    'WHERE start_ns=%s AND end_ns=%s AND generation=%s AND mode=%s',
                    (row['start_ns'],row['end_ns'],row['generation'],row['mode']))
                if saved!=[{k:row[k] for k in ('generation','records','new_events')}]:
                    raise ValueError('writer_metric_has_no_matching_committed_database_receipt')
            measurement.add(now,rows,observed=clock())
            if verify_sources(project)!=source:raise ValueError('installed_writer_changed')
            if clock()>=next_ad:
                last_ad=read_ad();next_ad=clock()+60
                if last_ad.get('identity')!=before.get('identity'):ad_issues.add('AD_INSTANCE_CHANGED')
            snapshot=activity_rows(reader.rows(ACTIVITY_SQL),names)
            # Compact uniform-time samples; no SQL/key/body export and no full
            # table scans. Bound memory for the eight-hour maximum.
            publisher=[s for s in snapshot['sessions'] if s['workload']=='VIEWER_PUBLISHER']
            for item in publisher:
                q=item.get('statement',{});key=(q.get('operation'),tuple(q.get('relations',[])))
                activity[key]+=1
            samples.append(dict(elapsed_seconds=round(clock()-began,3),publisher=publisher))
        except Exception as exc:
            failure=str(exc) if isinstance(exc,ValueError) else type(exc).__name__;break
        if measurement.failure or target and sum(bool(r.get('new_complete_window')) for r in measurement.rows)>=target or clock()-began>=seconds:break
        progress(dict(status='OBSERVING_VERIFIED_WRITER',elapsed_seconds=round(clock()-began,1),
            committed_windows=len(measurement.rows),implementation_source_sha256=source))
        wait(min(5,max(0,seconds-(clock()-began))))
    try:
        after=read_ad()
        if after.get('identity')!=before.get('identity'):ad_issues.add('AD_INSTANCE_CHANGED')
        # Revalidate after the final AD call as well: a process replacement at
        # the end must not turn into an accepted same-implementation result.
        if identity_key(current())!=identity_key(identity):failure='writer_changed_at_observation_end'
    except Exception as exc:
        after=None;failure=str(exc) if isinstance(exc,ValueError) else type(exc).__name__
    summary=measurement.summary(clock()-began)
    if failure:summary.update(status='INVALID',failure=failure)
    prefix_after=prefix_snapshot(reader)
    scope_after=scope_snapshot(reader)
    agreements=dict(before=scope_agreement(scope_before,before),after=scope_agreement(scope_after,after))
    if any(value!='MATCH' for value in agreements.values()):ad_issues.add('INPUT_CONTRACT_UNVERIFIED_OR_CHANGED')
    comparable=bool(after and not ad_issues and before.get('identity')==after.get('identity'))
    return dict(status='PARTIAL_VERIFIED_WRITER_OBSERVATION' if summary['failure'] or ad_issues else 'VERIFIED_WRITER_OBSERVATION',
        database_modified=False,workers_restarted=False,writer_identity=identity,throughput=summary,
        baseline_generation=generation,
        publication_receipts=measurement.rows,
        viewer_scope_before=scope_before,viewer_scope_after=scope_after,input_contract_agreement=agreements,
        ad_observation_status='DEGRADED_OR_UNVERIFIABLE' if ad_issues else 'STABLE_VERIFIED_PROCESS',
        ad_observation_issues=sorted(ad_issues),ad_samples=ad_samples,
        ad_before=before,ad_after=after,ad_progress_delta={k:after['counters'][k]-v
            for k,v in before['counters'].items() if comparable and type(v)is int and type(after['counters'].get(k))is int},
        samples=samples,final_write_samples=[dict(operation=k[0],relations=k[1],samples=v) for k,v in activity.items()],
        source_prefix_before=prefix_before,source_prefix_after=prefix_after,
        ad_fresh_prefix_distance_windows_before=ad_prefix_distance(prefix_before,before),
        ad_fresh_prefix_distance_windows_after=ad_prefix_distance(prefix_after,after),
        full_table_oracles_executed=False,eight_hour_acceptance='NOT_ASSIGNED',
        ad_backlog_acceptance='NOT_ASSIGNED_CACHED_COUNTS_REQUIRE_SEPARATE_REVIEW')


def main(argv=None):
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--project',type=Path,required=True)
    parser.add_argument('--seconds',type=int,default=3600)
    parser.add_argument('--windows',type=int,default=0)
    args=parser.parse_args(argv);project=args.project.resolve();sys.path.insert(0,str(project))
    if not 5<=args.seconds<=28800 or not 0<=args.windows<=1200:parser.error('seconds 5..28800; windows 0..1200')
    try:
        import psycopg
        from psycopg.rows import dict_row
        from viewer_performance.Qualify_Capacity_Candidate import literal_database
        from AnomalyDetection.validation.observe_viewer_live import Reader,connection_parameters
        from p24_foundation.viewer_runtime import atomic_json
        last=[0.]
        def progress(value):
            if value['elapsed_seconds']-last[0]>=15:
                print(json.dumps(value),flush=True);last[0]=value['elapsed_seconds']
        with psycopg.connect(**connection_parameters(literal_database(project)),autocommit=True,row_factory=dict_row) as connection:
            result=collect(project,Reader(connection),seconds=args.seconds,target=args.windows,progress=progress)
        output=project/'AnomalyDetection/reports'/('Viewer_Verified_Capacity_'+datetime.now(timezone.utc).strftime('%Y%m%d_%H%M%S_')+uuid.uuid4().hex[:8]+'.json')
        atomic_json(output,result)
        print(json.dumps(dict(status=result['status'],output=str(output),throughput=result['throughput'])),flush=True)
        return 0 if result['status']=='VERIFIED_WRITER_OBSERVATION' else 2
    except Exception as exc:
        print(json.dumps(dict(status='WRITER_OBSERVATION_BLOCKED',error_type=type(exc).__name__,
            code=str(exc) if isinstance(exc,ValueError) else None,database_modified=False,workers_restarted=False)))
        return 2


if __name__=='__main__':raise SystemExit(main())
