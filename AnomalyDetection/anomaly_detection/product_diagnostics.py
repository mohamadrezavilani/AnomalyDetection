"""Persisted queue diagnostics. SELECT only; never evaluate or warm a model."""
import json
import time
import re
import zipfile
from pathlib import Path

from . import BUILD_ID,FIVE_NS
from .process_control import safe_failure


FIELDS=('family','status','reason','model_id','service_path','observed','expected','upper','history_windows',
    'personal_history_windows','positive_history_windows','peer_qualified_windows','peer_session_epochs',
    'empirical_tail_rank','adjusted_empirical_tail_rank','comparison_count','screening_level','screening_policy',
    'calibration_status','baseline_unit','baseline_origin','single_signal_review_eligible','explanation_fa')


def read_queue(raw,now,targets=()):
    latest=raw.execute('SELECT start_ns,complete FROM anomaly_detection.adp_source_windows '
        'WHERE complete=TRUE ORDER BY start_ns DESC LIMIT 1').fetchone()
    latest_end=latest['start_ns']+FIVE_NS if latest else None
    columns='SELECT j.*,w.body AS window_body,sw.complete AS window_complete FROM anomaly_detection.adp_jobs j '
    joins='LEFT JOIN anomaly_detection.adp_windows w ON w.session_key=j.session_key AND w.start_ns=j.target_ns '
    joins+='LEFT JOIN anomaly_detection.adp_source_windows sw ON sw.start_ns=j.target_ns '
    pending=raw.execute(columns+joins+"WHERE j.target_scope='BEHAVIOR_TARGET' AND j.dirty=TRUE AND j.target_ns>=%s "
        'ORDER BY j.target_ns DESC,j.observed_count DESC NULLS LAST,j.session_key LIMIT 64',
        (max(FIVE_NS,now-72*FIVE_NS),)).fetchall()
    recent=raw.execute(columns+joins+'WHERE j.last_evaluated_ns IS NOT NULL '
        'ORDER BY j.last_evaluated_ns DESC,j.target_ns DESC,j.session_key LIMIT 16').fetchall()
    def record(row):
        summary=json.loads(row['window_body']) if row.get('window_body') else {}
        evaluation=json.loads(row['evaluation']) if row.get('evaluation') else {}
        current=bool(not row['dirty'] and row['processed_version']==row['version'])
        readiness=('WAITING_FOR_COMPLETE_WINDOW' if not row['window_complete'] else
            'PENDING_FIRST_EVALUATION' if row.get('last_evaluated_ns') is None else
            'RECHECK_REQUIRED' if not current else 'CURRENT_EVALUATION')
        if row.get('target_scope','BEHAVIOR_TARGET')=='COVERAGE_ONLY':readiness='COVERAGE_ONLY'
        elif 'target_scope' in row and row['target_scope'] is None and not current:readiness='SCOPE_PENDING'
        counts=summary.get('counts')
        return {'session_key':row['session_key'],'target_ns':row['target_ns'],
            'target_age_seconds':max(0,(now-row['target_ns']-FIVE_NS)/1e9),
            'window_complete':bool(row['window_complete']),'queue_state':readiness,
            'version':row['version'],'processed_version':row['processed_version'],'target_scope':row.get('target_scope','BEHAVIOR_TARGET'),
            'evaluation_current':current,'primary_input_current':row.get('primary_version') is not None and row['primary_version']==evaluation.get('primary_version'),
            'primary_version':row.get('primary_version'),'secondary_pending_families':evaluation.get('pending_families',[]),
            'primary_qualified_requests':evaluation.get('primary_qualified_requests'),'primary_expected_requests':evaluation.get('primary_expected_requests'),
            'last_evaluated_ns':row.get('last_evaluated_ns'),'due_ns':row['due_ns'],
            'counts_by_service':counts,'total_observed_executions':sum(counts.values()) if isinstance(counts,dict) else None,
            'waiting_reason':evaluation.get('reason'),
            'decisions':[{k:d[k] for k in FIELDS if k in d} for d in evaluation.get('decisions',[])]}
    cursors=raw.execute('SELECT name,body FROM anomaly_detection.adp_state WHERE name IN '
        "('fresh_cursor','overlap_cursor','learning_cursor','older_learning_cursor','scope_repair_cursor','root_reference_import','job_scope_backfill_v1','job_scope_fast_promote_v1','stable_cases_backfill_v1','stable_cases_review_policy_v2','rate_history_requalification_v2','rate_history_requalification_v3','population_backfill_v1','assessed_recheck_pass_v1')").fetchall()
    recent_targets=[]
    for session in sorted({s for s,at in targets})[:4]:
        recent_targets.extend((session,r['target_ns']) for r in raw.execute('SELECT target_ns FROM anomaly_detection.adp_jobs '
            "WHERE session_key=%s AND target_scope IS DISTINCT FROM 'COVERAGE_ONLY' ORDER BY target_ns DESC LIMIT 4",(session,)).fetchall())
    cases=[]
    for row in raw.execute('SELECT case_key,state,revision,body FROM anomaly_detection.adp_cases ORDER BY last_ns DESC,case_key DESC LIMIT 16').fetchall():
        value=json.loads(row['body']);strong=value.get('strongest',{})
        value['strongest']={k:strong[k] for k in ('family','reason','observed','expected','begin_ns','end_ns','duration_ns','evidence_verified','calibration_status') if k in strong}
        value['revision']=row['revision'];cases.append(value)
    return {'status':'READ_ONLY_PERSISTED_QUEUE','build_id':BUILD_ID,'observed_ns':now,'stable_cases_sample':cases,
        'latest_complete_owned_window_end_ns':latest_end,'pending_recent_sample':[record(r) for r in pending],
        'latest_evaluations_sample':[record(r) for r in recent],
        'tracked_tests':read_targets(raw,targets,record),
        'recent_tracked_session_windows':read_targets(raw,recent_targets,record),
        'cursors':{r['name']:json.loads(r['body']) for r in cursors},
        'pending_sample_limit':64,'latest_sample_limit':16,'samples_are_not_total_queue':True,
        'models_executed':False,'source_modified':False,'database_modified':False}


def tracked_targets(root):
    """Reuse the owner's exact-case report as diagnostic selection only.

    Nothing from this file is a training point, queue priority or model input.
    No service/session is hardcoded in the shipped detector.
    """
    paths=sorted((Path(root)/'reports').glob('exact_anomaly_cases_*.zip'),key=lambda p:p.stat().st_mtime,reverse=True)[:10]
    for path in paths:
        try:
            with zipfile.ZipFile(path) as z:
                if z.getinfo('exact_cases.json').file_size>256*1024:continue
                data=json.loads(z.read('exact_cases.json'))
            if data.get('scope')!='EXACT_OWNER_REPORTED_CASES_NOT_A_RANDOM_QUEUE_SAMPLE':continue
            targets=[]
            for row in data.get('cases',[])[:16]:
                s=row.get('session_key');at=row.get('target_ns')
                if isinstance(s,str) and re.fullmatch('[0-9a-f]{64}',s) and type(at) is int and 0<at<2**63 and at%FIVE_NS==0:
                    targets.append((s,at))
            return sorted(set(targets))
        except (OSError,ValueError,KeyError,zipfile.BadZipFile):continue
    return []


def read_targets(raw,targets,record):
    out=[]
    for session,target in targets[:16]:
        row=raw.execute('SELECT j.*,w.body AS window_body,sw.complete AS window_complete,i.state AS incident_state,'
            'i.incident_key,i.body AS incident_body FROM anomaly_detection.adp_jobs j '
            'LEFT JOIN anomaly_detection.adp_windows w ON w.session_key=j.session_key AND w.start_ns=j.target_ns '
            'LEFT JOIN anomaly_detection.adp_source_windows sw ON sw.start_ns=j.target_ns '
            'LEFT JOIN anomaly_detection.adp_incidents i ON i.session_key=j.session_key AND i.target_ns=j.target_ns '
            'WHERE j.session_key=%s AND j.target_ns=%s',(session,target)).fetchone()
        if row:
            item=record(row);item.update(job_found=True,observed_count=row['observed_count'],incident_state=row['incident_state'],incident_key=row['incident_key'])
            incident=json.loads(row['incident_body']) if row['incident_body'] else {}
            item['evidence_verified_at_last_incident']=incident.get('evidence_verified')
            item['target_evidence_priority_ready']=row.get('target_evidence_ready',False)
            quality=raw.execute('SELECT COUNT(*) AS active_eligible_facts,COUNT(details) AS audited_facts,'
                "COUNT(*) FILTER(WHERE details::jsonb->'quality'->>'evidence_available'='true' "
                "AND details::jsonb->'semantic'->>'revision'=revision::text "
                "AND details::jsonb->'semantic'->>'anchor_key'=anchor_key) AS matching_qualified_facts "
                'FROM anomaly_detection.adp_facts WHERE session_key=%s AND at_ns>=%s AND at_ns<%s '
                "AND state='active' AND eligible=TRUE AND source_present=TRUE",(session,target,target+FIVE_NS)).fetchone()
            item['fact_quality_counts']=dict(quality)
        else:item={'session_key':session,'target_ns':target,'job_found':False}
        out.append(item)
    return out


def snapshot(root):
    try:
        from .native_pg import database
        with database(root,readonly=True) as raw:
            return read_queue(raw,time.time_ns(),tracked_targets(root))
    except Exception as exc:
        return {'status':'QUEUE_READ_UNAVAILABLE','failure':safe_failure(exc),
            'models_executed':False,'database_modified':False}
