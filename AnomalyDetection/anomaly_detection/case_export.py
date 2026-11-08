r"""Export ALL persisted AD cases and their evidence for review; no model runs.

Run with the existing project Python:
  python Collect_Anomaly_Case_Review.py --project C:\path\to\pishkhan24

Creates one ZIP under AnomalyDetection/reports. No install, worker restart,
schema changes, baseline changes, feedback, Viewer reads, raw logs or credentials
are exported. Database access uses the existing AD role in a read-only snapshot.
Read/time/size limits are explicit: a partial export is labelled PARTIAL.
"""
from __future__ import annotations
import argparse
from datetime import datetime,timezone
import hashlib
import json
from pathlib import Path
import sys
import time
import uuid
import zipfile

VERSION='AD-CASE-REVIEW-20261106-06'
FIVE_NS=300_000_000_000
ROLE='p24_anomaly_detection'
SCHEMA='anomaly_detection'
REQ='(SELECT DISTINCT request_key FROM anomaly_detection.adp_case_requests)'
SCOPES='(SELECT DISTINCT job_session AS session_key,target_ns FROM anomaly_detection.adp_case_signals WHERE job_session IS NOT NULL)'


def datasets():
    from anomaly_detection.case_summary import CURRENT_SIGNAL_SQL
    # Fixed SELECTs against AD only. All cases/states are included, not a sample
    # of 16 or a single browser page. Membership is deduplicated for fact reads.
    tables=[
      ('case_counts','SELECT entity_type,state,issue_kind,service_path,COUNT(*) AS cases FROM anomaly_detection.adp_cases GROUP BY entity_type,state,issue_kind,service_path',()),
      ('cases',"SELECT c.*,EXISTS(SELECT 1 FROM anomaly_detection.adp_case_signals s JOIN anomaly_detection.adp_jobs j ON j.session_key=s.job_session AND j.target_ns=s.target_ns WHERE s.source_kind='actor' AND s.case_key=c.case_key AND s.state<>'WITHDRAWN' AND (CASE WHEN s.primary_version IS NOT NULL THEN j.primary_version<>s.primary_version ELSE j.dirty OR j.version<>s.job_version END)) AS stale_actor_input,EXISTS(SELECT 1 FROM anomaly_detection.adp_case_signals s JOIN anomaly_detection.adp_population_jobs j ON s.source_kind='population' AND j.start_ns=s.target_ns WHERE s.case_key=c.case_key AND s.state<>'WITHDRAWN' AND (j.dirty OR j.version<>s.job_version)) AS stale_population_input FROM anomaly_detection.adp_cases c ORDER BY c.case_key",()),
      ('case_signals',"SELECT s.*,"+CURRENT_SIGNAL_SQL+" AS current_method_input FROM anomaly_detection.adp_case_signals s LEFT JOIN anomaly_detection.adp_jobs j ON s.source_kind='actor' AND j.session_key=s.job_session AND j.target_ns=s.target_ns LEFT JOIN anomaly_detection.adp_population_jobs p ON s.source_kind='population' AND p.start_ns=s.target_ns LEFT JOIN anomaly_detection.adp_scenario_jobs fj ON fj.scope_key=s.scope_key AND s.source_kind='feature' ORDER BY s.case_key,s.signal_key",()),
      ('case_members','SELECT * FROM anomaly_detection.adp_case_requests ORDER BY case_key,signal_key,request_key',()),
      ('case_versions','SELECT * FROM anomaly_detection.adp_case_versions ORDER BY case_key,revision',()),
      ('case_feedback','SELECT * FROM anomaly_detection.adp_case_feedback ORDER BY id',()),
      ('case_lifecycle','SELECT * FROM anomaly_detection.adp_case_lifecycle ORDER BY case_key',()),
      ('case_jobs','SELECT j.*,w.body AS window_body,sw.complete AS window_complete,sw.source AS source_proof FROM '+SCOPES+' s JOIN LATERAL (SELECT j.* FROM anomaly_detection.adp_jobs j WHERE j.session_key=s.session_key AND j.target_ns=s.target_ns LIMIT 1) j ON TRUE LEFT JOIN LATERAL (SELECT w.body FROM anomaly_detection.adp_windows w WHERE w.session_key=j.session_key AND w.start_ns=j.target_ns LIMIT 1) w ON TRUE LEFT JOIN anomaly_detection.adp_source_windows sw ON sw.start_ns=j.target_ns ORDER BY j.session_key,j.target_ns',()),
      ('case_findings','SELECT f.* FROM '+SCOPES+' s JOIN anomaly_detection.adp_findings f USING(session_key,target_ns) ORDER BY f.finding_key',()),
      ('finding_versions','SELECT v.* FROM anomaly_detection.adp_finding_versions v WHERE EXISTS(SELECT 1 FROM anomaly_detection.adp_case_signals s WHERE s.signal_key=v.finding_key) ORDER BY v.finding_key,v.revision',()),
      ('case_models',"SELECT m.* FROM anomaly_detection.adp_models m WHERE m.model_id IN (SELECT f.body::jsonb->>'model_id' FROM anomaly_detection.adp_findings f JOIN "+SCOPES+" s USING(session_key,target_ns) UNION SELECT s.body::jsonb->>'model_id' FROM anomaly_detection.adp_case_signals s) ORDER BY m.model_id",()),
      ('case_facts','SELECT k.request_key AS referenced_request_key,f.* FROM '+REQ+' k LEFT JOIN LATERAL (SELECT f.* FROM anomaly_detection.adp_facts f WHERE f.request_key=k.request_key LIMIT 1) f ON TRUE ORDER BY k.request_key',()),
      ('fact_versions','SELECT v.* FROM '+REQ+' k JOIN anomaly_detection.adp_versions v USING(request_key) ORDER BY v.request_key,v.id',()),
      ('case_journeys','SELECT j.* FROM '+REQ+' k JOIN anomaly_detection.adp_journeys j USING(request_key) ORDER BY j.request_key',()),
      ('viewer_relations','SELECT v.* FROM anomaly_detection.adp_viewer_relations v WHERE v.origin_request IN (SELECT request_key FROM '+REQ+' q) OR v.from_request IN (SELECT request_key FROM '+REQ+' q) OR v.to_request IN (SELECT request_key FROM '+REQ+' q) ORDER BY v.origin_request,v.from_request,v.to_request,v.basis,v.identity_key',()),
      ('legacy_incidents','SELECT i.* FROM '+SCOPES+' s JOIN anomaly_detection.adp_incidents i USING(session_key,target_ns) ORDER BY i.incident_key',()),
      ('legacy_feedback','SELECT b.* FROM anomaly_detection.adp_feedback b JOIN anomaly_detection.adp_incidents i USING(incident_key) JOIN '+SCOPES+' s USING(session_key,target_ns) ORDER BY b.id',()),
      ('source_windows','SELECT * FROM anomaly_detection.adp_source_windows ORDER BY start_ns',()),
      ('population_job_summary','SELECT dirty,COUNT(*) AS jobs,MIN(start_ns) AS earliest_target_ns,MAX(start_ns) AS latest_target_ns,COUNT(*) FILTER(WHERE processed_version=version) AS matching_version FROM anomaly_detection.adp_population_jobs GROUP BY dirty',()),
      ('population_summaries',"SELECT * FROM anomaly_detection.adp_population WHERE service_path='*' OR service_path IN (SELECT DISTINCT service_path FROM anomaly_detection.adp_cases) ORDER BY service_path,start_ns",()),
      ('population_service_coverage',"SELECT service_path,COUNT(*) AS windows,COUNT(*) FILTER(WHERE body::jsonb->>'covered'='true') AS covered_windows,MIN(start_ns) AS first_ns,MAX(start_ns) AS last_ns FROM anomaly_detection.adp_population GROUP BY service_path",()),
      ('family_readiness',"SELECT d->>'family' AS family,d->>'status' AS status,d->>'reason' AS reason,(NOT j.dirty AND j.version=j.processed_version) AS current_evaluation,COUNT(*) AS decisions FROM (SELECT dirty,version,processed_version,evaluation FROM anomaly_detection.adp_jobs WHERE last_evaluated_ns IS NOT NULL ORDER BY last_evaluated_ns DESC LIMIT 512) j CROSS JOIN LATERAL jsonb_array_elements(COALESCE(j.evaluation::jsonb->'decisions','[]'::jsonb)) d GROUP BY 1,2,3,4 ORDER BY 1,2,3,4",()),
      ('queue_summary','SELECT target_scope,dirty,COUNT(*) AS jobs,COUNT(*) FILTER(WHERE last_evaluated_ns IS NOT NULL) AS ever_evaluated,MIN(target_ns) AS first_ns,MAX(target_ns) AS last_ns FROM anomaly_detection.adp_jobs GROUP BY target_scope,dirty',()),
      ('migration_and_source_state',"SELECT name,body FROM anomaly_detection.adp_state WHERE name IN ('counters','source_binding','fresh_cursor','overlap_cursor','learning_cursor','older_learning_cursor','scope_repair_cursor','root_reference_import','job_scope_backfill_v1','job_scope_fast_promote_v1','stable_cases_backfill_v1','stable_cases_review_policy_v2','rate_history_requalification_v2','population_backfill_v1','assessed_recheck_pass_v1','priority_audit_size','regular_audit_size','candidate_audit_scope_v3','profile_active_scope_v1','profile_independent_sample_v1','scenario_traffic_cursor','scenario_old_traffic_cursor','scenario_schedule_v1','longitudinal_seed_v1') ORDER BY name",()),
      ('reference_sets','SELECT * FROM anomaly_detection.adp_http_reference_sets WHERE service_path IN (SELECT DISTINCT service_path FROM anomaly_detection.adp_cases) ORDER BY dataset_id',()),
      ('service_reference_points','SELECT * FROM anomaly_detection.adp_service_reference_points WHERE service_path IN (SELECT DISTINCT service_path FROM anomaly_detection.adp_cases) AND start_ns>=(SELECT COALESCE(MIN(target_ns),0) FROM anomaly_detection.adp_case_signals)-%s ORDER BY service_path,kind,start_ns,session_key',(56*288*FIVE_NS,)),
      ('http_reference_calls','SELECT c.* FROM anomaly_detection.adp_http_reference_calls c JOIN anomaly_detection.adp_http_reference_sets d USING(dataset_id) WHERE d.service_path IN (SELECT DISTINCT service_path FROM anomaly_detection.adp_cases) ORDER BY c.dataset_id,c.request_key',()),
      ('reference_dependencies','SELECT d.* FROM '+SCOPES+' s JOIN anomaly_detection.adp_peer_dependencies d USING(session_key,target_ns) ORDER BY d.session_key,d.target_ns,d.service_path',()),
      ('secondary_model_queue','SELECT r.* FROM anomaly_detection.adp_model_queue r JOIN '+SCOPES+' s USING(session_key,target_ns) ORDER BY r.due_ns,r.session_key,r.target_ns',()),
      ('scenario_jobs','SELECT * FROM anomaly_detection.adp_scenario_jobs ORDER BY target_ns,scope_key',()),
      ('scenario_service_samples','SELECT * FROM anomaly_detection.adp_service_profile_samples ORDER BY start_ns,service_path',()),
      ('scenario_profile_queue',"SELECT COUNT(*) AS tasks,MIN(due_ns) AS earliest_due_ns,MAX(attempts) AS max_attempts FROM anomaly_detection.adp_profile_tasks",()),
      ('scenario_profile_summary',"SELECT service_path,COUNT(*) AS profiles,COUNT(*) FILTER(WHERE body::jsonb->>'qualified'='true') AS qualified,MIN(at_ns) AS first_ns,MAX(at_ns) AS last_ns FROM anomaly_detection.adp_profiles GROUP BY service_path",()),
      ('case_request_profiles','SELECT p.* FROM '+REQ+' k JOIN anomaly_detection.adp_profiles p USING(request_key) ORDER BY p.request_key',()),
      ('case_profile_versions','SELECT p.* FROM '+REQ+' k JOIN anomaly_detection.adp_profile_versions p USING(request_key) ORDER BY p.request_key,p.observed_ns,p.id',()),
      ('scenario_traffic_counts','SELECT * FROM anomaly_detection.adp_traffic_counts WHERE service_path IN (SELECT DISTINCT service_path FROM anomaly_detection.adp_cases) ORDER BY service_path,start_ns',()),
      ('owned_index_inventory',"SELECT tablename,indexname,indexdef FROM pg_catalog.pg_indexes WHERE schemaname='anomaly_detection' AND tablename IN ('adp_windows','adp_facts','adp_jobs','adp_case_signals','adp_case_requests') ORDER BY tablename,indexname",()),
      ('owned_table_statistics',"SELECT relname,n_live_tup,n_dead_tup,last_analyze,last_autoanalyze FROM pg_catalog.pg_stat_user_tables WHERE schemaname='anomaly_detection' ORDER BY relname",()),
    ]
    heavy={'service_reference_points','http_reference_calls','case_journeys','fact_versions','case_profile_versions'}
    scenario={'scenario_jobs','scenario_service_samples','scenario_profile_queue','scenario_profile_summary','case_request_profiles'}
    first=tables[:3]
    return first+[x for x in tables if x[0] in scenario]+[x for x in tables[3:] if x[0] not in heavy|scenario]+[x for x in tables if x[0] in heavy]



class ExportLimit(Exception):pass


def compact(name,row):
    if name=='case_facts':
        fact=json.loads(row.get('details') or '{}')
        keep=('semantic','quality','transport','service_path','source_present','versions','input_subject')
        result={k:fact[k] for k in keep if k in fact}
        fields={'observations':('axis','value','qualified','at_ns','origin_key','version_key','callpath','raw_available','authority','stage','scope'),
          'evidence':('origin_key','version_key','at_ns','callpath','qualified','raw_available','origin_version_count'),
          'identifiers':('identity_key','type','kind','value','scope','issuer','origin_key','version_key','evidence_quality'),
          'relations':('edge_key','relation_type','from_typed_id','to_typed_id','kind','scope','usable','eligibility','evidence_origin','evidence_version','evidence_quality')}
        for axis,keys in fields.items():result[axis]=[{k:v[k] for k in keys if k in v} for v in fact.get(axis,[])]
        row['details']=json.dumps(result,ensure_ascii=False,separators=(',',':'))
    elif name=='fact_versions':
        row.pop('body',None)
    elif name in ('case_request_profiles','case_profile_versions'):
        value=json.loads(row.get('body') or '{}');value.pop('ip_display',None)
        row['body']=json.dumps(value,ensure_ascii=False,sort_keys=True,separators=(',',':'))
    elif name=='case_journeys':
        value=json.loads(row.get('body') or '{}');journey=value.get('journey') or {}
        row['body']=json.dumps({'quality':value.get('quality'),'semantic':value.get('semantic'),
          'journey':{k:journey[k] for k in ('edges','truncated','coverage_caveats','request_keys','root_request_key','max_requests') if k in journey}},ensure_ascii=False)
    return row


def local_metadata(root):
    release=json.loads((root/'RELEASE_MANIFEST.json').read_text(encoding='utf-8'))
    bad=[]
    for name,expected in release.get('files_sha256',{}).items():
        if name.startswith('anomaly_detection/') or name in ('run_anomaly.py','Install_Update.py'):
            p=(root/name).resolve()
            if not p.is_relative_to(root) or not p.is_file() or hashlib.sha256(p.read_bytes()).hexdigest()!=expected:bad.append(name)
    result={'build_id':release.get('build_id'),'source_sha256':release.get('source_sha256'),
            'production_source_mismatches':bad,'production_source_matches_manifest':not bad}
    path=root/'reports/product_status.json'
    if path.is_file():
        status=json.loads(path.read_text(encoding='utf-8'))
        result['worker_status_at_file_read']={k:v for k,v in status.items() if k not in
            ('instance_token','command','arguments','executable','pid','parent_pid','owner')}
    return result


def collect(raw,archive,metadata,*,seconds=60,max_bytes=256*1024*1024):
    started=time.monotonic();used=0
    result={'collector':VERSION,'observed_at_utc':datetime.now(timezone.utc).isoformat(),
        'selection':'ALL_PERSISTED_CASES_ALL_STATES_NOT_A_PAGE_OR_16_CASE_SAMPLE',
        'models_executed':False,'database_modified':False,'viewer_live_reads':False,
        'credentials_included':False,'raw_logs_included':False,
        'client_ip_display_values_omitted':True,
        'projection':'ALL_FACT_KEYS_AND_QUALIFICATION_METADATA; RAW_PAYLOADS_AND_FULL_FACT_HISTORY_BODIES_OMITTED; PROFILE_HISTORY_IS_PROJECTED_FEATURES',
        'source_evidence':'PERSISTED_AD_FACTS_AND_DELEGATED_VIEWER_SNAPSHOTS_NOT_A_FRESH_RAW_AUDIT',
        'family_readiness_scope':'LATEST_512_EVALUATED_JOBS_NOT_WHOLE_POPULATION',
        'limits':{'seconds':seconds,'uncompressed_dataset_bytes':max_bytes},'installed':metadata,'datasets':[]}
    with raw.transaction():
        raw.execute('SET TRANSACTION ISOLATION LEVEL REPEATABLE READ, READ ONLY')
        identity=dict(raw.execute("SELECT current_database() AS database,current_user AS role,current_setting('transaction_read_only') AS read_only,current_setting('transaction_isolation') AS isolation").fetchone())
        if identity['read_only']!='on':raise RuntimeError('READ_ONLY_SNAPSHOT_REQUIRED')
        result['snapshot']=identity
        for number,(name,sql,args) in enumerate(datasets()):
            record={'name':name+'.jsonl','rows':0,'bytes':0,'complete':False};result['datasets'].append(record)
            if time.monotonic()-started>seconds:
                record['error']='EXPORT_TIME_LIMIT';break
            try:
                with raw.transaction():
                    with raw.cursor(name='ad_case_review_'+str(number)) as cursor,archive.open(record['name'],'w') as output:
                        cursor.execute(sql,args)
                        while True:
                            if time.monotonic()-started>seconds:raise ExportLimit('EXPORT_TIME_LIMIT')
                            rows=cursor.fetchmany(256)
                            if not rows:break
                            for row in rows:
                                encoded=(json.dumps(compact(name,dict(row)),ensure_ascii=False,default=str,separators=(',',':'))+'\n').encode()
                                if used+len(encoded)>max_bytes:raise ExportLimit('EXPORT_SIZE_LIMIT')
                                output.write(encoded);used+=len(encoded);record['rows']+=1;record['bytes']+=len(encoded)
                        record['complete']=True
            except Exception as exc:
                record['error']=str(exc) if isinstance(exc,ExportLimit) else 'READ_FAILED'
                record['exception_type']=type(exc).__name__;record['sqlstate']=getattr(exc,'sqlstate',None)
                if isinstance(exc,ExportLimit):break
    result['status']='COMPLETE_READ_ONLY_CASE_REVIEW' if len(result['datasets'])==len(datasets()) and all(r['complete'] for r in result['datasets']) else 'PARTIAL_READ_ONLY_CASE_REVIEW'
    result['export_seconds']=round(time.monotonic()-started,3);result['dataset_bytes']=used
    result['not_attempted']=[name+'.jsonl' for name,_,_ in datasets()[len(result['datasets']):]]
    archive.writestr('review_manifest.json',json.dumps(result,ensure_ascii=False,indent=2))
    return result


def main(project=None):
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--project',required=True,type=Path)
    project=Path(project) if project is not None else parser.parse_args().project
    root=(project.resolve()/'AnomalyDetection').resolve()
    if not __package__:sys.path.insert(0,str(root))
    try:
        metadata=local_metadata(root)
        saved=json.loads((root/'data/pg_credentials.local.json').read_text(encoding='utf-8'))
        params=dict(saved['connection'])
        if params.get('dbname')!='p24_design_viewer' or params.get('user')!=ROLE:raise RuntimeError('EXISTING_AD_ROLE_REQUIRED')
        for key in ('options','row_factory','autocommit','application_name','service','passfile'):params.pop(key,None)
        import psycopg
        from psycopg.rows import dict_row
        output=root/'reports'/('Anomaly_Case_Review_'+datetime.now(timezone.utc).strftime('%Y%m%d_%H%M%S')+'_'+uuid.uuid4().hex[:8]+'.zip')
        output.parent.mkdir(parents=True,exist_ok=True)
        params.update(connect_timeout=3,application_name=VERSION,autocommit=True,row_factory=dict_row,
            options='-c default_transaction_read_only=on -c statement_timeout=3000 -c lock_timeout=150 -c idle_in_transaction_session_timeout=10000 -c search_path=anomaly_detection,pg_catalog -c max_parallel_workers_per_gather=0 -c work_mem=8MB -c jit=off')
        with psycopg.connect(**params) as raw,zipfile.ZipFile(output,'w',zipfile.ZIP_DEFLATED,compresslevel=6) as archive:
            result=collect(raw,archive,metadata)
        cases=next((r['rows'] for r in result['datasets'] if r['name']=='cases.jsonl'),0)
        print(json.dumps({'status':result['status'],'output':str(output),'cases_exported':cases,'database_modified':False,'models_executed':False},indent=2))
        return 0 if result['status']=='COMPLETE_READ_ONLY_CASE_REVIEW' else 2
    except Exception as exc:
        # Never print exception text: a driver/config error can contain secrets.
        print(json.dumps({'status':'REVIEW_EXPORT_FAILED','exception_type':type(exc).__name__,'sqlstate':getattr(exc,'sqlstate',None),'database_modified':False}))
        return 1


if __name__=='__main__':raise SystemExit(main())
