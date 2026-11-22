"""Read current compact DB state for previously inspected source RequestIDs only."""
import argparse
from collections import Counter
import json
from pathlib import Path
import re
import sys
import time
import uuid


def validate_reports(unknown,source,stream):
    if unknown.get('status')!='READ_ONLY_UNKNOWN_REVIEW' or source.get('status')!='READ_ONLY_SOURCE_EVIDENCE':
        raise ValueError('expected_unknown_and_source_reviews')
    if unknown.get('counters',{}).get('stream_id')!=stream:
        raise ValueError('review_stream_mismatch')
    original={r['request_id']:r for g in unknown['groups'].values() for r in g['samples']}
    samples=source.get('samples',[])
    if not 1<=len(samples)<=24:raise ValueError('bounded_source_samples_required')
    seen=set()
    for sample in samples:
        key=sample['request_id']
        if uuid.UUID(key).hex!=key or key not in original or key in seen:
            raise ValueError('source_sample_identity_mismatch')
        if len(sample.get('documents',[]))>256:raise ValueError('source_document_limit')
        seen.add(key)
    return original,samples


def collect(db,schema,ad_schema,stream,unknown,source):
    from compact_behavior import FIVE
    from compact_behavior.extract import behavior_id,instant
    from compact_behavior.services import operation_role,operation_catalog
    from compact_behavior.store import ALL
    if not re.fullmatch(r'p24_compact(?:_[a-z0-9_]{1,40})?',schema) or not re.fullmatch(r'p24_compact_ad_[a-z0-9_]{1,32}',ad_schema):
        raise ValueError('compact_schemas_required')
    original,samples=validate_reports(unknown,source,stream)
    keys={r['request_id']:behavior_id(stream,r['request_id']) for r in samples}
    bids=list(keys.values())
    behaviors=db.execute(f'''SELECT behavior_id,request_id,observed_at_ns,api,result_code,kind,quality,revision,
        features->>'service_key' AS service_key,features->>'service_binding' AS service_binding,
        features->>'behavior_policy_version' AS policy_version,features->>'operation_role' AS stored_role,
        features->'service_rate_eligible' AS service_rate_eligible,features->'session_eligible' AS session_eligible,
        features->'input_eligible' AS input_eligible,features->'output_eligible' AS output_eligible
        FROM {schema}.behaviors WHERE stream_id=%s AND behavior_id=ANY(%s)''',(stream,bids)).fetchall()
    pending=db.execute(f'''SELECT behavior_id,status,first_seen_ns,deadline_ns,updated_at_ns,
        state->'apis' AS observed_apis FROM {schema}.pending_requests
        WHERE stream_id=%s AND behavior_id=ANY(%s)''',(stream,bids)).fetchall()
    tombstones=db.execute(f'''SELECT behavior_id,expired_at_ns FROM {schema}.expired_fragments
        WHERE stream_id=%s AND behavior_id=ANY(%s)''',(stream,bids)).fetchall()
    behaviors={r['behavior_id']:r for r in behaviors};pending={r['behavior_id']:r for r in pending}
    tombstones={r['behavior_id']:r for r in tombstones};results=[];starts=set()
    for sample in samples:
        key=sample['request_id'];bid=keys[key];body=behaviors.get(bid);wait=pending.get(bid)
        windows=set()
        for name in ('first_observed_ns','last_observed_ns'):
            value=original[key].get(name)
            if type(value) is int:windows.add(value//FIVE*FIVE)
        completions=[]
        for doc in sample.get('documents',[]):
            if doc.get('http_completion'):
                at=instant(doc['timestamp']);windows.add(at//FIVE*FIVE)
                completions.append({k:doc.get(k) for k in ('timestamp','call_path','logged_result_code')})
        if body:
            body['current_rule_role']=operation_role(body['api'],body['service_key'],body['service_binding'])
            body['role_differs_from_current_rules']=body['stored_role']!=body['current_rule_role']
            if body['observed_at_ns'] is not None:windows.add(body['observed_at_ns']//FIVE*FIVE)
        location=('INCONSISTENT_BEHAVIOR_AND_PENDING' if body and wait else 'BEHAVIOR' if body else
                  wait['status'] if wait else 'PURGED_FRAGMENTS_NOTICE' if bid in tombstones else 'NOT_FOUND')
        results.append(dict(request_id=key,behavior_id=bid,review_group=sample.get('review_group'),
            current_location=location,behavior=body,pending=wait,expired_fragments_notice=tombstones.get(bid),
            source_coverage=sample['coverage'],source_apis=sample.get('recognized_apis',[]),
            source_completions=completions,window_starts_ns=sorted(windows)))
        starts.update(windows)
    if len(starts)>128:raise ValueError('sample_window_limit')
    window_rows=[]
    if starts:
        window_rows=db.execute(f'''SELECT w.start_ns,w.end_ns,w.revision AS publication_revision,
            w.first_published_ns,w.published_at_ns,
            r.revision AS analysis_revision,r.analyzed_at_ns,r.feature_version,r.model_version,
            r.timing_confirmed_revision,
            COALESCE(d.processed_version<d.version,false) AS dirty_pending,
            COALESCE(j.processed_version<j.version,false) AS reanalysis_pending
            FROM {schema}.windows w
            LEFT JOIN {ad_schema}.window_results r ON r.stream_id=w.stream_id AND r.start_ns=w.start_ns
            LEFT JOIN {schema}.dirty_windows d ON d.stream_id=w.stream_id AND d.start_ns=w.start_ns AND d.session_id=%s
            LEFT JOIN {ad_schema}.reanalysis j ON j.stream_id=w.stream_id AND j.start_ns=w.start_ns
            WHERE w.stream_id=%s AND w.start_ns=ANY(%s) ORDER BY w.start_ns''',(ALL,stream,sorted(starts))).fetchall()
    return dict(status='READ_ONLY_SAMPLE_RECONCILIATION',samples=results,
        locations=dict(Counter(r['current_location'] for r in results)),windows=window_rows,
        unpublished_window_starts_ns=sorted(starts-{r['start_ns'] for r in window_rows}),
        stream=db.execute(f'SELECT * FROM {schema}.streams WHERE stream_id=%s',(stream,)).fetchone(),
        counters=db.execute(f'SELECT * FROM {schema}.queue_counts WHERE stream_id=%s',(stream,)).fetchone(),
        current_rule_policy=operation_catalog()['policy_version'],
        database_modified=False,workers_restarted=False,source_contacted=False,
        limitations=['Point-in-time comparison of previously selected cases, not population totals.',
            'Source evidence is the earlier report, not a new Elasticsearch query.',
            'Window analysis presence does not prove every method was eligible or every anomaly correct.',
            'An older policy stamp alone is not evidence of an incorrect behavior.',
            'A recognized source root absent from storage needs investigation; this tool never republishes it.',
            'No Session, IP, UserAgent or payload values are exported.'])


def read_json(path):
    if path.stat().st_size>8*1024*1024:raise ValueError('review_file_limit')
    return json.loads(path.read_text(encoding='utf-8-sig'))


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    for name in ('project','code-root','unknown-review','source-review'):
        parser.add_argument('--'+name,type=Path,required=True)
    args=parser.parse_args();sys.path.insert(0,str(args.code_root.resolve()))
    from compact_product.config import load
    from compact_product.version import verify
    from compact_behavior.store import Store
    unknown,source=read_json(args.unknown_review),read_json(args.source_review)
    if source.get('input_review')!=args.unknown_review.name:raise ValueError('review_pair_mismatch')
    cfg,settings,stream=load(args.project);package=verify(args.code_root)
    validate_reports(unknown,source,stream)
    db=Store(settings['DATABASE'],schema=cfg.source_schema,application='sample-reconciliation')
    try:
        db.conn.execute('SET default_transaction_read_only=on')
        db.conn.execute('SET statement_timeout=8000')
        with db.conn.transaction():
            db.conn.execute('SET TRANSACTION ISOLATION LEVEL REPEATABLE READ, READ ONLY')
            result=collect(db.conn,cfg.source_schema,cfg.ad_schema,stream,unknown,source)
    finally:db.close()
    result.update(observed_at_utc=time.strftime('%Y-%m-%dT%H:%M:%SZ',time.gmtime()),
        diagnostic_package=package,unknown_review=args.unknown_review.name,source_review=args.source_review.name)
    output=args.project/'AnomalyDetection/reports'/('Compact_Sample_Reconciliation_'+time.strftime('%Y%m%d_%H%M%S')+'.json')
    output.parent.mkdir(parents=True,exist_ok=True)
    output.write_text(json.dumps(result,ensure_ascii=False,indent=2,default=str),encoding='utf-8')
    print(json.dumps(dict(status=result['status'],output=str(output),locations=result['locations'],
        database_modified=False,workers_restarted=False,source_contacted=False)),flush=True)


if __name__=='__main__':main()
