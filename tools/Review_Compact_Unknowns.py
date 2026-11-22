"""Bounded, read-only classification samples; no payload/IP/UserAgent export."""
import argparse
from collections import Counter
import json
from pathlib import Path
import sys
import time


def projected_state(alias='p'):
    # JSON payload values never leave PostgreSQL. Paths are observations, not
    # assertions of the final service or a complete list of source CallPaths.
    return f"""{alias}.state->>'request_id' AS request_id,
        {alias}.state->'raw_request_ids' AS source_request_ids,
        {alias}.state->'apis' AS observed_apis,
        {alias}.state->'dispatch' AS dispatch_evidence,
        {alias}.state->'issues' AS extraction_notes,
        {alias}.state->'first_ns' AS first_observed_ns,
        {alias}.state->'last_ns' AS last_observed_ns,
        ARRAY(SELECT DISTINCT e->>'path' FROM jsonb_array_elements(
            COALESCE({alias}.state->'inputs','[]'::jsonb) || COALESCE({alias}.state->'outputs','[]'::jsonb)
            || COALESCE({alias}.state->'parse_errors','[]'::jsonb)) e
            WHERE e->>'path' IS NOT NULL ORDER BY 1) AS retained_paths,
        jsonb_array_length(COALESCE({alias}.state->'inputs','[]'::jsonb)) AS input_variants,
        jsonb_array_length(COALESCE({alias}.state->'outputs','[]'::jsonb)) AS output_variants"""


def summarize(rows):
    paths=Counter();notes=Counter()
    for r in rows:
        paths.update(set(r['retained_paths']) or ['NO_RETAINED_PATH'])
        notes.update(set(r.get('extraction_notes') or []) | set(r.get('quality') or []))
    return dict(sampled_requests=len(rows),retained_path_request_counts=dict(paths.most_common()),
        evidence_note_request_counts=dict(notes.most_common()),samples=rows)


def collect(db,schema,stream,*,limit=50,scan=500):
    if not 1<=limit<=100 or not limit<=scan<=1000:
        raise ValueError('bounded_sample_required')
    from compact_behavior.services import operation_role
    groups={}
    for status in ('WAITING','EXPIRED'):
        rows=db.execute(f'''WITH sample AS (SELECT behavior_id,status,first_seen_ns,deadline_ns,state
            FROM {schema}.pending_requests WHERE stream_id=%s AND status=%s
            ORDER BY updated_at_ns DESC LIMIT %s)
            SELECT p.behavior_id,p.status,p.first_seen_ns,p.deadline_ns,{projected_state()}
            FROM sample p''',(stream,status,limit)).fetchall()
        groups[status]=summarize(rows)
    latest=db.execute(f'''SELECT behavior_id,api,result_code,quality,observed_at_ns,
        features->>'service_key' AS service_key,features->>'service_binding' AS service_binding,
        features->'access_denied_attempt' AS access_denied_attempt
        FROM {schema}.behaviors WHERE stream_id=%s
        ORDER BY observed_at_ns DESC,behavior_id DESC LIMIT %s''',(stream,scan)).fetchall()
    unknown=[r for r in latest if operation_role(r['api'],r['service_key'],r['service_binding'])=='unknown'
        and not (r['api']=='Services.v1/InvoiceRegister' and (r.get('result_code')=='GR0004' or (r.get('result_code')=='G00010' and (r.get('access_denied_attempt') or {}).get('verified') is True)))][:limit]
    if unknown:
        records=db.execute(f'''SELECT p.behavior_id,{projected_state()}
            FROM {schema}.behavior_payloads p WHERE p.behavior_id=ANY(%s)''',([r['behavior_id'] for r in unknown],)).fetchall()
        metadata={r['behavior_id']:r for r in records}
        for row in unknown:
            row.update(metadata.get(row['behavior_id'],{}))
            row.setdefault('retained_paths',[])
            row['detail_path']='/behaviors/'+row['behavior_id']
    groups['UNKNOWN_BEHAVIORS']=summarize(unknown)
    return dict(status='READ_ONLY_UNKNOWN_REVIEW',groups=groups,recent_behaviors_scanned=len(latest),
        counters=db.execute(f'SELECT * FROM {schema}.queue_counts WHERE stream_id=%s',(stream,)).fetchone(),
        database_modified=False,workers_restarted=False,source_contacted=False,
        limitations=['Latest bounded samples, not population totals or a random sample.',
            'Retained paths omit source CallPaths that were not extracted; empty paths require source lookup.',
            'No payload values, IP, UserAgent or original Session IDs are exported.',
            'Request IDs are included for owner-authorized lookup in Elasticsearch.',
            'Unknown behavior roles and pending API absence are different classifications.'])


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--project',type=Path,required=True)
    p.add_argument('--code-root',type=Path,required=True)
    p.add_argument('--limit',type=int,default=50)
    p.add_argument('--scan',type=int,default=500)
    a=p.parse_args();sys.path.insert(0,str(a.code_root.resolve()))
    from compact_product.config import load
    from compact_behavior.store import Store
    cfg,source,stream=load(a.project)
    db=Store(source['DATABASE'],schema=cfg.source_schema,application='unknown-review')
    try:
        db.conn.execute('SET default_transaction_read_only=on')
        db.conn.execute('SET statement_timeout=8000')
        with db.conn.transaction():
            db.conn.execute('SET TRANSACTION ISOLATION LEVEL REPEATABLE READ, READ ONLY')
            report=collect(db.conn,cfg.source_schema,stream,limit=a.limit,scan=a.scan)
    finally:db.close()
    output=a.project/'AnomalyDetection/reports'/('Compact_Unknown_Review_'+time.strftime('%Y%m%d_%H%M%S')+'.json')
    output.parent.mkdir(parents=True,exist_ok=True)
    output.write_text(json.dumps(report,ensure_ascii=False,indent=2,default=str),encoding='utf-8')
    print(json.dumps(dict(status=report['status'],output=str(output),
        samples={k:v['sampled_requests'] for k,v in report['groups'].items()},database_modified=False)))


if __name__=='__main__':main()
