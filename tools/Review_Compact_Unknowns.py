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
    from compact_product.search import remaining_unknown_scope
    groups={}
    for status in ('WAITING','EXPIRED'):
        rows=db.execute(f'''WITH sample AS (SELECT behavior_id,status,first_seen_ns,deadline_ns,state
            FROM {schema}.pending_requests WHERE stream_id=%s AND status=%s
            ORDER BY updated_at_ns DESC LIMIT %s)
            SELECT p.behavior_id,p.status,p.first_seen_ns,p.deadline_ns,{projected_state()}
            FROM sample p''',(stream,status,limit)).fetchall()
        groups[status]=summarize(rows)
    predicate, params = remaining_unknown_scope(schema)
    latest=db.execute(f"""WITH recent AS MATERIALIZED (
        SELECT behavior_id,api,result_code,quality,observed_at_ns,features
        FROM {schema}.behaviors WHERE stream_id=%s
        ORDER BY observed_at_ns DESC,behavior_id DESC LIMIT %s)
        SELECT b.behavior_id,b.api,b.result_code,b.quality,b.observed_at_ns,
        features->>'service_key' AS service_key,features->>'service_binding' AS service_binding,
        ({predicate}) AS is_unknown FROM recent b ORDER BY observed_at_ns DESC,behavior_id DESC""",
        (stream,scan,*params)).fetchall()
    unknown=[r for r in latest if r['is_unknown']][:limit]
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


def inventory(db, schema, stream, *, page_size=128, progress=None):
    """Scan the installed sparse index once. Check evidence in bounded primary-key batches."""
    from psycopg import ClientCursor
    from compact_product.search import unknown_scope
    from compact_product.validation import verified_sql
    from compact_behavior.services import internal_proxies
    from compact_behavior.dispatch_evidence import verified_sql as provider_sql

    if not 1 <= page_size <= 256:
        raise ValueError('invalid_inventory_page_size')
    broad, args = unknown_scope()
    groups = {}
    scanned = 0
    started = last_update = time.monotonic()
    # Literal role arrays match the installed partial-index predicate even on
    # connections with prepared statements. Keep the cursor in the caller's snapshot.
    with ClientCursor(db) as cur:
        query = cur.mogrify(f"""SELECT b.behavior_id FROM {schema}.behaviors b
            WHERE b.stream_id=%s AND {broad} ORDER BY b.observed_at_ns,b.behavior_id""", (stream,*args))
    proxies = sorted(internal_proxies())
    with db.transaction(), db.cursor(name='compact_unknown_index_walk') as scan:
        scan.execute(query)
        while batch := scan.fetchmany(page_size):
            ids = [r['behavior_id'] for r in batch]
            rows = db.execute(f"""SELECT b.behavior_id,b.api,b.result_code,
                b.features->>'service_binding' AS binding,{verified_sql(schema)} AS validation_rejection,
                ({provider_sql(schema)}) AS provider_dispatch_verified
                FROM {schema}.behaviors b WHERE b.behavior_id=ANY(%s)
                AND NOT COALESCE(b.api=ANY(%s),false)""", (ids,proxies)).fetchall()
            for row in rows:
                key = tuple(row[k] for k in ('api','result_code','binding','validation_rejection','provider_dispatch_verified'))
                group = groups.setdefault(key, dict(api=key[0], result_code=key[1], binding=key[2],
                    validation_rejection=key[3], provider_dispatch_verified=key[4], requests=0, example=row['behavior_id']))
                group['requests'] += 1
                group['example'] = min(group['example'], row['behavior_id'])
            scanned += len(ids)
            now = time.monotonic()
            if progress and (scanned == len(ids) or now - last_update >= 5):
                progress(dict(status='READING_ROLE_INVENTORY', candidates_scanned=scanned,
                              elapsed_seconds=round(now-started,1), complete=False))
                last_update = now
        ordered = sorted(groups.values(), key=lambda g:(g['validation_rejection'], -g['requests'],
                         g['api'] or '', g['result_code'] or '', g['binding'] or ''))
        for offset in range(0, len(ordered), page_size):
            batch = ordered[offset:offset+page_size]
            examples = db.execute(f"""SELECT behavior_id,state->'raw_request_ids' AS ids
                FROM {schema}.behavior_payloads WHERE behavior_id=ANY(%s)""",
                ([g['example'] for g in batch],)).fetchall()
            by_id = {r['behavior_id']: r['ids'] for r in examples}
            for group in batch:
                group['example_source_request_ids'] = by_id.get(group['example'])
    return dict(status='READ_ONLY_ROLE_INVENTORY_COMPLETE',complete=True,candidates_scanned=scanned,
                remaining_unknown=sum(g['requests'] for g in ordered if not g['validation_rejection'] and not g['provider_dispatch_verified']),
                classified_validation_rejections=sum(g['requests'] for g in ordered if g['validation_rejection']),
                classified_provider_dispatches=sum(g['requests'] for g in ordered if g['provider_dispatch_verified']),
                groups=ordered,database_modified=False,workers_restarted=False,source_contacted=False)


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--project',type=Path,required=True)
    p.add_argument('--code-root',type=Path,required=True)
    p.add_argument('--limit',type=int,default=50)
    p.add_argument('--scan',type=int,default=500)
    p.add_argument('--inventory',action='store_true',help='Group every published unresolved candidate in one snapshot')
    a=p.parse_args();sys.path.insert(0,str(a.code_root.resolve()))
    from compact_product.config import load
    from compact_behavior.store import Store
    cfg,source,stream=load(a.project)
    db=Store(source['DATABASE'],schema=cfg.source_schema,application='unknown-review')
    try:
        db.conn.execute('SET default_transaction_read_only=on')
        db.conn.execute('SET statement_timeout=30000' if a.inventory else 'SET statement_timeout=8000')
        with db.conn.transaction():
            db.conn.execute('SET TRANSACTION ISOLATION LEVEL REPEATABLE READ, READ ONLY')
            report=(inventory(db.conn,cfg.source_schema,stream,
                    progress=lambda event: print(json.dumps(event), flush=True)) if a.inventory else
                    collect(db.conn,cfg.source_schema,stream,limit=a.limit,scan=a.scan))
    except Exception as exc:
        print(json.dumps(dict(status='READ_ONLY_REVIEW_INCOMPLETE',failure=type(exc).__name__,
            sqlstate=getattr(exc,'sqlstate',None),complete=False,database_modified=False)),flush=True)
        return 2
    finally:db.close()
    prefix='Compact_Role_Inventory_' if a.inventory else 'Compact_Unknown_Review_'
    output=a.project/'AnomalyDetection/reports'/(prefix+time.strftime('%Y%m%d_%H%M%S')+'.json')
    output.parent.mkdir(parents=True,exist_ok=True)
    output.write_text(json.dumps(report,ensure_ascii=False,indent=2,default=str),encoding='utf-8')
    summary = ({k:report[k] for k in ('remaining_unknown','classified_validation_rejections')} if a.inventory
               else dict(samples={k:v['sampled_requests'] for k,v in report['groups'].items()}))
    print(json.dumps(dict(status=report['status'],output=str(output),**summary,database_modified=False)))


if __name__=='__main__':raise SystemExit(main())
