"""Bounded READ ONLY observation of the real history's negative-Origin probes.

Uniform synthetic 64-hex keys exercise the existing binary Origin index. No
Capture, source key, user identifier, row body or SQL text is exported. First
access is not called cold; repeated access is a local cache comparison, not a
publication throughput test or a working-set-pressure qualification.
"""
import argparse
import hashlib
from datetime import datetime,timezone
import json
from pathlib import Path
import secrets
import statistics
import sys
import time
import uuid


class ReadOnlyProbe:
    sqlite=False

    def __init__(self,connection):self.conn=connection
    def sql(self,statement,params=()):return self.conn.execute(statement.replace('?','%s'),params)
    def one(self,statement,params=()):return self.sql(statement,params).fetchone()


def owner(db):
    from viewer_performance.capacity.trace import signature
    rows=db.sql('''SELECT a.pid,a.backend_start::text AS backend_start,a.state,
        a.wait_event_type,a.wait_event,a.query,
        EXTRACT(EPOCH FROM clock_timestamp()-a.query_start)::double precision AS seconds
        FROM pg_locks l JOIN pg_stat_activity a ON a.pid=l.pid
        WHERE l.locktype='advisory' AND l.classid=240026 AND l.objid=1 AND l.objsubid=2
          AND l.granted AND a.datname=current_database()''').fetchall()
    result=[]
    for row in rows:
        row=dict(row);query=row.pop('query') or ''
        fingerprint,operation,relations=signature(query)
        result.append({**row,'fingerprint':fingerprint,'operation':operation,'relations':list(relations)})
    return result


def plan_summary(plan):
    keys={'Node Type','Relation Name','Index Name','Actual Rows','Actual Loops',
        'Shared Hit Blocks','Shared Read Blocks','Shared Dirtied Blocks',
        'Local Hit Blocks','Local Read Blocks','Temp Read Blocks','Temp Written Blocks'}
    def nodes(node):
        yield {k:v for k,v in node.items() if k in keys}
        for child in node.get('Plans',[]):yield from nodes(child)
    root=plan['Plan']
    return dict(execution_ms=plan['Execution Time'],planning_ms=plan['Planning Time'],
        returned_rows=root['Actual Rows'],shared_hit_blocks=root.get('Shared Hit Blocks',0),
        shared_read_blocks=root.get('Shared Read Blocks',0),nodes=list(nodes(root)))


def observe(config,*,seconds=20,pairs=16,batch_size=128,_qualification=False):
    import psycopg
    from psycopg.rows import dict_row
    from p24_foundation.viewer_origin_storage import origin_lookup_sql,active
    name=config.get('dbname','')
    if name!='p24_design_viewer' and not (_qualification and
            name.startswith('p24_design_capacity_') and name.endswith('_qualification')):
        raise ValueError('recorded_viewer_or_owned_test_database_required')
    if not 3<=seconds<=60 or not 1<=pairs<=16 or not 1<=batch_size<=128:
        raise ValueError('invalid_read_only_probe_budget')
    connection={k:config[k] for k in ('host','port','dbname','user','password') if k in config}
    connection.update(connect_timeout=3,options='-c default_transaction_read_only=on -c statement_timeout=1200 -c lock_timeout=100 -c jit=off',application_name='P24.Capacity.index-readonly')
    result=dict(status='READ_ONLY_INDEX_COST_OBSERVATION',database_modified=False,
        workers_restarted=False,synthetic_keys_exported=False,actual_user_keys_loaded=False,
        scope='this_read_only_probe_not_the_writer',physical_disk_reads_inferred=False,
        active_working_set_larger_than_effective_cache='NOT_ESTABLISHED',
        cold_cache='NOT_CONTROLLED',publication_capacity='NOT_MEASURED',samples=[],failures=[])
    began=time.perf_counter();deadline=began+seconds
    with psycopg.connect(**connection,autocommit=True,row_factory=dict_row) as raw:
        db=ReadOnlyProbe(raw)
        result['settings']=db.sql('''SELECT name,setting,unit FROM pg_settings
            WHERE name=ANY(?)''',(['server_version','shared_buffers','effective_cache_size',
                'default_transaction_read_only','statement_timeout','lock_timeout','track_io_timing'],)).fetchall()
        if db.one("SELECT current_setting('transaction_read_only') AS value")['value']!='on':
            raise ValueError('read_only_connection_not_active')
        result['binary_origin_layout']=active(db)
        result['catalog_estimates_only']=True
        result['relation_estimates']=db.sql('''SELECT c.relname,c.relkind,c.relpages,
            c.reltuples::double precision AS estimated_rows,
            i.indisvalid,i.indisready,i.indisunique
            FROM pg_class c LEFT JOIN pg_index i ON i.indexrelid=c.oid
            WHERE c.relnamespace='public'::regnamespace AND
              (c.oid=ANY(ARRAY['public.viewer_events'::regclass,
                 'public.viewer_raw_events'::regclass,'public.viewer_links'::regclass])
               OR i.indrelid=ANY(ARRAY['public.viewer_events'::regclass,
                 'public.viewer_raw_events'::regclass,'public.viewer_links'::regclass]))
            ORDER BY c.relname''').fetchall()
        result['writer_before']=owner(db)
        for pair in range(pairs):
            if time.perf_counter()>=deadline:break
            keys=sorted(secrets.token_hex(32) for _ in range(batch_size))
            statement,params=origin_lookup_sql(db,'viewer_events',('origin_key','version_key','request_key'),keys)
            for access in ('first_observed','repeated_same_keys'):
                if time.perf_counter()>=deadline:break
                started=time.perf_counter()
                try:
                    plan=db.one('EXPLAIN (ANALYZE,BUFFERS,FORMAT JSON) '+statement,params)['QUERY PLAN'][0]
                    result['samples'].append(dict(pair=pair,access=access,origins=batch_size,
                        wall_seconds=time.perf_counter()-started,**plan_summary(plan)))
                except psycopg.Error as exc:
                    result['failures'].append(dict(stage='probe_select',pair=pair,access=access,
                        error_type=type(exc).__name__,sqlstate=exc.sqlstate,
                        seconds=time.perf_counter()-started))
                    if exc.sqlstate not in ('57014','55P03'):raise
                    break
        result['writer_after']=owner(db)
    result['elapsed_seconds']=time.perf_counter()-began
    result['completed_pairs']=sum(1 for pair in range(pairs) if
        len([s for s in result['samples'] if s['pair']==pair])==2)
    result['summary']={access:dict(samples=len(rows),origins=sum(s['origins'] for s in rows),
        wall_seconds=sum(s['wall_seconds'] for s in rows),
        shared_read_blocks=sum(s['shared_read_blocks'] for s in rows),
        shared_hit_blocks=sum(s['shared_hit_blocks'] for s in rows),
        median_ms_per_origin=statistics.median(s['wall_seconds']*1000/s['origins'] for s in rows) if rows else None)
        for access in ('first_observed','repeated_same_keys')
        for rows in [[s for s in result['samples'] if s['access']==access]]}
    if result['failures'] or not result['completed_pairs']:
        result['status']='PARTIAL_READ_ONLY_INDEX_COST_OBSERVATION'
    return result


def main(argv=None):
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--project',type=Path,required=True)
    parser.add_argument('--seconds',type=int,default=20)
    args=parser.parse_args(argv)
    project=args.project.resolve();sys.path.insert(0,str(project))
    from viewer_performance.Qualify_Capacity_Candidate import EXPECTED_RUNTIME,literal_database
    from p24_foundation.viewer_runtime import runtime_source_digest,atomic_json
    try:
        if runtime_source_digest(project)!=EXPECTED_RUNTIME:
            raise ValueError('installed_viewer_is_not_the_recorded_baseline')
        result=observe(literal_database(project),seconds=args.seconds)
        result['runtime_source_sha256']=EXPECTED_RUNTIME
        result['probe_source_sha256']=hashlib.sha256(Path(__file__).read_bytes()).hexdigest()
        result['runtime_still_matches']=runtime_source_digest(project)==EXPECTED_RUNTIME
        if not result['runtime_still_matches']:result['status']='PARTIAL_READ_ONLY_INDEX_COST_OBSERVATION'
        output=project/'AnomalyDetection/reports'/('Viewer_Index_Cost_'+datetime.now(timezone.utc).strftime('%Y%m%d_%H%M%S_')+uuid.uuid4().hex[:8]+'.json')
        atomic_json(output,result)
        notice={k:result[k] for k in ('status','completed_pairs','summary','database_modified','workers_restarted')}
        notice['output']=str(output)
    except Exception as exc:
        notice=dict(status='READ_ONLY_INDEX_COST_BLOCKED',error_type=type(exc).__name__,
            code=str(exc) if isinstance(exc,ValueError) else None,sqlstate=getattr(exc,'sqlstate',None),
            database_modified=False,workers_restarted=False)
    print(json.dumps(notice))
    return 0 if notice['status']!='READ_ONLY_INDEX_COST_BLOCKED' else 2


if __name__=='__main__':raise SystemExit(main())
