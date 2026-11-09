"""Transaction-rollback index probe on an explicitly configured disposable DB.

Measures the selected-fact SELECT, not trigger/write cost or online throughput.
Never use against a running application. No payload or principal values emitted.
"""
import argparse,json,sys,uuid,hashlib,statistics
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))

from p24_foundation.config import connect,read_config
from p24_foundation.store import assert_disposable

QUERY='''SELECT f.namespace_id,%s::uuid AS run_id,f.request_key,f.fact_id,f.fact_key
 FROM p24_next.extracted_fact f
 JOIN p24_next.projection_event pe ON pe.namespace_id=f.namespace_id AND pe.event_version_id=f.event_version_id
 JOIN p24_next.request_projection rp ON rp.namespace_id=f.namespace_id AND rp.request_key=f.request_key AND rp.run_id=pe.run_id
 WHERE pe.namespace_id=%s AND pe.run_id=%s AND pe.selection_state='selected' '''


def profile(connection,namespace,run):
    import psycopg
    assert_disposable(connection)
    namespace,run=uuid.UUID(str(namespace)),uuid.UUID(str(run))
    params=(run,namespace,run)
    if connection.execute('SELECT state FROM p24_next.projection_run WHERE namespace_id=%s AND run_id=%s',
                          (namespace,run)).fetchone()!=('sealed',):raise ValueError('sealed run required')
    sizes=dict(connection.execute("SELECT 'facts',count(*) FROM p24_next.extracted_fact UNION ALL SELECT 'projection_events',count(*) FROM p24_next.projection_event").fetchall())
    result=dict(scope='selected-fact SELECT only; synthetic/sanitized disposable dataset; not end-to-end capacity',rows_in_database=sizes)
    with connection.transaction():
        connection.execute('DROP INDEX IF EXISTS p24_next.extracted_fact_selected_event')
        for mode in ('without_selected_event_index','with_selected_event_index'):
            if mode.startswith('with_'):
                connection.execute('CREATE INDEX extracted_fact_selected_event ON p24_next.extracted_fact(namespace_id,event_version_id,request_key,fact_id)')
            connection.execute(QUERY,params).fetchall() # warm each variant before five measurements
            plans=[connection.execute('EXPLAIN (ANALYZE,BUFFERS,FORMAT JSON) '+QUERY,params).fetchone()[0][0] for _ in range(5)]
            actual=connection.execute(QUERY,params).fetchall()
            fingerprint=hashlib.sha256(json.dumps(sorted([str(x) for x in row] for row in actual),separators=(',',':')).encode()).hexdigest()
            plan=plans[-1]
            result[mode]=dict(execution_ms=statistics.median(p['Execution Time'] for p in plans),
                samples_ms=[p['Execution Time'] for p in plans],rows=plan['Plan']['Actual Rows'],result_sha256=fingerprint,plan=plan['Plan'])
        result['same_row_count']=result['without_selected_event_index']['rows']==result['with_selected_event_index']['rows']
        result['same_result_sha256']=result['without_selected_event_index']['result_sha256']==result['with_selected_event_index']['result_sha256']
        # Neither dropping nor creating the index survives this probe.
        raise psycopg.Rollback()
    return result


def main():
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--config',required=True,type=Path)
    parser.add_argument('--namespace',required=True);parser.add_argument('--run',required=True);parser.add_argument('--output',required=True,type=Path)
    args=parser.parse_args()
    with connect(read_config(args.config)['database']) as connection:
        result=profile(connection,args.namespace,args.run)
    args.output.parent.mkdir(exist_ok=True,parents=True);args.output.write_text(json.dumps(result,indent=2,default=str)+'\n')
    print(json.dumps({k:v for k,v in result.items() if k not in {'without_selected_event_index','with_selected_event_index'}},indent=2))
    return 0 if result['same_row_count'] and result['same_result_sha256'] else 1

if __name__=='__main__':raise SystemExit(main())
