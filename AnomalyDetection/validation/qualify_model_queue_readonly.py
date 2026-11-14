"""Compare selectors in one read-only snapshot without changing the installation.

Run from a separate checkout using the existing application Python. Only the
installation's reports directory is written. No Worker/model execution or DDL.
"""
import argparse
from datetime import datetime, timezone
import json
from pathlib import Path
import statistics
import sys
import time
import uuid

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from anomaly_detection import model_queue

ROLE = 'p24_anomaly_detection'
DATABASE = 'p24_design_viewer'
OPTIONS = ('-c default_transaction_read_only=on -c statement_timeout=3000 '
           '-c lock_timeout=100 -c idle_in_transaction_session_timeout=5000 '
           '-c max_parallel_workers_per_gather=0 -c work_mem=8MB -c jit=off')
LEGACY_SELECT = (
    'SELECT j.* FROM anomaly_detection.adp_model_queue r '
    'JOIN anomaly_detection.adp_jobs j USING(session_key,target_ns) '
    'WHERE r.due_ns<=%s AND r.expected_version=j.version AND j.dirty=FALSE '
    'AND j.processed_version=j.version '
    'ORDER BY r.due_ns,r.target_ns,r.session_key LIMIT 1'
)


def candidate_statement(now):
    class Capture:
        def execute(self, query, args):
            self.statement = query, args
            return self
        def fetchone(self):
            return None
    raw = Capture()
    model_queue.next_job(type('Store', (), {'raw':raw})(), now)
    return raw.statement


def plan_summary(plan):
    def nodes(node):
        yield node
        for child in node.get('Plans', []):
            yield from nodes(child)
    active = [n for n in nodes(plan['Plan']) if n.get('Actual Loops', 0)]
    return {
        'execution_ms':plan['Execution Time'],
        'planning_ms':plan['Planning Time'],
        'shared_hit_blocks':plan['Plan'].get('Shared Hit Blocks', 0),
        'shared_read_blocks':plan['Plan'].get('Shared Read Blocks', 0),
        'active_indexes':sorted({n['Index Name'] for n in active if 'Index Name' in n}),
        'active_sorts':[{'rows':n['Actual Rows'],
                         'input_rows':sum(c['Actual Rows'] for c in n.get('Plans', [])),
                         'space_type':n.get('Sort Space Type')} for n in active if n['Node Type']=='Sort'],
    }


def collect(raw, *, pairs=4):
    began = time.monotonic()
    now = time.time_ns()
    candidate = candidate_statement(now)
    statements = {'legacy':(LEGACY_SELECT, (now,)), 'candidate':candidate}
    result = dict(report_version='AD_SECONDARY_SHADOW_1', database_modified=False,
                  models_executed=False, scope='SECONDARY_JOB_SELECTION_ONLY',
                  raw_rows_exported=False, statement_timeout_ms=3000,
                  start_budget_seconds=40, trials=[], plans={})
    samples = {'legacy':[], 'candidate':[]}
    with raw.transaction():
        raw.execute('SET TRANSACTION ISOLATION LEVEL REPEATABLE READ, READ ONLY')
        result['snapshot'] = dict(raw.execute(
            "SELECT current_database() AS database,current_user AS role,"
            "current_setting('transaction_read_only') AS read_only,"
            "current_setting('transaction_isolation') AS isolation").fetchone())
        for pair in range(pairs):
            rows = {}
            trial = {'pair':pair+1, 'order':['legacy','candidate'] if pair%2==0 else ['candidate','legacy']}
            for label in trial['order']:
                if time.monotonic()-began >= 40:
                    trial[label] = {'status':'NOT_ATTEMPTED_BUDGET'}
                    continue
                started = time.monotonic()
                try:
                    with raw.transaction():
                        rows[label] = raw.execute(*statements[label]).fetchone()
                    elapsed = (time.monotonic()-started)*1000
                    samples[label].append(elapsed)
                    trial[label] = {'status':'COMPLETE', 'milliseconds':round(elapsed,3),
                                    'selected':rows[label] is not None}
                except Exception as exc:
                    trial[label] = {'status':'UNAVAILABLE','error_type':type(exc).__name__,
                                    'sqlstate':getattr(exc,'sqlstate',None)}
            trial['equal_full_rows'] = rows['legacy']==rows['candidate'] if len(rows)==2 else None
            result['trials'].append(trial)
        for label, statement in statements.items():
            if time.monotonic()-began >= 40:
                result['plans'][label] = {'status':'NOT_ATTEMPTED_BUDGET'}
                continue
            try:
                with raw.transaction():
                    plan = raw.execute('EXPLAIN (ANALYZE,BUFFERS,FORMAT JSON) '+statement[0], statement[1]).fetchone()['QUERY PLAN'][0]
                result['plans'][label] = dict(status='COMPLETE', **plan_summary(plan))
            except Exception as exc:
                result['plans'][label] = {'status':'UNAVAILABLE','error_type':type(exc).__name__,
                                         'sqlstate':getattr(exc,'sqlstate',None)}
    complete = all(t['equal_full_rows'] is True for t in result['trials'])
    mismatch = any(t['equal_full_rows'] is False for t in result['trials'])
    result['median_ms'] = {name:round(statistics.median(values),3) if values else None for name,values in samples.items()}
    result['status'] = 'FAIL_SELECTION_MISMATCH' if mismatch else 'PASS_READ_ONLY_EQUIVALENCE' if complete else 'PARTIAL'
    result['production_capacity_and_detection_accuracy'] = 'NOT_EVALUATED'
    result['seconds'] = round(time.monotonic()-began,3)
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--project', required=True, type=Path)
    args = parser.parse_args()
    try:
        import psycopg
        from psycopg.rows import dict_row
        root = args.project.resolve() / 'AnomalyDetection'
        saved = json.loads((root/'data/pg_credentials.local.json').read_text(encoding='utf-8-sig'))
        connection = dict(saved['connection'])
        if connection.get('dbname')!=DATABASE or connection.get('user')!=ROLE:
            raise ValueError('EXISTING_AD_ROLE_REQUIRED')
        for key in ('options','row_factory','autocommit','application_name','service','passfile'):
            connection.pop(key, None)
        connection.update(connect_timeout=3, application_name='P24.AD.SecondaryShadow',
                          autocommit=True, row_factory=dict_row, options=OPTIONS)
        with psycopg.connect(**connection) as raw:
            identity = raw.execute('SELECT current_database() AS db,current_user AS role').fetchone()
            if identity!={'db':DATABASE,'role':ROLE}:
                raise ValueError('UNEXPECTED_REPORT_DATABASE_IDENTITY')
            result = collect(raw)
        result['observed_at_utc'] = datetime.now(timezone.utc).isoformat()
        output = root/'reports'/('AD_Secondary_Shadow_'+datetime.now(timezone.utc).strftime('%Y%m%d_%H%M%S')+'_'+uuid.uuid4().hex[:8]+'.json')
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(json.dumps(result,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
        print(json.dumps({'status':result['status'],'output':str(output),'median_ms':result['median_ms'],
                          'database_modified':False,'models_executed':False},indent=2))
        return 0 if result['status']=='PASS_READ_ONLY_EQUIVALENCE' else 2
    except Exception as exc:
        print(json.dumps({'status':'SECONDARY_SHADOW_FAILED','error_type':type(exc).__name__,
                          'sqlstate':getattr(exc,'sqlstate',None),'database_modified':False}))
        return 1


if __name__=='__main__':
    raise SystemExit(main())
