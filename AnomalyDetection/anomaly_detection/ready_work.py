"""Indexed ready work and bounded backoff promotion in the owned schema.

due_ns=0 is the existing ready sentinel. Expired nonzero backoffs are promoted
in finite batches; history, versions, claims and attempts remain intact.
Scheduling never requires sorting the entire pending queue for one request.
"""

DDL = [
    'CREATE INDEX IF NOT EXISTS adp_profile_ready_priority ON anomaly_detection.adp_profile_tasks(priority DESC,request_key) WHERE due_ns=0',
    'CREATE INDEX IF NOT EXISTS adp_profile_ready_key ON anomaly_detection.adp_profile_tasks(request_key) WHERE due_ns=0',
    'CREATE INDEX IF NOT EXISTS adp_profile_deferred_due ON anomaly_detection.adp_profile_tasks(due_ns,priority DESC,request_key) WHERE due_ns<>0',
    'CREATE INDEX IF NOT EXISTS adp_scenario_deferred_due ON anomaly_detection.adp_scenario_jobs(due_ns,target_ns DESC,scope_key) WHERE dirty=TRUE AND due_ns<>0',
]
for lane, predicate in (('content', "kind<>'longitudinal'"), ('long', "kind='longitudinal'")):
    for direction in ('ASC', 'DESC'):
        DDL.append('CREATE INDEX IF NOT EXISTS adp_scenario_ready_'+lane+'_'+direction.lower()+
            ' ON anomaly_detection.adp_scenario_jobs(target_ns '+direction+',scope_key) '
            'WHERE dirty=TRUE AND due_ns=0 AND '+predicate)

PROFILE_CANDIDATES = """WITH candidates AS MATERIALIZED (
    SELECT request_key FROM anomaly_detection.adp_profile_tasks
    WHERE due_ns=0 ORDER BY priority DESC,request_key LIMIT 64) """


def promote(store, table, now, *, limit=64):
    if table == 'adp_scenario_jobs':
        key = 'scope_key'; eligible = 'dirty=TRUE AND '
        order = 'due_ns,target_ns DESC,scope_key'
    elif table == 'adp_profile_tasks':
        key = 'request_key'; eligible = ''; order = 'due_ns,priority DESC,request_key'
    else:
        raise ValueError('unsupported_ready_queue')
    if not 1 <= limit <= 128:
        raise ValueError('invalid_ready_promotion_limit')
    return store.raw.execute('WITH expired AS MATERIALIZED (SELECT '+key+
        ' FROM anomaly_detection.'+table+' WHERE '+eligible+'due_ns<>0 AND due_ns<=%s '
        'ORDER BY '+order+' LIMIT %s FOR UPDATE SKIP LOCKED) '
        'UPDATE anomaly_detection.'+table+' q SET due_ns=0 FROM expired e '
        'WHERE q.'+key+'=e.'+key+' AND q.due_ns<>0 AND q.due_ns<=%s', (now, limit, now))


def scenario_query(longitudinal, direction):
    if direction not in ('ASC', 'DESC'):
        raise ValueError('invalid_ready_queue_direction')
    predicate = "kind='longitudinal'" if longitudinal else "kind<>'longitudinal'"
    return ('SELECT * FROM anomaly_detection.adp_scenario_jobs '
        'WHERE dirty=TRUE AND due_ns=0 AND '+predicate+
        ' ORDER BY target_ns '+direction+',scope_key LIMIT 1 FOR UPDATE')


def profile_scope_query(independent=False):
    # Fixed tasks first, then at most eight memberships per task. The limit
    # bounds scheduling work only; it does not assert statistical completeness
    # or remove any task/scope. A separate keyset lane still services history.
    return PROFILE_CANDIDATES+"""SELECT p.request_keys FROM candidates t
        CROSS JOIN LATERAL (SELECT session_key,service_path,start_ns
          FROM anomaly_detection.adp_profile_scope_members
          WHERE request_key=t.request_key
          ORDER BY start_ns DESC,session_key DESC,service_path DESC LIMIT 8) m
        JOIN anomaly_detection.adp_profile_scopes p
          ON p.session_key=m.session_key AND p.service_path=m.service_path AND p.start_ns=m.start_ns
        WHERE p.available=TRUE """+('AND p.independent=TRUE ' if independent else '')+\
        'ORDER BY p.start_ns DESC,p.session_key,p.service_path LIMIT 1'


PROFILE_INDEPENDENT = PROFILE_CANDIDATES+"""SELECT t.request_key FROM candidates t
    CROSS JOIN LATERAL (SELECT start_ns FROM anomaly_detection.adp_service_sample_members
      WHERE request_key=t.request_key ORDER BY start_ns DESC LIMIT 1) m
    ORDER BY m.start_ns DESC,t.request_key LIMIT 1"""
