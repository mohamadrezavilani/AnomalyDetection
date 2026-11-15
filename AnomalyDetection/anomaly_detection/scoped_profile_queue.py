"""Finite keyset admission for a restricted history scope.

Old scheduling rows remain available if an operator later widens the scope.
Each scan checks at most 128 primary keys; it never sorts the whole old queue.
"""
STATE='profile_floor_pass_v1'


def next_key(store,now):
    floor=store.history_floor_ns;state=store.state(STATE)
    pending=state.get('pending',[])
    while pending:
        key=pending.pop(0)
        store.save_state(STATE,dict(state,pending=pending))
        row=store.raw.execute('SELECT request_key FROM anomaly_detection.adp_profile_tasks WHERE request_key=%s AND due_ns=0',(key,)).fetchone()
        if row:return key
    rows=store.raw.execute('SELECT request_key,due_ns,priority FROM anomaly_detection.adp_profile_tasks '
        'WHERE request_key>%s ORDER BY request_key LIMIT 128',(state.get('after',''),)).fetchall()
    if not rows:
        store.save_state(STATE,{'after':'','pending':[]});return None
    keys=[r['request_key'] for r in rows if r['due_ns']==0]
    eligible=store.raw.execute('''SELECT k.request_key,COALESCE(f.at_ns,p.at_ns) AS at_ns
        FROM unnest(%s::text[]) AS k(request_key)
        LEFT JOIN LATERAL (SELECT at_ns FROM anomaly_detection.adp_facts f WHERE f.request_key=k.request_key LIMIT 1) f ON TRUE
        LEFT JOIN LATERAL (SELECT at_ns FROM anomaly_detection.adp_profiles p WHERE p.request_key=k.request_key LIMIT 1) p ON TRUE''',
        (keys,)).fetchall() if keys else []
    allowed={r['request_key'] for r in eligible if r['at_ns'] is None or r['at_ns']>=floor}
    chosen=sorted((r for r in rows if r['request_key'] in allowed),key=lambda r:(-r['priority'],r['request_key']))
    pending=[r['request_key'] for r in chosen]
    key=pending.pop(0) if pending else None
    store.save_state(STATE,{'after':rows[-1]['request_key'],'pending':pending})
    return key
