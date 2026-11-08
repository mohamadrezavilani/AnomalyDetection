"""Preserve and quarantine populations produced before isolated atomic staging."""
import json
import time
from .snapshot import canonical,digest

def migrate(store):
    if store.state('atomic_scope_v3').get('ready'):return
    now=time.time_ns()
    with store.transaction():
        # Only windows built by the earlier shared staging path are affected.
        # Independent imported history and all feedback remain intact.
        old=store.raw.execute('SELECT start_ns FROM anomaly_detection.adp_source_windows').fetchall()
        if old:
            store.raw.execute("INSERT INTO anomaly_detection.adp_window_versions(session_key,start_ns,body,reason,observed_ns) "
                "SELECT w.session_key,w.start_ns,w.body,'pre_atomic_scope_preserved',%s FROM anomaly_detection.adp_windows w "
                'WHERE EXISTS(SELECT 1 FROM anomaly_detection.adp_source_windows p WHERE p.start_ns=w.start_ns)',(now,))
            after=None
            while True:
                batch=store.raw.execute('SELECT w.session_key,w.start_ns,w.body FROM anomaly_detection.adp_windows w WHERE '
                    'EXISTS(SELECT 1 FROM anomaly_detection.adp_source_windows p WHERE p.start_ns=w.start_ns) '+
                    ('AND (w.session_key,w.start_ns)>(%s,%s) ' if after else '')+'ORDER BY w.session_key,w.start_ns LIMIT 512',after or ()).fetchall()
                if not batch:break
                values=[]
                for row in batch:
                    body=json.loads(row['body'])|{'coverage_complete':False,'population_complete':False,'quality_reason':'REQUIRES_ATOMIC_SCOPE_RECHECK'}
                    values.append({'session_key':row['session_key'],'start_ns':row['start_ns'],'body':body,'content_digest':digest(body)})
                store.raw.execute("UPDATE anomaly_detection.adp_windows w SET body=(v->'body')::text,content_digest=v->>'content_digest' "
                    "FROM jsonb_array_elements(%s::jsonb) AS v WHERE w.session_key=v->>'session_key' AND w.start_ns=(v->>'start_ns')::bigint",(canonical(values),))
                after=(batch[-1]['session_key'],batch[-1]['start_ns'])
            store.raw.execute("UPDATE anomaly_detection.adp_source_windows SET complete=FALSE,source=(source::jsonb || '{\"needs_scope_repair\":true}'::jsonb)::text")
            store.raw.execute('UPDATE anomaly_detection.adp_peers p SET eligible=FALSE WHERE EXISTS('
                'SELECT 1 FROM anomaly_detection.adp_source_windows w WHERE w.start_ns=p.start_ns)')
            store.raw.execute('UPDATE anomaly_detection.adp_peer_epochs SET version=version+1')
            store.raw.execute('UPDATE anomaly_detection.adp_jobs j SET dirty=TRUE,version=version+1,due_ns=0 WHERE '
                'last_evaluated_ns IS NOT NULL OR EXISTS(SELECT 1 FROM anomaly_detection.adp_contexts c WHERE c.session_key=j.session_key AND c.target_ns=j.target_ns)')
            store.raw.execute("UPDATE anomaly_detection.adp_incidents SET state='RECHECK_REQUIRED' WHERE state<>'WITHDRAWN'")
        for name in ('fresh_cursor','overlap_cursor','learning_cursor','older_learning_cursor'):
            cursor=store.state(name)
            if cursor.get('after'):
                store.save_state('pre_atomic_cursor:'+name,cursor)
                store.save_state(name,{'target_ns':cursor['target_ns']})
        store.save_state('atomic_scope_v3',{'ready':True,'old_windows_requiring_recheck':len(old),'old_rows_preserved':True,'migrated_ns':now})
