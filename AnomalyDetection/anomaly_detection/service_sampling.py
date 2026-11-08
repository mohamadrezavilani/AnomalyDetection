"""Finite independent request samples in one read-only source snapshot.

This is not a request census. It can feed response/workflow screens without
waiting for a multi-page traffic census to complete during live publication.
"""
from collections import defaultdict
import json
from . import FIVE_NS
from .snapshot import api_path,canonical
from .history_scope import effective_floor


def read(source,cursor):
    with source.snapshot() as q:
        meta=source.metadata(q)
        begin=max(effective_floor(meta),cursor.get('next_ns',meta['next_ns']-FIVE_NS))
        windows=q('SELECT start_ns,end_ns FROM (SELECT start_ns,end_ns FROM public.viewer_live_windows WHERE start_ns>=%s AND end_ns<=%s ORDER BY start_ns LIMIT 1) w',(begin,meta['next_ns']),cap=1)
        if not windows:return {'status':'CAUGHT_UP','source':meta}
        target=windows[0]['start_ns']
        if windows[0]['end_ns']!=target+FIVE_NS:return {'status':'UNAVAILABLE','source':meta,'target_ns':target}
        # HMAC request keys select the finite sample independently of API
        # result, anomaly candidacy or SessionID presence. Identity is checked
        # by the delegated per-request reader, rather than guessed from IP.
        rows=q('SELECT r.request_key,r.root_call,s.root_call AS semantic_service,s.state AS semantic_state FROM (SELECT request_key,root_call FROM public.viewer_requests WHERE COALESCE(root_ns,started_ns)>=%s AND COALESCE(root_ns,started_ns)<%s AND root_count=1 AND NOT conflicted::boolean ORDER BY request_key LIMIT 32) r LEFT JOIN LATERAL (SELECT root_call,state FROM public.viewer_semantic_occurrences s WHERE s.request_key=r.request_key LIMIT 1) s ON TRUE ORDER BY r.request_key',(target,target+FIVE_NS),cap=32)
        return {'status':'SAMPLED','source':meta,'target_ns':target,'rows':rows}


def apply(store,packet,cursor_name):
    if packet['status']=='CAUGHT_UP':return packet['status']
    from .scenario_store import queue_keys,changed,enqueue,scope_key
    target=packet['target_ns']
    if target<store.history_floor_ns:
        return 'CAUGHT_UP'
    groups=defaultdict(list)
    for row in packet.get('rows',[]):
        service=api_path(row.get('semantic_service')) if row.get('semantic_state')=='active' else api_path(row.get('root_call'))
        if service:groups[service].append(row['request_key'])
    with store.transaction():
        store.bind(packet['source'])
        if packet['status']=='UNAVAILABLE':
            invalid=store.raw.execute('UPDATE anomaly_detection.adp_service_profile_samples SET available=FALSE WHERE start_ns=%s AND available=TRUE RETURNING service_path',(target,)).fetchall()
            for row in invalid:changed(store,[row['service_path']],target)
            store.save_state(cursor_name,{'next_ns':target+FIVE_NS})
            return packet['status']
        for service,keys in groups.items():
            census=store.raw.execute('SELECT body FROM anomaly_detection.adp_traffic_counts WHERE service_path=%s AND start_ns=%s',(service,target)).fetchone()
            if census and json.loads(census['body']).get('complete'):
                # Older products already stored a complete, independent
                # sample here. Add the response job without replacing it
                # with this smaller cross-service sample.
                for kind in ('request_workflow','request_response'):
                    store.raw.execute('INSERT INTO anomaly_detection.adp_scenario_jobs(scope_key,kind,entity_key,service_path,target_ns) VALUES(%s,%s,%s,%s,%s) ON CONFLICT(scope_key) DO NOTHING',(scope_key(kind,service,service,target),kind,service,service,target))
                continue
            before=store.raw.execute('SELECT request_keys,available FROM anomaly_detection.adp_service_profile_samples WHERE service_path=%s AND start_ns=%s',(service,target)).fetchone()
            value=canonical(sorted(set(keys)))
            if before is None or before['request_keys']!=value or not before['available']:
                store.raw.execute('INSERT INTO anomaly_detection.adp_service_profile_samples VALUES(%s,%s,%s,TRUE) ON CONFLICT(service_path,start_ns) DO UPDATE SET request_keys=excluded.request_keys,available=TRUE',(service,target,value))
                store.raw.execute('DELETE FROM anomaly_detection.adp_service_sample_members WHERE service_path=%s AND start_ns=%s',(service,target))
                store.raw.execute('INSERT INTO anomaly_detection.adp_service_sample_members SELECT %s,%s,k FROM unnest(%s::text[]) k',(service,target,keys))
                changed(store,[service],target)
                for kind in ('request_workflow','request_response'):enqueue(store,kind,service,service,target)
            queue_keys(store,keys,force=bool(before))
        store.save_state(cursor_name,{'next_ns':target+FIVE_NS})
    return packet['status']
