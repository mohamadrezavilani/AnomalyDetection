"""Bounded request-root census, including technical APIs such as registration.

These are logical request observations. They never create semantic behaviors,
change Viewer roles, infer shared users from IP or call a source initializer.
"""
from collections import Counter,defaultdict
import json
from . import FIVE_NS
from .snapshot import api_path,canonical,digest
from .history_scope import effective_floor


def read_page(source,state,*,oldest=False):
    with source.snapshot() as q:
        meta=source.metadata(q);target=state.get('target_ns')
        if target is not None and target<meta.get('analysis_floor_ns',0):
            state={'next_ns':meta['analysis_floor_ns'],'page_size':state.get('page_size',1024)}
            target=None
        if target is None:
            begin=max(effective_floor(meta),state.get('next_ns',meta.get('retention_cutoff_ns',0) if oldest else meta['next_ns']-FIVE_NS))
            windows=q('SELECT start_ns,end_ns,generation,last_publish_ns FROM (SELECT start_ns,end_ns,generation,last_publish_ns FROM public.viewer_live_windows WHERE start_ns>=%s AND end_ns<=%s ORDER BY start_ns LIMIT 1) x',(begin,meta['next_ns']),cap=1)
        else:windows=q('SELECT start_ns,end_ns,generation,last_publish_ns FROM public.viewer_live_windows WHERE start_ns=%s',(target,),cap=1)
        if not windows:return {'source':meta,'status':'CAUGHT_UP'}
        window=windows[0];target=window['start_ns'];stamp=digest([window,meta['generation'],meta['semantic_generation']])
        if window['end_ns']!=target+FIVE_NS or target<meta.get('retention_cutoff_ns',0):return {'source':meta,'target_ns':target,'status':'UNAVAILABLE'}
        if state.get('stamp') and state['stamp']!=stamp:return {'source':meta,'target_ns':target,'stamp':stamp,'status':'RESTART'}
        args=[target,target+FIVE_NS];after=''
        if state.get('after'):after='AND (e.at_ns,e.origin_key)>(%s,%s) ';args+=state['after']
        size=max(64,min(1024,int(state.get('page_size',1024))))
        rows=q('SELECT * FROM (SELECT e.origin_key,e.version_key,e.at_ns,e.request_key,e.session_key,e.ip_key,e.callpath,'
            'r.root_call,r.root_count,r.identity_state,r.conflicted,r.session_key AS owner_session,s.root_call AS semantic_service,s.state AS semantic_state,'
            '(SELECT COUNT(*) FROM public.viewer_events c WHERE c.origin_key=e.origin_key) AS variants,'
            'EXISTS(SELECT 1 FROM public.viewer_raw_events b WHERE b.origin_key=e.origin_key AND b.version_key=e.version_key) AS raw_available '
            'FROM public.viewer_events e LEFT JOIN public.viewer_requests r ON r.request_key=e.request_key '
            'LEFT JOIN public.viewer_semantic_occurrences s ON s.request_key=e.request_key '
            "WHERE e.kind IN ('client','other') AND trim(split_part(e.callpath,' Line:',1))=trim(split_part(r.root_call,' Line:',1)) AND e.at_ns>=%s AND e.at_ns<%s "+after+
            'ORDER BY e.at_ns,e.origin_key LIMIT %s) x',(*args,size+1),cap=size+1)
        more=len(rows)>size;rows=rows[:size]
        return {'source':meta,'target_ns':target,'stamp':stamp,'status':'PAGE','page_size':size,'rows':rows,'has_more':more,
            'after':[rows[-1]['at_ns'],rows[-1]['origin_key']] if more else None}


def apply(store,packet,*,cursor_name='scenario_traffic_cursor'):
    from .scenario_store import publish_scope,enqueue,changed,queue_keys
    target=packet.get('target_ns');status=packet['status']
    if status=='CAUGHT_UP' or target<store.history_floor_ns:return 'CAUGHT_UP'
    with store.transaction():
        store.bind(packet['source'])
        if status in ('RESTART','UNAVAILABLE'):
            store.raw.execute('DELETE FROM anomaly_detection.adp_traffic_staging WHERE lane=%s AND start_ns=%s',(cursor_name,target))
            store.save_state(cursor_name,{'target_ns':target} if status=='RESTART' else {'next_ns':target+FIVE_NS})
            if status=='UNAVAILABLE':
                rows=store.raw.execute('SELECT service_path,body FROM anomaly_detection.adp_traffic_counts WHERE start_ns=%s',(target,)).fetchall()
                for r in rows:
                    body=json.loads(r['body']);body['complete']=False
                    store.raw.execute('UPDATE anomaly_detection.adp_traffic_counts SET body=%s WHERE service_path=%s AND start_ns=%s',(canonical(body),r['service_path'],target));changed(store,[r['service_path']],target)
            return status
        for row in packet['rows']:
            store.raw.execute('INSERT INTO anomaly_detection.adp_traffic_staging VALUES(%s,%s,%s,%s) ON CONFLICT(lane,start_ns,origin_key) DO UPDATE SET body=excluded.body',(cursor_name,target,row['origin_key'],canonical(row)))
        if packet['has_more']:
            store.save_state(cursor_name,{'target_ns':target,'stamp':packet['stamp'],'after':packet['after'],'page_size':packet.get('page_size',1024)});return 'PAGE'
        rows=[json.loads(r['body']) for r in store.raw.execute('SELECT body FROM anomaly_detection.adp_traffic_staging WHERE lane=%s AND start_ns=%s ORDER BY origin_key',(cursor_name,target)).fetchall()]
        groups=defaultdict(dict);available=True
        for row in rows:
            if api_path(row.get('callpath'))!=api_path(row.get('root_call')):continue
            valid=bool(row.get('request_key') and not row.get('conflicted') and row.get('variants')==1 and row.get('raw_available') and row.get('root_count')==1)
            if not valid:available=False;continue
            service=api_path(row.get('semantic_service')) if row.get('semantic_state')=='active' else api_path(row.get('root_call'))
            row=dict(row,service_path=service,known_session=bool(row.get('owner_session') and row.get('session_key')==row.get('owner_session') and row.get('identity_state')=='assigned'));groups[service][row['request_key']]=row
        known={r['service_path'] for r in store.raw.execute('SELECT DISTINCT service_path FROM anomaly_detection.adp_traffic_counts WHERE start_ns<=%s',(target,)).fetchall()}
        store.raw.execute('DELETE FROM anomaly_detection.adp_traffic_members WHERE start_ns=%s',(target,))
        all_entries={key:row for entries in groups.values() for key,row in entries.items()}
        published=set()
        all_cohorts=defaultdict(list)
        for key,row in all_entries.items():
            if row['known_session']:all_cohorts[row['owner_session']].append(key)
        independent_sessions={all_entries[key]['owner_session'] for key in sorted(all_entries)[:32] if all_entries[key]['known_session']}
        for session,keys in all_cohorts.items():
            if session in independent_sessions or len(keys)>=2:
                publish_scope(store,session,'*',target,keys[:4096],independent=session in independent_sessions,available=available and len(keys)<=4096,authority='root_census');published.add((session,'*'))
        for service in sorted(set(groups)|known):
            entries=groups.get(service,{})
            for key,row in entries.items():store.raw.execute('INSERT INTO anomaly_detection.adp_traffic_members VALUES(%s,%s,%s)',(target,key,canonical(row)))
            body={'start_ns':target,'requests':len(entries),'sessions':len({r['owner_session'] for r in entries.values() if r['known_session']}),
                'sessions_complete':all(r['known_session'] for r in entries.values()),
                'request_keys':sorted(entries),'complete':available,'count_scope':'root_client_logical_requests','source_generation':packet['source']['generation']}
            prior=store.raw.execute('SELECT body FROM anomaly_detection.adp_traffic_counts WHERE service_path=%s AND start_ns=%s',(service,target)).fetchone()
            substantive={k:v for k,v in body.items() if k!='source_generation'}
            previous={k:v for k,v in json.loads(prior['body']).items() if k!='source_generation'} if prior else None
            if previous!=substantive:
                store.raw.execute('INSERT INTO anomaly_detection.adp_traffic_counts VALUES(%s,%s,%s) ON CONFLICT(service_path,start_ns) DO UPDATE SET body=excluded.body',(service,target,canonical(body)))
                changed(store,[service],target);enqueue(store,'traffic',service,service,target)
            # Select requests independently of identity/outcome. An absent
            # SessionID must not hide a changed service execution workflow.
            sample=sorted(entries)[:32];encoded=canonical(sample)
            prior_sample=store.raw.execute('SELECT request_keys,available FROM anomaly_detection.adp_service_profile_samples WHERE service_path=%s AND start_ns=%s',(service,target)).fetchone()
            if not prior_sample or prior_sample['request_keys']!=encoded or prior_sample['available']!=available:
                store.raw.execute('INSERT INTO anomaly_detection.adp_service_profile_samples VALUES(%s,%s,%s,%s) ON CONFLICT(service_path,start_ns) DO UPDATE SET request_keys=excluded.request_keys,available=excluded.available',(service,target,encoded,available))
                store.raw.execute('DELETE FROM anomaly_detection.adp_service_sample_members WHERE service_path=%s AND start_ns=%s',(service,target))
                if sample:store.raw.execute('INSERT INTO anomaly_detection.adp_service_sample_members SELECT %s,%s,k FROM unnest(%s::text[]) k',(service,target,sample))
                changed(store,[service],target)
                for kind in ('request_workflow','request_response'):enqueue(store,kind,service,service,target)
            queue_keys(store,sample)
            existing={r['request_key']:json.loads(r['body']) for r in store.raw.execute('SELECT request_key,body FROM anomaly_detection.adp_profiles WHERE request_key=ANY(%s)',(sample,)).fetchall()} if sample else {}
            corrections=[]
            for key in sample:
                p=existing.get(key);row=entries[key]
                if p and (p.get('session_key')!=row.get('owner_session') or p.get('actor_qualified',True)!=row['known_session'] or p.get('service_path')!=service or
                    (row['origin_key'],row['version_key']) not in {(w.get('origin_key'),w.get('version_key')) for w in p.get('witnesses',[])}):corrections.append(key)
            queue_keys(store,corrections,force=True)
            cohort=defaultdict(list)
            for key,row in entries.items():
                if row['known_session']:cohort[row['owner_session']].append(key)
            independent={entries[key]['owner_session'] for key in sorted(entries)[:32] if entries[key]['known_session']}
            for session,keys in cohort.items():
                if session in independent or len(keys)>=2:
                    publish_scope(store,session,service,target,keys[:4096],independent=session in independent,available=available and len(keys)<=4096,authority='root_census');published.add((session,service))
        # A corrected/retracted root must invalidate the previous owner scope,
        # including technical requests absent from the semantic behavior lane.
        prior_scopes=store.raw.execute("SELECT session_key,service_path,independent FROM anomaly_detection.adp_profile_scopes WHERE start_ns=%s AND authority='root_census'",(target,)).fetchall()
        for old in prior_scopes:
            if (old['session_key'],old['service_path']) not in published:
                publish_scope(store,old['session_key'],old['service_path'],target,[],independent=old['independent'],available=available,authority='root_census')
        store.raw.execute('DELETE FROM anomaly_detection.adp_traffic_staging WHERE lane=%s AND start_ns=%s',(cursor_name,target))
        store.save_state(cursor_name,{'next_ns':target+FIVE_NS})
    return 'COMPLETE'
