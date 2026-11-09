"""Observed-only audit of saved dumps through the maintained pure reconstruction.

Partition on both origin and RequestID connectivity, never five-minute files.
No PostgreSQL publication, detector utility or source completeness is implied.
"""
from collections import Counter,defaultdict
import hashlib
import os
from pathlib import Path
import time

from .errors import FoundationError
from .intake import read_batch
from .parser import Semantics,field,opaque,normalize_event
from .privacy import Keys,canonical
from .reconstruction import reconstruct,select_events
from .store import stable_id,MAX_PROJECTION_EVENTS
from .time import microsecond_cutoff

ROOT=Path(__file__).resolve().parents[1]


def audit(paths,*,keys=None,max_total_records=250000,progress=None):
    started=time.monotonic()
    if not 1<=len(paths)<=8:raise FoundationError('historical_input_limit')
    keys=keys or Keys(os.urandom(32),os.urandom(32),'audit')
    namespace='historical-replay';semantics=Semantics(ROOT/'catalogs/error_code_catalog.json')
    files=[];batches=[];total=0;digests=set()
    for path in paths:
        batch=read_batch(Path(path));coverage=batch.coverage
        if coverage.get('input_format')!='legacy_collector_dump':raise FoundationError('historical_requires_declared_dump')
        start=coverage['declared_window_start'];end=coverage['declared_window_end']
        first,last=microsecond_cutoff(start).epoch_ns,microsecond_cutoff(end).epoch_ns
        if last-first!=300_000_000_000:raise FoundationError('historical_requires_five_minute_window')
        digest=hashlib.sha256(batch.original).hexdigest()
        if digest in digests:raise FoundationError('historical_duplicate_input')
        digests.add(digest);total+=len(batch.records)
        if total>max_total_records:raise FoundationError('historical_total_record_limit')
        files.append(dict(sha256=digest,records=len(batch.records),start=start,end=end,start_ns=first,end_ns=last,
                          source_window_complete=False,source_finality='not_established'))
        batches.append(batch)
    ordered=sorted(zip(files,batches),key=lambda item:(item[0]['start_ns'],item[0]['sha256']))
    files,batches=map(list,zip(*ordered));boundary=files[0]['end_ns'];cutoff=max(f['end_ns'] for f in files)
    parent={}
    def find(x):
        parent.setdefault(x,x)
        if parent[x]!=x:parent[x]=find(parent[x])
        return parent[x]
    def union(a,b):
        a,b=find(a),find(b)
        if a!=b:parent[b]=a
    nodes=[];requests_by_file=[];sessions_by_file=[];raw_origins=[];missing=0
    for number,batch in enumerate(batches):
        request_ids=set();session_ids=set();origins=set();identities=[]
        for ordinal,record in enumerate(batch.records):
            rid=opaque(field(record,'RequestID')[0]);session=opaque(field(record,'Session')[0])
            if rid:request_ids.add(rid)
            else:missing+=1
            if session:session_ids.add(session)
            if record.get('_index') and record.get('_id'):
                origin=('origin',record['_index'],record['_id']);origins.add(origin)
            else:origin=('row',files[number]['sha256'],ordinal)
            node=('request',rid) if rid else origin
            union(node,origin);identities.append(node)
        nodes.append(identities);requests_by_file.append(request_ids);sessions_by_file.append(session_ids);raw_origins.append(origins)
    components=defaultdict(list)
    for number,(batch,identities) in enumerate(zip(batches,nodes)):
        for ordinal,(record,node) in enumerate(zip(batch.records,identities)):
            components[find(node)].append((number,ordinal,record))
    shared=set(requests_by_file[0]) if len(batches)>1 else set()
    for ids in requests_by_file[1:]:shared &= ids
    all_requests=set().union(*requests_by_file)
    shared_tokens={keys.token(namespace,'request',rid) for rid in shared}
    summary_counts=Counter();roles=Counter();parser_issues=Counter();checks=Counter();changes=Counter();examples=[]
    selected_total=ambiguous_total=unavailable_total=0;session_windows=defaultdict(set);session_ips=defaultdict(set)
    largest_component=0;accounted_origins=0;future_origins=0
    for index,observations in enumerate(components.values()):
        largest_component=max(largest_component,len(observations))
        if len(observations)>100000:raise FoundationError('historical_component_limit')
        events=[];early=[];anchors=defaultdict(list)
        for number,ordinal,record in observations:
            event=normalize_event(record,keys,namespace,semantics,fallback_scope=files[number]['sha256'],ordinal=ordinal)
            event['event_version_id']=stable_id(event['event_key'],event['content_digest'])
            events.append(event)
            if number==0:early.append(event)
            d=event['descriptor'];roles[d['role']]+=1;parser_issues.update(d['issues'])
            for session in d['session_candidates']:
                session_windows[session].add(number)
                if d['ip_key']:session_ips[session].add(d['ip_key'])
            if event['request_key']:anchors[event['request_key']].append([number,ordinal])
        origin_keys={e['event_key'] for e in events}
        early_result=reconstruct(select_events(early,boundary))
        pinned=canonical(early_result)
        selection=select_events(events,cutoff);final=reconstruct(selection)
        reverse=reconstruct(select_events(list(reversed(events)),cutoff))
        duplicate=reconstruct(select_events(events+events,cutoff))
        if canonical(final)!=canonical(reverse):raise FoundationError('historical_reverse_order_mismatch')
        if canonical(final)!=canonical(duplicate):raise FoundationError('historical_duplicate_delivery_mismatch')
        if pinned!=canonical(reconstruct(select_events(early,boundary))):raise FoundationError('historical_early_pin_changed')
        checks.update(reverse_order=1,duplicate_delivery=1,early_snapshot_preserved=1)
        selected_total+=len(selection['selected']);ambiguous_total+=len(selection['ambiguous']);unavailable_total+=len(selection['unavailable'])
        represented={e['event_key'] for e in selection['selected']}|{e['event_key'] for e in selection['ambiguous']}|{e['event_key'] for e in selection['unavailable']}
        future=origin_keys-represented
        for key in future:
            variants=[e for e in events if e['event_key']==key]
            if any(e['time'] is None or e['time'].epoch_ns<cutoff for e in variants):
                raise FoundationError('historical_origin_unaccounted')
        accounted_origins+=len(origin_keys);future_origins+=len(future)
        old={item['request_key']:item for item in early_result}
        for item in final:
            summary_counts['reconstructed_request_ids']+=1
            summary_counts['distinct_client_requests']+=item['distinct_client_request_count']
            summary_counts['client_'+item['client_completion_state']]+=1
            summary_counts['identity_'+item['identity_state']]+=1
            if item['request_key'] in shared_tokens:
                prior=old.get(item['request_key'])
                completed=bool(prior and prior['client_completion_state']=='not_observed' and item['client_completion_state']=='observed')
                changed=bool(prior and item['selected_event_count']>prior['selected_event_count'])
                changes.update(shared_requests_reconstructed=1,evidence_extended=int(changed),client_completion_arrived_later=int(completed))
                if len(examples)<20:
                    examples.append(dict(request_alias='boundary-'+str(len(examples)+1),source_row_anchors=anchors[item['request_key']],
                        earlier_events=prior['selected_event_count'] if prior else 0,combined_events=item['selected_event_count'],
                        earlier_client_state=prior['client_completion_state'] if prior else 'absent',combined_client_state=item['client_completion_state'],
                        logical_client_requests=item['distinct_client_request_count'],sql_observations=item['sql_observation_count'],
                        provider_observations=item['provider_observation_count'],identity_state=item['identity_state'],
                        earlier_final_outcome=prior['final_outcome'] if prior else 'unknown',combined_final_outcome=item['final_outcome']))
        if progress and index%2000==0:progress(index+1,len(components))
    return dict(schema='p24-historical-cross-window-audit.1',status='PASS',mode='offline_actual_parser_and_reconstruction',
        input_files=files,input_records=total,raw_request_ids=len(all_requests),missing_requestid_rows=missing,
        raw_request_ids_in_every_input=len(shared),raw_sessions_in_every_input=len(set.intersection(*sessions_by_file)),
        duplicate_origins_across_inputs=sum(map(len,raw_origins))-len(set().union(*raw_origins)),
        unique_input_origins=accounted_origins,excluded_future_origins=future_origins,
        selected_origins=selected_total,ambiguous_origins=ambiguous_total,unavailable_origins=unavailable_total,
        request_summary_counts=dict(summary_counts),source_row_roles=dict(roles),parser_issues=dict(parser_issues),
        cross_window_changes=dict(changes),examples=examples,checks=dict(checks),
        reconstructed_sessions_spanning_inputs=sum(len(w)>1 for w in session_windows.values()),
        reconstructed_sessions_with_multiple_ips=sum(len(ips)>1 for ips in session_ips.values()),
        largest_connected_component_records=largest_component,elapsed_seconds=round(time.monotonic()-started,3),
        production_modified=False,database_used=False,source_completeness_verified=False,
        full_database_publication='NOT_RUN',full_union_exceeds_existing_projection_record_limit=total>MAX_PROJECTION_EVENTS,
        runtime_source_sha256={name:hashlib.sha256((ROOT/name).read_bytes()).hexdigest() for name in
            ['p24_foundation/historical_replay.py','p24_foundation/parser.py','p24_foundation/reconstruction.py',
             'p24_foundation/intake.py','p24_foundation/time.py','p24_foundation/outcomes.py','p24_foundation/privacy.py','p24_foundation/store.py']},
        limitations=['observed dump rows only; no scroll completeness or source finality proof',
                     'event chronology does not prove provider/SQL execution order or workflow success',
                     'offline component partitioning does not qualify PostgreSQL capacity or full publication',
                     'two windows cannot establish detector usefulness or adequate personal reference history'])
