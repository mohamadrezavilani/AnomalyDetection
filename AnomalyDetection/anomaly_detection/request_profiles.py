"""Bounded content fingerprints delegated to the pinned Viewer's raw reader.

No business-anchor reconstruction, raw decryptor, secret storage or Viewer DDL.
Input identifiers are compared by digest within their endpoint/field namespace.
"""
from collections import Counter
from decimal import Decimal
import json,re
from .snapshot import api_path,canonical,digest,require

VERSION='qualified-request-profile-3'
IGNORED=re.compile(r'password|secret|token|authorization|signature|apikey|accesskey|session|trace(?:number|id)?|requestid|counter|timestamp|walletidentifier|feereduction|invoice(?:unique)?id|bills?uniq(?:ue|e)ids?|queryuniqueid|servicecode|serviceid|servicename|servicepath|operation|^ip$|ipaddress|clientip|remoteip',re.I)
SUBJECT=re.compile(r'billid|nationalcode|nationalid|identitynumber|mobilenumber|phonenumber|plate|vin$|postalcode|iban|accountnumber',re.I)
VOLATILE=re.compile(r'date|time|trace|requestid|session|token|password|secret|signature|invoice|uniqueid|national|mobile|phone|name|address|billid|paymentid|iban|account',re.I)


def scalar(value):
    if isinstance(value,Decimal):return float(value)
    return value


def decoded(value,depth=0):
    if depth>7:raise ValueError('PROFILE_NESTING_LIMIT')
    if isinstance(value,str) and value.lstrip().startswith(('{','[')):
        try:return decoded(json.loads(value),depth+1)
        except (ValueError,TypeError):return value
    if isinstance(value,dict):return {str(k):decoded(v,depth+1) for k,v in value.items()}
    if isinstance(value,list):return [decoded(v,depth+1) for v in value]
    return scalar(value)


def flatten(value):
    result={};visited=0
    def visit(v,path,depth):
        nonlocal visited
        visited+=1
        if visited>512 or depth>10:raise ValueError('PROFILE_FIELD_LIMIT')
        if isinstance(v,dict):
            if not v:result[path]='empty_object'
            for k,child in sorted(v.items()):
                k='*' if re.fullmatch(r'[0-9a-f]{20,}|\d{6,}',k) else k
                visit(child,path+'.'+k,depth+1)
        elif isinstance(v,list):
            result[path]={'array_length':len(v)}
            # Sample is never called a complete element-content projection.
            if len(v)>32:raise ValueError('PROFILE_ARRAY_LIMIT')
            for i,child in enumerate(v):visit(child,path+'['+str(i)+']',depth+1)
        else:result[path]=v
    visit(value,'$',0);return result


def input_features(value,channel):
    flat=flatten(decoded(value));business={};subjects=[]
    for path,v in flat.items():
        leaf=path.rsplit('.',1)[-1]
        normalized_leaf=re.sub(r'[^a-z0-9]','',leaf.lower())
        if IGNORED.search(normalized_leaf) or v is None or v=='':continue
        if isinstance(v,(str,int,float,bool)):
            business[path]=v
            if SUBJECT.search(normalized_leaf):
                field=re.sub(r'\[\d+\]','[]',path)
                shown=str(v)
                # Group by the full typed digest; keep only a masked label.
                # The original identifier remains in its Viewer witness.
                display='…'+shown[-4:] if len(shown)>4 else 'پوشیده'
                subjects.append({'field':field,'key':digest([channel,field,v]),'display':display[:160]})
    return {'key':digest([channel,business]) if business else None,'subjects':subjects,'fields':sorted(business)}


def output_features(value):
    flat=flatten(decoded(value));shape=[];categories={};numbers={}
    for path,v in flat.items():
        if VOLATILE.search(path):continue
        typ='null' if v is None else 'boolean' if isinstance(v,bool) else 'number' if isinstance(v,(int,float)) else 'array' if isinstance(v,dict) and 'array_length' in v else 'string'
        shape.append((re.sub(r'\[\d+\]','[]',path),typ))
        if v is None or isinstance(v,bool):categories[path]=canonical(v)
        elif isinstance(v,(int,float)):
            numbers[path]=float(v);categories[path]=canonical(v)
        elif isinstance(v,dict) and 'array_length' in v:
            numbers[path+'.length']=v['array_length'];categories[path+'.length']=canonical(v['array_length'])
        elif isinstance(v,str) and len(v)<=160:
            # Hash arbitrary result text; retain neither names nor payloads.
            categories[path]='value:'+digest(v)
    return {'shape':digest(sorted(set(shape))),'shape_fields':sorted(set(shape)),'categories':categories,'numbers':numbers}


def build(request,events,raw_by_origin,links,parse_section,*,semantic=None):
    key=request['request_key'];root=api_path(request.get('root_call'));semantic=semantic or {}
    service=api_path(semantic.get('root_call')) if semantic.get('state')=='active' else root
    at=semantic.get('anchor_ns') if semantic.get('state')=='active' else request.get('root_ns') or request.get('started_ns')
    known_actor=bool(request.get('session_key') and request.get('identity_state')=='assigned' and not request.get('conflicted'))
    valid=bool(key and not request.get('conflicted') and type(at) is int and at>0 and (known_actor or request.get('root_count')==1 or semantic.get('state')=='active'))
    complete=bool(events and len(events)<=512 and all(e.get('variant_count')==1 and e.get('raw_available') for e in events))
    client=[e for e in events if api_path(e.get('callpath'))==root and e.get('session_key')==request.get('session_key')]
    ips=sorted({e['ip_key'] for e in client if e.get('ip_key')})
    channels={};targets={};subjects=[];issues=[];input_issues=[];output_issues=[]
    for e in events:
        channel=api_path(e.get('callpath'))
        if not (channel==root or e.get('kind')=='provider'):continue
        raw=raw_by_origin.get((e['origin_key'],e['version_key']))
        if raw is None:
            input_issues.append(channel)
            output_issues.append(channel)
            continue
        message=raw.get('message')
        if not isinstance(message,str) or len(message)>262144:
            issues.append('RAW_BODY_UNAVAILABLE_OR_LARGE');input_issues.append('raw');output_issues.append('raw');continue
        a,as_=parse_section(message,'Input:');b,bs=parse_section(message,'Output:')
        try:
            if as_=='complete':
                f=input_features(a,channel)
                if f['key']:targets[channel]=f['key']
                subjects.extend(dict(x,channel=channel) for x in f['subjects'])
        except (ValueError,TypeError,RecursionError):issues.append('INPUT_PROJECTION_TRUNCATED');input_issues.append(channel)
        if as_=='parse_error':input_issues.append(channel)
        try:
            if bs=='complete':channels[channel]=output_features(b)
            elif bs=='parse_error':channels[channel]={'shape':'logged-non-json','shape_fields':[['$','logged-non-json']],'categories':{'$.logged_representation':'non_json'},'numbers':{}}
        except (ValueError,TypeError,RecursionError):issues.append('OUTPUT_PROJECTION_TRUNCATED');output_issues.append(channel)
    # Stable query-parameter hashes are target evidence. Invoice/BillUniqueID
    # are execution/item references and must NOT stand in for original BillID.
    for link in links:
        if link.get('link_domain')=='query_parameters_hash' and link.get('qualified'):
            targets.setdefault('viewer:'+link['link_domain'],link['link_key'])
    return {'version':VERSION,'request_key':key,'session_key':request.get('session_key'),'service_path':service,'at_ns':at,
        'semantic_active':semantic.get('state')=='active',
        'actor_qualified':known_actor,
        'anchor_key':semantic.get('anchor_key'),'semantic_revision':semantic.get('revision'),
        'qualified':bool(valid and complete),'content_complete':not issues,'input_complete':not input_issues,'output_complete':not output_issues,'complete_event_scope':complete,'source_finality':'not_established',
        'count_scope':'observed_logical_requests_not_manual_clicks','ip_keys':ips,'ip_scope':'root_client_events_only',
        'targets':targets,'subjects':subjects,'outputs':channels,'stages':sorted({api_path(e.get('callpath')) for e in events}),
        'root_code':request.get('root_code'),'ended_ns':request.get('ended_ns'),'issues':sorted(set(issues)),
        'witnesses':[{'origin_key':e['origin_key'],'version_key':e['version_key'],'callpath':e.get('callpath'),'at_ns':e['at_ns']} for e in events[:512]]}


def read(source,key):
    from .viewer_bridge import reader
    from .product_source import SELECT
    from . import FIVE_NS
    with source.snapshot() as q:
        meta=source.metadata(q);facade=reader(source.project,q)
        request=q('SELECT * FROM public.viewer_requests WHERE request_key=%s',(key,),cap=1)
        if not request:return {'source':meta,'profile':None,'request_key':key}
        semantic=q(SELECT+'WHERE s.request_key=%s',(key,),cap=1)
        events=q('SELECT * FROM (SELECT e.origin_key,e.version_key,e.request_key,e.session_key,e.ip_key,e.at_ns,e.callpath,e.kind,e.code,'
            '(SELECT COUNT(*) FROM public.viewer_events c WHERE c.origin_key=e.origin_key) AS variant_count,'
            'EXISTS(SELECT 1 FROM public.viewer_raw_events b WHERE b.origin_key=e.origin_key AND b.version_key=e.version_key) AS raw_available '
            'FROM public.viewer_events e WHERE e.request_key=%s ORDER BY e.at_ns,e.origin_key LIMIT 513) x',(key,),cap=513)
        links=q('SELECT l.*,NOT EXISTS(SELECT 1 FROM public.viewer_events e WHERE e.origin_key=l.origin_key AND e.version_key<>l.version_key) AS qualified FROM public.viewer_links l WHERE l.request_key=%s',(key,),cap=256)
        root=api_path(request[0].get('root_call'));candidates=[e for e in events if api_path(e.get('callpath'))==root or e.get('kind')=='provider']
        raw={}
        from p24_foundation.parser import json_section,field
        if len(candidates)<=12:
            for e in candidates:
                if e['variant_count']==1 and e['raw_available']:
                    body=facade.get_raw(e['origin_key'],e['version_key'])
                    message,status=field(body,'message') if body else (None,'missing')
                    raw[(e['origin_key'],e['version_key'])]={'message':message if status=='present' else None}
        profile=build(request[0],events,raw,links,json_section,semantic=semantic[0] if semantic else None)
        # Read existing raw identity columns; never infer an IP from provider
        # messages or rewrite the pinned Viewer's identity contract.
        observations=q('SELECT o.axis,o.value,o.origin_key,o.version_key,o.at_ns FROM public.viewer_contract_observations o WHERE o.request_key=%s AND o.axis=%s',(key,'service_dispatch.inquiry_result'),cap=128)
        valid_origins={(e['origin_key'],e['version_key']) for e in events if e['variant_count']==1 and e['raw_available']}
        client_origins=[e['origin_key'] for e in events if api_path(e.get('callpath'))==root and e.get('session_key')==request[0].get('session_key') and (e['origin_key'],e['version_key']) in valid_origins]
        profile['ip_display']={}
        if client_origins:
            from ipaddress import ip_address
            ip_rows=q('SELECT e.ip_key,b.raw_ip FROM public.viewer_events e JOIN public.viewer_raw_events b ON b.origin_key=e.origin_key AND b.version_key=e.version_key WHERE e.request_key=%s AND e.origin_key=ANY(%s)',(key,client_origins),cap=512)
            displays={}
            for item in ip_rows:
                try:value=str(ip_address(item['raw_ip']))
                except (ValueError,TypeError):continue
                displays.setdefault(item['ip_key'],set()).add(value)
            profile['ip_display']={k:next(iter(v)) for k,v in displays.items() if k in profile['ip_keys'] and len(v)==1}
        values={str(o['value']) for o in observations if (o['origin_key'],o['version_key']) in valid_origins}
        if len(values)==1:profile['result']={'scope':'dispatcher_inquiry_result','code':next(iter(values))}
        elif not values and api_path(request[0].get('root_call'))==profile['service_path'] and request[0].get('root_code'):
            profile['result']={'scope':'direct_api_reported_result','code':request[0]['root_code']}
        if len(candidates)>12:
            profile['issues'].append('CONTENT_EVENT_LIMIT');profile['content_complete']=False;profile['input_complete']=False;profile['output_complete']=False
        return {'source':meta,'profile':profile,'request_key':key}
