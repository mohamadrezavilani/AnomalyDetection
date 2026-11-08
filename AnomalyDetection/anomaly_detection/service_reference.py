"""Sparse service references across session epochs; no per-window crowd gate.

Canonical window summaries remain canonical. A separately qualified census of
direct HTTP client roots is stored separately and is usable ONLY against the
same directly observed transport after current request evidence is verified.
Raw root exports never become semantic facts, coverage windows, or journeys.
"""
from collections import Counter,defaultdict
from bisect import bisect_left
from datetime import datetime,timezone
from pathlib import Path
from statistics import median
import ast,gzip,hashlib,json,re,sys,time,zipfile

from . import FIVE_NS,SOURCE_SHA
from .snapshot import api_path,canonical,digest,require

MODEL_VERSION='pooled-service-reference-3'
MIN_SESSIONS=100
HORIZON=56*288*FIVE_NS
SEED_LIFETIME=7*288*FIVE_NS
SCREENING_LEVEL=.01
DDL=[
 '''CREATE TABLE IF NOT EXISTS anomaly_detection.adp_service_reference_points(service_path TEXT NOT NULL,kind TEXT NOT NULL,
 session_key TEXT NOT NULL,start_ns BIGINT NOT NULL,value INTEGER NOT NULL,qualified BOOLEAN NOT NULL,
 PRIMARY KEY(service_path,kind,session_key,start_ns))''',
 'CREATE INDEX IF NOT EXISTS adp_service_reference_time ON anomaly_detection.adp_service_reference_points(start_ns,session_key)',
 'CREATE INDEX IF NOT EXISTS adp_service_reference_model ON anomaly_detection.adp_service_reference_points(service_path,kind,start_ns,session_key)',
 'CREATE TABLE IF NOT EXISTS anomaly_detection.adp_service_reference_scopes(start_ns BIGINT PRIMARY KEY,stamp TEXT NOT NULL)',
 '''CREATE TABLE IF NOT EXISTS anomaly_detection.adp_http_reference_sets(dataset_id TEXT PRIMARY KEY,
 service_path TEXT NOT NULL,begin_ns BIGINT NOT NULL,cutoff_ns BIGINT NOT NULL,body TEXT NOT NULL,imported_ns BIGINT NOT NULL)''',
 'CREATE INDEX IF NOT EXISTS adp_http_reference_service ON anomaly_detection.adp_http_reference_sets(service_path,cutoff_ns DESC)',
 '''CREATE TABLE IF NOT EXISTS anomaly_detection.adp_http_reference_calls(dataset_id TEXT NOT NULL,request_key TEXT NOT NULL,
 session_key TEXT NOT NULL,at_ns BIGINT NOT NULL,origin TEXT NOT NULL,PRIMARY KEY(dataset_id,request_key))''',
 'CREATE INDEX IF NOT EXISTS adp_http_reference_time ON anomaly_detection.adp_http_reference_calls(dataset_id,at_ns,session_key)',
 '''CREATE TABLE IF NOT EXISTS anomaly_detection.adp_reference_cases(session_key TEXT NOT NULL,target_ns BIGINT NOT NULL,
 dataset_id TEXT NOT NULL,PRIMARY KEY(session_key,target_ns))''',
]


def refresh_points(store,target,proof,rows):
    """Called in the same atomic publication as owned canonical summaries."""
    values=[]
    for row in rows:
        body=json.loads(row['body']);valid=bool(proof.get('peer_population_valid') and body.get('coverage_complete') and body.get('population_complete'))
        for service,n in (body.get('counts') or {}).items():
            kind=body.get('count_kinds',{}).get(service)
            if kind=='service_execution' and type(n) is int and n>0:
                values.append({'service':service,'session':row['session_key'],'at':target,'n':n,'valid':valid,'kind':kind})
    before=[dict(r) for r in store.raw.execute('SELECT service_path,kind,session_key,value,qualified FROM anomaly_detection.adp_service_reference_points WHERE start_ns=%s',(target,)).fetchall()]
    incoming=[{'service_path':r['service'],'kind':r['kind'],'session_key':r['session'],'value':r['n'],'qualified':r['valid']} for r in values]
    changed=canonical(sorted(before,key=lambda r:(r['service_path'],r['kind'],r['session_key'])))!=canonical(sorted(incoming,key=lambda r:(r['service_path'],r['kind'],r['session_key'])))
    store.raw.execute('DELETE FROM anomaly_detection.adp_service_reference_points WHERE start_ns=%s',(target,))
    if values:
        store.raw.execute("INSERT INTO anomaly_detection.adp_service_reference_points SELECT v->>'service',v->>'kind',v->>'session',"
            "(v->>'at')::bigint,(v->>'n')::integer,(v->>'valid')::boolean FROM jsonb_array_elements(%s::jsonb) AS v",(canonical(values),))
    store.raw.execute('INSERT INTO anomaly_detection.adp_service_reference_scopes VALUES(%s,%s) ON CONFLICT(start_ns) DO UPDATE SET stamp=excluded.stamp',
                      (target,canonical({k:proof.get(k) for k in ('namespace','stream_key','keys_fingerprint','generation','semantic_generation','scope_contract','source_finality')})))
    if changed:
        from .model_queue import reference_changed
        reference_changed(store,[(r['service_path'],target) for r in before+incoming])


def warm_one(store):
    row=store.raw.execute('SELECT sw.start_ns,sw.source FROM anomaly_detection.adp_source_windows sw WHERE sw.complete=TRUE '
        'AND NOT EXISTS(SELECT 1 FROM anomaly_detection.adp_service_reference_scopes r WHERE r.start_ns=sw.start_ns) '
        'ORDER BY sw.start_ns DESC LIMIT 1').fetchone()
    if not row:return False
    with store.transaction():
        rows=store.raw.execute('SELECT session_key,body FROM anomaly_detection.adp_windows WHERE start_ns=%s',(row['start_ns'],)).fetchall()
        refresh_points(store,row['start_ns'],json.loads(row['source']),rows)
        from .product_dependencies import context_changed_many
        context_changed_many(store,[(s,row['start_ns']) for r in rows for s in (json.loads(r['body']).get('counts') or {})])
    return True


def invalidate_points(store,scopes):
    if not scopes:return
    store.model_cache.clear()
    store.reference_inputs_cache.clear()
    changed=store.raw.execute("WITH scopes AS (SELECT DISTINCT v->>'session' AS session,(v->>'at')::bigint AS at FROM jsonb_array_elements(%s::jsonb) AS v) "
        'UPDATE anomaly_detection.adp_service_reference_points p SET qualified=FALSE FROM scopes s WHERE p.session_key=s.session AND p.start_ns=s.at AND p.qualified=TRUE RETURNING p.service_path,p.start_ns',
        (canonical([{'session':s,'at':at//FIVE_NS*FIVE_NS} for s,at in scopes if s]),)).fetchall()
    from .model_queue import reference_changed
    reference_changed(store,[(r['service_path'],r['start_ns']) for r in changed])


def timestamp(value):
    require(isinstance(value,str),'REFERENCE_TIMESTAMP_INVALID')
    match=re.fullmatch(r'(.*?)(?:\.(\d+))?(Z|[+-]\d\d:\d\d)',value)
    require(match is not None,'REFERENCE_TIMESTAMP_INVALID')
    dt=datetime.fromisoformat(match[1]+('+00:00' if match[3]=='Z' else match[3]))
    return int(dt.timestamp())*1_000_000_000+int((match[2] or '')[:9].ljust(9,'0'))


def reference(points,session,target,service,*,unit,reference_id):
    """One conservative maximum per OTHER session epoch, past-only, active-only.

    Sampling units are SessionID epochs, not independent humans. The empirical
    tail rank is descriptive under exchangeability, never a fraud probability.
    No missing bucket, pruned period, or absent session is filled with zero.
    """
    maxima={};times=[];n=0
    for p in points:
        if p['session_key']==session or not p.get('qualified',True) or not target-HORIZON<=p['start_ns']<target:continue
        value=p['value']
        if type(value) is not int or value<=0:continue
        maxima[p['session_key']]=max(maxima.get(p['session_key'],0),value)
        times.extend((p.get('first_ns',p['start_ns']),p.get('last_ns',p['start_ns'])))
        n+=p.get('point_count',1)
    values=sorted(maxima.values());span=max(times)-min(times) if times else 0
    ready=len(values)>=MIN_SESSIONS and span>=24*12*FIVE_NS
    body={'status':'READY_BASELINE' if ready else 'INSUFFICIENT_DATA','version':MODEL_VERSION,
          'model_id':'pr1:'+digest([MODEL_VERSION,service,target,session,unit,reference_id,sorted(maxima.items())]),
          'family':'pooled_session_maximum','cutoff_ns':target,'reference_id':reference_id,'unit':unit,
          'other_session_epochs':len(values),'active_session_windows':n,'observed_span_ns':span,
          'zero_filled':False,'subject_independence':'session_epochs_not_proven_distinct_people',
          'reference_values':values,'expected':median(values) if values else None,'upper':max(values) if values else None,
          'reason':'POOLED_REFERENCE_READY' if ready else 'INSUFFICIENT_POOLED_SESSION_REFERENCE'}
    return body


def rank_screen(ref,observed,comparisons):
    """Tie-conservative tail rank, adjusted for services in this target.

    A fixed multiplier of the largest past value discards rare observations
    simply because one historical actor was busy. Rank screening uses the
    entire qualified distribution. This is a review screen, not a calibrated
    production false-positive guarantee: exposure/exchangeability can differ.
    """
    values=ref['reference_values'];m=max(1,int(comparisons))
    tail=(1+len(values)-bisect_left(values,observed))/(len(values)+1)
    adjusted=min(1.,m*tail)
    return {'empirical_tail_rank':tail,'adjusted_empirical_tail_rank':adjusted,
        'comparison_count':m,'screening_level':SCREENING_LEVEL,
        'screening_policy':'session_max_tail_rank_bonferroni_v1',
        'calibration_status':'DESCRIPTIVE_RANK_PRODUCTION_ERROR_RATE_NOT_VALIDATED',
        'high':bool(ref['status']=='READY_BASELINE' and observed>ref['expected'] and adjusted<=SCREENING_LEVEL)}


def qualify_roots(archive,token,source_fingerprint):
    """Qualify ONLY a client-root rate metric; never override semantic eligibility."""
    with zipfile.ZipFile(archive) as z:
        require(z.getinfo('manifest.json').file_size<=256*1024,'REFERENCE_MANIFEST_TOO_LARGE')
        manifest=json.loads(z.read('manifest.json'));proof=manifest.get('root_verification') or {}
        require(manifest.get('format')=='AD_SCOPED_HISTORY_EXPORT_1' and proof.get('complete_root_query_snapshot') is True,
                'REFERENCE_ROOT_CENSUS_NOT_COMPLETE')
        require(manifest.get('source_fingerprint')==source_fingerprint,'REFERENCE_SOURCE_MISMATCH')
        service=manifest.get('service');require(isinstance(service,str) and re.fullmatch(r'[A-Za-z0-9_.]+/[A-Za-z0-9_]+',service)
            and service not in ('Services.v1/InvoiceRegister',),'REFERENCE_SERVICE_NOT_DIRECT')
        info=z.getinfo('service_roots.jsonl.gz');require(info.file_size<=64*1024*1024,'REFERENCE_BYTES_EXCEEDED')
        blob=z.read(info);require(hashlib.sha256(blob).hexdigest()==proof.get('capture_sha256'),'REFERENCE_CAPTURE_HASH_MISMATCH')
        import io
        with gzip.GzipFile(fileobj=io.BytesIO(blob)) as stream:raw=stream.read(64*1024*1024+1)
        require(len(raw)<=64*1024*1024,'REFERENCE_BYTES_EXCEEDED')
    begin=timestamp(manifest['history_from_tehran']);cutoff=timestamp(manifest['training_before_tehran']);end=timestamp(manifest['holdout_until_tehran'])
    require(begin<cutoff<=end and cutoff%FIVE_NS==0,'REFERENCE_BOUNDS_INVALID')
    records=[json.loads(line) for line in raw.splitlines()]
    require(len(records)==proof.get('selected_root_records') and len(records)<=5000,'REFERENCE_ROOT_COUNT_MISMATCH')
    seen=set();ids=set();calls=[];cases=set();part_counts=Counter();missing=0
    for row in records:
        s=row.get('_source');require(isinstance(s,dict) and row.get('selected_service_root') is True,'REFERENCE_ROW_INVALID')
        origin=(row.get('_index'),row.get('_id'))
        require(all(isinstance(v,str) and v for v in origin) and origin not in seen,'REFERENCE_ORIGIN_DUPLICATED');seen.add(origin)
        require(type(row.get('_version')) is int and row['_version']>0,'REFERENCE_VERSION_MISSING')
        rid=s.get('RequestID');sid=s.get('Session');at=timestamp(s.get('@timestamp'))
        require(isinstance(rid,str) and rid and rid not in ids,'REFERENCE_REQUEST_AMBIGUOUS');ids.add(rid)
        require(api_path(s.get('CallPath'))==service and begin<=at<end,'REFERENCE_ROW_OUTSIDE_SCOPE')
        # The archive is a census of client API roots, not arbitrary substring
        # matches from SQL/provider messages. Keep the metric's scope explicit.
        require(re.match(r'^(GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS) https?://',str(s.get('message',''))) is not None,
                'REFERENCE_CLIENT_ROOT_NOT_OBSERVED')
        part='history' if at<cutoff else 'holdout';require(row.get('partition')==part,'REFERENCE_PARTITION_OR_LEAKAGE_ERROR')
        part_counts[part]+=1
        valid=isinstance(sid,str) and sid.strip()==sid and 0<len(sid)<=512 and sid.casefold() not in ('n/a','null','none')
        if not valid:missing+=1;continue
        session_key=token('session',sid)
        if part=='history':calls.append({'request_key':token('request',rid),'session_key':session_key,'at_ns':at,
            'origin':canonical({'index':origin[0],'id':origin[1],'version':row['_version']})})
        else:cases.add((session_key,at//FIVE_NS*FIVE_NS))
    for part in ('history','holdout'):
        require(part_counts[part]==proof.get('datasets',{}).get(part,{}).get('selected_client_rows'),'REFERENCE_PARTITION_COUNT_MISMATCH')
    dataset='hr1:'+digest([proof['capture_sha256'],source_fingerprint,service,begin,cutoff])
    return {'dataset_id':dataset,'service_path':service,'begin_ns':begin,'cutoff_ns':cutoff,'calls':calls,'cases':sorted(cases),
        'qualification':{'unit':'observed_direct_client_request_roots','semantic_fact_imported':False,
            'full_request_context_claimed':False,'canonical_behavior_baseline':False,'raw_reference_sha256':proof['capture_sha256'],
            'training_calls':len(calls),'missing_session_rows_excluded':missing,'holdout_calls_excluded':part_counts['holdout'],
            'source_finality':'not_established','late_reference_corrections':'new_census_or_canonical_history_required'}}


def import_roots(store,packet,now):
    service=packet['service_path'];dataset=packet['dataset_id']
    with store.transaction():
        if store.raw.execute('SELECT 1 FROM anomaly_detection.adp_http_reference_sets WHERE dataset_id=%s',(dataset,)).fetchone():
            return {'status':'ALREADY_IMPORTED','dataset_id':dataset}
        body={k:v for k,v in packet.items() if k not in ('calls','cases')}
        store.raw.execute('INSERT INTO anomaly_detection.adp_http_reference_sets VALUES(%s,%s,%s,%s,%s,%s)',
            (dataset,service,packet['begin_ns'],packet['cutoff_ns'],canonical(body),now))
        values=[(dataset,r['request_key'],r['session_key'],r['at_ns'],r['origin']) for r in packet['calls']]
        if values:
            with store.raw.cursor() as cur:cur.executemany('INSERT INTO anomaly_detection.adp_http_reference_calls VALUES(%s,%s,%s,%s,%s)',values)
        for session,target in packet['cases']:
            store.raw.execute('INSERT INTO anomaly_detection.adp_reference_cases VALUES(%s,%s,%s) ON CONFLICT DO NOTHING',(session,target,dataset))
        from .product_dependencies import context_changed
        context_changed(store,service,packet['begin_ns'],at_high=packet['cutoff_ns'])
        from .model_queue import reference_changed
        reference_changed(store,[(service,packet['begin_ns']),(service,packet['cutoff_ns'])])
        store.model_cache.clear()
    return {'status':'IMPORTED_ROOT_RATE_REFERENCE','dataset_id':dataset,'training_calls':len(values),
            'holdout_windows':len(packet['cases']),'semantic_facts_created':0,'source_modified':False}


def bootstrap(store,project,source):
    """Read the owner's existing export once, locally. No new Elasticsearch I/O."""
    if getattr(store,'history_floor_ns',0):
        return {'status':'LOCAL_REFERENCE_DISABLED_BY_AD_HISTORY_BOUNDARY','model_version':MODEL_VERSION}
    project=Path(project);reports=project/'AnomalyDetection/reports'
    candidates=sorted(reports.glob('anomaly_history_v2_*.zip'),key=lambda p:p.stat().st_mtime,reverse=True)[:20]
    if not candidates:return {'status':'NO_LOCAL_ROOT_REFERENCE','model_version':MODEL_VERSION}
    # Use the pinned source's key implementation read-only; never initialize a
    # ViewerDB, generate keys, or request source writes.
    known={}
    def literal(node):
        if isinstance(node,ast.Name):return known[node.id]
        if isinstance(node,ast.Dict):return {literal(k):literal(v) for k,v in zip(node.keys,node.values)}
        if isinstance(node,(ast.List,ast.Tuple)):return [literal(n) for n in node.elts]
        if isinstance(node,ast.Call) and isinstance(node.func,ast.Name) and node.func.id=='dict' and not node.args:
            require(all(k.arg for k in node.keywords),'REFERENCE_LITERAL_CONFIG_REQUIRED')
            return {k.arg:literal(k.value) for k in node.keywords}
        return ast.literal_eval(node)
    for item in ast.parse((project/'viewer_config.local.py').read_text(encoding='utf-8-sig')).body:
        if isinstance(item,(ast.Assign,ast.AnnAssign)) and item.value is not None:
            for name in (item.targets if isinstance(item,ast.Assign) else [item.target]):
                if isinstance(name,ast.Name):
                    try:known[name.id]=literal(item.value)
                    except (ValueError,TypeError,KeyError):pass
    settings=known.get('ELASTICSEARCH');require(isinstance(settings,dict),'REFERENCE_LITERAL_ES_BINDING_MISSING')
    source_fp=hashlib.sha256(json.dumps([str(settings.get('host','')).rstrip('/'),settings.get('index_pattern')]).encode()).hexdigest()
    sys.path.insert(0,str(project)) if str(project) not in sys.path else None
    from p24_foundation.privacy import Keys
    keys=Keys.read(project/known.get('KEYS_PATH','private/viewer_keys.json'))
    require(keys.fingerprint==source['keys_fingerprint'] and source.get('runtime_sha256')==SOURCE_SHA,'REFERENCE_KEY_OR_SOURCE_BINDING_MISMATCH')
    def token(kind,value):return keys.token('p24-viewer.1',kind,value).split(':')[-1]
    rejected=[];existing=None
    for path in candidates:
        try:packet=qualify_roots(path,token,source_fp)
        except (ValueError,KeyError,OSError,zipfile.BadZipFile) as exc:
            rejected.append(type(exc).__name__);continue
        with store.transaction():store.bind(source)
        result=import_roots(store,packet,time.time_ns());result.update(model_version=MODEL_VERSION,rejected_files=len(rejected))
        if result['status']=='ALREADY_IMPORTED':existing=result;continue
        return result
    if existing:return existing
    return {'status':'NO_QUALIFIED_LOCAL_ROOT_REFERENCE','rejected_files':len(rejected),'model_version':MODEL_VERSION}


def model(store,service,session,target,kind):
    """Cache only against the existing context dependency epoch/CAS contract."""
    name='reference:'+service
    with store.transaction():
        store.raw.execute('INSERT INTO anomaly_detection.adp_peer_epochs VALUES(%s,0) ON CONFLICT DO NOTHING',(name,))
        epoch=store.raw.execute('SELECT version FROM anomaly_detection.adp_peer_epochs WHERE service_path=%s FOR SHARE',(name,)).fetchone()['version']
        key=('pooled-service',service,session,target,kind,epoch)
        if key in store.model_cache:return store.model_cache[key],{name:epoch}
        shared_key=(service,target,kind,epoch)
        shared=store.reference_inputs_cache.get(shared_key)
        if shared is None:
            # Same per-session maxima, positive-point count and time span,
            # with one indexed range read instead of two heap passes plus
            # transmitting every historical point to Python. Any invalid
            # point still disqualifies the entire session in this interval.
            rows=store.raw.execute("SELECT session_key,MAX(value) AS value,COUNT(*) AS raw_count,COUNT(*) FILTER(WHERE value>0) AS point_count,MIN(start_ns) FILTER(WHERE value>0) AS first_ns,MAX(start_ns) FILTER(WHERE value>0) AS last_ns,COALESCE(MAX(start_ns) FILTER(WHERE value>0),MIN(start_ns)) AS start_ns FROM anomaly_detection.adp_service_reference_points WHERE service_path=%s AND kind=%s AND start_ns<%s AND start_ns>=%s GROUP BY session_key HAVING BOOL_AND(qualified) LIMIT 20001",
                (service,kind,target,target-HORIZON)).fetchall()
            canonical_points=[dict(row) for row in rows] if sum(r['raw_count'] for r in rows)<=20000 else []
            excluded={r['session_key'] for r in store.raw.execute('SELECT DISTINCT i.session_key FROM anomaly_detection.adp_incidents i '
                'JOIN anomaly_detection.adp_feedback f ON f.incident_key=i.incident_key WHERE i.target_ns<%s '
                "AND f.label='confirmed_suspicious' AND f.id=(SELECT MAX(v.id) FROM anomaly_detection.adp_feedback v WHERE v.incident_key=i.incident_key)",(target,)).fetchall()}
            shared={'canonical':[p for p in canonical_points if p['session_key'] not in excluded],
                'excluded':excluded,'http_loaded':False,'http':[],'http_id':None}
            if len(store.reference_inputs_cache)>=16:
                store.reference_inputs_cache.pop(next(iter(store.reference_inputs_cache)))
            store.reference_inputs_cache[shared_key]=shared
        # Complete rolling canonical history supersedes the finite bootstrap.
        # Units are selected independently and are never pooled together.
        result=reference(shared['canonical'],session,target,service,unit='canonical_service_executions',reference_id='owned-complete-windows')
        if result['status']!='READY_BASELINE' and kind=='service_execution':
            if not shared['http_loaded']:
                selected=store.raw.execute('SELECT * FROM anomaly_detection.adp_http_reference_sets WHERE service_path=%s AND cutoff_ns<=%s '
                    'AND cutoff_ns>=%s ORDER BY cutoff_ns DESC,imported_ns DESC LIMIT 1',(service,target,target-SEED_LIFETIME)).fetchone()
                if selected:
                    rows=store.raw.execute('SELECT session_key,(at_ns/%s)*%s AS start_ns,COUNT(*)::integer AS value '
                        'FROM anomaly_detection.adp_http_reference_calls WHERE dataset_id=%s AND at_ns<%s '
                        'GROUP BY session_key,2',(FIVE_NS,FIVE_NS,selected['dataset_id'],selected['cutoff_ns'])).fetchall()
                    shared['http']=[dict(r) for r in rows if r['session_key'] not in shared['excluded']]
                    shared['http_id']=selected['dataset_id']
                shared['http_loaded']=True
            if shared['http_id']:
                result=reference(shared['http'],session,target,service,unit='observed_direct_client_request_roots',reference_id=shared['http_id'])
        result['selection_policy']='canonical_first_qualified_http_bootstrap_fallback'
        if len(store.model_cache)>=256:store.model_cache.clear()
        store.model_cache[key]=result
        return result,{name:epoch}


def decisions(store,job,context,details,services):
    current=next((w for w in context['windows'] if w['start_ns']==job['target_ns']),{})
    by_key={r['request_key']:r.get('details') for r in details};out=[];inputs={}
    comparisons=sum(current.get('count_kinds',{}).get(s)=='service_execution' for s in (current.get('counts') or {}))
    for service,observed in sorted((current.get('counts') or {}).items()):
        if service not in services:continue
        kind=current.get('count_kinds',{}).get(service)
        if kind!='service_execution':continue
        ref,epochs=model(store,service,job['session_key'],job['target_ns'],kind);inputs.update(epochs)
        reference_ready=ref['status']=='READY_BASELINE'
        screen=rank_screen(ref,observed,comparisons);high=screen.pop('high')
        resolution=screen['comparison_count']/(ref['other_session_epochs']+1)<=SCREENING_LEVEL
        ready=reference_ready and resolution
        keys={e['request_key'] for e in context.get('events',[]) if job['target_ns']<=e['anchor_ns']<job['target_ns']+FIVE_NS and api_path(e.get('root_call'))==service}
        # Raw HTTP reference only compares with matching ACTUAL HTTP transport,
        # not an InvoiceRegister dispatcher renamed to a business service.
        transports=[by_key[k] for k in keys if by_key.get(k)]
        incompatible=ref['unit']=='observed_direct_client_request_roots' and any(api_path(d.get('transport',{}).get('root_call'))!=service for d in transports)
        if ref['unit']=='observed_direct_client_request_roots' and len(keys)!=observed:incompatible=True
        if ref['unit']=='observed_direct_client_request_roots' and len(transports)==len(keys):
            incompatible=incompatible or any(not any(api_path(e.get('callpath'))==service and e.get('qualified') and e.get('raw_available')
                and type(e.get('at_ns')) is int and job['target_ns']<=e['at_ns']<job['target_ns']+FIVE_NS
                for e in d.get('evidence',[])) for d in transports)
        comparable=ref['unit']=='canonical_service_executions' or bool(keys and len(transports)==len(keys) and not incompatible)
        status='INSUFFICIENT_DATA' if not ready or incompatible or not context.get('target_complete') else 'CANDIDATE' if high else 'NO_DEVIATION_OBSERVED'
        reason=('INSUFFICIENT_POOLED_SESSION_REFERENCE' if not reference_ready else
            'REFERENCE_TAIL_RESOLUTION_INSUFFICIENT' if not resolution else
            'DIRECT_HTTP_REFERENCE_NOT_COMPARABLE' if incompatible else
            'POOLED_RATE_EXCEEDED' if high else 'POOLED_RATE_WITHIN_RANGE')
        out.append({'finding_key':'pf1:'+digest([job['session_key'],job['target_ns'],'peer_service_rate_5m',service]),
            'session_key':job['session_key'],'target_ns':job['target_ns'],'family':'peer_service_rate_5m','dimension':'activity',
            'service_path':service,'status':status,'reason':reason,'operator_alert':False,'precision_recall':'NOT_EVALUATED',
            'observed':observed,'expected':ref['expected'],'upper':ref['upper'],'peer_session_epochs':ref['other_session_epochs'],
            **screen,'baseline_unit':ref['unit'],'baseline_origin':'other_sessions_of_same_service_over_time',
            'single_signal_review_eligible':bool(high and comparable and observed>ref['upper']),
            'review_policy_version':2,'review_basis':'REFERENCE_CONTRAST' if high and ready and observed>ref['upper'] else 'DESCRIPTIVE_RARITY_ONLY',
            'score':float(observed/(ref['upper'] or 1)),
            'witness_request_key':current.get('witnesses',{}).get(service),'model':ref,
            'explanation_fa':(f'{observed} فراخوانی در پنج دقیقه؛ مرجعِ {ref["other_session_epochs"]} نشست دیگرِ همین خدمت، '
                f'بیشینهٔ مشاهده‌شدهٔ {ref["upper"]} را نشان می‌دهد. رتبهٔ دُم پس از تعدیل تعداد خدمات '
                f'{screen["adjusted_empirical_tail_rank"]:.6f} است؛ این رتبه احتمال تقلب یا تضمین نرخ خطا نیست.' if ready else
                'مرجعِ نشست‌های دیگرِ همین خدمت در طول زمان هنوز کافی نیست؛ دادهٔ ناکافی عادی‌بودن نیست.')})
    return out,inputs


def next_case(store,now):
    row=store.raw.execute('SELECT j.* FROM anomaly_detection.adp_reference_cases c JOIN anomaly_detection.adp_jobs j '
        'ON j.session_key=c.session_key AND j.target_ns=c.target_ns JOIN anomaly_detection.adp_source_windows sw ON sw.start_ns=j.target_ns '
        'WHERE j.target_scope=\'BEHAVIOR_TARGET\' AND j.dirty=TRUE AND j.due_ns<=%s AND sw.complete=TRUE ORDER BY j.target_ns,c.session_key LIMIT 1',(now,)).fetchone()
    return dict(row) if row else None


def case_report(store):
    rows=store.raw.execute('SELECT c.session_key,c.target_ns,s.service_path,j.version,j.processed_version,j.dirty,'
        'j.last_evaluated_ns,j.evaluation,i.state AS incident_state,w.body AS summary '
        'FROM anomaly_detection.adp_reference_cases c JOIN anomaly_detection.adp_http_reference_sets s ON s.dataset_id=c.dataset_id '
        'LEFT JOIN anomaly_detection.adp_jobs j ON j.session_key=c.session_key AND j.target_ns=c.target_ns '
        'LEFT JOIN anomaly_detection.adp_incidents i ON i.session_key=c.session_key AND i.target_ns=c.target_ns '
        'LEFT JOIN anomaly_detection.adp_windows w ON w.session_key=c.session_key AND w.start_ns=c.target_ns '
        'ORDER BY c.target_ns,c.session_key LIMIT 65').fetchall()
    cases=[]
    for row in rows[:64]:
        summary=json.loads(row['summary']) if row['summary'] else {}
        evaluation=json.loads(row['evaluation']) if row['evaluation'] else {}
        current=bool(row['version'] is not None and row['processed_version']==row['version'] and row['dirty'] is False)
        cases.append({'session_key':row['session_key'],'target_ns':row['target_ns'],'service_path':row['service_path'],
            'observed_canonical_executions':(summary.get('counts') or {}).get(row['service_path']) if summary.get('counts') is not None else None,
            'evaluation_current':current,'last_evaluated_ns':row['last_evaluated_ns'],'incident_state':row['incident_state'],
            'reference_decisions':[d for d in evaluation.get('decisions',[]) if d['family']=='peer_service_rate_5m' and d.get('service_path')==row['service_path']]})
    return {'reference_import':store.state('root_reference_import'),'cases':cases,'case_list_truncated':len(rows)>64,
            'case_results_are_persisted_not_read_time_reclassification':True,'source_modified':False,
            'precision_recall':'NOT_EVALUATED'}
