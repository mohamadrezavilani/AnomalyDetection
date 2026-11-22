"""Hourly/daily-weekday profiles selected on a chronological holdout.

One five-minute slot per hour is sampled, over at most 28 days. All source
points are complete published summaries strictly before the target. Models
predict counts, not fraud probabilities. Adapted from legacy temporal.py.
"""
from collections import defaultdict
from datetime import datetime, timezone
from functools import lru_cache
import math
from statistics import median
from zoneinfo import ZoneInfo
from compact_behavior import FIVE
from compact_behavior.extract import digest

HORIZON = 28*288
ZONE = ZoneInfo('Asia/Tehran')


def phase(at, family):
    local=datetime.fromtimestamp(at/1e9,timezone.utc).astimezone(ZONE)
    return local.hour if family=='daily' else local.weekday()*24+local.hour


@lru_cache(maxsize=128)
def fit(points):
    if len(points)<72:
        return {'status':'WARMING_UP'}
    slots=(points[-1][0]-points[0][0])//(12*FIVE)+1
    if len(points)/slots<.8:
        return {'status':'INSUFFICIENT_COVERAGE'}
    split=max(48,len(points)*3//4)
    train,validation=points[:split],points[split:]
    logs=[math.log1p(p[1]) for p in train]
    running=list(logs)
    residuals=[]
    for _,value in validation:
        residuals.append(math.log1p(value)-median(running[-24:]))
        running.append(math.log1p(value))
    baseline_error=sum(abs(v) for v in residuals)/len(residuals)
    best=baseline_error;family='rolling';selected=residuals
    for candidate,cycle in [('daily',24),('weekly',168)]:
        if slots<3*cycle or len(points)<3*cycle*.9:
            continue
        grouped=defaultdict(list)
        for at,value in train:
            grouped[phase(at,candidate)].append(math.log1p(value))
        if sum(len(v)>=2 for v in grouped.values())<cycle*.9:
            continue
        if any(phase(at,candidate) not in grouped for at,_ in validation):
            continue
        profiles={k:median(v) for k,v in grouped.items()}
        errors=[math.log1p(value)-profiles[phase(at,candidate)] for at,value in validation]
        error=sum(abs(v) for v in errors)/len(errors)
        if error<best and error<=baseline_error*.75:
            family,best,selected=candidate,error,errors
    groups=defaultdict(list)
    if family!='rolling':
        for at,value in points:groups[phase(at,family)].append(math.log1p(value))
    return dict(status='READY',family=family,profile={k:median(v) for k,v in groups.items()},
        residual_high=sorted(selected)[math.ceil(.995*len(selected))-1],
        validation_mae=best,validation_samples=len(validation),
        model_id=digest(['compact-seasonality-1',points,family,selected]))


def adjust_rates(start, results, references, add):
    refs=sorted((r for r in references if start-HORIZON*FIVE<=r['start_ns']<start
        and (r['start_ns']//FIVE)%12==(start//FIVE)%12),key=lambda r:r['start_ns'])
    if len({r['start_ns'] for r in refs})!=len(refs):
        raise ValueError('duplicate_temporal_reference')
    prepared={}
    for result in list(results):
        if result['method'] not in ('service_rate','actor_rate'):
            continue
        result['baseline_family']='rolling_24h'
        key=result['service'];index=0 if result['method']=='service_rate' else 1
        if (key,index) not in prepared:
            points=[];used=[];seen=False
            for ref in refs:
                value=ref['rates'].get(key)
                seen=seen or value is not None
                if not seen or value is not None and not value[2] or value is None and not ref['complete']:
                    continue
                points.append((ref['start_ns'],float(value[index]) if value else 0.));used.append(ref)
            model=fit(tuple(points)) if points and points[-1][0]>=start-24*FIVE else {'status':'INSUFFICIENT_RECENT_COVERAGE'}
            prepared[key,index]=(model,used,digest([(r['start_ns'],r['summary_hash']) for r in used]))
        model,used,signature=prepared[key,index]
        result['seasonal_readiness']=model['status']
        if model['status']!='READY' or model['family']=='rolling' or result['status'] not in ('NORMAL','ANOMALY'):
            continue
        prediction=model['profile'].get(phase(start,model['family']))
        if prediction is None:
            continue
        expected=max(0,math.expm1(prediction))
        threshold=max(5,expected*3,expected+4*math.sqrt(max(1,expected)),
            math.expm1(prediction+max(0,model['residual_high']))*1.1)
        result.update(baseline=expected,threshold=threshold,
            status='ANOMALY' if result['observed']>threshold else 'NORMAL',
            baseline_family=model['family'],model_id=model['model_id'],
            validation_log_mae=model['validation_mae'],validation_samples=model['validation_samples'],
            reference_windows=len(used),reference_from_ns=used[0]['start_ns'],
            reference_cutoff_ns=used[-1]['start_ns']+FIVE,
            reference_signature=signature,
            reference_policy='PAST_COMPLETE_HOURLY_SAMPLED_5M_WINDOWS_TEHRAN_HOLDOUT',
            reason='TEMPORAL_PROFILE_SELECTED_ON_PAST_HOLDOUT')


def initialize(db, schema):
    db.execute(f'''CREATE TABLE IF NOT EXISTS {schema}.rate_history(
        stream_id TEXT NOT NULL,start_ns BIGINT NOT NULL,slot SMALLINT NOT NULL,
        rates JSONB NOT NULL,complete BOOLEAN NOT NULL,summary_hash TEXT NOT NULL,
        PRIMARY KEY(stream_id,start_ns))''')
    db.execute(f'CREATE INDEX IF NOT EXISTS compact_rate_slot ON {schema}.rate_history(stream_id,slot,start_ns)')
    db.execute(f'''CREATE TABLE IF NOT EXISTS {schema}.rate_backfill(
        stream_id TEXT PRIMARY KEY,next_ns BIGINT NOT NULL)''')


def save_rates(db, schema, stream, start, summary, signature):
    from psycopg.types.json import Jsonb
    rates={k:[v['count'],v.get('actor_p95',0),not bool(v['invalid_rate'])]
        for k,v in summary['services'].items() if k!='<unresolved>'}
    db.execute(f'''INSERT INTO {schema}.rate_history SELECT %s,%s,%s,%s,%s,%s
        WHERE EXISTS(SELECT 1 FROM {schema}.window_results WHERE stream_id=%s AND start_ns=%s AND summary_hash=%s)
        ON CONFLICT(stream_id,start_ns) DO UPDATE SET rates=excluded.rates,
        complete=excluded.complete,summary_hash=excluded.summary_hash
        WHERE {schema}.rate_history.summary_hash IS DISTINCT FROM excluded.summary_hash''',
        (stream,start,(start//FIVE)%12,Jsonb(rates),not(summary['invalid_contract'] or summary['unresolved']),signature,
         stream,start,signature))


def backfill(db, schema, stream):
    # Bounded one-time projection of existing summaries; no behavior/source scan.
    with db.transaction():
        cursor=db.execute(f'SELECT next_ns FROM {schema}.rate_backfill WHERE stream_id=%s',(stream,)).fetchone()
        rows=db.execute(f'''SELECT start_ns,summary,summary_hash FROM {schema}.window_results
            WHERE stream_id=%s AND start_ns>=%s ORDER BY start_ns LIMIT 16''',
            (stream,cursor['next_ns'] if cursor else 0)).fetchall()
        for row in rows:save_rates(db,schema,stream,row['start_ns'],row['summary'],row['summary_hash'])
        if rows:
            db.execute(f'''INSERT INTO {schema}.rate_backfill VALUES(%s,%s)
                ON CONFLICT(stream_id) DO UPDATE SET next_ns=excluded.next_ns''',(stream,rows[-1]['start_ns']+FIVE))
    return len(rows)
