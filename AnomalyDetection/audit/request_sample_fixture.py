"""Scripted PostgreSQL I/O for the REAL request-sample dispatcher.

All IDs are synthetic. No SQL engine or database is opened. The fixture has
separate authoritative Fact rows and cached Profile bodies, so stale evidence
is not silently declared current by the fixture itself.
"""
from contextlib import nullcontext
from copy import deepcopy
from unittest.mock import patch
from anomaly_detection import FIVE_NS
from anomaly_detection.request_profiles import VERSION,output_features
from anomaly_detection.snapshot import canonical

T=1_800_000_000_000_000_000//FIVE_NS*FIVE_NS
S='Services.v1/FixtureInquiry'
FAMILIES=('service_workflow_change','response_schema_change','response_content_change','service_health','multi_session_target')


def make_profile(i,at,actor):
    key=f'{i:064x}'
    return dict(version=VERSION,request_key=key,session_key=actor,service_path=S,at_ns=at,ended_ns=at+1,
        qualified=True,actor_qualified=True,semantic_active=True,semantic_revision=1,anchor_key='ba1:'+key,
        content_complete=True,input_complete=True,output_complete=True,complete_event_scope=True,
        targets={'provider':str(i)},subjects=[],ip_keys=['synthetic-ip'],stages=[S,'DB.Access'],
        outputs={'provider':output_features({'Result':{'Exists':True}})},
        result={'scope':'direct_api_reported_result','code':'G00000'},witnesses=[{'at_ns':at}])


class Result:
    def __init__(self,rows=()):self.rows=list(rows)
    def fetchone(self):return self.rows[0] if self.rows else None
    def fetchall(self):return self.rows


class Store:
    history_floor_ns=0
    def __init__(self,family,mode='valid'):
        self.family=family;self.mode=mode;self.raw=self;self.states={};self.queries=[]
        self.current=[make_profile(10000+i,T+i,f'current-{i%3}') for i in range(12)]
        self.past=[make_profile(100000+w*20+i,T-(120-w)*FIVE_NS+i,f'peer-{i%20}') for w in range(120) for i in range(20)]
        for p in self.current:
            if family=='service_workflow_change':p['stages']=[S]
            if family=='response_schema_change':p['outputs']['provider']=output_features({'Result':{'Exists':'changed-type'}})
            if family=='response_content_change':p['outputs']['provider']=output_features({'Result':{'Exists':False}})
            if family=='service_health':p['result']['code']='GD2076'
            if family=='multi_session_target':p['targets']={'provider':'same-target-across-sessions'}
            if mode=='technical_without_fact':p.update(semantic_active=False,semantic_revision=None,anchor_key=None)
        self.frames=[dict(start_ns=T,available=True,request_keys=canonical([p['request_key'] for p in self.current]))]
        for w in range(120):
            at=T-(w+1)*FIVE_NS
            self.frames.append(dict(start_ns=at,available=True,request_keys=canonical([p['request_key'] for p in self.past if p['at_ns']//FIVE_NS*FIVE_NS==at])))
    def state(self,key):return self.states.get(key,{})
    def save_state(self,key,value):self.states[key]=deepcopy(value)
    def transaction(self):return nullcontext()
    def bind(self,source):pass
    def execute(self,sql,params=()):
        self.queries.append(sql)
        if sql.startswith('SELECT * FROM anomaly_detection.adp_scenario_jobs'):
            return Result([dict(scope_key='synthetic-scope',kind='request_workflow' if self.family=='service_workflow_change' else 'request_response',
                entity_key=S,service_path=S,target_ns=T,version=2)])
        if sql.startswith('SELECT * FROM anomaly_detection.adp_service_profile_samples'):return Result(self.frames)
        if sql.startswith('SELECT COALESCE(SUM(octet_length(body))'):return Result([{'n':8_000_000}])
        if 'FROM anomaly_detection.adp_profiles p' in sql or sql.startswith('SELECT request_key,body FROM anomaly_detection.adp_profiles'):
            rows=[]
            for p in self.current+self.past:
                current=p['at_ns']>=T
                rev=2 if current and self.mode=='stale_revision' else 1
                state='withdrawn' if current and self.mode=='withdrawn_fact' else 'active'
                present=not (current and self.mode=='source_absent')
                if current and self.mode in ('missing_fact','technical_without_fact'):rev=state=present=None
                rows.append(dict(request_key=p['request_key'],body=canonical(p),revision=rev,anchor_key='ba1:'+p['request_key'] if rev else None,
                    state=state,source_present=present,refresh_pending=bool(current and self.mode=='refresh_pending')))
            return Result(rows)
        if sql.startswith('SELECT DISTINCT m.request_key'):return Result()
        if sql.startswith('SELECT version FROM anomaly_detection.adp_scenario_jobs'):return Result([{'version':2}])
        if sql.startswith(('INSERT ','UPDATE ')):return Result()
        raise AssertionError('Unsupported SCRIPTED SQL: '+sql[:100])


def run_sample(family,mode='valid'):
    from anomaly_detection.scenario_store import process_one
    store=Store(family,mode)
    with patch('anomaly_detection.cases.replace_scope') as publication,patch('anomaly_detection.cases.normal_observations'):
        outcome=process_one(store,T+FIVE_NS)
    item=next(d for d in outcome['decisions'] if d['family']==family)
    return item,outcome['status'],publication.call_args,store
