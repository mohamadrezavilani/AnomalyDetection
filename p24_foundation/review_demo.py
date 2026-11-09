"""Local review data from sanitized fixtures and an explicitly synthetic conflict."""
import copy
import json
import uuid
from collections import Counter

from .errors import FoundationError
from .investigation import VIEW_VERSION, operation_card, request_card
from .parser import Semantics,normalize_event
from .privacy import Keys
from .reconstruction import reconstruct,select_events,registration_candidates
from .store import ROOT,stable_id
from .time import parse_time


class DemoReviewProvider:
    publication_id='00000000-0000-4000-8000-000000000201'
    mode='demo'

    def __init__(self):
        self.keys=Keys(b'\x41'*32,b'\x42'*32,'demo_v1');namespace=self.namespace='review_demo'
        self.raw_session=json.loads((ROOT/'fixtures/MANIFEST.json').read_text())['anchors']['session_token']
        self.session_key=self.keys.token(namespace,'session',self.raw_session)
        semantics=Semantics(ROOT/'catalogs/error_code_catalog.json');events=[];sources={}
        for name in ('session_activity.sanitized.json','boundary.sanitized.json','registration.sanitized.json'):
            from .intake import read_batch
            for ordinal,record in enumerate(read_batch(ROOT/'fixtures'/name).records):
                e=normalize_event(record,self.keys,namespace,semantics,fallback_scope=name,ordinal=ordinal)
                e['event_version_id']=stable_id(e['event_key'],e['content_digest']);events.append(e)
                sources[e['event_key']]=[dict(snapshot_id=str(uuid.uuid5(uuid.NAMESPACE_URL,name)),source_key='demo:'+name,intake_revision=1,row_ordinals=[ordinal])]
        # This conflict is deliberately fabricated; it is not a finding about
        # the source fixture or an operator decision.
        for i,path in enumerate(('Core.v1/ConfigBasic','DBPath.app.ud_prc_userSessionHasAccess')):
            message='POST https://demo.invalid/config HTTP/1.1 (G00000 | successful)' if i==0 else '(Command Text: ud_prc_userSessionHasAccess)(Code: 1)(Result: Ok)(SQL Parameters: @session=DEMO_OTHER_SESSION @action=v1/ConfigBasic)'
            record={'_index':'demo-synthetic','_id':'identity-conflict-'+str(i),'_source':{
                '@timestamp':'2026-10-20T07:36:00Z','RequestID':'DEMO_IDENTITY_CONFLICT','Session':self.raw_session,
                'IP':'198.51.100.40','CallPath':path,'message':message,'ExecutionTime':'0'}}
            e=normalize_event(record,self.keys,namespace,semantics,fallback_scope='demo-conflict',ordinal=i)
            e['event_version_id']=stable_id(e['event_key'],e['content_digest']);events.append(e)
            sources[e['event_key']]=[dict(snapshot_id=str(uuid.uuid5(uuid.NAMESPACE_URL,'demo-conflict')),source_key='demo:synthetic-conflict',intake_revision=1,row_ordinals=[i])]
        selected=select_events(events,parse_time('2026-10-20T07:45:00Z').epoch_ns)
        self.summaries={r['request_key']:r for r in reconstruct(selected)}
        self.operations={}
        for e in selected['selected']:
            d=e['descriptor'];key=d['request_key']
            if not key:continue
            item=dict(origin_key=e['event_key'],event_version_id=str(e['event_version_id']),selection_state='selected',selection_reason='demo_fixture',
                      source_time_epoch_ns=d['source_time']['epoch_ns'],timestamp_precision=d['source_time']['fraction_digits'],
                      source_role=d['role'],endpoint=d['endpoint'],event_kind=d['event_kind'],descriptor=e['payload'],provenance=sources[e['event_key']])
            self.operations.setdefault(key,[]).append(operation_card(item))
        for items in self.operations.values():items.sort(key=lambda i:(int(i['time_ns']),i['origin_key']))
        self.examples=[dict(key=r['request_key'],label='بررسی پاسخ ناموفق سرویس‌دهنده') for r in self.summaries.values() if r['provider_observation_count'] and r['final_outcome']=='failure'][:1]

    def _check(self,publication):
        if publication!=self.publication_id:raise FoundationError('publication_not_available')

    def _incident_fixture(self):
        keys=sorted(self.summaries)[:2]
        incident=str(uuid.uuid5(uuid.NAMESPACE_URL,'p24-synthetic-incident'))
        revision=str(uuid.uuid5(uuid.NAMESPACE_URL,'p24-synthetic-incident-revision'))
        requests=[dict(request_key=k,client_http=True,first_event_ns=self.summaries[k]['first_time_ns'],last_event_ns=self.summaries[k]['last_time_ns']) for k in keys]
        observations=[dict(first_event_ns=r['first_event_ns'],last_event_ns=r['last_event_ns'],finding_ids=['synthetic']) for r in requests]
        return dict(incident_id=incident,revision_id=revision,generation=1,
            result=dict(publication_id=self.publication_id,pattern_key='synthetic-review-example',scope_kind='session',failure_family=None,
                distinct_client_http_requests=len(keys),distinct_supported_requests=len(keys),occurrence_count=len(observations),
                occurrences=observations,requests=requests,active_findings=[],excluded_findings=[],priority='unrated',
                first_event_ns=min((r['first_event_ns'] for r in requests),key=int,default=None),
                last_event_ns=max((r['last_event_ns'] for r in requests),key=int,default=None),
                coverage='Synthetic demo only; not traffic-wide completeness.',root_cause='not_established'),
            review=dict(verdict='unmarked',visibility='active'))

    def incidents(self,publication,*,limit=25,cursor=None):
        self._check(publication)
        items,following=self._page([self._incident_fixture()],limit,cursor,'incidents')
        return dict(items=items,next_cursor=following)

    def incident(self,publication,key,*,revision_id=None):
        self._check(publication);saved=self._incident_fixture()
        if key!=saved['incident_id'] or revision_id not in (None,saved['revision_id']):raise FoundationError('incident_not_available')
        return saved

    def incident_evidence(self,publication,key,*,revision_id=None,limit=25,cursor=None):
        saved=self.incident(publication,key,revision_id=revision_id)
        rows,following=self._page(saved['result']['requests'],limit,cursor,'incident-evidence:'+saved['revision_id'])
        return dict(total=len(saved['result']['requests']),items=rows,next_cursor=following)

    def incident_revision_status(self,key,revision_id):
        saved=self._incident_fixture()
        if key!=saved['incident_id'] or revision_id!=saved['revision_id']:raise FoundationError('incident_not_available')
        return dict(incident_id=key,revision_id=revision_id,latest_revision_id=revision_id,latest_generation=saved['generation'],is_latest=True)

    def incident_priority(self,key):
        saved=self._incident_fixture()
        if key!=saved['incident_id']:raise FoundationError('incident_not_available')
        return dict(priority='unrated',stale=False,decision_id=None)

    def incident_priority_history(self,key,*,limit=25,cursor=None):
        saved=self._incident_fixture()
        if key!=saved['incident_id']:raise FoundationError('incident_not_available')
        if cursor is not None:raise FoundationError('invalid_page_cursor')
        return dict(incident_id=key,total=0,items=[],next_cursor=None,as_of='synthetic',page_size=limit)

    def incident_links(self,key):
        saved=self._incident_fixture()
        if key!=saved['incident_id']:raise FoundationError('incident_not_available')
        return dict(items=[],total=0,claim='shared RequestID evidence only; no common identity or root cause inferred')

    def investigations(self,publication):
        self._check(publication)
        return dict(publication_id=publication,items=[],total=0,
                    claim='Only validated shared RequestID evidence is shown; no common identity or root cause inferred')

    def workflows(self,publication,*,limit=25,cursor=None):
        self._check(publication)
        from .workflow_demo import workflow_examples
        result=workflow_examples()['scenarios'][1]['projection']
        for row in result['state_publications']:
            row['state_publication_id']=str(uuid.uuid5(uuid.NAMESPACE_URL,row['subject_token'] or row['workflow_token']))
        result['state_publication_count']=len(result['state_publications'])
        result['state_publications'],following=self._page(result['state_publications'],limit,cursor,'workflow-states')
        return dict(publication_id=publication,status='available',synthetic=True,result=result,next_cursor=following)

    def workflow_state(self,publication,key,*,limit=25,cursor=None):
        page=self.workflows(publication,limit=100)
        state=next((row for row in page['result']['state_publications'] if row['state_publication_id']==key),None)
        if state is None:raise FoundationError('workflow_state_not_available')
        items=[dict(observation_id=str(uuid.uuid5(uuid.NAMESPACE_URL,source)),source_version_id=source,state_fact_id=fact,
                    state_key=state['state_key'],outcome=state['published_state'],source_role='provider',
                    source_time_ns=page['result']['event_cutoff_ns'],request_key=None,field_path='synthetic.state')
               for source,fact in zip(state['source_version_ids'],state['state_fact_refs'])]
        rows,following=self._page(items,limit,cursor,'workflow-evidence:'+key)
        return dict(publication_id=publication,state_publication_id=key,state=state,total_observations=len(items),items=rows,next_cursor=following)

    @staticmethod
    def _page(items,limit,cursor,kind):
        offset=0
        if cursor is not None:
            try:
                prefix,value=cursor.rsplit(':',1)
                if prefix!='demo:'+kind or not value.isdecimal():raise ValueError
                offset=int(value)
                if not 0<=offset<=100000:raise ValueError
            except (ValueError,AttributeError):raise FoundationError('invalid_page_cursor') from None
        page=copy.deepcopy(items[offset:offset+limit]);following='demo:'+kind+':'+str(offset+limit) if offset+limit<len(items) else None
        return page,following

    def session(self,publication,*,identity_scope,limit,cursor=None):
        self._check(publication)
        assigned=[r for r in self.summaries.values() if r['session_key']==self.session_key and r['identity_state']=='known']
        conflicts=[r for r in self.summaries.values() if r['identity_state']=='conflicting' and self.session_key in r['session_candidates']]
        rows=assigned if identity_scope=='assigned' else conflicts
        rows=sorted(rows,key=lambda r:(int(r['activity_time_ns']),r['request_key']))
        items,following=self._page([request_card(r,projection_run_id='demo-fixture',identity_scope=identity_scope) for r in rows],limit,cursor,identity_scope)
        groups=Counter(r['classification']['activity_group'] for r in assigned)
        count=lambda name:sum(r[name] for r in assigned)
        outcomes={k:sum(r['distinct_client_request_count'] for r in assigned if (r['final_outcome']==k if k in ('success','failure') else r['final_outcome'] not in ('success','failure'))) for k in ('success','failure','unknown_or_conflicting')}
        totals=dict(assigned_request_projections=len(assigned),conflicting_context_request_projections=len(conflicts),assigned_client_http_requests=count('distinct_client_request_count'),
                    assigned_log_events=count('selected_event_count'),assigned_sql_observations=count('sql_observation_count'),assigned_provider_observations=count('provider_observation_count'),
                    client_http_outcomes=outcomes,first_observed_time_ns=min((r['first_time_ns'] for r in assigned),key=int,default=None),last_observed_time_ns=max((r['last_time_ns'] for r in assigned),key=int,default=None),
                    assigned_distinct_network_sources=len({ip for r in assigned for ip in r['ip_keys']}),
                    activity_groups=dict(application_support_request_projections=groups['application_support'],security_request_projections=groups['security'],business_candidate_request_projections=groups['business_candidate'],unknown_request_projections=groups['unknown']))
        return dict(publication_id=publication,session_key=self.session_key,identity_scope=identity_scope,totals=totals,items=items,next_cursor=following,has_more=bool(following),view_version=VIEW_VERSION)

    def request(self,publication,key):
        self._check(publication)
        if key not in self.summaries:raise FoundationError('request_not_available')
        return dict(publication_id=publication,item=request_card(self.summaries[key],projection_run_id='demo-fixture',identity_scope='request_evidence'))

    def evidence(self,publication,key,*,limit,cursor=None):
        self._check(publication)
        if key not in self.operations:raise FoundationError('request_not_available')
        items,following=self._page(self.operations[key],limit,cursor,'evidence:'+key)
        return dict(publication_id=publication,request_key=key,items=items,total_event_versions=len(self.operations[key]),next_cursor=following)

    def candidates(self,publication,*,limit,cursor=None):
        self._check(publication)
        candidates,truncated=registration_candidates(list(self.summaries.values()))
        if truncated:raise FoundationError('candidate_result_limit_requires_narrower_scope')
        alternatives={}
        for c in candidates:alternatives.setdefault(c['registration_request_key'],set()).add(c['session_key'])
        rows=sorted((c for c in candidates if c['session_key']==self.session_key),key=lambda c:(c['registration_request_key'],c['session_key'],c['support_request_key']))
        items,following=self._page(rows,limit,cursor,'candidates')
        return dict(publication_id=publication,session_key=self.session_key,total_candidates=len(rows),items=items,next_cursor=following,
                    candidate_session_counts={c['registration_request_key']:len(alternatives[c['registration_request_key']]) for c in items},association_authority='context_candidate_only')

    def _service_groups(self):
        grouped={}
        for r in self.summaries.values():grouped.setdefault(r['endpoint'],[]).append(r)
        groups=[]
        for endpoint,rows in grouped.items():
            outcomes={k:sum(r['distinct_client_request_count'] for r in rows if (r['final_outcome']==k if k in ('success','failure') else r['final_outcome'] not in ('success','failure'))) for k in ('success','failure','unknown_or_conflicting')}
            groups.append(dict(service_key=self.keys.token(self.namespace,'service_endpoint',endpoint),endpoint=endpoint,request_projections=len(rows),
                client_http_requests=sum(r['distinct_client_request_count'] for r in rows),client_outcomes=outcomes,
                sql_observations=sum(r['sql_observation_count'] for r in rows),provider_observations=sum(r['provider_observation_count'] for r in rows),
                known_sessions=len({r['session_key'] for r in rows if r['identity_state']=='known'}),
                conflicting_identity_requests=sum(r['identity_state']=='conflicting' for r in rows),missing_identity_requests=sum(r['identity_state']=='missing' for r in rows),
                first_time_ns=min((r['first_time_ns'] for r in rows if r['first_time_ns'] is not None),key=int,default=None),
                last_time_ns=max((r['last_time_ns'] for r in rows if r['last_time_ns'] is not None),key=int,default=None),mapping_state='observed_endpoint_only'))
        return sorted(groups,key=lambda g:(g['endpoint'] is not None,g['endpoint'] or ''))

    def services(self,publication,*,limit,cursor=None):
        self._check(publication);groups=self._service_groups()
        items,following=self._page(groups,limit,cursor,'services')
        return dict(publication_id=publication,total_endpoints=len(groups),items=items,next_cursor=following)

    def service(self,publication,key,*,limit,cursor=None):
        self._check(publication)
        group=next((g for g in self._service_groups() if g['service_key']==key),None)
        if group is None:raise FoundationError('service_not_available')
        rows=sorted((r for r in self.summaries.values() if r['endpoint']==group['endpoint']),key=lambda r:(int(r['activity_time_ns']),r['request_key']))
        items,following=self._page([request_card(r,identity_scope='service_context') for r in rows],limit,cursor,'service:'+key)
        return dict(publication_id=publication,service=group,items=items,next_cursor=following)
