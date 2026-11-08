"""Short indexed RR/RO snapshots; source lag is measured, never a stop switch."""
from contextlib import contextmanager
from pathlib import Path
import time

from . import FIVE_NS,SOURCE_SHA,CATALOG_SHA,SEMANTIC_SCHEMA
from .pg_source import BudgetQuery,read_database_config,connection_parameters,product_read_budget,installed_source_identity,collect_sample
from .snapshot import require,api_path
from .history_scope import effective_floor

SELECT="SELECT s.*,r.identity_state,r.conflicted,r.session_key AS request_session_key FROM public.viewer_semantic_occurrences s LEFT JOIN public.viewer_requests r ON r.request_key=s.request_key "


def bounded_semantic_select(where,order):
    """Limit the indexed semantic batch before looking up request identity.

    Both LIMIT boundaries are deliberate. The request-side primary-key lookup
    cannot become a full request-table hash/merge join ahead of the page limit.
    Missing requests remain LEFT-joined unknowns, rather than disappearing.
    Predicates/order are internal SQL constants; values stay parameters.
    """
    return ('SELECT s.*,r.identity_state,r.conflicted,r.session_key AS request_session_key '
        'FROM (SELECT s.* FROM public.viewer_semantic_occurrences s '+where+
        'ORDER BY '+order+' LIMIT %s) AS s LEFT JOIN LATERAL '
        '(SELECT r.identity_state,r.conflicted,r.session_key FROM public.viewer_requests r '
        'WHERE r.request_key=s.request_key LIMIT 1) AS r ON TRUE ORDER BY '+order)


class ProductSource:
    def profile(self,key):
        from .request_profiles import read
        return read(self,key)
    def __init__(self,project):
        self.project=Path(project);self.identity=installed_source_identity(self.project)
        from .native_pg import source_parameters
        self.config=source_parameters(self.project);self.page_size=128
        self.semantic_page_size=128
        self.analysis_floor_ns=0
        self.last_metrics=[];self.last_source=None
    @contextmanager
    def snapshot(self):
        import psycopg
        from psycopg.rows import dict_row
        self.last_metrics=[]
        with product_read_budget():
            params=connection_parameters(self.config);params['application_name']='AnomalyDetection.Product.readonly'
            raw=psycopg.connect(**params,autocommit=False,row_factory=dict_row)
            query=None
            try:
                raw.execute('SET TRANSACTION ISOLATION LEVEL REPEATABLE READ, READ ONLY')
                query=BudgetQuery(raw)
                yield query
            finally:
                if query is not None:self.last_metrics=query.metrics
                try:raw.rollback()
                finally:raw.close()
    def metadata(self,q):
        flags=q("SELECT current_database() AS db,current_user AS source_role,current_setting('transaction_read_only') AS ro,current_setting('transaction_isolation') AS isolation",cap=1)
        require(flags and flags[0]['db']=='p24_design_viewer' and flags[0]['ro']=='on' and flags[0]['isolation']=='repeatable read','SOURCE_TRANSACTION_NOT_READ_ONLY_REPEATABLE_READ')
        require(flags[0]['source_role']==self.config['user'],'SOURCE_CONNECTION_ROLE_MISMATCH')
        rows=q('SELECT l.stream_key,l.keys_fingerprint,l.generation,l.next_ns,l.lag_seconds,l.last_success_ns,'
            "(l.last_error IS NOT NULL AND l.last_error<>'') AS has_error,s.generation AS semantic_generation,s.state AS semantic_state,"
            'c.fingerprint AS catalog_fingerprint FROM public.viewer_live_state l CROSS JOIN public.viewer_semantic_checkpoint s '
            'CROSS JOIN public.viewer_service_catalog_state c WHERE l.id=1 AND s.id=1 AND c.id=1',cap=1)
        require(rows and rows[0]['semantic_state']=='ready' and rows[0]['catalog_fingerprint']==CATALOG_SHA and
            rows[0]['generation']==rows[0]['semantic_generation'],'SOURCE_NOT_READY')
        row=rows[0];require(row['has_error'] is False,'SOURCE_REPORTED_ERROR')
        source=dict(row,namespace='viewer:'+row['stream_key'],runtime_sha256=SOURCE_SHA,captured_at_ns=time.time_ns(),
            catalog_status='CURRENT',semantic_schema=SEMANTIC_SCHEMA,maintenance='CLEAR',consistent_snapshot=True,
            evidence_mode='postgresql_readonly_snapshot',source_finality='not_established',source_role=flags[0]['source_role'],source_read_only=True)
        audit=q("SELECT to_regclass('public.viewer_retention_audit') AS present",cap=1)
        retention=q('SELECT MAX(cutoff_ns) AS cutoff_ns FROM public.viewer_retention_audit',cap=1) if audit[0]['present'] else []
        source['retention_cutoff_ns']=(retention[0]['cutoff_ns'] or 0) if retention else 0
        if self.analysis_floor_ns:
            source['analysis_floor_ns']=self.analysis_floor_ns
            # A seek can advance next_ns without publishing a single window.
            # The receipt, rather than the seek cursor, proves source coverage.
            latest=q('SELECT * FROM (SELECT start_ns,end_ns FROM public.viewer_live_windows '
                'WHERE start_ns>=%s AND start_ns<=%s AND end_ns=start_ns+%s '
                'ORDER BY start_ns DESC LIMIT 1) AS latest_published',
                (effective_floor(source),source['next_ns']-FIVE_NS,FIVE_NS),cap=1)
            source['scope_latest_published_end_ns']=latest[0]['end_ns'] if latest else None
        self.last_source=source
        return source
    def page(self,after=None):
        size=self.semantic_page_size or self.page_size
        with self.snapshot() as q:
            source=self.metadata(q)
            if self.analysis_floor_ns:
                rows=self.scoped_page(q,source,after,size)
            else:
                rows=q('SELECT * FROM ('+bounded_semantic_select('WHERE s.request_key>%s ' if after else '', 's.request_key')+') AS source_page',
                    (*((after,) if after else ()),size+1),cap=size+1)
            more=len(rows)>size;rows=rows[:size]
        next_key=None
        if more:
            last=rows[-1]
            next_key=[last['anchor_ns'],last['request_key']] if self.analysis_floor_ns else last['request_key']
        return {'rows':rows,'source':source,'after':next_key,'has_more':more}

    def scoped_page(self,q,source,after,size):
        begin=effective_floor(source)
        end=source['next_ns']
        if end<=begin:
            return []
        where='WHERE s.state=%s AND s.anchor_ns>=%s AND s.anchor_ns<%s '
        params=[begin,end]
        if after and isinstance(after,(tuple,list)) and len(after)==2:
            where+='AND (s.anchor_ns,s.request_key)>(%s,%s) '
            params.extend(after)
        # Each scan matches the existing (state, anchor_ns, request_key) index.
        statement=bounded_semantic_select(where,'s.anchor_ns,s.request_key')
        rows=[]
        for state in ('active','withdrawn'):
            rows.extend(q('SELECT * FROM ('+statement+') AS scoped_source_page',
                          (state,*params,size+1),cap=size+1))
        return sorted(rows,key=lambda row:(row['anchor_ns'],row['request_key']))[:size+1]
    def reduce_page_size(self,lane):
        if lane=='semantic_keyset':self.semantic_page_size=max(64,(self.semantic_page_size or self.page_size)//2)
        else:self.page_size=max(64,self.page_size//2)
    def page_sizes(self):
        return {'window':self.page_size,'semantic_keyset':self.semantic_page_size or self.page_size}
    def context(self,job):
        session,target=job['session_key'],job['target_ns'];begin=max(FIVE_NS,target-56*288*FIVE_NS)
        with self.snapshot() as q:
            source=self.metadata(q)
            require(target+FIVE_NS<=source['next_ns'],'TARGET_NOT_PUBLISHED')
            floor=source.get('analysis_floor_ns',0)
            require(target>=floor,'TARGET_BEFORE_AD_HISTORY_BOUNDARY')
            begin=max(begin,floor)
            if floor:
                known=q('SELECT MIN(anchor_ns) AS first_ns FROM public.viewer_semantic_occurrences '
                        'WHERE session_key=%s AND anchor_ns>=%s',(session,floor),cap=1)
            else:
                known=q('SELECT MIN(anchor_ns) AS first_ns FROM public.viewer_semantic_occurrences WHERE session_key=%s',(session,),cap=1)
            groups=q('SELECT * FROM (SELECT (s.anchor_ns/%s)*%s AS start_ns,trim(split_part(s.root_call,\' Line:\',1)) AS service_path,'
                'COUNT(*) AS n,MIN(s.anchor_ns) AS first_ns,MIN(s.request_key) AS witness,MIN(s.kind) AS kind,'
                "MIN(CASE WHEN r.identity_state='assigned' AND r.conflicted=0 AND r.session_key=s.session_key THEN 1 ELSE 0 END) AS valid "
                'FROM public.viewer_semantic_occurrences s LEFT JOIN public.viewer_requests r ON r.request_key=s.request_key '
                "WHERE s.session_key=%s AND s.state='active' AND s.kind IN ('service_execution','product_reservation_execution','wallet_funding_execution','user_management_execution') AND s.anchor_ns>=%s AND s.anchor_ns<%s "
                'GROUP BY 1,2 ORDER BY 1 DESC,2 LIMIT 8193) AS summary_page',(FIVE_NS,FIVE_NS,session,begin,target+FIVE_NS),cap=8193)
            truncated=len(groups)>8192;groups=groups[:8192]
            if truncated:
                fence=min(row['start_ns'] for row in groups);groups=[row for row in groups if row['start_ns']>fence];begin=fence+FIVE_NS
            coverage=q('SELECT start_ns,end_ns FROM public.viewer_live_windows WHERE start_ns>=%s AND start_ns<=%s ORDER BY start_ns',
                (begin,target),cap=16129)
            events=q('SELECT * FROM ('+SELECT+"WHERE s.session_key=%s AND s.state='active' AND s.kind IN ('service_execution','product_reservation_execution','wallet_funding_execution','user_management_execution') AND s.anchor_ns>=%s AND s.anchor_ns<%s "
                'ORDER BY s.anchor_ns DESC,s.request_key DESC LIMIT 2049) AS event_page',(session,begin,target+FIVE_NS),cap=2049)
            events_truncated=len(events)>2048;events=events[:2048]
        first=known[0]['first_ns']
        by_time={}
        for row in groups:by_time.setdefault(row['start_ns'],[]).append(row)
        windows=[]
        for covered in coverage:
            at=covered['start_ns'];records=by_time.get(at,[])
            if first is not None and at<first//FIVE_NS*FIVE_NS:continue
            retained=at>=source['retention_cutoff_ns']
            mapped=[r for r in records if api_path(r['service_path'])]
            unmapped=sum(r['n'] for r in records if not api_path(r['service_path']))
            valid=retained and first is not None and covered['end_ns']==at+FIVE_NS and all(row['valid']==1 for row in records)
            windows.append({'start_ns':at,'coverage_complete':bool(valid),'population_complete':bool(valid),
                'counts':{row['service_path']:row['n'] for row in mapped} if valid else None,
                'witnesses':{row['service_path']:row['witness'] for row in mapped},'first_observed_ns':first,
                'count_kinds':{row['service_path']:row['kind'] for row in mapped},'unmapped_behaviors':unmapped,'count_scope':'RESOLVED_SERVICE_PATHS',
                'quality_reason':'OBSERVED_COMPLETE' if valid else 'RETENTION_SCOPE_UNAVAILABLE' if not retained else 'SESSION_POPULATION_UNPROVEN'})
        if not any(row['start_ns']==target for row in windows):
            windows.append({'start_ns':target,'coverage_complete':False,'population_complete':False,'counts':None,'witnesses':{},'first_observed_ns':first})
        current=next(row for row in windows if row['start_ns']==target)
        events=sorted(events,key=lambda row:(row['anchor_ns'],row['request_key']))
        current_events_complete=not events_truncated or not events or events[0]['anchor_ns']<target
        return {'source':source,'session_key':session,'target_ns':target,'windows':sorted(windows,key=lambda row:row['start_ns']),
            'events':events,'target_complete':current['coverage_complete'],'target_events_complete':current_events_complete,
            'history_truncated':truncated,'event_history_truncated':events_truncated,'history_scope':'SOURCE_AS_OBSERVED_56_DAY_MODEL_CONTEXT',
            'evidence_verified':False,'coverage_is_source_finality':False}
    def audit(self,keys):
        keys=sorted(set(keys))
        with self.snapshot() as q:
            snapshot,report=collect_sample(q,runtime_sha256=SOURCE_SHA,sample_limit=len(keys),request_keys=keys)
            from .input_subjects import CONTRACTS,collect,load_key
            if any(api_path(r.get('root_call')) in CONTRACTS and r.get('kind')=='service_execution'
                   for r in snapshot.occurrences.values()):
                from .viewer_bridge import reader
                facade=reader(self.project,q)
                from p24_foundation.parser import field,json_section
                if not getattr(self,'_input_subject_key',None):
                    self._input_subject_key=load_key(self.project)
                snapshot.input_subjects=collect(snapshot,facade,json_section,field,self._input_subject_key)
        return snapshot
    def cohort(self,after=None,target=None):
        with self.snapshot() as q:
            source=self.metadata(q)
            if target is not None and target<source.get('analysis_floor_ns',0):
                return {'source':source,'target_ns':None,'rows':[]}
            if target is None:
                desired=max(effective_floor(source),after if after is not None else max(FIVE_NS,source['next_ns']-56*288*FIVE_NS))
                found=q('SELECT * FROM (SELECT start_ns,end_ns FROM public.viewer_live_windows WHERE start_ns>=%s '
                    'AND end_ns<=%s ORDER BY start_ns LIMIT 1) AS available',(desired,source['next_ns']),cap=1)
                if not found:return {'source':source,'target_ns':None,'rows':[]}
                target=found[0]['start_ns']
            covered=q('SELECT start_ns,end_ns FROM public.viewer_live_windows WHERE start_ns=%s',(target,),cap=1)
            if not covered or covered[0]['end_ns']!=target+FIVE_NS or target<source['retention_cutoff_ns']:
                return {'source':source,'target_ns':target,'rows':[],'available':False}
            rows=q("SELECT service_path,percentile_disc(0.95) WITHIN GROUP(ORDER BY n)::double precision AS value,COUNT(*) AS sessions,MIN(valid) AS population_valid "
                "FROM (SELECT trim(split_part(s.root_call,' Line:',1)) AS service_path,s.session_key,COUNT(*) AS n,"
                "MIN(CASE WHEN r.identity_state='assigned' AND r.conflicted=0 AND r.session_key=s.session_key THEN 1 ELSE 0 END) AS valid "
                "FROM public.viewer_semantic_occurrences s LEFT JOIN public.viewer_requests r ON r.request_key=s.request_key "
                "WHERE s.state='active' AND s.kind='service_execution' AND s.session_key IS NOT NULL "
                'AND s.anchor_ns>=%s AND s.anchor_ns<%s GROUP BY 1,2) AS counts GROUP BY service_path ORDER BY service_path',
                (target,target+FIVE_NS),cap=1024)
        return {'source':source,'target_ns':target,'rows':[row for row in rows if api_path(row['service_path']) and row['service_path']!='Services.v1/InvoiceRegister'],'available':True}
