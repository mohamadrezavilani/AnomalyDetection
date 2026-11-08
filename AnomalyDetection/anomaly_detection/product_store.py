"""Native PostgreSQL event ledger, historical invalidation, models and review."""
from __future__ import annotations
import json
import time
from contextlib import contextmanager

from . import FIVE_NS,KINDS
from .snapshot import canonical,digest,require,api_path,KEY
from .history_scope import INPUT_LOCK,load_floor

PREFIX='anomaly_detection.'
HISTORY_NS=56*288*FIVE_NS
DDL=[
"CREATE TABLE IF NOT EXISTS anomaly_detection.adp_state(name TEXT PRIMARY KEY,body TEXT NOT NULL)",
"""CREATE TABLE IF NOT EXISTS anomaly_detection.adp_facts(request_key TEXT PRIMARY KEY,anchor_key TEXT UNIQUE NOT NULL,
 session_key TEXT,at_ns BIGINT NOT NULL,service_path TEXT,kind TEXT,state TEXT NOT NULL,revision BIGINT NOT NULL,
 eligible BOOLEAN NOT NULL,source_present BOOLEAN NOT NULL DEFAULT TRUE,body TEXT NOT NULL,content_digest TEXT NOT NULL,
 details TEXT,details_digest TEXT,last_seen_ns BIGINT NOT NULL,last_audit_ns BIGINT NOT NULL DEFAULT 0,next_audit_ns BIGINT NOT NULL DEFAULT 0)""",
"CREATE INDEX IF NOT EXISTS adp_fact_session ON anomaly_detection.adp_facts(session_key,at_ns,request_key)",
"CREATE INDEX IF NOT EXISTS adp_fact_service ON anomaly_detection.adp_facts(service_path,at_ns DESC,request_key)",
"CREATE INDEX IF NOT EXISTS adp_fact_service_audited ON anomaly_detection.adp_facts(service_path,at_ns DESC,request_key DESC) WHERE eligible=TRUE AND source_present=TRUE AND details IS NOT NULL",
"CREATE INDEX IF NOT EXISTS adp_fact_fresh_audit ON anomaly_detection.adp_facts(last_audit_ns,at_ns DESC,request_key)",
"CREATE INDEX IF NOT EXISTS adp_fact_audit ON anomaly_detection.adp_facts(next_audit_ns,last_audit_ns,request_key)",
"""CREATE TABLE IF NOT EXISTS anomaly_detection.adp_jobs(session_key TEXT NOT NULL,target_ns BIGINT NOT NULL,
 version BIGINT NOT NULL DEFAULT 1,processed_version BIGINT NOT NULL DEFAULT 0,dirty BOOLEAN NOT NULL DEFAULT TRUE,
 training_begin_ns BIGINT NOT NULL DEFAULT 0,due_ns BIGINT NOT NULL DEFAULT 0,last_evaluated_ns BIGINT,
 input_digest TEXT,evaluation TEXT,target_scope TEXT DEFAULT 'BEHAVIOR_TARGET',PRIMARY KEY(session_key,target_ns))""",
"CREATE INDEX IF NOT EXISTS adp_job_work ON anomaly_detection.adp_jobs(dirty,due_ns,target_ns,session_key)",
"CREATE INDEX IF NOT EXISTS adp_job_recent ON anomaly_detection.adp_jobs(dirty,due_ns,target_ns DESC,session_key)",
"CREATE INDEX IF NOT EXISTS adp_job_evaluated ON anomaly_detection.adp_jobs(last_evaluated_ns DESC) WHERE last_evaluated_ns IS NOT NULL",
"CREATE INDEX IF NOT EXISTS adp_job_completed_target ON anomaly_detection.adp_jobs(target_ns DESC) WHERE dirty=FALSE",
"CREATE INDEX IF NOT EXISTS adp_job_time ON anomaly_detection.adp_jobs(target_ns DESC,session_key DESC)",
"ALTER TABLE anomaly_detection.adp_jobs ADD COLUMN IF NOT EXISTS observed_count BIGINT",
"CREATE INDEX IF NOT EXISTS adp_job_live_first ON anomaly_detection.adp_jobs(target_ns DESC,observed_count DESC NULLS LAST,session_key) WHERE dirty=TRUE AND last_evaluated_ns IS NULL",
"CREATE INDEX IF NOT EXISTS adp_job_first_volume ON anomaly_detection.adp_jobs(observed_count DESC NULLS LAST,target_ns,session_key) WHERE dirty=TRUE AND last_evaluated_ns IS NULL",
"CREATE INDEX IF NOT EXISTS adp_job_dirty_volume ON anomaly_detection.adp_jobs(observed_count DESC NULLS LAST,target_ns,session_key) WHERE dirty=TRUE",
"""CREATE TABLE IF NOT EXISTS anomaly_detection.adp_contexts(session_key TEXT NOT NULL,target_ns BIGINT NOT NULL,
 body TEXT NOT NULL,content_digest TEXT NOT NULL,captured_ns BIGINT NOT NULL,job_version BIGINT NOT NULL,PRIMARY KEY(session_key,target_ns))""",
"""CREATE TABLE IF NOT EXISTS anomaly_detection.adp_windows(session_key TEXT NOT NULL,start_ns BIGINT NOT NULL,
 body TEXT NOT NULL,content_digest TEXT NOT NULL,PRIMARY KEY(session_key,start_ns))""",
"""CREATE TABLE IF NOT EXISTS anomaly_detection.adp_peers(service_path TEXT NOT NULL,start_ns BIGINT NOT NULL,
 value DOUBLE PRECISION,eligible BOOLEAN NOT NULL,input_digest TEXT NOT NULL,PRIMARY KEY(service_path,start_ns))""",
"""CREATE TABLE IF NOT EXISTS anomaly_detection.adp_findings(finding_key TEXT PRIMARY KEY,session_key TEXT NOT NULL,
 target_ns BIGINT NOT NULL,family TEXT NOT NULL,dimension TEXT NOT NULL,state TEXT NOT NULL,revision BIGINT NOT NULL,
 score DOUBLE PRECISION NOT NULL,content_digest TEXT NOT NULL,body TEXT NOT NULL,updated_ns BIGINT NOT NULL)""",
"CREATE INDEX IF NOT EXISTS adp_find_scope ON anomaly_detection.adp_findings(session_key,target_ns,state)",
"CREATE INDEX IF NOT EXISTS adp_active_find_scopes ON anomaly_detection.adp_findings(session_key,target_ns) WHERE state='ACTIVE'",
"""CREATE TABLE IF NOT EXISTS anomaly_detection.adp_finding_versions(finding_key TEXT NOT NULL,revision BIGINT NOT NULL,
 body TEXT NOT NULL,observed_ns BIGINT NOT NULL,PRIMARY KEY(finding_key,revision))""",
"""CREATE TABLE IF NOT EXISTS anomaly_detection.adp_incidents(incident_key TEXT PRIMARY KEY,session_key TEXT NOT NULL,
 target_ns BIGINT NOT NULL,state TEXT NOT NULL,revision BIGINT NOT NULL,body TEXT NOT NULL,content_digest TEXT NOT NULL,updated_ns BIGINT NOT NULL)""",
"CREATE INDEX IF NOT EXISTS adp_incident_time ON anomaly_detection.adp_incidents(updated_ns DESC,incident_key)",
"CREATE INDEX IF NOT EXISTS adp_incident_scope ON anomaly_detection.adp_incidents(session_key,target_ns)",
"CREATE INDEX IF NOT EXISTS adp_incident_state ON anomaly_detection.adp_incidents(state,incident_key)",
"""CREATE TABLE IF NOT EXISTS anomaly_detection.adp_feedback(id BIGINT GENERATED BY DEFAULT AS IDENTITY PRIMARY KEY,
 incident_key TEXT NOT NULL,label TEXT NOT NULL,note TEXT NOT NULL,created_ns BIGINT NOT NULL,incident_revision BIGINT NOT NULL)""",
"CREATE INDEX IF NOT EXISTS adp_feedback_case ON anomaly_detection.adp_feedback(incident_key,id DESC)",
"""CREATE TABLE IF NOT EXISTS anomaly_detection.adp_versions(id BIGINT GENERATED BY DEFAULT AS IDENTITY PRIMARY KEY,
 request_key TEXT NOT NULL,change_type TEXT NOT NULL,content_digest TEXT NOT NULL,body TEXT NOT NULL,observed_ns BIGINT NOT NULL)""",
"CREATE INDEX IF NOT EXISTS adp_versions_request ON anomaly_detection.adp_versions(request_key,id DESC)",
"CREATE TABLE IF NOT EXISTS anomaly_detection.adp_models(model_id TEXT PRIMARY KEY,family TEXT NOT NULL,body TEXT NOT NULL,created_ns BIGINT NOT NULL)",
]


def core(row):
    request=row['request_key'];anchor=row['anchor_key'];session=row.get('session_key')
    require(isinstance(request,str) and KEY.fullmatch(request),'INVALID_PRODUCT_REQUEST')
    require(isinstance(anchor,str) and anchor.startswith('ba1:') and KEY.fullmatch(anchor[4:]),'INVALID_PRODUCT_ANCHOR')
    require(type(row.get('anchor_ns')) is int and row['anchor_ns']>=0,'INVALID_PRODUCT_EVENT_TIME')
    require(type(row.get('revision')) is int and row['revision']>=1,'INVALID_PRODUCT_REVISION')
    require(row.get('state') in ('active','withdrawn'),'INVALID_PRODUCT_STATE')
    service=api_path(row.get('root_call'))
    eligible=bool(row['state']=='active' and row.get('kind') in KINDS and service and
        service!='Services.v1/InvoiceRegister' and isinstance(session,str) and KEY.fullmatch(session) and
        row.get('identity_state')=='assigned' and not row.get('conflicted',True) and row.get('request_session_key')==session)
    fields=('request_key','anchor_key','session_key','anchor_ns','kind','root_call','root_code','state','revision','identity_state','conflicted','request_session_key')
    return {key:row.get(key) for key in fields}|{'conflicted':bool(row.get('conflicted',True)),'service_path':service,'eligible':eligible}


class ProductStore:
    def __init__(self,raw):self.raw=raw;self.model_cache={};self.reference_inputs_cache={};self.ready_pass=None;self.recheck_pass=None;self._history_floor_ns=None
    @property
    def history_floor_ns(self):
        if self._history_floor_ns is None:
            self._history_floor_ns=load_floor(self)
        return self._history_floor_ns
    @contextmanager
    def transaction(self):
        # Serializes only our short mutations (including web feedback). Viewer
        # takes a different lock and is never blocked by this application lock.
        with self.raw.transaction():
            self.raw.execute('SELECT pg_advisory_xact_lock(%s)',(INPUT_LOCK,))
            yield
    def service_details(self,job,services):
        from .product_dependencies import service_details
        return service_details(self,job,services)
    def continuous_models(self,job,context):
        from .continuous import evaluate
        return evaluate(self,job,context)
    def next_model_job(self,now):
        from .model_queue import next_job
        return next_job(self,now)
    def reference_services(self,job):
        return {r['body'] and json.loads(r['body'])['service_path'] for r in self.raw.execute(
            'SELECT body FROM anomaly_detection.adp_findings WHERE session_key=%s AND target_ns=%s AND family=%s',
            (job['session_key'],job['target_ns'],'peer_service_rate_5m')).fetchall()}
    def initialize(self):
        from .product_dependencies import DDL as dependency_ddl
        from .product_pipeline import DDL as pipeline_ddl
        from .product_enrichment import DDL as enrichment_ddl
        from .service_reference import DDL as reference_ddl
        from .product_priority import DDL as priority_ddl
        from .job_scope import DDL as scope_ddl
        from .cases import DDL as case_ddl
        from .model_queue import DDL as model_ddl
        from .population import DDL as population_ddl
        from .scenario_store import DDL as scenario_ddl
        from .schema_setup import ensure
        self.initialization_step='inspect_owned_catalog_and_migrate_missing_objects'
        with self.transaction():
            self.initialization_schema=ensure(self.raw,DDL+dependency_ddl+pipeline_ddl+enrichment_ddl+reference_ddl+priority_ddl+scope_ddl+case_ddl+population_ddl+model_ddl+scenario_ddl)
            self.raw.execute("INSERT INTO anomaly_detection.adp_state VALUES('format','{\"version\":1}') ON CONFLICT DO NOTHING")
        self.initialization_step='verify_format_and_existing_migration_markers'
        require(self.state('format')['version']==1,'PRODUCT_SCHEMA_VERSION_MISMATCH')
        if not self.state('dependency_contract_v2').get('ready'):
            with self.transaction():
                self.raw.execute('UPDATE anomaly_detection.adp_jobs j SET version=version+1,dirty=TRUE,due_ns=0 WHERE last_evaluated_ns IS NOT NULL OR EXISTS(SELECT 1 FROM anomaly_detection.adp_contexts c WHERE c.session_key=j.session_key AND c.target_ns=j.target_ns)')
                self.raw.execute('UPDATE anomaly_detection.adp_peers SET eligible=FALSE')
                self.raw.execute("UPDATE anomaly_detection.adp_incidents SET state='RECHECK_REQUIRED' WHERE state<>'WITHDRAWN'")
                self.save_state('dependency_contract_v2',{'ready':True,'old_decisions_require_recheck':True})
        from .window_migration import migrate
        migrate(self)
        if not self.state('reference_policy_v2').get('ready'):
            with self.transaction():
                self.raw.execute('UPDATE anomaly_detection.adp_jobs j SET version=version+1,dirty=TRUE,due_ns=0 '
                    'WHERE j.last_evaluated_ns IS NOT NULL AND EXISTS(SELECT 1 FROM anomaly_detection.adp_peer_dependencies d '
                    'WHERE d.session_key=j.session_key AND d.target_ns=j.target_ns AND d.service_path LIKE %s)',('context:%',))
                self.raw.execute("UPDATE anomaly_detection.adp_incidents i SET state='RECHECK_REQUIRED' WHERE EXISTS("
                    'SELECT 1 FROM anomaly_detection.adp_jobs j WHERE j.session_key=i.session_key AND j.target_ns=i.target_ns AND j.dirty=TRUE)')
                self.save_state('reference_policy_v2',{'ready':True})
        if not self.state('reference_rank_policy_v3').get('ready'):
            with self.transaction():
                self.raw.execute('UPDATE anomaly_detection.adp_jobs SET version=version+1,dirty=TRUE,due_ns=0 '
                    'WHERE last_evaluated_ns IS NOT NULL AND EXISTS(SELECT 1 FROM '
                    "jsonb_array_elements(COALESCE(evaluation,'{}')::jsonb->'decisions') d WHERE d->>'family'='peer_service_rate_5m')")
                self.raw.execute("UPDATE anomaly_detection.adp_incidents i SET state='RECHECK_REQUIRED' WHERE EXISTS("
                    'SELECT 1 FROM anomaly_detection.adp_jobs j WHERE j.session_key=i.session_key AND j.target_ns=i.target_ns AND j.dirty=TRUE)')
                self.save_state('reference_rank_policy_v3',{'ready':True})
        self.initialization_step='ready'
    def state(self,name,default=None):
        row=self.raw.execute('SELECT body FROM anomaly_detection.adp_state WHERE name=%s',(name,)).fetchone()
        return json.loads(row['body']) if row else ({} if default is None else default)
    def save_state(self,name,value):
        self.raw.execute('INSERT INTO anomaly_detection.adp_state VALUES(%s,%s) ON CONFLICT(name) DO UPDATE SET body=excluded.body',(name,canonical(value)))
    def bind(self,source):
        binding={key:source[key] for key in ('namespace','stream_key','keys_fingerprint')}
        old=self.state('source_binding')
        require(not old or old==binding,'PRODUCT_SOURCE_IDENTITY_CHANGED')
        if not old:self.save_state('source_binding',binding)
        watermark=self.state('source_watermark')
        current={key:source[key] for key in ('generation','semantic_generation')}
        require(all(type(value) is int and value>=watermark.get(key,0) for key,value in current.items()),'PRODUCT_SOURCE_GENERATION_REGRESSED')
        if current!=watermark:self.save_state('source_watermark',current)
    def invalidate(self,session,at):
        self.invalidate_many([(session,at)])
    def invalidate_many(self,changed, *, create_targets=None):
        windows=sorted({(session,at//FIVE_NS*FIVE_NS) for session,at in changed if session and at>0})
        if not windows:return
        from .population import enqueue
        enqueue(self,[at for _,at in windows])
        from .product_priority import invalidate
        invalidate(self,windows)
        targets=windows if create_targets is None else sorted(set(windows)&{
            (session,at//FIVE_NS*FIVE_NS) for session,at in create_targets if session and at>0})
        values=canonical([{'session_key':session,'at_ns':at} for session,at in windows])
        creations=canonical([{'session_key':session,'at_ns':at} for session,at in targets])
        incoming="WITH incoming AS (SELECT session_key,at_ns FROM jsonb_to_recordset(%s::jsonb) AS x(session_key TEXT,at_ns BIGINT)), scopes AS (SELECT session_key,MIN(at_ns) AS first_ns,MAX(at_ns) AS last_ns,ARRAY_AGG(at_ns) AS changed_ns FROM incoming GROUP BY session_key) "
        self.raw.execute(incoming+'UPDATE anomaly_detection.adp_jobs j SET version=version+1,primary_version=primary_version+CASE WHEN j.target_ns=ANY(s.changed_ns) THEN 1 ELSE 0 END,dirty=TRUE,due_ns=0 FROM scopes s '
            'WHERE j.session_key=s.session_key AND j.target_ns>=s.first_ns AND j.target_ns<=s.last_ns+%s '
            "AND (j.target_ns=ANY(s.changed_ns) OR (j.target_scope IS DISTINCT FROM 'COVERAGE_ONLY' AND j.training_begin_ns<=s.last_ns))",(values,HISTORY_NS))
        self.raw.execute('INSERT INTO anomaly_detection.adp_jobs(session_key,target_ns,target_scope) '
            "SELECT session_key,at_ns,'BEHAVIOR_TARGET' FROM jsonb_to_recordset(%s::jsonb) AS x(session_key TEXT,at_ns BIGINT) WHERE TRUE "
            "ON CONFLICT(session_key,target_ns) DO UPDATE SET target_scope='BEHAVIOR_TARGET',dirty=TRUE,due_ns=0",(creations,))
        self.raw.execute(incoming+"UPDATE anomaly_detection.adp_incidents i SET state='RECHECK_REQUIRED' FROM scopes s WHERE i.session_key=s.session_key "
            "AND i.target_ns>=s.first_ns AND i.target_ns<=s.last_ns+%s AND i.state<>'RECHECK_REQUIRED'",(values,HISTORY_NS))
    def apply_rows(self,rows,source, *, cursor_state=None,fault=None):
        require(len(rows)<=4096,'PRODUCT_PAGE_BUDGET_EXCEEDED')
        prepared=[core(row) for row in rows];now=source['captured_at_ns']
        floor=self.history_floor_ns
        keys=[row['request_key'] for row in prepared]
        require(len(keys)==len(set(keys)),'DUPLICATE_PRODUCT_REQUEST')
        changed=[];new_count=0
        with self.transaction():
            self.bind(source)
            old={row['request_key']:row for row in self.raw.execute('SELECT * FROM anomaly_detection.adp_facts WHERE request_key IN ('+
                ','.join('%s' for _ in keys)+')',keys).fetchall()} if keys else {}
            values=[];versions=[];context_changes=[]
            for value in prepared:
                previous=old.get(value['request_key']);signature=digest(value)
                if previous:
                    require(previous['anchor_key']==value['anchor_key'],'PRODUCT_ANCHOR_IDENTITY_CHANGED')
                    require(value['revision']>=previous['revision'],'PRODUCT_REVISION_REGRESSED')
                    if value['revision']==previous['revision']:
                        before=json.loads(previous['body'])
                        require(all(before.get(field)==value.get(field) for field in ('anchor_key','session_key','anchor_ns','kind','service_path','state')),
                            'PRODUCT_SEMANTIC_CHANGE_WITHOUT_REVISION')
                if value['anchor_ns']<floor:
                    if previous and previous['source_present']:
                        self.raw.execute('UPDATE anomaly_detection.adp_facts SET source_present=FALSE,details=NULL,details_digest=NULL '
                            'WHERE request_key=%s',(value['request_key'],))
                        changed.append((previous['session_key'],previous['at_ns']))
                        context_changes.append((previous['service_path'],previous['at_ns']))
                    continue
                if previous and previous['content_digest']==signature and previous['source_present']:continue
                new_count+=int(previous is None)
                changed.append((value['session_key'],value['anchor_ns']))
                if previous:changed.append((previous['session_key'],previous['at_ns']))
                if previous:context_changes.append((previous['service_path'],previous['at_ns']))
                context_changes.append((value['service_path'],value['anchor_ns']))
                encoded=canonical(value)
                values.append((value['request_key'],value['anchor_key'],value['session_key'],value['anchor_ns'],value['service_path'],
                    value['kind'],value['state'],value['revision'],value['eligible'],encoded,signature,now))
                versions.append((value['request_key'],'semantic_change' if previous else 'first_observation',signature,encoded,now))
            if values:
                with self.raw.cursor() as cursor:
                    cursor.executemany('INSERT INTO anomaly_detection.adp_facts(request_key,anchor_key,session_key,at_ns,service_path,kind,state,revision,'
                        'eligible,body,content_digest,last_seen_ns) VALUES('+','.join(['%s']*12)+') ON CONFLICT(request_key) DO UPDATE SET '
                        'session_key=excluded.session_key,at_ns=excluded.at_ns,service_path=excluded.service_path,kind=excluded.kind,state=excluded.state,'
                        'revision=excluded.revision,eligible=excluded.eligible,body=excluded.body,content_digest=excluded.content_digest,'
                        'source_present=TRUE,last_seen_ns=excluded.last_seen_ns,next_audit_ns=0',values)
                    cursor.executemany('INSERT INTO anomaly_detection.adp_versions(request_key,change_type,content_digest,body,observed_ns) '
                        'VALUES(%s,%s,%s,%s,%s)',versions)
            self.invalidate_many(changed)
            # A changed semantic row invalidates the old population snapshot.
            # Keep its summaries/history; the existing repair lane republishes
            # complete membership before it can certify a new rolling span.
            if changed:
                affected=sorted({at//FIVE_NS*FIVE_NS for session,at in changed if session})
                self.raw.execute("UPDATE anomaly_detection.adp_source_windows SET complete=FALSE,source=jsonb_set(source::jsonb,'{needs_scope_repair}','true'::jsonb)::text WHERE start_ns=ANY(%s) AND complete=TRUE",(affected,))
                from .longitudinal import coverage_changed
                for at in affected:coverage_changed(self,at)
                from .scenario_store import changed_many as profiles_changed
                profiles_changed(self,context_changes)
            from .service_reference import invalidate_points
            invalidate_points(self,changed)
            from .product_dependencies import context_changed_many
            context_changed_many(self,context_changes)
            if values:
                stats=self.state('counters');stats['registered_behaviors']=stats.get('registered_behaviors',0)+new_count
                stats['semantic_changes']=stats.get('semantic_changes',0)+len(values);self.save_state('counters',stats)
            if cursor_state is not None:self.save_state(cursor_state[0],cursor_state[1])
            if fault:fault()
        return {'rows':len(rows),'changed':len(values),'new':new_count,'invalidated_windows':len(set(changed))}
    def audit_keys(self,now,limit=8, *, priority=False,revisit=False,fresh=False):
        if priority:
            from .audit_scope import keys as scope_keys
            found=scope_keys(self,now,limit)
            if found:return found
        return [row['request_key'] for row in self.raw.execute('SELECT request_key FROM anomaly_detection.adp_facts '
            'WHERE next_audit_ns<=%s '+('AND last_audit_ns>0 ' if revisit else '')+('AND last_audit_ns=0 ' if fresh else '')+("AND EXISTS(SELECT 1 FROM anomaly_detection.adp_findings f WHERE f.session_key=adp_facts.session_key "
            "AND f.target_ns=(adp_facts.at_ns/%s)*%s AND f.state='ACTIVE') " if priority else '')+
            ('ORDER BY at_ns DESC,request_key LIMIT %s' if fresh else 'ORDER BY next_audit_ns,last_audit_ns,request_key LIMIT %s'),
            (now,FIVE_NS,FIVE_NS,limit) if priority else (now,limit)).fetchall()]
    def defer_audits(self,keys,now):
        # One oversized or temporarily unavailable request must not starve all
        # older evidence. It stays registered and will be tried again.
        with self.transaction(),self.raw.cursor() as cursor:
            cursor.executemany('UPDATE anomaly_detection.adp_facts SET next_audit_ns=%s WHERE request_key=%s',
                [(now+60_000_000_000,key) for key in keys])
    def apply_audit(self,snapshot):
        source=snapshot.source;facts={fact['request_key']:fact for fact in snapshot.facts()};now=source['captured_at_ns'];changed=0;windows=[];contexts=[]
        for key,subject in getattr(snapshot,'input_subjects',{}).items():
            if key in facts:facts[key]['input_subject']=subject
        floor=self.history_floor_ns
        if floor:
            facts={key:fact for key,fact in facts.items() if
                   (fact.get('semantic',{}).get('anchor_ns') or 0)>=floor}
        with self.transaction():
            self.bind(source)
            for key in sorted(snapshot.keys):
                old=self.raw.execute('SELECT * FROM anomaly_detection.adp_facts WHERE request_key=%s',(key,)).fetchone()
                if old is None:continue
                fact=facts.get(key)
                if fact is None:
                    value={'source_present':False,'reason':'ABSENT_FROM_EXPLICIT_REQUEST_SNAPSHOT'}
                else:
                    value=fact
                    if value.get('input_subject',{}).get('status')=='READ_DEFERRED' and old['details']:
                        from .input_subjects import verified_subject
                        prior=json.loads(old['details']).get('input_subject')
                        if prior and verified_subject(value['semantic'],value|{'input_subject':prior},value['service_path']):
                            value['input_subject']=prior
                signature=digest(value)
                if old['details_digest']!=signature:
                    changed+=1
                    self.raw.execute('INSERT INTO anomaly_detection.adp_versions(request_key,change_type,content_digest,body,observed_ns) '
                        'VALUES(%s,%s,%s,%s,%s)',(key,'evidence_change',signature,canonical(value),now))
                    windows.append((old['session_key'],old['at_ns']));contexts.append((old['service_path'],old['at_ns']))
                self.raw.execute('UPDATE anomaly_detection.adp_facts SET details=%s,details_digest=%s,source_present=%s,'
                    'last_audit_ns=%s,next_audit_ns=%s WHERE request_key=%s',
                (canonical(value),signature,fact is not None,now,
                     now+(60 if value.get('input_subject',{}).get('status')=='READ_DEFERRED' else 600)*1_000_000_000,key))
            from .population import enqueue
            enqueue(self,[old['at_ns'] for old in self.raw.execute('SELECT at_ns FROM anomaly_detection.adp_facts WHERE request_key=ANY(%s)',(list(snapshot.keys),)).fetchall()])
            self.invalidate_many(windows)
            from .product_dependencies import context_changed_many
            context_changed_many(self,contexts)
            # Evidence and its semantic revision commit together. A malformed
            # revision must not leave newly qualified evidence partially saved.
            rows=[]
            for fact in facts.values():
                row=dict(fact['semantic'],identity_state=fact['quality']['identity_state'],conflicted=fact['quality']['conflicted'],
                    request_session_key=snapshot.requests.get(fact['request_key'],{}).get('session_key'));rows.append(row)
            if rows:self.apply_rows(rows,source)
            if changed:
                from .scenario_store import queue_keys,changed as profile_changed
                queue_keys(self,sorted(facts),force=True)
                for service,at in contexts:profile_changed(self,[service],at)
            from .product_priority import refresh
            refresh(self,[(old['session_key'],old['at_ns']) for old in
                self.raw.execute('SELECT session_key,at_ns FROM anomaly_detection.adp_facts WHERE request_key=ANY(%s)',(list(snapshot.keys),)).fetchall()],now)
        return {'audited':len(snapshot.keys),'evidence_changes':changed}
    def next_job(self,now, *, recheck=False,recent=False,cached=False):
        # Source audits, semantic revisions, references and feedback already
        # invalidate consumers. A clock alone is not a changed model input.
        row=self.raw.execute('SELECT * FROM anomaly_detection.adp_jobs j WHERE target_scope=\'BEHAVIOR_TARGET\' AND dirty=TRUE AND due_ns<=%s '+
            ('AND last_evaluated_ns IS NOT NULL ' if recheck else '')+
            ('AND EXISTS(SELECT 1 FROM anomaly_detection.adp_contexts c WHERE c.session_key=j.session_key AND c.target_ns=j.target_ns AND c.job_version=j.version) ' if cached else '')+
            'ORDER BY due_ns,target_ns '+('DESC' if recent else 'ASC')+',session_key LIMIT 1',(now,)).fetchone()
        return dict(row) if row else None
    def next_ready_job(self,now):
        """Finite keyset passes: new targets cannot jump ahead of an active pass.

        This reserves recent, fully read windows. The separate historical lane
        still services every age, including jobs outside this scheduling band.
        A restart may restart a pass; durable dirty/version state owns correctness.
        """
        for _ in range(3):
            if self.ready_pass is None:
                latest=self.raw.execute('SELECT MAX(start_ns) AS at FROM anomaly_detection.adp_source_windows WHERE complete=TRUE').fetchone()['at']
                if latest is None:return None
                self.ready_pass={'begin':max(FIVE_NS,latest-11*FIVE_NS),'end':latest+FIVE_NS,'after':None,'first_visit':True}
            cursor=self.ready_pass;params=[now,cursor['begin'],cursor['end']]
            after=''
            if cursor['after'] is not None:
                after='AND (j.target_ns,j.session_key)>(%s,%s) ';params.extend(cursor['after'])
            row=self.raw.execute('SELECT j.* FROM anomaly_detection.adp_jobs j WHERE j.target_scope=\'BEHAVIOR_TARGET\' AND j.dirty=TRUE AND j.due_ns<=%s '
                'AND j.target_ns>=%s AND j.target_ns<%s '+after+
                ('AND j.last_evaluated_ns IS NULL ' if cursor['first_visit'] else 'AND j.last_evaluated_ns IS NOT NULL ')+
                'AND EXISTS(SELECT 1 FROM anomaly_detection.adp_source_windows w WHERE w.start_ns=j.target_ns AND w.complete=TRUE) '
                'ORDER BY j.target_ns,j.session_key LIMIT 1',params).fetchone()
            if row:
                cursor['after']=(row['target_ns'],row['session_key'])
                return dict(row)
            if cursor['first_visit']:
                cursor.update(first_visit=False,after=None)
            else:self.ready_pass=None
        return None
    def next_recheck_job(self,now):
        """Finite descending keyset passes across ALL assessed ages.

        New arrivals or a repeatedly dirtied newest target cannot jump ahead
        of an in-progress pass. The cursor survives worker restarts.
        """
        state=self.state('assessed_recheck_pass_v1')
        if not state.get('upper'):
            last=self.raw.execute("SELECT target_ns,session_key FROM anomaly_detection.adp_jobs WHERE target_scope='BEHAVIOR_TARGET' "
                'AND dirty=TRUE AND last_evaluated_ns IS NOT NULL ORDER BY target_ns DESC,session_key DESC LIMIT 1').fetchone()
            if not last:return None
            state={'upper':[last['target_ns'],last['session_key']]}
        after='';params=[now,*state['upper']]
        if state.get('after'):
            after='AND (j.target_ns,j.session_key)<(%s,%s) ';params.extend(state['after'])
        row=self.raw.execute("SELECT j.* FROM anomaly_detection.adp_jobs j WHERE j.target_scope='BEHAVIOR_TARGET' "
            'AND j.dirty=TRUE AND j.last_evaluated_ns IS NOT NULL AND j.due_ns<=%s '
            'AND (j.target_ns,j.session_key)<=(%s,%s) '+after+
            'AND EXISTS(SELECT 1 FROM anomaly_detection.adp_source_windows sw WHERE sw.start_ns=j.target_ns AND sw.complete=TRUE) '
            'ORDER BY j.target_ns DESC,j.session_key DESC LIMIT 1',params).fetchone()
        with self.transaction():
            if row:state['after']=[row['target_ns'],row['session_key']]
            else:state={}
            self.save_state('assessed_recheck_pass_v1',state)
        return dict(row) if row else None
    def warm_live_priorities(self,limit=128):
        """Bounded upgrade of scheduling metadata, with no model/input changes."""
        self.raw.execute('WITH candidates AS (SELECT j.session_key,j.target_ns,w.body FROM anomaly_detection.adp_jobs j '
            'JOIN anomaly_detection.adp_windows w ON w.session_key=j.session_key AND w.start_ns=j.target_ns '
            'WHERE j.target_scope=\'BEHAVIOR_TARGET\' AND j.dirty=TRUE AND j.last_evaluated_ns IS NULL AND j.observed_count IS NULL '
            'ORDER BY j.target_ns DESC,j.session_key LIMIT %s) '
            'UPDATE anomaly_detection.adp_jobs j SET observed_count=COALESCE((SELECT SUM(value::bigint) '
            "FROM jsonb_each_text(NULLIF(c.body::jsonb->'counts','null'::jsonb))),0) FROM candidates c "
            'WHERE j.session_key=c.session_key AND j.target_ns=c.target_ns',(limit,))
    def next_live_job(self,now):
        """Recent completed populations get a reserved first assessment lane."""
        latest=self.raw.execute('SELECT start_ns FROM anomaly_detection.adp_source_windows WHERE complete=TRUE '
            'ORDER BY start_ns DESC LIMIT 1').fetchone()
        if latest is None:return None
        row=self.raw.execute('SELECT j.* FROM anomaly_detection.adp_jobs j WHERE j.target_scope=\'BEHAVIOR_TARGET\' AND j.dirty=TRUE '
            'AND j.last_evaluated_ns IS NULL AND j.due_ns<=%s AND j.target_ns>=%s AND j.target_ns<=%s '
            'AND EXISTS(SELECT 1 FROM anomaly_detection.adp_source_windows sw WHERE sw.start_ns=j.target_ns AND sw.complete=TRUE) '
            'ORDER BY j.target_ns DESC,j.observed_count DESC NULLS LAST,j.session_key LIMIT 1',
            (now,max(FIVE_NS,latest['start_ns']-2*FIVE_NS),latest['start_ns'])).fetchone()
        return dict(row) if row else None
    def next_backlog_job(self,now):
        """Busy dirty assessments remain reachable after leaving the live band."""
        row=self.raw.execute('SELECT j.* FROM anomaly_detection.adp_jobs j WHERE j.target_scope=\'BEHAVIOR_TARGET\' AND j.dirty=TRUE '
            'AND j.due_ns<=%s '
            'AND EXISTS(SELECT 1 FROM anomaly_detection.adp_source_windows sw WHERE sw.start_ns=j.target_ns AND sw.complete=TRUE) '
            'ORDER BY j.observed_count DESC NULLS LAST,j.target_ns,j.session_key LIMIT 1',(now,)).fetchone()
        return dict(row) if row else None
    def next_candidate_job(self,now):
        row=self.raw.execute("SELECT j.* FROM anomaly_detection.adp_jobs j WHERE j.target_scope='BEHAVIOR_TARGET' AND j.dirty=TRUE AND j.due_ns<=%s AND EXISTS(SELECT 1 FROM anomaly_detection.adp_case_signals s WHERE s.job_session=j.session_key AND s.target_ns=j.target_ns AND s.state='ACTIVE' AND s.review_eligible=TRUE) ORDER BY j.target_ns DESC,j.session_key LIMIT 1",(now,)).fetchone()
        return dict(row) if row else None

    def defer_job(self,job,now,reason):
        self.raw.execute("UPDATE anomaly_detection.adp_jobs SET due_ns=%s,evaluation=(COALESCE(evaluation,'{}')::jsonb || %s::jsonb)::text WHERE session_key=%s AND target_ns=%s AND version=%s",
            (now+30_000_000_000,canonical({'status':'WAITING_FOR_SOURCE_CONTEXT','reason':reason}),job['session_key'],job['target_ns'],job['version']))
    def save_context(self,job,context):
        floor=self.history_floor_ns
        if floor:
            require(job['target_ns']>=floor,'TARGET_BEFORE_AD_HISTORY_BOUNDARY')
            context=dict(context,windows=[r for r in context['windows'] if r['start_ns']>=floor],
                         events=[r for r in context.get('events',[]) if r['anchor_ns']>=floor])
        now=context['source']['captured_at_ns']
        with self.transaction():
            locked=self.raw.execute('SELECT version FROM anomaly_detection.adp_jobs WHERE session_key=%s AND target_ns=%s FOR UPDATE',
                (job['session_key'],job['target_ns'])).fetchone()
            require(locked and locked['version']==job['version'],'PRODUCT_CONTEXT_INPUT_CHANGED_RETRY')
            if not context.get('owned_snapshot'):self.bind(context['source'])
            window_rows=[]
            old={row['start_ns']:json.loads(row['body']) for row in self.raw.execute('SELECT start_ns,body FROM anomaly_detection.adp_windows '
                'WHERE session_key=%s AND start_ns>=%s AND start_ns<=%s',(job['session_key'],job['target_ns'] if context.get('target_local') else job['target_ns']-HISTORY_NS,job['target_ns'])).fetchall()}
            changed=[]
            for row in context['windows']:
                before=old.get(row['start_ns'])
                # Retention is loss of current availability, not a corrected zero.
                # Keep the qualified historical observation with its provenance.
                if before and row.get('quality_reason')=='RETENTION_SCOPE_UNAVAILABLE':continue
                if before!=row:window_rows.append((job['session_key'],row['start_ns'],canonical(row),digest(row)))
                fields=('coverage_complete','population_complete','counts','first_observed_ns')
                if before is not None and any(before.get(field)!=row.get(field) for field in fields):changed.append((job['session_key'],row['start_ns']))
            if window_rows:
                with self.raw.cursor() as cursor:
                    cursor.executemany('INSERT INTO anomaly_detection.adp_windows VALUES(%s,%s,%s,%s) '
                        'ON CONFLICT(session_key,start_ns) DO UPDATE SET body=excluded.body,content_digest=excluded.content_digest',window_rows)
            from .job_scope import coverage_only
            observed=[(job['session_key'],row['start_ns']) for row in context['windows'] if not coverage_only(row)]
            self.invalidate_many(changed,create_targets=observed)
            current=self.raw.execute('SELECT version FROM anomaly_detection.adp_jobs WHERE session_key=%s AND target_ns=%s',
                (job['session_key'],job['target_ns'])).fetchone()
            # Historical summaries live once in adp_windows, rather than being
            # duplicated for every target/session context. Evaluation reads them
            # by the indexed session/time range.
            context=dict(context,job_version=current['version'],windows=[row for row in context['windows'] if row['start_ns']==job['target_ns']])
            self.raw.execute('INSERT INTO anomaly_detection.adp_contexts VALUES(%s,%s,%s,%s,%s,%s) ON CONFLICT(session_key,target_ns) '
                'DO UPDATE SET body=excluded.body,content_digest=excluded.content_digest,captured_ns=excluded.captured_ns,job_version=excluded.job_version',
                (job['session_key'],job['target_ns'],canonical(context),digest(context),now,current['version']))
        return context
    def context(self,job):
        row=self.raw.execute('SELECT body FROM anomaly_detection.adp_contexts WHERE session_key=%s AND target_ns=%s',
            (job['session_key'],job['target_ns'])).fetchone()
        value=json.loads(row['body']) if row else None
        return value if value and value.get('job_version')==job['version'] else None
    def history(self,job):
        rows=self.raw.execute('SELECT w.body FROM anomaly_detection.adp_windows w WHERE w.session_key=%s AND w.start_ns>=%s AND w.start_ns<%s '
            "AND NOT EXISTS(SELECT 1 FROM anomaly_detection.adp_incidents i JOIN anomaly_detection.adp_feedback f ON f.incident_key=i.incident_key "
            "WHERE i.session_key=w.session_key AND i.target_ns=w.start_ns AND f.label='confirmed_suspicious' "
            "AND f.id=(SELECT MAX(latest.id) FROM anomaly_detection.adp_feedback latest WHERE latest.incident_key=i.incident_key)) "
            'ORDER BY w.start_ns DESC LIMIT 16128',(job['session_key'],job['target_ns']-HISTORY_NS,job['target_ns'])).fetchall()
        return sorted([json.loads(row['body']) for row in rows],key=lambda row:row['start_ns'])
    def excluded_windows(self,job):
        return {row['target_ns'] for row in self.raw.execute('SELECT i.target_ns FROM anomaly_detection.adp_incidents i '
            'JOIN anomaly_detection.adp_feedback f ON f.incident_key=i.incident_key WHERE i.session_key=%s '
            "AND i.target_ns>=%s AND i.target_ns<%s AND f.label='confirmed_suspicious' "
            'AND f.id=(SELECT MAX(latest.id) FROM anomaly_detection.adp_feedback latest WHERE latest.incident_key=i.incident_key)',
            (job['session_key'],job['target_ns']-HISTORY_NS,job['target_ns'])).fetchall()}
    def details(self,job):
        rows=self.raw.execute('SELECT f.request_key,f.at_ns,f.service_path,f.details,f.revision,f.anchor_key,f.state,f.source_present,j.body AS journey,j.semantic_revision FROM anomaly_detection.adp_facts f '
            'LEFT JOIN anomaly_detection.adp_journeys j ON j.request_key=f.request_key WHERE f.session_key=%s '
            'AND f.at_ns>=%s AND f.at_ns<%s AND f.eligible=TRUE '
            'AND (NOT EXISTS(SELECT 1 FROM anomaly_detection.adp_source_windows sw WHERE sw.start_ns=(f.at_ns/%s)*%s) '
            'OR EXISTS(SELECT 1 FROM anomaly_detection.adp_source_windows sw JOIN anomaly_detection.adp_window_members wm ON wm.start_ns=sw.start_ns '
            'WHERE sw.start_ns=(f.at_ns/%s)*%s AND sw.complete=TRUE AND wm.request_key=f.request_key)) '
            'ORDER BY f.at_ns DESC,f.request_key DESC LIMIT 4097',
            (job['session_key'],job['target_ns']-HISTORY_NS,job['target_ns']+FIVE_NS,FIVE_NS,FIVE_NS,FIVE_NS,FIVE_NS)).fetchall()
        values=[]
        for row in reversed(rows[:4096]):
            fact=json.loads(row['details']) if row['details'] else None
            if fact and (not row['source_present'] or row['state']!='active' or fact.get('semantic',{}).get('revision')!=row['revision'] or
                         fact.get('semantic',{}).get('anchor_key')!=row['anchor_key']):fact=None
            if fact and row['journey'] and row['semantic_revision']==fact.get('semantic',{}).get('revision'):
                fact['viewer_journey']=json.loads(row['journey'])
            values.append({'request_key':row['request_key'],'at_ns':row['at_ns'],'service_path':row['service_path'],'details':fact})
        return values,len(rows)<=4096
    def peer(self,service,target):
        return self.raw.execute('SELECT start_ns,value,eligible,input_digest FROM anomaly_detection.adp_peers WHERE service_path=%s '
            'AND start_ns<%s AND start_ns>=%s ORDER BY start_ns LIMIT 16128',(service,target,target-HISTORY_NS)).fetchall()
    def apply_cohort(self,packet, *, advance=True):
        from .product_dependencies import apply_cohort
        return apply_cohort(self,packet,advance=advance)
    def import_previous(self,limit=1024):
        """Reuse the already-migrated PostgreSQL summaries; never open a file DB."""
        if self.history_floor_ns:
            return {'done':True,'skipped':'AD_HISTORY_BOUNDARY'}
        state=self.state('previous_import')
        if state.get('done'):return state
        exists=self.raw.execute("SELECT to_regclass('anomaly_detection.ah_windows') AS name").fetchone()['name']
        if exists is None:
            self.save_state('previous_import',{'done':True,'rows':0});return {'done':True,'rows':0}
        if not state.get('binding_checked'):
            metadata_exists=self.raw.execute("SELECT to_regclass('anomaly_detection.ah_state') AS name").fetchone()['name']
            metadata=self.raw.execute('SELECT body FROM anomaly_detection.ah_state WHERE id=1').fetchone() if metadata_exists else None
            binding=json.loads(metadata['body']).get('binding') if metadata else None
            if not binding or (self.state('source_binding') and binding!=self.state('source_binding')):
                state.update(done=True,rows=0,skipped='PREVIOUS_SOURCE_BINDING_UNAVAILABLE_OR_DIFFERENT')
                self.save_state('previous_import',state);return state
            self.save_state('source_binding',binding);state['binding_checked']=True
        params=[];predicate=''
        if state.get('session') is not None:
            predicate=' WHERE (session_key,start_ns)>(%s,%s)';params=[state['session'],state['at']]
        rows=self.raw.execute('SELECT session_key,start_ns,body,last_valid FROM anomaly_detection.ah_windows'+predicate+
            ' ORDER BY session_key,start_ns LIMIT %s',(*params,limit)).fetchall()
        with self.transaction():
            values=[]
            for row in rows:
                body=json.loads(row['last_valid'] or row['body'])
                values.append((row['session_key'],row['start_ns'],canonical(body),digest(body)))
            if values:
                with self.raw.cursor() as cursor:
                    cursor.executemany('INSERT INTO anomaly_detection.adp_windows VALUES(%s,%s,%s,%s) ON CONFLICT DO NOTHING',values)
                positive=[(row['session_key'],row['start_ns']) for row in rows if sum((json.loads(row['last_valid'] or row['body']).get('counts') or {}).values())>0]
                self.invalidate_many(positive)
            state.update(rows=state.get('rows',0)+len(rows),done=len(rows)<limit)
            if rows:state.update(session=rows[-1]['session_key'],at=rows[-1]['start_ns'])
            self.save_state('previous_import',state)
            if state['done'] and self.raw.execute("SELECT to_regclass('anomaly_detection.adb_points') AS name").fetchone()['name'] is not None:
                self.raw.execute("INSERT INTO anomaly_detection.adp_peers SELECT service_path,start_ns,value,FALSE,input_digest "
                    "FROM anomaly_detection.adb_points WHERE metric='active_session_p95' ON CONFLICT DO NOTHING")
        return state
    def complete(self,job,context,decisions,now, *, fault=None):
        key=(job['session_key'],job['target_ns']);changed=0
        with self.transaction():
            row=self.raw.execute('SELECT version,primary_version FROM anomaly_detection.adp_jobs WHERE session_key=%s AND target_ns=%s FOR UPDATE',key).fetchone()
            if not row or row['version']!=job['version']:return {'status':'INPUT_CHANGED_RETRY'}
            from .product_dependencies import commit_dependencies
            if not commit_dependencies(self,job,context.get('peer_inputs',{})):return {'status':'INPUT_CHANGED_RETRY'}
            for decision in decisions:
                model=decision.get('model')
                if model:
                    decision['model_id']=model['model_id']
                    self.raw.execute('INSERT INTO anomaly_detection.adp_models VALUES(%s,%s,%s,%s) ON CONFLICT DO NOTHING',(model['model_id'],decision['family'],canonical(model),now))
            old={row['finding_key']:row for row in self.raw.execute('SELECT * FROM anomaly_detection.adp_findings '
                'WHERE session_key=%s AND target_ns=%s',key).fetchall()}
            current={decision['finding_key']:decision for decision in decisions}
            for finding_key in sorted(old.keys()|current.keys()):
                previous=old.get(finding_key);decision=current.get(finding_key)
                if decision is None:
                    body=json.loads(previous['body'])
                    unavailable=any(d['family']==body['family'] and d['status']=='INSUFFICIENT_DATA' and
                        d.get('service_path','*') in ('*',body.get('service_path','*')) for d in decisions)
                    unmodelled=any(w.get('unmapped_behaviors',0) for w in context.get('windows',[]) if w['start_ns']==job['target_ns'])
                    known_absent=bool(context.get('target_complete') and not unavailable and not unmodelled)
                    decision=body|{'status':'NO_DEVIATION_OBSERVED' if known_absent else 'INSUFFICIENT_DATA',
                        'reason':'NOT_PRESENT_IN_CURRENT_COMPLETE_EVALUATION' if known_absent else 'FAMILY_OR_TARGET_COVERAGE_UNKNOWN'}
                state=('ACTIVE' if decision['status']=='CANDIDATE' else 'DEFERRED' if decision['status']=='INSUFFICIENT_DATA' else 'WITHDRAWN')
                if previous is None and state!='ACTIVE':continue
                model=decision.get('model')
                value={k:v for k,v in decision.items() if k!='model'}|{'state':state,'source_observed_ns':context['source']['captured_at_ns']}
                if model:value['model_id']=model['model_id']
                signature=digest({k:v for k,v in value.items() if k not in ('source_observed_ns','source_generation')})
                if previous and signature==previous['content_digest']:continue
                revision=previous['revision']+1 if previous else 1
                self.raw.execute('INSERT INTO anomaly_detection.adp_findings VALUES('+','.join(['%s']*11)+') '
                    'ON CONFLICT(finding_key) DO UPDATE SET state=excluded.state,revision=excluded.revision,score=excluded.score,'
                    'content_digest=excluded.content_digest,body=excluded.body,updated_ns=excluded.updated_ns',
                    (finding_key,*key,decision['family'],decision['dimension'],state,revision,float(decision.get('score',0)),signature,canonical(value),now))
                self.raw.execute('INSERT INTO anomaly_detection.adp_finding_versions VALUES(%s,%s,%s,%s)',(finding_key,revision,canonical(value),now));changed+=1
                if model:self.raw.execute('INSERT INTO anomaly_detection.adp_models VALUES(%s,%s,%s,%s) ON CONFLICT DO NOTHING',
                    (model['model_id'],decision['family'],canonical(model),now))
            active=self.raw.execute("SELECT finding_key,dimension,body FROM anomaly_detection.adp_findings WHERE session_key=%s AND target_ns=%s AND state='ACTIVE'",key).fetchall()
            deferred=self.raw.execute("SELECT 1 FROM anomaly_detection.adp_findings WHERE session_key=%s AND target_ns=%s AND state='DEFERRED' LIMIT 1",key).fetchone() is not None
            incident_key='ai1:'+digest(list(key))
            previous=self.raw.execute('SELECT * FROM anomaly_detection.adp_incidents WHERE incident_key=%s',(incident_key,)).fetchone()
            if active or previous:
                from .input_subjects import FAMILY as INPUT_FAMILY
                from .review_policy import corroborated_scopes
                active_values=[json.loads(r['body']) for r in active]
                dimensions=sorted({row['dimension'] for row in active if row['dimension']!='context'})
                peer_explained=any(v.get('peer_activity_can_explain') for v in active_values)
                qualified=context.get('target_complete') is True and context.get('evidence_verified') is True
                strong_single=any(v.get('family')=='peer_service_rate_5m' and
                    v.get('single_signal_review_eligible') is True for v in active_values)
                input_finding=any(v.get('family')==INPUT_FAMILY and v.get('evidence_verified') is True
                    and v.get('single_signal_review_eligible') is True for v in active_values)
                ready=input_finding or (qualified and (corroborated_scopes(active_values) or (strong_single and not peer_explained)))
                state='NEEDS_REVIEW' if ready else 'HOLD' if active or deferred else 'WITHDRAWN'
                body={'incident_key':incident_key,'session_key':key[0],'target_ns':key[1],
                    'finding_keys':[row['finding_key'] for row in active],'dimensions':dimensions,'signal_groups':len(dimensions),
                    'evidence_verified':qualified,'peer_activity_can_explain':peer_explained,'state':state,'operator_alert':False,'precision_recall':'NOT_EVALUATED',
                    'explanation_fa':('چند موضوع ورودی متمایز با شاهد معتبر در بازهٔ کوتاه دیده شد و برای بررسی انسانی ثبت شد.' if input_finding else
                    'نرخ خدمت با مرجع معتبر همان خدمت و شواهد درخواست‌ها انحراف دارد؛ نیازمند بررسی انسانی است و اثبات تقلب نیست.' if strong_single else
                    'چند بُعد رفتاری با شاهد قابل بررسی دیده شده است؛ نیازمند بررسی انسانی است.') if state=='NEEDS_REVIEW' else
                    'انحراف آماری برای بررسی ذخیره شده است؛ شاهد مستقل یا پوشش کافی برای اولویت بالاتر هنوز فراهم نیست.' if active else
                    'شاهد یا پوشش فعلی برای بازبینی کافی نیست؛ تصمیم قبلی تا رسیدن داده در انتظار بررسی باقی می‌ماند.' if deferred else
                    'با رسیدن شواهد جدید، معیارهای انحراف قبلی دیگر برقرار نیستند.'}
                signature=digest(body)
                if previous is None or previous['content_digest']!=signature:
                    revision=previous['revision']+1 if previous else 1
                    self.raw.execute('INSERT INTO anomaly_detection.adp_incidents VALUES(%s,%s,%s,%s,%s,%s,%s,%s) '
                        'ON CONFLICT(incident_key) DO UPDATE SET state=excluded.state,revision=excluded.revision,body=excluded.body,'
                        'content_digest=excluded.content_digest,updated_ns=excluded.updated_ns',(incident_key,*key,state,revision,canonical(body),signature,now))
                elif previous['state']!=state:
                    self.raw.execute('UPDATE anomaly_detection.adp_incidents SET state=%s,updated_ns=%s WHERE incident_key=%s',(state,now,incident_key))
            fields=('family','status','reason','score','service_path','observed','expected','upper','baseline_origin',
                'history_windows','personal_history_windows','positive_history_windows','peer_windows','peer_qualified_windows',
                'witness_request_key','explanation_fa')
            fields+=('model_id','duration_ns','begin_ns','end_ns','span_evidence_verified','other_session_epochs','peer_session_epochs','empirical_tail_rank','adjusted_empirical_tail_rank','comparison_count',
                'subject_field','verified_input_requests','observed_requests','observed_span_ns','reference_model_id','upper_bound_tail_rank',
                'screening_level','screening_policy','calibration_status','baseline_unit','single_signal_review_eligible','reference_max','review_basis','review_policy_version','independent_positive_history','history_interval_ns')
            pending=list(context.get('pending_families') or ())
            if 'continuous_rate' not in pending and any(d.get('reason')=='CONTINUOUS_MODEL_READ_RETRY' for d in decisions):
                pending.append('continuous_rate')
            evaluation={'decisions':[{k:decision[k] for k in fields if k in decision} for decision in decisions],
                'changed_findings':changed,'operator_alert':False,'rate_history_policy_version':2,'pending_families':pending,
                'primary_version':row['primary_version'],'primary_qualified_requests':context.get('primary_qualified_requests'),
                'primary_expected_requests':context.get('primary_expected_requests')}
            # Includes imported windows and qualified evidence used by models,
            # even when the latest source page has a narrower retained scope.
            begin=max(FIVE_NS,job['target_ns']-HISTORY_NS)
            self.raw.execute('UPDATE anomaly_detection.adp_jobs SET dirty=FALSE,processed_version=version,training_begin_ns=%s,'
                'last_evaluated_ns=%s,input_digest=%s,evaluation=%s,due_ns=%s WHERE session_key=%s AND target_ns=%s',
                (begin,now,digest(context),canonical(evaluation),now+600_000_000_000,*key))
            self.raw.execute('DELETE FROM anomaly_detection.adp_evidence_ready WHERE session_key=%s AND target_ns=%s',key)
            from .model_queue import schedule
            schedule(self,job,pending,now+(30_000_000_000 if pending and not context.get('primary_evaluation') else 0))
            from .cases import sync_actor
            sync_actor(self,dict(job,primary_version=row['primary_version']),context,now,decisions)
            if fault:fault()
        return {'status':'APPLIED','changed_findings':changed,'decisions':evaluation['decisions']}
    def feedback(self,incident,label,note,now):
        require(label in ('confirmed_suspicious','reviewed_benign','needs_evidence'),'INVALID_REVIEW_LABEL')
        require(isinstance(note,str) and len(note)<=2000,'REVIEW_NOTE_TOO_LONG')
        case=self.raw.execute('SELECT revision,session_key,target_ns FROM anomaly_detection.adp_incidents WHERE incident_key=%s',(incident,)).fetchone()
        require(case is not None,'INCIDENT_NOT_FOUND')
        with self.transaction():
            self.raw.execute('INSERT INTO anomaly_detection.adp_feedback(incident_key,label,note,created_ns,incident_revision) VALUES(%s,%s,%s,%s,%s)',
                (incident,label,note,now,case['revision']))
            self.invalidate(case['session_key'],case['target_ns'])
            from .product_dependencies import context_changed
            services=self.raw.execute('SELECT DISTINCT service_path FROM anomaly_detection.adp_facts WHERE session_key=%s AND at_ns>=%s AND at_ns<%s',
                (case['session_key'],case['target_ns'],case['target_ns']+FIVE_NS)).fetchall()
            for row in services:context_changed(self,row['service_path'],case['target_ns'])
            from .model_queue import reference_changed
            reference_changed(self,[(r['service_path'],case['target_ns']) for r in services])
            from .product_pipeline import refresh_cohort
            refresh_cohort(self,case['target_ns'])
    def report(self):
        from .case_summary import statistics as review_statistics
        from .scenario_store import report as scenario_report
        from .runtime_statistics import collect
        def rows(query):return [dict(r) for r in self.raw.execute(query).fetchall()]
        def one(query):return dict(self.raw.execute(query).fetchone())
        def grouped(query,key):return {r[key]:r['n'] for r in self.raw.execute(query).fetchall()}
        def latest():
            row=self.raw.execute('SELECT target_ns FROM anomaly_detection.adp_jobs WHERE dirty=FALSE ORDER BY target_ns DESC LIMIT 1').fetchone()
            return row['target_ns']+FIVE_NS if row else None
        controls={'case_migration':'stable_cases_backfill_v1','population_backfill':'population_backfill_v1',
            'job_scope_backfill':'job_scope_backfill_v1','job_scope_fast_promote':'job_scope_fast_promote_v1',
            'candidate_audit_scope':'candidate_audit_scope_v4'}
        sections=[
            ('counters',lambda:self.state('counters')),
            ('control_state',lambda:{k:self.state(v) for k,v in controls.items()}),
            ('scenario_analysis',lambda:scenario_report(self)),
            ('stable_cases',lambda:grouped('SELECT state,COUNT(*) AS n FROM anomaly_detection.adp_cases GROUP BY state','state')),
            ('review_queue',lambda:review_statistics(self)),
            ('population_queue',lambda:one('SELECT COUNT(*) AS jobs,COUNT(*) FILTER(WHERE dirty=TRUE) AS pending,COUNT(*) FILTER(WHERE processed_version>0) AS attempted,MAX(start_ns) FILTER(WHERE processed_version>0) AS newest_attempted_target_ns FROM anomaly_detection.adp_population_jobs')),
            ('complete_shared_windows',lambda:one('SELECT COUNT(*) AS n FROM anomaly_detection.adp_source_windows WHERE complete=TRUE')['n']),
            ('latest_evaluated_target_end_ns',latest),
            ('readiness',lambda:rows("SELECT d->>'family' AS family,d->>'status' AS status,COUNT(*) AS decisions FROM (SELECT evaluation FROM anomaly_detection.adp_jobs WHERE last_evaluated_ns IS NOT NULL ORDER BY last_evaluated_ns DESC LIMIT 256) AS recent CROSS JOIN LATERAL jsonb_array_elements(recent.evaluation::jsonb->'decisions') AS d GROUP BY 1,2 ORDER BY 1,2")),
            ('secondary_model_queue',lambda:one('SELECT COUNT(*) AS jobs,COUNT(*) FILTER(WHERE r.expected_version=j.version AND NOT j.dirty) AS current_inputs,MIN(r.due_ns) AS first_due_ns FROM anomaly_detection.adp_model_queue r LEFT JOIN anomaly_detection.adp_jobs j USING(session_key,target_ns)')),
            ('jobs',lambda:grouped("SELECT CASE WHEN target_scope='COVERAGE_ONLY' THEN 'coverage_only' WHEN target_scope IS NULL THEN 'scope_pending' WHEN dirty THEN 'pending' ELSE 'evaluated' END AS state,COUNT(*) AS n FROM anomaly_detection.adp_jobs GROUP BY 1",'state')),
            ('incidents',lambda:grouped('SELECT state,COUNT(*) AS n FROM anomaly_detection.adp_incidents GROUP BY state','state')),
            ('behavior_kinds',lambda:rows('SELECT kind,eligible,COUNT(*) AS behaviors FROM anomaly_detection.adp_facts GROUP BY kind,eligible ORDER BY kind,eligible')),
        ]
        parts,quality=collect(self,sections)
        result=parts.pop('counters') or {};result.update(parts.pop('control_state') or {})
        result.update(parts)
        # Maintain the established response types while explicitly retaining
        # null for an unavailable count. No missing count becomes zero.
        for name in ('scenario_analysis','stable_cases','review_queue','population_queue','secondary_model_queue','incidents'):
            if result[name] is None:result[name]={}
        if result['jobs'] is None:result['jobs']={k:None for k in ('pending','evaluated','coverage_only','scope_pending')}
        for name in ('readiness','behavior_kinds'):
            if result[name] is None:result[name]=[]
        result.update(storage_backend='postgresql',schema='anomaly_detection',historical_recheck_age_limit=None,
            source_cdc_complete=False,operator_alerts=0,precision_recall='NOT_EVALUATED',
            readiness_scope='LATEST_256_EVALUATED_JOBS_NOT_TOTAL_POPULATION',statistics_collection=quality)
        return result
