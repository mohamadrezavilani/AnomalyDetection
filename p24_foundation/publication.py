"""Bounded incremental reconciliation and atomic observed-evidence publication.

Publication is independent of producer authority. Source heads remain untouched.
Every reader pins an immutable publication; only its current pointer changes.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import re
import uuid
from datetime import timezone

from .errors import FoundationError
from .parser import PARSER_VERSION, PRIVACY_VERSION
from .privacy import canonical
from .reconstruction import RESOLVER_VERSION, registration_candidates
from .store import MAX_PROJECTION_EVENTS, MAX_SOURCES, execute_many, jsonb, stable_id
from .time import microsecond_cutoff

PUBLICATION_VERSION = "p24-observed-publication.2h.2"
MAX_HEADS = 100_000
MAX_CLOSURE_ORIGINS = MAX_PROJECTION_EVENTS * 2
MAX_CLOSURE_STEPS = 64


def head_digest(heads):
    # Typed keys and UUIDs cannot contain the separators.
    data = "".join(q+"\t"+str(run)+"\n" for q,run in sorted(heads.items()))
    return hashlib.sha256(data.encode()).hexdigest()


def checked_reference(value):
    try:
        return uuid.UUID(str(value))
    except (TypeError, ValueError, AttributeError):
        raise FoundationError("invalid_publication_reference") from None


def checked_limit(value):
    if isinstance(value,bool) or not isinstance(value,int) or not 1<=value<=100:
        raise FoundationError("invalid_page_size")
    return value


class ObservationPublisher:
    def __init__(self, store, *, checkpoint_every=64):
        if isinstance(checkpoint_every,bool) or not isinstance(checkpoint_every,int) or not 1<=checkpoint_every<=64:
            raise FoundationError("invalid_checkpoint_interval")
        self.store, self.c, self.n = store, store.c, store.namespace_id
        self.checkpoint_every = checkpoint_every

    def _current(self):
        row=self.c.execute("SELECT publication_id,generation FROM p24_next.foundation_observation_current WHERE namespace_id=%s",(self.n,)).fetchone()
        return row if row else (None,0)

    def _header(self, publication_id):
        p=checked_reference(publication_id)
        row=self.c.execute("""SELECT base_publication_id,expected_generation,is_checkpoint,overlay_depth,
            input_manifest,input_sha256,request_heads_sha256,coverage,statistics,entry_count,request_count,state
            FROM p24_next.foundation_observation_publication WHERE namespace_id=%s AND publication_id=%s""",(self.n,p)).fetchone()
        if not row or row[-1]!='sealed':
            raise FoundationError("publication_not_available")
        names=('base_publication_id','expected_generation','is_checkpoint','overlay_depth','input_manifest','input_sha256',
               'request_heads_sha256','coverage','statistics','entry_count','request_count','state')
        return dict(zip(names,row),publication_id=p)

    def _heads(self, publication_id, request=None):
        rows=self.c.execute("SELECT request_key,run_id FROM p24_next.foundation_observation_heads(%s,%s,%s) LIMIT %s",
                            (self.n,publication_id,request,MAX_HEADS+1)).fetchall()
        if len(rows)>MAX_HEADS:
            raise FoundationError("publication_request_limit")
        return dict(rows)

    def _origin_rows(self, sources, *, extra_sql='', extra_args=()):
        if not sources:return set()
        rows=self.c.execute("""SELECT DISTINCT ev.event_key FROM p24_next.event_source es
            JOIN p24_next.event_version ev USING(namespace_id,event_version_id)
            WHERE es.namespace_id=%s AND es.snapshot_id=ANY(%s)"""+extra_sql+" LIMIT %s",
            (self.n,list(sources),*extra_args,MAX_CLOSURE_ORIGINS+1)).fetchall()
        if len(rows)>MAX_CLOSURE_ORIGINS:raise FoundationError("publication_impact_limit")
        return {r[0] for r in rows}

    def _closure(self, sources, origins, requests=()):
        """Close the RequestID/origin graph, including changed-ID variants."""
        requests=set(requests);origins=set(origins)
        if not sources:return requests
        for _ in range(MAX_CLOSURE_STEPS):
            before=(len(origins),len(requests))
            if origins:
                rows=self.c.execute("""SELECT DISTINCT ev.request_key FROM p24_next.event_source es
                    JOIN p24_next.event_version ev USING(namespace_id,event_version_id)
                    WHERE es.namespace_id=%s AND es.snapshot_id=ANY(%s) AND ev.event_key=ANY(%s)
                      AND ev.request_key IS NOT NULL LIMIT %s""",(self.n,list(sources),sorted(origins),MAX_CLOSURE_ORIGINS+1)).fetchall()
                requests.update(r[0] for r in rows)
            if len(requests)>MAX_CLOSURE_ORIGINS:raise FoundationError("publication_impact_limit")
            if requests:
                origins.update(self._origin_rows(sources,extra_sql=' AND ev.request_key=ANY(%s)',extra_args=(sorted(requests),)))
            if len(origins)>MAX_CLOSURE_ORIGINS:raise FoundationError("publication_impact_limit")
            if before==(len(origins),len(requests)):return requests
        raise FoundationError("publication_impact_closure_limit")

    def prepare(self, source_ids, *, event_cutoff, knowledge_at, expected_generation,
                mode='historical_revised', association_horizon_seconds=300, workflow_run_id=None):
        if isinstance(expected_generation,bool) or not isinstance(expected_generation,int) or expected_generation<0:
            raise FoundationError("invalid_publication_generation")
        if not isinstance(mode,str) or mode not in {'design_fixture','online_original','historical_revised'}:
            raise FoundationError("invalid_projection_mode")
        if isinstance(association_horizon_seconds,bool) or not isinstance(association_horizon_seconds,int) or not 0<=association_horizon_seconds<=3600:
            raise FoundationError("invalid_association_search_horizon")
        cutoff,known=microsecond_cutoff(event_cutoff),microsecond_cutoff(knowledge_at)
        try:sources=sorted({uuid.UUID(str(x)) for x in source_ids})
        except (TypeError,ValueError,AttributeError):raise FoundationError("invalid_source_vector") from None
        if len(sources)>MAX_SOURCES:raise FoundationError("source_vector_limit")
        with self.c.transaction():
            self.store._lock()
            base_id,generation=self._current()
            if generation!=expected_generation:raise FoundationError("stale_publication_generation")
            base=self._header(base_id) if base_id else None
            policy=dict(version=PUBLICATION_VERSION,mode=mode,extraction=PARSER_VERSION,resolver=RESOLVER_VERSION,
                        privacy=PRIVACY_VERSION,catalog=self.store.catalog.digest,key_version=self.store.keys.version,
                        association_horizon_seconds=association_horizon_seconds)
            if base and (cutoff.epoch_ns<int(base['input_manifest']['event_cutoff_ns']) or known.epoch_ns<int(base['input_manifest']['knowledge_at_ns'])):
                raise FoundationError("publication_time_regression")
            rows=self.c.execute("""SELECT s.snapshot_id,s.source_digest,s.observed_at,m.receive_time_basis,m.coverage,
                    sm.manifest_version,sm.source_kind,sm.manifest_sha256,sm.producer_authority,
                    sm.source_window_complete,sm.source_finality,receipt.first_received_at,
                    receipt.first_receipt_id,receipt.receipt_count
                FROM p24_next.source_snapshot s JOIN p24_next.foundation_snapshot_metadata m USING(namespace_id,snapshot_id)
                JOIN p24_next.foundation_source_manifest sm USING(namespace_id,snapshot_id)
                LEFT JOIN LATERAL (
                    SELECT min(r.received_at) AS first_received_at,
                           (array_agg(r.receipt_id ORDER BY r.received_at,r.receipt_id))[1] AS first_receipt_id,
                           count(*)::bigint AS receipt_count
                    FROM p24_next.foundation_source_receipt r
                    WHERE r.namespace_id=s.namespace_id AND r.snapshot_id=s.snapshot_id AND r.received_at<=%s
                ) receipt ON true
                WHERE s.namespace_id=%s AND s.snapshot_id=ANY(%s) ORDER BY s.snapshot_id""",(known.floor,self.n,sources)).fetchall()
            if len(rows)!=len(sources):raise FoundationError("source_vector_not_in_namespace")
            if mode!='design_fixture' and any(r[2]>known.floor for r in rows):raise FoundationError("source_not_known_at_snapshot")
            effective,choices=self.store._resolve_source_vector(sources) if sources else ([],{})
            effective_set=set(effective)
            safe_sources=[dict(snapshot_id=str(r[0]),digest=r[1],receive_time_basis=r[3],
                               manifest_version=r[5],source_kind=r[6],manifest_sha256=r[7],
                               producer_authority=r[8],source_window_complete=bool(r[9]),source_finality=r[10],
                               first_receipt_at=r[11].astimezone(timezone.utc).isoformat() if r[11] else None,
                               first_receipt_id=str(r[12]) if r[12] else None,receipt_count_known=int(r[13] or 0),
                               query_traversal_complete=bool(r[4].get('acquisition',{}).get('query_traversal_complete',False))) for r in rows]
            replacement_manifest=[]
            for old,value in sorted(choices.items()):
                lineage=self.c.execute("""WITH RECURSIVE chain AS (
                    SELECT r.revision_id,r.prior_snapshot_id,r.replacement_snapshot_id,r.reason_key,r.declared_by,r.declared_at,1 AS depth
                    FROM p24_next.foundation_source_replacement r
                    WHERE r.namespace_id=%s AND r.replacement_snapshot_id=%s
                    UNION ALL
                    SELECT r.revision_id,r.prior_snapshot_id,r.replacement_snapshot_id,r.reason_key,r.declared_by,r.declared_at,c.depth+1
                    FROM chain c JOIN p24_next.foundation_source_replacement r
                      ON r.namespace_id=%s AND r.replacement_snapshot_id=c.prior_snapshot_id
                    WHERE c.prior_snapshot_id<>%s AND c.depth<128
                ) SELECT revision_id,prior_snapshot_id,replacement_snapshot_id,reason_key,declared_by,declared_at
                  FROM chain ORDER BY depth DESC""",
                    (self.n,value[1],self.n,old)).fetchall()
                if (not lineage or lineage[0][1]!=old or lineage[-1][2]!=value[1]
                        or any(left[2]!=right[1] for left,right in zip(lineage,lineage[1:]))):
                    raise FoundationError("source_replacement_lineage_missing")
                replacement_manifest.append(dict(prior_snapshot_id=str(old),replacement_snapshot_id=str(value[1]),
                    revision_chain=[dict(revision_id=str(edge[0]),prior_snapshot_id=str(edge[1]),
                        replacement_snapshot_id=str(edge[2]),reason_key=edge[3],declared_by=edge[4],
                        declared_at=edge[5].astimezone(timezone.utc).isoformat()) for edge in lineage],
                    assertion="operator_declared_not_producer_verified"))
            manifest=dict(requested_sources=safe_sources,effective_sources=[str(x) for x in effective],
                          superseded=replacement_manifest,
                          event_cutoff_ns=str(cutoff.epoch_ns),knowledge_at_ns=str(known.epoch_ns),policy=policy,
                          checkpoint_every=self.checkpoint_every)
            if workflow_run_id is not None:
                from .workflow_store import WorkflowStore
                manifest['workflow_projection']=WorkflowStore(self.store).binding(workflow_run_id,
                    sources=effective,event_cutoff_ns=cutoff.epoch_ns,knowledge_at_ns=known.epoch_ns)
            digest=hashlib.sha256(canonical(manifest)).hexdigest()
            p=stable_id(self.store.namespace,'observed_publication',str(base_id) if base_id else None,generation,digest)
            if self.c.execute("SELECT 1 FROM p24_next.foundation_observation_publication WHERE namespace_id=%s AND publication_id=%s",(self.n,p)).fetchone():
                return self._info(p)
            event_count=self.c.execute("SELECT count(*) FROM (SELECT DISTINCT event_version_id FROM p24_next.event_source WHERE namespace_id=%s AND snapshot_id=ANY(%s)) x",(self.n,effective)).fetchone()[0]
            old_heads=self._heads(base_id) if base_id else {}
            old_sources={checked_reference(x) for x in base['input_manifest']['effective_sources']} if base else set()
            combined=old_sources|effective_set
            full=base is None or base['input_manifest']['policy']!=policy
            # Retained history is not the incremental recomputation workload.
            # Full rebuilds and every scoped projection keep their existing caps.
            if full and event_count>MAX_PROJECTION_EVENTS:
                raise FoundationError("publication_event_limit")
            origins=self._origin_rows(combined if full else old_sources^effective_set)
            seed_requests=set(old_heads) if full else set()
            if base and not full:
                prior=base['input_manifest']
                temporal=' AND ((ev.source_time_epoch_ns>=%s::numeric AND ev.source_time_epoch_ns<%s::numeric)'
                args=[prior['event_cutoff_ns'],str(cutoff.epoch_ns)]
                if mode!='design_fixture':
                    temporal+=' OR (ev.received_at>%s AND ev.received_at<=%s)'
                    args.extend([microsecond_cutoff_from_ns(prior['knowledge_at_ns']),known.floor])
                temporal+=')'
                origins.update(self._origin_rows(combined,extra_sql=temporal,extra_args=args))
            impacted=self._closure(combined,origins,seed_requests)
            scoped=[]
            if effective and impacted:
                scoped=[r[0] for r in self.c.execute("""SELECT DISTINCT request_key FROM p24_next.request_source
                    WHERE namespace_id=%s AND snapshot_id=ANY(%s) AND request_key=ANY(%s) LIMIT %s""",
                    (self.n,effective,sorted(impacted),MAX_PROJECTION_EVENTS+1)).fetchall()]
            if len(scoped)>MAX_PROJECTION_EVENTS:raise FoundationError("publication_request_limit")
            recomputed={};reconstruction_events=0
            if scoped:
                run=self.store.project(effective,event_cutoff=event_cutoff,knowledge_at=knowledge_at,mode=mode,
                                       association_horizon_seconds=association_horizon_seconds,request_keys=scoped)
                run_id=uuid.UUID(run['run_id'])
                recomputed={q:run_id for q, in self.c.execute("SELECT request_key FROM p24_next.foundation_request_summary WHERE namespace_id=%s AND run_id=%s",(self.n,run_id)).fetchall()}
                reconstruction_events=run['selected_request_events']
            heads={q:r for q,r in old_heads.items() if q not in impacted}
            heads.update(recomputed)
            if len(heads)>MAX_HEADS:raise FoundationError("publication_request_limit")
            removed=(set(old_heads)&impacted)-set(recomputed)
            checkpoint_reason=('initial' if base is None else 'overlay_depth' if base['overlay_depth']+1>=self.checkpoint_every
                               else 'delta_capacity' if len(recomputed)+len(removed)>MAX_HEADS else None)
            checkpoint=checkpoint_reason is not None
            depth=0 if checkpoint else base['overlay_depth']+1
            entries=[(self.n,p,q,r,'upsert','recomputed' if q in recomputed else 'checkpoint_reuse')
                     for q,r in sorted((heads if checkpoint else recomputed).items())]
            if not checkpoint:entries.extend((self.n,p,q,None,'remove','removed') for q in sorted(removed))
            stats=dict(reconciliation='full_policy_rebuild' if full else 'incremental',impacted_requests=len(impacted),
                       reconciled_request_ids=len(scoped),
                       recomputed_requests=len(recomputed),reused_requests=len(heads)-len(recomputed),removed_requests=len(removed),
                       reconstructed_request_events=reconstruction_events,input_event_versions=event_count,
                       delta_entries=len(recomputed)+len(removed),stored_entries=len(entries))
            stats['checkpoint_reason']=checkpoint_reason
            coverage=dict(evidence_scope='observed_only',source_window_complete=False,authoritative_source_heads_published=False,
                          producer_authority='unverified_local_capture',source_finality='not_established',
                          selected_sources=len(effective),requested_sources=len(sources),
                          consistent_capture_sources=sum(s['query_traversal_complete'] for s in safe_sources if checked_reference(s['snapshot_id']) in effective_set))
            self.c.execute("""INSERT INTO p24_next.foundation_observation_publication
                (namespace_id,publication_id,base_publication_id,expected_generation,is_checkpoint,overlay_depth,input_manifest,
                 input_sha256,request_heads_sha256,coverage,statistics,entry_count,request_count)
                VALUES(%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)""",
                (self.n,p,base_id,generation,checkpoint,depth,jsonb(manifest),digest,head_digest(heads),jsonb(coverage),jsonb(stats),len(entries),len(heads)))
            execute_many(self.c,"INSERT INTO p24_next.foundation_observation_entry VALUES(%s,%s,%s,%s,%s,%s)",entries)
            if workflow_run_id is not None:
                self.c.execute("INSERT INTO p24_next.foundation_observation_workflow VALUES(%s,%s,%s)",
                               (self.n,p,checked_reference(workflow_run_id)))
            self.c.execute("UPDATE p24_next.foundation_observation_publication SET state='sealed' WHERE namespace_id=%s AND publication_id=%s",(self.n,p))
        return self._info(p)

    def _advance_current(self, p, generation):
        if generation==1:
            self.c.execute("INSERT INTO p24_next.foundation_observation_current VALUES(%s,%s,%s)",(self.n,p,generation))
        else:
            row=self.c.execute("""UPDATE p24_next.foundation_observation_current SET publication_id=%s,generation=%s
                WHERE namespace_id=%s AND generation=%s RETURNING publication_id""",(p,generation,self.n,generation-1)).fetchone()
            if not row:raise FoundationError('stale_publication_generation')

    def publish(self, publication_id):
        p=checked_reference(publication_id)
        with self.c.transaction():
            self.store._lock()
            header=self._header(p)
            existing=self.c.execute("SELECT generation FROM p24_next.foundation_observation_commit WHERE namespace_id=%s AND publication_id=%s",(self.n,p)).fetchone()
            if existing:return self._info(p)
            current,generation=self._current()
            if (current,generation)!=(header['base_publication_id'],header['expected_generation']):
                raise FoundationError("stale_publication_generation")
            if head_digest(self._heads(p))!=header['request_heads_sha256']:
                raise FoundationError("publication_head_manifest_mismatch")
            self.c.execute("INSERT INTO p24_next.foundation_observation_commit(namespace_id,publication_id,generation) VALUES(%s,%s,%s)",(self.n,p,generation+1))
            self._advance_current(p,generation+1)
        return self._info(p)

    def info(self, publication_id=None, *, access_token=None):
        """Inspect a publication only through the signed investigator policy."""
        _, principal = self.store._authorize_access("read_publication", "publication",
                                                    publication_id or "current", access_token)
        result = self._info(publication_id)
        if result.get("publication_id"):
            p = checked_reference(result["publication_id"])
            token = self.store.keys.token(self.store.namespace, "publication_resource", str(p))
            self._audit(p, "publication", token, principal)
        return result

    def _info(self, publication_id=None):
        if publication_id is None:
            current,generation=self._current()
            if current is None:return dict(status='empty',generation=0,publication_id=None,evidence_scope='observed_only')
            publication_id=current
        h=self._header(publication_id);p=h['publication_id']
        commit=self.c.execute("SELECT generation FROM p24_next.foundation_observation_commit WHERE namespace_id=%s AND publication_id=%s",(self.n,p)).fetchone()
        totals=self.c.execute("""SELECT coalesce(sum((s.summary->>'distinct_client_request_count')::int),0),
            coalesce(sum((s.summary->>'selected_event_count')::int),0),count(DISTINCT s.summary->>'session_key')
            FROM p24_next.foundation_observation_heads(%s,%s) h
            JOIN p24_next.foundation_request_summary s ON s.namespace_id=%s AND s.request_key=h.request_key AND s.run_id=h.run_id""",(self.n,p,self.n)).fetchone()
        return dict(publication_id=str(p),generation=commit[0] if commit else None,status='published' if commit else 'prepared',
                    expected_generation=h['expected_generation'],base_publication_id=str(h['base_publication_id']) if h['base_publication_id'] else None,
                    request_count=h['request_count'],distinct_client_requests=int(totals[0]),selected_request_events=int(totals[1]),known_sessions=totals[2],
                    is_checkpoint=h['is_checkpoint'],overlay_depth=h['overlay_depth'],input_manifest_sha256=h['input_sha256'],
                    request_heads_sha256=h['request_heads_sha256'],coverage=h['coverage'],statistics=h['statistics'],
                    input_manifest=h['input_manifest'],production_modified=False)

    def _audit(self, p, kind, token, principal_key):
        if not isinstance(principal_key,str) or not re.fullmatch(r'[A-Za-z_]+:[A-Za-z0-9_-]+:[a-f0-9]{64}',principal_key):
            raise FoundationError('invalid_verified_principal')
        self.c.execute("INSERT INTO p24_next.foundation_observation_access(namespace_id,publication_id,object_kind,object_token,principal_claim,authentication_state) VALUES(%s,%s,%s,%s,%s,'verified_signed_credential')",
                       (self.n,p,kind,token,principal_key))

    def _cursor(self, p, kind, scope, position):
        payload=dict(publication=str(p),kind=kind,scope=scope,position=position)
        encoded=base64.urlsafe_b64encode(canonical(payload)).decode().rstrip('=')
        return encoded+'.'+self.store.keys.token(self.store.namespace,'observation_cursor',payload).split(':')[-1]

    def _read_cursor(self, cursor, p, kind, scope):
        if cursor is None:return None
        try:
            if not isinstance(cursor,str) or len(cursor)>4096:raise ValueError
            encoded,signature=cursor.split('.')
            payload=json.loads(base64.urlsafe_b64decode(encoded+'='*(-len(encoded)%4)))
            expected=self.store.keys.token(self.store.namespace,'observation_cursor',payload).split(':')[-1]
            if not hmac.compare_digest(signature,expected) or (payload['publication'],payload['kind'],payload['scope'])!=(str(p),kind,scope):raise ValueError
            return payload['position']
        except Exception:raise FoundationError('invalid_page_cursor') from None

    def request(self, publication_id, raw_request_id, *, access_token=None):
        _, principal=self.store._authorize_access('read_request','request',raw_request_id,access_token)
        p=self._header(publication_id)['publication_id'];key=self.store.request_key(raw_request_id)
        heads=self._heads(p,key)
        if key not in heads:raise FoundationError('request_not_available')
        summary=self.store.get_request(heads[key],raw_request_id,access_token=access_token)
        self._audit(p,'request',key,principal)
        return dict(publication_id=str(p),projection_run_id=str(heads[key]),summary=summary,evidence_scope='observed_only')

    def request_evidence(self, publication_id, raw_request_id, *, limit=100, cursor=None, access_token=None):
        _, principal=self.store._authorize_access('read_evidence','request_evidence',raw_request_id,access_token)
        p=self._header(publication_id)['publication_id'];key=self.store.request_key(raw_request_id)
        heads=self._heads(p,key)
        if key not in heads:raise FoundationError('request_not_available')
        inner=self._read_cursor(cursor,p,'request_evidence',key)
        if inner is not None and not isinstance(inner,str):raise FoundationError('invalid_page_cursor')
        result=self.store.request_evidence(heads[key],raw_request_id,limit=limit,cursor=inner,access_token=access_token)
        result['publication_id']=str(p)
        if result['next_cursor']:result['next_cursor']=self._cursor(p,'request_evidence',key,result['next_cursor'])
        self._audit(p,'request_evidence',key,principal)
        return result

    def request_by_key(self, publication_id, key, *, access_token=None):
        key=self.store.checked_request_key(key)
        _,principal=self.store._authorize_access('read_request','request',key,access_token)
        p=self._header(publication_id)['publication_id'];heads=self._heads(p,key)
        if key not in heads:raise FoundationError('request_not_available')
        row=self.c.execute("SELECT summary FROM p24_next.foundation_request_summary WHERE namespace_id=%s AND run_id=%s AND request_key=%s",
                           (self.n,heads[key],key)).fetchone()
        if not row:raise FoundationError('request_not_available')
        self.store._access(heads[key],'request',key,principal=principal,purpose='request_investigation')
        self._audit(p,'request',key,principal)
        return dict(publication_id=str(p),projection_run_id=str(heads[key]),summary=row[0],evidence_scope='observed_only')

    def request_evidence_by_key(self, publication_id, key, *, limit=100,cursor=None,access_token=None):
        key=self.store.checked_request_key(key)
        _,principal=self.store._authorize_access('read_evidence','request_evidence',key,access_token)
        p=self._header(publication_id)['publication_id'];heads=self._heads(p,key)
        if key not in heads:raise FoundationError('request_not_available')
        inner=self._read_cursor(cursor,p,'request_evidence',key)
        if inner is not None and not isinstance(inner,str):raise FoundationError('invalid_page_cursor')
        result=self.store.request_evidence_by_key(heads[key],key,limit=limit,cursor=inner,access_token=access_token)
        result['publication_id']=str(p)
        if result['next_cursor']:result['next_cursor']=self._cursor(p,'request_evidence',key,result['next_cursor'])
        self._audit(p,'request_evidence',key,principal)
        return result

    def requests(self, publication_id, *, limit=100, cursor=None, access_token=None):
        return self._page(publication_id,None,limit,cursor,access_token)

    def session_activity(self, publication_id, raw_session_id, *, limit=100, cursor=None, access_token=None):
        return self._page(publication_id,self.store.session_key(raw_session_id),limit,cursor,access_token)

    def _page(self, publication_id, session, limit, cursor, access_token):
        checked_limit(limit)
        h=self._header(publication_id);p=h['publication_id'];kind='session' if session else 'requests'
        scope=session or self.store.keys.token(self.store.namespace,'publication_requests',str(p))
        action='read_session' if session else 'read_requests'
        _, principal=self.store._authorize_access(action,kind,scope,access_token)
        last=self._read_cursor(cursor,p,kind,scope)
        if last is not None and (not isinstance(last,list) or len(last)!=2 or not all(isinstance(x,str) for x in last)):
            raise FoundationError('invalid_page_cursor')
        args=[self.n,p,self.n];where=''
        if session:where+=' AND s.summary->>\'session_key\'=%s';args.append(session)
        scope_args=args.copy();scope_where=where
        at_sql="coalesce((s.summary->>'activity_time_ns')::numeric,999999999999999999999999999999::numeric)"
        if last is not None:
            try:int(last[0])
            except ValueError:raise FoundationError('invalid_page_cursor') from None
            where+=' AND ('+at_sql+",s.request_key)>(%s::numeric,%s)";args.extend(last)
        sql=""" FROM p24_next.foundation_observation_heads(%s,%s) h JOIN p24_next.foundation_request_summary s
            ON s.namespace_id=%s AND s.request_key=h.request_key AND s.run_id=h.run_id WHERE true"""
        rows=self.c.execute("SELECT s.request_key,s.run_id,s.summary"+sql+where+' ORDER BY '+at_sql+",s.request_key LIMIT %s",(*args,limit+1)).fetchall()
        total=self.c.execute('SELECT count(*)'+sql+scope_where,scope_args).fetchone()[0]
        next_cursor=None
        if len(rows)>limit:
            tail=rows[limit-1];next_cursor=self._cursor(p,kind,scope,[tail[2]['activity_time_ns'] or '999999999999999999999999999999',tail[0]])
        self._audit(p,kind,scope,principal)
        return dict(publication_id=str(p),total_requests=total,items=[dict(projection_run_id=str(r[1]),summary=r[2]) for r in rows[:limit]],
                    next_cursor=next_cursor,evidence_scope='observed_only')

    def candidates(self, publication_id, *, limit=100, cursor=None, access_token=None, session_key=None):
        checked_limit(limit)
        _, principal=self.store._authorize_access('read_candidates','registration_candidates',publication_id,access_token)
        if session_key is not None and (not isinstance(session_key,str) or not re.fullmatch('session:'+re.escape(self.store.keys.version)+':[a-f0-9]{64}',session_key)):
            raise FoundationError('invalid_session_reference')
        h=self._header(publication_id);p=h['publication_id']
        scope=self.store.keys.token(self.store.namespace,'publication_candidates',str(p) if session_key is None else [str(p),session_key])
        last=self._read_cursor(cursor,p,'registration_candidates',scope)
        if last is not None and (not isinstance(last,list) or len(last)!=3 or not all(isinstance(x,str) for x in last)):
            raise FoundationError('invalid_page_cursor')
        rows=self.c.execute("""SELECT jsonb_build_object(
            'request_key',s.summary->'request_key','identity_state',s.summary->'identity_state',
            'session_key',s.summary->'session_key','activity_time_ns',s.summary->'activity_time_ns',
            'ip_keys',s.summary->'ip_keys','client_contexts',s.summary->'client_contexts','classification',s.summary->'classification')
            FROM p24_next.foundation_observation_heads(%s,%s) h
            JOIN p24_next.foundation_request_summary s ON s.namespace_id=%s AND s.request_key=h.request_key AND s.run_id=h.run_id LIMIT %s""",(self.n,p,self.n,MAX_HEADS+1)).fetchall()
        if len(rows)>MAX_HEADS:raise FoundationError('publication_request_limit')
        candidates,truncated=registration_candidates([r[0] for r in rows],horizon_seconds=h['input_manifest']['policy']['association_horizon_seconds'])
        if truncated or len(candidates)>MAX_HEADS:raise FoundationError('candidate_result_limit_requires_narrower_scope')
        alternatives={}
        for c in candidates:alternatives.setdefault(c['registration_request_key'],set()).add(c['session_key'])
        if session_key is not None:candidates=[c for c in candidates if c['session_key']==session_key]
        def order(c):return (c['registration_request_key'],c['session_key'],c['support_request_key'])
        candidates.sort(key=order);total=len(candidates)
        if last is not None:candidates=[c for c in candidates if order(c)>tuple(last)]
        page=candidates[:limit];next_cursor=self._cursor(p,'registration_candidates',scope,list(order(page[-1]))) if len(candidates)>limit else None
        self._audit(p,'registration_candidates',scope,principal)
        return dict(publication_id=str(p),total_candidates=total,items=page,next_cursor=next_cursor,
                    association_authority='context_candidate_only',session_key=session_key,
                    candidate_session_counts={c['registration_request_key']:len(alternatives[c['registration_request_key']]) for c in page})


def microsecond_cutoff_from_ns(value):
    from .store import floor_ns
    return floor_ns(int(value))
