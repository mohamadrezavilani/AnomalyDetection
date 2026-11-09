"""Atomic workflow projections over sealed PostgreSQL evidence runs.

Inputs reference existing immutable source facts from a trusted extractor and
verifier. This internal adapter does not authenticate a provider, accept raw
payloads, or expose a write route to the review UI.
"""
from __future__ import annotations

import hashlib
import re
import uuid
from dataclasses import asdict, dataclass
from decimal import Decimal

from .errors import FoundationError
from .privacy import canonical
from .store import execute_many, jsonb, stable_id
from .time import EPOCH
from .workflows import (MAX_ROWS, DeliveryObservation, ExternalEvent, SelectedEvidence,
                        WorkflowState, reconcile_workflows, LABEL)

WORKFLOW_STORE_VERSION = "p24-workflow-store.2s.1"


@dataclass(frozen=True)
class EventClaim:
    source_version_id: str
    identity_fact_id: str
    content_fact_id: str
    issuer: str
    topic: str
    identifier_domain: str
    schema_version: str
    identity_state: str = "unresolved"
    authenticity_state: str = "unverified"


@dataclass(frozen=True)
class DeliveryClaim:
    source_version_id: str
    acknowledgement_fact_id: str
    attempt_fact_id: str | None = None
    issuer: str | None = None
    attempt_domain: str | None = None
    attempt_verified: bool = False


@dataclass(frozen=True)
class StateClaim:
    source_version_id: str
    workflow_fact_id: str
    state_fact_id: str
    contract_version: str
    link_state: str = "candidate"
    authenticity_state: str = "unverified"
    subject_domain: str | None = None
    subject_fact_id: str | None = None
    sequence_fact_id: str | None = None
    phase: str = "unknown"
    workflow_domain: str = "workflow"


def _uuid(value):
    try:
        return uuid.UUID(str(value))
    except (ValueError, TypeError, AttributeError):
        raise FoundationError("invalid_workflow_reference") from None


def _ns(value):
    delta = value - EPOCH
    return (delta.days * 86400 + delta.seconds) * 1_000_000_000 + delta.microseconds * 1000


def _ordered(values):
    return sorted(set(values), key=lambda row: canonical(asdict(row)))


class WorkflowStore:
    def __init__(self, store):
        self.store, self.c, self.n = store, store.c, store.namespace_id

    def _result(self, run_id):
        run = _uuid(run_id)
        row = self.c.execute("SELECT result,result_sha256,input_sha256,base_run_id FROM p24_next.foundation_workflow_run WHERE namespace_id=%s AND run_id=%s", (self.n, run)).fetchone()
        if not row:
            raise FoundationError("workflow_projection_not_available")
        if hashlib.sha256(canonical(row[0])).hexdigest() != row[1]:
            raise FoundationError("workflow_result_digest_mismatch")
        return dict(run_id=str(run), base_run_id=str(row[3]), result_sha256=row[1],
                    input_sha256=row[2], result=row[0])

    def project(self, base_run_id, *, events=(), deliveries=(), states=(), contracts=()):
        """Build a new immutable run; source/fact membership is checked in SQL.

        Verified flags are trusted verifier inputs, not signature verification.
        Production issuers must supply a separately approved verification adapter.
        """
        base = _uuid(base_run_id)
        events, deliveries, states = map(_ordered, (events, deliveries, states))
        contracts = tuple(sorted(contracts, key=lambda row: row.version))
        if sum(map(len, (events, deliveries, states))) > MAX_ROWS:
            raise FoundationError("workflow_projection_limit")
        for claim in events:
            if not all(isinstance(v,str) and LABEL.fullmatch(v) for v in
                       (claim.issuer,claim.topic,claim.identifier_domain,claim.schema_version)):
                raise FoundationError('invalid_workflow_claim_label')
        for claim in states:
            if not all(isinstance(v,str) and LABEL.fullmatch(v) for v in
                       (claim.contract_version,claim.phase,claim.workflow_domain)):
                raise FoundationError('invalid_workflow_claim_label')
        for claim in deliveries:
            if not isinstance(claim.attempt_verified,bool):
                raise FoundationError('invalid_workflow_verifier_decision')
        # Validate the complete contract set before taking a database lock.
        reconcile_workflows((), namespace=self.store.namespace, event_cutoff_ns=0, knowledge_at_ns=0, contracts=contracts)
        with self.c.transaction():
            self.store._lock()
            self.store._sealed(base)
            if self.c.execute("SELECT 1 FROM p24_next.foundation_projection_request_scope WHERE namespace_id=%s AND run_id=%s LIMIT 1", (self.n, base)).fetchone():
                raise FoundationError("workflow_requires_full_source_run")
            b = self.c.execute("SELECT mode,event_cutoff,knowledge_snapshot_at,taxonomy_id,privacy_version,input_manifest_sha256 FROM p24_next.projection_run WHERE namespace_id=%s AND run_id=%s", (self.n, base)).fetchone()
            rows = self.c.execute("""SELECT e.event_version_id,e.event_key,e.source_time_epoch_ns,e.received_at,e.source_role,e.request_key,e.source_event_time
                FROM p24_next.projection_event p JOIN p24_next.event_version e USING(namespace_id,event_version_id)
                WHERE p.namespace_id=%s AND p.run_id=%s AND p.selection_state='selected'
                ORDER BY e.event_version_id LIMIT %s""", (self.n, base, MAX_ROWS+1)).fetchall()
            if len(rows)>MAX_ROWS:
                raise FoundationError("workflow_projection_limit")
            selected = {str(row[0]): row for row in rows}
            cutoff, known = _ns(b[1]), _ns(b[2])
            evidence = [SelectedEvidence(str(r[0]),self.store.namespace,r[1],int(r[2]) if r[2] is not None else None,_ns(r[3])) for r in rows]
            requested = set()
            for claim in events:
                requested.update((_uuid(claim.identity_fact_id),_uuid(claim.content_fact_id)))
            for claim in deliveries:
                requested.add(_uuid(claim.acknowledgement_fact_id))
                if claim.attempt_fact_id:requested.add(_uuid(claim.attempt_fact_id))
            for claim in states:
                requested.update((_uuid(claim.workflow_fact_id),_uuid(claim.state_fact_id)))
                for value in (claim.subject_fact_id,claim.sequence_fact_id):
                    if value:requested.add(_uuid(value))
            facts = self.c.execute("""SELECT fact_id,event_version_id,fact_key,public_value,equality_token,token_key_version,completeness
                FROM p24_next.source_event_fact WHERE namespace_id=%s AND fact_id=ANY(%s) ORDER BY fact_id""", (self.n, sorted(requested))).fetchall() if requested else []
            facts = {str(row[0]): row for row in facts}
            if len(facts)!=len(requested):
                raise FoundationError("workflow_fact_not_available")
            def fact(version, reference, kind, *, token=False):
                version, reference = str(_uuid(version)), str(_uuid(reference))
                f = facts[reference]
                if (version not in selected or str(f[1])!=version or f[2]!=kind or f[6]!='complete'):
                    raise FoundationError("workflow_fact_source_or_kind_mismatch")
                if token:
                    if not isinstance(f[4],str) or not re.fullmatch(r"[A-Za-z0-9_]+:"+re.escape(self.store.keys.version)+r":[a-f0-9]{64}",f[4]) or f[5]!=self.store.keys.version:
                        raise FoundationError("workflow_fact_token_mismatch")
                    return f[4]
                return f[3]
            # Bind each policy version permanently; revisions need new names.
            for contract in contracts:
                definition=asdict(contract);digest=hashlib.sha256(canonical(definition)).hexdigest()
                self.c.execute("INSERT INTO p24_next.foundation_workflow_contract(namespace_id,contract_version,content_sha256,definition) VALUES(%s,%s,%s,%s) ON CONFLICT DO NOTHING",(self.n,contract.version,digest,jsonb(definition)))
                existing=self.c.execute("SELECT content_sha256,registered_at FROM p24_next.foundation_workflow_contract WHERE namespace_id=%s AND contract_version=%s",(self.n,contract.version)).fetchone()
                if existing[0]!=digest:raise FoundationError("workflow_contract_version_conflict")
                if b[0]!='design_fixture' and _ns(existing[1])>known:raise FoundationError("workflow_contract_not_known_at_snapshot")
            source_ids=[str(r[0]) for r in self.c.execute("SELECT snapshot_id FROM p24_next.projection_source WHERE namespace_id=%s AND run_id=%s ORDER BY snapshot_id",(self.n,base)).fetchall()]
            manifest=dict(version=WORKFLOW_STORE_VERSION,base_run_id=str(base),base_manifest_sha256=b[5],source_ids=source_ids,
                events=[asdict(x) for x in events],deliveries=[asdict(x) for x in deliveries],states=[asdict(x) for x in states],
                contracts=[asdict(x) for x in contracts],source_facts_sha256=hashlib.sha256(canonical(list(facts.values()))).hexdigest(),
                event_cutoff_ns=str(cutoff),knowledge_at_ns=str(known),verification_scope='trusted_adapter_decisions; producer_authentication_not_implemented')
            input_digest=hashlib.sha256(canonical(manifest)).hexdigest()
            run=stable_id(self.store.namespace,'workflow_run',input_digest)
            if self.c.execute("SELECT 1 FROM p24_next.foundation_workflow_run WHERE namespace_id=%s AND run_id=%s",(self.n,run)).fetchone():
                return self._result(run)
            self.c.execute("""INSERT INTO p24_next.projection_run(namespace_id,run_id,mode,event_cutoff,knowledge_snapshot_at,taxonomy_id,resolver_version,privacy_version,input_manifest_sha256)
                VALUES(%s,%s,%s,%s,%s,%s,%s,%s,%s)""",(self.n,run,b[0],b[1],b[2],b[3],WORKFLOW_STORE_VERSION,b[4],input_digest))
            self.c.execute("INSERT INTO p24_next.projection_source SELECT namespace_id,%s,snapshot_id FROM p24_next.projection_source WHERE namespace_id=%s AND run_id=%s",(run,self.n,base))
            self.c.execute("INSERT INTO p24_next.projection_event SELECT namespace_id,%s,event_key,event_version_id,selection_state,selection_reason FROM p24_next.projection_event WHERE namespace_id=%s AND run_id=%s",(run,self.n,base))
            projected_facts=set()
            def use(version, reference, kind):
                projected_facts.add((self.n,run,_uuid(version),_uuid(reference),kind))
            def eligible(version):
                r=selected.get(str(_uuid(version)))
                if r is None:raise FoundationError("workflow_source_not_selected")
                return r[2] is not None and int(r[2])<cutoff and _ns(r[3])<=known
            converted_events=[];event_groups={}
            for claim in events:
                token=fact(claim.source_version_id,claim.identity_fact_id,'external_event_identity',token=True)
                digest=fact(claim.source_version_id,claim.content_fact_id,'logical_event_content_digest')
                if not isinstance(digest,str) or not re.fullmatch(r'[a-f0-9]{64}',digest):raise FoundationError('invalid_workflow_content_digest_fact')
                if claim.identity_state not in {'verified','unresolved','conflicting','rejected'} or claim.authenticity_state not in {'verified','unverified','rejected','unknown'}:raise FoundationError('invalid_workflow_verifier_decision')
                if not eligible(claim.source_version_id):continue
                use(claim.source_version_id,claim.identity_fact_id,'external_event_identity')
                use(claim.source_version_id,claim.content_fact_id,'logical_event_content_digest')
                verified=claim.identity_state=='verified' and claim.authenticity_state=='verified'
                identity=(claim.issuer,claim.topic,claim.identifier_domain,self.store.keys.version,token)
                key=stable_id(self.store.namespace,'external_event',identity if verified else ('unresolved',claim.source_version_id,claim.identity_fact_id))
                event_groups.setdefault(key,[]).append((claim,token,digest,verified))
            # All fact memberships must exist before assertions cite them.
            for claim in deliveries:
                fact(claim.source_version_id,claim.acknowledgement_fact_id,'delivery_acknowledgement')
                if claim.attempt_fact_id:fact(claim.source_version_id,claim.attempt_fact_id,'delivery_attempt_identity',token=True)
                if eligible(claim.source_version_id):
                    use(claim.source_version_id,claim.acknowledgement_fact_id,'delivery_acknowledgement')
                    if claim.attempt_fact_id:use(claim.source_version_id,claim.attempt_fact_id,'delivery_attempt_identity')
            policy={c.version:c for c in contracts};converted_states=[];state_specs=[]
            for claim in states:
                token=fact(claim.source_version_id,claim.workflow_fact_id,'workflow_identifier',token=True)
                state_key=fact(claim.source_version_id,claim.state_fact_id,'workflow_state')
                if not isinstance(state_key,str) or not re.fullmatch(r'[A-Za-z0-9_.:-]{1,160}',state_key):raise FoundationError('invalid_workflow_state_fact')
                subject=fact(claim.source_version_id,claim.subject_fact_id,'workflow_subject',token=True) if claim.subject_fact_id else None
                if bool(claim.subject_domain)!=bool(subject):raise FoundationError('workflow_subject_binding_incomplete')
                sequence=fact(claim.source_version_id,claim.sequence_fact_id,'issuer_sequence') if claim.sequence_fact_id else None
                if sequence is not None:
                    if isinstance(sequence,bool) or not isinstance(sequence,(int,Decimal)) or int(sequence)!=sequence or not 0<=sequence<2**63:raise FoundationError('invalid_workflow_sequence_fact')
                    sequence=int(sequence)
                if claim.link_state not in {'accepted','candidate','ambiguous','conflicting','rejected'} or claim.authenticity_state not in {'verified','unverified','rejected','unknown'}:raise FoundationError('invalid_workflow_verifier_decision')
                if not eligible(claim.source_version_id):continue
                for reference,kind in ((claim.workflow_fact_id,'workflow_identifier'),(claim.state_fact_id,'workflow_state'),(claim.subject_fact_id,'workflow_subject'),(claim.sequence_fact_id,'issuer_sequence')):
                    if reference:use(claim.source_version_id,reference,kind)
                assertion=stable_id(run,'workflow_link',canonical(asdict(claim)).hex())
                contract=policy.get(claim.contract_version)
                normalized=WorkflowState(str(_uuid(claim.source_version_id)),token,claim.contract_version,state_key,
                    selected[str(_uuid(claim.source_version_id))][4],claim.link_state,claim.authenticity_state,'complete',
                    claim.subject_domain,subject,sequence,contract.sequence_domain if sequence is not None and contract else None,
                    str(assertion),str(_uuid(claim.state_fact_id)))
                converted_states.append(normalized);state_specs.append((claim,normalized,assertion))
            execute_many(self.c,"INSERT INTO p24_next.event_fact_projection VALUES(%s,%s,%s,%s,%s)",sorted(projected_facts,key=str))
            event_support={}
            for key,group in sorted(event_groups.items(),key=lambda item:str(item[0])):
                first,root_token,_,verified=group[0];assertion=stable_id(run,'external_identity',str(key))
                self.c.execute("INSERT INTO p24_next.external_event_identity(namespace_id,external_event_key) VALUES(%s,%s) ON CONFLICT DO NOTHING",(self.n,key))
                self.c.execute("""INSERT INTO p24_next.external_event_identity_assertion(namespace_id,run_id,assertion_id,external_event_key,issuer_key,topic_key,identity_state,
                    identifier_domain,equality_token,token_key_version,source_event_version_id,evidence_fact_id,contract_version)
                    VALUES(%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)""",(self.n,run,assertion,key,first.issuer,first.topic,'verified' if verified else 'unresolved',
                    first.identifier_domain if verified else None,root_token if verified else None,self.store.keys.version if verified else None,
                    _uuid(first.source_version_id),_uuid(first.identity_fact_id) if verified else None,WORKFLOW_STORE_VERSION))
                for claim,token,digest,is_verified in group:
                    version=_uuid(claim.source_version_id);r=selected[str(version)]
                    revision=stable_id(key,digest,claim.schema_version,str(version))
                    self.c.execute("""INSERT INTO p24_next.external_event_revision(namespace_id,external_revision_id,external_event_key,content_sha256,source_event_version_id,
                        first_received_at,schema_version,authenticity_state,completeness) VALUES(%s,%s,%s,%s,%s,%s,%s,%s,'complete') ON CONFLICT DO NOTHING""",
                        (self.n,revision,key,digest,version,r[3],claim.schema_version,'unknown'))
                    self.c.execute("""INSERT INTO p24_next.external_event_support(namespace_id,run_id,external_revision_id,external_event_key,event_version_id,identity_domain,
                        identity_assertion_id,identity_fact_id,identity_fact_use_kind,support_state,support_basis) VALUES(%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s) ON CONFLICT DO NOTHING""",
                        (self.n,run,revision,key,version,claim.identifier_domain if is_verified else None,assertion if is_verified else None,
                         _uuid(claim.identity_fact_id),'external_event_identity','verified' if is_verified else 'unresolved','verified_identifier' if is_verified else 'unknown'))
                    event_support.setdefault(str(version),[]).append((revision,is_verified))
                    converted_events.append(ExternalEvent(str(version),claim.issuer,claim.topic,claim.identifier_domain,token,self.store.keys.version,digest,
                        claim.schema_version,'verified' if is_verified else 'unresolved',claim.authenticity_state,str(assertion),str(_uuid(claim.identity_fact_id))))
            converted_deliveries=[]
            for claim in deliveries:
                if not eligible(claim.source_version_id):continue
                version=_uuid(claim.source_version_id);r=selected[str(version)]
                acknowledgement=fact(claim.source_version_id,claim.acknowledgement_fact_id,'delivery_acknowledgement')
                if acknowledgement not in {'http_accepted','http_rejected','not_observed','unknown'}:raise FoundationError('invalid_delivery_acknowledgement')
                attempt=fact(claim.source_version_id,claim.attempt_fact_id,'delivery_attempt_identity',token=True) if claim.attempt_fact_id else None
                converted_deliveries.append(DeliveryObservation(str(version),acknowledgement,attempt,r[5],claim.attempt_verified,claim.issuer,claim.attempt_domain))
            # Kernel normalizes contradictory claims on the same source into one
            # observation. Persist its separate transport/attempt units exactly.
            for claim,normalized,assertion in state_specs:
                version=_uuid(claim.source_version_id);r=selected[str(version)]
                accepted=claim.link_state=='accepted'
                if accepted:
                    self.c.execute("INSERT INTO p24_next.business_workflow VALUES(%s,%s,%s,%s,%s) ON CONFLICT DO NOTHING",(self.n,normalized.workflow_token,claim.workflow_domain,self.store.keys.version,WORKFLOW_STORE_VERSION))
                    saved=self.c.execute("SELECT equality_domain,token_key_version FROM p24_next.business_workflow WHERE namespace_id=%s AND workflow_key=%s",(self.n,normalized.workflow_token)).fetchone()
                    if saved!=(claim.workflow_domain,self.store.keys.version):raise FoundationError('workflow_identity_domain_conflict')
                self.c.execute("""INSERT INTO p24_next.workflow_identifier_assertion(namespace_id,run_id,assertion_id,source_event_version_id,workflow_key,phase_key,
                    identifier_role,identifier_kind,equality_domain,equality_token,token_key_version,event_fact_id,event_fact_use_kind,assertion_state,contract_version)
                    VALUES(%s,%s,%s,%s,%s,%s,'unknown',%s,%s,%s,%s,%s,'workflow_identifier',%s,%s)""",
                    (self.n,run,assertion,version,normalized.workflow_token if accepted else None,claim.phase,claim.workflow_domain,claim.workflow_domain,normalized.workflow_token,
                     self.store.keys.version,_uuid(claim.workflow_fact_id),claim.link_state,claim.contract_version))
                observation=stable_id(run,'workflow_state',canonical(asdict(claim)).hex())
                contract=policy.get(claim.contract_version)
                meaning=dict(contract.states).get(normalized.state_key,'unknown') if contract and contract.review_state=='reviewed' and normalized.authenticity_state=='verified' and accepted and normalized.source_role in contract.allowed_roles else 'unknown'
                self.c.execute("""INSERT INTO p24_next.workflow_state_observation(namespace_id,run_id,observation_id,workflow_key,workflow_assertion_id,event_version_id,
                    state_fact_id,state_fact_use_kind,phase_key,state_scope,subject_domain,subject_token,state_key,state_contract_version,outcome_state,
                    source_event_time,received_at,source_role,completeness) VALUES(%s,%s,%s,%s,%s,%s,%s,'workflow_state',%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,'complete')""",
                    (self.n,run,observation,normalized.workflow_token if accepted else None,assertion if accepted else None,version,_uuid(claim.state_fact_id),claim.phase,
                     'subject' if normalized.subject_token else 'workflow',normalized.subject_domain,normalized.subject_token,normalized.state_key,claim.contract_version,meaning,r[6],r[3],r[4]))
            result=reconcile_workflows(evidence,converted_events,converted_deliveries,converted_states,namespace=self.store.namespace,
                                       event_cutoff_ns=cutoff,knowledge_at_ns=known,contracts=contracts)
            for delivery in result['delivery_observations']:
                version=_uuid(delivery['source_version_id']);r=selected[str(version)];supports=event_support.get(str(version),[])
                attempt_state=delivery['attempt_identity_state']
                linked=supports[0][0] if attempt_state=='verified_attempt' and len(supports)==1 and supports[0][1] else None
                ack=delivery['acknowledgement'] if delivery['acknowledgement']!='conflicting' else 'unknown'
                self.c.execute("""INSERT INTO p24_next.delivery_attempt(namespace_id,run_id,delivery_attempt_id,event_version_id,external_revision_id,transport_request_key,
                    received_at,acknowledgement_state,identity_state,coverage_state) VALUES(%s,%s,%s,%s,%s,%s,%s,%s,%s,'complete')""",
                    (self.n,run,stable_id(run,'delivery',str(version)),version,linked,r[5],r[3],ack,attempt_state))
            for publication in result['state_publications']:
                members=[]
                for claim,normalized,_ in state_specs:
                    if ((normalized.workflow_token,normalized.contract_version,normalized.subject_domain,normalized.subject_token)==
                            (publication['workflow_token'],publication['contract_version'],publication['subject_domain'],publication['subject_token'])
                            and normalized.link_state=='accepted' and normalized.authenticity_state=='verified'
                            and normalized.source_role in policy[normalized.contract_version].allowed_roles
                            and normalized.state_key in dict(policy[normalized.contract_version].states)):
                        members.append(stable_id(run,'workflow_state',canonical(asdict(claim)).hex()))
                if len(members)!=publication['observation_count']:raise FoundationError('workflow_state_manifest_mismatch')
                state_id=stable_id(run,'state_publication',publication['workflow_token'],publication['contract_version'],publication['subject_domain'],publication['subject_token'])
                self.c.execute("""INSERT INTO p24_next.workflow_state_publication(namespace_id,run_id,state_publication_id,workflow_key,state_contract_version,state_scope,
                    subject_domain,subject_token,published_state,coverage_state,observation_count,conflict_count,event_cutoff,knowledge_snapshot_at,input_manifest_sha256,built_at)
                    VALUES(%s,%s,%s,%s,%s,%s,%s,%s,%s,'unknown',%s,0,%s,%s,%s,clock_timestamp())""",
                    (self.n,run,state_id,publication['workflow_token'],publication['contract_version'],publication['state_scope'],publication['subject_domain'],publication['subject_token'],publication['published_state'],len(members),b[1],b[2],input_digest))
                execute_many(self.c,"INSERT INTO p24_next.workflow_state_publication_input VALUES(%s,%s,%s,%s)",[(self.n,run,state_id,obs) for obs in members])
            self.c.execute("UPDATE p24_next.projection_run SET state='sealed' WHERE namespace_id=%s AND run_id=%s",(self.n,run))
            self.c.execute("INSERT INTO p24_next.foundation_workflow_run(namespace_id,run_id,base_run_id,input_manifest,input_sha256,result,result_sha256) VALUES(%s,%s,%s,%s,%s,%s,%s)",
                (self.n,run,base,jsonb(manifest),input_digest,jsonb(result),hashlib.sha256(canonical(result)).hexdigest()))
        return self._result(run)

    def binding(self, run_id, *, sources, event_cutoff_ns, knowledge_at_ns):
        result=self._result(run_id)
        actual={str(row[0]) for row in self.c.execute("SELECT snapshot_id FROM p24_next.projection_source WHERE namespace_id=%s AND run_id=%s",(self.n,_uuid(run_id))).fetchall()}
        r=result['result']
        if actual!={str(x) for x in sources} or int(r['event_cutoff_ns'])!=event_cutoff_ns or int(r['knowledge_at_ns'])!=knowledge_at_ns:
            raise FoundationError('workflow_publication_input_mismatch')
        return dict(run_id=result['run_id'],result_sha256=result['result_sha256'])

    def _pinned(self, publication_id, access_token):
        # Authorize before looking up publication existence or workflow metadata.
        _,principal=self.store._authorize_access('read_workflows','publication',str(publication_id),access_token)
        from .publication import ObservationPublisher
        publisher=ObservationPublisher(self.store);header=publisher._header(publication_id)
        row=self.c.execute("SELECT run_id FROM p24_next.foundation_observation_workflow WHERE namespace_id=%s AND publication_id=%s",(self.n,header['publication_id'])).fetchone()
        publisher._audit(header['publication_id'],'publication',self.store.keys.token(self.store.namespace,'workflow_resource',str(header['publication_id'])),principal)
        return publisher,header,row[0] if row else None

    def for_publication(self, publication_id, *, limit=25, cursor=None, access_token=None):
        from .publication import checked_limit
        checked_limit(limit)
        publisher,header,run=self._pinned(publication_id,access_token)
        p=header['publication_id']
        if run is None:
            if cursor is not None:raise FoundationError('invalid_page_cursor')
            return dict(publication_id=str(p),status='not_provided',result=None,next_cursor=None)
        saved=self._result(run)
        last=publisher._read_cursor(cursor,p,'workflow_states:'+WORKFLOW_STORE_VERSION,str(run))
        if last is not None:last=str(_uuid(last))
        rows=self.c.execute("""SELECT state_publication_id,workflow_key,state_contract_version,state_scope,subject_domain,subject_token,
            published_state,observation_count FROM p24_next.workflow_state_publication
            WHERE namespace_id=%s AND run_id=%s AND (%s::uuid IS NULL OR state_publication_id>%s::uuid)
            ORDER BY state_publication_id LIMIT %s""",(self.n,run,last,last,limit+1)).fetchall()
        items=[dict(state_publication_id=str(r[0]),workflow_token=r[1],contract_version=r[2],state_scope=r[3],
                    subject_domain=r[4],subject_token=r[5],published_state=r[6],observation_count=r[7]) for r in rows[:limit]]
        following=publisher._cursor(p,'workflow_states:'+WORKFLOW_STORE_VERSION,str(run),str(rows[limit-1][0])) if len(rows)>limit else None
        fields=('version','event_cutoff_ns','knowledge_at_ns','logical_event_count','delivery_observation_count',
                'verified_delivery_attempt_count','distinct_transport_request_count','unverified_event_observations',
                'unresolved_state_observations','excluded_evidence_counts','excluded_observation_counts','projection_sha256')
        summary={k:saved['result'].get(k) for k in fields}
        summary['state_publication_count']=len(saved['result']['state_publications'])
        summary['state_publications']=items
        return dict(publication_id=str(p),status='available',run_id=str(run),result_sha256=saved['result_sha256'],
                    result=summary,next_cursor=following,items_scope='one page; aggregate counts cover the complete pinned workflow run')

    def state_evidence(self, publication_id, state_publication_id, *, limit=25, cursor=None, access_token=None):
        from .publication import checked_limit
        checked_limit(limit)
        publisher,header,run=self._pinned(publication_id,access_token)
        state_id=_uuid(state_publication_id);p=header['publication_id']
        if run is None:raise FoundationError('workflow_state_not_available')
        state=self.c.execute("""SELECT workflow_key,state_contract_version,state_scope,subject_domain,subject_token,published_state,observation_count
            FROM p24_next.workflow_state_publication WHERE namespace_id=%s AND run_id=%s AND state_publication_id=%s""",(self.n,run,state_id)).fetchone()
        if state is None:raise FoundationError('workflow_state_not_available')
        last=publisher._read_cursor(cursor,p,'workflow_state_evidence:'+WORKFLOW_STORE_VERSION,str(state_id))
        if last is not None:last=str(_uuid(last))
        rows=self.c.execute("""SELECT o.observation_id,o.event_version_id,o.state_fact_id,o.state_key,o.outcome_state,o.source_role,
            e.source_time_epoch_ns,e.request_key,f.field_path FROM p24_next.workflow_state_publication_input i
            JOIN p24_next.workflow_state_observation o USING(namespace_id,observation_id)
            JOIN p24_next.event_version e ON e.namespace_id=o.namespace_id AND e.event_version_id=o.event_version_id
            JOIN p24_next.source_event_fact f ON f.namespace_id=o.namespace_id AND f.fact_id=o.state_fact_id
            WHERE i.namespace_id=%s AND i.run_id=%s AND i.state_publication_id=%s AND (%s::uuid IS NULL OR o.observation_id>%s::uuid)
            ORDER BY o.observation_id LIMIT %s""",(self.n,run,state_id,last,last,limit+1)).fetchall()
        items=[dict(observation_id=str(r[0]),source_version_id=str(r[1]),state_fact_id=str(r[2]),state_key=r[3],outcome=r[4],
                    source_role=r[5],source_time_ns=str(r[6]),request_key=r[7],field_path=r[8]) for r in rows[:limit]]
        following=publisher._cursor(p,'workflow_state_evidence:'+WORKFLOW_STORE_VERSION,str(state_id),str(rows[limit-1][0])) if len(rows)>limit else None
        return dict(publication_id=str(p),state_publication_id=str(state_id),state=dict(workflow_token=state[0],contract_version=state[1],
                    state_scope=state[2],subject_domain=state[3],subject_token=state[4],published_state=state[5]),
                    total_observations=state[6],items=items,next_cursor=following)
