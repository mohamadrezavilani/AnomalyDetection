"""Evidence-backed multi-pattern links and explicit, revision-bound priority.

Only shared request evidence is linked automatically here. Dependency/workflow
causality remains unlinked until a reviewed contract can prove it. Priority is
an operator decision over named impact dimensions, never a transformed detector
score or feedback verdict.
"""
from __future__ import annotations

import uuid

from .errors import FoundationError
from .incidents import IncidentRegistry, digest, ref
from .publication import checked_limit
from .store import jsonb, stable_id

VERSION = "p24-investigation-priority.2u.1"
HISTORY_CURSOR_VERSION = "p24-priority-history.1"
PRIORITIES = {"unrated", "low", "medium", "high", "critical"}
IMPACT = {"unknown", "single_request", "multiple_requests", "multiple_sessions", "service_wide"}
URGENCY = {"unknown", "routine", "time_sensitive", "active"}
CONFIDENCE = {"low", "medium", "high"}
REASONS = {"operator_assessment", "service_impact", "security_review", "correction"}


def _investigation_id(namespace, publication_id, incident_revisions):
    """Identify one immutable proof group by publication and exact revisions."""
    pins=sorted((dict(incident_id=str(item['incident_id']),revision_id=str(item['revision_id']))
                 for item in incident_revisions),key=lambda item:item['incident_id'])
    return stable_id(namespace,"shared_request_investigation",
                     dict(publication_id=str(publication_id),incidents=pins))


def _proof_revision_state(incident_id, incident_revision_id, linked_incident_id,
                          linked_revision_id, current_heads):
    """Classify an immutable pair as current only while both pins are heads."""
    current=(current_heads.get(str(incident_id))==str(incident_revision_id)
             and current_heads.get(str(linked_incident_id))==str(linked_revision_id))
    return "current" if current else "historical"


class InvestigationRegistry:
    def __init__(self, store):
        self.store, self.c, self.n = store, store.c, store.namespace_id
        self.incidents = IncidentRegistry(store)

    def link_shared_requests(self, publication_id, incident_a, incident_b, *, access_token=None):
        """Create a symmetric immutable link only for exact shared RequestIDs.

        The pair is pinned to incident revisions from one sealed publication.
        Same IP, Session, time proximity, service name, failure code, or score
        alone does not qualify as proof.
        """
        publication=ref(publication_id)
        a, b = ref(incident_a), ref(incident_b)
        if a == b:
            raise FoundationError("investigation_link_requires_distinct_incidents")
        pa = self.incidents.read(publication, a, access_token=access_token)
        pb = self.incidents.read(publication, b, access_token=access_token)
        left, right = pa["result"], pb["result"]
        shared = sorted({r["request_key"] for r in left["requests"]} & {r["request_key"] for r in right["requests"]})
        if not shared:
            raise FoundationError("investigation_shared_request_proof_missing")
        principal_a=self.incidents._authorize("review_incidents", a, access_token)
        principal_b=self.incidents._authorize("review_incidents", b, access_token)
        incident_revisions=[dict(incident_id=str(a), revision_id=pa["revision_id"]),
                             dict(incident_id=str(b), revision_id=pb["revision_id"])]
        incident_revisions.sort(key=lambda x:x["incident_id"])
        manifest = dict(version=VERSION, basis="shared_request", publication_id=str(publication),
                        incidents=incident_revisions, shared_request_keys=shared)
        proof_hash = digest(manifest)
        title = "بررسیِ شواهدِ درخواستِ مشترک"
        with self.c.transaction():
            self.store._lock()
            # Reuse an exact pre-existing proof (including links created by the
            # earlier incident-pair ID scheme). A changed publication or
            # incident revision gets a new immutable investigation identity.
            existing=self.c.execute("""SELECT DISTINCT investigation_id
                FROM p24_next.foundation_investigation_link_proof
                WHERE namespace_id=%s AND publication_id=%s AND (
                    (incident_id=%s AND incident_revision_id=%s AND linked_incident_id=%s AND linked_revision_id=%s)
                    OR (incident_id=%s AND incident_revision_id=%s AND linked_incident_id=%s AND linked_revision_id=%s))
                ORDER BY investigation_id LIMIT 1""",
                (self.n,publication,incident_revisions[0]['incident_id'],incident_revisions[0]['revision_id'],
                 incident_revisions[1]['incident_id'],incident_revisions[1]['revision_id'],
                 incident_revisions[1]['incident_id'],incident_revisions[1]['revision_id'],
                 incident_revisions[0]['incident_id'],incident_revisions[0]['revision_id'])).fetchone()
            if existing:
                investigation=existing[0]
            else:
                investigation=_investigation_id(self.store.namespace,publication,incident_revisions)
            self.c.execute("INSERT INTO p24_next.investigation(namespace_id,investigation_id,title_fa,status) VALUES(%s,%s,%s,'open') ON CONFLICT DO NOTHING",
                           (self.n, investigation, title))
            for current, other, current_rev, other_rev in (
                (a, b, pa["revision_id"], pb["revision_id"]),
                (b, a, pb["revision_id"], pa["revision_id"]),
            ):
                self.c.execute("INSERT INTO p24_next.investigation_link(namespace_id,investigation_id,incident_id,basis_key,proof_manifest_sha256) VALUES(%s,%s,%s,'shared_request',%s) ON CONFLICT DO NOTHING",
                               (self.n, investigation, current, proof_hash))
                prior = self.c.execute("SELECT proof_sha256 FROM p24_next.foundation_investigation_link_proof WHERE namespace_id=%s AND investigation_id=%s AND incident_id=%s",
                                       (self.n, investigation, current)).fetchone()
                if prior and prior[0] != proof_hash:
                    raise FoundationError("investigation_link_proof_conflict")
                if not prior:
                    self.c.execute("""INSERT INTO p24_next.foundation_investigation_link_proof
                        (namespace_id,investigation_id,incident_id,publication_id,incident_revision_id,linked_incident_id,linked_revision_id,shared_request_keys,proof_sha256)
                        VALUES(%s,%s,%s,%s,%s,%s,%s,%s,%s)""",
                    (self.n, investigation, current, publication, ref(current_rev), other, ref(other_rev), jsonb(shared), proof_hash))
            self.incidents.pub._audit(publication,'publication',
                self.store.keys.token(self.store.namespace,'investigation_link',[str(investigation),str(a),str(b)]),principal_a)
        return dict(version=VERSION, investigation_id=str(investigation), basis="shared_request",
                    shared_request_count=len(shared), proof_sha256=proof_hash, reused=bool(existing))

    def read(self, investigation_id, *, access_token=None):
        investigation = ref(investigation_id)
        # Authorize before revealing whether the requested investigation exists.
        self.incidents._authorize("read_incidents", investigation, access_token)
        row = self.c.execute("SELECT title_fa,status FROM p24_next.investigation WHERE namespace_id=%s AND investigation_id=%s",
                             (self.n, investigation)).fetchone()
        if row is None:
            raise FoundationError("investigation_not_available")
        links = self.c.execute("""SELECT p.incident_id,p.linked_incident_id,p.publication_id,
                    p.incident_revision_id,p.linked_revision_id,p.shared_request_keys,p.proof_sha256,l.basis_key
            FROM p24_next.foundation_investigation_link_proof p JOIN p24_next.investigation_link l
              USING(namespace_id,investigation_id,incident_id)
            WHERE p.namespace_id=%s AND p.investigation_id=%s ORDER BY p.incident_id""",
            (self.n, investigation)).fetchall()
        revision_states={}
        for item in links:
            principal=self.incidents._authorize("read_incidents", item[0], access_token)
            self.incidents._authorize("read_incidents", item[1], access_token)
            manifest=dict(version=VERSION,basis="shared_request",publication_id=str(item[2]),
                incidents=[dict(incident_id=str(item[0]),revision_id=str(item[3])),
                           dict(incident_id=str(item[1]),revision_id=str(item[4]))],
                shared_request_keys=list(item[5]))
            manifest["incidents"].sort(key=lambda x:x["incident_id"])
            if digest(manifest)!=item[6]:
                raise FoundationError("investigation_link_proof_digest_mismatch")
            heads=self.c.execute("""SELECT incident_id,revision_id FROM p24_next.foundation_incident_head
                WHERE namespace_id=%s AND incident_id=ANY(%s)""",(self.n,[item[0],item[1]])).fetchall()
            current={str(incident_id):str(revision_id) for incident_id,revision_id in heads}
            revision_states[(str(item[0]),str(item[1]))]=_proof_revision_state(
                item[0],item[3],item[1],item[4],current)
            self.incidents.pub._audit(item[2],'publication',
                self.store.keys.token(self.store.namespace,'investigation_link',[str(investigation),str(item[0])]),principal)
        return dict(version=VERSION, investigation_id=str(investigation), title_fa=row[0], status=row[1],
                    links=[dict(investigation_id=str(investigation),incident_id=str(r[0]),linked_incident_id=str(r[1]),publication_id=str(r[2]),
                                incident_revision_id=str(r[3]),linked_revision_id=str(r[4]),
                                shared_request_keys=list(r[5]),shared_request_count=len(r[5]),
                                basis=r[7],proof_sha256=r[6],revision_state=revision_states[(str(r[0]),str(r[1]))]) for r in links],
                    claim="shared RequestID evidence only; no common identity or root cause inferred")

    def for_incident(self, incident_id, *, access_token=None):
        """Read validated shared-request proofs attached to one incident."""
        incident = ref(incident_id)
        self.incidents._authorize("read_incidents", incident, access_token)
        rows = self.c.execute("""SELECT DISTINCT investigation_id
            FROM p24_next.foundation_investigation_link_proof
            WHERE namespace_id=%s AND incident_id=%s ORDER BY investigation_id LIMIT 51""",
            (self.n, incident)).fetchall()
        if len(rows) > 50:
            raise FoundationError("investigation_link_limit_requires_narrower_scope")
        result=[]
        for (investigation_id,) in rows:
            saved=self.read(investigation_id, access_token=access_token)
            result.extend(link for link in saved["links"] if link["incident_id"] == str(incident))
        return dict(items=result, total=len(result), claim="shared RequestID evidence only; no common identity or root cause inferred")

    def list_for_publication(self, publication_id, *, access_token=None):
        """List proof-backed investigation groups in one sealed publication."""
        publication=ref(publication_id)
        self.incidents._authorize("read_incidents",publication,access_token)
        rows=self.c.execute("""SELECT DISTINCT investigation_id
            FROM p24_next.foundation_investigation_link_proof
            WHERE namespace_id=%s AND publication_id=%s
            ORDER BY investigation_id LIMIT 101""",(self.n,publication)).fetchall()
        if len(rows)>100:
            raise FoundationError("investigation_queue_limit_requires_narrower_publication")
        items=[]
        for (investigation_id,) in rows:
            group=self.read(investigation_id,access_token=access_token)
            items.append(group)
        return dict(publication_id=str(publication),items=items,total=len(items),
                    claim="Only validated shared RequestID evidence is shown; no common identity or root cause inferred")

    def priority_history(self, incident_id, *, limit=25, cursor=None, access_token=None):
        """Read append-only priority decisions with signed, revision-bound pages."""
        checked_limit(limit)
        incident=ref(incident_id)
        principal=self.incidents._authorize("read_incidents",incident,access_token)
        current=self.c.execute("""SELECT h.revision_id,r.input_sha256,r.publication_id
            FROM p24_next.foundation_incident_head h JOIN p24_next.foundation_incident_revision r
            USING(namespace_id,incident_id,revision_id) WHERE h.namespace_id=%s AND h.incident_id=%s""",
            (self.n,incident)).fetchone()
        if current is None:raise FoundationError("incident_not_available")
        publication=current[2];scope="priority_history:"+str(incident)
        position=self.incidents.pub._read_cursor(cursor,publication,HISTORY_CURSOR_VERSION,scope)
        if position is None:
            after_time=after_id=None
            as_of=self.c.execute("SELECT clock_timestamp()").fetchone()[0]
        else:
            try:
                raw=position["after"]
                after_id=str(ref(raw[1]))
                from datetime import datetime
                after_time=datetime.fromisoformat(raw[0])
                as_of=datetime.fromisoformat(position["as_of"])
            except (KeyError,IndexError,TypeError,ValueError):
                raise FoundationError("invalid_page_cursor") from None
        head=self.c.execute("SELECT decision_id FROM p24_next.foundation_priority_head WHERE namespace_id=%s AND incident_id=%s",
                            (self.n,incident)).fetchone()
        head_id=str(head[0]) if head else None
        rows=self.c.execute("""SELECT decision_id,priority,policy_version,impact_factors,evidence_manifest_sha256,
                actor_key,reason_fa,supersedes_decision_id,decided_at
            FROM p24_next.priority_decision WHERE namespace_id=%s AND incident_id=%s AND decided_at<=%s
              AND (%s::timestamptz IS NULL OR (decided_at,decision_id)<(%s::timestamptz,%s::uuid))
            ORDER BY decided_at DESC,decision_id DESC LIMIT %s""",
            (self.n,incident,as_of,after_time,after_time,after_id,limit+1)).fetchall()
        total=self.c.execute("SELECT count(*) FROM p24_next.priority_decision WHERE namespace_id=%s AND incident_id=%s AND decided_at<=%s",
                             (self.n,incident,as_of)).fetchone()[0]
        items=[]
        for row in rows[:limit]:
            factors=row[3];revision=factors.get("incident_revision_id") if isinstance(factors,dict) else None
            if str(row[0])!=head_id:state="superseded"
            elif revision==str(current[0]) and row[4]==current[1]:state="current"
            else:state="stale"
            items.append(dict(decision_id=str(row[0]),priority=row[1],policy_version=row[2],impact_factors=factors,
                evidence_sha256=row[4],actor_key=row[5],reason_key=row[6],supersedes_decision_id=str(row[7]) if row[7] else None,
                decided_at=row[8].isoformat(),state=state))
            self.incidents.pub._audit(publication,"publication",
                self.store.keys.token(self.store.namespace,"priority_history",[str(incident),str(row[0])]),principal)
        following=None
        if len(rows)>limit:
            last=rows[limit-1]
            following=self.incidents.pub._cursor(publication,HISTORY_CURSOR_VERSION,scope,
                dict(after=[last[8].isoformat(),str(last[0])],as_of=as_of.isoformat()))
        self.incidents.pub._audit(publication,"publication",
            self.store.keys.token(self.store.namespace,"priority_history_page",[str(incident),str(publication)]),principal)
        return dict(publication_id=str(publication),incident_id=str(incident),total=int(total),items=items,
                    next_cursor=following,as_of=as_of.isoformat(),page_size=limit)

    def preview_priority(self, incident_id, *, priority, impact, urgency, confidence, reason_key,
                         access_token=None):
        """Return the current evidence and decision generation for a review preview."""
        incident=ref(incident_id)
        self.incidents._authorize("review_incidents",incident,access_token)
        if (priority not in PRIORITIES-{"unrated"} or impact not in IMPACT or urgency not in URGENCY or
                confidence not in CONFIDENCE or reason_key not in REASONS):
            raise FoundationError("invalid_priority_decision")
        head=self.c.execute("""SELECT h.revision_id,h.generation,r.input_sha256,r.publication_id
            FROM p24_next.foundation_incident_head h JOIN p24_next.foundation_incident_revision r
            USING(namespace_id,incident_id,revision_id) WHERE h.namespace_id=%s AND h.incident_id=%s""",
            (self.n,incident)).fetchone()
        if head is None:raise FoundationError("incident_not_available")
        current=self.c.execute("SELECT generation FROM p24_next.foundation_priority_head WHERE namespace_id=%s AND incident_id=%s",
                               (self.n,incident)).fetchone()
        return dict(incident_id=str(incident),priority=priority,impact=impact,urgency=urgency,
                    confidence=confidence,reason_key=reason_key,decision_generation=current[0] if current else 0,
                    evidence_revision_id=str(head[0]),incident_generation=head[1],evidence_sha256=head[2],
                    publication_id=str(head[3]))

    def decide_priority(self, incident_id, *, priority, impact, urgency, confidence, reason_key,
                        expected_generation, expected_revision_id=None, expected_evidence_sha256=None, access_token=None):
        incident = ref(incident_id)
        principal = self.incidents._authorize("review_incidents", incident, access_token)
        if (priority not in PRIORITIES or impact not in IMPACT or urgency not in URGENCY or
                confidence not in CONFIDENCE or reason_key not in REASONS or
                isinstance(expected_generation, bool) or not isinstance(expected_generation, int) or expected_generation < 0):
            raise FoundationError("invalid_priority_decision")
        with self.c.transaction():
            self.store._lock()
            head = self.c.execute("""SELECT h.revision_id,h.generation,r.input_sha256,r.publication_id
                FROM p24_next.foundation_incident_head h JOIN p24_next.foundation_incident_revision r
                USING(namespace_id,incident_id,revision_id) WHERE h.namespace_id=%s AND h.incident_id=%s""",
                (self.n, incident)).fetchone()
            if head is None:
                raise FoundationError("incident_not_available")
            if expected_revision_id is not None and (ref(expected_revision_id)!=head[0] or expected_evidence_sha256!=head[2]):
                raise FoundationError("stale_priority_evidence")
            current = self.c.execute("SELECT generation,decision_id,revision_id FROM p24_next.foundation_priority_head WHERE namespace_id=%s AND incident_id=%s",
                                     (self.n, incident)).fetchone()
            generation = current[0] if current else 0
            if generation != expected_generation:
                raise FoundationError("stale_priority_generation")
            factors = dict(impact=impact, urgency=urgency, confidence=confidence,
                           detector_score_used=False, operator_verdict_used=False,
                           incident_revision_id=str(head[0]), incident_generation=head[1])
            decision_id = stable_id(self.store.namespace, "priority_decision", str(incident), generation + 1,
                                    str(head[0]), priority, factors, principal, reason_key)
            supersedes = current[1] if current else None
            self.c.execute("""INSERT INTO p24_next.priority_decision
                (namespace_id,decision_id,incident_id,priority,policy_version,impact_factors,
                 evidence_manifest_sha256,actor_key,reason_fa,supersedes_decision_id)
                VALUES(%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)""",
                (self.n, decision_id, incident, priority, VERSION, jsonb(factors), head[2], principal,
                 reason_key, supersedes))
            if current:
                self.c.execute("UPDATE p24_next.foundation_priority_head SET decision_id=%s,generation=%s,revision_id=%s WHERE namespace_id=%s AND incident_id=%s",
                               (decision_id, generation + 1, head[0], self.n, incident))
            else:
                self.c.execute("INSERT INTO p24_next.foundation_priority_head VALUES(%s,%s,%s,1,%s)",
                               (self.n, incident, decision_id, head[0]))
        self.incidents.pub._audit(head[3],'publication',
            self.store.keys.token(self.store.namespace,'priority_decision',str(decision_id)),principal)
        return dict(decision_id=str(decision_id),priority=priority,generation=generation+1,
                    evidence_revision_id=str(head[0]),evidence_sha256=head[2],impact_factors=factors,
                    actor=principal,priority_is_operator_assessed=True)

    def priority(self, incident_id, *, access_token=None):
        incident=ref(incident_id)
        self.incidents._authorize("read_incidents", incident, access_token)
        row=self.c.execute("""SELECT d.decision_id,d.priority,d.policy_version,d.impact_factors,d.evidence_manifest_sha256,
                h.revision_id,h.generation,r.input_sha256,d.actor_key,d.reason_fa
            FROM p24_next.foundation_priority_head h JOIN p24_next.priority_decision d USING(namespace_id,decision_id)
            JOIN p24_next.foundation_incident_revision r ON r.namespace_id=h.namespace_id AND r.incident_id=h.incident_id AND r.revision_id=h.revision_id
            WHERE h.namespace_id=%s AND h.incident_id=%s""",(self.n,incident)).fetchone()
        if row is None:
            return dict(priority="unrated",stale=False,decision_id=None,decision_generation=0)
        latest=self.c.execute("SELECT revision_id FROM p24_next.foundation_incident_head WHERE namespace_id=%s AND incident_id=%s",
                              (self.n,incident)).fetchone()
        stale=latest is None or latest[0]!=row[5] or row[4]!=row[7]
        return dict(priority="unrated" if stale else row[1],recorded_priority=row[1],stale=stale,
                    decision_id=str(row[0]),policy_version=row[2],impact_factors=row[3],
                    evidence_revision_id=str(row[5]),decision_generation=row[6],actor_key=row[8],reason_key=row[9],
                    note="Priority must be reassessed after incident evidence changes" if stale else "Operator-assessed against the pinned incident revision")
