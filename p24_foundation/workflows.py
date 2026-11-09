"""Deterministic workflow reconciliation over selected, already-verified facts.

The caller supplies evidence selected by a sealed run and verifier decisions.
This kernel does not authenticate a callback, parse a payload, or connect to a
provider. Transport receipts, logical event identities and business state are
different observation units.
"""
from __future__ import annotations

import hashlib
import re
import uuid
from collections import defaultdict
from dataclasses import asdict, dataclass

from .errors import FoundationError
from .privacy import canonical

WORKFLOW_RESOLVER_VERSION = "p24-workflow-reconciliation.2r.1"
TOKEN = re.compile(r"^[A-Za-z0-9_]+:[A-Za-z0-9_-]{1,40}:[a-f0-9]{64}$")
LABEL = re.compile(r"^[A-Za-z0-9_.:-]{1,160}$")
OUTCOMES = {"success", "failure", "pending", "partial", "unknown"}
MAX_ROWS = 100_000


@dataclass(frozen=True)
class SelectedEvidence:
    version_id: str
    namespace: str
    origin_key: str
    event_time_ns: int | None
    received_at_ns: int


@dataclass(frozen=True)
class ExternalEvent:
    source_version_id: str
    issuer: str
    topic: str
    identifier_domain: str
    identifier_token: str
    token_key_version: str
    content_sha256: str
    schema_version: str
    identity_state: str = "unresolved"
    authenticity_state: str = "unverified"
    identity_assertion_ref: str | None = None
    identity_fact_ref: str | None = None


@dataclass(frozen=True)
class DeliveryObservation:
    source_version_id: str
    acknowledgement: str = "unknown"
    attempt_token: str | None = None
    transport_request_key: str | None = None
    attempt_identity_verified: bool = False
    issuer: str | None = None
    attempt_domain: str | None = None


@dataclass(frozen=True)
class StateContract:
    version: str
    states: tuple  # (state_key, outcome)
    transitions: tuple = ()  # (previous_state_key, next_state_key)
    terminal_states: tuple = ()
    allowed_roles: tuple = ("provider",)
    sequence_domain: str | None = None
    authority_ref: str | None = None
    review_state: str = "unreviewed"


@dataclass(frozen=True)
class WorkflowState:
    source_version_id: str
    workflow_token: str
    contract_version: str
    state_key: str
    source_role: str
    link_state: str = "unresolved"
    authenticity_state: str = "unverified"
    completeness: str = "unknown"
    subject_domain: str | None = None
    subject_token: str | None = None
    issuer_sequence: int | None = None
    sequence_domain: str | None = None
    link_assertion_ref: str | None = None
    state_fact_ref: str | None = None


def _token(value):
    return isinstance(value, str) and TOKEN.fullmatch(value) is not None


def _label(value):
    return isinstance(value, str) and LABEL.fullmatch(value) is not None


def _uuid(value):
    try:
        uuid.UUID(value)
        return True
    except (ValueError, TypeError, AttributeError):
        return False


def _dedup(rows):
    # Dataclass values have no raw payload. Exact repeats are idempotent.
    return sorted(set(rows), key=lambda row: canonical(asdict(row)))


def _state_result(rows, contract):
    meanings = dict(contract.states)
    states = {row.state_key for row in rows}
    if len(states) == 1:
        final = next(iter(states))
        return final, meanings[final], "consistent_observations"
    if contract.sequence_domain is None or any(
            row.issuer_sequence is None or row.sequence_domain != contract.sequence_domain for row in rows):
        return None, "conflicting", "unordered_state_changes"
    ordered = defaultdict(set)
    for row in rows:
        ordered[row.issuer_sequence].add(row.state_key)
    if any(len(values) != 1 for values in ordered.values()):
        return None, "conflicting", "same_sequence_conflict"
    sequence = [next(iter(values)) for _, values in sorted(ordered.items())]
    for before, after in zip(sequence, sequence[1:]):
        if before != after and ((before, after) not in contract.transitions or before in contract.terminal_states):
            return None, "conflicting", "unapproved_state_transition"
    return sequence[-1], meanings[sequence[-1]], "verified_issuer_sequence"


def reconcile_workflows(evidence, events=(), deliveries=(), states=(), *, namespace,
                        event_cutoff_ns, knowledge_at_ns, contracts=()):
    """Return one bounded immutable projection; timestamps alone never choose state.

    Event cutoff is exclusive and knowledge cutoff inclusive. Inputs from a
    different namespace are rejected. Unverified identity/authenticity and
    partial state evidence remain unresolved. No contract is enabled by default.
    """
    evidence, events, deliveries, states, contracts = map(tuple, (evidence, events, deliveries, states, contracts))
    if (sum(map(len, (evidence, events, deliveries, states))) > MAX_ROWS or len(contracts) > 256
            or not isinstance(event_cutoff_ns, int) or isinstance(event_cutoff_ns, bool)
            or not isinstance(knowledge_at_ns, int) or isinstance(knowledge_at_ns, bool)):
        raise FoundationError("workflow_projection_limit_or_cutoff_invalid")
    policy = {}
    for contract in contracts:
        meanings = dict(contract.states)
        if (not _label(contract.version) or contract.version in policy or not meanings or len(meanings) > 4096
                or len(meanings) != len(contract.states) or not all(_label(k) and v in OUTCOMES for k, v in contract.states)
                or not set(contract.terminal_states) <= set(meanings)
                or not all(a in meanings and b in meanings for a, b in contract.transitions)
                or contract.review_state not in {"reviewed", "unreviewed"}):
            raise FoundationError("invalid_workflow_state_contract")
        policy[contract.version] = contract
    versions, all_versions, origins, excluded = {}, {}, defaultdict(set), defaultdict(int)
    for item in _dedup(evidence):
        try:
            uuid.UUID(item.version_id)
        except (ValueError, TypeError, AttributeError):
            raise FoundationError("invalid_workflow_source_reference") from None
        if (item.namespace != namespace or not _token(item.origin_key)
                or not isinstance(item.received_at_ns, int) or isinstance(item.received_at_ns, bool)
                or (item.event_time_ns is not None and (not isinstance(item.event_time_ns, int)
                                                      or isinstance(item.event_time_ns, bool)))):
            raise FoundationError("invalid_workflow_source_scope")
        if item.version_id in all_versions and all_versions[item.version_id] != item:
            raise FoundationError("conflicting_workflow_source_metadata")
        all_versions[item.version_id] = item
        if item.received_at_ns > knowledge_at_ns:
            excluded["not_yet_known"] += 1
            continue
        if item.event_time_ns is None:
            excluded["unknown_event_time"] += 1
            continue
        if item.event_time_ns >= event_cutoff_ns:
            excluded["at_or_after_event_cutoff"] += 1
            continue
        versions[item.version_id] = item
        origins[item.origin_key].add(item.version_id)
    ambiguous = {version for values in origins.values() if len(values) > 1 for version in values}
    for version in ambiguous:
        del versions[version]
    excluded["conflicting_origin_versions"] = len(ambiguous)
    groups, linked_versions, excluded_observations = defaultdict(list), {}, defaultdict(int)
    unresolved_events = 0
    for event in _dedup(events):
        if event.source_version_id not in versions:
            excluded_observations["external_events_missing_or_ineligible_source"] += 1
            continue
        if (event.identity_state != "verified" or event.authenticity_state != "verified"
                or not all(_label(v) for v in (event.issuer, event.topic, event.identifier_domain, event.token_key_version, event.schema_version))
                or not _token(event.identifier_token)
                or not _uuid(event.identity_assertion_ref) or not _uuid(event.identity_fact_ref)
                or not re.fullmatch(r"[a-f0-9]{64}", event.content_sha256)):
            unresolved_events += 1
            continue
        identity = (event.issuer, event.topic, event.identifier_domain, event.token_key_version, event.identifier_token)
        groups[identity].append(event)
        linked_versions.setdefault(event.source_version_id, set()).add(identity)
    conflicting_identity_sources = {version for version, identities in linked_versions.items() if len(identities) > 1}
    if conflicting_identity_sources:
        for identity in list(groups):
            groups[identity] = [event for event in groups[identity] if event.source_version_id not in conflicting_identity_sources]
            if not groups[identity]:
                del groups[identity]
        unresolved_events += sum(1 for event in _dedup(events) if event.source_version_id in conflicting_identity_sources)
    event_rows = []
    for identity, values in sorted(groups.items()):
        revisions = sorted({(e.content_sha256, e.schema_version) for e in values})
        event_rows.append(dict(issuer=identity[0], topic=identity[1], identifier_domain=identity[2],
            token_key_version=identity[3], identifier_token=identity[4],
            state="consistent_revision" if len(revisions) == 1 else "conflicting_revisions",
            revision_count=len(revisions), source_observation_count=len({e.source_version_id for e in values}),
            source_version_ids=sorted({e.source_version_id for e in values})))
    attempt_groups, delivery_rows, by_delivery_source = defaultdict(list), [], defaultdict(list)
    for delivery in _dedup(deliveries):
        if delivery.source_version_id not in versions:
            excluded_observations["deliveries_missing_or_ineligible_source"] += 1
            continue
        if delivery.acknowledgement not in {"http_accepted", "http_rejected", "not_observed", "unknown"}:
            raise FoundationError("invalid_delivery_acknowledgement")
        if delivery.transport_request_key is not None and not _token(delivery.transport_request_key):
            raise FoundationError("invalid_delivery_transport_reference")
        by_delivery_source[delivery.source_version_id].append(delivery)
    for source_version, variants in sorted(by_delivery_source.items()):
        identities = {(row.issuer,row.attempt_domain,row.attempt_token) for row in variants}
        verified = (len(identities) == 1 and all(row.attempt_identity_verified is True and _token(row.attempt_token)
                    and _label(row.issuer) and _label(row.attempt_domain) for row in variants))
        request_keys = {row.transport_request_key for row in variants}
        acknowledgements = {row.acknowledgement for row in variants}
        links = linked_versions.get(source_version, set())
        public_row = dict(source_version_id=source_version,
            acknowledgement=next(iter(acknowledgements)) if len(acknowledgements) == 1 else "conflicting",
            attempt_identity_state="verified_attempt" if verified else "ambiguous" if len(identities) > 1 else "source_observation_only",
            attempt_token=variants[0].attempt_token if verified else None,
            transport_request_key=next(iter(request_keys)) if len(request_keys) == 1 else None,
            source_assertion_variants=len(variants),
            logical_event_link_state="verified_identity" if len(links) == 1 else "conflicting_identity" if links else "unresolved")
        delivery_rows.append(public_row)
        if verified:
            attempt_groups[next(iter(identities))].append(public_row)
    attempt_rows = [dict(issuer=identity[0], attempt_domain=identity[1], attempt_token=identity[2], source_observations=len({r["source_version_id"] for r in rows}),
                         acknowledgement=next(iter({r["acknowledgement"] for r in rows})) if len({r["acknowledgement"] for r in rows}) == 1 else "conflicting")
                    for identity, rows in sorted(attempt_groups.items())]
    state_groups, unresolved_states = defaultdict(list), 0
    for row in _dedup(states):
        if row.source_version_id not in versions:
            excluded_observations["states_missing_or_ineligible_source"] += 1
            continue
        contract = policy.get(row.contract_version)
        subject_valid = (row.subject_domain is None and row.subject_token is None) or (_label(row.subject_domain) and _token(row.subject_token))
        if (contract is None or contract.review_state != "reviewed" or not _label(contract.authority_ref)
                or row.link_state != "accepted" or row.authenticity_state != "verified"
                or row.completeness != "complete" or row.source_role not in contract.allowed_roles
                or not _uuid(row.link_assertion_ref) or not _uuid(row.state_fact_ref)
                or row.state_key not in dict(contract.states) or not _token(row.workflow_token) or not subject_valid
                or (row.issuer_sequence is not None and (not isinstance(row.issuer_sequence, int) or isinstance(row.issuer_sequence, bool) or row.issuer_sequence < 0))):
            unresolved_states += 1
            continue
        state_groups[(row.workflow_token, row.contract_version, row.subject_domain or "", row.subject_token or "")].append(row)
    state_rows = []
    for key, rows in sorted(state_groups.items()):
        contract = policy[key[1]]
        final, outcome, basis = _state_result(rows, contract)
        state_rows.append(dict(workflow_token=key[0], contract_version=key[1], state_scope="subject" if key[2] else "workflow",
            subject_domain=key[2] or None, subject_token=key[3] or None, published_state=outcome, state_key=final,
            resolution_basis=basis, terminal_state_observed=final in contract.terminal_states if final else False,
            observation_count=len(rows), source_version_ids=sorted({r.source_version_id for r in rows}),
            state_fact_refs=sorted({r.state_fact_ref for r in rows}),
            source_finality="not_established"))
    payload = dict(version=WORKFLOW_RESOLVER_VERSION, namespace=namespace, event_cutoff_ns=str(event_cutoff_ns),
                   knowledge_at_ns=str(knowledge_at_ns), selected_source_versions=sorted(versions),
                   excluded_evidence_counts=dict(sorted(excluded.items())), logical_events=event_rows,
                   excluded_observation_counts=dict(sorted(excluded_observations.items())),
                   logical_event_count=len(event_rows), unverified_event_observations=unresolved_events,
                   conflicting_external_identity_sources=sorted(conflicting_identity_sources),
                   delivery_observations=delivery_rows, delivery_observation_count=len(delivery_rows),
                   verified_delivery_attempts=attempt_rows, verified_delivery_attempt_count=len(attempt_rows),
                   distinct_transport_request_count=len({d["transport_request_key"] for d in delivery_rows if d["transport_request_key"]}),
                   state_publications=state_rows, unresolved_state_observations=unresolved_states,
                   acknowledgement_establishes_business_success=False,
                   contract_digest=hashlib.sha256(canonical(sorted((asdict(c) for c in contracts), key=lambda c:c["version"]))).hexdigest())
    payload["projection_sha256"] = hashlib.sha256(canonical(payload)).hexdigest()
    return payload
