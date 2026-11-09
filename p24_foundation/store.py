"""Native psycopg persistence against the reviewed domain model.

Only disposable databases are accepted. Intake/projection transactions are
atomic; original snapshots/events and sealed runs are append-only. This batch
uses explicit input vectors and does not publish production serving heads.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import re
import uuid
from collections import Counter, defaultdict
from datetime import datetime, timedelta, timezone
from pathlib import Path

from .config import ALLOWED_DATABASE
from .access import AccessPolicy, VerifiedPrincipal, POLICY_VERSION
from .errors import FoundationError
from .intake import Batch, decode_batch
from .parser import PARSER_VERSION, PRIVACY_VERSION, Semantics, normalize_event
from .privacy import canonical, Vault
from .reconstruction import RESOLVER_VERSION, select_events, reconstruct, registration_candidates
from .time import microsecond_cutoff, EPOCH

ROOT = Path(__file__).resolve().parents[1]
UUID_DOMAIN = uuid.UUID("e99c5b52-4931-5e1f-8fb4-83b61c65da22")
MAX_PROJECTION_EVENTS = 100_000
MAX_SOURCES = 128

def stable_id(*parts):
    return uuid.uuid5(UUID_DOMAIN, canonical(parts).decode("utf-8"))

def floor_ns(value):
    seconds, ns = divmod(int(value), 1_000_000_000)
    return EPOCH + timedelta(seconds=seconds, microseconds=ns // 1000)

def jsonb(value):
    from psycopg.types.json import Jsonb
    return Jsonb(value)

def execute_many(connection, statement, rows, *, chunk_size=512):
    """Retains the validated native writer's Cursor.executemany pattern."""
    rows = list(rows)
    with connection.cursor() as cursor:
        for offset in range(0, len(rows), chunk_size):
            cursor.executemany(statement, rows[offset:offset + chunk_size])

def assert_disposable(connection):
    actual = connection.execute("SELECT current_database()").fetchone()[0]
    if not ALLOWED_DATABASE.fullmatch(actual):
        raise FoundationError("database_requires_disposable_name")

def initialize(connection):
    assert_disposable(connection)
    for version, filename, marker in (
        ("p24-domain.3", "0001_domain.sql", "namespace"),
        ("p24-foundation.2a.1", "0002_batch2a.sql", "foundation_event_descriptor"),
        ("p24-foundation.2b.1", "0003_batch2b.sql", "foundation_work_item"),
        ("p24-foundation.2c.1", "0004_batch2c.sql", "foundation_work_oldest_cutoff"),
        ("p24-foundation.2d.1", "0005_taxonomy_candidates.sql", "catalog_code_entry"),
        ("p24-foundation.2e.1", "0006_acquisition.sql", "foundation_acquisition_assessment"),
        ("p24-foundation.2f.1", "0007_observed_publication.sql", "foundation_observation_publication"),
        ("p24-foundation.2g.1", "0008_access_preservation.sql", "foundation_access_decision"),
        ("p24-foundation.2h.1", "0009_source_receipts.sql", "foundation_source_manifest"),
        ("p24-foundation.2s.1", "0010_workflow_projection.sql", "foundation_workflow_run"),
        ("p24-foundation.2t.1", "0011_incident_review.sql", "foundation_incident_revision"),
        ("p24-foundation.2u.1", "0012_investigation_priority.sql", "foundation_investigation_link_proof"),
    ):
        text = (ROOT / "sql" / filename).read_text(encoding="utf-8")
        digest = hashlib.sha256(text.encode("utf-8")).hexdigest()
        exists = connection.execute("SELECT to_regclass(%s)", ("p24_next." + marker,)).fetchone()[0]
        if not exists:
            if not connection.autocommit:
                raise FoundationError("initialization_requires_autocommit")
            before, separator, after = text.rpartition("COMMIT;")
            if not separator or after.strip():
                raise FoundationError("migration_transaction_contract_invalid")
            # Record the exact source checksum in the same DDL transaction.
            recorded = before + "INSERT INTO p24_next.design_version(version_key,content_sha256) VALUES('" + version + "','" + digest + "');\nCOMMIT;\n"
            try:
                connection.execute(recorded, prepare=False)
            except Exception:
                connection.execute("ROLLBACK")
                raise FoundationError("migration_failed") from None
        row = connection.execute("SELECT content_sha256 FROM p24_next.design_version WHERE version_key=%s", (version,)).fetchone()
        if not row:
            raise FoundationError("unversioned_schema_not_adopted")
        if row[0] != digest:
            raise FoundationError("migration_checksum_mismatch")
    _backfill_source_manifest_receipts(connection)
    return dict(status="initialized", schema="p24_next", version="p24-foundation.2u.1", production_modified=False)


def _safe_source_manifest(source_digest, source_kind, input_format, row_count, window_start, window_end,
                          receive_time_basis, assessment=None):
    """Build the small, non-secret manifest retained beside every source."""
    if isinstance(assessment, dict):
        capture = assessment.get("capture_manifest")
        if isinstance(capture, dict):
            expected = capture.get("sha256")
            unsigned = {k: v for k, v in capture.items() if k != "sha256"}
            if not isinstance(expected, str) or hashlib.sha256(canonical(unsigned)).hexdigest() != expected:
                raise FoundationError("capture_manifest_digest_mismatch")
            return capture, capture.get("version", "p24-capture-manifest.1"), "scroll_capture"
        # A pre-2H acquisition assessment is retained as a legacy manifest.
        safe = dict(version="p24-capture-manifest.legacy",contract_version=assessment.get("contract_version"),
                    query_traversal_complete=bool(assessment.get("query_traversal_complete",False)),
                    source_window_complete=False,source_finality="not_established",
                    producer_authority="unverified",legacy_selected_page_metadata=assessment.get("pages",[]),
                    legacy_slice_metadata=assessment.get("slices",[]),legacy_issues=assessment.get("issues",[]))
        return safe, safe["version"], "scroll_capture"
    safe = dict(version="p24-source-manifest.1",source_kind="legacy_unassessed",
                source_digest=source_digest,input_format=input_format,record_count=int(row_count),
                declared_interval=dict(start=window_start.astimezone(timezone.utc).isoformat(),end=window_end.astimezone(timezone.utc).isoformat()),
                receipt_time_basis=receive_time_basis,
                claims=dict(producer_authority="unverified",source_window_complete=False,
                            source_finality="not_established",query_traversal="not_assessed"))
    return safe, safe["version"], "legacy_unassessed"


def _backfill_source_manifest_receipts(connection, *, batch_size=250, max_batches=None):
    """Bind legacy rows in committed batches; optional budgets yield safely.

    The return value remains the number of new manifests. A repeated call
    starts from durable missing rows, never from an in-memory checkpoint.
    """
    if isinstance(batch_size, bool) or not isinstance(batch_size, int) or not 1 <= batch_size <= 250:
        raise FoundationError("invalid_backfill_batch_size")
    if max_batches is not None and (isinstance(max_batches, bool) or not isinstance(max_batches, int)
                                    or not 1 <= max_batches <= 1000):
        raise FoundationError("invalid_backfill_batch_budget")
    if not connection.autocommit:
        raise FoundationError("backfill_requires_autocommit")
    inserted = 0
    batches = 0
    cursor = None
    while True:
        rows = connection.execute("""SELECT s.namespace_id,s.snapshot_id,s.source_digest,s.observed_at,s.raw_event_count,
            w.window_start,w.window_end,m.input_format,m.receive_time_basis,a.assessment
            FROM p24_next.source_snapshot s
            JOIN p24_next.source_window w USING(namespace_id,window_key)
            JOIN p24_next.foundation_snapshot_metadata m USING(namespace_id,snapshot_id)
            LEFT JOIN p24_next.foundation_acquisition_assessment a USING(namespace_id,snapshot_id)
            WHERE (%s::uuid IS NULL OR (s.namespace_id,s.snapshot_id)>(%s::uuid,%s::uuid))
              AND (NOT EXISTS (SELECT 1 FROM p24_next.foundation_source_manifest sm
                    WHERE sm.namespace_id=s.namespace_id AND sm.snapshot_id=s.snapshot_id)
                OR NOT EXISTS (SELECT 1 FROM p24_next.foundation_source_receipt r
                    WHERE r.namespace_id=s.namespace_id AND r.snapshot_id=s.snapshot_id AND r.disposition='accepted'))
            ORDER BY s.namespace_id,s.snapshot_id LIMIT %s""",
            (cursor[0] if cursor else None,cursor[0] if cursor else None,cursor[1] if cursor else None,batch_size)).fetchall()
        if not rows:
            # An inner join must not turn missing legacy metadata into a
            # successful upgrade. Leave those source rows untouched for repair.
            pending = connection.execute("""SELECT EXISTS (
                SELECT 1 FROM p24_next.source_snapshot s
                WHERE NOT EXISTS (SELECT 1 FROM p24_next.foundation_source_manifest m
                    WHERE m.namespace_id=s.namespace_id AND m.snapshot_id=s.snapshot_id)
                   OR NOT EXISTS (SELECT 1 FROM p24_next.foundation_source_receipt r
                    WHERE r.namespace_id=s.namespace_id AND r.snapshot_id=s.snapshot_id
                      AND r.disposition='accepted'))""").fetchone()[0]
            if pending:
                raise FoundationError("source_backfill_incomplete")
            break
        with connection.transaction():
            for namespace_id,snapshot_id,digest,received,count,start,end,input_format,basis,assessment in rows:
                manifest,version,kind = _safe_source_manifest(digest,
                    "scroll_capture" if assessment is not None else "legacy_unassessed",
                    input_format,count,start,end,basis,assessment)
                manifest_digest=hashlib.sha256(canonical(manifest)).hexdigest()
                result=connection.execute("""INSERT INTO p24_next.foundation_source_manifest
                    (namespace_id,snapshot_id,source_digest,manifest_version,source_kind,manifest_sha256,safe_manifest)
                    SELECT s.namespace_id,s.snapshot_id,s.source_digest,%s,%s,%s,%s
                    FROM p24_next.source_snapshot s WHERE s.namespace_id=%s AND s.snapshot_id=%s
                    ON CONFLICT(namespace_id,snapshot_id) DO NOTHING""",
                    (version,kind,manifest_digest,jsonb(manifest),namespace_id,snapshot_id))
                inserted += result.rowcount
                receipt = connection.execute("""INSERT INTO p24_next.foundation_source_receipt
                    (namespace_id,snapshot_id,source_digest,manifest_sha256,received_at,receipt_time_basis,
                     disposition,input_bytes,row_count,interval_start,interval_end)
                    SELECT s.namespace_id,s.snapshot_id,s.source_digest,mf.manifest_sha256,s.observed_at,
                        CASE m.receive_time_basis WHEN 'producer_manifest' THEN 'producer_manifest_unverified'
                             ELSE m.receive_time_basis END,'accepted',o.byte_count,s.raw_event_count,w.window_start,w.window_end
                    FROM p24_next.source_snapshot s
                    JOIN p24_next.foundation_source_manifest mf USING(namespace_id,snapshot_id)
                    JOIN p24_next.foundation_snapshot_metadata m USING(namespace_id,snapshot_id)
                    JOIN p24_next.raw_object o USING(namespace_id,snapshot_id)
                    JOIN p24_next.source_window w USING(namespace_id,window_key)
                    WHERE s.namespace_id=%s AND s.snapshot_id=%s AND NOT EXISTS (SELECT 1 FROM p24_next.foundation_source_receipt r
                        WHERE r.namespace_id=s.namespace_id AND r.snapshot_id=s.snapshot_id AND r.disposition='accepted')""",
                    (namespace_id,snapshot_id))
                if receipt.rowcount != 1 and not connection.execute("""SELECT 1
                    FROM p24_next.foundation_source_receipt WHERE namespace_id=%s AND snapshot_id=%s
                    AND disposition='accepted'""", (namespace_id,snapshot_id)).fetchone():
                    raise FoundationError("source_backfill_incomplete")
        cursor=(rows[-1][0],rows[-1][1])
        batches += 1
        if max_batches is not None and batches >= max_batches:
            break
    return inserted

class FoundationStore:
    def __init__(self, connection, keys, namespace, vault_path, *, catalog_path=None, access_policy=None):
        assert_disposable(connection)
        if not isinstance(namespace, str) or not re.fullmatch(r"[A-Za-z0-9_.-]{1,100}", namespace):
            raise FoundationError("invalid_namespace")
        if access_policy is not None and not isinstance(access_policy, AccessPolicy):
            raise FoundationError("invalid_access_policy")
        self.c, self.keys, self.namespace = connection, keys, namespace
        self.access_policy = access_policy
        self.namespace_id = stable_id("namespace", namespace)
        self.catalog = Semantics(catalog_path or ROOT / "catalogs/error_code_catalog.json")
        self.vault = Vault(vault_path, keys, namespace)
        self.taxonomy_id = stable_id("candidate_catalog", namespace, self.catalog.digest, PARSER_VERSION)
        expected = (keys.version, keys.fingerprint, hmac.new(keys.encryption, b"p24-encryption-key-binding", hashlib.sha256).hexdigest(), PARSER_VERSION, self.catalog.digest)
        # Existing immutable contracts can be checked without taking a writer
        # lock. A newly connected reader must not wait behind reconstruction.
        binding = self.c.execute("SELECT equality_key_version,equality_key_fingerprint,encryption_key_fingerprint,extraction_version,catalog_sha256 FROM p24_next.foundation_namespace_contract WHERE namespace_id=%s", (self.namespace_id,)).fetchone()
        if binding is not None:
            if binding != expected:
                raise FoundationError("namespace_contract_mismatch")
            if self.c.execute("SELECT 1 FROM p24_next.taxonomy_release WHERE namespace_id=%s AND taxonomy_id=%s",(self.namespace_id,self.taxonomy_id)).fetchone():
                return
        with self.c.transaction():
            self._lock()
            self.c.execute("INSERT INTO p24_next.namespace(namespace_id,application_key,identity_contract_version) VALUES(%s,%s,'platform-session-contract.1') ON CONFLICT DO NOTHING", (self.namespace_id, namespace))
            self.c.execute("INSERT INTO p24_next.foundation_namespace_contract(namespace_id,equality_key_version,equality_key_fingerprint,encryption_key_fingerprint,extraction_version,catalog_sha256) VALUES(%s,%s,%s,%s,%s,%s) ON CONFLICT DO NOTHING",
                (self.namespace_id, keys.version, keys.fingerprint,
                 hmac.new(keys.encryption, b"p24-encryption-key-binding", hashlib.sha256).hexdigest(), PARSER_VERSION, self.catalog.digest))
            binding = self.c.execute("SELECT equality_key_version,equality_key_fingerprint,encryption_key_fingerprint,extraction_version,catalog_sha256 FROM p24_next.foundation_namespace_contract WHERE namespace_id=%s", (self.namespace_id,)).fetchone()
            if binding != expected:
                raise FoundationError("namespace_contract_mismatch")
            self.c.execute("INSERT INTO p24_next.taxonomy_release(namespace_id,taxonomy_id,version_key,state,content_sha256) VALUES(%s,%s,%s,'draft',%s) ON CONFLICT DO NOTHING",
                           (self.namespace_id, self.taxonomy_id, PARSER_VERSION + ":" + self.catalog.digest[:16], self.catalog.digest))

    def _lock(self):
        self.c.execute("SELECT pg_advisory_xact_lock(hashtextextended(%s,0))", ("p24-foundation:" + self.namespace,))

    def request_key(self, raw):
        return self.keys.token(self.namespace, "request", raw)

    def session_key(self, raw):
        return self.keys.token(self.namespace, "session", raw)

    def import_taxonomy_candidates(self, collection_paths, *, error_catalog_path=None, log_evidence_paths=None):
        from .taxonomy_import import persist_candidate_taxonomy
        return persist_candidate_taxonomy(self,collection_paths,error_catalog_path=error_catalog_path,
                                          log_evidence_paths=log_evidence_paths)

    def ingest(self, batch, *, source_key, interval_start, interval_end, observed_at=None,
               receive_time_basis="intake_clock"):
        if not isinstance(batch, Batch):
            raise FoundationError("decoded_batch_required")
        # Derive from the archived bytes, never a caller-mutated record list or
        # caller-forged coverage flags. Streaming intake is a later batch.
        batch = decode_batch(batch.original)
        if not isinstance(source_key, str) or not re.fullmatch(r"[A-Za-z0-9_.:-]{1,200}", source_key):
            raise FoundationError("invalid_source_key")
        start, end = microsecond_cutoff(interval_start), microsecond_cutoff(interval_end)
        if start.epoch_ns >= end.epoch_ns:
            raise FoundationError("invalid_source_interval")
        if "declared_window_start" in batch.coverage:
            declared_start=microsecond_cutoff(batch.coverage["declared_window_start"])
            declared_end=microsecond_cutoff(batch.coverage["declared_window_end"])
            if (declared_start.epoch_ns,declared_end.epoch_ns)!=(start.epoch_ns,end.epoch_ns):
                raise FoundationError("acquisition_interval_mismatch")
        if receive_time_basis not in {"intake_clock", "synthetic_fixture"}:
            raise FoundationError("unsupported_receipt_contract")
        if observed_at is not None and receive_time_basis != "synthetic_fixture":
            raise FoundationError("receipt_override_requires_synthetic_label")
        observed = microsecond_cutoff(observed_at).floor if observed_at else datetime.now(timezone.utc)
        digest = hashlib.sha256(batch.original).hexdigest()
        snapshot_id = stable_id(self.namespace, source_key, digest)
        normalized = [normalize_event(record, self.keys, self.namespace, self.catalog,
                                      fallback_scope=str(snapshot_id), ordinal=i)
                      for i, record in enumerate(batch.records)]
        for event in normalized:
            event["event_version_id"] = stable_id(event["event_key"], event["content_digest"])
            if len(canonical(event["payload"])) > 60_000:
                raise FoundationError("descriptor_size_limit")
        archived = self.vault.put(batch.original, object_scope=str(snapshot_id))
        object_id = stable_id(str(snapshot_id), "raw_object")
        coverage = dict(batch.coverage)
        coverage.update(receive_time_basis=receive_time_basis,
                        source_time_outside_declared_interval=sum(e["time"] is not None and not start.epoch_ns <= e["time"].epoch_ns < end.epoch_ns for e in normalized),
                        originless_records=sum(e["identity_kind"] != "origin_document" for e in normalized),
                        requestless_records=sum(e["request_key"] is None for e in normalized),
                        timestamp_unknown_records=sum(e["time"] is None for e in normalized))
        acquisition = coverage.get("acquisition") if isinstance(coverage.get("acquisition"), dict) else None
        safe_manifest, manifest_version, source_kind = _safe_source_manifest(
            digest, "scroll_capture" if acquisition is not None else "legacy_unassessed",
            coverage["input_format"], len(normalized), start.floor, end.floor,
            receive_time_basis, acquisition)
        manifest_digest = hashlib.sha256(canonical(safe_manifest)).hexdigest()
        receipt_id = uuid.uuid4()
        with self.c.transaction():
            self._lock()
            existing_window = self.c.execute("SELECT window_start,window_end FROM p24_next.source_window WHERE namespace_id=%s AND window_key=%s", (self.namespace_id, source_key)).fetchone()
            if existing_window and existing_window != (start.floor, end.floor):
                raise FoundationError("source_interval_changed")
            previous = self.c.execute("SELECT s.snapshot_id,m.coverage FROM p24_next.source_snapshot s JOIN p24_next.foundation_snapshot_metadata m USING(namespace_id,snapshot_id) WHERE s.namespace_id=%s AND s.window_key=%s AND s.source_digest=%s", (self.namespace_id, source_key, digest)).fetchone()
            if previous:
                stored_manifest = self.c.execute("SELECT manifest_sha256 FROM p24_next.foundation_source_manifest WHERE namespace_id=%s AND snapshot_id=%s", (self.namespace_id, previous[0])).fetchone()
                if not stored_manifest:
                    raise FoundationError("source_manifest_not_available")
                self.c.execute("""INSERT INTO p24_next.foundation_source_receipt
                    (namespace_id,receipt_id,snapshot_id,source_digest,manifest_sha256,received_at,receipt_time_basis,
                     disposition,input_bytes,row_count,interval_start,interval_end)
                    VALUES(%s,%s,%s,%s,%s,%s,%s,'reused_identical',%s,%s,%s,%s)""",
                    (self.namespace_id,receipt_id,previous[0],digest,stored_manifest[0],observed,receive_time_basis,
                     len(batch.original),len(batch.records),start.floor,end.floor))
                return dict(snapshot_id=str(previous[0]), receipt_id=str(receipt_id), reused=True,
                            records=len(batch.records), coverage=previous[1], manifest_sha256=stored_manifest[0])
            self.c.execute("INSERT INTO p24_next.source_window(namespace_id,window_key,window_start,window_end) VALUES(%s,%s,%s,%s) ON CONFLICT DO NOTHING", (self.namespace_id, source_key, start.floor, end.floor))
            revision = self.c.execute("SELECT coalesce(max(intake_revision),0)+1 FROM p24_next.source_snapshot WHERE namespace_id=%s AND window_key=%s", (self.namespace_id, source_key)).fetchone()[0]
            self.c.execute("INSERT INTO p24_next.source_snapshot(namespace_id,window_key,snapshot_id,intake_revision,source_digest,observed_at,source_complete,raw_event_count,ordering_status) VALUES(%s,%s,%s,%s,%s,%s,false,%s,'unverified')",
                           (self.namespace_id, source_key, snapshot_id, revision, digest, observed, len(batch.records)))
            self.c.execute("INSERT INTO p24_next.raw_object(namespace_id,object_id,snapshot_id,storage_key,content_sha256,format_key,byte_count,row_count,encryption_key_ref,manifest_key) VALUES(%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)",
                (self.namespace_id, object_id, snapshot_id, archived["storage_key"], digest,
                 "json_gzip" if coverage["compression"]=="gzip" else "json",len(batch.original),len(batch.records),self.keys.version,"pg:foundation_row_membership:"+str(snapshot_id)))
            self.c.execute("INSERT INTO p24_next.evidence_availability(namespace_id,object_id,status,checked_at) VALUES(%s,%s,'available',clock_timestamp())", (self.namespace_id, object_id))
            self.c.execute("INSERT INTO p24_next.foundation_snapshot_metadata VALUES(%s,%s,%s,%s,%s,%s)",
                (self.namespace_id, snapshot_id, coverage["input_format"], jsonb(coverage), archived["cipher_sha256"], receive_time_basis))
            self.c.execute("""INSERT INTO p24_next.foundation_source_manifest
                (namespace_id,snapshot_id,source_digest,manifest_version,source_kind,manifest_sha256,safe_manifest)
                VALUES(%s,%s,%s,%s,%s,%s,%s)""",
                (self.namespace_id,snapshot_id,digest,manifest_version,source_kind,manifest_digest,jsonb(safe_manifest)))
            self.c.execute("""INSERT INTO p24_next.foundation_source_receipt
                (namespace_id,receipt_id,snapshot_id,source_digest,manifest_sha256,received_at,receipt_time_basis,
                 disposition,input_bytes,row_count,interval_start,interval_end)
                VALUES(%s,%s,%s,%s,%s,%s,%s,'accepted',%s,%s,%s,%s)""",
                (self.namespace_id,receipt_id,snapshot_id,digest,manifest_digest,observed,receive_time_basis,
                 len(batch.original),len(normalized),start.floor,end.floor))
            if isinstance(coverage.get("acquisition"),dict):
                assessment=coverage["acquisition"]
                self.c.execute("""INSERT INTO p24_next.foundation_acquisition_assessment
                    (namespace_id,snapshot_id,assessment_version,source_digest,capture_claim_state,
                     query_traversal_complete,source_window_complete,assessment)
                    VALUES(%s,%s,%s,%s,'unverified_local_capture',%s,false,%s)""",
                    (self.namespace_id,snapshot_id,assessment["contract_version"],digest,
                     assessment["query_traversal_complete"],jsonb(assessment)))
            request_keys = {e["request_key"] for e in normalized} - {None}
            execute_many(self.c, "INSERT INTO p24_next.logical_request(namespace_id,request_key,key_version) VALUES(%s,%s,%s) ON CONFLICT DO NOTHING", [(self.namespace_id, q, self.keys.version) for q in sorted(request_keys)])
            session_keys = {s for e in normalized for s in e["descriptor"]["session_candidates"]}
            execute_many(self.c, "INSERT INTO p24_next.user_session(namespace_id,session_key,key_version) VALUES(%s,%s,%s) ON CONFLICT DO NOTHING", [(self.namespace_id, s, self.keys.version) for s in sorted(session_keys)])
            unique = {e["event_version_id"]: e for e in normalized}
            execute_many(self.c, "INSERT INTO p24_next.event_identity(namespace_id,event_key,identity_kind,identity_contract_version) VALUES(%s,%s,%s,'origin-index-id.1') ON CONFLICT DO NOTHING", [(self.namespace_id,e["event_key"],e["identity_kind"]) for e in unique.values()])
            execute_many(self.c, """INSERT INTO p24_next.event_version(namespace_id,event_version_id,event_key,content_sha256,source_event_time,timestamp_precision,request_key,source_role,endpoint,event_kind,received_at,source_time_epoch_ns,source_time_fraction_digits)
                VALUES(%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s) ON CONFLICT DO NOTHING""",
                [(self.namespace_id,e["event_version_id"],e["event_key"],e["content_digest"],e["time"].floor if e["time"] else None,e["time"].precision if e["time"] else "unknown",e["request_key"],e["descriptor"]["role"],e["descriptor"]["endpoint"],e["descriptor"]["event_kind"],observed,str(e["time"].epoch_ns) if e["time"] else None,e["time"].fraction_digits if e["time"] else None) for e in unique.values()])
            execute_many(self.c, "INSERT INTO p24_next.foundation_event_descriptor(namespace_id,event_version_id,extraction_version,descriptor) VALUES(%s,%s,%s,%s) ON CONFLICT DO NOTHING",
                         [(self.namespace_id,e["event_version_id"],PARSER_VERSION,jsonb(e["payload"])) for e in unique.values()])
            execute_many(self.c, "INSERT INTO p24_next.foundation_row_membership VALUES(%s,%s,%s,%s)", [(self.namespace_id,snapshot_id,i,e["event_version_id"]) for i,e in enumerate(normalized)])
            first_ordinals = {}
            for i, event in enumerate(normalized):
                first_ordinals.setdefault(event["event_version_id"], i)
            execute_many(self.c, "INSERT INTO p24_next.event_source VALUES(%s,%s,%s,%s,0,%s)", [(self.namespace_id,snapshot_id,v,object_id,ordinal) for v,ordinal in first_ordinals.items()])
            request_rows = Counter(e["request_key"] for e in normalized if e["request_key"])
            request_versions = defaultdict(set)
            for e in normalized:
                if e["request_key"]:
                    request_versions[e["request_key"]].add(e["event_version_id"])
            execute_many(self.c, "INSERT INTO p24_next.request_source VALUES(%s,%s,%s,%s,%s)", [(self.namespace_id,q,snapshot_id,count,len(request_versions[q])) for q,count in request_rows.items()])
            operations, links, facts = [], [], []
            for event in unique.values():
                descriptor, request = event["descriptor"], event["request_key"]
                if request is None:
                    continue
                operation_key = None
                if descriptor["event_kind"] != "client_completion":
                    operation_key = self.keys.token(self.namespace,"operation_observation",event["event_key"])
                    operations.append((self.namespace_id,request,operation_key,"unresolved_observation"))
                    links.append((self.namespace_id,operation_key,event["event_version_id"],"same_origin_observation"))
                items = []
                for observation in descriptor["session_observations"]:
                    items.append(("session_candidate",observation["path"],observation["direction"],"personal",None,observation["token"]))
                if descriptor["ip_key"]:
                    items.append(("ip_context","metadata.IP","metadata","personal",None,descriptor["ip_key"]))
                if descriptor["client_context"]:
                    items.append(("reported_client_context","SQL.Parameters.userAgent.parsed","sql_parameter","operational",descriptor["client_context"],None))
                items.append(("coverage","extraction.coverage","metadata","operational",dict(issues=descriptor["issues"],session_state=descriptor["structured_session_state"],output=descriptor["output_coverage"]),None))
                if descriptor["secret_fields_present"]:
                    items.append(("secret_presence","SQL.Parameters.secret_presence","metadata","operational",descriptor["secret_fields_present"],None))
                for observation in descriptor["outcomes"]:
                    items.append(("outcome",observation["path"],"output","operational",observation,None))
                for i,(kind,path,direction,sensitivity,value,token) in enumerate(items):
                    fact_id = stable_id(str(event["event_version_id"]),kind,path,i)
                    facts.append((self.namespace_id,fact_id,event["event_version_id"],request,operation_key,kind,path,direction,sensitivity,jsonb(value) if value is not None else None,token,self.keys.version if token else None,PARSER_VERSION,"complete"))
            execute_many(self.c, "INSERT INTO p24_next.operation_identity VALUES(%s,%s,%s,%s) ON CONFLICT DO NOTHING", operations)
            execute_many(self.c, "INSERT INTO p24_next.operation_event VALUES(%s,%s,%s,%s) ON CONFLICT DO NOTHING", links)
            execute_many(self.c, "INSERT INTO p24_next.extracted_fact(namespace_id,fact_id,event_version_id,request_key,operation_key,fact_key,field_path,direction,sensitivity,public_value,equality_token,token_key_version,extraction_version,completeness) VALUES(%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s) ON CONFLICT DO NOTHING", facts)
        return dict(snapshot_id=str(snapshot_id), receipt_id=str(receipt_id), reused=False, records=len(normalized),
                    unique_event_versions=len(unique), coverage=coverage, manifest_sha256=manifest_digest)

    def replace_source_snapshot(self, prior_snapshot_id, replacement_snapshot_id, *, expected_prior_revision, reason_key, declared_by):
        """Record an explicit, append-only source correction; never mutates old runs."""
        try:
            prior, replacement = uuid.UUID(str(prior_snapshot_id)), uuid.UUID(str(replacement_snapshot_id))
        except (ValueError, TypeError, AttributeError):
            raise FoundationError("invalid_source_reference") from None
        if prior == replacement or isinstance(expected_prior_revision, bool) or not isinstance(expected_prior_revision, int) or expected_prior_revision < 1:
            raise FoundationError("invalid_source_replacement")
        if reason_key not in {"corrected_export", "late_evidence_supersedes_partial", "producer_reissued", "operator_reconciled"}:
            raise FoundationError("invalid_replacement_reason")
        if not isinstance(declared_by, str) or not re.fullmatch(r"[A-Za-z0-9_.@:-]{1,100}", declared_by):
            raise FoundationError("invalid_operator_claim")
        with self.c.transaction():
            self._lock()
            old = self.c.execute("SELECT window_key,intake_revision FROM p24_next.source_snapshot WHERE namespace_id=%s AND snapshot_id=%s FOR UPDATE", (self.namespace_id, prior)).fetchone()
            new = self.c.execute("SELECT window_key,intake_revision FROM p24_next.source_snapshot WHERE namespace_id=%s AND snapshot_id=%s FOR SHARE", (self.namespace_id, replacement)).fetchone()
            if not old or not new:
                raise FoundationError("source_not_available")
            if old[0] != new[0] or old[1] != expected_prior_revision or new[1] <= old[1]:
                raise FoundationError("source_replacement_revision_conflict")
            if self.c.execute("SELECT 1 FROM p24_next.foundation_source_replacement WHERE namespace_id=%s AND (prior_snapshot_id=%s OR replacement_snapshot_id=%s)", (self.namespace_id, prior, replacement)).fetchone():
                raise FoundationError("source_revision_already_linked")
            revision_id = uuid.uuid4()
            try:
                self.c.execute("INSERT INTO p24_next.foundation_source_replacement(namespace_id,revision_id,prior_snapshot_id,replacement_snapshot_id,prior_intake_revision,replacement_intake_revision,reason_key,declared_by) VALUES(%s,%s,%s,%s,%s,%s,%s,%s)", (self.namespace_id,revision_id,prior,replacement,old[1],new[1],reason_key,declared_by))
            except Exception:
                raise FoundationError("source_replacement_rejected") from None
        return dict(revision_id=str(revision_id),prior_snapshot_id=str(prior),replacement_snapshot_id=str(replacement),generation=int(new[1]),reason_key=reason_key,assertion="operator_declared_not_producer_verified",prior_runs_unchanged=True)

    def _resolve_source_vector(self, requested):
        """Supersede only explicitly linked ancestors present in this vector."""
        rows = self.c.execute("""WITH RECURSIVE ancestry(descendant,ancestor,depth) AS (
              SELECT r.replacement_snapshot_id,r.prior_snapshot_id,1 FROM p24_next.foundation_source_replacement r
              WHERE r.namespace_id=%s AND r.replacement_snapshot_id=ANY(%s)
              UNION ALL
              SELECT a.descendant,r.prior_snapshot_id,a.depth+1 FROM ancestry a
              JOIN p24_next.foundation_source_replacement r ON r.namespace_id=%s AND r.replacement_snapshot_id=a.ancestor
              WHERE a.depth<128
            )
            SELECT ancestor,descendant,depth FROM ancestry WHERE ancestor=ANY(%s)
            ORDER BY ancestor,depth DESC,descendant""", (self.namespace_id,requested,self.namespace_id,requested)).fetchall()
        replacements = {}
        for ancestor,descendant,_depth in rows:
            replacements.setdefault(ancestor,descendant)
        choices = {s:("replaced_by_selected_descendant", replacements[s]) for s in requested if s in replacements}
        effective = sorted(set(requested)-set(choices))
        if not effective:
            raise FoundationError("source_replacement_vector_empty")
        return effective,choices

    def _access(self, run_id, object_kind, token, *, principal, purpose="test"):
        if purpose not in {"run_inspection","request_investigation","session_investigation","registration_review","evidence_page","test"}:
            raise FoundationError("invalid_access_purpose")
        if not isinstance(principal,str) or not re.fullmatch(r"[A-Za-z0-9_.@:-]{1,100}",principal):
            raise FoundationError("invalid_operator_claim")
        self.c.execute("INSERT INTO p24_next.foundation_access_audit(namespace_id,run_id,principal_claim,authentication_state,purpose_key,object_kind,object_token) VALUES(%s,%s,%s,'verified_signed_credential',%s,%s,%s)", (self.namespace_id,run_id,principal,purpose,object_kind,token))

    def _authorize_access(self, action, resource_kind, resource_value, access_token):
        resource_key = self.keys.token(self.namespace, "access_resource", [resource_kind, resource_value])
        credential = self.keys.token(self.namespace, "access_credential_attempt", access_token) if isinstance(access_token, str) and access_token else None
        principal = None
        try:
            if self.access_policy is None:
                raise FoundationError("access_policy_not_configured")
            verified = self.access_policy.authorize(access_token, action)
            principal = self.keys.token(self.namespace, "principal", verified.subject)
            auth_state, decision, reason = "verified", "allowed", "authorized"
        except FoundationError as exc:
            code = exc.code
            auth_state, decision = {
                "access_policy_not_configured": ("policy_unavailable", "denied"),
                "access_credential_expired": ("expired", "denied"),
                "access_namespace_mismatch": ("misbound", "denied"),
                "access_role_insufficient": ("role_insufficient", "denied"),
            }.get(code, ("missing" if not access_token else "invalid", "denied"))
            reason = {
                "policy_unavailable": "policy_unavailable", "expired": "expired_credential",
                "misbound": "wrong_namespace", "role_insufficient": "insufficient_role",
                "missing": "missing_credential", "invalid": "invalid_credential",
            }[auth_state]
            self.c.execute("""INSERT INTO p24_next.foundation_access_decision
                (namespace_id,principal_key,credential_fingerprint,action_key,resource_kind,resource_key,
                 authentication_state,decision,reason_key,policy_version)
                VALUES(%s,NULL,%s,%s,%s,%s,%s,%s,%s,%s)""",
                (self.namespace_id, credential, action, resource_kind, resource_key, auth_state, decision, reason, POLICY_VERSION))
            raise FoundationError("access_denied") from None
        self.c.execute("""INSERT INTO p24_next.foundation_access_decision
            (namespace_id,principal_key,credential_fingerprint,action_key,resource_kind,resource_key,
             authentication_state,decision,reason_key,policy_version)
            VALUES(%s,%s,%s,%s,%s,%s,'verified','allowed','authorized',%s)""",
            (self.namespace_id, principal, credential, action, resource_kind, resource_key, POLICY_VERSION))
        return verified, principal

    def place_evidence_hold(self, snapshot_id, *, reason, access_token, reference=None):
        """Place an append-only hold. No release or deletion path is enabled."""
        try:
            snapshot = uuid.UUID(str(snapshot_id))
        except (ValueError, TypeError, AttributeError):
            raise FoundationError("invalid_snapshot_reference") from None
        if not isinstance(reason,str) or reason not in {"incident_review", "security_investigation", "legal_preservation", "regulatory_preservation", "operator_request", "other"}:
            raise FoundationError("invalid_preservation_reason")
        if reference is not None and (not isinstance(reference,str) or len(reference)>200):
            raise FoundationError("invalid_preservation_reference")
        _, principal = self._authorize_access("place_hold", "source_snapshot", snapshot, access_token)
        if not self.c.execute("SELECT 1 FROM p24_next.source_snapshot WHERE namespace_id=%s AND snapshot_id=%s", (self.namespace_id, snapshot)).fetchone():
            raise FoundationError("snapshot_not_available")
        reference_key = self.keys.token(self.namespace, "hold_reference", reference) if reference else None
        row = self.c.execute("""INSERT INTO p24_next.foundation_evidence_hold
            (namespace_id,snapshot_id,reason_key,reference_key,placed_by_key)
            VALUES(%s,%s,%s,%s,%s) RETURNING hold_id""",
            (self.namespace_id, snapshot, reason, reference_key, principal)).fetchone()
        return dict(hold_id=str(row[0]), snapshot_id=str(snapshot), reason=reason,
                    state="active_indefinitely", release_workflow="not_implemented", evidence_deleted=False)

    def enqueue_projection(self, source_ids, *, event_cutoff, knowledge_at, mode, dedupe_key):
        if mode not in {"online_original","historical_revised"}:
            raise FoundationError("invalid_projection_mode")
        if not isinstance(dedupe_key,str) or not re.fullmatch(r"[A-Za-z0-9_.:-]{1,200}",dedupe_key):
            raise FoundationError("invalid_work_deduplication_key")
        try:
            sources=sorted({str(uuid.UUID(str(x))) for x in source_ids})
        except (ValueError,TypeError,AttributeError):
            raise FoundationError("invalid_source_vector") from None
        if not 1<=len(sources)<=MAX_SOURCES:
            raise FoundationError("source_vector_limit")
        cutoff,known=microsecond_cutoff(event_cutoff),microsecond_cutoff(knowledge_at)
        payload=dict(source_snapshot_ids=sources,event_cutoff_ns=str(cutoff.epoch_ns),knowledge_at_ns=str(known.epoch_ns),mode=mode)
        token=self.keys.token(self.namespace,"work_dedupe",dedupe_key).split(":")[-1]
        work_id=stable_id(self.namespace,"project_sources",token)
        with self.c.transaction():
            self._lock()
            if self.c.execute("SELECT count(*) FROM p24_next.source_snapshot WHERE namespace_id=%s AND snapshot_id=ANY(%s)",(self.namespace_id,[uuid.UUID(x) for x in sources])).fetchone()[0]!=len(sources):
                raise FoundationError("source_vector_not_in_namespace")
            existing=self.c.execute("SELECT work_id,payload,state FROM p24_next.foundation_work_item WHERE namespace_id=%s AND work_kind='project_sources' AND dedupe_token=%s",(self.namespace_id,token)).fetchone()
            if existing:
                if existing[1]!=payload:raise FoundationError("work_deduplication_collision")
                return dict(work_id=str(existing[0]),state=existing[2],reused=True,payload=payload)
            self.c.execute("INSERT INTO p24_next.foundation_work_item(namespace_id,work_id,work_kind,dedupe_token,payload) VALUES(%s,%s,'project_sources',%s,%s)",(self.namespace_id,work_id,token,jsonb(payload)))
        return dict(work_id=str(work_id),state="pending",reused=False,payload=payload)

    def claim_work(self, worker, *, limit=1, lease_seconds=60):
        if not isinstance(worker,str) or not re.fullmatch(r"[A-Za-z0-9_.:-]{1,100}",worker):raise FoundationError("invalid_worker_claim")
        if isinstance(limit,bool) or not isinstance(limit,int) or not 1<=limit<=32:raise FoundationError("invalid_work_batch_size")
        if isinstance(lease_seconds,bool) or not isinstance(lease_seconds,int) or not 10<=lease_seconds<=300:raise FoundationError("invalid_lease_duration")
        claimed=[]
        with self.c.transaction():
            exhausted=self.c.execute("""UPDATE p24_next.foundation_work_item SET state='dead',lease_owner=NULL,lease_until=NULL,updated_at=clock_timestamp(),last_error_code='attempt_limit'
                WHERE namespace_id=%s AND attempt_count>=8 AND ((state IN ('pending','retry') AND available_at<=clock_timestamp()) OR (state='leased' AND lease_until<=clock_timestamp()))
                RETURNING work_id,lease_generation,lease_owner""",(self.namespace_id,)).fetchall()
            for row in exhausted:
                self.c.execute("INSERT INTO p24_next.foundation_work_attempt(namespace_id,work_id,lease_generation,action,worker_claim,error_code) VALUES(%s,%s,%s,'lease_exhausted',%s,'attempt_limit')",(self.namespace_id,row[0],row[1],row[2]))
            rows=self.c.execute("""WITH pick AS (
                SELECT work_id FROM p24_next.foundation_work_item WHERE namespace_id=%s AND attempt_count<8
                AND ((state IN ('pending','retry') AND available_at<=clock_timestamp()) OR (state='leased' AND lease_until<=clock_timestamp()))
                ORDER BY event_cutoff_ns,available_at,created_at,work_id FOR UPDATE SKIP LOCKED LIMIT %s
              ) UPDATE p24_next.foundation_work_item w SET state='leased',attempt_count=w.attempt_count+1,
                lease_generation=w.lease_generation+1,lease_owner=%s,lease_until=clock_timestamp()+(%s*interval '1 second'),updated_at=clock_timestamp()
              FROM pick WHERE w.namespace_id=%s AND w.work_id=pick.work_id
              RETURNING w.work_id,w.work_kind,w.payload,w.attempt_count,w.lease_generation,w.lease_until""",(self.namespace_id,limit,worker,lease_seconds,self.namespace_id)).fetchall()
            for row in rows:
                self.c.execute("INSERT INTO p24_next.foundation_work_attempt(namespace_id,work_id,lease_generation,action,worker_claim) VALUES(%s,%s,%s,'claimed',%s)",(self.namespace_id,row[0],row[4],worker))
                claimed.append(dict(work_id=str(row[0]),work_kind=row[1],payload=row[2],attempt=row[3],lease_generation=row[4],lease_until=row[5].astimezone(timezone.utc).isoformat(),worker=worker))
        return claimed

    def renew_work(self, work_id, worker, lease_generation, *, lease_seconds=60):
        return self._change_work_lease(work_id,worker,lease_generation,lease_seconds=lease_seconds,action="renewed")

    def _change_work_lease(self, work_id, worker, lease_generation, *, lease_seconds, action):
        try:wid=uuid.UUID(str(work_id))
        except (ValueError,TypeError,AttributeError):raise FoundationError("invalid_work_reference") from None
        if not isinstance(worker,str) or not re.fullmatch(r"[A-Za-z0-9_.:-]{1,100}",worker):raise FoundationError("invalid_worker_claim")
        if isinstance(lease_generation,bool) or not isinstance(lease_generation,int) or lease_generation<1:raise FoundationError("invalid_lease_generation")
        if isinstance(lease_seconds,bool) or not isinstance(lease_seconds,int) or not 10<=lease_seconds<=300:raise FoundationError("invalid_lease_duration")
        with self.c.transaction():
            row=self.c.execute("UPDATE p24_next.foundation_work_item SET lease_until=clock_timestamp()+(%s*interval '1 second'),updated_at=clock_timestamp() WHERE namespace_id=%s AND work_id=%s AND state='leased' AND lease_owner=%s AND lease_generation=%s AND lease_until>clock_timestamp() RETURNING work_id",(lease_seconds,self.namespace_id,wid,worker,lease_generation)).fetchone()
            if not row:return False
            self.c.execute("INSERT INTO p24_next.foundation_work_attempt(namespace_id,work_id,lease_generation,action,worker_claim) VALUES(%s,%s,%s,%s,%s)",(self.namespace_id,wid,lease_generation,action,worker))
        return True

    def complete_work(self, work_id, worker, lease_generation, result_run_id):
        try:wid=uuid.UUID(str(work_id))
        except (ValueError,TypeError,AttributeError):raise FoundationError("invalid_work_reference") from None
        if not isinstance(worker,str) or not re.fullmatch(r"[A-Za-z0-9_.:-]{1,100}",worker):raise FoundationError("invalid_worker_claim")
        if isinstance(lease_generation,bool) or not isinstance(lease_generation,int) or lease_generation<1:raise FoundationError("invalid_lease_generation")
        result_id=self._sealed(result_run_id)
        with self.c.transaction():
            item=self.c.execute("SELECT payload FROM p24_next.foundation_work_item WHERE namespace_id=%s AND work_id=%s AND state='leased' AND lease_owner=%s AND lease_generation=%s AND lease_until>clock_timestamp() FOR UPDATE",(self.namespace_id,wid,worker,lease_generation)).fetchone()
            if not item:return False
            payload=item[0]
            run=self.c.execute("SELECT event_cutoff,knowledge_snapshot_at,mode FROM p24_next.projection_run WHERE namespace_id=%s AND run_id=%s AND state='sealed'",(self.namespace_id,result_id)).fetchone()
            if not run:raise FoundationError("work_result_not_sealed")
            expected=(floor_ns(int(payload["event_cutoff_ns"])),floor_ns(int(payload["knowledge_at_ns"])),payload["mode"])
            actual_sources=[str(row[0]) for row in self.c.execute("SELECT snapshot_id FROM p24_next.foundation_projection_source_choice WHERE namespace_id=%s AND run_id=%s ORDER BY snapshot_id",(self.namespace_id,result_id)).fetchall()]
            if run!=expected or actual_sources!=payload["source_snapshot_ids"]:
                raise FoundationError("work_result_input_mismatch")
            if self.c.execute("SELECT 1 FROM p24_next.foundation_projection_request_scope WHERE namespace_id=%s AND run_id=%s LIMIT 1",(self.namespace_id,result_id)).fetchone():
                raise FoundationError("work_result_input_mismatch")
            row=self.c.execute("UPDATE p24_next.foundation_work_item SET state='completed',result_run_id=%s,lease_owner=NULL,lease_until=NULL,updated_at=clock_timestamp() WHERE namespace_id=%s AND work_id=%s AND state='leased' AND lease_owner=%s AND lease_generation=%s AND lease_until>clock_timestamp() RETURNING work_id",(result_id,self.namespace_id,wid,worker,lease_generation)).fetchone()
            if not row:return False
            self.c.execute("INSERT INTO p24_next.foundation_work_attempt(namespace_id,work_id,lease_generation,action,worker_claim) VALUES(%s,%s,%s,'completed',%s)",(self.namespace_id,wid,lease_generation,worker))
        return True

    def fail_work(self, work_id, worker, lease_generation, *, error_code, retryable=True, delay_seconds=30):
        try:wid=uuid.UUID(str(work_id))
        except (ValueError,TypeError,AttributeError):raise FoundationError("invalid_work_reference") from None
        if not isinstance(worker,str) or not re.fullmatch(r"[A-Za-z0-9_.:-]{1,100}",worker):raise FoundationError("invalid_worker_claim")
        if isinstance(lease_generation,bool) or not isinstance(lease_generation,int) or lease_generation<1:raise FoundationError("invalid_lease_generation")
        if not isinstance(error_code,str) or not re.fullmatch(r"[a-z0-9_]{1,80}",error_code):raise FoundationError("invalid_work_error_code")
        if type(retryable) is not bool or isinstance(delay_seconds,bool) or not isinstance(delay_seconds,int) or not 0<=delay_seconds<=3600:raise FoundationError("invalid_retry_policy")
        with self.c.transaction():
            row=self.c.execute("""UPDATE p24_next.foundation_work_item SET state=CASE WHEN %s AND attempt_count<8 THEN 'retry' ELSE 'dead' END,
                available_at=clock_timestamp()+(%s*interval '1 second'),lease_owner=NULL,lease_until=NULL,updated_at=clock_timestamp(),last_error_code=%s
                WHERE namespace_id=%s AND work_id=%s AND state='leased' AND lease_owner=%s AND lease_generation=%s AND lease_until>clock_timestamp()
                RETURNING state""",(retryable,delay_seconds,error_code,self.namespace_id,wid,worker,lease_generation)).fetchone()
            if not row:return False
            action="retry_scheduled" if row[0]=="retry" else "dead_lettered"
            self.c.execute("INSERT INTO p24_next.foundation_work_attempt(namespace_id,work_id,lease_generation,action,worker_claim,error_code) VALUES(%s,%s,%s,%s,%s,%s)",(self.namespace_id,wid,lease_generation,action,worker,error_code))
        return row[0]

    def project(self, source_ids, *, event_cutoff, knowledge_at, mode="design_fixture", association_horizon_seconds=300,
                request_keys=None):
        if mode not in {"design_fixture","online_original","historical_revised"}:
            raise FoundationError("invalid_projection_mode")
        if isinstance(association_horizon_seconds, bool) or not isinstance(association_horizon_seconds,int) or not 0 <= association_horizon_seconds <= 3600:
            raise FoundationError("invalid_association_search_horizon")
        cutoff, known = microsecond_cutoff(event_cutoff), microsecond_cutoff(knowledge_at)
        try:
            source_ids = sorted({uuid.UUID(str(s)) for s in source_ids})
        except (TypeError, ValueError, AttributeError):
            raise FoundationError("invalid_source_vector") from None
        if not 1 <= len(source_ids) <= MAX_SOURCES:
            raise FoundationError("source_vector_limit")
        scope = None
        if request_keys is not None:
            try:
                scope=sorted(set(request_keys))
            except (TypeError,ValueError):
                raise FoundationError("invalid_request_scope") from None
            pattern=r"request:"+re.escape(self.keys.version)+r":[a-f0-9]{64}"
            if not 1<=len(scope)<=MAX_PROJECTION_EVENTS or any(not isinstance(q,str) or not re.fullmatch(pattern,q) for q in scope):
                raise FoundationError("invalid_request_scope")
        with self.c.transaction():
            self._lock()
            if scope is not None and self.c.execute("SELECT count(*) FROM p24_next.logical_request WHERE namespace_id=%s AND request_key=ANY(%s)",(self.namespace_id,scope)).fetchone()[0]!=len(scope):
                raise FoundationError("request_scope_not_in_namespace")
            sources = self.c.execute("""SELECT s.snapshot_id,s.source_digest,s.observed_at,m.coverage,m.receive_time_basis
                FROM p24_next.source_snapshot s JOIN p24_next.foundation_snapshot_metadata m USING(namespace_id,snapshot_id)
                WHERE s.namespace_id=%s AND s.snapshot_id=ANY(%s) ORDER BY s.snapshot_id""", (self.namespace_id,source_ids)).fetchall()
            if len(sources) != len(source_ids):
                raise FoundationError("source_vector_not_in_namespace")
            if mode != "design_fixture" and any(s[2] > known.floor for s in sources):
                raise FoundationError("source_not_known_at_snapshot")
            effective_source_ids, source_replacements = self._resolve_source_vector(source_ids)
            effective_sources = [s for s in sources if s[0] in effective_source_ids]
            if len(effective_sources) != len(effective_source_ids):
                raise FoundationError("source_vector_resolution_failed")
            manifest = dict(requested_sources=[dict(snapshot_id=str(s[0]),digest=s[1]) for s in sources],
                            sources=[dict(snapshot_id=str(s[0]),digest=s[1]) for s in effective_sources],
                            superseded=[dict(snapshot_id=str(old),replacement_snapshot_id=str(new)) for old,new in sorted(source_replacements.items())],
                            event_cutoff=str(cutoff.epoch_ns), knowledge_at=str(known.epoch_ns),mode=mode,
                            extraction=PARSER_VERSION,resolver=RESOLVER_VERSION,privacy=PRIVACY_VERSION,
                            catalog=self.catalog.digest,key_version=self.keys.version,
                            candidate_search_seconds=association_horizon_seconds)
            if scope is not None:
                manifest["request_scope"]=scope
            manifest_digest = hashlib.sha256(canonical(manifest)).hexdigest()
            run_id = stable_id(self.namespace,"run",manifest_digest)
            existing = self.c.execute("SELECT state FROM p24_next.projection_run WHERE namespace_id=%s AND run_id=%s",(self.namespace_id,run_id)).fetchone()
            if existing:
                if existing[0] != "sealed":
                    raise FoundationError("existing_projection_not_sealed")
                return self._run_info(run_id)
            rows = self._projection_event_rows(effective_source_ids,scope)
            if len(rows) > MAX_PROJECTION_EVENTS:
                raise FoundationError("projection_event_limit")
            events = [dict(event_key=r[0],event_version_id=r[1],content_digest=r[2],identity_kind=r[3],payload=r[5]) for r in rows if mode == "design_fixture" or r[4] <= known.floor]
            selection = select_events(events,cutoff.epoch_ns)
            summaries = reconstruct(selection)
            scope_set=set(scope) if scope is not None else None
            if scope_set is not None and any(s["request_key"] not in scope_set for s in summaries):
                raise FoundationError("request_scope_not_closed")
            candidates,truncated_candidates = ([],[]) if scope is not None else registration_candidates(summaries,horizon_seconds=association_horizon_seconds)
            self.c.execute("INSERT INTO p24_next.projection_run(namespace_id,run_id,mode,event_cutoff,knowledge_snapshot_at,taxonomy_id,resolver_version,privacy_version,input_manifest_sha256) VALUES(%s,%s,%s,%s,%s,%s,%s,%s,%s)",
                (self.namespace_id,run_id,mode,cutoff.floor,known.floor,self.taxonomy_id,RESOLVER_VERSION,PRIVACY_VERSION,manifest_digest))
            if scope is not None:
                execute_many(self.c,"INSERT INTO p24_next.foundation_projection_request_scope VALUES(%s,%s,%s)",[(self.namespace_id,run_id,q) for q in scope])
            execute_many(self.c,"INSERT INTO p24_next.projection_source VALUES(%s,%s,%s)",[(self.namespace_id,run_id,s) for s in effective_source_ids])
            choice_rows=[]
            for snapshot_id in source_ids:
                if snapshot_id in source_replacements:
                    _choice,replacement_id=source_replacements[snapshot_id]
                    choice_rows.append((self.namespace_id,run_id,snapshot_id,"replaced_by_selected_descendant",replacement_id))
                else:
                    choice_rows.append((self.namespace_id,run_id,snapshot_id,"included",None))
            execute_many(self.c,"INSERT INTO p24_next.foundation_projection_source_choice(namespace_id,run_id,snapshot_id,choice,replaced_by_snapshot_id,reason_key) VALUES(%s,%s,%s,%s,%s,CASE WHEN %s='replaced_by_selected_descendant' THEN 'explicit_source_replacement' ELSE NULL END)",[(n,r,ss,ch,by,ch) for n,r,ss,ch,by in choice_rows])
            selected_rows = [(self.namespace_id,run_id,e["event_key"],e["event_version_id"],"selected","compatible_origin_and_cutoff") for e in selection["selected"]]
            selected_rows.extend((self.namespace_id,run_id,item["event_key"],None,state,item["reason"]) for state,key in (("ambiguous","ambiguous"),("unavailable","unavailable")) for item in selection[key])
            execute_many(self.c,"INSERT INTO p24_next.projection_event VALUES(%s,%s,%s,%s,%s,%s)",selected_rows)
            request_rows=[]
            for summary in summaries:
                request_rows.append((self.namespace_id,run_id,summary["request_key"],summary["session_key"],summary["identity_state"],floor_ns(summary["activity_time_ns"]) if summary["activity_time_ns"] else None,uuid.UUID(summary["client_event_version_id"]) if summary["client_event_version_id"] else None,summary["client_completion_state"],"unknown",summary["classification"]["phase"],summary["classification"]["state"],summary["final_outcome"],summary["outcome_code"],floor_ns(summary["first_time_ns"]) if summary["first_time_ns"] else None,floor_ns(summary["last_time_ns"]) if summary["last_time_ns"] else None))
            execute_many(self.c,"INSERT INTO p24_next.request_projection(namespace_id,run_id,request_key,session_key,identity_state,activity_time,client_event_version_id,client_completion_state,initiation,phase_key,classification_state,final_outcome,outcome_code,first_observed_event_at,last_observed_event_at) VALUES(%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)",request_rows)
            execute_many(self.c,"INSERT INTO p24_next.foundation_request_summary VALUES(%s,%s,%s,%s)",[(self.namespace_id,run_id,s["request_key"],jsonb(s)) for s in summaries])
            ops=[(self.namespace_id,run_id,s["request_key"],self.keys.token(self.namespace,"operation_observation",op["event_key"]),op["role"],op["endpoint"] or "unknown",op["outcome"],"observed_only") for s in summaries for op in s["operations"]]
            execute_many(self.c,"INSERT INTO p24_next.operation_projection(namespace_id,run_id,request_key,operation_key,source_role,endpoint,outcome,chain_coverage) VALUES(%s,%s,%s,%s,%s,%s,%s,%s)",ops)
            self.c.execute("""INSERT INTO p24_next.projection_fact(namespace_id,run_id,request_key,fact_id,use_kind)
                SELECT f.namespace_id,%s,f.request_key,f.fact_id,f.fact_key FROM p24_next.extracted_fact f
                JOIN p24_next.projection_event pe ON pe.namespace_id=f.namespace_id AND pe.event_version_id=f.event_version_id
                JOIN p24_next.request_projection rp ON rp.namespace_id=f.namespace_id AND rp.request_key=f.request_key AND rp.run_id=pe.run_id
                WHERE pe.namespace_id=%s AND pe.run_id=%s AND pe.selection_state='selected'""",(run_id,self.namespace_id,run_id))
            execute_many(self.c,"INSERT INTO p24_next.foundation_registration_candidate VALUES(%s,%s,%s,%s,%s,%s)",[(self.namespace_id,run_id,c["registration_request_key"],c["session_key"],c["support_request_key"],jsonb(c["basis"])) for c in candidates])
            # Explicit source/input coverage is available from immutable metadata;
            # no production current head or source-complete flag is fabricated.
            if truncated_candidates:
                raise FoundationError("candidate_result_limit_requires_narrower_scope")
            self.c.execute("UPDATE p24_next.projection_run SET state='sealed' WHERE namespace_id=%s AND run_id=%s",(self.namespace_id,run_id))
        return self._run_info(run_id)

    def _projection_event_rows(self, sources, scope):
        # Deduplicate compact version IDs before joining JSON descriptors.
        # Materialization also prevents repeated source/scope subquery scans.
        ctes="""WITH selected_versions AS MATERIALIZED (
            SELECT DISTINCT event_version_id FROM p24_next.event_source
            WHERE namespace_id=%s AND snapshot_id=ANY(%s))"""
        args=[self.namespace_id,sources]
        scope_join=""
        if scope is not None:
            # Keep all selected variants of a matching origin, including
            # variants whose conflicting RequestID is outside this scope.
            ctes+=""", scoped_origins AS MATERIALIZED (
                SELECT DISTINCT v.event_key FROM selected_versions ids
                JOIN p24_next.event_version v ON v.namespace_id=%s AND v.event_version_id=ids.event_version_id
                WHERE v.request_key=ANY(%s))"""
            args.extend([self.namespace_id,scope])
            scope_join=" JOIN scoped_origins origins ON origins.event_key=ev.event_key"
        args.extend([self.namespace_id,MAX_PROJECTION_EVENTS+1])
        return self.c.execute(ctes+"""
            SELECT ev.event_key,ev.event_version_id,ev.content_sha256,ei.identity_kind,ev.received_at,fd.descriptor
            FROM selected_versions ids
            JOIN p24_next.event_version ev ON ev.namespace_id=%s AND ev.event_version_id=ids.event_version_id
            JOIN p24_next.event_identity ei ON ei.namespace_id=ev.namespace_id AND ei.event_key=ev.event_key
            JOIN p24_next.foundation_event_descriptor fd ON fd.namespace_id=ev.namespace_id AND fd.event_version_id=ev.event_version_id
            """+scope_join+" ORDER BY ev.event_key,ev.event_version_id LIMIT %s",args).fetchall()

    def _sealed(self, run_id):
        try:
            run_id=uuid.UUID(str(run_id))
        except (ValueError,AttributeError,TypeError):
            raise FoundationError("invalid_run_reference") from None
        row=self.c.execute("SELECT state FROM p24_next.projection_run WHERE namespace_id=%s AND run_id=%s",(self.namespace_id,run_id)).fetchone()
        if not row or row[0] != "sealed":
            raise FoundationError("run_not_available")
        return run_id

    def run_info(self, run_id, *, access_token=None):
        """Return run/source coverage only after an investigator read check."""
        _, principal = self._authorize_access("read_run", "projection_run", run_id, access_token)
        checked_run = self._sealed(run_id)
        self._access(checked_run, "projection_run", self.keys.token(self.namespace, "run_resource", str(checked_run)),
                     principal=principal, purpose="run_inspection")
        return self._run_info(checked_run)

    def _run_info(self, run_id):
        run_id=self._sealed(run_id)
        row=self.c.execute("SELECT mode,event_cutoff,knowledge_snapshot_at,input_manifest_sha256 FROM p24_next.projection_run WHERE namespace_id=%s AND run_id=%s",(self.namespace_id,run_id)).fetchone()
        totals=self.c.execute("""SELECT count(*),coalesce(sum((summary->>'distinct_client_request_count')::int),0),
            coalesce(sum((summary->>'selected_event_count')::int),0),coalesce(sum((summary->>'sql_observation_count')::int),0),
            coalesce(sum((summary->>'provider_observation_count')::int),0),count(DISTINCT summary->>'session_key')
            FROM p24_next.foundation_request_summary WHERE namespace_id=%s AND run_id=%s""",(self.namespace_id,run_id)).fetchone()
        states=dict(self.c.execute("SELECT selection_state,count(*) FROM p24_next.projection_event WHERE namespace_id=%s AND run_id=%s GROUP BY selection_state",(self.namespace_id,run_id)).fetchall())
        sources=self.c.execute("""SELECT s.snapshot_id,s.source_digest,m.coverage,m.receive_time_basis FROM p24_next.projection_source ps
            JOIN p24_next.source_snapshot s USING(namespace_id,snapshot_id)
            JOIN p24_next.foundation_snapshot_metadata m USING(namespace_id,snapshot_id)
            WHERE ps.namespace_id=%s AND ps.run_id=%s ORDER BY s.snapshot_id""",(self.namespace_id,run_id)).fetchall()
        choices=self.c.execute("SELECT snapshot_id,choice,replaced_by_snapshot_id,reason_key FROM p24_next.foundation_projection_source_choice WHERE namespace_id=%s AND run_id=%s ORDER BY snapshot_id",(self.namespace_id,run_id)).fetchall()
        scoped=self.c.execute("SELECT count(*) FROM p24_next.foundation_projection_request_scope WHERE namespace_id=%s AND run_id=%s",(self.namespace_id,run_id)).fetchone()[0]
        return dict(run_id=str(run_id),mode=row[0],event_cutoff=row[1].astimezone(timezone.utc).isoformat(),knowledge_at=row[2].astimezone(timezone.utc).isoformat(),input_manifest_sha256=row[3],
                    request_projections=totals[0],distinct_client_requests=int(totals[1]),selected_request_events=int(totals[2]),
                    sql_observations=int(totals[3]),provider_observations=int(totals[4]),known_sessions=totals[5],selection_states=states,
                    source_coverage=[dict(snapshot_id=str(s[0]),digest=s[1],coverage=s[2],receive_time_basis=s[3]) for s in sources],
                    source_selection=[dict(snapshot_id=str(c[0]),choice=c[1],replaced_by_snapshot_id=str(c[2]) if c[2] else None,reason_key=c[3]) for c in choices],
                    projection_scope="request_subset" if scoped else "full_source_vector",scoped_request_count=scoped,
                    registration_context_computed=not bool(scoped),
                    authoritative_source_heads_published=False,production_modified=False)

    def get_request(self, run_id, raw_request_id, *, access_token=None, purpose="request_investigation"):
        _, principal = self._authorize_access("read_request", "request", raw_request_id, access_token)
        run_id=self._sealed(run_id)
        key=self.request_key(raw_request_id)
        row=self.c.execute("SELECT summary FROM p24_next.foundation_request_summary WHERE namespace_id=%s AND run_id=%s AND request_key=%s",(self.namespace_id,run_id,key)).fetchone()
        if not row:
            raise FoundationError("request_not_available")
        self._access(run_id,"request",key,principal=principal,purpose=purpose)
        return row[0]

    def candidates(self, run_id, *, limit=100, cursor=None, access_token=None, purpose="registration_review"):
        _, principal = self._authorize_access("read_candidates", "registration_candidates", run_id, access_token)
        run_id=self._sealed(run_id)
        if self.c.execute("SELECT 1 FROM p24_next.foundation_projection_request_scope WHERE namespace_id=%s AND run_id=%s LIMIT 1",(self.namespace_id,run_id)).fetchone():
            raise FoundationError("registration_context_requires_publication")
        if isinstance(limit,bool) or not isinstance(limit,int) or not 1<=limit<=100:
            raise FoundationError("invalid_page_size")
        last=None
        if cursor:
            try:
                if not isinstance(cursor,str) or len(cursor)>2048:raise ValueError
                encoded,signature=cursor.split(".")
                payload=json.loads(base64.urlsafe_b64decode(encoded+"="*(-len(encoded)%4)))
                expected=self.keys.token(self.namespace,"candidate_cursor",payload).split(":")[-1]
                if not hmac.compare_digest(signature,expected) or payload["run"]!=str(run_id):raise ValueError
                last=(payload["registration"],payload["session"],payload["support"])
                if not all(isinstance(value,str) and value for value in last):raise ValueError
            except Exception:raise FoundationError("invalid_page_cursor") from None
        where=""
        args=[self.namespace_id,run_id]
        if last is not None:
            where=" AND (registration_request_key,session_key,support_request_key)>(%s,%s,%s)"
            args.extend(last)
        args.append(limit+1)
        rows=self.c.execute("SELECT registration_request_key,session_key,support_request_key,basis FROM p24_next.foundation_registration_candidate WHERE namespace_id=%s AND run_id=%s"+where+" ORDER BY registration_request_key,session_key,support_request_key LIMIT %s",args).fetchall()
        total=self.c.execute("SELECT count(*) FROM p24_next.foundation_registration_candidate WHERE namespace_id=%s AND run_id=%s",(self.namespace_id,run_id)).fetchone()[0]
        items=[dict(registration_request_key=r[0],session_key=r[1],support_request_key=r[2],basis=r[3]) for r in rows[:limit]]
        next_cursor=None
        if len(rows)>limit:
            last_row=rows[limit-1]
            payload=dict(run=str(run_id),registration=last_row[0],session=last_row[1],support=last_row[2])
            encoded=base64.urlsafe_b64encode(canonical(payload)).decode().rstrip("=")
            next_cursor=encoded+"."+self.keys.token(self.namespace,"candidate_cursor",payload).split(":")[-1]
        self._access(run_id,"registration_candidates",self.keys.token(self.namespace,"candidate_scope",str(run_id)),principal=principal,purpose=purpose)
        return dict(run_id=str(run_id),total_candidates=int(total),items=items,next_cursor=next_cursor,has_more=next_cursor is not None)

    def request_evidence(self, run_id, raw_request_id, *, limit=100, cursor=None, access_token=None, purpose="evidence_page"):
        """Read source-backed, safe request evidence in stable signed pages."""
        return self._request_evidence(run_id,self.request_key(raw_request_id),resource_value=raw_request_id,
                                     limit=limit,cursor=cursor,access_token=access_token,purpose=purpose)

    def checked_request_key(self, key):
        if not isinstance(key,str) or not re.fullmatch(r"request:"+re.escape(self.keys.version)+r":[a-f0-9]{64}",key):
            raise FoundationError("invalid_request_reference")
        return key

    def request_evidence_by_key(self, run_id, key, *, limit=100, cursor=None, access_token=None, purpose="evidence_page"):
        return self._request_evidence(run_id,self.checked_request_key(key),resource_value=key,
                                     limit=limit,cursor=cursor,access_token=access_token,purpose=purpose)

    def _request_evidence(self, run_id, request, *, resource_value, limit, cursor, access_token, purpose):
        _, principal = self._authorize_access("read_evidence", "request_evidence", resource_value, access_token)
        run_id=self._sealed(run_id)
        if isinstance(limit,bool) or not isinstance(limit,int) or not 1<=limit<=100:raise FoundationError("invalid_page_size")
        last_time,last_event,last_version=None,None,None
        if cursor:
            try:
                if not isinstance(cursor,str) or len(cursor)>2048:raise ValueError
                encoded,signature=cursor.split(".")
                payload=json.loads(base64.urlsafe_b64decode(encoded+"="*(-len(encoded)%4)))
                expected=self.keys.token(self.namespace,"request_evidence_cursor",payload).split(":")[-1]
                if not hmac.compare_digest(signature,expected) or payload["run"]!=str(run_id) or payload["request"]!=request:raise ValueError
                last_time=int(payload["time_ns"]);last_event=payload["event_key"];last_version=payload["event_version_id"]
                if not isinstance(last_event,str) or not isinstance(last_version,str):raise ValueError
            except Exception:raise FoundationError("invalid_page_cursor") from None
        null_time="999999999999999999999999999999"
        where=""
        args=[self.namespace_id,run_id,request]
        if last_time is not None:
            where=" AND (coalesce(ev.source_time_epoch_ns,%s::numeric),pe.event_key,coalesce(ev.event_version_id::text,''))>(%s::numeric,%s,%s)"
            args.extend([null_time,str(last_time),last_event,last_version])
        args.append(limit+1)
        rows=self.c.execute("""SELECT pe.event_key,ev.event_version_id,pe.selection_state,pe.selection_reason,
              ev.source_time_epoch_ns,ev.timestamp_precision,ev.source_role,ev.endpoint,ev.event_kind,fd.descriptor,
              coalesce((SELECT jsonb_agg(jsonb_build_object('snapshot_id',x.snapshot_id,'source_key',x.window_key,
                  'intake_revision',x.intake_revision,'row_ordinals',x.row_ordinals) ORDER BY x.window_key,x.snapshot_id)
                FROM (SELECT s.snapshot_id,s.window_key,s.intake_revision,
                    array_agg(m.row_ordinal ORDER BY m.row_ordinal) AS row_ordinals
                  FROM p24_next.event_source es
                  JOIN p24_next.projection_source ps ON ps.namespace_id=es.namespace_id AND ps.snapshot_id=es.snapshot_id AND ps.run_id=%s
                  JOIN p24_next.source_snapshot s ON s.namespace_id=es.namespace_id AND s.snapshot_id=es.snapshot_id
                  JOIN p24_next.foundation_row_membership m ON m.namespace_id=es.namespace_id AND m.snapshot_id=es.snapshot_id AND m.event_version_id=es.event_version_id
                  WHERE es.namespace_id=%s AND es.event_version_id=ev.event_version_id
                  GROUP BY s.snapshot_id,s.window_key,s.intake_revision) x),'[]'::jsonb) AS provenance
            FROM p24_next.projection_event pe
            JOIN p24_next.event_version ev ON ev.namespace_id=pe.namespace_id AND ev.event_key=pe.event_key
              AND (pe.event_version_id IS NULL OR pe.event_version_id=ev.event_version_id)
            JOIN p24_next.foundation_event_descriptor fd ON fd.namespace_id=ev.namespace_id AND fd.event_version_id=ev.event_version_id
            WHERE pe.namespace_id=%s AND pe.run_id=%s AND ev.request_key=%s
            AND EXISTS(SELECT 1 FROM p24_next.projection_source frozen
                JOIN p24_next.event_source support USING(namespace_id,snapshot_id)
                JOIN p24_next.projection_run r ON r.namespace_id=frozen.namespace_id AND r.run_id=frozen.run_id
                WHERE frozen.namespace_id=pe.namespace_id AND frozen.run_id=pe.run_id
                  AND support.event_version_id=ev.event_version_id
                  AND (r.mode='design_fixture' OR ev.received_at<=r.knowledge_snapshot_at))"""+where+
            " ORDER BY coalesce(ev.source_time_epoch_ns,"+null_time+"::numeric),pe.event_key,ev.event_version_id::text LIMIT %s",
            [run_id,self.namespace_id,*args]).fetchall()
        items=[]
        for row in rows[:limit]:
            items.append(dict(origin_key=row[0],event_version_id=str(row[1]),selection_state=row[2],selection_reason=row[3],
                source_time_epoch_ns=str(row[4]) if row[4] is not None else None,timestamp_precision=row[5],source_role=row[6],
                endpoint=row[7],event_kind=row[8],descriptor=row[9],provenance=row[10]))
        next_cursor=None
        if len(rows)>limit:
            last=rows[limit-1]
            payload=dict(run=str(run_id),request=request,time_ns=str(last[4]) if last[4] is not None else null_time,event_key=last[0],event_version_id=str(last[1]))
            encoded=base64.urlsafe_b64encode(canonical(payload)).decode().rstrip("=")
            next_cursor=encoded+"."+self.keys.token(self.namespace,"request_evidence_cursor",payload).split(":")[-1]
        count=self.c.execute("""SELECT count(*) FROM (SELECT DISTINCT pe.event_key,ev.event_version_id FROM p24_next.projection_event pe
            JOIN p24_next.event_version ev ON ev.namespace_id=pe.namespace_id AND ev.event_key=pe.event_key
              AND (pe.event_version_id IS NULL OR pe.event_version_id=ev.event_version_id)
            WHERE pe.namespace_id=%s AND pe.run_id=%s AND ev.request_key=%s
            AND EXISTS(SELECT 1 FROM p24_next.projection_source frozen JOIN p24_next.event_source support USING(namespace_id,snapshot_id)
                JOIN p24_next.projection_run r ON r.namespace_id=frozen.namespace_id AND r.run_id=frozen.run_id
                WHERE frozen.namespace_id=pe.namespace_id AND frozen.run_id=pe.run_id AND support.event_version_id=ev.event_version_id
                  AND (r.mode='design_fixture' OR ev.received_at<=r.knowledge_snapshot_at))) q""",(self.namespace_id,run_id,request)).fetchone()[0]
        self._access(run_id,"request_evidence",request,principal=principal,purpose=purpose)
        return dict(run_id=str(run_id),request_key=request,total_event_versions=count,items=items,next_cursor=next_cursor,
            evidence_scope="selected projection versions and explicit ambiguities only; raw payloads are not returned")

    def session_activity(self, run_id, raw_session_id, *, limit=100, cursor=None, access_token=None, purpose="session_investigation"):
        _, principal = self._authorize_access("read_session", "session", raw_session_id, access_token)
        run_id=self._sealed(run_id)
        if isinstance(limit,bool) or not isinstance(limit,int) or not 1 <= limit <= 100:
            raise FoundationError("invalid_page_size")
        session=self.session_key(raw_session_id)
        last_time,last_request=None,None
        if cursor:
            try:
                if not isinstance(cursor,str) or len(cursor)>2048:
                    raise ValueError
                encoded,signature=cursor.split(".")
                payload=json.loads(base64.urlsafe_b64decode(encoded+"="*(-len(encoded)%4)))
                expected=self.keys.token(self.namespace,"cursor",payload).split(":")[-1]
                if not hmac.compare_digest(signature,expected) or payload["run"]!=str(run_id) or payload["session"]!=session:
                    raise ValueError
                last_time=microsecond_cutoff(payload["at"]).floor
                last_request=payload["request"]
                if not isinstance(last_request,str):
                    raise ValueError
            except Exception:
                raise FoundationError("invalid_page_cursor") from None
        where=""
        args=[self.namespace_id,run_id,session]
        if last_time is not None:
            where=" AND (rp.activity_time,rp.request_key)>(%s,%s)"
            args.extend([last_time,last_request])
        args.append(limit+1)
        rows=self.c.execute("""SELECT rp.activity_time,rp.request_key,s.summary FROM p24_next.request_projection rp
            JOIN p24_next.foundation_request_summary s USING(namespace_id,run_id,request_key)
            WHERE rp.namespace_id=%s AND rp.run_id=%s AND rp.session_key=%s"""+where+" ORDER BY rp.activity_time,rp.request_key LIMIT %s",args).fetchall()
        total=self.c.execute("SELECT count(*) FROM p24_next.request_projection WHERE namespace_id=%s AND run_id=%s AND session_key=%s",(self.namespace_id,run_id,session)).fetchone()[0]
        next_cursor=None
        if len(rows)>limit:
            last=rows[limit-1]
            payload=dict(run=str(run_id),session=session,at=last[0].astimezone(timezone.utc).isoformat(),request=last[1])
            encoded=base64.urlsafe_b64encode(canonical(payload)).decode().rstrip("=")
            next_cursor=encoded+"."+self.keys.token(self.namespace,"cursor",payload).split(":")[-1]
        self._access(run_id,"session",session,principal=principal,purpose=purpose)
        return dict(run_id=str(run_id),session_key=session,total_requests=total,items=[r[2] for r in rows[:limit]],next_cursor=next_cursor)

