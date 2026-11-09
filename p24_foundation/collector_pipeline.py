"""Finite, explicit collector capture and observed-publication integration.

No background process, production database, verified issuer or complete traffic
claim is introduced here. Raw capture files belong in a private local directory.
"""
from __future__ import annotations

from datetime import datetime, timezone
import copy
import hashlib
import json
from pathlib import Path
import re
import time
import uuid

from .errors import FoundationError
from .intake import Batch, MAX_INPUT_BYTES, MAX_RECORDS, decode_batch, read_batch
from .privacy import canonical
from .time import microsecond_cutoff

ROOT = Path(__file__).resolve().parents[1]
PLAN_VERSION = "p24-collector-import.1"


def verified_target(root):
    """Read the exact eight-file target baseline without executing its code."""
    expected = json.loads((ROOT / "catalogs/collector_target_sha256.json").read_text())
    result = {}
    for relative, wanted in expected.items():
        try:
            path = Path(root) / relative
            with path.open("rb") as stream:
                data = stream.read(2_000_001)
        except OSError:
            raise FoundationError("collector_target_file_missing") from None
        if len(data) > 2_000_000 or hashlib.sha256(data).hexdigest() != wanted:
            raise FoundationError("collector_target_hash_mismatch")
        result[relative] = data
    return result


def verified_transport(root):
    """Verify only executed collector/settings bytes; never load legacy writers.

    The old collector is a reviewed archive match. The additional settings hash
    is the user's explicitly supplied trusted local configuration fingerprint;
    its credentials/contents are not copied into this project.
    """
    allowed={
        "elastic_log_fetcher.py": {
            "96837ac60ca87a2545eeffea244695d7020ab93bbab0b2b65fa6fb4c79fced61",
            "e5b18e7b3ff27b6e1c8dbe970fae78f34830395633470bb566b6313c777e970b"},
        "PopulationVersion/config.py": {
            "a9ba388659b357bf0399de5e2c449a56e5e13920cd025cfad96d7e85ce74921e",
            "5f3ccc1f8618b202deed6ed99948deb30c3d31fd609098f933a1252426d6ca68"}}
    result={}
    for name,hashes in allowed.items():
        try:
            with (Path(root)/name).open('rb') as stream:data=stream.read(2_000_001)
        except OSError:raise FoundationError('collector_transport_file_missing') from None
        if len(data)>2_000_000 or hashlib.sha256(data).hexdigest() not in hashes:
            raise FoundationError('collector_transport_hash_mismatch')
        result[name]=data
    return result


def capture_window(client, *, index_pattern, start, end, before_request=lambda: None,
                   max_runtime_seconds=120, page_size=10000):
    """Retain one actual single-slice scroll transcript, including exhaustion.

    Transport failures become retained partial attempts, never complete dumps.
    The caller's transport must bound each network request to the remaining
    budget. The target collector's fetch_budget supplies that bound.
    """
    first, last = microsecond_cutoff(start), microsecond_cutoff(end)
    if last.epoch_ns - first.epoch_ns != 300_000_000_000:
        raise FoundationError("collector_requires_five_minute_window")
    if (isinstance(max_runtime_seconds, bool) or not isinstance(max_runtime_seconds, int)
            or not 1 <= max_runtime_seconds <= 300):
        raise FoundationError("invalid_collector_runtime_limit")
    if isinstance(page_size, bool) or not isinstance(page_size, int) or not 1 <= page_size <= 10000:
        raise FoundationError("invalid_collector_page_size")
    body = dict(query={"bool": {"filter": [{"range": {"@timestamp": {"gte": start, "lt": end}}}]}},
                sort=["_doc"], size=page_size, _source=True, track_total_hits=True)
    now = lambda: datetime.now(timezone.utc).isoformat()
    attempt = dict(number=1, failure_kind="none", initial_request=dict(
        index=index_pattern, scroll="10m", body=body), pages=[])
    packet = dict(acquisition=dict(version="p24-scroll-capture.1", window_start=start,
        window_end=end, started_at=now(), finished_at=now(), index_pattern=index_pattern,
        expected_slices=1, attempt_budget=1,
        query=dict(scope="window_only", time_field="@timestamp", range_mode="gte_lt", level_filter=[])),
        slices=[dict(id=0, attempts=[attempt])])
    # Validate header intent before any network access.
    decode_batch(canonical(packet))
    deadline = time.monotonic() + max_runtime_seconds
    cursor = None
    row_count, encoded_bytes = 0, len(canonical(packet))
    try:
        for ordinal in range(2048):
            if time.monotonic() >= deadline:
                raise TimeoutError()
            before_request()
            response = (client.search(index=index_pattern, body=copy.deepcopy(body), scroll="10m")
                        if ordinal == 0 else client.scroll(scroll_id=cursor, scroll="10m"))
            if not isinstance(response, dict):
                raise ValueError()
            # Retain the latest returned cursor even on the final empty page.
            returned_cursor = response.get("_scroll_id")
            page = dict(ordinal=ordinal, request_cursor=cursor, received_at=now(), response=response)
            if isinstance(returned_cursor, str) and returned_cursor:
                cursor = returned_cursor
            hits = response.get("hits", {}).get("hits") if isinstance(response.get("hits"), dict) else None
            if not isinstance(hits, list):
                raise ValueError()
            row_count += len(hits)
            encoded_bytes += len(canonical(page)) + 2
            if row_count > MAX_RECORDS or encoded_bytes > MAX_INPUT_BYTES - 4096:
                attempt["failure_kind"] = "cancelled"
                break
            attempt["pages"].append(page)
            if (response.get("timed_out") is not False or response.get("terminated_early") is True
                    or response.get("_shards", {}).get("failed", 0)):
                break
            if not hits:
                break
            if not isinstance(returned_cursor, str) or not returned_cursor:
                break
        else:
            attempt["failure_kind"] = "cancelled"
    except TimeoutError:
        attempt["failure_kind"] = "transport_timeout"
    except (ValueError, TypeError, AttributeError, KeyError):
        attempt["failure_kind"] = "decode_error"
    except Exception:
        # Do not copy URLs, credentials or server exception text into metadata.
        attempt["failure_kind"] = "http_error"
    finally:
        if cursor:
            try:
                client.clear_scroll(scroll_id=cursor)
            except Exception:
                pass
        packet["acquisition"]["finished_at"] = now()
    data = canonical(packet)
    # The same intake validator used by persistence is the acceptance oracle.
    try:
        return decode_batch(data)
    except FoundationError as error:
        # Preserve the bounded transcript even when a response cannot be
        # assessed. Persistence always re-decodes original bytes, so this
        # diagnostic wrapper cannot turn rejected evidence into accepted input.
        return Batch((), dict(input_format="unassessed_scroll_capture", acquisition=dict(
            query_traversal_complete=False, window_scope_eligible=False,
            issues=[error.code], scope_issues=["capture_assessment_failed"])), data)


def capture_summary(batch):
    assessment = batch.coverage["acquisition"]
    assessed = batch.coverage.get("input_format") == "scroll_capture"
    return dict(sha256=hashlib.sha256(batch.original).hexdigest(), records=len(batch.records) if assessed else None,
        assessment_status="available" if assessed else "invalid_capture",
        query_traversal_complete=assessment["query_traversal_complete"],
        window_scope_eligible=assessment["window_scope_eligible"],
        issues=assessment["issues"], scope_issues=assessment["scope_issues"],
        producer_authority="unverified", source_window_complete=False,
        source_finality="not_established")


def load_plan(path):
    """Read all bounded, digest-pinned captures before opening a transaction."""
    path = Path(path)
    try:
        with path.open("rb") as stream:
            raw = stream.read(128_001)
        if len(raw) > 128_000:
            raise ValueError()
        def unique(pairs):
            result = {}
            for key, value in pairs:
                if key in result:
                    raise ValueError()
                result[key] = value
            return result
        plan = json.loads(raw, object_pairs_hook=unique,
                          parse_constant=lambda value: (_ for _ in ()).throw(ValueError()))
        allowed = {"version", "stream", "index_pattern", "expected_generation", "event_cutoff", "captures"}
        if not isinstance(plan, dict) or set(plan) != allowed or plan["version"] != PLAN_VERSION:
            raise ValueError()
        if not isinstance(plan["stream"], str) or not re.fullmatch(r"[A-Za-z0-9_.-]{1,64}", plan["stream"]):
            raise ValueError()
        generation = plan["expected_generation"]
        if isinstance(generation, bool) or not isinstance(generation, int) or generation < 0:
            raise ValueError()
        if not isinstance(plan["index_pattern"], str):
            raise ValueError()
        cutoff = microsecond_cutoff(plan["event_cutoff"])
        if not isinstance(plan["captures"], list) or not 1 <= len(plan["captures"]) <= 128:
            raise ValueError()
        prepared, windows = [], set()
        total_bytes, total_rows, total_decoded_bytes = 0, 0, 0
        for item in plan["captures"]:
            if not isinstance(item, dict) or not {"path", "sha256"} <= set(item) <= {"path", "sha256", "replaces"}:
                raise ValueError()
            source_path = Path(item["path"])
            if not source_path.is_absolute():
                source_path = path.parent / source_path
            batch = read_batch(source_path)
            total_bytes += len(batch.original)
            total_rows += len(batch.records)
            total_decoded_bytes += len(canonical(batch.records))
            if total_bytes > MAX_INPUT_BYTES or total_decoded_bytes > MAX_INPUT_BYTES or total_rows > MAX_RECORDS:
                raise FoundationError("collector_plan_input_limit")
            if hashlib.sha256(batch.original).hexdigest() != item["sha256"]:
                raise FoundationError("collector_capture_digest_mismatch")
            if batch.coverage["input_format"] != "scroll_capture":
                raise FoundationError("collector_transcript_required")
            assessment = batch.coverage["acquisition"]
            if not assessment["query_traversal_complete"] or not assessment["window_scope_eligible"]:
                raise FoundationError("collector_capture_not_eligible")
            if assessment["index_pattern"] != plan["index_pattern"] or assessment["expected_slices"] != 1:
                raise FoundationError("collector_capture_scope_mismatch")
            start, end = map(microsecond_cutoff, (assessment["declared_window_start"], assessment["declared_window_end"]))
            if end.epoch_ns - start.epoch_ns != 300_000_000_000 or end.epoch_ns > cutoff.epoch_ns:
                raise FoundationError("collector_capture_cutoff_mismatch")
            key = f"collector:{plan['stream']}:{start.epoch_ns}:{end.epoch_ns}"
            if key in windows:
                raise FoundationError("duplicate_collector_window")
            windows.add(key)
            replacement = item.get("replaces")
            if replacement is not None:
                if not isinstance(replacement, dict) or set(replacement) != {"snapshot_id", "intake_revision"}:
                    raise ValueError()
                replacement["snapshot_id"] = str(uuid.UUID(replacement["snapshot_id"]))
                revision = replacement["intake_revision"]
                if isinstance(revision, bool) or not isinstance(revision, int) or revision < 1:
                    raise ValueError()
            prepared.append(dict(batch=batch, source_key=key, start=assessment["declared_window_start"],
                                 end=assessment["declared_window_end"], replaces=replacement))
        return dict(stream=plan["stream"], index_pattern=plan["index_pattern"],
                    expected_generation=generation, event_cutoff=plan["event_cutoff"], captures=prepared)
    except FoundationError:
        raise
    except (OSError, ValueError, TypeError, KeyError, AttributeError):
        raise FoundationError("invalid_collector_import_plan") from None


def publish_plan(store, plan):
    """Publish one explicit batch atomically; retain the current selected vector.

    No mtime selection, inferred replacement, source-head promotion, or old
    workflow binding reuse is permitted. Workflows remain unavailable until an
    approved issuer/meaning adapter supplies a separately pinned projection.
    """
    from .publication import ObservationPublisher
    publisher = ObservationPublisher(store)
    imported = []
    with store.c.transaction():
        store._lock()
        current, generation = publisher._current()
        if generation != plan["expected_generation"]:
            raise FoundationError("stale_publication_generation")
        sources = publisher._header(current)["input_manifest"]["effective_sources"] if current else []
        rows = store.c.execute("""SELECT s.snapshot_id,s.window_key,s.intake_revision,s.source_digest,m.coverage
            FROM p24_next.source_snapshot s JOIN p24_next.foundation_snapshot_metadata m USING(namespace_id,snapshot_id)
            WHERE s.namespace_id=%s AND s.snapshot_id=ANY(%s)""",
            (store.namespace_id, [uuid.UUID(value) for value in sources])).fetchall()
        by_window = {}
        for snapshot, key, revision, digest, coverage in rows:
            if (not key.startswith("collector:" + plan["stream"] + ":")
                    or coverage.get("acquisition", {}).get("index_pattern") != plan["index_pattern"]
                    or key in by_window):
                raise FoundationError("collector_namespace_stream_conflict")
            by_window[key] = (str(snapshot), revision, digest)
        for item in plan["captures"]:
            previous = by_window.get(item["source_key"])
            replacement = item["replaces"]
            digest = hashlib.sha256(item["batch"].original).hexdigest()
            if replacement is not None and (previous is None or
                    (replacement["snapshot_id"], replacement["intake_revision"]) != previous[:2]):
                raise FoundationError("collector_replacement_conflict")
            if previous and previous[2] != digest and replacement is None:
                raise FoundationError("collector_explicit_replacement_required")
            if replacement is not None and previous[2] == digest:
                raise FoundationError("collector_replacement_identical")
            source = store.ingest(item["batch"], source_key=item["source_key"],
                                  interval_start=item["start"], interval_end=item["end"])
            if replacement is not None:
                store.replace_source_snapshot(previous[0], source["snapshot_id"],
                    expected_prior_revision=previous[1], reason_key="producer_reissued",
                    declared_by="collector-import:" + plan["stream"])
            sources = list(set(sources + [source["snapshot_id"]]))
            revision = store.c.execute("""SELECT intake_revision FROM p24_next.source_snapshot
                WHERE namespace_id=%s AND snapshot_id=%s""",
                (store.namespace_id, source["snapshot_id"])).fetchone()[0]
            imported.append(dict(snapshot_id=source["snapshot_id"], receipt_id=source["receipt_id"],
                intake_revision=revision, window_start=item["start"], window_end=item["end"],
                sha256=digest, reused=source["reused"]))
        known = datetime.now(timezone.utc).isoformat()
        if microsecond_cutoff(plan["event_cutoff"]).epoch_ns > microsecond_cutoff(known).epoch_ns:
            raise FoundationError("collector_future_event_cutoff")
        prepared = publisher.prepare(sources, event_cutoff=plan["event_cutoff"], knowledge_at=known,
                                    expected_generation=generation, mode="historical_revised")
        published = publisher.publish(prepared["publication_id"])
    return {key: published[key] for key in ("publication_id", "generation", "distinct_client_requests",
        "selected_request_events", "known_sessions", "input_manifest_sha256")} | dict(
        imported=imported, evidence_scope="observed_only", producer_authority="unverified",
        source_window_complete=False, workflow_status="unavailable_no_reviewed_adapter", production_modified=False)
