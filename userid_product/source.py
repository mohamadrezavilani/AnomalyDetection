"""Explicit, bounded source adapters; constructing/importing starts no capture.

Publication is the caller's transaction. A SourceWindow is returned only after
the entire file/snapshot, count, origins and event-time bounds have been checked.
"""
from __future__ import annotations

from copy import deepcopy
import gzip
import hashlib
import json
from pathlib import Path

from compact_behavior.extract import instant, iso, LimitExceeded
from compact_behavior.json_value import unique_object
from compact_behavior.source import ElasticWindow as LegacyElasticWindow
from contracts.userid import CONTRACT_VERSION
from .identity import BoundaryError, locations, nanoseconds, scope

PROFILE = "p24-core-userid-v1"
FIVE = 300_000_000_000
PROJECTION = ("@timestamp", "CallPath", "RequestID", "UserID", "message",
              "ExecutionTime", "IP", "UserAgent", "userAgent")


def _constant(_):
    raise BoundaryError("NONFINITE_JSON_NUMBER")


class WindowFile:
    """Streaming JSON/gzip export, with duplicate property rejection at all levels."""
    def __init__(self, path, *, max_value_chars=67_108_864):
        self.path = Path(path)
        self.limit = max_value_chars
        self.metadata = {}
        self.count = 0

    def records(self):
        self.metadata = {}
        self.count = 0
        decoder = json.JSONDecoder(object_pairs_hook=unique_object, parse_constant=_constant)
        opener = gzip.open if self.path.suffix == ".gz" else open
        buffer = ""
        eof = False
        with opener(self.path, "rt", encoding="utf-8-sig") as file:
            def fill():
                nonlocal buffer, eof
                block = file.read(65536)
                eof = not block
                buffer += block
            def ws():
                nonlocal buffer
                while True:
                    buffer = buffer.lstrip()
                    if buffer or eof:
                        return
                    fill()
            def take(char):
                nonlocal buffer
                ws()
                if not buffer.startswith(char):
                    raise BoundaryError("SOURCE_JSON_INVALID")
                buffer = buffer[len(char):]
            def value():
                nonlocal buffer
                while True:
                    ws()
                    try:
                        v, end = decoder.raw_decode(buffer)
                    except json.JSONDecodeError:
                        if eof:
                            raise BoundaryError("SOURCE_JSON_INCOMPLETE") from None
                        if len(buffer) > self.limit:
                            raise LimitExceeded("source_record_size_limit")
                        fill()
                        continue
                    except (ValueError, RecursionError):
                        raise BoundaryError("SOURCE_JSON_DUPLICATE_OR_INVALID") from None
                    if not eof and (end == len(buffer) or
                            type(v) in (int, float) and buffer[end:end+1] not in ",]} \t\n\r:"):
                        fill()
                        continue
                    if end > self.limit:
                        raise LimitExceeded("source_record_size_limit")
                    buffer = buffer[end:]
                    return v
            take("{")
            first = True
            seen = set()
            while True:
                ws()
                if buffer.startswith("}"):
                    take("}")
                    break
                if not first:
                    take(",")
                first = False
                name = value()
                take(":")
                if not isinstance(name, str) or name in seen:
                    raise BoundaryError("SOURCE_JSON_DUPLICATE_PROPERTY")
                seen.add(name)
                if name != "logs":
                    self.metadata[name] = value()
                    continue
                take("[")
                initial = True
                while True:
                    ws()
                    if buffer.startswith("]"):
                        take("]")
                        break
                    if not initial:
                        take(",")
                    initial = False
                    row = value()
                    if not isinstance(row, dict):
                        raise BoundaryError("SOURCE_RECORD_NOT_OBJECT")
                    self.count += 1
                    yield row
            ws()
            if buffer or "logs" not in seen or self.metadata.get("complete") is not True:
                raise BoundaryError("SOURCE_WINDOW_INCOMPLETE")
            if type(self.metadata.get("count")) is not int or self.metadata["count"] != self.count:
                raise BoundaryError("SOURCE_COUNT_MISMATCH")
            self.metadata["method"] = "export"


class ElasticWindow(LegacyElasticWindow):
    """Pinned pure transport adapter: replace Session projection with UserID.

    PIT/scroll completeness and cleanup remain the frozen, regression-tested
    transport implementation. validate_window adds origin and range checks to
    both paths, including PIT. No config discovery or auto-start is performed.
    """
    def request(self, path, body=None, method="POST"):
        if isinstance(body, dict) and "_source" in body:
            body = dict(body, _source=list(PROJECTION))
        return super().request(path, body, method)


def metadata(row):
    if not isinstance(row, dict):
        raise BoundaryError("SOURCE_RECORD_NOT_OBJECT")
    result = {}
    if "_source" in row:
        if not isinstance(row["_source"], dict):
            raise BoundaryError("SOURCE_METADATA_INVALID")
        result["_source"] = row["_source"]
    elif "fields" not in row:
        result["log"] = row
    if "fields" in row:
        if not isinstance(row["fields"], dict):
            raise BoundaryError("SOURCE_METADATA_INVALID")
        result["fields"] = row["fields"]
    if any("Session" in data for data in result.values()):
        raise BoundaryError("SOURCE_PROFILE_LEGACY_SESSION")
    return {name: {k: deepcopy(v) for k, v in data.items() if k in PROJECTION}
            for name, data in result.items()}


def single(meta, field):
    values = []
    for name, value in locations(meta, field):
        if name.startswith("fields.") and isinstance(value, list) and len(value) == 1:
            value = value[0]
        if not any(type(value) is type(old) and value == old for old in values):
            values.append(value)
    if len(values) > 1:
        raise BoundaryError("SOURCE_FIELD_CONFLICT")
    return values[0] if values else None


def normalize(row, source_scope, seen_at_ns):
    scope(source_scope)
    nanoseconds(seen_at_ns)
    origin = [row.get("_index"), row.get("_id")]
    if any(not isinstance(v, str) or not v or len(v.encode("utf-8")) > 4096 for v in origin):
        raise BoundaryError("SOURCE_DOCUMENT_ORIGIN_INVALID")
    meta = metadata(row)
    raw_time = single(meta, "@timestamp")
    try:
        at = str(instant(raw_time))
        nanoseconds(at)
    except (ValueError, TypeError, OverflowError):
        at = None
    message = single(meta, "message")
    if message is None:
        message = ""
    if not isinstance(message, str) or len(message) > 67_108_864:
        raise BoundaryError("SOURCE_MESSAGE_INVALID")
    # Preserve raw identity locations, but avoid a second retained message copy.
    for data in meta.values():
        data.pop("message", None)
    document = json.dumps(["userid-document-1", source_scope, *origin],
                          ensure_ascii=False, separators=(",", ":"), allow_nan=False)
    return dict(record_type="SourceRecord", contract_version=CONTRACT_VERSION,
                source_scope=source_scope, source_profile=PROFILE,
                document_key=hashlib.sha256(document.encode("utf-8")).hexdigest(),
                event_time_ns=at, seen_at_ns=seen_at_ns, metadata=meta, message=message)


def records(reader, source_scope, seen_at_ns, *, max_documents=1_000_000):
    """Yield provisional records; reader.metadata is certified only at EOF.

    Consumers must discard all provisional state if iteration raises. Use
    extraction.extract_window for an atomic complete extraction boundary.
    """
    reader._userid_window = None
    seen = set()
    minimum = maximum = None
    for row in reader.records():
        record = normalize(row, source_scope, seen_at_ns)
        document = record["document_key"]
        if document in seen:
            raise BoundaryError("SOURCE_DUPLICATE_DOCUMENT")
        if len(seen) >= max_documents:
            raise LimitExceeded("source_documents_limit")
        seen.add(document)
        if record["event_time_ns"] is None:
            raise BoundaryError("SOURCE_WINDOW_UNDATED_DOCUMENT")
        at = int(record["event_time_ns"])
        minimum = at if minimum is None else min(minimum, at)
        maximum = at if maximum is None else max(maximum, at)
        yield record
    begin = instant(reader.metadata.get("window_start"))
    end = instant(reader.metadata.get("window_end"))
    if begin < 0 or begin % FIVE or end - begin != FIVE:
        raise BoundaryError("SOURCE_WINDOW_ALIGNMENT_INVALID")
    if minimum is not None and not (begin <= minimum <= maximum < end):
        raise BoundaryError("SOURCE_DOCUMENT_OUTSIDE_WINDOW")
    if reader.metadata.get("complete") is not True or reader.metadata.get("count") != len(seen):
        raise BoundaryError("SOURCE_WINDOW_INCOMPLETE")
    reader._userid_window = _completed_window(reader, source_scope)


def _completed_window(reader, source_scope):
    method = reader.metadata.get("method")
    basis = {"export": "EXPORTED_COUNT_AND_ORIGIN_CHECKED",
             "pit_search_after": "EXACT_TOTAL_AND_MONOTONIC_PIT_CURSOR",
             "scroll": "EXACT_TOTAL_UNIQUE_DOCUMENTS_AND_EMPTY_TERMINAL"}.get(method)
    if basis is None:
        raise BoundaryError("SOURCE_COMPLETENESS_BASIS_UNKNOWN")
    return dict(record_type="SourceWindow", contract_version=CONTRACT_VERSION,
                source_scope=scope(source_scope), source_profile=PROFILE,
                window_start_ns=str(instant(reader.metadata["window_start"])),
                window_end_ns=str(instant(reader.metadata["window_end"])),
                source_records=reader.count, complete=True, completeness_basis=basis,
                source_finality="NOT_ESTABLISHED")


def window(reader, source_scope):
    completed = getattr(reader, "_userid_window", None)
    if completed is None or completed["source_scope"] != source_scope:
        raise BoundaryError("SOURCE_WINDOW_NOT_CERTIFIED")
    return deepcopy(completed)
