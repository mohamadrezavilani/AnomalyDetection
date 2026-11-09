"""Bounded decoding of collector JSON, Elasticsearch hits, Kibana and NDJSON."""
from __future__ import annotations

import json
import gzip
import io
import re
import zlib
from dataclasses import dataclass
from decimal import Decimal
from pathlib import Path

from .errors import FoundationError

MAX_INPUT_BYTES = 64 * 1024 * 1024
MAX_RECORDS = 100_000

@dataclass(frozen=True)
class Batch:
    records: tuple
    coverage: dict
    original: bytes

def _unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate_json_key")
        result[key] = value
    return result

def _collector_rows(records):
    """Recover only the collector's unambiguous index:id serialization.

    Multi-colon values can mean a remote index or an ID containing a colon;
    they remain originless. Original row bytes always stay in the vault.
    """
    if not isinstance(records, list):
        return records, 0
    rows, recovered = [], 0
    for row in records:
        origin = row.get("_source_id") if isinstance(row, dict) else None
        if isinstance(origin, str) and origin.count(":") == 1:
            index, doc_id = origin.split(":")
            if re.fullmatch(r"[a-z0-9][a-z0-9_.-]{0,254}", index) and doc_id and len(doc_id) <= 512 and not any(c.isspace() or ord(c)<32 for c in doc_id):
                rows.append(dict(_index=index, _id=doc_id, _source=row))
                recovered += 1
                continue
        rows.append(row)
    return rows, recovered

def decode_batch(data, *, max_bytes=MAX_INPUT_BYTES, max_records=MAX_RECORDS):
    if not isinstance(data, bytes) or len(data) > max_bytes:
        raise FoundationError("input_size_limit")
    original = data
    compression = "none"
    if data.startswith(b"\x1f\x8b"):
        try:
            with gzip.GzipFile(fileobj=io.BytesIO(data)) as stream:
                data = stream.read(max_bytes + 1)
        except (OSError,EOFError,zlib.error):
            raise FoundationError("invalid_gzip_input") from None
        if len(data)>max_bytes:
            raise FoundationError("decompressed_input_size_limit")
        compression = "gzip"
    try:
        text = data.decode("utf-8-sig")
        decoder = json.JSONDecoder(parse_float=Decimal,
                                   object_pairs_hook=_unique_object,
                                   parse_constant=lambda _: (_ for _ in ()).throw(ValueError()))
        roots, offset = [], 0
        while offset < len(text):
            while offset < len(text) and text[offset].isspace():
                offset += 1
            if offset == len(text):
                break
            value, offset = decoder.raw_decode(text, offset)
            roots.append(value)
            if len(roots) > max_records:
                raise FoundationError("record_count_limit")
    except FoundationError:
        raise
    except (UnicodeError, ValueError, RecursionError):
        raise FoundationError("invalid_json_input") from None
    if not roots:
        raise FoundationError("empty_input_not_a_manifest")
    metadata = dict(input_format="documents", query_total=None, query_total_relation="unknown",
                    query_complete=False, source_window_complete=False, receive_times_supplied=False,
                    source_time_coverage="uninspected", fields_only_records=0)
    metadata["compression"] = compression
    acquisition = None
    if len(roots)==1 and isinstance(roots[0],dict) and "acquisition" in roots[0]:
        from .acquisition import assess_scroll_capture
        records,acquisition = assess_scroll_capture(roots[0],max_records=max_records)
        metadata.update(input_format="scroll_capture",acquisition=acquisition,
                        declared_window_start=acquisition["declared_window_start"],
                        declared_window_end=acquisition["declared_window_end"],
                        query_complete=acquisition["query_traversal_complete"])
    elif len(roots)==1 and isinstance(roots[0],dict) and "logs" in roots[0]:
        from .time import microsecond_cutoff
        packet=roots[0]
        records,recovered=_collector_rows(packet["logs"])
        try:
            start,end=microsecond_cutoff(packet.get("window_start")),microsecond_cutoff(packet.get("window_end"))
        except FoundationError:
            raise FoundationError("invalid_collector_window") from None
        if start.epoch_ns>=end.epoch_ns:
            raise FoundationError("invalid_collector_window")
        count=packet.get("count")
        count_valid=isinstance(count,int) and not isinstance(count,bool) and count>=0
        metadata.update(input_format="legacy_collector_dump",
            declared_window_start=packet["window_start"],declared_window_end=packet["window_end"],
            legacy_complete_claim=packet.get("complete") is True,
            legacy_count_matches=count_valid and isinstance(records,list) and count==len(records),
            legacy_origin_recovered_rows=recovered,
            legacy_origin_contract="single_colon_index_id_only.1",
            acquisition=dict(contract_version="legacy-collector-unverified.1",source_claim_state="unverified_local_capture",
                query_traversal_complete=False,source_window_complete=False,source_finality="not_established",
                issues=["page_transcript_not_retained"],legacy_complete_claim=packet.get("complete") is True,
                legacy_count_matches=count_valid and isinstance(records,list) and count==len(records)))
    if acquisition is None and metadata["input_format"]!="legacy_collector_dump" and len(roots) == 1 and isinstance(roots[0], dict) and "rawResponse" in roots[0]:
        outer = roots[0]
        if outer.get("isPartial") is True or outer.get("isRunning") is True:
            raise FoundationError("partial_search_response")
        roots = [outer["rawResponse"]]
        metadata["input_format"] = "kibana_response"
    if metadata["input_format"] in {"scroll_capture","legacy_collector_dump"}:
        pass
    elif len(roots) == 1 and isinstance(roots[0], dict) and "hits" in roots[0]:
        response = roots[0]
        try:
            if response.get("timed_out") or response.get("_shards", {}).get("failed", 0):
                raise FoundationError("incomplete_search_response")
            records = response["hits"]["hits"]
            total = response["hits"].get("total")
            if isinstance(total, int) and not isinstance(total, bool):
                total, relation = total, "eq"
            elif isinstance(total, dict):
                total, relation = total.get("value"), total.get("relation", "unknown")
            else:
                total, relation = None, "unknown"
            if isinstance(total, bool) or total is not None and (not isinstance(total, int) or total < 0):
                raise FoundationError("invalid_search_total")
            metadata.update(query_total=total, query_total_relation=relation,
                            query_complete=relation == "eq" and total == len(records))
            if metadata["input_format"] != "kibana_response":
                metadata["input_format"] = "elasticsearch_response"
        except (KeyError, TypeError):
            raise FoundationError("unsupported_search_response") from None
    elif len(roots) == 1 and isinstance(roots[0], list):
        records = roots[0]
        metadata["input_format"] = "document_array"
    else:
        records = roots
        metadata["input_format"] = "document_stream" if len(roots) > 1 else "document"
    if not isinstance(records, list) or len(records) > max_records:
        raise FoundationError("record_count_limit")
    if not all(isinstance(record, dict) for record in records):
        raise FoundationError("source_record_must_be_object")
    if any(not any(key in record for key in ("_source", "fields", "message", "RequestID", "@timestamp")) for record in records):
        raise FoundationError("unsupported_source_record")
    metadata["returned_records"] = len(records)
    metadata["fields_only_records"] = sum(not isinstance(r.get("_source"), dict) and isinstance(r.get("fields"), dict) for r in records)
    metadata["source_time_coverage"] = "formatted_fields_only" if records and metadata["fields_only_records"] == len(records) else "mixed_or_source"
    return Batch(tuple(records), metadata, original)

def read_batch(path):
    try:
        with Path(path).open("rb") as stream:
            data = stream.read(MAX_INPUT_BYTES + 1)
    except OSError:
        raise FoundationError("input_unavailable") from None
    return decode_batch(data)

