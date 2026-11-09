"""Persist unpublished taxonomy candidates; no semantic publication occurs."""
from __future__ import annotations

import hashlib
import json
import uuid
from pathlib import Path
from psycopg.types.json import Jsonb

from .errors import FoundationError
from .privacy import canonical
from .taxonomy import TAXONOMY_IMPORT_VERSION, error_catalog_candidates, observed_callpath_candidates, postman_candidates


def persist_candidate_taxonomy(store, collection_paths, *, error_catalog_path=None, log_evidence_paths=None):
    paths = [Path(p) for p in collection_paths]
    if not paths:
        raise FoundationError("postman_collection_required")
    catalog_path = Path(error_catalog_path or Path(__file__).resolve().parents[1] / "catalogs/error_code_catalog.json")
    try:
        codes = error_catalog_candidates(json.loads(catalog_path.read_text(encoding="utf-8")))
    except (OSError, UnicodeError, json.JSONDecodeError, RecursionError):
        raise FoundationError("error_catalog_unavailable") from None
    collections, logs = [], []
    for path in paths:
        try:
            raw = path.read_bytes()
        except OSError:
            raise FoundationError("postman_collection_unavailable") from None
        collections.append(postman_candidates(raw, locator=path.name))
    for path in (Path(p) for p in (log_evidence_paths or [])):
        try:
            raw = path.read_bytes()
        except OSError:
            raise FoundationError("observed_log_sample_unavailable") from None
        logs.append(observed_callpath_candidates(raw, locator=path.name, keys=store.keys, namespace=store.namespace))
    manifest = [dict(kind=c.source_kind, locator=c.locator, sha256=c.content_sha256) for c in collections + logs]
    manifest += [dict(kind=v["source_kind"], locator=v["locator"], sha256=v["content_sha256"]) for v in codes["sources"].values()]
    manifest.sort(key=lambda x: (x["kind"], x["locator"], x["sha256"]))
    digest = hashlib.sha256(canonical(dict(version=TAXONOMY_IMPORT_VERSION, source_manifest=manifest))).hexdigest()
    taxonomy_id = uuid.uuid5(uuid.NAMESPACE_URL, canonical([str(store.namespace_id), "taxonomy-candidate", digest]).decode())
    version_key = TAXONOMY_IMPORT_VERSION + ":" + digest[:16]
    mappings, unresolved, observed, unresolved_logs = 0, 0, 0, 0
    with store.c.transaction():
        store._lock()
        store.c.execute("INSERT INTO p24_next.taxonomy_release(namespace_id,taxonomy_id,version_key,state,content_sha256) VALUES(%s,%s,%s,'draft',%s) ON CONFLICT DO NOTHING", (store.namespace_id,taxonomy_id,version_key,digest))
        state = store.c.execute("SELECT content_sha256,state FROM p24_next.taxonomy_release WHERE namespace_id=%s AND taxonomy_id=%s", (store.namespace_id,taxonomy_id)).fetchone()
        if state != (digest,"draft"):
            raise FoundationError("taxonomy_release_conflict")
        source_ids = {}
        specs = [(c.content_sha256,c.title,c.locator,c.source_kind) for c in collections + logs]
        specs += [(v["content_sha256"],v["title"],v["locator"],v["source_kind"]) for v in codes["sources"].values()]
        for source_digest,title,locator,kind in specs:
            proposed = uuid.uuid5(uuid.NAMESPACE_URL,"p24:"+store.namespace+":"+source_digest)
            store.c.execute("INSERT INTO p24_next.documentation_source(namespace_id,document_id,title,source_locator,content_sha256,source_kind) VALUES(%s,%s,%s,%s,%s,%s) ON CONFLICT(namespace_id,content_sha256) DO NOTHING", (store.namespace_id,proposed,title,locator,source_digest,kind))
            row = store.c.execute("SELECT document_id FROM p24_next.documentation_source WHERE namespace_id=%s AND content_sha256=%s",(store.namespace_id,source_digest)).fetchone()
            if row is None:
                raise FoundationError("taxonomy_source_persistence_failed")
            source_ids[source_digest] = row[0]
        insert = """INSERT INTO p24_next.service_mapping
            (namespace_id,taxonomy_id,mapping_id,service_key,source_role,exact_endpoint,method,
             service_selector,logged_action,phase_key,match_contract,status,document_id,rationale)
            VALUES(%s,%s,%s,NULL,%s,%s,%s,NULL,%s,'unknown',%s,'candidate',%s,%s)
            ON CONFLICT(namespace_id,taxonomy_id,mapping_id) DO NOTHING"""
        for collection in collections:
            for m in collection.mappings:
                mapping_id = uuid.uuid5(uuid.NAMESPACE_URL,"p24:"+store.namespace+":"+str(taxonomy_id)+":"+collection.content_sha256+":"+m["item_path"])
                contract = dict(collection=collection.title,item_path=m["item_path"],request_name=m["request_name"],
                    folder_path=m["folder_path"],endpoint_state=m["endpoint_state"],origin_kind=m["origin_kind"],classification_state="unresolved")
                store.c.execute(insert,(store.namespace_id,taxonomy_id,mapping_id,"client_http",m["exact_endpoint"],m["method"],m["request_name"],Jsonb(contract),source_ids[collection.content_sha256],
                    "Postman records a label and route; deployed service purpose, phase, security and provider binding remain unverified."))
                mappings += 1
                unresolved += int(m["endpoint_state"] != "resolved" or m["method"] is None)
        for source in logs:
            unresolved_logs += source.unresolved_record_count
            for m in source.mappings:
                mapping_id = uuid.uuid5(uuid.NAMESPACE_URL,"p24:"+store.namespace+":"+str(taxonomy_id)+":"+source.content_sha256+":"+m["source_role"]+":"+m["exact_endpoint"]+":"+str(m["method"]))
                contract = dict(source_kind="retained_sanitized_log",source_file=source.locator,endpoint_basis="CallPath",
                    observed_event_count=m["observed_event_count"],distinct_request_count=m["distinct_request_count"],
                    event_kinds=m["event_kinds"],classification_state="unresolved")
                store.c.execute(insert,(store.namespace_id,taxonomy_id,mapping_id,m["source_role"],m["exact_endpoint"],m["method"],m["logged_action"],Jsonb(contract),source_ids[source.content_sha256],
                    "A sanitized finite log sample records a CallPath and extraction role; deployed semantics remain unverified."))
                observed += 1
        for e in codes["records"]:
            entry_id = uuid.uuid5(uuid.NAMESPACE_URL,"p24:"+store.namespace+":"+str(taxonomy_id)+":"+e["source_sha256"]+":"+e["source_sheet"]+":"+str(e["source_row"])+":"+e["code"])
            store.c.execute("""INSERT INTO p24_next.catalog_code_entry
                (namespace_id,taxonomy_id,entry_id,code_system,code,user_message_fa,technical_symbol,
                 definition_state,meaning_authority,operation_binding_state,document_id,source_sheet,source_row,source_cells)
                VALUES(%s,%s,%s,%s,%s,%s,%s,%s,%s,'not_established_by_workbook',%s,%s,%s,%s)
                ON CONFLICT(namespace_id,taxonomy_id,entry_id) DO NOTHING""",
                (store.namespace_id,taxonomy_id,entry_id,e["code_system"],e["code"],e["user_message_fa"],e["technical_symbol"],
                 e["definition_state"],e["meaning_authority"],source_ids[e["source_sha256"]],e["source_sheet"],e["source_row"],Jsonb(e["source_cells"])))
    return dict(status="draft_candidates_imported",taxonomy_id=str(taxonomy_id),version_key=version_key,
        source_documents=len(source_ids),postman_collections=len(collections),postman_request_items=mappings,
        unresolved_endpoint_items=unresolved,observed_log_files=len(logs),observed_log_callpath_candidates=observed,
        unresolved_log_records=unresolved_logs,literal_error_code_rows=len(codes["records"]),published=False,
        semantic_classifications_inferred=False,request_bodies_or_auth_values_persisted=False)
