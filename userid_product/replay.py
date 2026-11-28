"""Offline WP01 qualification. Emits aggregate coverage only, never raw identities.

Not a collector, database migration, detector or production launcher. Files
remain private; an optional report contains counts/versions/hashes only.
"""
from __future__ import annotations

import argparse
from collections import Counter
from dataclasses import replace
import json
from pathlib import Path
import sys
import time

from compact_behavior.extract import canonical
from contracts.userid import CONTRACT_VERSION, FEATURE_VERSION, IDENTITY_POLICY_VERSION
from contracts.userid.validate import validate_record
from . import EXTRACTOR_VERSION
from .extraction import (Limits, LimitExceeded, behavior_hash, extract_window,
                         materialize, merge, verify_adapter)
from .source import WindowFile


def replay(paths, source_scope, *, seen_at_ns, limits=Limits(), progress=None):
    started = time.perf_counter()
    states = {}
    sizes = {}
    state_bytes = peak_bytes = 0
    windows = []
    repeated_requests = changed_behaviors = 0
    quarantine = Counter()
    for path in paths:
        window_started = time.perf_counter()
        window, extracted = extract_window(WindowFile(path), source_scope, seen_at_ns, limits=limits)
        quarantine.update(extracted.quarantine)
        for rid, state in extracted.states.items():
            previous = states.get(rid)
            if previous:
                repeated_requests += 1
            prepared = merge(previous, state, limits)
            if previous and behavior_hash(materialize(previous)) != behavior_hash(materialize(prepared)):
                changed_behaviors += 1
            size = len(canonical(prepared).encode("utf-8"))
            state_bytes += size - sizes.get(rid, 0)
            if state_bytes > limits.total_state_bytes or len(states) + (rid not in states) > limits.requests:
                raise LimitExceeded("replay_aggregate_state_limit")
            states[rid] = prepared
            sizes[rid] = size
        peak_bytes = max(peak_bytes, state_bytes + extracted.state_bytes)
        windows.append(dict(window, requests=len(extracted.states),
                            encoded_window_state_bytes=extracted.state_bytes,
                            extraction_and_merge_seconds=round(time.perf_counter()-window_started, 3)))
        if progress:
            progress(dict(stage="WINDOW_VERIFIED", windows=len(windows),
                          source_records=window["source_records"], requests=len(extracted.states)))
    counts = {name: Counter() for name in ("identity_status", "identity_kind", "state", "operation_role", "attempt_kind")}
    eligibility = Counter()
    actor_keys = set()
    digest_parts = []
    for rid in sorted(states):
        behavior = materialize(states[rid])
        validate_record(behavior)
        counts["identity_status"][behavior["identity"]["status"]] += 1
        counts["identity_kind"][behavior["identity"]["kind"]] += 1
        counts["state"][behavior["state"]] += 1
        counts["operation_role"][behavior["operation_role"]] += 1
        attempt = behavior["observations"]["attempt"]
        if attempt:
            counts["attempt_kind"][attempt["kind"]] += 1
        if behavior["identity"]["actor_key"]:
            actor_keys.add(behavior["identity"]["actor_key"])
        for field in ("actor_eligible", "account_eligible", "service_eligible", "result_eligible"):
            eligibility[field] += behavior["features"][field]
        for direction in ("input", "output"):
            for dimension, eligible in behavior["features"][direction]["eligibility"].items():
                eligibility[direction + "_" + dimension] += eligible
        digest_parts.append(behavior_hash(behavior))
        if progress and len(digest_parts) % 10000 == 0:
            progress(dict(stage="BEHAVIORS_VALIDATED", requests=len(digest_parts)))
    from compact_behavior.extract import digest
    return dict(status="VERIFIED_OFFLINE", contract_version=CONTRACT_VERSION,
                extractor_version=EXTRACTOR_VERSION, identity_policy_version=IDENTITY_POLICY_VERSION,
                feature_version=FEATURE_VERSION, content_adapter=verify_adapter(), windows=windows,
                source_records=sum(w["source_records"] for w in windows), logical_requests=len(states),
                repeated_request_window_memberships=repeated_requests,
                cross_window_behavior_changes=changed_behaviors, quarantine=dict(quarantine),
                counts={k: dict(v) for k, v in counts.items()}, eligibility=dict(eligibility),
                distinct_valid_actors=len(actor_keys), normalized_behavior_digest=digest(digest_parts),
                aggregate_encoded_state_bytes=state_bytes,
                peak_simultaneous_encoded_state_bytes=peak_bytes,
                elapsed_seconds=round(time.perf_counter()-started, 3),
                not_run=["LIVE_ELASTICSEARCH", "POSTGRESQL", "CURSOR_PUBLICATION_RECOVERY",
                         "DETECTOR_ACCURACY", "BROWSER", "PRODUCTION_CAPACITY"])


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("files", nargs="+", type=Path)
    parser.add_argument("--scope", required=True)
    parser.add_argument("--seen-at-ns", default=str(time.time_ns()))
    parser.add_argument("--max-requests", type=int, default=60000)
    parser.add_argument("--max-total-state-mib", type=int, default=128)
    parser.add_argument("--report", type=Path)
    args = parser.parse_args(argv)
    if args.max_requests < 1 or not 1 <= args.max_total_state_mib <= 4096:
        parser.error("invalid replay budget")
    report = replay(args.files, args.scope, seen_at_ns=args.seen_at_ns,
                    limits=replace(Limits(), requests=args.max_requests,
                                   total_state_bytes=args.max_total_state_mib * 1024**2),
                    progress=lambda value: print(json.dumps(value), file=sys.stderr, flush=True))
    result = json.dumps(report, ensure_ascii=False, indent=2) + "\n"
    if args.report:
        args.report.write_text(result, encoding="utf-8")
    print(result, end="")


if __name__ == "__main__":
    main()
