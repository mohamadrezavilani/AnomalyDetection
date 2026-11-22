"""Bounded, typed, multi-day input comparisons over authoritative Sessions.

Sets retain the smallest hashes, not an additive daily distinct count. When a
set fills, its size is a lower bound; it is never used as an exact peer value.
There is no identity inference from IP and no raw input value in this layer.
"""
import json
import statistics
import zlib
import time
from collections import defaultdict

from compact_behavior import FEATURES, FIVE
from compact_behavior.extract import digest
from .engine import upper

VERSION = "compact-long-input-1"
METHOD = "long_target_enumeration"
DAY = 288 * FIVE
OFFSET = 210 * 60 * 10**9  # Tehran; event dates supported by this product.
SPANS = (3, 7, 30)
TARGET_CAP = 256
ACTOR_CAP = 50000
ENTRY_CAP = 250000
BYTE_CAP = 32 * 1024 * 1024


class CapacityExceeded(Exception):
    pass


def day_start(at):
    return ((at + OFFSET) // DAY) * DAY - OFFSET


def pack(value):
    raw = json.dumps(value, separators=(",", ":"), sort_keys=True).encode()
    if len(raw) > BYTE_CAP:
        raise CapacityExceeded("longitudinal_payload_budget")
    return zlib.compress(raw, 3)


def unpack(blob):
    decoder = zlib.decompressobj()
    raw = decoder.decompress(bytes(blob), BYTE_CAP + 1)
    if len(raw) > BYTE_CAP or not decoder.eof or decoder.unused_data:
        raise CapacityExceeded("longitudinal_payload_budget")
    return json.loads(raw)


def projection(summary, actors):
    """Reuse the already-read window; no source or database lookups."""
    services = defaultdict(dict)
    for (session, service), a in actors.items():
        fields = {}
        for path, field in a.get("target_fields", {}).items():
            tokens = sorted(field["tokens"])
            fields[path] = dict(tokens=tokens[:TARGET_CAP],
                                overflow=len(tokens) > TARGET_CAP,
                                covered=field["covered"])
        services[service][session] = dict(
            count=a["count"], fields=fields, days=1,
            invalid=bool(a["input_invalid"] or a.get('sequence_incomplete') or summary["content_resource_invalid"]),
            evidence=list(a["witnesses"])[:6],
        )
    return dict(services)


def merge(chunks, *, active_days=False):
    """Merge window chunks into a day, or day chunks into a span.

    Budgets are fail-closed for this service/cohort, never partial-normal. The
    caller streams one service at a time, so memory does not grow with history.
    """
    actors = {}
    entries = 0
    for chunk in chunks:
        if '@capacity_limit' in chunk:
            raise CapacityExceeded('longitudinal_window_payload_budget')
        for session, row in chunk.items():
            a = actors.setdefault(session, dict(count=0, fields={}, days=0,
                                                 invalid=False, evidence=[]))
            if len(actors) > ACTOR_CAP:
                raise CapacityExceeded("longitudinal_actor_budget")
            a["count"] += row["count"]
            a["days"] = a["days"] + 1 if active_days else 1
            a["invalid"] |= row["invalid"]
            # Keep evidence from both the beginning and end of the span.
            evidence = list(dict.fromkeys(a["evidence"] + row["evidence"]))
            a["evidence"] = evidence if len(evidence) <= 12 else evidence[:6] + evidence[-6:]
            for path, field in row["fields"].items():
                dest = a["fields"].setdefault(path, dict(tokens=set(), overflow=False, covered=0))
                previous = len(dest["tokens"])
                union = dest["tokens"] | set(field["tokens"])
                dest["overflow"] |= field["overflow"] or len(union) > TARGET_CAP
                dest["tokens"] = set(sorted(union)[:TARGET_CAP])
                dest["covered"] += field["covered"]
                entries += len(dest["tokens"]) - previous
                if entries > ENTRY_CAP:
                    raise CapacityExceeded("longitudinal_target_budget")
    for a in actors.values():
        for f in a["fields"].values():
            f["tokens"] = sorted(f["tokens"])
    return actors


def evaluate(actors, *, service, end, span, signature, diagnostics=None):
    """Contemporaneous peer comparison at a completed event-time cutoff.

    A conservative rank and effect-size rule, not a fraud probability. Peers
    share service, typed field, span, activity days and comparable request
    volume. A single well-supported content reason can open a review case.
    """
    results = []
    diagnostics = diagnostics if diagnostics is not None else {}
    diagnostics.update(eligible_comparisons=0,insufficient_peer_comparisons=0,
                       censored_peer_comparisons=0)
    began = time.monotonic()
    # Build sorted volume indexes once; avoid all-actor squared comparisons.
    import bisect
    indexes = defaultdict(list)
    for number, (session, a) in enumerate(actors.items()):
        if number % 100 == 0 and time.monotonic()-began > 5:
            raise CapacityExceeded('longitudinal_comparison_time_budget')
        if a["invalid"]:
            continue
        for path, field in a["fields"].items():
            if field["covered"] == a["count"]:
                indexes[(path, a["days"])].append((a["count"], session, len(field["tokens"]),field['overflow']))
    for values in indexes.values():
        values.sort()
    # Rank correction is over tested typed fields/spans, not activity buckets.
    comparisons = max(1, len({path for path, _ in indexes})) * len(SPANS)
    for number, (session, a) in enumerate(actors.items()):
        if number % 100 == 0 and time.monotonic()-began > 5:
            raise CapacityExceeded('longitudinal_comparison_time_budget')
        if a["invalid"] or a["days"] < (3 if span <= 7 else 7):
            continue
        best = None
        for path, field in a["fields"].items():
            if field["covered"] != a["count"]:
                continue
            observed = len(field["tokens"]) + int(field["overflow"])
            if observed <= 20:
                continue
            peers = []
            for days in range(max(1, a["days"] - 1), a["days"] + 2):
                values = indexes.get((path, days), [])
                left = bisect.bisect_left(values, (a["count"] / 2, "", -1))
                right = bisect.bisect_right(values, (a["count"] * 2, chr(0x10ffff), 10**20))
                peers.extend((v,limited) for _, identity, v, limited in values[left:right] if identity != session)
            if any(limited for _,limited in peers):
                diagnostics['censored_peer_comparisons']+=1
                continue
            peers=[v for v,_ in peers]
            if len(peers) < 100:
                diagnostics['insufficient_peer_comparisons']+=1
                continue
            diagnostics['eligible_comparisons']+=1
            limit = max(20, upper(peers), max(peers) + 1)
            rank = min(1, comparisons * (1 + sum(v >= observed for v in peers)) / (1 + len(peers)))
            if observed <= limit or rank > .05:
                continue
            candidate = dict(
                method=METHOD, service=service, session_id=session, status="ANOMALY",
                observed=observed, observed_is_lower_bound=field["overflow"],
                baseline=statistics.median(peers), threshold=limit,
                peer_count=len(peers), peer_max=max(peers), adjusted_tail_rank=rank,
                comparisons=comparisons, active_days=a["days"], requests=a["count"],
                numeric_path=path, horizon_days=span, period_start_ns=end-span*DAY,
                period_end_ns=end, reference_windows=span*288,
                reference_cutoff_ns=end, reference_signature=signature,
                reference_policy="SAME_COMPLETED_PERIOD_TYPED_FIELD_VOLUME_ACTIVITY_PEERS",
                model_version=VERSION, feature_version=FEATURES,
                window_start_ns=end-FIVE, window_end_ns=end,
                evidence=a["evidence"], single_signal_review_eligible=True,
                reason="QUALIFIED_MULTI_DAY_TARGET_ENUMERATION",
                next_action="تنوع شناسه‌ها و درخواست‌های شاهد را بررسی کنید؛ رتبهٔ آماری احتمال تخلف نیست.",
            )
            if best is None or candidate["adjusted_tail_rank"] < best["adjusted_tail_rank"]:
                best = candidate
        if best and len(set(best["evidence"])) >= 3:
            results.append(best)
    return results
