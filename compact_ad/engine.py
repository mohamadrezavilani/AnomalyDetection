"""Bounded per-window aggregates and explainable, past-only robust comparisons.

These are review signals, not calibrated fraud probabilities. References are
revised observed history at analysis time, not a claim of historical prediction.
"""

from collections import Counter, defaultdict
import math
import statistics
from compact_behavior import FEATURES, FIVE
from compact_behavior.extract import digest, canonical
from . import MODEL, MIN_REFERENCE_WINDOWS
from .methods import METHODS


def percentile(values, q=0.95):
    if not values:
        return 0
    items = sorted(values)
    return items[max(0, math.ceil(len(items) * q) - 1)]


def upper(values, *, floor=5):
    """Robust absolute threshold plus count noise; no future samples."""
    if not values:
        return None
    median = statistics.median(values)
    mad = statistics.median(abs(x - median) for x in values)
    return max(
        floor, median * 3, median + 6 * 1.4826 * mad + 4 * math.sqrt(max(1, median))
    )


def summarize(
    rows,
    *,
    max_rows=60000,
    max_feature_bytes=64 * 1024 * 1024,
    max_targets=100000,
    max_numeric_values=100000,
    cutoff_ns=None
):
    services = {}
    actors = {}
    total = 0
    bytes_used = 0
    targets_used = numeric_used = 0
    resource_invalid = False
    unresolved = 0
    invalid_contract = 0
    missing_actor = 0
    witness_limit = 12

    def service(key):
        if key not in services:
            services[key] = dict(
                count=0,
                invalid_rate=0,
                result_counts=Counter(),
                invalid_result=0,
                input_valid=0,
                input_invalid=0,
                output_valid=0,
                output_invalid=0,
                numeric_valid=0,
                numeric_invalid=0,
                shapes=Counter(),
                numeric=defaultdict(list),
                target_repeat=[],
                target_diversity=[],
                actor_counts=[],
                shape_witnesses=defaultdict(list),
                result_witnesses=defaultdict(list),
                witnesses=[],
                rate_eligible_count=0,
            )
        return services[key]

    for row in rows:
        if row.get("kind") == "automatic_support":
            continue
        total += 1
        if total > max_rows:
            raise ValueError("analysis_window_row_limit")
        f = row["features"]
        key = f.get("service_key") or "<unresolved>"
        s = service(key)
        s["count"] += 1
        if key == "<unresolved>":
            unresolved += 1
        valid_contract = f.get("version") == FEATURES
        if not valid_contract:
            invalid_contract += 1
        valid_rate = (
            valid_contract
            and f.get("service_rate_eligible") is True
            and key != "<unresolved>"
        )
        s["rate_eligible_count"] += valid_rate
        s["invalid_rate"] += not valid_rate
        if len(s["witnesses"]) < witness_limit:
            s["witnesses"].append(row["behavior_id"])
        if valid_contract and f.get("result_eligible") and key != "<unresolved>":
            s["result_counts"][row["result_code"]] += 1
            if len(s["result_witnesses"][row["result_code"]]) < witness_limit:
                s["result_witnesses"][row["result_code"]].append(row["behavior_id"])
        else:
            s["invalid_result"] += 1
        session = row["session_id"]
        actor = None
        if valid_rate and not f.get("session_eligible"):
            missing_actor += 1
        if valid_rate and f.get("session_eligible") is True and session:
            actor = actors.setdefault(
                (session, key),
                dict(
                    count=0,
                    targets=Counter(),
                    target_witnesses=defaultdict(list),
                    input_valid=0,
                    input_invalid=0,
                    witnesses=[],
                ),
            )
            actor["count"] += 1
            if len(actor["witnesses"]) < witness_limit:
                actor["witnesses"].append(row["behavior_id"])
        size = len(canonical(f).encode())
        bytes_used += size
        if bytes_used > max_feature_bytes:
            resource_invalid = True
            continue
        inp = f.get("input") or {}
        out = f.get("output") or {}
        ie = (
            valid_contract
            and (
                cutoff_ns is None
                or f.get("input_asof_ns") is not None
                and f["input_asof_ns"] < cutoff_ns
            )
            and f.get("input_feature_eligibility", {}).get("targets") is True
        )
        oe = (
            valid_contract
            and (
                cutoff_ns is None
                or f.get("output_asof_ns") is not None
                and f["output_asof_ns"] < cutoff_ns
            )
            and f.get("output_feature_eligibility", {}).get("shape") is True
        )
        s["input_valid"] += ie
        s["input_invalid"] += not ie
        s["output_valid"] += oe
        s["output_invalid"] += not oe
        if actor:
            actor["input_valid"] += ie
            actor["input_invalid"] += not ie
            if ie:
                # One occurrence per logical behavior+typed target. Repeated items
                # within a single array are not extra requests to that target.
                tokens = {
                    digest([path, value])
                    for path, values in inp.get("targets", {}).items()
                    for value in values
                }
                targets_used += len(tokens)
                if targets_used > max_targets:
                    resource_invalid = True
                else:
                    actor["targets"].update(tokens)
                    for token in tokens:
                        if len(actor["target_witnesses"][token]) < witness_limit:
                            actor["target_witnesses"][token].append(row["behavior_id"])
        if oe:
            s["shapes"][out["shape_hash"]] += 1
            if len(s["shape_witnesses"][out["shape_hash"]]) < witness_limit:
                s["shape_witnesses"][out["shape_hash"]].append(row["behavior_id"])
        ne = (
            valid_contract
            and (
                cutoff_ns is None
                or f.get("output_asof_ns") is not None
                and f["output_asof_ns"] < cutoff_ns
            )
            and f.get("output_feature_eligibility", {}).get("numeric") is True
        )
        s["numeric_valid"] += ne
        s["numeric_invalid"] += not ne
        if ne:
            for path, values in out.get("numeric", {}).items():
                if (
                    path.rsplit(".", 1)[-1].replace("[]", "").casefold()
                    == "executiontime"
                ):
                    continue
                numeric_used += 1
                if (
                    numeric_used > max_numeric_values
                    or len(s["numeric"]) >= 128
                    and path not in s["numeric"]
                ):
                    resource_invalid = True
                    break
                s["numeric"][path].append(values["mean"])
    for (session, key), actor in actors.items():
        s = services[key]
        s["actor_counts"].append(actor["count"])
        if actor["input_valid"] and not actor["input_invalid"]:
            s["target_repeat"].append(max(actor["targets"].values(), default=0))
            s["target_diversity"].append(len(actor["targets"]))
    # Persist service-level summaries only. Actor maps remain transient.
    summary = {
        key: dict(
            count=s["rate_eligible_count"],
            observed=s["count"],
            invalid_rate=s["invalid_rate"],
            result_counts=dict(s["result_counts"]),
            invalid_result=s["invalid_result"],
            input_valid=s["input_valid"],
            input_invalid=s["input_invalid"],
            output_valid=s["output_valid"],
            output_invalid=s["output_invalid"],
            numeric_valid=s["numeric_valid"],
            numeric_invalid=s["numeric_invalid"],
            shapes=dict(s["shapes"]),
            numeric={
                p: dict(n=len(v), median=statistics.median(v))
                for p, v in s["numeric"].items()
            },
            actor_p95=percentile(s["actor_counts"]),
            repeat_p95=percentile(s["target_repeat"]),
            diversity_p95=percentile(s["target_diversity"]),
        )
        for key, s in services.items()
    }
    return (
        dict(
            services=summary,
            total=total,
            unresolved=unresolved,
            invalid_contract=invalid_contract,
            missing_actor=missing_actor,
            invalid_behavior_rate=sum(v["invalid_rate"] for v in services.values()),
            content_resource_invalid=resource_invalid,
            feature_bytes=bytes_used,
        ),
        services,
        actors,
    )


def evaluate(start, summary, services, actors, references):
    # Defensive cutoff even when a caller mistakenly supplies future summaries.
    refs = sorted(
        [r for r in references if r["start_ns"] < start], key=lambda r: r["start_ns"]
    )
    if len({r["start_ns"] for r in refs}) != len(refs):
        raise ValueError("duplicate_reference_window")
    ref_count = len(refs)
    results = []
    signature_cache = {}
    reference_cache = {}
    cutoff = max((r["start_ns"] + FIVE for r in refs), default=None)

    def add(
        method,
        key,
        session,
        status,
        value=None,
        baseline=None,
        threshold=None,
        witnesses=(),
        reason=None,
        path=None,
        used=None,
    ):
        selected_refs = refs if used is None else used
        signature_key = tuple(id(r) for r in selected_refs)
        if signature_key not in signature_cache:
            signature_cache[signature_key] = digest(
                [
                    [r["start_ns"], r.get("summary_hash") or digest(r["summary"])]
                    for r in selected_refs
                ]
            )
        results.append(
            dict(
                method=method,
                service=key,
                session_id=session,
                status=status,
                observed=value,
                baseline=baseline,
                threshold=threshold,
                reference_windows=len(selected_refs),
                reference_from_ns=(
                    selected_refs[0]["start_ns"] if selected_refs else None
                ),
                reference_signature=signature_cache[signature_key],
                reference_cutoff_ns=max(
                    (r["start_ns"] + FIVE for r in selected_refs), default=None
                ),
                reference_policy="REVISED_OBSERVED_HISTORY_STRICTLY_BEFORE_TARGET",
                model_version=MODEL,
                feature_version=FEATURES,
                window_start_ns=start,
                window_end_ns=start + FIVE,
                evidence=list(witnesses)[:12],
                reason=reason,
                numeric_path=path,
                next_action="درخواست‌های شاهد و خطای استخراج را بررسی کنید؛ سپس نتیجهٔ انسانی را ثبت کنید.",
            )
        )

    def history_for(key):
        if key not in reference_cache:
            pairs = []
            for r in refs:
                h = r["summary"]["services"].get(key)
                if h is not None:
                    if h["invalid_rate"]:
                        continue
                elif r["summary"]["invalid_contract"] or r["summary"]["unresolved"]:
                    continue
                else:
                    h = dict(
                        count=0,
                        result_counts={},
                        input_valid=0,
                        input_invalid=0,
                        output_valid=0,
                        output_invalid=0,
                        numeric={},
                        shapes={},
                    )
                pairs.append((r, h))
            reference_cache[key] = ([r for r, h in pairs], [h for r, h in pairs])
        return reference_cache[key]

    for key, s in services.items():
        rate_refs, history = history_for(key)
        count = summary["services"][key]["count"]
        historical_count = sum(h["count"] for h in history)
        enough = len(history) >= MIN_REFERENCE_WINDOWS and historical_count >= 30
        invalid = s["invalid_rate"] > 0 or key == "<unresolved>"
        threshold = upper([h["count"] for h in history])
        value = count
        status = (
            "INVALID_INPUT"
            if invalid
            else (
                "INSUFFICIENT_DATA"
                if not enough
                else "ANOMALY" if value > threshold else "NORMAL"
            )
        )
        add(
            "service_rate",
            key,
            None,
            status,
            value,
            statistics.median([h["count"] for h in history]) if history else None,
            threshold,
            s["witnesses"],
            "UNRESOLVED_OR_INCOMPLETE_BEHAVIOR" if invalid else None,
            used=rate_refs,
        )
        result_n = sum(s["result_counts"].values())
        old_results = Counter()
        for h in history:
            if not h.get("invalid_result", 0):
                old_results.update(h["result_counts"])
        # No undocumented code is labelled failure. Compare the distribution of
        # exact reported codes. G00000 is a named reported success, not finance.
        old_n = sum(old_results.values())
        error_n = result_n - s["result_counts"].get("G00000", 0)
        old_errors = old_n - old_results.get("G00000", 0)
        base = old_errors / old_n if old_n else None
        limit = (
            max(
                0.25,
                base + 4 * math.sqrt(max(0.0001, base * (1 - base)) / max(1, result_n)),
            )
            if base is not None
            else None
        )
        status = (
            "INVALID_INPUT"
            if invalid or s["invalid_result"]
            else (
                "INSUFFICIENT_DATA"
                if len([h for h in history if not h.get("invalid_result", 0)])
                < MIN_REFERENCE_WINDOWS
                or old_n < 30
                or result_n < 10
                else "ANOMALY" if error_n / result_n > limit else "NORMAL"
            )
        )
        add(
            "reported_result",
            key,
            None,
            status,
            error_n / result_n if result_n else None,
            base,
            limit,
            [
                bid
                for code, bids in s["result_witnesses"].items()
                if code != "G00000"
                for bid in bids
            ],
            reason="NON_G00000_CODE_SHARE_NOT_PAYMENT_FAILURE",
            used=[
                r for r, h in zip(rate_refs, history) if not h.get("invalid_result", 0)
            ],
        )
        content_bad = (
            summary["content_resource_invalid"]
            or summary["invalid_contract"] > 0
            or key == "<unresolved>"
        )
        old_shapes = Counter()
        for h in history:
            if not h.get("output_invalid", 0):
                old_shapes.update(h["shapes"])
        novel = sum(
            n for shape, n in s["shapes"].items() if old_shapes.get(shape, 0) == 0
        )
        status = (
            "INVALID_INPUT"
            if content_bad or s["output_invalid"]
            else (
                "INSUFFICIENT_DATA"
                if len([h for h in history if not h.get("output_invalid", 0)])
                < MIN_REFERENCE_WINDOWS
                or sum(old_shapes.values()) < 30
                or s["output_valid"] < 10
                else "ANOMALY" if novel / s["output_valid"] > 0.5 else "NORMAL"
            )
        )
        add(
            "response_shape",
            key,
            None,
            status,
            novel / max(1, s["output_valid"]),
            0,
            0.5,
            [
                bid
                for shape, bids in s["shape_witnesses"].items()
                if old_shapes.get(shape, 0) == 0
                for bid in bids
            ],
            reason="SHARE_OF_PREVIOUSLY_UNSEEN_RESPONSE_SHAPES",
            used=[
                r for r, h in zip(rate_refs, history) if not h.get("output_invalid", 0)
            ],
        )
        paths = sorted(s["numeric"])
        if not paths:
            add(
                "response_numeric",
                key,
                None,
                (
                    "INVALID_INPUT"
                    if content_bad or s["numeric_invalid"]
                    else "INSUFFICIENT_DATA"
                ),
                reason="NO_ELIGIBLE_NUMERIC_PATH",
                used=[],
            )
        for path in paths:
            values = s["numeric"][path]
            past = [
                h["numeric"][path]["median"]
                for h in history
                if path in h["numeric"] and not h.get("numeric_invalid", 0)
            ]
            n = sum(h["numeric"].get(path, {}).get("n", 0) for h in history)
            median = statistics.median(past) if past else None
            spread = statistics.median(abs(x - median) for x in past) if past else None
            delta = max(abs(median) * 0.5, 6 * 1.4826 * spread, 1e-9) if past else None
            value = statistics.median(values)
            status = (
                "INVALID_INPUT"
                if content_bad or s["numeric_invalid"]
                else (
                    "INSUFFICIENT_DATA"
                    if len(past) < MIN_REFERENCE_WINDOWS or n < 30 or len(values) < 10
                    else "ANOMALY" if abs(value - median) > delta else "NORMAL"
                )
            )
            add(
                "response_numeric",
                key,
                None,
                status,
                value,
                median,
                delta,
                s["witnesses"],
                reason="ABSOLUTE_MEDIAN_DEVIATION_THRESHOLD",
                path=path,
                used=[
                    r
                    for r, h in zip(rate_refs, history)
                    if path in h["numeric"] and not h.get("numeric_invalid", 0)
                ],
            )
    for (session, key), actor in actors.items():
        rate_refs, history = history_for(key)
        enough = (
            len(history) >= MIN_REFERENCE_WINDOWS
            and sum(h["count"] for h in history) >= 30
        )
        threshold = upper([h.get("actor_p95", 0) for h in history])
        status = (
            "INSUFFICIENT_DATA"
            if not enough
            else "ANOMALY" if actor["count"] > threshold else "NORMAL"
        )
        add(
            "actor_rate",
            key,
            session,
            status,
            actor["count"],
            (
                statistics.median([h.get("actor_p95", 0) for h in history])
                if history
                else None
            ),
            threshold,
            actor["witnesses"],
            used=rate_refs,
        )
        for method, field, value in [
            (
                "repeated_target",
                "repeat_p95",
                max(actor["targets"].values(), default=0),
            ),
            ("target_diversity", "diversity_p95", len(actor["targets"])),
        ]:
            old_valid = sum(h["input_valid"] for h in history)
            past = [
                h.get(field, 0)
                for h in history
                if h["input_valid"] and not h.get("input_invalid")
            ]
            threshold = upper(past)
            status = (
                "INVALID_INPUT"
                if actor["input_invalid"] or summary["content_resource_invalid"]
                else (
                    "INSUFFICIENT_DATA"
                    if len(past) < MIN_REFERENCE_WINDOWS
                    or old_valid < 30
                    or not actor["input_valid"]
                    else "ANOMALY" if value > threshold else "NORMAL"
                )
            )
            witnesses = (
                actor["target_witnesses"].get(
                    max(actor["targets"], key=actor["targets"].get), []
                )
                if method == "repeated_target" and actor["targets"]
                else actor["witnesses"]
            )
            add(
                method,
                key,
                session,
                status,
                value,
                statistics.median(past) if past else None,
                threshold,
                witnesses,
                used=[
                    r
                    for r, h in zip(rate_refs, history)
                    if h["input_valid"] and not h.get("input_invalid")
                ],
            )
    # Actor service mix versus past population, not an inferred personal identity.
    grouped = defaultdict(dict)
    for (session, key), actor in actors.items():
        grouped[session][key] = actor
    mix_refs = [
        r
        for r in refs
        if not r["summary"]["invalid_contract"]
        and not r["summary"]["unresolved"]
        and not r["summary"].get("invalid_behavior_rate")
    ]
    past_total = sum(
        sum(h["count"] for h in r["summary"]["services"].values()) for r in mix_refs
    )
    for session, group in grouped.items():
        n = sum(a["count"] for a in group.values())
        rare = []
        for key, actor in group.items():
            k = sum(
                r["summary"]["services"].get(key, {}).get("count", 0) for r in mix_refs
            )
            if past_total and k / past_total < 0.01:
                rare.append((key, actor["count"]))
        rare_count = sum(n for key, n in rare)
        status = (
            "INVALID_INPUT"
            if summary["invalid_contract"]
            or summary["unresolved"]
            or summary.get("invalid_behavior_rate")
            else (
                "INSUFFICIENT_DATA"
                if len(mix_refs) < MIN_REFERENCE_WINDOWS or past_total < 100 or n < 10
                else "ANOMALY" if rare_count / n > 0.8 else "NORMAL"
            )
        )
        add(
            "service_mix",
            "*",
            session,
            status,
            rare_count / max(1, n),
            0.01,
            0.8,
            [
                v
                for key, actor in group.items()
                if key in {k for k, n in rare}
                for v in actor["witnesses"]
            ],
            reason="SHARE_OF_SERVICES_RARE_IN_PAST_POPULATION",
            used=mix_refs,
        )
    # Missing actors/content produce explicit method readiness, not green success.
    present = {r["method"] for r in results}
    for method in METHODS.keys() - present:
        add(
            method,
            "*",
            None,
            (
                "INVALID_INPUT"
                if summary["invalid_contract"]
                or summary["unresolved"]
                or summary.get("invalid_behavior_rate")
                or summary.get("missing_actor")
                else "INSUFFICIENT_DATA"
            ),
            reason="NO_ELIGIBLE_OBSERVATIONS",
        )
    return results
