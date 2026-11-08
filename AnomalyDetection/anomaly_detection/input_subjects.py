"""Verified one-subject inputs and a conservative peer count comparison."""
from collections import defaultdict
import hmac
from pathlib import Path
import re
import secrets

from . import FIVE_NS
from .snapshot import ContractError, api_path, canonical, digest

VERSION = "verified-inquiry-input-1"
FAMILY = "input_subject_burst"
PRIMARY_FAMILIES = ("peer_service_rate_5m", FAMILY)
CONTRACTS = {
    "Services.v1/WaterBills": ("WaterBillID", ("WaterBillInquiry",)),
    "Services.v1/ElectricBills": ("ElectricityBillID", ("ElectricityBillInquiry",)),
    "Services.v1/GasBills": ("GasBillID", ("GasBillInquiry",)),
    "Services.v2/GasBills": ("ParticipateCode", ("GasBillInquiry",)),
    "Services.v1/LandLinePhoneBills": ("FixedLineNumber", ("FixedLineBillInquiry",)),
    "Services.v1/CellPhoneBills": ("MobileNumber", (
        "MCIMobileBillInquiry", "MTNMobileBillInquiry", "MtnMobileDebtInquiry", "RightelMobileBillInquiry",
    )),
}
MAX_INPUT_EVENTS = 4
MAX_INPUT_READS = 8
MAX_INPUT_MESSAGE_CHARS = 262144
WITNESS_FIELDS = ("origin_key", "version_key", "at_ns", "callpath")


def load_key(project):
    """The single owned worker creates a private, persistent HMAC key."""
    from .process_control import read_json, write_json
    path = Path(project) / "AnomalyDetection/data/input_subject_key.local.json"
    data = read_json(path)
    if data is None:
        data = {"key": secrets.token_hex(32)}
        write_json(path, data)
    try:
        key = bytes.fromhex(data["key"])
    except (ValueError, KeyError, TypeError):
        raise ContractError("AD_INPUT_SUBJECT_KEY_INVALID") from None
    if len(key) != 32:
        raise ContractError("AD_INPUT_SUBJECT_KEY_INVALID")
    return key


def provider_call(service, callpath):
    return api_path(callpath) in {"ClientAyanCoInquiry."+method for method in CONTRACTS[service][1]}


def input_value(message, field, parse_section):
    if not isinstance(message, str) or len(message) > MAX_INPUT_MESSAGE_CHARS:
        return None
    start = message.find("Input:")
    output = message.find("Output:")
    if start < 0 or 0 <= output < start:
        return None
    payload, state = parse_section(message, "Input:")
    if state != "complete":
        return None
    if isinstance(payload, list):
        if len(payload) != 1:
            return None
        payload = payload[0]
    if not isinstance(payload, dict):
        return None
    values = [p[field] for p in (payload, payload.get("Parameters"))
              if isinstance(p, dict) and field in p]
    if not values or any(type(v) is not str for v in values):
        return None
    found = set()
    for value in values:
        value = value.strip()
        if field == "MobileNumber":
            if re.fullmatch(r"(?:\+98|0098|98)9[0-9]{9}", value):
                value = "0"+value[-10:]
            elif re.fullmatch(r"9[0-9]{9}", value):
                value = "0"+value
            if not re.fullmatch(r"09[0-9]{9}", value):
                return None
        elif field == "FixedLineNumber" and re.fullmatch(r"(?:\+98|0098|98)[1-8][0-9]{9}", value):
            value = "0"+value[-10:]
        if not re.fullmatch(r"[0-9]{3,32}", value) or not value.strip("0"):
            return None
        found.add(value)
    return next(iter(found)) if len(found) == 1 else None


def collect(snapshot, reader, parse_section, message_field, key):
    """Read only known provider input fields from the pinned audit snapshot."""
    scopes = {request: api_path(row.get("root_call")) for request, row in snapshot.occurrences.items()
              if row.get("state") == "active" and row.get("kind") == "service_execution"}
    events = defaultdict(list)
    for event in snapshot.tables["viewer_events"]:
        request = event.get("request_key")
        service = scopes.get(request)
        if service in CONTRACTS and provider_call(service, event.get("callpath")):
            events[request].append(event)
    result = {}
    deferred = False
    reads = 0
    for request, service in scopes.items():
        if service not in CONTRACTS:
            continue
        row = snapshot.requests.get(request, {})
        expected = snapshot.occurrences[request]
        field = CONTRACTS[service][0]
        receipt = {"version": VERSION, "field": field, "status": "UNKNOWN"}
        result[request] = receipt
        found = events[request]
        if (row.get("identity_state") != "assigned" or row.get("conflicted")
                or not expected.get("session_key") or row.get("session_key") != expected["session_key"]
                or not 1 <= len(found) <= MAX_INPUT_EVENTS
                or any(not e["raw_available"] or len(snapshot.origins[e["origin_key"]]) != 1 for e in found)):
            continue
        values = set()
        proof = []
        for event in sorted(found, key=lambda e: (e["at_ns"], e["origin_key"])):
            if deferred or reads >= MAX_INPUT_READS:
                deferred = True
                break
            try:
                reads += 1
                raw = reader.get_raw(event["origin_key"], event["version_key"])
            except Exception as exc:
                if getattr(exc, "sqlstate", None) not in ("57014", "55P03") and not (
                    isinstance(exc, ContractError) and str(exc) == "SOURCE_TOTAL_READ_BUDGET_EXCEEDED"
                ):
                    raise
                deferred = True
                break
            message, status = message_field(raw, "message") if raw else (None, "missing")
            value = input_value(message, field, parse_section) if status == "present" else None
            if value is None:
                break
            values.add(value)
            proof.append({k: event[k] for k in WITNESS_FIELDS})
        if deferred:
            receipt["status"] = "READ_DEFERRED"
        elif len(values) == 1 and len(proof) == len(found):
            receipt.update(status="VERIFIED", witnesses=proof, key_tag=digest(key.hex())[:16],
                           subject_key=hmac.digest(key, canonical([service, field, next(iter(values))]).encode(),
                                                   "sha256").hex())
    return result


def verified_subject(event, detail, service):
    fact = detail or {}
    semantic = fact.get("semantic", {})
    quality = fact.get("quality", {})
    subject = fact.get("input_subject") or {}
    if not (service in CONTRACTS and fact.get("source_present") is True and quality.get("evidence_available") is True
            and not quality.get("conflicted") and semantic.get("state") == "active"
            and semantic.get("request_key") == event["request_key"]
            and semantic.get("session_key") == event["session_key"]
            and semantic.get("anchor_key") == event["anchor_key"]
            and semantic.get("revision") == event["revision"]
            and subject.get("version") == VERSION and subject.get("status") == "VERIFIED"
            and subject.get("field") == CONTRACTS[service][0] and subject.get("subject_key")
            and subject.get("key_tag")):
        return None
    current = [e for e in fact.get("evidence", []) if provider_call(service, e.get("callpath"))]
    if not 1 <= len(current) <= MAX_INPUT_EVENTS or not all(
        e.get("qualified") is True and e.get("raw_available") is True for e in current
    ):
        return None
    locators = [{k: e.get(k) for k in WITNESS_FIELDS} for e in sorted(current, key=lambda e: (e["at_ns"], e["origin_key"]))]
    if locators == subject.get("witnesses"):
        return subject
    return None


def decisions(job, context, details, rates):
    """P(U_peer >= u) is bounded by P(N_peer >= u) when each request has one input.

    This uses the same tested service/window comparison as the triggering rate
    decision. It does not claim a fitted subject baseline or independent votes.
    """
    from .service_reference import rank_screen
    rates = [r for r in rates if r["family"] == "peer_service_rate_5m" and r.get("service_path") in CONTRACTS]
    if not rates:
        return
    target = job["target_ns"]
    session = job["session_key"]
    events = defaultdict(dict)
    for event in context.get("events", []):
        service = api_path(event.get("root_call"))
        if (service in CONTRACTS and event.get("kind") == "service_execution" and event.get("session_key") == session
                and target <= event["anchor_ns"] < target+FIVE_NS):
            events[service][event["request_key"]] = event
    by_key = {row["request_key"]:row.get("details") for row in details}
    for rate in rates:
        service = rate.get("service_path")
        source_model = rate.get("model") or {}
        candidate = rate.get("status") == "CANDIDATE"
        base = {"family": FAMILY, "dimension": "input_subject", "target_ns": target, "session_key": session,
                "finding_key": "pf1:"+digest([session,target,FAMILY,service]), "service_path":service,
                "begin_ns":target, "end_ns":target+FIVE_NS, "subject_field":CONTRACTS[service][0],
                "observed_requests":rate.get("observed"), "operator_alert":False,
                "count_scope":"verified_single_input_subject_per_canonical_request",
                "status":"INSUFFICIENT_DATA", "reason":"COMPARABLE_INPUT_REFERENCE_REQUIRED",
                "explanation_fa":"برای این روش به مرجع هم‌دامنه و شاهد معتبر موضوع ورودی نیاز است.",
                "evidence_verified":False, "single_signal_review_eligible":False}
        if not candidate or source_model.get("unit") != "canonical_service_executions":
            # The conservative count reference may prove a positive, but it
            # cannot prove the absence of a subject-specific deviation.
            yield base
            continue
        rows = events[service]
        proofs = [verified_subject(event, by_key.get(request),service) for request,event in rows.items()]
        available = [p for p in proofs if p is not None]
        if (not context.get("target_complete") or not context.get("target_events_complete")
                or len(rows) != rate["observed"] or len(available) != len(rows)
                or len({p["key_tag"] for p in available}) != 1):
            yield base | {"reason":"VERIFIED_INPUT_EVIDENCE_INCOMPLETE", "verified_input_requests":len(available),
                          "explanation_fa":"شاهد موضوع ورودی برای همهٔ اجراهای این خدمت هنوز تکمیل نشده است."}
            continue
        distinct = len({p["subject_key"] for p in available})
        screen = rank_screen(source_model,distinct,rate["comparison_count"])
        times = sorted(e["anchor_ns"] for e in rows.values())
        span = times[-1]-times[0]
        proof_model = {
            "model_id":"is1:"+digest([VERSION,source_model["model_id"],rate["comparison_count"]]),
            "version":VERSION,"cutoff_ns":source_model["cutoff_ns"],
            "reference_model_id":source_model["model_id"],"comparison_count":rate["comparison_count"],
            "reference_unit":"other_sessions_total_executions_upper_bound_for_distinct_subjects",
        }
        base.update(observed=distinct, verified_input_requests=len(available), evidence_verified=True,
                    observed_span_ns=span, request_keys=sorted(rows),
                    witness_request_key=min(rows,key=lambda k:rows[k]["anchor_ns"]),
                    baseline_unit="other_sessions_total_executions_upper_bound_for_distinct_subjects",
                    peer_session_epochs=source_model["other_session_epochs"],
                    upper_bound_tail_rank=screen["adjusted_empirical_tail_rank"],
                    model=proof_model, reference_model_id=source_model["model_id"],
                    reference_cutoff_ns=source_model["cutoff_ns"])
        if distinct < 2:
            base.update(status="NO_DEVIATION_OBSERVED",reason="ONE_VERIFIED_INPUT_SUBJECT",
                        explanation_fa="همهٔ درخواست‌های تأییدشده به یک موضوع ورودی مربوط‌اند.")
        elif screen["high"]:
            base.update(status="CANDIDATE",reason="UNUSUAL_DISTINCT_INQUIRY_INPUTS",
                        single_signal_review_eligible=True,review_basis="VERIFIED_DISTINCT_INPUTS_CONSERVATIVE_BOUND",
                        score=1-screen["adjusted_empirical_tail_rank"],
                        explanation_fa=f'{distinct} موضوع ورودی متمایز در {len(rows)} اجرای یکتا طی {span/1e9:.2f} ثانیه. '
                        f'کران محافظه‌کارانهٔ رتبهٔ دُم {screen["adjusted_empirical_tail_rank"]:.6f} است. '
                        'مرجع از تعداد کل اجراهای نشست‌های دیگر ساخته شده است و رتبه، احتمال تقلب نیست.')
        yield base
