"""Bounded extracted facts, never source log records or a request tree."""

from __future__ import annotations
from dataclasses import dataclass
from datetime import datetime, timezone
import hashlib
import json
import math
import re
from . import CONTRACT, EXTRACTOR, FEATURES

API = re.compile(r"^(?:Core|Services)\.v\d+/[A-Za-z][A-Za-z0-9_]*$")
LINE = re.compile(r"\s+Line:\d+.*$")
STATUS = re.compile(r"\(([A-Z]{1,3}\d{4,6})\s*\|\s*([A-Za-z_]+)\)")
SECRET = re.compile(
    r"password|passwd|secret|token|authorization|api[_-]?key|signature|^sign$|^otp(?:code)?$|verificationcode",
    re.I,
)
AUTOMATIC = {"Core.v1/AddUserData", "Core.v1/GetUserData"}
BUSINESS_SQL = {
    "DBPath.pishkhan24.application.ud_prc_inquiryInvoiceResult2",
    "DBPath.pishkhan24.application.ud_prc_invoiceRegister",
}
# Reviewed exact pairs only. Other supporting payloads remain explicitly unbound.
PROVIDERS = {
    "Services.v1/WaterBills": "ClientAyanCoInquiry.WaterBillInquiry",
    "Services.v1/GasBills": "ClientAyanCoInquiry.GasBillInquiry",
}
ANCILLARY = {
    "ClientAyanCoPaymentGateway.PaymentInquiry",
    "ClientAyanCoCarTax.CarTraverseAddToWatch",
}
TARGET = re.compile(
    r"(?:billid|participatecode|nationalcode|nationalid|platenumber|iban|phonenumber|mobilenumber|telephone|accountnumber)$",
    re.I,
)


class LimitExceeded(ValueError):
    pass


@dataclass(frozen=True)
class Limits:
    requests: int = 60000
    state_bytes: int = 262144
    total_state_bytes: int = 134217728
    variants: int = 4
    surfaces: int = 32
    pending_requests: int = 40000
    dirty_windows: int = 500000


def canonical(value):
    return json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    )


def digest(value):
    return hashlib.sha256(canonical(value).encode()).hexdigest()


def instant(value):
    if not isinstance(value, str):
        raise ValueError("timestamp_required")
    match = re.fullmatch(
        r"(\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d)(?:\.(\d{1,9}))?(Z|[+-]\d\d:\d\d)", value
    )
    if not match:
        raise ValueError("invalid_timestamp")
    date = datetime.fromisoformat(match[1] + match[3].replace("Z", "+00:00"))
    epoch = datetime(1970, 1, 1, tzinfo=timezone.utc)
    delta = date.astimezone(timezone.utc) - epoch
    return (delta.days * 86400 + delta.seconds) * 1_000_000_000 + int(
        (match[2] or "").ljust(9, "0")
    )


def iso(ns):
    seconds, fraction = divmod(ns, 1_000_000_000)
    return (
        datetime.fromtimestamp(seconds, timezone.utc).strftime("%Y-%m-%dT%H:%M:%S")
        + f".{fraction:09d}Z"
    )


def identity(value):
    if (
        not isinstance(value, str)
        or not value.strip()
        or value.strip().upper() in ("N/A", "NULL")
    ):
        return None
    if len(value) > 512 or any(ord(c) < 32 for c in value):
        return None
    # GUID representations compare canonically; other opaque identifiers retain case.
    compact = value.replace("-", "")
    return compact.lower() if re.fullmatch(r"[0-9a-fA-F]{32}", compact) else value


def behavior_id(stream, request):
    return digest([CONTRACT, stream, identity(request)])


def field(row, key):
    values = []
    source = row.get("_source", row if "fields" not in row else {})
    for mapping in (source, row.get("fields", {})):
        if not isinstance(mapping, dict) or key not in mapping:
            continue
        value = mapping[key]
        if isinstance(value, list):
            if len(value) != 1:
                return None, "conflicting"
            value = value[0]
        values.append(value)
    if not values:
        return None, "missing"
    if any(v != values[0] for v in values):
        return None, "conflicting"
    return values[0], "present"


def scrub(value, depth=0):
    if depth > 20:
        raise LimitExceeded("payload_depth_limit")
    if isinstance(value, dict):
        output = {}
        for k, v in value.items():
            if SECRET.search(str(k)):
                continue
            if re.search(r"base64|imagebytes|filebytes", str(k), re.I) and isinstance(
                v, str
            ):
                output[str(k)] = dict(
                    binary_content_omitted=True,
                    characters=len(v),
                    sha256=hashlib.sha256(v.encode()).hexdigest(),
                )
            else:
                output[str(k)] = scrub(v, depth + 1)
        return output
    if isinstance(value, list):
        return [scrub(v, depth + 1) for v in value]
    if isinstance(value, str) and value.lstrip().startswith(("{", "[")):
        try:
            decoded = json.loads(value)
        except (ValueError, RecursionError):
            return value
        return scrub(decoded, depth + 1)
    if isinstance(value, float) and not math.isfinite(value):
        raise ValueError("nonfinite_payload")
    return value


def sql_fields(message):
    """Recognized parameter boundaries at JSON depth zero; no SQL text retained."""
    if "(SQL Parameters:" not in message:
        return {}, set()
    text = message.split("(SQL Parameters:", 1)[1].removesuffix(")")
    marks = []
    depth = 0
    quoted = False
    escaped = False
    for i, c in enumerate(text):
        if quoted:
            if escaped:
                escaped = False
            elif c == "\\":
                escaped = True
            elif c == '"':
                quoted = False
        elif c == '"':
            quoted = True
        elif c in "[{":
            depth += 1
        elif c in "]}":
            depth = max(0, depth - 1)
        elif c == "@" and depth == 0 and (i == 0 or text[i - 1].isspace()):
            match = re.match(r"@([A-Za-z][A-Za-z0-9_]*)=", text[i:])
            if match:
                marks.append((i, i + match.end(), match[1].lower()))
    values = {}
    errors = set()
    for j, (begin, end, name) in enumerate(marks):
        if name not in ("queryparameters", "queryresult", "action", "serviceid"):
            continue
        raw = text[end : marks[j + 1][0] if j + 1 < len(marks) else len(text)].strip()
        try:
            if name in ("queryparameters", "queryresult"):
                value = scrub(json.loads(raw, object_pairs_hook=unique_object))
            else:
                value = raw
            if name in values and values[name] != value:
                errors.add(name)
            values[name] = value
        except (ValueError, RecursionError):
            errors.add(name)
    return values, errors


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate_json_key")
        result[key] = value
    return result


def sql_parameters(message):
    values, errors = sql_fields(message)
    return {
        k: v
        for k, v in values.items()
        if k in ("queryparameters", "queryresult") and k not in errors
    }


def resolve_service(state, api):
    if api != "Services.v1/InvoiceRegister":
        return api, "PUBLIC_OPERATION" if api else "CONFLICT"
    actions = {v["value"] for v in state.get("dispatch", []) if v["kind"] == "action"}
    requests = {
        v["value"] for v in state.get("dispatch", []) if v["kind"] == "service_request"
    }
    if len(actions) == 1 and len(requests) == 1:
        return next(iter(actions)), "SAME_REQUEST_REVIEWED_DISPATCH"
    return None, (
        "UNRESOLVED_DISPATCH"
        if len(actions) < 2 and len(requests) < 2
        else "CONFLICTING_DISPATCH"
    )


def empty(request):
    return dict(
        request_id=request,
        raw_request_ids=[],
        raw_session_ids=[],
        sessions=[],
        apis=[],
        roots=[],
        inputs=[],
        outputs=[],
        parse_errors=[],
        dispatch=[],
        issues=[],
        first_ns=None,
        last_ns=None,
    )


def union(before, after, limit, issues, label):
    unique = {canonical(x): x for x in before + after}
    if len(unique) > limit:
        raise LimitExceeded(label + "_limit")
    return [unique[k] for k in sorted(unique)]


def merge(a, b, limits=Limits()):
    if a["request_id"] != b["request_id"]:
        raise ValueError("request_identity_changed")
    c = empty(a["request_id"])
    c["issues"] = sorted(set(a["issues"] + b["issues"]))
    for key in ("parse_errors", "dispatch"):
        c[key] = union(
            a.get(key, []), b.get(key, []), limits.surfaces, c["issues"], key
        )
    for key in ("sessions", "apis", "roots", "raw_request_ids", "raw_session_ids"):
        c[key] = union(a[key], b[key], limits.variants, c["issues"], key)
    for key in ("inputs", "outputs"):
        c[key] = union(a[key], b[key], limits.surfaces, c["issues"], key)
    for key, fn in [("first_ns", min), ("last_ns", max)]:
        values = [v for v in (a[key], b[key]) if v is not None]
        c[key] = fn(values) if values else None
    if len(canonical(c).encode()) > limits.state_bytes:
        raise LimitExceeded("request_state_bytes_limit")
    return c


def facts(row):
    raw_request, request_state = field(row, "RequestID")
    request = identity(raw_request)
    if not request:
        return None
    result = empty(request)
    result["raw_request_ids"] = [raw_request]
    if request_state != "present":
        result["issues"].append("request_id_" + request_state)
    session, status = field(row, "Session")
    if status == "conflicting":
        result["issues"].append("session_field_conflict")
    elif identity(session):
        result["sessions"] = [identity(session)]
        result["raw_session_ids"] = [session]
    raw_time, status = field(row, "@timestamp")
    try:
        if status != "present":
            raise ValueError("timestamp_" + status)
        at = instant(raw_time)
        result["first_ns"] = result["last_ns"] = at
    except ValueError:
        at = None
        result["issues"].append("timestamp_unavailable")
    path, path_status = field(row, "CallPath")
    message, message_status = field(row, "message")
    path = LINE.sub("", path) if isinstance(path, str) else ""
    message = message if isinstance(message, str) else ""
    if path_status == "conflicting":
        result["issues"].append("operation_field_conflict")
    if message_status == "conflicting":
        result["issues"].append("message_field_conflict")
    if API.fullmatch(path):
        result["apis"] = [path]
        # Only the public HTTP completion contributes final outcome/duration.
        if re.match(r"^(?:GET|POST|PUT|DELETE|PATCH|HEAD)\s+https?://", message):
            code = STATUS.search(message)
            duration, _ = field(row, "ExecutionTime")
            try:
                duration = float(duration)
                if not math.isfinite(duration) or duration < 0:
                    duration = None
            except (TypeError, ValueError):
                duration = None
            result["roots"] = [
                dict(
                    api=path,
                    at_ns=at,
                    code=code[1] if code else None,
                    symbol=code[2] if code else None,
                    reported_duration=duration,
                )
            ]
    for label, section in [("inputs", "Input:"), ("outputs", "Output:")]:
        if section not in message:
            continue
        if API.fullmatch(path):
            basis = "public_api"
        elif path.startswith("ClientAyanCo") and path not in ANCILLARY:
            basis = "supporting"
        else:
            continue
        try:
            value, _ = json.JSONDecoder(object_pairs_hook=unique_object).raw_decode(
                message.split(section, 1)[1].lstrip()
            )
            value = scrub(value)
        except LimitExceeded:
            raise
        except (ValueError, RecursionError):
            result["issues"].append(label + "_parse_error")
            result["parse_errors"].append(
                dict(direction=label, basis=basis, path=path, observed_at_ns=at)
            )
            continue
        result[label].append(
            dict(basis=basis, path=path, value=value, observed_at_ns=at)
        )
    if path in BUSINESS_SQL:
        params, errors = sql_fields(message)
        for key, target in [("queryparameters", "inputs"), ("queryresult", "outputs")]:
            if key in errors:
                result["issues"].append(target + "_parse_error")
                result["parse_errors"].append(
                    dict(
                        direction=target,
                        basis="business_parameters",
                        path=path,
                        observed_at_ns=at,
                    )
                )
        for key, target in [("queryparameters", "inputs"), ("queryresult", "outputs")]:
            if key in params and key not in errors:
                result[target].append(
                    dict(
                        basis="business_parameters",
                        path=path,
                        value=params[key],
                        observed_at_ns=at,
                    )
                )
    if path in (
        "DBPath.pishkhan24.application.ud_prc_userSessionHasAccess",
        "DBPath.pishkhan24.application.ud_prc_invoiceRequest",
    ):
        params, errors = sql_fields(message)
        if (
            path.endswith(".ud_prc_userSessionHasAccess")
            and "action" in params
            and "action" not in errors
        ):
            from .services import routes

            action = "Services." + params["action"]
            if action in routes():
                result["dispatch"].append(dict(kind="action", value=action))
        if (
            path.endswith(".ud_prc_invoiceRequest")
            and "serviceid" in params
            and "serviceid" not in errors
        ):
            value = params["serviceid"]
            if re.fullmatch(r"[0-9]{1,12}", value):
                result["dispatch"].append(dict(kind="service_request", value=value))
    return result


class Extractor:
    def __init__(self, limits=Limits()):
        self.limits = limits
        self.states = {}
        self.records = 0
        self.missing_request_ids = 0
        self.state_bytes = 0
        self.sizes = {}

    def add(self, row):
        self.records += 1
        item = facts(row)
        if item is None:
            self.missing_request_ids += 1
            return
        key = item["request_id"]
        if key not in self.states and len(self.states) >= self.limits.requests:
            raise LimitExceeded("window_request_limit")
        value = merge(self.states.get(key, empty(key)), item, self.limits)
        size = len(canonical(value).encode())
        self.state_bytes += size - self.sizes.get(key, 0)
        if self.state_bytes > self.limits.total_state_bytes:
            raise LimitExceeded("window_state_bytes_limit")
        self.states[key] = value
        self.sizes[key] = size

    def finish(self):
        size = sum(len(canonical(s).encode()) for s in self.states.values())
        if size > self.limits.total_state_bytes:
            raise LimitExceeded("window_state_bytes_limit")
        return self.states


def selected(state, key, api):
    values = state[key]
    errors = [x for x in state.get("parse_errors", []) if x["direction"] == key]
    for basis in ("business_parameters", "public_api"):
        found = [
            x
            for x in values
            if x["basis"] == basis and (basis != "public_api" or x["path"] == api)
        ]
        bad = [
            x
            for x in errors
            if x["basis"] == basis and (basis != "public_api" or x["path"] == api)
        ]
        if found or bad:
            return found, basis
    if api in PROVIDERS:
        found = [x for x in values if x["path"] == PROVIDERS[api]]
        bad = [x for x in errors if x["path"] == PROVIDERS[api]]
        if found or bad:
            return found, "reviewed_same_request_provider"
    candidates = [x for x in values if x["basis"] == "supporting"]
    if candidates:
        return candidates, "unconfirmed_same_request_provider"
    return [], "unavailable"


def features(value):
    from .feature_contract import extract_features

    return extract_features(value)


def materialize(stream, state):
    if not state["apis"]:
        return None
    issues = set(state["issues"])
    api = state["apis"][0] if len(state["apis"]) == 1 else None
    if not api:
        issues.add("operation_conflict")
    session = state["sessions"][0] if len(state["sessions"]) == 1 else None
    if len(state["sessions"]) > 1:
        issues.add("session_conflict")
    if session is None:
        issues.add("session_unavailable")
    roots = state["roots"]
    times = [x["at_ns"] for x in roots if x["at_ns"] is not None]
    at = min(times) if times else state["first_ns"]
    if not times:
        issues.add("operation_completion_unavailable")
    if len(roots) > 1:
        issues.add("multiple_completion_variants")
    codes = sorted({r["code"] for r in roots if r["code"]})
    code = codes[0] if len(codes) == 1 else None
    if len(codes) > 1:
        issues.add("result_conflict")
    chosen_input, input_basis = selected(state, "inputs", api)
    chosen_output, output_basis = selected(state, "outputs", api)
    iv = {canonical(x["value"]): x["value"] for x in chosen_input}
    ov = {canonical(x["value"]): x["value"] for x in chosen_output}
    if len(iv) > 1:
        issues.add("input_conflict")
    if len(ov) > 1:
        issues.add("output_conflict")
    if input_basis == "unconfirmed_same_request_provider":
        issues.add("input_binding_unconfirmed")
    if output_basis == "unconfirmed_same_request_provider":
        issues.add("output_binding_unconfirmed")
    if not iv:
        issues.add("input_unavailable")
    if not ov:
        issues.add("output_unavailable")
    usable = (
        api is not None
        and session is not None
        and at is not None
        and len(roots) == 1
        and roots[0]["at_ns"] is not None
        and not any(
            x in issues
            for x in (
                "session_field_conflict",
                "operation_field_conflict",
                "multiple_completion_variants",
            )
        )
    )
    operation_usable = (
        api is not None
        and len(roots) == 1
        and roots[0]["at_ns"] is not None
        and "operation_field_conflict" not in issues
    )
    content_identity_valid = (
        len(state["sessions"]) <= 1 and "session_field_conflict" not in issues
    )
    outcome = (
        "reported_success"
        if code == "G00000"
        and len(roots) == 1
        and roots[0]["symbol"].lower() == "successful"
        else "unknown"
    )
    from .feature_contract import complete

    def selected_error(direction, basis, chosen):
        paths = {v["path"] for v in chosen}
        if basis == "public_api":
            paths.add(api)
        if basis == "reviewed_same_request_provider":
            paths.add(PROVIDERS.get(api))
        return any(
            e["direction"] == direction
            and (
                e["path"] in paths
                or basis == "business_parameters"
                and e["basis"] == basis
            )
            for e in state.get("parse_errors", [])
        )

    input_feature = features(next(iter(iv.values()))) if len(iv) == 1 else None
    output_feature = features(next(iter(ov.values()))) if len(ov) == 1 else None
    input_valid = (
        operation_usable
        and content_identity_valid
        and all(x.get("observed_at_ns") is not None for x in chosen_input)
        and "prior_fragments_expired" not in issues
        and len(iv) == 1
        and input_basis != "unconfirmed_same_request_provider"
        and not selected_error("inputs", input_basis, chosen_input)
    )
    output_valid = (
        operation_usable
        and content_identity_valid
        and all(x.get("observed_at_ns") is not None for x in chosen_output)
        and "prior_fragments_expired" not in issues
        and len(ov) == 1
        and output_basis != "unconfirmed_same_request_provider"
        and not selected_error("outputs", output_basis, chosen_output)
    )
    service, binding = resolve_service(state, api)
    if service is None:
        issues.add(binding.lower())
    body = dict(
        contract=CONTRACT,
        extractor=EXTRACTOR,
        behavior_id=behavior_id(stream, state["request_id"]),
        request_id=state["request_id"],
        session_id=session,
        api=api,
        service_key=service,
        service_binding=binding,
        observed_at_ns=at,
        reported_duration=roots[0]["reported_duration"] if len(roots) == 1 else None,
        duration_unit="UNVERIFIED",
        result_code=code,
        result_kind=outcome,
        kind="automatic_support" if api in AUTOMATIC else "observed_api_operation",
        manual_start="UNKNOWN",
        quality=sorted(issues),
        features=dict(
            version=FEATURES,
            rate_eligible=usable and api not in AUTOMATIC,
            service_rate_eligible=operation_usable and api not in AUTOMATIC,
            session_eligible=usable,
            input_eligible=input_valid and input_feature["complete"],
            input_feature_eligibility={
                k: bool(input_valid and complete(input_feature, k))
                for k in ("targets", "numeric", "shape")
            },
            output_eligible=output_valid and output_feature["complete"],
            output_feature_eligibility={
                k: bool(output_valid and complete(output_feature, k))
                for k in ("targets", "numeric", "shape")
            },
            input_asof_ns=max(
                (
                    x["observed_at_ns"]
                    for x in chosen_input
                    if x.get("observed_at_ns") is not None
                ),
                default=None,
            ),
            output_asof_ns=max(
                (
                    x["observed_at_ns"]
                    for x in chosen_output
                    if x.get("observed_at_ns") is not None
                ),
                default=None,
            ),
            input_basis=input_basis,
            output_basis=output_basis,
            service_key=service,
            service_binding=binding,
            financial_chain="OUT_OF_SCOPE",
            duration_analysis="OUT_OF_SCOPE_UNVERIFIED_UNIT",
            result_eligible=operation_usable
            and code is not None
            and api not in AUTOMATIC,
            input=input_feature,
            output=output_feature,
        ),
    )
    return body
