"""Bounded extracted facts, never source log records or a request tree."""

from __future__ import annotations
from dataclasses import dataclass
from datetime import datetime, timezone
import hashlib
import json
import math
import re
from . import CONTRACT, EXTRACTOR, FEATURES
from .json_value import unique_object
from .payload import packed, normalize as normalize_payload, identity as payload_identity, feature as payload_feature
from .services import operation_role, operation_catalog, meaningful, operation_label, independent_operations, internal_proxies
from . import context as request_context
from . import inquiry, postal

CONTROL = re.compile(r"[\x00-\x1f]")
GUID = re.compile(r"[0-9a-fA-F]{32}")
API = re.compile(r"^(?:Core|Services)\.v\d+/[A-Za-z][A-Za-z0-9_]*$")
LINE = re.compile(r"\s+Line:\d+.*$")
STATUS = re.compile(r"\(([A-Z]{1,3}\d{4,6})\s*\|\s*([A-Za-z_]+)\)")
SECRET = re.compile(
    r"password|passwd|secret|token|authorization|api[_-]?key|signature|^sign$|^otp(?:code)?$|verificationcode",
    re.I,
)
AUTOMATIC = {
    "Core.v1/AddUserData", "Core.v1/GetUserData",
    "Services.v1/AddUserData", "Services.v1/GetUserData",
}
BUSINESS_SQL = {
    "DBPath.pishkhan24.application.ud_prc_inquiryInvoiceResult2",
    "DBPath.pishkhan24.application.ud_prc_invoiceRegister",
}
# Reviewed exact pairs only. Other supporting payloads remain explicitly unbound.
PROVIDERS = {
    postal.SERVICE: "ClientAyanCoInquiry.PostalCodeToAddress",
    "Services.v1/WaterBills": "ClientAyanCoInquiry.WaterBillInquiry",
    "Services.v1/GasBills": "ClientAyanCoInquiry.GasBillInquiry",
    # PostPackagesStatusHandler.CallService invokes exactly this provider.
    "Services.v1/PostPackagesStatus": "ClientAyanCoInquiry.PostTrackingInquiry",
    # Reviewed CallService methods; OTP/login are prerequisites, not results.
    "Services.v1/LivelihoodInformation": "ClientAyanCoInquiry.SfaraCouponInquiry",
    "Services.v1/SfaraCoupon": "ClientAyanCoInquiry.SfaraCouponInquiry",
    "Services.v1/LandLinePhoneBills": "ClientAyanCoInquiry.FixedLineBillInquiry",
    # Reviewed v3 export handler returns the uploaded URL after fetching the PDF.
    # This is the observed upload response, not the public API response envelope.
    "Services.v3/LandLinePhoneBillsExport": "ClientAyanCoS3.Upload",
}
ANCILLARY = {
    "ClientAyanCoPaymentGateway.PaymentInquiry",
    "ClientAyanCoCarTax.CarTraverseAddToWatch",
}
TARGET = re.compile(
    r"(?:billid|participatecode|nationalcode|nationalid|platenumber|iban|phonenumber|mobilenumber|linenumber|telephone|accountnumber)$",
    re.I,
)


class LimitExceeded(ValueError):
    pass


@dataclass(frozen=True)
class Limits:
    requests: int = 60000
    # Values >16KiB become bounded feature snapshots. 64 surfaces can each
    # retain two <=128KiB components; the whole window remains <=128MiB.
    state_bytes: int = 20971520
    total_state_bytes: int = 134217728
    variants: int = 4
    surfaces: int = 32
    # Compatibility name: high-water warning for durable DB rows, NOT an
    # admission limit. Blocking publication here prevents event-time expiry.
    # RAM is bounded by requests/state_bytes/total_state_bytes for one window.
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
    if len(value) > 512 or CONTROL.search(value):
        return None
    # GUID representations compare canonically; other opaque identifiers retain case.
    compact = value.replace("-", "")
    return compact.lower() if GUID.fullmatch(compact) else value


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
            decoded = json.loads(value, object_pairs_hook=unique_object)
        except (ValueError, RecursionError):
            return value
        return scrub(decoded, depth + 1)
    if isinstance(value, float) and not math.isfinite(value):
        raise ValueError("nonfinite_payload")
    return value


def sql_fields(message, context=None, context_source=None, observed_at_ns=None):
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
            if context is not None and name in request_context.SQL_FIELDS:
                raw = text[end : marks[j + 1][0] if j + 1 < len(marks) else len(text)].strip()
                request_context.observe(context, request_context.SQL_FIELDS[name], raw, context_source + '.@' + name, observed_at_ns)
            continue
        raw = text[end : marks[j + 1][0] if j + 1 < len(marks) else len(text)].strip()
        try:
            if name in ("queryparameters", "queryresult"):
                # SQL nullable payloads are logged as an empty parameter value.
                # Absence is not malformed JSON and must not shadow an exact
                # reviewed same-request provider. Nonempty malformed JSON blocks.
                if not raw:
                    continue
                value = scrub(json.loads(raw, object_pairs_hook=unique_object))
            else:
                value = raw
            if name in values and values[name] != value:
                errors.add(name)
            values[name] = value
        except (ValueError, RecursionError):
            errors.add(name)
    return values, errors


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
    # Common singleton/empty sets need neither JSON keys nor sorting.
    if len(before) <= min(limit, 1) and len(after) <= min(limit, 1):
        if not after or before == after:
            return before
        if not before:
            return after
    unique = {canonical(x): x for x in before + after}
    if len(unique) > limit:
        raise LimitExceeded(label + "_limit")
    return [unique[k] for k in sorted(unique)]


def timed_union(before, after, limit, label):
    # Repeated equal content is one version. Keep its earliest known evidence
    # time, so a later duplicate neither exhausts variants nor erases past
    # eligibility. The overall state still records first/last observation.
    unique = {}
    for value in before + after:
        data = {k: v for k, v in value.items() if k != "observed_at_ns"}
        # A later release may derive a subject from identical oversized input
        # bytes. Preserve the richer projection and the earliest evidence time.
        candidates = data.pop('inquiry_candidates', None)
        key = canonical(data)
        previous = unique.get(key)
        if candidates or (previous and previous.get('inquiry_candidates')):
            old = (previous or {}).get('inquiry_candidates')
            if old and candidates and old != candidates:
                raise ValueError('inconsistent_inquiry_snapshot')
            data['inquiry_candidates'] = candidates or old
        times = [
            v
            for v in (
                value.get("observed_at_ns"),
                previous.get("observed_at_ns") if previous else None,
            )
            if v is not None
        ]
        unique[key] = dict(data, observed_at_ns=min(times) if times else None)
    if len(unique) > limit:
        raise LimitExceeded(label + "_limit")
    return [unique[k] for k in sorted(unique)]


def merge(a, b, limits=Limits(), *, _check_size=True, _normalized=False):
    if a["request_id"] != b["request_id"]:
        raise ValueError("request_identity_changed")
    c = empty(a["request_id"])
    c["issues"] = sorted(set(a["issues"] + b["issues"]))
    if 'postal_cache_date' in a or 'postal_cache_date' in b:
        left, right = a.get('postal_cache_date'), b.get('postal_cache_date')
        c['postal_cache_date'] = 'CONFLICT' if left and right and left != right else left or right
    if 'postal_contacts' in a or 'postal_contacts' in b:
        c['postal_contacts'] = postal.merge_contacts(a.get('postal_contacts', {}), b.get('postal_contacts', {}))
    c["dispatch"] = union(
        a.get("dispatch", []),
        b.get("dispatch", []),
        limits.surfaces,
        c["issues"],
        "dispatch",
    )
    c["parse_errors"] = timed_union(
        a.get("parse_errors", []),
        b.get("parse_errors", []),
        limits.surfaces,
        "parse_errors",
    )
    for key in ("sessions", "apis", "roots", "raw_request_ids", "raw_session_ids"):
        c[key] = union(a[key], b[key], limits.variants, c["issues"], key)
    for key in ("inputs", "outputs"):
        if _normalized and not b[key]:
            c[key] = a[key]
            continue
        c[key] = timed_union([normalize_payload(x) for x in a[key]], [normalize_payload(x) for x in b[key]], limits.surfaces, key)
    for key, fn in [("first_ns", min), ("last_ns", max)]:
        values = [v for v in (a[key], b[key]) if v is not None]
        c[key] = fn(values) if values else None
    context = request_context.combine(a.get('request_context', {}), b.get('request_context', {}))
    if context:
        c['request_context'] = context
    if _check_size and len(canonical(c).encode()) > limits.state_bytes:
        error = LimitExceeded("request_state_bytes_limit")
        error.details = dict(limit_bytes=limits.state_bytes, measured_bytes=len(canonical(c).encode()), apis=c["apis"], inputs=len(c["inputs"]), outputs=len(c["outputs"]))
        raise error
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
    else:
        session_id = identity(session)
        if session_id:
            result["sessions"] = [session_id]
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
    context = request_context.from_log(row, at)
    path, path_status = field(row, "CallPath")
    message, message_status = field(row, "message")
    path = LINE.sub("", path) if isinstance(path, str) else ""
    message = message if isinstance(message, str) else ""
    if path_status == "conflicting":
        result["issues"].append("operation_field_conflict")
    if message_status == "conflicting":
        result["issues"].append("message_field_conflict")
    operation_path = bool(API.fullmatch(path)) or path in independent_operations()
    if operation_path:
        result["apis"] = [path]
        # Only the public HTTP completion contributes final outcome/duration.
        if re.match(r"^(?:GET|POST|PUT|DELETE|PATCH|HEAD)\s+https?://", message):
            if not context:
                context = request_context.empty()
            request_context.observe(context, 'http_method', message.split(' ', 1)[0], 'public_http_completion', at)
            code = STATUS.search(message)
            duration, duration_status = field(row, "ExecutionTime")
            try:
                if duration_status != 'present' or isinstance(duration, bool):
                    raise ValueError('invalid_duration_field')
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
        if operation_path and operation_role(path) in ("support", "system"):
            # Auxiliary API payloads are not inputs to behavioral methods.
            continue
        if operation_path:
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
        except LimitExceeded as exc:
            result["issues"].append(label + "_content_limit")
            result["parse_errors"].append(dict(direction=label, basis=basis, path=path, observed_at_ns=at, reason=str(exc)))
            continue
        except (ValueError, RecursionError):
            result["issues"].append(label + "_parse_error")
            result["parse_errors"].append(
                dict(direction=label, basis=basis, path=path, observed_at_ns=at)
            )
            continue
        context = request_context.combine(context, request_context.from_payload(value, 'payload.' + path, at))
        result[label].append(
            dict(basis=basis, path=path, **packed(value, inquiry_input=label == "inputs"), observed_at_ns=at)
        )
    if path == postal.PROVIDER and at is not None:
        kind = postal.contact_kind(message, result['outputs'])
        if kind:
            result['postal_contacts'] = {kind: [at, at]}
    if path == postal.CACHE:
        projection = postal.cache_projection(message)
        if projection is not None:
            if 'ReportDateTime' in projection:
                result['postal_cache_date'] = projection.pop('ReportDateTime')
            result['outputs'].append(dict(basis=postal.BASIS, path=path, **packed(projection), observed_at_ns=at))
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
                        **packed(params[key], inquiry_input=target == "inputs"),
                        observed_at_ns=at,
                    )
                )
    if path in request_context.SQL_PATHS or path == "DBPath.pishkhan24.application.ud_prc_invoiceRequest":
        if path in request_context.SQL_PATHS and not context:
            context = request_context.empty()
        params, errors = sql_fields(message, context if path in request_context.SQL_PATHS else None, request_context.SQL_SOURCES.get(path, path), at)
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
    if context and (context['values'] or context['limited']):
        result['request_context'] = context
    return result


class Extractor:
    def __init__(self, limits=Limits()):
        self.limits = limits
        self.states = {}
        self.records = 0
        self.missing_request_ids = 0
        self.state_bytes = 0
        self.sizes = {}
        self.contexts = {}
        self.context_sizes = {}
        self.context_bytes = 0

    def add(self, row):
        self.records += 1
        item = facts(row)
        if item is None:
            self.missing_request_ids += 1
            return
        key = item["request_id"]
        # Keep metadata outside repeated state serialization in the hot loop.
        metadata = item.pop('request_context', {})
        prior_metadata = self.contexts.get(key, {})
        merged_metadata = request_context.combine(prior_metadata, metadata)
        if merged_metadata and merged_metadata != prior_metadata:
            metadata_size = len(canonical(merged_metadata).encode())
            self.context_bytes += metadata_size - self.context_sizes.get(key, 0)
            self.contexts[key] = merged_metadata
            self.context_sizes[key] = metadata_size
        if key not in self.states and len(self.states) >= self.limits.requests:
            raise LimitExceeded("window_request_limit")
        value = merge(self.states.get(key, empty(key)), item, self.limits, _check_size=False, _normalized=True)
        size = len(canonical(value).encode())
        if size + self.context_sizes.get(key, 0) > self.limits.state_bytes:
            raise LimitExceeded("request_state_bytes_limit")
        self.state_bytes += size - self.sizes.get(key, 0)
        if self.state_bytes + self.context_bytes > self.limits.total_state_bytes:
            raise LimitExceeded("window_state_bytes_limit")
        self.states[key] = value
        self.sizes[key] = size

    def finish(self):
        size = sum(len(canonical(s).encode()) for s in self.states.values())
        if size + self.context_bytes > self.limits.total_state_bytes:
            raise LimitExceeded("window_state_bytes_limit")
        return {key: dict(state, request_context=self.contexts[key]) if key in self.contexts else state
                for key, state in self.states.items()}


def reviewed_providers(key, service):
    if key == "inputs" and service == inquiry.CELL_SERVICE:
        return inquiry.CELL_INPUT_PROVIDERS
    path = PROVIDERS.get(service)
    return (path,) if path else ()


def selected(state, key, api, service=None):
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
    providers = reviewed_providers(key, service or api)
    if providers:
        found = [x for x in values if x["path"] in providers]
        bad = [x for x in errors if x["path"] in providers]
        if found or bad:
            return found, "reviewed_same_request_provider"
    candidates = [x for x in values if x["basis"] == "supporting"]
    if candidates:
        return candidates, "unconfirmed_same_request_provider"
    return [], "unavailable"


def features(value):
    from .feature_contract import extract_features

    return extract_features(value)


def materialize(stream, state, *, context=None):
    if not state["apis"]:
        return None
    issues = set(state["issues"])
    from .services import foreground_apis
    apis = foreground_apis(state['apis'], state['roots'])
    roots = state["roots"]
    if len(apis) > 1 and internal_proxies().intersection(apis):
        # A system call sharing RequestID with an outer API is supporting
        # evidence. Preserve competing outer API roots as a real conflict.
        outer = [api for api in apis if api not in internal_proxies()]
        if outer:
            apis = outer
            roots = [root for root in roots if root["api"] in outer]
    api = apis[0] if len(apis) == 1 else None
    if not api:
        issues.add("operation_conflict")
    session = state["sessions"][0] if len(state["sessions"]) == 1 else None
    if len(state["sessions"]) > 1:
        issues.add("session_conflict")
    if session is None:
        issues.add("session_unavailable")
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
    service, binding = resolve_service(state, api)
    role = operation_role(api, service, binding)
    in_scope = meaningful(api, service, binding)
    chosen_input, input_basis = selected(state, "inputs", api, service)
    chosen_output, output_basis = selected(state, "outputs", api, service)
    iv = {payload_identity(x): x for x in chosen_input}
    ov = {payload_identity(x): x for x in chosen_output}
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
            paths.update(reviewed_providers(direction, service or api))
        return any(
            e["direction"] == direction
            and (
                e["path"] in paths
                or basis == "business_parameters"
                and e["basis"] == basis
            )
            for e in state.get("parse_errors", [])
        )

    input_feature = payload_feature(next(iter(iv.values()))) if len(iv) == 1 else None
    output_feature = payload_feature(next(iter(ov.values()))) if len(ov) == 1 else None
    input_valid = (
        in_scope
        and operation_usable
        and content_identity_valid
        and all(x.get("observed_at_ns") is not None for x in chosen_input)
        and "prior_fragments_expired" not in issues
        and len(iv) == 1
        and input_basis != "unconfirmed_same_request_provider"
        and not selected_error("inputs", input_basis, chosen_input)
    )
    output_valid = (
        in_scope
        and operation_usable
        and content_identity_valid
        and all(x.get("observed_at_ns") is not None for x in chosen_output)
        and "prior_fragments_expired" not in issues
        and len(ov) == 1
        and output_basis != "unconfirmed_same_request_provider"
        and not selected_error("outputs", output_basis, chosen_output)
    )
    if service is None:
        issues.add(binding.lower())
    if role in ("support", "system"):
        issues.discard("input_unavailable")
        issues.discard("output_unavailable")
        issues.add("auxiliary_content_out_of_scope")
    for direction, values in (("input", chosen_input), ("output", chosen_output)):
        if any(x.get("representation") == "FEATURES_ONLY_V1" for x in values):
            issues.add(direction + "_value_replaced_by_features")
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
        duration_unit="MILLISECONDS_OWNER_CONFIRMED_20261122",
        result_code=code,
        result_kind=outcome,
        kind=("automatic_support" if api in AUTOMATIC else "support_operation" if role == "support" else "system_operation" if role == "system" else "unclassified_operation" if role == "unknown" else "observed_api_operation"),
        operation_role=role,
        label_fa=operation_label(api, service),
        manual_start="UNKNOWN",
        quality=sorted(issues),
        features=dict(
            version=FEATURES,
            behavior_policy_version=operation_catalog()["policy_version"],
            operation_role=role,
            content_scope="IN_SCOPE" if in_scope else "OUT_OF_SCOPE_AUXILIARY" if role in ("support", "system") else "UNCLASSIFIED",
            rate_eligible=usable and in_scope,
            service_rate_eligible=operation_usable and in_scope,
            session_eligible=usable and in_scope,
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
            duration_analysis="PUBLIC_HTTP_MILLISECONDS_OWNER_CONFIRMED_20261122",
            result_eligible=operation_usable
            and code is not None
            and in_scope,
            input=input_feature,
            output=output_feature,
        ),
    )
    if api in internal_proxies():
        body['features']['role_authority'] = operation_catalog()['routes'][api]['authority']
    if ('postal_contacts' in state and api == postal.SERVICE and operation_usable
            and content_identity_valid and 'prior_fragments_expired' not in issues):
        body['features']['postal_contacts'] = state['postal_contacts']
    if api == postal.SERVICE and operation_usable and content_identity_valid and code == 'G00000' and 'prior_fragments_expired' not in issues:
        cache = [entry for entry in state['outputs'] if entry['basis'] == postal.BASIS]
        if len(cache) == 1 and cache[0]['value']['PostalCode'] and cache[0]['observed_at_ns'] is not None:
            body['features']['postal_cache_returned_at_ns'] = cache[0]['observed_at_ns']
        elif cache:
            body['quality'] = sorted(issues | {'postal_cache_result_unconfirmed'})
    if service in inquiry.ROUTES and body['features']['input_feature_eligibility']['targets']:
        matched = next(iter(iv.values()))
        body['features'][inquiry.POLICY] = inquiry.subjects(service, api, input_basis, matched)
    if (api == 'Services.v1/InvoiceRegister' and binding == 'UNRESOLVED_DISPATCH'
            and code == 'GR0004' and usable):
        actions = {v['value'] for v in state.get('dispatch', []) if v['kind']=='action'}
        requests = {v['value'] for v in state.get('dispatch', []) if v['kind']=='service_request'}
        # Requested destination is evidence of intent, never completed execution.
        if len(actions)==1 and not requests and operation_role(next(iter(actions))) in ('business','user_management'):
            action=next(iter(actions))
            body['features']['rejected_attempt'] = dict(service=action,eligible=True,
                stage='RATE_LIMITED_BEFORE_CONFIRMED_DISPATCH',result_code=code)
    # This exact code/symbol pair identifies a pre-dispatch access refusal.
    # G00010 alone is generic and must never imply this classification.
    if (api == 'Services.v1/InvoiceRegister' and binding == 'UNRESOLVED_DISPATCH'
            and usable and code == 'G00010'
            and roots[0]['symbol'] == 'UserAccessObjectsDoesNotContainAccessObject'):
        actions = {v['value'] for v in state.get('dispatch', []) if v['kind'] == 'action'}
        requests = {v['value'] for v in state.get('dispatch', []) if v['kind'] == 'service_request'}
        if len(actions) == 1 and not requests and operation_role(next(iter(actions))) in ('business', 'user_management'):
            body['features']['access_denied_attempt'] = dict(
                service=next(iter(actions)), verified=True, result_code=code,
                stage='ACCESS_DENIED_BEFORE_CONFIRMED_DISPATCH',
                dedicated_ad='verified-access-attempt-1')
    from . import security
    attempt = security.project(state, context)
    if attempt:
        body['features'][security.FIELD] = attempt
        # A terminal refusal is an attempt, never a completed user action.
        for name in ('rate_eligible', 'service_rate_eligible', 'session_eligible', 'result_eligible',
                     'input_eligible', 'output_eligible'):
            body['features'][name] = False
        for direction in ('input', 'output'):
            body['features'][direction + '_feature_eligibility'] = dict.fromkeys(('targets', 'numeric', 'shape'), False)
    return body
