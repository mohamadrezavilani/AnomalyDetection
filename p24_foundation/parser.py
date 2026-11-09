"""Versioned source descriptors. Raw payloads never enter public descriptors.

Role/phase mappings below are finite reviewed extraction candidates, not a
complete authoritative taxonomy. Unknown routes and codes remain unknown.
"""
from __future__ import annotations

import json
import re
from decimal import Decimal, InvalidOperation
from pathlib import Path

from .errors import FoundationError
from .outcomes import ScopedOutcomeResolver, REVIEWED_RULES
from .privacy import canonical
from .time import parse_time, compatible_times

PARSER_VERSION = "p24-extraction.2r.1"
PRIVACY_VERSION = "p24-minimum-privacy.2a.1"
LINE_SUFFIX = re.compile(r"\s+Line:\d+.*$")  # Legacy parse_utils pure normalization retained.
CLIENT_PATH = re.compile(r"^(Core|Services)\.v\d+/[A-Za-z][A-Za-z0-9_]*$")
SAFE_PATH = re.compile(r"^(?:DBPath\.[A-Za-z0-9_.]+|(?:Core|Services)\.v\d+/[A-Za-z][A-Za-z0-9_]*|(?:ClientAyanCoInquiry|ClientAyanCoMessage|EwanoApi)\.[A-Za-z][A-Za-z0-9_.]*)$")
HTTP = re.compile(r"^(GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS|TRACE|CONNECT)\s+https?://\S+\s+HTTP/\S+\s+\(([^|()\s]+)\s*\|\s*([^()]*)\)")
LOG_STATUS = re.compile(r"\(([A-Z]{1,3}\d{4,6})\s*\|\s*([A-Za-z][A-Za-z0-9_]*)\)")
SQL_RESULT = re.compile(r"\((Code|Result):\s*([^)]*)\)")
KNOWN_FIELDS = ("RequestID", "Session", "IP", "CallPath", "message", "ExecutionTime", "Counter", "ProcessID", "ThreadID", "level")
CALLER_SQL = {
    "ud_prc_userSessionHasAccess", "ud_prc_configBadgeServices", "ud_prc_userSessionVerify",
    "ud_prc_oneTimePasswordGenerate", "ud_prc_oneTimePasswordValidate", "ud_prc_oneTimePasswordConsume",
    "ud_prc_invoiceBelongs", "ud_prc_mobileVerificationReview", "ud_prc_inquiryInvoiceResult2",
    "ud_prc_persistentCacheReadServiceData2", "ud_prc_basketRequest",
}
SECRET_NAME = re.compile(r"password|otp|secret|token|authorization|apikey|accesskey|rsakey|sign(?:ature)?", re.I)

def scalar(value):
    if isinstance(value, list):
        return value[0] if len(value) == 1 and not isinstance(value[0], (dict, list)) else None
    return value if value is None or isinstance(value, (str, int, float, Decimal, bool)) else None

def normalized_scalar(key, value):
    if key in {"ExecutionTime", "Counter", "ProcessID", "ThreadID"} and value is not None:
        try:
            number = Decimal(str(value))
            if not number.is_finite():
                return None
            return format(number.normalize(), "f")
        except InvalidOperation:
            return None
    return None if value is None else str(value)

def representations(record, key):
    source = record.get("_source")
    if not isinstance(source, dict):
        source = record if "fields" not in record else {}
    fields = record.get("fields") if isinstance(record.get("fields"), dict) else {}
    result = []
    for kind, values in (("source", source), ("fields", fields)):
        if key in values:
            item = values[key]
            value = scalar(item)
            malformed = isinstance(item, (list, dict)) and value is None
            result.append((kind, value, malformed))
    return result

def field(record, key):
    values = representations(record, key)
    if not values:
        return None, "missing"
    if any(malformed for _, _, malformed in values):
        return None, "conflicting"
    normalized = {normalized_scalar(key, value) for _, value, _ in values}
    if len(normalized) > 1:
        return None, "conflicting"
    value = values[0][1]
    if value is None:
        return None, "null"
    if isinstance(value, str) and not value.strip():
        return value, "logged_empty"
    if isinstance(value, str) and value.strip().upper() == "N/A":
        return value, "sentinel_na"
    return value, "present"

def opaque(value):
    return value if isinstance(value, str) and 0 < len(value) <= 4096 and value.strip() and value.strip().upper() != "N/A" and not any(ord(ch) < 32 for ch in value) else None

def sql_parameters(message):
    """Split @parameters only outside quoted/JSON values; preserve empty values."""
    marker = "(SQL Parameters:"
    if marker not in message:
        return {}, "unlogged"
    text = message.split(marker, 1)[1]
    if text.endswith(")"):
        text = text[:-1]
    marks, quote, escaped, depth, i = [], False, False, 0, 0
    while i < len(text):
        char = text[i]
        if quote:
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == '"':
                quote = False
        elif char == '"':
            quote = True
        elif char in "[{":
            depth += 1
        elif char in "]}":
            depth = max(depth - 1, 0)
        elif char == "@" and depth == 0 and (i == 0 or text[i - 1].isspace()):
            match = re.match(r"@([A-Za-z][A-Za-z0-9_]{0,63})=", text[i:])
            if match:
                marks.append((i, i + match.end(), match.group(1)))
                i += match.end() - 1
        i += 1
    values = {}
    duplicate = False
    for index, (_, start, name) in enumerate(marks):
        end = marks[index + 1][0] if index + 1 < len(marks) else len(text)
        name = name.lower()
        if name in values:
            duplicate = True
        else:
            values[name] = text[start:end].strip()
    return values, "parse_error" if quote or depth or duplicate else "complete"

def client_context(ua):
    if not isinstance(ua, str) or len(ua) > 32768:
        return None
    context = {}
    for name, pattern in (("android_version", r"Android\s+([0-9.]{1,30})"),
                          ("chrome_version", r"Chrome/([0-9.]{1,40})"),
                          ("firefox_version", r"Firefox/([0-9.]{1,40})"),
                          ("reported_app_version", r"AppVersion:\(([0-9.]{1,40})\)")):
        found = re.search(pattern, ua)
        if found:
            context[name] = found.group(1)
    if not context:
        return None
    context["format"] = "structured_native_reported" if ua.startswith("BuildVersion:") else "browser_reported"
    context["model_or_device_label_present"] = bool(re.search(r"\b(?:Model|Device):", ua))
    context["signature_present"] = bool(re.search(r"\bSign(?:ature)?:", ua))
    # No raw UA or signature equality hash is stored.
    return context

class Semantics:
    def __init__(self, path, *, rules=REVIEWED_RULES):
        data = json.loads(Path(path).read_text(encoding="utf-8"))
        self.resolver = ScopedOutcomeResolver(data, rules=rules)
        self.digest = self.resolver.digest

    def observation(self, code, *, path, layer, role, endpoint, symbol=None, at_ns=None):
        if not isinstance(code, (str, int, Decimal)) or isinstance(code, bool):
            return None
        code = str(code)
        if not re.fullmatch(r"(?:[A-Z]{1,3}\d{4,6}|\d{3,5})", code):
            return None
        result = dict(code=code, path=path, layer=layer, role=role)
        result.update(self.resolver.resolve(code, endpoint=endpoint, role=role, layer=layer,
                                           path=path, symbol=symbol, at_ns=at_ns))
        if isinstance(symbol, str) and re.fullmatch(r"[A-Za-z][A-Za-z0-9_]{0,127}", symbol):
            result["symbol"] = symbol
        return result

def json_section(message, marker):
    if marker not in message:
        return None, "unlogged"
    tail = message.split(marker, 1)[1].lstrip()
    try:
        value, _ = json.JSONDecoder(parse_float=Decimal).raw_decode(tail)
        return value, "complete"
    except (ValueError, RecursionError):
        return None, "parse_error"

def body_observations(value, semantics, endpoint, role, root="Output", *, budget=256, at_ns=None):
    output = []
    seen = 0
    def visit(item, path, depth):
        nonlocal seen
        seen += 1
        if seen > budget or depth > 12:
            raise FoundationError("nested_output_limit")
        if isinstance(item, list):
            for i, part in enumerate(item):
                visit(part, f"{path}[{i}]", depth + 1)
        elif isinstance(item, dict):
            for key, part in item.items():
                if not isinstance(key, str) or not re.fullmatch(r"[A-Za-z][A-Za-z0-9_]{0,63}", key):
                    continue
                here = f"{path}.{key}"
                if key.lower() == "httpstatus":
                    observation = semantics.observation(part, path=here, layer="provider_http_envelope", role=role, endpoint=endpoint, at_ns=at_ns)
                    if observation:
                        output.append(observation)
                if key.lower() == "status" and isinstance(part, dict):
                    for code_key, code_value in part.items():
                        if str(code_key).lower() == "code":
                            observation = semantics.observation(code_value, path=here + "." + code_key,
                                layer="provider_body" if role == "provider" else "unknown", role=role, endpoint=endpoint, at_ns=at_ns)
                            if observation:
                                output.append(observation)
                if key.lower() == "content" and isinstance(part, str):
                    try:
                        decoded = json.loads(part, parse_float=Decimal)
                    except (ValueError, RecursionError):
                        continue
                    visit(decoded, here, depth + 1)
                elif isinstance(part, (dict, list)):
                    visit(part, here, depth + 1)
    try:
        visit(value, root, 0)
        return output, "complete"
    except FoundationError:
        return output, "truncated"

def normalize_event(record, keys, namespace, semantics, *, fallback_scope, ordinal):
    issues = []
    values, states = {}, {}
    for name in KNOWN_FIELDS:
        values[name], states[name] = field(record, name)
        if states[name] == "conflicting":
            issues.append("field_conflict_" + name)
    timestamp, time_basis = None, "unknown"
    time_values = representations(record, "@timestamp")
    parsed = []
    for kind, value, malformed in time_values:
        try:
            if malformed:
                raise FoundationError("invalid_source_time")
            parsed.append((kind, parse_time(value)))
        except FoundationError:
            issues.append("invalid_" + kind + "_timestamp")
    if parsed and len(parsed) == len(time_values):
        if all(compatible_times(parsed[0][1], item[1]) for item in parsed):
            time_basis, timestamp = next((item for item in parsed if item[0] == "source"), parsed[0])
        else:
            issues.append("timestamp_representation_conflict")
    rid = opaque(values["RequestID"])
    request_key = keys.token(namespace, "request", rid) if rid else None
    index, origin = record.get("_index"), record.get("_id")
    if isinstance(index, str) and isinstance(origin, str) and index and origin:
        event_key = keys.token(namespace, "origin", [index, origin])
        identity_kind = "origin_document"
    else:
        event_key = keys.token(namespace, "ambiguous", [fallback_scope, ordinal])
        identity_kind = "fingerprint_ambiguous"
        issues.append("origin_identity_unavailable")
    endpoint = LINE_SUFFIX.sub("", values["CallPath"]).strip() if isinstance(values["CallPath"], str) else None
    if not endpoint or not SAFE_PATH.fullmatch(endpoint):
        endpoint = None
    message = values["message"] if isinstance(values["message"], str) else ""
    signature_values = {k: normalized_scalar(k, values[k]) for k in KNOWN_FIELDS}
    signature = keys.content_digest(namespace, signature_values)
    if len(message) > 1_048_576:
        message = message[:1_048_576]
        issues.append("message_extraction_truncated")
    params, params_state = sql_parameters(message)
    command = re.search(r"\(Command Text:\s*([A-Za-z0-9_.]+)\)", message)
    method, role, event_kind = None, "unknown", "unknown"
    http = HTTP.match(message)
    if endpoint and endpoint.startswith("DBPath.") and command:
        role, event_kind = "sql", "operation_observation"
    elif endpoint and CLIENT_PATH.fullmatch(endpoint) and http:
        role, event_kind, method = "client_http", "client_completion", http.group(1)
    elif endpoint and endpoint.startswith(("ClientAyanCoInquiry.", "ClientAyanCoMessage.", "EwanoApi.")):
        role, event_kind = "provider", "operation_observation"
    sessions = set()
    session_observations = []
    for representation, value, malformed in representations(record, "Session"):
        if opaque(value):
            token = keys.token(namespace, "session", value)
            sessions.add(token)
            session_observations.append(dict(token=token, path=("_source.Session" if representation == "source" and "_source" in record else "Session" if representation == "source" else "fields.Session[0]"), direction="metadata"))
    if command and command.group(1) in CALLER_SQL and params_state == "complete" and opaque(params.get("session")):
        token = keys.token(namespace, "session", params["session"])
        sessions.add(token)
        session_observations.append(dict(token=token, path="message.SQL.Parameters.session", direction="sql_parameter"))
    ip = opaque(values["IP"])
    ip_key = keys.token(namespace, "ip", ip) if ip else None
    context = client_context(params.get("useragent"))
    context_key = keys.token(namespace, "client_context", context) if context else None
    observations = []
    status = http.groups()[1:] if http else None
    if status:
        code, symbol = status
        observation = semantics.observation(code, path="message.status.code", layer="platform_log", role=role, endpoint=endpoint, symbol=symbol.strip(), at_ns=timestamp.epoch_ns if timestamp else None)
        if observation:
            observations.append(observation)
    else:
        status_match = LOG_STATUS.search(message)
        if status_match:
            observation = semantics.observation(status_match.group(1), path="message.status.code", layer="platform_log", role=role, endpoint=endpoint, symbol=status_match.group(2), at_ns=timestamp.epoch_ns if timestamp else None)
            if observation:
                observations.append(observation)
    sql_result = dict(SQL_RESULT.findall(message)) if role == "sql" else {}
    sql_execution = "success" if sql_result.get("Code") == "1" and sql_result.get("Result", "").lower() == "ok" else "unknown"
    if role == "sql":
        # Store finite execution observations without treating them as client/business outcomes.
        observations.append(dict(code="1" if sql_result.get("Code") == "1" else None, path="message.sql.Code",
                                 layer="sql_result", role="sql", outcome=sql_execution, meaning_fa=None,
                                 meaning_source=None, validation="observed_sql_execution"))
    output, output_state = json_section(message, "Output:")
    if output is not None:
        nested, output_state = body_observations(output, semantics, endpoint, role, at_ns=timestamp.epoch_ns if timestamp else None)
        observations.extend(nested)
    if output_state in {"parse_error", "truncated"}:
        issues.append("output_" + output_state)
    # Query-result/status SQL parameters preserve their own recorded-stage scope.
    if "statuscode" in params:
        observation = semantics.observation(params["statuscode"], path="SQL.Parameters.statusCode", layer="workflow_body", role=role, endpoint=endpoint, symbol=params.get("statusname"), at_ns=timestamp.epoch_ns if timestamp else None)
        if observation:
            observations.append(observation)
    log_outcomes = [o["outcome"] for o in observations if o["layer"] == "platform_log"]
    body_outcomes = [o["outcome"] for o in observations if o["layer"] == "provider_body" and o["outcome"] != "unknown"]
    if role == "sql":
        operation_outcome = sql_execution
    else:
        relevant = body_outcomes if role == "provider" and body_outcomes else [a for a in log_outcomes if a != "unknown"]
        operation_outcome = next(iter(set(relevant))) if len(set(relevant)) == 1 else "conflicting" if relevant else "unknown"
    duration = normalized_scalar("ExecutionTime", values["ExecutionTime"])
    if duration is not None and Decimal(duration) < 0:
        duration = None
        issues.append("invalid_negative_duration")
    secret_fields = sorted(k for k in params if SECRET_NAME.search(k))
    descriptor = dict(parser_version=PARSER_VERSION, request_key=request_key,
                      structured_session_state=states["Session"], sql_session_state=("logged_empty" if params.get("session") == "" else "present" if "session" in params else "unlogged"),
                      session_candidates=sorted(sessions), session_observations=session_observations, identity_conflict=states["Session"] == "conflicting" or len(sessions) > 1,
                      ip_key=ip_key, client_context=context, client_context_key=context_key,
                      endpoint=endpoint, role=role, event_kind=event_kind, method=method,
                      source_time=timestamp.public() if timestamp else None, time_basis=time_basis,
                      duration_ms=duration, outcomes=observations, operation_outcome=operation_outcome,
                      sql_parameter_names=sorted(params), sql_parameter_coverage=params_state,
                      secret_fields_present=secret_fields, secrets_value_retained=False,
                      output_coverage=output_state, source_coverage="observed_only", issues=sorted(set(issues)),
                      application_label=params.get("application") if params.get("application") in {"ewano", "pishkhan24"} else None,
                      application_version=params.get("version") if re.fullmatch(r"[0-9.]{1,40}", params.get("version", "")) else None,
                      caller_sql_action=params.get("action") if re.fullmatch(r"v\d+/[A-Za-z][A-Za-z0-9_]*", params.get("action", "")) else None)
    payload = dict(descriptor=descriptor, facts_signature=signature,
                   raw_time=timestamp.original if timestamp else None)
    return dict(event_key=event_key, identity_kind=identity_kind, request_key=request_key,
                content_digest=keys.content_digest(namespace, [signature, payload]),
                descriptor=descriptor, payload=payload, time=timestamp)

