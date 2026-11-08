"""Synthetic projection contract, with expectations taken from the handoff.

No raw logs are classified here. These are NOT exported owner Viewer results.
"""
from copy import deepcopy
import hashlib

from anomaly_detection import CONTRACT, SOURCE_SHA, CATALOG_SHA, SEMANTIC_SCHEMA, FIVE_NS
from anomaly_detection.snapshot import TABLES

START = 1_798_000_000_000_000_000 // FIVE_NS * FIVE_NS
SECOND = 1_000_000_000
SESSION_A = "a" * 64
SESSION_B = "b" * 64
WATER = "Services.v1/WaterBills"
DISPATCHED = "Services.v1/SocialSecurityInsuranceElectronicPrescription"


def key(number):
    return f"{number:064x}"


def anchor(number):
    # Test-only fixture identity. Consumer copies, never generates these keys.
    return "ba1:" + hashlib.sha256(("synthetic-anchor:" + str(number)).encode()).hexdigest()


def metadata(sequence=1):
    return dict(namespace="synthetic-two-window-contract", stream_key="synthetic-stream",
                keys_fingerprint="synthetic-key-namespace", runtime_sha256=SOURCE_SHA,
                catalog_fingerprint=CATALOG_SHA, semantic_schema=SEMANTIC_SCHEMA,
                catalog_status="CURRENT", semantic_state="ready", maintenance="OFFLINE_FIXTURE",
                evidence_mode="synthetic_contract", source_finality="not_established",
                sequence=sequence, generation=10 + sequence, semantic_generation=10 + sequence,
                captured_at_ns=START + (600 + sequence) * SECOND, consistent_snapshot=True,
                global_origin_versions_complete=True)


def event(number, request_number, call, second, *, version=1):
    return dict(origin_key=key(1000 + number), version_key=key(2000 + version),
                request_key=key(request_number), at_ns=START + second * SECOND,
                callpath=call, raw_available=True)


def initial():
    tables = {name: [] for name in TABLES}
    specs = [(1, WATER, WATER, "service_execution", SESSION_A, 299),
             (2, WATER, WATER, "service_execution", SESSION_A, 301),
             (3, "Services.v1/AddUserData", None, None, SESSION_A, 302),
             (4, "Core.v1/WalletPayment", None, None, SESSION_A, 303),
             (5, None, None, "product_reservation_execution", SESSION_A, 304),
             (6, "Core.v1/UserWalletCharge", "Core.v1/UserWalletCharge", "wallet_funding_execution", SESSION_A, 305),
             (7, "Core.v1/UserProfileUpdate", "Core.v1/UserProfileUpdate", "user_management_execution", SESSION_A, 306),
             (8, "Services.v1/InvoiceRegister", DISPATCHED, "service_execution", SESSION_B, 307)]
    for number, transport, service, kind, session, second in specs:
        tables["viewer_requests"].append(dict(request_key=key(number), session_key=session,
            identity_state="assigned", conflicted=0, root_call=transport, root_code="G00000",
            started_ns=START + second * SECOND, ended_ns=START + (second + 3) * SECOND))
        tables["viewer_events"].append(event(number, number, transport or "ClientAyanCoTopUp.ProductReserve", second))
        if not kind:
            continue
        role = "user_management" if kind == "user_management_execution" else "business"
        tables["viewer_semantic_occurrences"].append(dict(request_key=key(number), anchor_key=anchor(number),
            session_key=session, anchor_ns=START + second * SECOND, kind=kind,
            occurrence_key="bo1:" + key(3000 + number), root_call=service,
            root_code="G00000", family_id=None, family_label_fa=None, category=role,
            initiation="unknown", state="active", revision=1, updated_at="2026-10-31T00:00:00Z"))
        if service:
            tables["viewer_service_roles"].append(dict(service_path=service, role=role,
                initiation="unknown", source="operator", reviewed=1, note="synthetic contract", changed_at="fixture"))
    # One logical request crosses two windows; the second event is not a new behavior.
    tables["viewer_events"].append(event(11, 1, "ClientAyanCoInquiry.WaterBills", 302))
    # Remove the repeated role row for the two independent WaterBills requests.
    tables["viewer_service_roles"] = list({row["service_path"]: row for row in tables["viewer_service_roles"]}.values())
    return dict(format=CONTRACT, source=metadata(), scope=dict(id="two-window-small-scope",
                request_keys=[key(n) for n in range(1, 9)], complete=True, population_complete=True,
                complete_intervals_ns=[[START, START + FIVE_NS], [START + FIVE_NS, START + 2 * FIVE_NS]]), tables=tables)


def next_snapshot(snapshot):
    result = deepcopy(snapshot)
    result["source"].update(metadata(result["source"]["sequence"] + 1))
    return result


def occurrence(snapshot, number):
    return next(row for row in snapshot["tables"]["viewer_semantic_occurrences"] if row["request_key"] == key(number))


def late_result(snapshot):
    result = next_snapshot(snapshot)
    ev = event(21, 8, "DBPath.ud_prc_inquiryInvoiceResult2", 390)
    result["tables"]["viewer_events"].append(ev)
    result["tables"]["viewer_contract_observations"].append(dict(origin_key=ev["origin_key"],
        version_key=ev["version_key"], request_key=key(8), at_ns=ev["at_ns"], callpath=ev["callpath"],
        axis="service_dispatch.inquiry_result", value="GD2076", field_path="statusCode", authority="reported"))
    return result


def replacement(snapshot):
    result = next_snapshot(snapshot)
    row = occurrence(result, 5)
    row.update(kind="service_execution", root_call="Services.v1/TopUpProductPurchase",
               occurrence_key="bo1:" + key(4005), revision=2, anchor_ns=START + 200 * SECOND)
    return result


def withdraw(snapshot):
    result = next_snapshot(snapshot)
    row = occurrence(result, 1)
    row.update(state="withdrawn", revision=row["revision"] + 1)
    return result


def restore(snapshot):
    result = next_snapshot(snapshot)
    row = occurrence(result, 1)
    row.update(state="active", revision=row["revision"] + 1)
    return result


def retention(snapshot):
    result = next_snapshot(snapshot)
    for name in ("viewer_semantic_occurrences", "viewer_requests", "viewer_events"):
        result["tables"][name] = [row for row in result["tables"][name] if row["request_key"] != key(2)]
    return result


def sequence():
    snapshots = [initial()]
    for mutate in (late_result, replacement, withdraw, restore, retention):
        snapshots.append(mutate(snapshots[-1]))
    return snapshots
