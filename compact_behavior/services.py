"""Exact dispatcher routes reviewed against source; never inferred by provider name."""

from functools import lru_cache
import json
from pathlib import Path


@lru_cache(maxsize=1)
def routes():
    return json.loads(
        (Path(__file__).with_name("dispatch_routes.json")).read_text(encoding="utf-8")
    )["routes"]


@lru_cache(maxsize=1)
def operation_catalog():
    return json.loads(Path(__file__).with_name("operation_roles.json").read_text(encoding="utf-8"))


@lru_cache(maxsize=1)
def independent_operations():
    """Exact additional roots confirmed by the owner; no prefix inference."""
    value = json.loads(Path(__file__).with_name("independent_operations.json").read_text(encoding="utf-8"))
    for path, entry in value['routes'].items():
        if operation_catalog()['routes'].get(path, {}).get('role') != entry['role']:
            raise ValueError('independent_operation_role_mismatch')
    return frozenset(value['routes'])


@lru_cache(maxsize=1)
def internal_proxies():
    return frozenset(api for api, row in operation_catalog()['routes'].items()
                     if row.get('authority') == 'owner-confirmed-internal-proxy-20261123')


def operation_role(api, service=None, binding=None):
    if api == "Services.v1/InvoiceRegister":
        if binding == "SAME_REQUEST_REVIEWED_DISPATCH" and service:
            return operation_catalog()["routes"].get(service, {}).get("role", "unknown")
        return "unknown"
    if api in ("Core.v1/AddUserData", "Core.v1/GetUserData", "Services.v1/AddUserData", "Services.v1/GetUserData"):
        return "support"
    return operation_catalog()["routes"].get(api, {}).get("role", "unknown")


def meaningful(api, service=None, binding=None):
    return operation_role(api, service, binding) in ("business", "user_management")


def meaningful_apis():
    return sorted(api for api in operation_catalog()["routes"] if meaningful(api))


def foreground_apis(apis, roots):
    """A reviewed timer trace can inherit a request's logging context.

    Only its non-HTTP cleanup trace is supplementary to an actual HTTP root.
    Preserve standalone jobs and every competing HTTP completion.
    """
    cleanup = 'HelperQueue.CleanupOldItems'
    if (cleanup in apis and len(apis) > 1 and roots
            and not any(r['api'] == cleanup for r in roots)):
        return [api for api in apis if api != cleanup]
    return apis


def operation_label(api, service=None):
    target = service or api
    labels = {"WaterBills":"استعلام قبض آب", "GasBills":"استعلام قبض گاز", "ElectricBills":"استعلام قبض برق", "CellPhoneBills":"استعلام قبض تلفن همراه", "LandLinePhoneBills":"استعلام قبض تلفن ثابت"}
    action = (target or "").split("/")[-1]
    return labels.get(action) or operation_catalog()["routes"].get(target, {}).get("family_label_fa") or target or "خدمت نامشخص"
