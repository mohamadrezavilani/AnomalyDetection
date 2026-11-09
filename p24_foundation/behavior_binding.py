"""Immutable detector evidence bindings, shared by the writer and incident reader."""
import hashlib
import uuid

from .privacy import canonical
from .errors import FoundationError

VERSION = "p24-behavior-binding.1"


def window_key(start_ns, end_ns):
    return f"{start_ns}:{end_ns}"


def heads_digest(requests, heads):
    if not requests or len(requests) > 100_000 or any(key not in heads for key in requests):
        raise FoundationError("behavior_target_support_unavailable")
    return hashlib.sha256(canonical(sorted((key, str(heads[key])) for key in requests))).hexdigest()


def binding_reason(binding, selections, effective_sources, current_digest):
    """Return a fixed exclusion code; legacy findings never enter this path."""
    try:
        if binding["version"] != VERSION:
            raise ValueError()
        uuid.UUID(binding["evaluation_id"])
        key = window_key(binding["start_ns"], binding["end_ns"])
        if selections.get(key) != binding["evaluation_id"]:
            return "behavior_evaluation_superseded"
        if not binding["reference_snapshots"] or len(binding["reference_snapshots"]) > 128:
            raise ValueError()
        if not set(binding["reference_snapshots"]) <= set(map(str, effective_sources)):
            return "behavior_reference_selection_changed"
        if current_digest != binding["target_heads_sha256"]:
            return "behavior_target_group_changed"
        return None
    except (KeyError, TypeError, ValueError, AttributeError):
        return "behavior_binding_invalid"
