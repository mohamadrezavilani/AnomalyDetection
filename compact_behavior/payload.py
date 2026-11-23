"""Retain bounded values or exact bounded features, never an oversized raw payload."""

import copy
import hashlib
import json
from .feature_contract import extract_features

VALUE_BYTES = 16384
COMPONENT_BYTES = 131072


def encoded(value):
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()


def packed(value, *, inquiry_input=False):
    raw = encoded(value)
    info = dict(value_hash=hashlib.sha256(raw).hexdigest(), value_bytes=len(raw))
    if len(raw) <= VALUE_BYTES:
        return dict(info, representation="FULL_VALUE_V1", value=value)
    feature = extract_features(value)
    for component in ("targets", "numeric"):
        if len(encoded(feature[component])) > COMPONENT_BYTES:
            feature[component] = {}
            complete = feature["completeness"][component]
            complete["complete"] = False
            complete["reasons"] = sorted(set(complete["reasons"] + ["FEATURE_STORAGE_LIMIT"]))
    feature["complete"] = all(x["complete"] for x in feature["completeness"].values())
    if inquiry_input:
        from .inquiry import NAMES, candidates
        fields = candidates(value, NAMES)
        if fields:
            info['inquiry_candidates'] = fields
    return dict(info, representation="FEATURES_ONLY_V1", value=None, feature_snapshot=feature)


def normalize(entry):
    if "representation" in entry:
        return entry
    return {**entry, **packed(entry["value"])}


def identity(entry):
    return entry.get("value_hash") or hashlib.sha256(encoded(entry["value"])).hexdigest()


def feature(entry):
    if entry.get("representation") == "FEATURES_ONLY_V1":
        return copy.deepcopy(entry["feature_snapshot"])
    return extract_features(entry["value"])
