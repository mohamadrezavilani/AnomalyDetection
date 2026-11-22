"""Bounded, explicit feature completeness; array targets are typed multisets."""

from collections import defaultdict
import hashlib
import json
import math
import re
from .json_value import unique_object

TARGET = re.compile(
    r"(?:billid|participatecode|nationalcode|nationalid|platenumber|iban|phonenumber|mobilenumber|linenumber|telephone|accountnumber)$",
    re.I,
)


def canonical(value):
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    )


def extract_features(
    value,
    *,
    max_array_items=512,
    max_nodes=8192,
    max_depth=16,
    max_shapes=1024,
    max_numeric_paths=128
):
    targets = defaultdict(list)
    numbers = defaultdict(list)
    shapes = []
    nodes = 0
    reasons = {k: set() for k in ("targets", "numeric", "shape")}

    def limited(reason, fields=("targets", "numeric", "shape")):
        for field in fields:
            reasons[field].add(reason)

    def shape(item):
        if len(shapes) < max_shapes:
            shapes.append(item)
        else:
            limited("SHAPE_LIMIT", ("shape",))

    def walk(node, path="", depth=0):
        nonlocal nodes
        nodes += 1
        if nodes > max_nodes:
            limited("NODE_LIMIT")
            return
        if depth > max_depth:
            limited("DEPTH_LIMIT")
            return
        if isinstance(node, dict):
            if node.get("binary_content_omitted") is True:
                limited("BINARY_CONTENT_OMITTED")
                return
            shape([path, "object", sorted(node)])
            for key, child in sorted(node.items()):
                here = path + "." + key if path else key
                if (
                    TARGET.search(key)
                    and isinstance(child, (str, int))
                    and not isinstance(child, bool)
                ):
                    targets[here].append(
                        dict(
                            type="string" if isinstance(child, str) else "integer",
                            value=child,
                        )
                    )
                walk(child, here, depth + 1)
                if nodes > max_nodes:
                    break
        elif isinstance(node, list):
            shape([path, "array", len(node)])
            if len(node) > max_array_items:
                limited("ARRAY_LIMIT")
            for child in node[:max_array_items]:
                walk(child, path + "[]", depth + 1)
                if nodes > max_nodes:
                    break
        else:
            if isinstance(node, str) and node.lstrip().startswith(("{", "[")):
                try:
                    json.loads(node, object_pairs_hook=unique_object)
                except (ValueError, RecursionError):
                    limited("ENCODED_JSON_PARSE_ERROR")
            shape([path, type(node).__name__])
            if isinstance(node, (int, float)) and not isinstance(node, bool):
                try:
                    finite = math.isfinite(node)
                except OverflowError:
                    finite = False
                if not finite:
                    limited("NONFINITE_NUMBER", ("numeric",))
                    return
                if path not in numbers and len(numbers) >= max_numeric_paths:
                    limited("NUMERIC_PATH_LIMIT", ("numeric",))
                    return
                numbers[path].append(node)

    walk(value)
    numeric = {}
    for path, values in sorted(numbers.items()):
        try:
            total = math.fsum(values)
        except OverflowError:
            limited("NUMERIC_OVERFLOW", ("numeric",))
            continue
        if not math.isfinite(total):
            limited("NUMERIC_OVERFLOW", ("numeric",))
            continue
        numeric[path] = dict(
            count=len(values),
            min=min(values),
            max=max(values),
            sum=total,
            mean=total / len(values),
            values_hash=hashlib.sha256(canonical(sorted(values)).encode()).hexdigest(),
        )
    completeness = {
        key: dict(complete=not value, reasons=sorted(value))
        for key, value in reasons.items()
    }
    return dict(
        targets={
            key: sorted(values, key=canonical)
            for key, values in sorted(targets.items())
        },
        numeric=numeric,
        shape_hash=hashlib.sha256(
            canonical(sorted(shapes, key=canonical)).encode()
        ).hexdigest(),
        completeness=completeness,
        complete=all(v["complete"] for v in completeness.values()),
        array_contract="TYPED_TARGET_MULTISET_NUMERIC_SUMMARY_AND_MULTISET_HASH",
        visited_nodes=min(nodes, max_nodes),
    )


def complete(feature, component):
    return (
        isinstance(feature, dict)
        and feature.get("completeness", {}).get(component, {}).get("complete") is True
    )
