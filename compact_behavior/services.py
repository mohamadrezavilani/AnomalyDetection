"""Exact dispatcher routes reviewed against source; never inferred by provider name."""

from functools import lru_cache
import json
from pathlib import Path


@lru_cache(maxsize=1)
def routes():
    return json.loads(
        (Path(__file__).with_name("dispatch_routes.json")).read_text(encoding="utf-8")
    )["routes"]
