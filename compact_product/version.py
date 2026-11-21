"""One startup verification of compact code, model, route map and templates."""

import hashlib
import json
from pathlib import Path
from compact_behavior.version import verify as behavior_verify
from . import BUILD


def verify(root=None):
    root = Path(root).resolve() if root else Path(__file__).resolve().parents[1]
    manifest = json.loads(
        (root / "compact_product/MANIFEST.json").read_text(encoding="utf-8")
    )
    files = manifest["files_sha256"]
    actual = {}
    for name, expected in files.items():
        path = (root / name).resolve()
        if not path.is_relative_to(root) or not (name == "catalogs/error_code_catalog.json" or name.startswith(
            ("compact_ad/", "compact_product/", "requirements-compact.txt")
        )):
            raise ValueError("invalid_product_manifest_path")
        actual[name] = hashlib.sha256(path.read_bytes()).hexdigest()
    if not actual or actual != files:
        raise ValueError("compact_product_package_bytes_changed")
    source = behavior_verify(root / "compact_behavior")
    return dict(
        build_id=BUILD,
        source_sha256=hashlib.sha256(
            json.dumps([actual, source], sort_keys=True).encode()
        ).hexdigest(),
        behavior=source,
        checked_files=len(files) + source["checked_files"],
    )


def write():
    root = Path(__file__).resolve().parents[1]
    paths = sorted(
        [
            p
            for folder in ("compact_ad", "compact_product")
            for p in (root / folder).rglob("*")
            if p.is_file() and p.suffix in (".py", ".html", ".ps1")
        ]
        + [root / "requirements-compact.txt", root / "catalogs/error_code_catalog.json"]
    )
    manifest = dict(
        build_id=BUILD,
        files_sha256={
            p.relative_to(root).as_posix(): hashlib.sha256(p.read_bytes()).hexdigest()
            for p in paths
        },
    )
    (root / "compact_product/MANIFEST.json").write_text(
        json.dumps(manifest, indent=2) + "\n", encoding="utf-8"
    )


if __name__ == "__main__":
    write()
