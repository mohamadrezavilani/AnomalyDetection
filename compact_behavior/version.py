"""Verify this small package once at startup, never in the processing loop."""

import hashlib
import json
from pathlib import Path


def verify(root=None):
    root = Path(root) if root else Path(__file__).resolve().parent
    manifest = json.loads((root / "MANIFEST.json").read_text(encoding="utf-8"))
    files = manifest["files_sha256"]
    if not files or any(
        "/" in k
        or "\\" in k
        or not k.endswith((".py", ".json"))
        or k == "MANIFEST.json"
        for k in files
    ):
        raise ValueError("invalid_compact_manifest")
    actual = {k: hashlib.sha256((root / k).read_bytes()).hexdigest() for k in files}
    if actual != files:
        raise ValueError("compact_package_bytes_changed")
    sha = hashlib.sha256(
        json.dumps(actual, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()
    return dict(
        build_id=manifest["build_id"], source_sha256=sha, checked_files=len(files)
    )


if __name__ == "__main__":
    root = Path(__file__).resolve().parent
    value = dict(
        build_id="COMPACT-BEHAVIOR-20261123-21",
        contract="compact-behavior-1",
        files_sha256={
            p.name: hashlib.sha256(p.read_bytes()).hexdigest()
            for p in sorted(list(root.glob("*.py")) + [p for p in root.glob("*.json") if p.name != "MANIFEST.json"])
        },
    )
    (root / "MANIFEST.json").write_text(
        json.dumps(value, indent=2) + "\n", encoding="utf-8"
    )
