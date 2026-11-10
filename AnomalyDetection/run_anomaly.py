"""Verify this build before importing/running any AnomalyDetection command."""
from __future__ import annotations

import hashlib
from importlib.machinery import PathFinder,SourceFileLoader
import json
from pathlib import Path
import sys

EXPECTED_BUILD = "AD-20261110-AUDIT-REPORT"
ROOT = Path(__file__).resolve().parent
VERIFIED_FILES = {}
sys.dont_write_bytecode = True


def verify_build():
    global VERIFIED_FILES
    manifest = json.loads((ROOT / "RELEASE_MANIFEST.json").read_text(encoding="utf-8"))
    if manifest.get("build_id") != EXPECTED_BUILD:
        raise ValueError("wrong_build_manifest")
    entries = manifest.get("files_sha256", {})
    if not entries or not all(name in entries for name in ('run_anomaly.py','anomaly_detection/product_cli.py')):
        raise ValueError("incomplete_build_manifest")
    for name, expected in entries.items():
        path = (ROOT / name).resolve()
        if not path.is_relative_to(ROOT) or not path.is_file():
            raise ValueError("missing_or_unsafe_build_member:" + name)
        if hashlib.sha256(path.read_bytes()).hexdigest() != expected:
            raise ValueError("build_file_mismatch:" + name)
    for directory, suffix in (("anomaly_detection", ".py"), ("tests", ".py"), ("fixtures", ".json")):
        actual = {path.relative_to(ROOT).as_posix() for path in (ROOT / directory).rglob("*" + suffix)
                  if "__pycache__" not in path.parts}
        expected = {name for name in entries if name.startswith(directory + "/") and name.endswith(suffix)}
        if actual != expected:
            raise ValueError("mixed_build_inventory:" + directory)
    calculated = hashlib.sha256(json.dumps(entries, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
    if calculated != manifest.get("source_sha256"):
        raise ValueError("build_digest_mismatch")
    VERIFIED_FILES = dict(entries)
    return calculated


class VerifiedSourceLoader(SourceFileLoader):
    def get_code(self,fullname):
        path=Path(self.get_filename(fullname)).resolve()
        name=path.relative_to(ROOT).as_posix()
        source=self.get_data(str(path))
        if hashlib.sha256(source).hexdigest()!=VERIFIED_FILES.get(name):
            raise ImportError("VERIFIED_APPLICATION_SOURCE_CHANGED")
        return self.source_to_code(source,str(path))


class VerifiedApplicationFinder:
    def find_spec(self,fullname,path=None,target=None):
        if not any(fullname==name or fullname.startswith(name+'.') for name in ('anomaly_detection','tests')):
            return None
        spec=PathFinder.find_spec(fullname,path)
        if spec is None: return None
        if not spec.origin or not Path(spec.origin).resolve().is_relative_to(ROOT):
            raise ImportError("UNVERIFIED_APPLICATION_IMPORT")
        spec.loader=VerifiedSourceLoader(fullname,spec.origin)
        return spec


if __name__ == "__main__":
    try:
        source_sha = verify_build()
    except (ValueError, OSError) as error:
        print(json.dumps({"status": "BUILD_VERIFICATION_FAILED", "expected_build": EXPECTED_BUILD,
                          "error": str(error)}, ensure_ascii=False))
        raise SystemExit(1)
    sys.path.insert(0, str(ROOT))
    # Only application/test imports bypass bytecode. Standard/vendor imports
    # keep their ordinary valid cache, avoiding a global cold dependency load.
    sys.meta_path.insert(0,VerifiedApplicationFinder())
    from anomaly_detection.product_cli import main
    raise SystemExit(main(source_sha))
