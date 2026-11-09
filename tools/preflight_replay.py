"""Run the bounded offline replay contracts and, optionally, native acceptance.

The command never starts a collector. Without --config, database integration is
reported as NOT_RUN. Test output is kept out of the machine result.
"""
from pathlib import Path
import argparse
import hashlib
import json
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[1]


def run_suite(config=None):
    """Run the maintained suite and return its compact result plus exit code."""
    with tempfile.TemporaryDirectory(prefix="p24-preflight-") as temporary:
        result_path = Path(temporary) / "tests.json"
        command = [sys.executable, str(ROOT / "tools" / "run_tests.py")]
        if config is None:
            command.append("--offline")
        else:
            command.extend(("--config", str(config.resolve())))
        command.extend(("--output", str(result_path)))
        completed = subprocess.run(command, cwd=ROOT, stdout=subprocess.DEVNULL,
                                   stderr=subprocess.PIPE, text=True, check=False)
        if not result_path.is_file():
            missing_dependency = "ModuleNotFoundError: No module named" in completed.stderr
            return {"status": "NOT_RUN" if missing_dependency else "FAIL",
                    "reason": "required_dependency_missing" if missing_dependency else "suite_result_missing"}, completed.returncode
        try:
            raw = json.loads(result_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            return {"status": "FAIL", "reason": "suite_result_invalid"}, completed.returncode
        status = "PASS" if completed.returncode == 0 and raw.get("ok") is True else "FAIL"
        compact = {
            "status": status,
            "tests": raw.get("tests"),
            "failures": raw.get("failures"),
            "errors": raw.get("errors"),
            "unexpected_skips": len(raw.get("unexpected_skip_details", [])),
            "postgres_server_version": raw.get("postgres_server_version"),
            "startup_error": raw.get("startup_error"),
            "failed_tests": raw.get("failure_test_ids", []),
            "errored_tests": raw.get("error_test_ids", []),
            "source_file_count": len(raw.get("tested_source_sha256", {})),
            "source_manifest_sha256": hashlib.sha256(json.dumps(
                raw.get("tested_source_sha256", {}), sort_keys=True,
                separators=(",", ":")).encode("utf-8")).hexdigest(),
        }
        return compact, completed.returncode


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", type=Path,
                        help="explicit local config for the guarded PostgreSQL suite")
    parser.add_argument("--output", type=Path,
                        default=ROOT / "validation" / "latest_preflight.json")
    args = parser.parse_args()

    offline, _ = run_suite()
    checks = {
        "offline_golden_replay": offline,
        "postgresql_integration": {"status": "NOT_RUN"},
    }
    if args.config is not None:
        native, _ = run_suite(args.config)
        checks["postgresql_integration"] = native

    required = [offline] + ([checks["postgresql_integration"]] if args.config is not None else [])
    statuses = [item["status"] for item in required]
    overall = "FAIL" if "FAIL" in statuses else "NOT_RUN" if "NOT_RUN" in statuses else "PASS"
    result = {
        "schema": "p24.preflight.v1",
        "status": overall,
        "checks": checks,
        "scope": [
            "overlap, Session continuity, boundary chain, outcome separation, privacy and request reconstruction use maintained offline fixtures/contracts",
            "PostgreSQL integration is NOT_RUN unless an explicit local config is supplied",
            "no collector or production system is started or modified",
        ],
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, ensure_ascii=False, indent=2) + "\n",
                           encoding="utf-8")
    print(json.dumps(result, ensure_ascii=False, separators=(",", ":")))
    return 1 if overall == "FAIL" else 2 if overall == "NOT_RUN" else 0


if __name__ == "__main__":
    raise SystemExit(main())
