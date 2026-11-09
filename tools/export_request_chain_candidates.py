"""Export sanitized per-RequestID operation-chain candidates from fixtures."""
import argparse
import json
import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from p24_foundation.privacy import Keys
from p24_foundation.request_chains import REQUEST_CHAIN_VERSION, build_request_chain_candidates


def build(paths, catalog_path=Path("catalogs/error_code_catalog.json")):
    keys = Keys(os.urandom(32), os.urandom(32), "request_chain_export_v1")
    sources = []
    for path in sorted(map(Path, paths), key=lambda item: item.name.casefold()):
        sources.append(build_request_chain_candidates(
            path.read_bytes(), locator=path.name, keys=keys,
            namespace="request_chain:" + path.name, catalog_path=catalog_path,
        ))
    return {
        "version": REQUEST_CHAIN_VERSION,
        "status": "unpublished_request_chain_candidates",
        "interpretation": "same-RequestID co-observation; timestamps order observations but do not prove causality",
        "source_counts_must_not_be_summed": "fixture captures may overlap; cross-source RequestID union is not computed",
        "raw_request_ids_ip_session_sql_values_or_payloads_exported": False,
        "sources": sources,
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--inputs", nargs="+", required=True, type=Path)
    parser.add_argument("--catalog", type=Path, default=Path("catalogs/error_code_catalog.json"))
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    output = build(args.inputs, args.catalog)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(output, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({
        "sources": len(output["sources"]),
        "request_projections": sum(s["request_projection_count"] for s in output["sources"]),
        "raw_identity_or_payload_values_exported": False,
        "causal_execution_proven": False,
    }, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
