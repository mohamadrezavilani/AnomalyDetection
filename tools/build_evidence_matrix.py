"""Build the source-scoped route/outcome evidence matrix from saved candidates."""
import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from p24_foundation.evidence_matrix import EVIDENCE_MATRIX_VERSION, build_evidence_matrix


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--chains", type=Path, default=Path("catalogs/request_chain_candidates.json"))
    parser.add_argument("--api", type=Path, default=Path("catalogs/action_api_reconciliation_candidates.json"))
    parser.add_argument("--errors", type=Path, default=Path("catalogs/error_operation_candidates.json"))
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    result = build_evidence_matrix(
        json.loads(args.chains.read_text(encoding="utf-8")),
        json.loads(args.api.read_text(encoding="utf-8")),
        json.loads(args.errors.read_text(encoding="utf-8")),
    )
    if result["version"] != EVIDENCE_MATRIX_VERSION:
        raise RuntimeError("unexpected evidence matrix version")
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    summary = {
        "sources": len(result["sources"]),
        "source_scoped_pairs": sum(source["pair_count"] for source in result["sources"]),
        "ambiguous_outcome_contexts": sum(source["ambiguous_outcome_context_count"] for source in result["sources"]),
        "authoritative_taxonomy_published": False,
        "cross_source_counts_summed": False,
        "causality_or_execution_proven": False,
    }
    print(json.dumps(summary, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
