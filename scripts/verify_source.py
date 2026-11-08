"""Verify the published baseline subset and the separate experimental selector."""
import hashlib
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def main():
    provenance = json.loads((ROOT / 'docs/PUBLIC_SOURCE_PROVENANCE.json').read_text(encoding='utf-8'))
    groups = ('baseline_files_sha256', 'candidate_files_sha256')
    for group in groups:
        for name, expected in provenance[group].items():
            path = (ROOT / name).resolve()
            if not path.is_relative_to(ROOT) or not path.is_file():
                raise SystemExit(f'INVALID_SOURCE_MEMBER {name}')
            if hashlib.sha256(path.read_bytes()).hexdigest() != expected:
                raise SystemExit(f'SOURCE_HASH_MISMATCH {name}')
    print(json.dumps({
        'status': 'PASS_PUBLIC_SOURCE_INTEGRITY',
        'baseline_build_id': provenance['baseline_build_id'],
        'verified_baseline_files': len(provenance[groups[0]]),
        'verified_candidate_files': len(provenance[groups[1]]),
    }, indent=2))


if __name__ == '__main__':
    main()
