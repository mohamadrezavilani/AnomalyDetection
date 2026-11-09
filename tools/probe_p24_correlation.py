"""Offline, read-only probe for P24_CORRELATION_V1 candidates in JSON windows."""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from p24_foundation.correlation_preflight import scan_files


def main(argv=None) -> int:
    p = argparse.ArgumentParser(description='Inspect candidate correlation markers; never joins payments')
    p.add_argument('--path', action='append', required=True,
                   help='JSON/.json.gz file or directory of evidence windows (repeatable)')
    p.add_argument('--max-records', type=int)
    p.add_argument('--sample-limit', type=int, default=20)
    p.add_argument('--report', help='optional local JSON report file')
    args = p.parse_args(argv)
    files = []
    for value in args.path:
        path = Path(value)
        if path.is_dir():
            files.extend(p for p in path.rglob('*') if p.name.endswith('.json.gz') or p.suffix == '.json')
        else:
            files.append(path)
    files = sorted(set(files))
    if not files:
        p.error('no .json or .json.gz evidence windows found')
    try:
        data = scan_files(files, max_records=args.max_records, sample_limit=args.sample_limit)
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        p.exit(2, f'ERROR: {exc}\n')
    output = json.dumps(data, ensure_ascii=False, indent=2)
    if args.report:
        Path(args.report).write_text(output+'\n', encoding='utf-8')
    print(output)
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
