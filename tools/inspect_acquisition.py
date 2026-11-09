"""Inspect a local capture without DB access, network calls or raw output."""
from pathlib import Path
import argparse
import json
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from p24_foundation.errors import FoundationError
from p24_foundation.intake import read_batch


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", type=Path, required=True)
    args = parser.parse_args()
    try:
        batch = read_batch(args.input)
        print(json.dumps(dict(ok=True, assessment=batch.coverage, raw_payload_printed=False,
                              database_used=False, network_used=False), ensure_ascii=False, indent=2))
        return 0
    except FoundationError as error:
        print(json.dumps(dict(ok=False, error=error.code, raw_payload_printed=False)), file=sys.stderr)
        return 2
    except Exception:
        print(json.dumps(dict(ok=False, error="capture_inspection_failed", raw_payload_printed=False)), file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
