"""LC3C self-contained synthetic replay acceptance guard. Does not open the user's DB."""
from __future__ import annotations
import argparse
import json
from pathlib import Path
import sys
ROOT=Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:sys.path.insert(0,str(ROOT))
from p24_foundation.lc3_replay_audit import replay_witness

def main(argv=None):
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--out',type=Path,required=True)
    args=parser.parse_args(argv)
    try:
        result=replay_witness()
        args.out.parent.mkdir(parents=True,exist_ok=True)
        args.out.write_text(json.dumps(result,ensure_ascii=False,indent=2),encoding='utf-8')
        print(json.dumps({'output':str(args.out),'orders_tested':len(result['orders_tested']),
            'order_independent_derived_snapshot':result['order_independent_derived_snapshot'],
            'repeated_file_import_idempotent':result['repeated_file_import_idempotent'],
            'full_r5_end_to_end_accepted_cases':0},ensure_ascii=False))
        return 0
    except Exception as exc:
        # Fixed error identifiers only; never print raw payloads or filenames.
        print('LC3C_REPLAY_FAILED: '+type(exc).__name__,file=sys.stderr)
        return 2

if __name__=='__main__':raise SystemExit(main())
