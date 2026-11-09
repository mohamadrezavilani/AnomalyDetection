"""Audit explicit saved gzip dumps, including cross-window chains; no network/DB."""
import argparse,json
from pathlib import Path
import sys
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))
from p24_foundation.historical_replay import audit
from p24_foundation.replay import _write_report
from p24_foundation.errors import FoundationError


def main(argv=None):
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--dumps',type=Path,nargs='+',required=True)
    parser.add_argument('--output',type=Path,required=True)
    args=parser.parse_args(argv)
    try:
        if args.output.exists():raise FoundationError('historical_output_exists')
        report=audit(args.dumps)
        _write_report(args.output,report,create=True)
        print(json.dumps({key:report[key] for key in ['status','input_records','raw_request_ids','cross_window_changes','request_summary_counts','elapsed_seconds','database_used']}))
        return 0
    except FoundationError as error:
        print(json.dumps(dict(status='FAIL',error=error.code)));return 2
    except Exception:
        print(json.dumps(dict(status='FAIL',error='historical_replay_failed')));return 2


if __name__=='__main__':raise SystemExit(main())
