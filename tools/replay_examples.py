"""Finite safe fixture replay; explicit isolated config, no source deletion."""
from pathlib import Path
import argparse,json,sys
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))
from p24_foundation.config import read_config,connect
from p24_foundation.errors import FoundationError
from p24_foundation.intake import read_batch
from p24_foundation.privacy import Keys
from p24_foundation.store import FoundationStore,initialize

def main():
    parser=argparse.ArgumentParser();parser.add_argument('--config',type=Path,required=True);args=parser.parse_args()
    try:
        config=read_config(args.config)
        with connect(config['database']) as c:
            initialize(c)
            store=FoundationStore(c,Keys.read(config['keys_path']),config['namespace'],config['vault_path'])
            sources=[]
            for filename in ('ip_activity.sanitized.json','session_activity.sanitized.json','registration.sanitized.json','boundary.sanitized.json'):
                sources.append(store.ingest(read_batch(ROOT/'fixtures'/filename),source_key='example:'+filename,interval_start='2026-10-20T07:25:00Z',interval_end='2026-10-20T07:45:00Z'))
            run=store.project([s['snapshot_id'] for s in sources],event_cutoff='2026-10-20T07:40:00Z',knowledge_at='2026-10-20T07:45:00Z',mode='design_fixture')
            if (run['distinct_client_requests'],run['selected_request_events'])!=(13,53):raise FoundationError('example_replay_count_mismatch')
            print(json.dumps(dict(ok=True,run=run,scope='Sanitized examples only; fixture mode ignores physical receipt date; no detector/throughput/production gate'),ensure_ascii=False,indent=2))
        return 0
    except FoundationError as error:
        print(json.dumps(dict(ok=False,error=error.code)),file=sys.stderr);return 2
    except Exception:
        print(json.dumps(dict(ok=False,error='operation_failed')),file=sys.stderr);return 2
if __name__=='__main__':raise SystemExit(main())
