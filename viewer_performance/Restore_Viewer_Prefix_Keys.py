"""Restore R3.7 evidence indexes before an explicit code downgrade."""
from pathlib import Path
import argparse
import json
import sys


def main(argv=None):
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--restore',action='store_true',required=True)
    parser.parse_args(argv)
    root=Path(__file__).resolve().parents[1];sys.path.insert(0,str(root))
    from viewer_performance.Run_Viewer_Web import existing_options
    from p24_foundation.viewer_data import ViewerDB
    from p24_foundation.viewer_online import single_worker
    from p24_foundation.viewer_prefix_storage import restore
    with ViewerDB(**existing_options(root)) as db:
        db.progress_callback=lambda value:print(json.dumps({'progress':value}),flush=True)
        with single_worker(db,root/'private/viewer_captures/viewer_worker.lock'):
            restore(db)
    print(json.dumps({'status':'PREFIX_INDEXES_RESTORED','evidence_deleted':False,'checkpoint_modified':False}))
    return 0


if __name__=='__main__':raise SystemExit(main())
