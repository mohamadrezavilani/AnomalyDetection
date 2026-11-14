"""Restore original origin/version conflict targets before a Viewer downgrade."""
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
    from p24_foundation.viewer_origin_storage import restore_original_keys
    with ViewerDB(**existing_options(root)) as db:
        db.progress_callback=lambda value:print(json.dumps({'progress':value}),flush=True)
        restore_original_keys(db)
    print(json.dumps({'status':'ORIGINAL_ORIGIN_KEYS_RESTORED','evidence_deleted':False,'checkpoint_modified':False}))
    return 0


if __name__=='__main__':raise SystemExit(main())
