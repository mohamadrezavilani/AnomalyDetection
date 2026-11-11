"""Explicit data-preserving storage rollback before downgrading Viewer code."""
from pathlib import Path
import argparse
import json
import sys


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--restore', action='store_true', required=True)
    args = parser.parse_args(argv)
    root = Path(__file__).resolve().parents[1]
    sys.path.insert(0, str(root))
    from viewer_performance.Run_Viewer_Web import existing_options
    from p24_foundation.viewer_data import ViewerDB
    from p24_foundation.viewer_storage_keys import restore_original_keys
    with ViewerDB(**existing_options(root)) as db:
        db.progress_callback = lambda event: print(json.dumps({'progress': event}), flush=True)
        restore_original_keys(db)
    print(json.dumps({'status': 'ORIGINAL_FULL_KEYS_RESTORED', 'evidence_deleted': False, 'checkpoint_modified': False}))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
