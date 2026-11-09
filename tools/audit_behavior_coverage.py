"""Read-only classification coverage over all indexed Viewer requests.

Windows PowerShell:
 python .\tools\audit_behavior_coverage.py --config .\viewer_config.local.py --top 40

Never prints raw logs, sessions, payment identifiers, secrets or user targets.
"""
from __future__ import annotations
import argparse
import importlib.util
import json
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from p24_foundation.viewer_data import ViewerDB


def viewer_options(path):
    if not path.is_file():
        raise ValueError('config_missing')
    spec = importlib.util.spec_from_file_location('private_coverage_config',path.resolve())
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    key = Path(mod.KEYS_PATH).expanduser().resolve()
    if getattr(mod,'SQLITE_OFFLINE_PATH',None):
        return dict(sqlite_path=Path(mod.SQLITE_OFFLINE_PATH),keys_path=key)
    config = dict(mod.DATABASE)
    if not str(config.get('dbname','')).startswith('p24_design_'):
        raise ValueError('isolated_viewer_database_required')
    return dict(config=config,keys_path=key)


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--config',type=Path,required=True)
    parser.add_argument('--top',type=int,default=30)
    args=parser.parse_args()
    try:
        opts=viewer_options(args.config)
        with ViewerDB(**opts) as db:
            result=db.behavior_coverage(top=args.top)
        print(json.dumps(result,ensure_ascii=False,indent=2))
    except (ValueError, OSError):
        print('Coverage audit failed: check isolated Viewer config and input.',file=sys.stderr)
        raise SystemExit(2) from None

if __name__=='__main__':
    main()
