"""Explicit server trial of the reviewed C2/C3 writer; resume existing cursors."""
import argparse
import json
from pathlib import Path
import sys


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--project-root', type=Path, default=Path(__file__).resolve().parents[1])
    parser.add_argument('--trial', action='store_true', help='Explicitly select the reviewed writer trial')
    args = parser.parse_args(argv)
    root = args.project_root.resolve()
    try:
        if not args.trial:
            raise ValueError('fast_writer_requires_explicit_trial')
        if root != Path(__file__).resolve().parents[1]:
            raise ValueError('fast_writer_run_from_this_installation')
        sys.path.insert(0, str(root))
        from tools.check_viewer_install import verify_release
        from viewer_performance.fast_writer import BUILD, BASE_RUNTIME, activate, verify_sources
        source = verify_sources(root)
        if verify_release(root)['status'] != 'PASS':
            raise ValueError('fast_writer_base_installation_mismatch')
        print(json.dumps(dict(status='VIEWER_FAST_TRIAL_STARTING', build_id=BUILD,
            implementation_source_sha256=source, canonical_runtime_source_sha256=BASE_RUNTIME,
            checkpoint_seek_performed=False, history_scope_changed=False,
            evidence_deleted=False, schema_migration=False, parallel_readers=0,
            acceptance='PENDING_OWNER_CAPACITY_TRIAL')), flush=True)
        from viewer_performance.Run_Viewer_Catchup import main as catchup
        # No date/skip/reset options are exposed. The existing replay cursor
        # and concurrent AD prefix/priority rules remain authoritative.
        with activate():
            return catchup(['--project-root', str(root), '--with-anomaly'])
    except KeyboardInterrupt:
        return 130
    except SystemExit:
        print(json.dumps(dict(status='VIEWER_FAST_TRIAL_RELEASE_CHANGED',
            code='FAST_WRITER_SOURCE_FENCE_STOPPED_RECONNECTS')), flush=True)
        return 2
    except Exception as exc:
        print(json.dumps(dict(status='VIEWER_FAST_TRIAL_BLOCKED', error_type=type(exc).__name__,
            code=str(exc) if isinstance(exc, ValueError) else None,
            sqlstate=getattr(exc, 'sqlstate', None))), flush=True)
        return 2


if __name__ == '__main__':
    raise SystemExit(main())
