"""Run a verified reporter checkout against an existing, unchanged installation.

Use the existing application Python. No install, start/stop, DDL, ACL change,
Viewer initialization, model evaluation or application-source replacement.
Only the selected installation's reports directory receives evidence ZIPs.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import runpy
import sys


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--project', required=True, type=Path)
    parser.add_argument('--seconds', type=int, choices=range(91), default=60, metavar='0..90')
    args = parser.parse_args()
    reporter = Path(__file__).resolve().parent
    target = args.project.resolve() / 'AnomalyDetection'
    try:
        if not (target / 'run_anomaly.py').is_file() or not (target / 'RELEASE_MANIFEST.json').is_file():
            print(json.dumps({'status':'REPORT_TARGET_NOT_FOUND'}))
            return 1
        launcher = runpy.run_path(str(reporter / 'run_anomaly.py'))
        sha = launcher['verify_build']()
        sys.path.insert(0, str(reporter))
        sys.meta_path.insert(0, launcher['VerifiedApplicationFinder']())
        from anomaly_detection import BUILD_ID
        from anomaly_detection.acceptance_report import collect
        value = collect(target, sha, seconds=args.seconds)
        value.update(collector_build_id=BUILD_ID, collector_source_sha256=sha,
                     installation_source_modified=False, database_modified=False)
        print(json.dumps(value, ensure_ascii=False, indent=2))
        return 0 if value['status']=='EVIDENCE_BUNDLE_EXPORTED' else 2
    except Exception as exc:
        # Exception messages, absolute paths, SQL and credentials stay private.
        print(json.dumps({'status':'READ_ONLY_REPORT_FAILED','error_type':type(exc).__name__,
                          'errno':getattr(exc,'errno',None),'winerror':getattr(exc,'winerror',None),
                          'installation_source_modified':False,'database_modified':False}))
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
