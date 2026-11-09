"""Run only Viewer regressions and write compact, source-pinned evidence."""
from __future__ import annotations
import argparse
import contextlib
from datetime import datetime,timezone
import hashlib
import importlib.metadata
import io
import json
from pathlib import Path
import platform
import sys
import time
import unittest
ROOT=Path(__file__).resolve().parents[1];sys.path.insert(0,str(ROOT))


def fingerprints():
    return {p.relative_to(ROOT).as_posix():hashlib.sha256(p.read_bytes()).hexdigest()
        for folder in ('p24_foundation','tools','tests','review_ui','catalogs')
        for p in sorted((ROOT/folder).rglob('*'))
        if p.is_file() and p.suffix in ('.py','.html','.css','.js','.json','.csv') and '__pycache__' not in p.parts}


def main(argv=None):
    ap=argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--out',type=Path,default=ROOT/'validation/viewer_tests.json')
    args=ap.parse_args(argv);began=time.monotonic();before=fingerprints()
    suite=unittest.defaultTestLoader.discover(str(ROOT/'tests'),pattern='test_viewer*.py',top_level_dir=str(ROOT))
    # Regression modules print their own synthetic results; keep verbose output
    # in one local log, not the human-facing summary or acceptance counts.
    log=io.StringIO()
    with contextlib.redirect_stdout(log),contextlib.redirect_stderr(log):
        result=unittest.TextTestRunner(stream=log,verbosity=2).run(suite)
    report=dict(status='PASS' if result.wasSuccessful() and before==fingerprints() else 'FAIL',
       tests=result.testsRun,passed=result.testsRun-len(result.failures)-len(result.errors)-len(result.skipped),
       failures=len(result.failures),errors=len(result.errors),skipped=len(result.skipped),
       failure_ids=[t.id() for t,_ in result.failures],error_ids=[t.id() for t,_ in result.errors],
       skip_details=[dict(id=t.id(),reason=reason) for t,reason in result.skipped],
       elapsed_seconds=round(time.monotonic()-began,3),python=platform.python_version(),platform=platform.system(),
       executed_at_utc=datetime.now(timezone.utc).isoformat(),mode='viewer_offline_regressions',
       dependencies={p:importlib.metadata.version(p) for p in ('Flask','psycopg','cryptography')},
       native_owner_postgresql='NOT_RUN',live_elasticsearch='NOT_RUN',source_sha256=before)
    args.out.parent.mkdir(parents=True,exist_ok=True)
    args.out.write_text(json.dumps(report,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
    args.out.with_suffix('.log').write_text(log.getvalue(),encoding='utf-8')
    print(json.dumps({k:report[k] for k in ('status','tests','passed','failures','errors','skipped','elapsed_seconds')}))
    return 0 if report['status']=='PASS' else 2

if __name__=='__main__':raise SystemExit(main())
