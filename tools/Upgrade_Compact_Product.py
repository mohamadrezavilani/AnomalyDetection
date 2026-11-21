"""Upgrade the existing compact product to an explicitly pinned package; preserve history task.
Run from the existing virtualenv as Windows Administrator. No initial-install reset.
"""
import argparse
import ctypes
import json
import os
from pathlib import Path
import subprocess
import sys
import time

sys.dont_write_bytecode = True
EXPECTED = None


def run_old(root, code, project):
    result = subprocess.run([sys.executable, '-X', 'utf8', '-B', '-c', code, str(project)],
                            cwd=root, capture_output=True, text=True, encoding='utf-8', timeout=240)
    if result.returncode:
        raise RuntimeError('PREVIOUS_RELEASE_COMMAND_FAILED')
    return json.loads(result.stdout)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--project', type=Path, required=True)
    parser.add_argument('--code-root', type=Path, required=True)
    parser.add_argument('--old-code-root', type=Path, required=True)
    parser.add_argument('--expected-source-sha', required=True)
    args = parser.parse_args()
    global EXPECTED
    EXPECTED = args.expected_source_sha
    if os.name != 'nt' or not ctypes.windll.shell32.IsUserAnAdmin():
        raise RuntimeError('WINDOWS_ADMINISTRATOR_REQUIRED')
    project, root, old = (p.resolve() for p in (args.project, args.code_root, args.old_code_root))
    if root == old:
        raise RuntimeError('SEPARATE_NEW_RELEASE_REQUIRED')
    sys.path.insert(0, str(root))
    from compact_product.version import verify
    from compact_product.runtime import status, start, stop, ROLES
    from compact_product.operations import task, wait_for_supervisor, probe
    from compact_product.config import load
    from compact_product.history import progress
    from compact_behavior.store import Store
    from viewer_performance.Diagnose_Three_Modes import controller_lock
    package = verify(root)
    if package['source_sha256'] != EXPECTED:
        raise RuntimeError('PINNED_RELEASE_HASH_MISMATCH')
    old_package = run_old(old, 'import json;from compact_product.version import verify;print(json.dumps(verify()))', project)
    cfg, source, stream = load(project)
    folder = project / 'AnomalyDetection' / 'reports'
    folder.mkdir(parents=True, exist_ok=True)
    output = folder / ('Compact_Upgrade_' + time.strftime('%Y%m%d_%H%M%S') + '.json')
    result = dict(status='PREPARING', code_root=str(root), previous_code_root=str(old),
                  package=package, history_task_changed=False, data_reset=False)

    def save():
        output.write_text(json.dumps(result, ensure_ascii=False, indent=2, default=str), encoding='utf-8')

    def checkpoint():
        db = Store(source['DATABASE'], schema=cfg.source_schema, application='upgrade-check')
        try:
            db.conn.execute('SET default_transaction_read_only=on')
            cursor = db.cursor(stream)
            job = db.conn.execute(f'SELECT job_id,next_ns FROM {cfg.source_schema}.history_jobs WHERE stream_id=%s ORDER BY created_at_ns DESC LIMIT 1', (stream,)).fetchone()
            return dict(input_next_ns=cursor, history=job)
        finally:
            db.close()

    with controller_lock(project):
        before = status(project)
        if not all(before.get(r, {}).get('running') for r in (*ROLES, 'supervisor')):
            raise RuntimeError('EXISTING_CORE_ROLES_MUST_BE_RUNNING')
        if not all(before[r].get('package', {}).get('source_sha256') == old_package['source_sha256'] for r in (*ROLES, 'supervisor')):
            raise RuntimeError('PREVIOUS_RELEASE_DOES_NOT_MATCH_RUNNING_ROLES')
        result['before'] = checkpoint()
        save()
        stopping = False
        try:
            # Validate task ownership before affecting workers. History has a separate task.
            task(project, 'disable')
            stopping = True
            stop(project, timeout=180)
            task(project, 'stop')
            start(project)  # ingestion, analysis, web; supervisor registered after verification
            probe(cfg)
            task(project, 'register')
            wait_for_supervisor(project)
            current = status(project)
            if not all(current[r].get('package', {}).get('source_sha256') == EXPECTED for r in (*ROLES, 'supervisor')):
                raise RuntimeError('NEW_ROLE_PACKAGE_MISMATCH')
            # Check both navigation destinations, not only the liveness endpoint.
            from urllib.request import urlopen
            for port in cfg.web_ports:
                for path in ('/status', '/incidents'):
                    with urlopen(f'http://127.0.0.1:{port}{path}', timeout=8) as response:
                        if response.status != 200:
                            raise RuntimeError('WEB_PAGE_NOT_READY')
            result['after'] = checkpoint()
            if result['after']['input_next_ns'] < result['before']['input_next_ns']:
                raise RuntimeError('INPUT_CHECKPOINT_REWOUND')
            previous = result['before']['history']
            after = result['after']['history']
            if previous and (not after or previous['job_id'] != after['job_id'] or after['next_ns'] < previous['next_ns']):
                raise RuntimeError('HISTORY_CHECKPOINT_CHANGED_OR_REWOUND')
            result['roles'] = current
            result['status'] = 'COMPACT_UPGRADED_HISTORY_PRESERVED'
        except BaseException as exc:
            result['failure'] = dict(type=type(exc).__name__, code=str(exc) if isinstance(exc, RuntimeError) else None)
            result['status'] = 'COMPACT_UPGRADE_FAILED'
            save()
            if stopping:
                try:
                    task(project, 'disable')
                    stop(project, timeout=180)
                    task(project, 'stop')
                    code = ('import json,sys;from pathlib import Path;'
                            'from compact_product.runtime import start;'
                            'from compact_product.operations import task,wait_for_supervisor,probe;'
                            'from compact_product.config import load;'
                            'p=Path(sys.argv[1]);start(p);task(p,"register");'
                            'wait_for_supervisor(p);probe(load(p)[0]);print(json.dumps({"restored":True}))')
                    result['restore'] = run_old(old, code, project)
                    result['status'] = 'COMPACT_UPGRADE_FAILED_PREVIOUS_RELEASE_RESTORED'
                except BaseException as restore_error:
                    result['restore_failure'] = type(restore_error).__name__
                    result['status'] = 'COMPACT_UPGRADE_RESTORE_NEEDS_ATTENTION'
            save()
            print(json.dumps(dict(status=result['status'], output=str(output), failure=result.get('failure'), restore_failure=result.get('restore_failure'))), flush=True)
            return 2
        save()
        print(json.dumps(dict(status=result['status'], output=str(output), data_reset=False, history_task_changed=False)), flush=True)
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
