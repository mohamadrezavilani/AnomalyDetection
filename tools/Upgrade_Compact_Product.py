"""Pinned sequential upgrade; drain leases AND processes before any rollback.

History must be paused by Upgrade_Compact_Context. Old/new product packages
are imported in separate interpreters. No process termination or data reset.
"""
import argparse
import json
from pathlib import Path
import re
import subprocess
import sys
import time

sys.dont_write_bytecode = True
CORE = ('web', 'ingest', 'analysis', 'supervisor')


def failure(exc):
    code = str(exc)
    safe = isinstance(exc, (ValueError, RuntimeError, TimeoutError)) and re.fullmatch(r'[A-Za-z0-9_:,.-]{1,240}', code)
    return dict(type=type(exc).__name__, code=code if safe else None, sqlstate=getattr(exc, 'sqlstate', None))


def read_package(root):
    value = subprocess.run([sys.executable, '-X', 'utf8', '-B', '-m', 'compact_product', 'version'],
                           cwd=root, capture_output=True, text=True, encoding='utf-8', timeout=30)
    if value.returncode or len(value.stdout) > 65536:
        raise ValueError('PREVIOUS_PACKAGE_VERIFICATION_FAILED')
    return json.loads(value.stdout)


def quiesce(host, expected, emit, *, clock=time.monotonic, sleep=time.sleep, timeout=180):
    from tools.Recover_Compact_Product import require, validate_roles
    deadline = clock() + timeout
    host.supervision_enabled = False
    host.task('core', 'disable')
    while True:
        roles = host.roles()
        validate_roles(roles, expected)
        require(not roles.get('history', {}).get('running'), 'STOP_HISTORY_BEFORE_CORE_UPGRADE')
        try:
            host.stop_core()
            require(not any(host.roles().get(r, {}).get('running') for r in CORE), 'CORE_STOP_PENDING')
            host.guard(expected)
            host.check_children()
            return
        except (TimeoutError, ValueError) as exc:
            retry = str(exc).startswith(('UNLEASED_COMPACT_PROCESSES:', 'COMPACT_STOP_PENDING',
                'CORE_STOP_PENDING', 'SUPERVISOR_TASK_NOT_QUIESCENT', 'OWNED_CHILD_STILL_STARTING'))
            if not retry:
                raise
            if clock() >= deadline:
                raise TimeoutError('CORE_PROCESSES_NOT_DRAINED_NO_ROLLBACK_STARTED') from None
            emit('WAITING_FOR_OWNED_PROCESSES_TO_EXIT')
            sleep(2)


def start_core(host, expected, emit):
    from tools.Recover_Compact_Product import require, validate_roles, ready
    for role in ('web', 'ingest', 'analysis'):
        emit('STARTING_' + role.upper())
        host.guard(expected)
        require(not host.roles().get('supervisor', {}).get('running'), 'SUPERVISOR_REAPPEARED_DURING_UPGRADE')
        host.start(role)
        host.wait(role, expected)
    emit('CHECKING_WEB_AND_CATALOG')
    host.probe()
    host.catalog()
    emit('STARTING_SUPERVISOR')
    host.task('core', 'register')
    host.wait('supervisor', expected)
    roles = host.roles()
    validate_roles(roles, expected)
    require(all(ready(roles.get(r, {})) for r in CORE), 'CORE_READINESS_NOT_CONFIRMED')


def upgrade_core(host, previous, candidate, restore, emit, diagnose):
    from tools.Recover_Compact_Product import require, validate_roles, preserved, ready
    result = dict(status='PREPARING', data_reset=False, history_task_changed=False)
    changed = False
    try:
        emit('CHECKING_EXISTING_ROLES_AND_CHECKPOINTS')
        roles = host.roles()
        validate_roles(roles, previous)
        require(all(ready(roles.get(r, {})) for r in CORE), 'EXISTING_CORE_ROLES_MUST_BE_HEALTHY')
        require(not roles.get('history', {}).get('running'), 'STOP_HISTORY_BEFORE_CORE_UPGRADE')
        result['before'] = host.checkpoint()
        host.supervision_enabled = True
        host.guard(previous)
        changed = True
        emit('STOPPING_PREVIOUS_CORE')
        quiesce(host, previous, emit)
        start_core(host, candidate, emit)
        result['after'] = host.checkpoint()
        preserved(result['before'], result['after'])
        result['roles'] = host.roles()
        result['status'] = 'COMPACT_UPGRADED_HISTORY_PRESERVED'
    except BaseException as exc:
        result.update(status='COMPACT_UPGRADE_FAILED', failure=failure(exc))
        try:
            diagnose(result)
        except Exception as diagnostic_exc:
            result['diagnostic_failure'] = failure(diagnostic_exc)
        if changed:
            try:
                emit('DRAINING_BEFORE_PREVIOUS_RELEASE_RESTORE')
                packages = {v.get('package', {}).get('source_sha256') for v in host.roles().values() if v.get('running')}
                require(packages <= {previous, candidate} and len(packages) <= 1, 'MIXED_ROLES_BLOCK_RESTORE')
                quiesce(host, next(iter(packages), candidate), emit)
                result['restore'] = restore(result['before'])
                result['status'] = 'COMPACT_UPGRADE_FAILED_PREVIOUS_RELEASE_RESTORED'
            except BaseException as restore_exc:
                result.update(status='COMPACT_UPGRADE_RESTORE_NEEDS_ATTENTION', restore_failure=failure(restore_exc))
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('project', 'code-root', 'old-code-root'):
        parser.add_argument('--' + name, type=Path, required=True)
    parser.add_argument('--expected-source-sha', required=True)
    parser.add_argument('--action', choices=('upgrade', 'restore-core', 'resume-history', 'preflight'), default='upgrade')
    parser.add_argument('--baseline', type=Path)
    args = parser.parse_args()
    project, root, old = (p.resolve() for p in (args.project, args.code_root, args.old_code_root))
    sys.path.insert(0, str(root))
    # Old releases predate the helper. Load this tool's sibling, while all
    # product imports still come exclusively from the pinned code-root.
    import importlib.util
    spec = importlib.util.spec_from_file_location('tools.Recover_Compact_Product', Path(__file__).with_name('Recover_Compact_Product.py'))
    helper = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = helper
    spec.loader.exec_module(helper)
    from compact_product.operations import require_windows_admin
    from compact_product.version import verify
    from compact_product.runtime import stop, _children
    from viewer_performance.Diagnose_Three_Modes import controller_lock

    class Host(helper.WindowsHost):
        def stop_core(self):
            stop(project, timeout=15)
        def check_children(self):
            helper.require(not any(c.poll() is None for c in _children.values()), 'OWNED_CHILD_STILL_STARTING')
        def catalog(self):
            from compact_product.error_catalog import CATALOG_VERSION, CATALOG_ROW_COUNT
            db = self.database()
            try:
                count = db.conn.execute(f'SELECT count(*) AS n FROM {self.cfg.source_schema}.error_code_definitions WHERE version=%s', (CATALOG_VERSION,)).fetchone()['n']
                helper.require(count == CATALOG_ROW_COUNT, 'ERROR_CATALOG_IMPORT_NOT_CONFIRMED')
            finally:
                db.close()

    output = project / 'AnomalyDetection/reports' / ('Compact_Upgrade_' + time.strftime('%Y%m%d_%H%M%S') + '_' + args.action + '.json')
    result = dict(status='PREPARING', code_root=str(root), previous_code_root=str(old), data_reset=False)
    def emit(stage):
        result['stage'] = stage
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(json.dumps(result, indent=2, default=str), encoding='utf-8')
        print(json.dumps(dict(status='COMPACT_UPGRADE_PROGRESS', stage=stage, output=str(output))), flush=True)
    def diagnose(value):
        from compact_product.operations import collect_role_diagnostics
        folder = output.with_suffix('')
        folder.mkdir(parents=True, exist_ok=True)
        value['diagnostic_failures'] = collect_role_diagnostics(project, folder)
        value['diagnostics'] = str(folder)
        result.update(value)
        emit('ORIGINAL_FAILURE_SAVED')
    try:
        emit('VERIFYING_PINNED_PACKAGE')
        require_windows_admin()
        package = verify(root)
        helper.require(package['source_sha256'] == args.expected_source_sha, 'PINNED_RELEASE_HASH_MISMATCH')
        host = Host(project, allowed_core_task_roots=(old,))
        if args.action == 'preflight':
            host.checkpoint()
            result['status'] = 'COMPACT_UPGRADE_PACKAGE_AND_DATABASE_VERIFIED'
        elif args.action == 'resume-history':
            host.supervision_enabled = True
            host.guard(args.expected_source_sha)
            roles = host.roles()
            helper.require(all(helper.ready(roles.get(r, {})) for r in CORE), 'OLD_CORE_NOT_HEALTHY_HISTORY_NOT_RESUMED')
            before = host.checkpoint()
            if before['history']['state'] != 'COMPLETE':
                host.task('history', 'register')
                host.wait('history', args.expected_source_sha)
            helper.preserved(before, host.checkpoint())
            result['status'] = 'COMPACT_PREVIOUS_HISTORY_RESUMED'
        elif args.action == 'restore-core':
            baseline = json.loads(args.baseline.read_text(encoding='utf-8'))
            helper.preserved(baseline, host.checkpoint())
            helper.require(not any(v.get('running') for v in host.roles().values()), 'RESTORE_REQUIRES_DRAINED_ROLES')
            start_core(host, args.expected_source_sha, emit)
            helper.preserved(baseline, host.checkpoint())
            result['status'] = 'COMPACT_PREVIOUS_CORE_RESTORED'
        else:
            helper.require(root != old, 'SEPARATE_NEW_RELEASE_REQUIRED')
            previous = read_package(old)
            result['package'] = package
            def restore(baseline):
                path = output.with_suffix('.baseline.json')
                path.write_text(json.dumps(baseline), encoding='utf-8')
                # Explicitly load this controller's transport too, not the old tool.
                transport_spec = importlib.util.spec_from_file_location('compact_upgrade_transport', Path(__file__).with_name('Upgrade_Compact_Context.py'))
                transport = importlib.util.module_from_spec(transport_spec)
                transport_spec.loader.exec_module(transport)
                code, restored = transport.run([Path(__file__).resolve(), '--action', 'restore-core',
                    '--project', project, '--code-root', old, '--old-code-root', root,
                    '--expected-source-sha', previous['source_sha256'], '--baseline', path], old)
                helper.require(code == 0 and restored.get('status') == 'COMPACT_PREVIOUS_CORE_RESTORED', 'PREVIOUS_RELEASE_RESTORE_FAILED')
                return restored
            with controller_lock(project):
                result.update(upgrade_core(host, previous['source_sha256'], args.expected_source_sha, restore, emit, diagnose))
    except BaseException as exc:
        result.update(status='COMPACT_UPGRADE_FAILED', failure=failure(exc))
    output.write_text(json.dumps(result, indent=2, default=str), encoding='utf-8')
    print(json.dumps(dict(status=result['status'], output=str(output), data_reset=False,
                         failure=result.get('failure'), restore_failure=result.get('restore_failure'))), flush=True)
    return 0 if result['status'] in ('COMPACT_UPGRADED_HISTORY_PRESERVED', 'COMPACT_PREVIOUS_CORE_RESTORED',
        'COMPACT_PREVIOUS_HISTORY_RESUMED', 'COMPACT_UPGRADE_PACKAGE_AND_DATABASE_VERIFIED') else 2


if __name__ == '__main__':
    raise SystemExit(main())
