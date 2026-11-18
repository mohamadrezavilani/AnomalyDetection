"""Stop only the live session of a receipt-proven isolated benchmark copy.

Download outside the checkout and run with the base Python, from the project
working directory, using a relative --run-directory under AD reports. A
project-venv/absolute-project command line would trip the exclusive host gate.
No source checkout, product connection, scope change, DROP or worker control
is performed. The existing controller must do cleanup and verified restore;
its receipts must be reviewed afterward. This is not a successful benchmark.
"""
import argparse
import json
import os
from pathlib import Path
import sys
import time
import uuid


def read_json(path):
    if path.stat().st_size > 4*1024**2:
        raise ValueError('STOP_RECEIPT_BYTE_BUDGET_EXCEEDED')
    return json.loads(path.read_text(encoding='utf-8-sig'))


def request_stop(admin, directory, *, expected_source):
    from viewer_performance.behavior_resources import CopyOwner
    directory = Path(directory)
    release = read_json(directory/'release.json')
    if release.get('status') == 'PREVIOUS_ROLES_RESTORED':
        return dict(status='NO_STOP_NEEDED_PREVIOUS_ROLES_ALREADY_RESTORED')
    if (release.get('status') != 'PREPARED_FOR_MAIN_UPDATE'
            or release.get('scope_command') or not release.get('stopping_started')
            or 'frozen_cursors' not in release):
        raise ValueError('STOP_REFUSED_NOT_IN_FROZEN_BENCHMARK_PHASE')
    allocations = read_json(directory/'allocations.json')
    CopyOwner.validate(allocations)
    if allocations.get('source') != expected_source:
        raise ValueError('STOP_REFUSED_SOURCE_RECEIPT_MISMATCH')
    owned = [a for a in allocations['allocations'] if a.get('state') == 'OWNED']
    if len(owned) != 1 or any(a.get('state') not in ('OWNED', 'DROPPED') for a in allocations['allocations']):
        raise ValueError('STOP_REFUSED_COPY_OR_CLEANUP_PHASE')
    selected = owned[0]
    database = admin.execute("""SELECT oid, shobj_description(oid,'pg_database') AS tag,
        pg_get_userbyid(datdba)=current_user AS owned_by_operator
        FROM pg_database WHERE datname=%s""", (selected['name'],)).fetchone()
    if (not database or database['oid'] != selected.get('oid')
            or database['tag'] != 'P24.BehaviorBenchmark:'+allocations['run_id']
            or not database['owned_by_operator']):
        raise ValueError('STOP_REFUSED_COPY_OWNERSHIP_NOT_PROVEN')
    control = admin.execute("""SELECT pid FROM pg_stat_activity WHERE pid<>pg_backend_pid()
        AND datname='postgres' AND usename=current_user
        AND application_name='P24.BehaviorBenchmark.Control'
        AND backend_type='client backend'""").fetchall()
    if len(control) != 1:
        raise ValueError('STOP_REFUSED_ORIGINAL_CONTROLLER_NOT_UNIQUE_OR_ALIVE')
    sessions = admin.execute("""SELECT pid,backend_start,application_name,backend_type,
        usename=current_user AS owned_by_operator FROM pg_stat_activity WHERE datid=%s""",
        (database['oid'],)).fetchall()
    if (len(sessions) != 1 or sessions[0]['application_name'] != 'P24.FinancialScreen.A'
            or sessions[0]['backend_type'] != 'client backend' or not sessions[0]['owned_by_operator']):
        raise ValueError('STOP_REFUSED_UNEXPECTED_COPY_SESSIONS')
    if read_json(directory/'release.json') != release or read_json(directory/'allocations.json') != allocations:
        raise ValueError('STOP_REFUSED_RECEIPTS_CHANGED')
    session = sessions[0]
    note = dict(status='VERIFIED_ISOLATED_COPY_STOP_REQUEST', at_ns=time.time_ns(),
                run_id=allocations['run_id'], database=selected['name'], oid=database['oid'],
                pid=session['pid'], backend_start=session['backend_start'].isoformat(),
                product_database_connected=False, product_data_modified=False,
                controller_terminated=False, workers_manually_started=False)
    output = directory/('benchmark-stop-'+uuid.uuid4().hex[:12]+'.json')
    with output.open('x', encoding='utf-8') as stream:
        json.dump(note, stream, ensure_ascii=True, indent=2)
        stream.flush()
        os.fsync(stream.fileno())
    # Recheck the database OID/tag and session identity in the signaling query.
    # Never terminate the control connection, a guessed PID or a product client.
    stopped = admin.execute("""SELECT pg_terminate_backend(a.pid,5000) AS stopped
        FROM pg_stat_activity a JOIN pg_database d ON d.oid=a.datid
        WHERE a.pid=%s AND a.backend_start=%s AND a.datid=%s AND d.datname=%s
        AND shobj_description(d.oid,'pg_database')=%s AND pg_get_userbyid(d.datdba)=current_user
        AND a.application_name='P24.FinancialScreen.A' AND a.usename=current_user
        AND a.backend_type='client backend'""",
        (session['pid'], session['backend_start'], database['oid'], selected['name'], database['tag'])).fetchall()
    if stopped != [dict(stopped=True)]:
        raise ValueError('STOP_NOT_CONFIRMED_SEND_STOP_RECEIPT')
    return dict(status='ISOLATED_COPY_STOPPED_AWAIT_ORIGINAL_CONTROLLER_RESTORE', output=str(output),
                product_database_connected=False, product_data_modified=False)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--run-directory', required=True, type=Path)
    args = parser.parse_args()
    project = Path.cwd().resolve()
    directory = (project/args.run_directory).resolve()
    try:
        if args.run_directory.is_absolute() or not directory.is_relative_to(project/'AnomalyDetection/reports'):
            raise ValueError('RELATIVE_PRIVATE_RUN_DIRECTORY_REQUIRED')
        sys.path[:0] = [str(project), str(project/'.venv/Lib/site-packages')]
        from tools.check_viewer_install import verify_release
        from viewer_performance.Qualify_Capacity_Candidate import literal_database
        if verify_release(project)['status'] != 'PASS':
            raise ValueError('INSTALLED_SOURCE_MANIFEST_MISMATCH')
        import psycopg
        from psycopg.rows import dict_row
        cfg = literal_database(project)
        params = {k: cfg[k] for k in ('host', 'port', 'user', 'password') if k in cfg}
        with psycopg.connect(**params, dbname='postgres', connect_timeout=5, autocommit=True,
                row_factory=dict_row, application_name='IsolatedBenchmarkStop',
                options='-c statement_timeout=10000 -c lock_timeout=1000') as admin:
            result = request_stop(admin, directory, expected_source=cfg['dbname'])
        print(json.dumps(result, ensure_ascii=True), flush=True)
        return 0
    except Exception as exc:
        print(json.dumps(dict(status='BENCHMARK_STOP_NOT_CONFIRMED', error_type=type(exc).__name__,
            code=str(exc) if isinstance(exc, ValueError) else None, sqlstate=getattr(exc,'sqlstate',None))), flush=True)
        return 2


if __name__ == '__main__':
    raise SystemExit(main())
