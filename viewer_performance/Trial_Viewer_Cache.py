"""One reversible 12 GiB cache trial on the owner's existing Windows server.

Run outside the checkout using its venv Python from the checkout directory.
Uses an already-restored release receipt for the known launch commands/tasks.
No copy, evidence deletion, reindex, model execution, source edit or cursor seek.
Cancels an unfinished publication before stopping its verified writer; its
transaction rolls back and the same durable checkpoint is retried on restart.
Actual capacity is NOT accepted by changing a setting or restoring processes.
"""
import argparse
import ctypes
import hashlib
from datetime import datetime,timezone
import json
import ntpath
import os
from pathlib import Path
import sys
import time
import uuid

GIB=1024**3
TARGETS={'shared_buffers':'12GB','track_io_timing':'on','track_wal_io_timing':'on'}
PROCESS_SNAPSHOT_PS=r'''@((Get-CimInstance Win32_Process) | ForEach-Object {
    [pscustomobject]@{pid=[long]$_.ProcessId;parent_pid=[long]$_.ParentProcessId;
        created_ticks=$(if($_.CreationDate){[long]$_.CreationDate.ToUniversalTime().Ticks}else{$null});
        image=$_.ExecutablePath}
})'''


class ServiceBindingError(ValueError):
    def __init__(self,code,details):super().__init__(code);self.details=details


def service_owner(snapshot,backend_pid,*,backend_images=('postgres.exe',)):
    """Bind the live SQL backend to the service by native process ancestry.

    A service's -D argument can name a configuration directory or use another
    Windows spelling of the same directory. Text equality is not ownership.
    The live SQL PID and creation-ordered CIM ancestry identify the service
    without exporting command lines or trusting a guessed path/PID.
    """
    service=snapshot.get('service') or {}
    details=dict(service_name=service.get('Name'),service_state=service.get('State'),
                 service_pid=service.get('ProcessId'),sql_backend_pid=backend_pid,chain=[])
    def fail(code):raise ServiceBindingError(code,details)
    if service.get('Name','').lower()!='postgresql-x64-18' or service.get('State')!='Running':
        fail('POSTGRESQL_18_SERVICE_NOT_RUNNING')
    owner=service.get('ProcessId')
    if type(owner)is not int or owner<=0 or type(backend_pid)is not int or backend_pid<=0:
        fail('SERVICE_OR_SQL_PROCESS_ID_UNAVAILABLE')
    rows=snapshot.get('processes') or []
    if not isinstance(rows,list):fail('WINDOWS_PROCESS_SNAPSHOT_UNAVAILABLE')
    processes={row.get('pid'):row for row in rows}
    if len(processes)!=len(rows):fail('AMBIGUOUS_WINDOWS_PROCESS_SNAPSHOT')
    current=processes.get(backend_pid);seen=set();child_time=None
    if current and current.get('image') and ntpath.basename(current['image']).lower() not in backend_images:
        fail('SQL_BACKEND_PROCESS_IMAGE_DOES_NOT_MATCH_POSTGRES')
    while current and len(seen)<32:
        pid=current['pid'];created=current.get('created_ticks')
        if pid in seen:fail('WINDOWS_PROCESS_ANCESTRY_CYCLE')
        if type(created)is not int or created<=0:fail('WINDOWS_PROCESS_CREATION_TIME_UNAVAILABLE')
        if child_time is not None and created>child_time:fail('WINDOWS_PARENT_PID_WAS_REUSED')
        seen.add(pid);details['chain'].append(dict(pid=pid,created_ticks=created,
            image=ntpath.basename(current.get('image') or '')))
        if pid==owner:return dict(method='LIVE_SQL_BACKEND_NATIVE_SERVICE_ANCESTRY',**details)
        child_time=created;current=processes.get(current.get('parent_pid'))
    fail('POSTGRES_SERVICE_NOT_IN_LIVE_SQL_BACKEND_ANCESTRY')


def service_snapshot(h):
    return h.powershell('''$s=Get-CimInstance Win32_Service -Filter "Name='postgresql-x64-18'"
        if(-not $s){throw 'POSTGRESQL_18_SERVICE_MISSING'}
        $p='''+PROCESS_SNAPSHOT_PS+'''
        [pscustomobject]@{service=($s | Select-Object Name,State,ProcessId);processes=@($p)} |
            ConvertTo-Json -Depth 8 -Compress''')


def require_windows_admin():
    if os.name!='nt' or not ctypes.windll.shell32.IsUserAnAdmin():
        raise ValueError('RUN_IN_ADMINISTRATOR_POWERSHELL_ON_OWNER_WINDOWS')


def memory_guard(memory,before):
    current=int(before['shared_buffers']['setting'])*8192
    target=12*GIB
    if current>=target:raise ValueError('CACHE_ALREADY_AT_LEAST_12_GIB_NO_RESTART_NEEDED')
    if target>int(memory['total_bytes'])*.4:
        raise ValueError('12_GIB_CACHE_REQUIRES_AT_LEAST_30_GIB_RAM')
    if memory['available_bytes']<target-current+4*GIB:
        raise ValueError('CACHE_INCREASE_WOULD_EXHAUST_OS_RESERVE')


def settings_snapshot(admin):
    rows=admin.execute('SELECT name,setting,unit,pending_restart FROM pg_settings WHERE name=ANY(%s)',
                       (list(TARGETS),)).fetchall()
    current={r['name']:dict(r) for r in rows}
    if set(current)!=set(TARGETS):raise ValueError('CACHE_SETTINGS_UNAVAILABLE')
    auto=admin.execute("""SELECT name,setting FROM pg_file_settings
        WHERE replace(sourcefile,chr(92),'/') LIKE '%%/postgresql.auto.conf'
        AND name=ANY(%s) ORDER BY seqno""",(list(TARGETS),)).fetchall()
    return dict(effective=current,auto={r['name']:r['setting'] for r in auto})


def set_parameters(admin,values):
    from psycopg import sql
    if set(values)-set(TARGETS):raise ValueError('UNSUPPORTED_CACHE_PARAMETER')
    for name,value in values.items():
        admin.execute(sql.SQL('ALTER SYSTEM SET {} TO {}').format(sql.Identifier(name),sql.Literal(value)))
    admin.execute('SELECT pg_reload_conf()')


def restore_parameters(admin,snapshot):
    from psycopg import sql
    for name in TARGETS:
        if name in snapshot['auto']:
            admin.execute(sql.SQL('ALTER SYSTEM SET {} TO {}').format(sql.Identifier(name),sql.Literal(snapshot['auto'][name])))
        else:admin.execute(sql.SQL('ALTER SYSTEM RESET {}').format(sql.Identifier(name)))
    admin.execute('SELECT pg_reload_conf()')


def load(path):
    path=Path(path)
    if path.stat().st_size>4*1024**2:raise ValueError('RECEIPT_TOO_LARGE')
    return json.loads(path.read_text(encoding='utf-8-sig'))


def main(argv=None):
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--release-receipt',type=Path)
    parser.add_argument('--rollback',type=Path,help='The cache trial cache.json receipt')
    args=parser.parse_args(argv)
    if bool(args.release_receipt)==bool(args.rollback):parser.error('choose --release-receipt or --rollback')
    project=Path.cwd().resolve();sys.path[:0]=[str(project),str(project/'.venv/Lib/site-packages')]
    state=None;receipt=None;admin=None;h=None;restore=None
    original_settings=None;settings_written=False;stopping=False;service=None
    def save(status=None,**fields):
        if status:state['status']=status
        state.update(fields)
        from p24_foundation.viewer_runtime import atomic_json
        atomic_json(receipt,state)
        print(json.dumps(dict(status=state['status'],output=str(receipt)),ensure_ascii=True),flush=True)
    try:
        require_windows_admin()
        from tools.check_viewer_install import verify_release
        if verify_release(project)['status']!='PASS':raise ValueError('INSTALLED_MANIFEST_MISMATCH')
        from viewer_performance.financial_screen import host as h
        from viewer_performance.Behavior_Release import restore,verify_cursors
        from viewer_performance.Run_Viewer_Memory import memory_info
        from viewer_performance.writer_identity import LEASE_SQL,read_identity
        import psycopg
        from psycopg.rows import dict_row
        prior=load(args.rollback) if args.rollback else None
        old=load(prior['release_receipt'] if prior else args.release_receipt)
        if old['status']!='PREVIOUS_ROLES_RESTORED' or old.get('restore_failures'):
            raise ValueError('PREVIOUS_RELEASE_MUST_HAVE_RESTORED_ITS_ROLES')
        plan=old['before']['restore_plan']
        if plan['viewer_restart']!=['viewer_performance/Run_Viewer_Fast.py','--trial']:
            raise ValueError('KNOWN_RESUMING_FAST_VIEWER_COMMAND_REQUIRED')
        if not all(plan['active'].values()):raise ValueError('THIS_TRIAL_REQUIRES_PREVIOUS_FOUR_ROLE_PLAN')
        cfg=h.parameters(project);cfg['connect_timeout']=5
        if str(cfg.get('host') or 'localhost').lower() not in ('localhost','127.0.0.1','::1'):
            raise ValueError('LOCAL_POSTGRESQL_REQUIRED_FOR_WINDOWS_SERVICE_TRIAL')
        def connect():return psycopg.connect(**cfg,dbname='postgres',autocommit=True,row_factory=dict_row,
            application_name='P24.CacheTrial',options='-c statement_timeout=10000 -c lock_timeout=1000')
        admin=connect()
        original_settings=settings_snapshot(admin)
        memory=memory_info()
        if not prior and int(original_settings['effective']['shared_buffers']['setting'])*8192>=12*GIB:
            print(json.dumps(dict(status='CACHE_ALREADY_AT_LEAST_12_GIB',server_restarted=False,
                capacity_acceptance='NOT_ASSIGNED')),flush=True)
            return 0
        if not prior:memory_guard(memory,original_settings['effective'])
        elif not prior.get('before_settings'):raise ValueError('ROLLBACK_SETTINGS_RECEIPT_REQUIRED')
        directory=admin.execute('SHOW data_directory').fetchone()['data_directory']
        inventory=service_snapshot(h);service=inventory['service']
        binding=service_owner(inventory,admin.info.backend_pid)
        # A still-live command on this exact connection closes the CIM-read
        # race: a PostgreSQL restart cannot silently reassign its SQL PID.
        if admin.execute('SELECT pg_backend_pid() AS pid').fetchone()['pid']!=admin.info.backend_pid:
            raise ValueError('SQL_CONNECTION_CHANGED_DURING_SERVICE_VERIFICATION')
        snapshot=h.inventory(project);known={h.key(t):t for t in plan['task_restore']}
        for task in snapshot['tasks']:
            if h.key(task) not in known or task['Actions']!=known[h.key(task)]['Actions']:
                raise ValueError('SCHEDULED_TASK_PLAN_CHANGED')
            if task['State']=='Running' and task['Name']!='P24-Office-LAN-Proxy':
                raise ValueError('WAIT_FOR_CURRENT_MONITOR_TASK_TO_FINISH_THEN_RETRY')
        folder=project/'AnomalyDetection/reports'/('Viewer_Cache_Trial_'+datetime.now(timezone.utc).strftime('%Y%m%d_%H%M%S_')+uuid.uuid4().hex[:8])
        folder.mkdir();receipt=folder/'cache.json'
        auto_path=Path(directory)/'postgresql.auto.conf'
        auto_before=auto_path.read_bytes()
        # This is a tiny settings receipt, not a database copy. It also permits
        # recovery if a failed service start makes ALTER SYSTEM unavailable.
        (folder/'postgresql.auto.conf.before').write_bytes(auto_before)
        state=dict(status='CACHE_TRIAL_PREPARED',release_receipt=str((Path(prior['release_receipt']) if prior else args.release_receipt).resolve()),
            project=str(project),before=dict(restore_plan=plan),before_settings=original_settings,memory_before=memory,
            target_settings=prior['before_settings'] if prior else TARGETS,rollback_of=str(args.rollback) if prior else None,
            stopping_started=False,attempted_roles=[],disabled_tasks=[],restore_failures=[],new_database_copies=0,
            evidence_deleted=False,checkpoint_seek_performed=False,capacity_acceptance='NOT_ASSIGNED',
            data_directory=directory,service_name=service['Name'],service_binding=binding)
        save()
        # Record an attempted disable before mutation so an interrupted run
        # has the exact actions and original enabled state for restoration.
        for task in snapshot['tasks']:
            if task['Enabled']:
                state['disabled_tasks'].append(task);save('DISABLING_AUTOSTART')
                h.task_change(task,False)
        stopping=True;state['stopping_started']=True
        state['attempted_roles'].append('ad');save('STOPPING_AD');h.stop_role(project,'ad')
        state['attempted_roles'].append('viewer');save('STOPPING_VIEWER')
        with h.product_reader(project) as reader:
            owner=read_identity(project,[dict(r) for r in reader.execute(LEASE_SQL).fetchall()])
            # This is the current receipt-proven backend, not an old PID. The
            # unfinished atomic publication is retried from its durable cursor.
            state['cancelled_writer_identity']=owner;save()
            stopped=reader.execute("""SELECT pg_cancel_backend(pid) AS cancelled FROM pg_stat_activity
                WHERE pid=%s AND EXTRACT(EPOCH FROM backend_start)::text=%s
                AND datname=current_database() AND application_name=%s""",
                (owner['backend_pid'],owner['backend_start'],owner['application_name'])).fetchall()
            state['publication_cancel_result']=[dict(r) for r in stopped]
        h.stop_role(project,'viewer')
        with h.product_reader(project) as reader:state['frozen_cursors']=h.cursors(reader)
        save('APPLYING_CACHE_SETTINGS')
        settings_written=True
        try:
            if prior:restore_parameters(admin,prior['before_settings'])
            else:set_parameters(admin,TARGETS)
        finally:
            state['applied_auto_conf_sha256']=hashlib.sha256(auto_path.read_bytes()).hexdigest()
        admin.close();admin=None
        save('RESTARTING_POSTGRESQL')
        h.powershell("""$ErrorActionPreference='Stop'
            Restart-Service -Name postgresql-x64-18 -ErrorAction Stop
            Get-Service -Name postgresql-x64-18 | Select-Object Name,Status | ConvertTo-Json -Compress""")
        admin=connect()
        after=settings_snapshot(admin);state['after_settings']=after
        expected=prior['before_settings']['effective'] if prior else {
            'shared_buffers':{'setting':str(12*GIB//8192)},'track_io_timing':{'setting':'on'},'track_wal_io_timing':{'setting':'on'}}
        if any(after['effective'][name]['setting']!=expected[name]['setting'] for name in TARGETS):
            raise ValueError('POST_RESTART_CACHE_SETTINGS_NOT_ACTIVE')
        with h.product_reader(project) as reader:verify_cursors(state['frozen_cursors'],h.cursors(reader))
        save('CACHE_SETTINGS_VERIFIED')
    except Exception as exc:
        failure=dict(error_type=type(exc).__name__,code=str(exc) if isinstance(exc,ValueError) else None,
                     sqlstate=getattr(exc,'sqlstate',None))
        if isinstance(exc,ServiceBindingError):failure['service_binding']=exc.details
        if state:
            state['failure']=failure
            # If activation failed, put back the exact previous auto.conf
            # entries before attempting the normal role restoration.
            if settings_written and original_settings:
                try:
                    if admin is None or admin.closed:admin=connect()
                    restore_parameters(admin,original_settings);admin.close();admin=None
                    h.powershell("Restart-Service -Name postgresql-x64-18 -ErrorAction Stop; [pscustomobject]@{status='RESTARTED'} | ConvertTo-Json -Compress")
                    state['settings_restored_after_failure']=True
                except Exception as recovery:
                    state['settings_sql_restore_failure']=dict(error_type=type(recovery).__name__)
                    try:
                        if admin is not None:admin.close();admin=None
                        stopped=h.powershell("Stop-Service -Name postgresql-x64-18 -ErrorAction Stop; [pscustomobject]@{state=[string](Get-Service postgresql-x64-18).Status} | ConvertTo-Json -Compress")
                        if stopped['state']!='Stopped':raise ValueError('SERVICE_NOT_STOPPED_FOR_CONFIG_RECOVERY')
                        if hashlib.sha256(auto_path.read_bytes()).hexdigest()!=state.get('applied_auto_conf_sha256'):
                            raise ValueError('AUTO_CONF_CHANGED_AFTER_TRIAL_NO_OVERWRITE')
                        with auto_path.open('wb') as out:out.write(auto_before);out.flush();os.fsync(out.fileno())
                        h.powershell("Start-Service -Name postgresql-x64-18 -ErrorAction Stop; [pscustomobject]@{status='STARTED'} | ConvertTo-Json -Compress")
                        state['settings_restored_after_failure']=True
                    except Exception as fallback:
                        state['settings_restore_failure']=dict(error_type=type(fallback).__name__,code=str(fallback) if isinstance(fallback,ValueError) else None)
            save('CACHE_TRIAL_FAILED')
        else:print(json.dumps(dict(status='CACHE_TRIAL_BLOCKED',**failure)),flush=True)
    finally:
        if admin is not None:admin.close()
        if state:
            if stopping:
                try:restore(project,receipt,state)
                except Exception as exc:state['final_restore_failure']=dict(error_type=type(exc).__name__,code=str(exc))
            else:
                for task in reversed(state['disabled_tasks']):
                    try:h.task_change(task,True)
                    except Exception as exc:state['restore_failures'].append(dict(task=task['Name'],error_type=type(exc).__name__))
            success=not state.get('failure') and state.get('status')=='PREVIOUS_ROLES_RESTORED' and not state.get('final_restore_failure')
            save('CACHE_TRIAL_APPLIED_ROLES_RESTORED' if success else 'CACHE_TRIAL_INCOMPLETE_SEND_RECEIPT',
                 process_capacity_is_not_detection_accuracy=True)
    return 0 if state and state['status']=='CACHE_TRIAL_APPLIED_ROLES_RESTORED' else 2


if __name__=='__main__':raise SystemExit(main())
