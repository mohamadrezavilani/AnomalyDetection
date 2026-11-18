"""One reversible 12 GiB cache trial on the owner's existing Windows server.

Run outside the checkout using its venv Python from the checkout directory.
Uses an already-restored release receipt for the known launch commands/tasks.
No copy, evidence deletion, reindex, model execution, source edit or cursor seek.
Stops the verified writer without first cancelling its SQL connection; its
unfinished transaction rolls back and the durable checkpoint is retried.
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
import subprocess
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


class ServiceActivationError(ValueError):
    def __init__(self,code,details):super().__init__(code);self.details=details


class ViewerControlError(ValueError):
    def __init__(self,code,details):super().__init__(code);self.details=details


def stop_viewer(h,project,state,save,*,wait=time.sleep):
    """Let the installed controller bind its live client before stopping it.

    A preceding pg_cancel_backend can make that client exit between its lease,
    TCP and handle checks. The controller already aborts an unfinished publish
    through the verified process and exact SQL lease. Retain its complete
    structured result, including a blocked stage/code, in the private receipt.
    """
    done=('VIEWER_WORKER_STOPPED','VIEWER_BACKEND_STOPPED','NO_VIEWER_LOCK_OWNER_OBSERVED')
    for _ in range(12):
        result,code=h.command(project,'viewer_performance/Stop_Viewer_Worker.py','--stop')
        state.setdefault('viewer_stop_attempts',[]).append(dict(return_code=code,result=result))
        save('STOPPING_VIEWER')
        if code==0 and result.get('status') in done:return result
        if result.get('status')!='VIEWER_BACKEND_STOP_PENDING':
            raise ViewerControlError('CONTROLLED_STOP_BLOCKED:viewer:'+str(result.get('status')),
                                     dict(return_code=code,result=result))
        wait(1)
    raise ViewerControlError('CONTROLLED_STOP_TIMEOUT:viewer',dict(last_result=result))


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
        [pscustomobject]@{service=($s | Select-Object Name,State,ProcessId,StartName,PathName);processes=@($p)} |
            ConvertTo-Json -Depth 8 -Compress''')


def orphan_owner(snapshot,admin,report):
    """Prove the reported live cluster and stopped service are the same target.

    This explicit recovery route requires the private read-only inventory.
    The live SQL connection, pid-file header, unchanged native process creation
    identity, service account and executable/config directory must all agree.
    """
    from viewer_performance.financial_screen.reviewed_host import words,norm
    service=snapshot.get('service') or {};sql=report.get('sql') or {}
    def fail(code):raise ServiceBindingError(code,dict(service_name=service.get('Name'),service_state=service.get('State')))
    if (not report.get('same_server_during_collection') or report.get('settings_modified')
            or service.get('State')!='Stopped' or service.get('ProcessId')!=0
            or service.get('Name','').lower()!='postgresql-x64-18'):
        fail('ORPHAN_RECOVERY_REQUIRES_REPORTED_STOPPED_SERVICE')
    account=lambda v:''.join(str(v).lower().split())
    owner=report.get('postmaster_owner') or {}
    if (owner.get('ReturnValue')!=0 or account(owner.get('Domain','')+'\\'+owner.get('User',''))!='ntauthority\\networkservice'
            or account(service.get('StartName'))!='ntauthority\\networkservice'):
        fail('ORPHAN_AND_SERVICE_ACCOUNTS_MUST_MATCH_NETWORK_SERVICE')
    current=admin.execute("""SELECT current_setting('data_directory') AS directory,
        current_setting('config_file') AS config_file,
        EXTRACT(EPOCH FROM pg_postmaster_start_time())::double precision AS started,
        (SELECT system_identifier::text FROM pg_control_system()) AS system_identifier""").fetchone()
    if (current['system_identifier']!=sql.get('system_identifier')
            or norm(current['directory'])!=norm(sql.get('data_directory',''))
            or norm(current['config_file'])!=norm(sql.get('config_file',''))):
        fail('LIVE_CLUSTER_DIFFERS_FROM_RUNTIME_REPORT')
    expected_start=datetime.fromisoformat(sql['postmaster_started']).timestamp()
    if abs(current['started']-expected_start)>.001:fail('POSTMASTER_RESTARTED_SINCE_RUNTIME_REPORT')
    header=admin.execute("SELECT pg_read_file('postmaster.pid',0,1024) AS body").fetchone()['body'].splitlines()
    master_pid=int(header[0]);started_epoch=int(header[2])
    if master_pid!=sql.get('postmaster_pid') or norm(header[1])!=norm(current['directory']):
        fail('POSTMASTER_PID_FILE_DIFFERS_FROM_RUNTIME_REPORT')
    rows={r['pid']:r for r in snapshot['processes']};master=rows.get(master_pid);backend=rows.get(admin.info.backend_pid)
    reported=next((p for p in report.get('postmaster_ancestry',[]) if p.get('pid')==master_pid),None)
    if (not master or not reported or not backend or backend.get('parent_pid')!=master_pid
            or master.get('created_ticks')!=reported.get('created_ticks')
            or norm(master.get('image',''))!=norm(reported.get('image',''))
            or ntpath.basename(master.get('image') or '').lower()!='postgres.exe'):
        fail('LIVE_NATIVE_POSTMASTER_IDENTITY_NOT_PROVEN')
    if abs(master['created_ticks']//10_000_000-62_135_596_800-started_epoch)>2:
        fail('NATIVE_POSTMASTER_PID_WAS_REUSED')
    command=words(service.get('PathName') or '');flags=[v.lower() for v in command]
    pg_ctl=ntpath.join(ntpath.dirname(master['image']),'pg_ctl.exe')
    if (not command or norm(command[0])!=norm(pg_ctl) or 'runservice' not in flags or '-d' not in flags
            or norm(command[flags.index('-d')+1])!=norm(ntpath.dirname(current['config_file']))
            or '-o' in flags):
        fail('STOPPED_SERVICE_EXECUTABLE_OR_CONFIG_DIFFERS_FROM_LIVE_CLUSTER')
    return dict(method='REPORTED_ORPHAN_TO_MATCHING_NETWORK_SERVICE',system_identifier=current['system_identifier'],
                postmaster_pid=master_pid,created_ticks=master['created_ticks'],pg_ctl=pg_ctl,
                data_directory=current['directory'],service_name=service['Name'],adopt_orphan=True)


def activate_service(h,binding,*,run=subprocess.run,progress=lambda value:None):
    """Fast, graceful stop of the proven orphan, then one normal SCM start.

    pg_ctl uses the named signal pipe and its pid file; no OS process kill or
    second server start is attempted while the old server remains active.
    """
    if binding.get('adopt_orphan'):
        progress('STOPPING_VERIFIED_ORPHAN_POSTGRESQL')
        try:
            result=run([binding['pg_ctl'],'-D',binding['data_directory'],'-m','fast','-w','-t','120','stop'],
                capture_output=True,encoding='utf-8',errors='replace',timeout=140)
        except subprocess.TimeoutExpired as exc:
            raise ServiceActivationError('PG_CTL_GRACEFUL_STOP_TIMEOUT',dict(timeout_seconds=140)) from exc
        if result.returncode:
            raise ServiceActivationError('PG_CTL_GRACEFUL_STOP_FAILED:'+str(result.returncode),
                dict(returncode=result.returncode,stdout=str(result.stdout or '')[-16000:],stderr=str(result.stderr or '')[-16000:]))
        progress('STARTING_MATCHING_POSTGRESQL_SERVICE')
        h.powershell("Start-Service -Name postgresql-x64-18 -ErrorAction Stop; [pscustomobject]@{status='STARTED'} | ConvertTo-Json -Compress")
    else:
        h.powershell("Restart-Service -Name postgresql-x64-18 -ErrorAction Stop; [pscustomobject]@{status='RESTARTED'} | ConvertTo-Json -Compress")


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
    parser.add_argument('--runtime-report',type=Path,help='Read-only inventory proving a live orphan and its matching stopped service')
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
        notice=dict(status=state['status'],output=str(receipt))
        if state.get('failure') and status in ('CACHE_TRIAL_FAILED','CACHE_TRIAL_INCOMPLETE_SEND_RECEIPT'):
            notice['failure']=state['failure']
        print(json.dumps(notice,ensure_ascii=True),flush=True)
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
        binding=(orphan_owner(inventory,admin,load(args.runtime_report))
                 if args.runtime_report and service.get('State')=='Stopped'
                 else service_owner(inventory,admin.info.backend_pid))
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
            maintenance_source_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
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
            state['verified_writer_before_stop']=owner;save()
        stop_viewer(h,project,state,save)
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
        activate_service(h,binding,progress=save)
        admin=connect()
        if binding.get('adopt_orphan'):
            service_owner(service_snapshot(h),admin.info.backend_pid)
            actual_id=admin.execute('SELECT system_identifier::text AS id FROM pg_control_system()').fetchone()['id']
            if actual_id!=binding['system_identifier']:raise ValueError('STARTED_SERVICE_IS_A_DIFFERENT_CLUSTER')
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
        if isinstance(exc,ServiceActivationError):failure['service_activation']=exc.details
        if isinstance(exc,ViewerControlError):failure['viewer_control']=exc.details
        if h is not None and isinstance(exc,h.HostOperationError):failure['host_operation']=exc.details
        if state:
            state['failure']=failure
            # If activation failed, put back the exact previous auto.conf
            # entries before attempting the normal role restoration.
            if settings_written and original_settings:
                try:
                    if admin is None or admin.closed:admin=connect()
                    restore_parameters(admin,original_settings);admin.close();admin=None
                    # If the orphan never stopped, its original cache is still
                    # active. Restoring auto.conf is sufficient; do not start
                    # another server against its occupied directory.
                    live_orphan=False
                    if state.get('service_binding',{}).get('adopt_orphan'):
                        status=h.powershell("[pscustomobject]@{state=[string](Get-Service postgresql-x64-18).Status} | ConvertTo-Json -Compress")
                        live_orphan=status['state']=='Stopped'
                    if not live_orphan:
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
