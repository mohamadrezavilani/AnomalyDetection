"""Apply the owner's approved resource settings, restart the exact Windows service.

Only four PostgreSQL settings are changed. Config backup stays under private/;
the public JSON never contains config contents, credentials or database rows.
"""
from __future__ import annotations
import argparse
import ctypes
import hashlib
import json
import ntpath
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import time
import uuid

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))
from p24_foundation.viewer_runtime import atomic_json,runtime_source_digest
from tools.viewer_pg_observer import load_viewer_database
from tools.check_viewer_install import check
from tools.run_finalized_projection_probe import checkpoint,main as probe

TARGETS={'shared_buffers':'8GB','wal_buffers':'16MB','max_wal_size':'8GB','min_wal_size':'1GB'}
TARGET_BYTES={'shared_buffers':8*1024**3,'wal_buffers':16*1024**2,
              'max_wal_size':8*1024**3,'min_wal_size':1024**3}
DURABILITY=('fsync','full_page_writes','synchronous_commit','wal_level')
RESTART_TARGETS=frozenset(('shared_buffers','wal_buffers'))


class ResourceError(RuntimeError):
    pass


def require_admin():
    if os.name!='nt' or not ctypes.windll.shell32.IsUserAnAdmin():
        raise ResourceError('run_powershell_as_administrator')


def digest(path):return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def size_bytes(row):
    return int(row['setting'])*{'8kB':8192,'kB':1024,'MB':1024**2,'GB':1024**3,'B':1,None:1}[row['unit']]


def connect(database):
    import psycopg
    from psycopg.rows import dict_row
    options=dict(database);options['connect_timeout']=3
    c=psycopg.connect(**options,autocommit=True,row_factory=dict_row)
    c.execute('SET statement_timeout=8000')
    return c


def snapshot(c):
    identity=c.execute("SELECT system_identifier::text AS id FROM pg_control_system()").fetchone()['id']
    data=c.execute("SELECT current_setting('data_directory') AS data, current_setting('port') AS port").fetchone()
    rows=c.execute('SELECT name,setting,unit,pending_restart FROM pg_settings WHERE name=ANY(%s)',
                   (list(TARGETS)+list(DURABILITY),)).fetchall()
    return dict(identity=identity,data=data['data'],port=data['port'],settings={r['name']:dict(r) for r in rows})


def overrides(c):
    rows=c.execute('SELECT sourcefile,name,setting FROM pg_file_settings WHERE name=ANY(%s) ORDER BY seqno',
                   (list(TARGETS),)).fetchall()
    return {r['name']:r['setting'] for r in rows
            if str(r['sourcefile']).replace('\\','/').rsplit('/',1)[-1]=='postgresql.auto.conf'}


def config_validation(c,auto,*,targets_written=False):
    """Distinguish validated postmaster changes from genuine file errors.

    Call targets_written=True only after all four ALTER SYSTEM statements have
    succeeded: PostgreSQL itself has then parsed/validated the exact values.
    pg_file_settings checks current files even before a reload. Its generic
    'setting could not be applied' also covers postmaster changes until restart.
    Never accept that message alone, a shadowed entry, or another parameter.
    """
    rows=c.execute('''SELECT f.seqno,f.sourcefile,f.sourceline,f.name,f.setting,
                            f.applied,f.error,s.context
                     FROM pg_file_settings f LEFT JOIN pg_settings s ON s.name=f.name
                     ORDER BY f.seqno''').fetchall()
    normalize=lambda path:ntpath.normcase(ntpath.normpath(str(path or '')))
    final={row['name']:row for row in rows}
    errors=[];restart=[]

    def issue(row,reason):
        # Config values and raw error text can contain secrets: publish neither.
        errors.append(dict(parameter=row['name'] if row['name'] in TARGETS else 'other',
                           file='postgresql.auto.conf' if normalize(row['sourcefile'])==normalize(auto) else 'other_config',
                           line=row['sourceline'],reason=reason))

    for row in rows:
        if row['error'] is None:continue
        expected=(targets_written and row['name'] in RESTART_TARGETS
                  and row['context']=='postmaster' and row['applied'] is False
                  and row['error']=='setting could not be applied'
                  and row is final[row['name']]
                  and normalize(row['sourcefile'])==normalize(auto)
                  and row['setting']==TARGETS[row['name']])
        if expected:restart.append(row['name'])
        else:issue(row,'CONFIG_ERROR')
    if targets_written:
        for name,value in TARGETS.items():
            row=final.get(name)
            if row is None:
                errors.append(dict(parameter=name,file='missing',line=None,reason='TARGET_MISSING'))
                continue
            if normalize(row['sourcefile'])!=normalize(auto) or row['setting']!=value:
                issue(row,'TARGET_CHANGED_OR_OVERRIDDEN')
            elif not row['applied'] and name not in restart and row['error'] is None:
                issue(row,'TARGET_NOT_APPLICABLE')
    return dict(status='INVALID' if errors else 'READY_FOR_RESTART' if targets_written else 'VALID',
                restart_required=sorted(restart),errors=errors)


def set_setting(c,name,value):
    from psycopg import sql
    if name not in TARGETS:raise ResourceError('unapproved_parameter')
    if value is None:c.execute(sql.SQL('ALTER SYSTEM RESET {}').format(sql.Identifier(name)))
    else:c.execute(sql.SQL('ALTER SYSTEM SET {} TO {}').format(sql.Identifier(name),sql.Literal(str(value))))


def choose_service(services,data_dir,parent_pid=None):
    normalize=lambda s:ntpath.normcase(ntpath.normpath(s))
    by_parent=[s for s in services if parent_pid and int(s.get('ProcessId') or 0)==int(parent_pid)]
    if len(by_parent)==1:return by_parent[0]['Name']
    matches=[]
    for s in services:
        command=s.get('PathName') or ''
        match=re.search(r'(?:^|\s)(?:-D\s+|--pgdata[=\s]+)(?:"([^"]+)"|(\S+))',command,re.I)
        if match and normalize(match.group(1) or match.group(2))==normalize(data_dir):matches.append(s)
    if len(matches)!=1:raise ResourceError('postgres_service_not_unique')
    return matches[0]['Name']


def windows_service(c,data_dir):
    master=int(c.execute("SELECT pg_read_file('postmaster.pid',0,200) AS body").fetchone()['body'].splitlines()[0])
    env=dict(os.environ,P24_DB_MASTER_PROCESS=str(master))
    script=r'''$ErrorActionPreference='Stop'; [Console]::OutputEncoding=[System.Text.UTF8Encoding]::new($false)
$process=Get-CimInstance Win32_Process -Filter ('ProcessId='+$env:P24_DB_MASTER_PROCESS)
$services=@(Get-CimInstance Win32_Service | Where-Object {$_.PathName -match '(?i)(postgres|pg_ctl)'} |
 Select-Object Name,PathName,ProcessId)
@{parent=$process.ParentProcessId;services=$services} | ConvertTo-Json -Depth 4 -Compress'''
    result=subprocess.run(['powershell.exe','-NoProfile','-NonInteractive','-Command',script],
        env=env,capture_output=True,encoding='utf-8-sig',timeout=20,check=True)
    parsed=json.loads(result.stdout)
    return choose_service(parsed['services'],data_dir,parsed.get('parent'))


def restart_service(name):
    print(json.dumps({'stage':'restarting_postgresql','service':name}),flush=True)
    env=dict(os.environ,P24_PG_RESOURCE_SERVICE=name)
    script=r'''$ErrorActionPreference='Stop'
$service=@(Get-Service | Where-Object {$_.Name -ceq $env:P24_PG_RESOURCE_SERVICE})
if ($service.Count -ne 1) { throw 'Service not unique' }
if ($service[0].Status -eq 'Running') { Restart-Service -InputObject $service[0] -ErrorAction Stop }
else { Start-Service -InputObject $service[0] -ErrorAction Stop }
(Get-Service -Name $service[0].Name).WaitForStatus('Running',[TimeSpan]::FromSeconds(45))'''
    subprocess.run(['powershell.exe','-NoProfile','-NonInteractive','-Command',script],
        env=env,capture_output=True,timeout=180,check=True)


def wait_ready(database,identity):
    until=time.monotonic()+60
    while time.monotonic()<until:
        try:
            with connect(database) as c:
                state=snapshot(c)
                if state['identity']!=identity:raise ResourceError('server_identity_changed')
                return state
        except ResourceError:raise
        except Exception:time.sleep(1)
    raise ResourceError('postgresql_did_not_return')


def restore_local(state):
    target=Path(state['data'])/'postgresql.auto.conf'
    if digest(target)!=state.get('after_hash'):raise ResourceError('config_changed_externally')
    backup=Path(state['backup_file'])
    if digest(backup)!=state['before_hash']:raise ResourceError('config_backup_corrupt')
    temp=target.with_name(target.name+'.p24-restore-'+uuid.uuid4().hex+'.tmp')
    try:
        with temp.open('wb') as out:
            out.write(backup.read_bytes());out.flush();os.fsync(out.fileno())
        os.replace(temp,target)
    finally:
        if temp.exists():temp.unlink()


def recover(database,state,state_path):
    # Prefer parameter-specific restore, preserving unrelated admin changes.
    try:
        c=connect(database)
    except Exception:c=None
    if c is not None:
        with c:
            if snapshot(c)['identity']!=state['identity']:raise ResourceError('server_identity_changed')
            current=overrides(c)
            for name in TARGETS:
                before=state['before_overrides'].get(name)
                if current.get(name) not in (before,TARGETS[name]):raise ResourceError('config_changed_externally')
            for name in TARGETS:set_setting(c,name,state['before_overrides'].get(name))
            c.execute('SELECT pg_reload_conf()')
    else:restore_local(state)
    restart_service(state['service'])
    restored=wait_ready(database,state['identity'])
    if any(size_bytes(restored['settings'][name])!=size_bytes(state['settings'][name]) for name in TARGETS):
        raise ResourceError('rollback_settings_not_restored')
    state['status']='ROLLED_BACK';atomic_json(state_path,state)
    return restored


def apply(database,backup_root,report):
    require_admin()
    with connect(database) as c:
        if not c.execute('SELECT pg_try_advisory_lock(240026,1) AS ok').fetchone()['ok']:
            raise ResourceError('stop_viewer_worker_first')
        before=snapshot(c)
        if c.execute('SELECT COUNT(*) AS n FROM pg_settings WHERE pending_restart').fetchone()['n']:
            raise ResourceError('preexisting_pending_restart')
        if not c.execute("""SELECT bool_and(has_parameter_privilege(current_user,name,'ALTER SYSTEM')) AS ok
                           FROM unnest(%s::text[]) AS names(name)""",(list(TARGETS),)).fetchone()['ok']:
            raise ResourceError('alter_system_privilege_required')
        if all(size_bytes(before['settings'][name])==value for name,value in TARGET_BYTES.items()):
            report['resource_status']='ALREADY_APPLIED';return
        service=windows_service(c,before['data'])
        directory=Path(before['data']);auto=directory/'postgresql.auto.conf'
        if shutil.disk_usage(directory).free<20*1024**3:raise ResourceError('insufficient_disk_headroom')
        report['config_before']=config_validation(c,auto)
        if report['config_before']['status']=='INVALID':raise ResourceError('preexisting_postgres_config_error')
        old_overrides=overrides(c)
        backup_root.mkdir(parents=True,exist_ok=False)
        backup=backup_root/'postgresql.auto.conf.before'
        with backup.open('wb') as out:
            out.write(auto.read_bytes());out.flush();os.fsync(out.fileno())
        state=dict(before,service=service,before_overrides=old_overrides,before_hash=digest(backup),
                   backup_file=str(backup.resolve()),targets=TARGETS,status='PREPARED')
        state_path=backup_root/'state.json';atomic_json(state_path,state)
        report['rollback_state']=str(state_path);report['settings_before']=before['settings']
        try:
            for name,value in TARGETS.items():
                set_setting(c,name,value)
                state['after_hash']=digest(auto);state['status']='CONFIG_WRITTEN';atomic_json(state_path,state)
            # A reload cannot activate postmaster settings and is unnecessary:
            # validate the files, then restart once to activate all four together.
            report['config_written']=config_validation(c,auto,targets_written=True)
            if report['config_written']['status']=='INVALID':
                raise ResourceError('new_postgres_config_error')
            state['status']='CONFIG_VALIDATED';atomic_json(state_path,state)
        except Exception:
            # Connection is still available in ordinary ALTER SYSTEM errors.
            try:
                for name in TARGETS:set_setting(c,name,old_overrides.get(name))
                c.execute('SELECT pg_reload_conf()')
                state['status']='ROLLED_BACK_BEFORE_RESTART'
                report['resource_status']='ROLLED_BACK_BEFORE_RESTART'
            except Exception:
                report['resource_status']='RECOVERY_REQUIRED'
                state['status']='RECOVERY_REQUIRED'
            atomic_json(state_path,state)
            raise
    try:
        restart_service(service)
        after=wait_ready(database,before['identity'])
        if any(size_bytes(after['settings'][name])!=value or after['settings'][name]['pending_restart']
               for name,value in TARGET_BYTES.items()):raise ResourceError('resource_settings_not_active')
        if any(after['settings'][name]['setting']!=before['settings'][name]['setting'] for name in DURABILITY):
            raise ResourceError('durability_settings_changed')
        state['status']='VERIFIED';atomic_json(state_path,state)
        report['settings_after']=after['settings'];report['service']=service
        report['resource_status']='APPLIED_AND_RESTARTED'
    except Exception:
        try:recover(database,state,state_path);report['resource_status']='ROLLED_BACK'
        except Exception as recovery:report['resource_status']='RECOVERY_REQUIRED';report['recovery_error_type']=type(recovery).__name__
        raise


def main(argv=None):
    ap=argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--config',type=Path,required=True)
    ap.add_argument('--action',choices=('apply','rollback'),default='apply')
    ap.add_argument('--state',type=Path)
    ap.add_argument('--probe',action='store_true')
    ap.add_argument('--out',type=Path,default=Path('validation/d2_resources_probe.json'))
    args=ap.parse_args(argv)
    report=dict(status='STOPPED',runtime_source_sha256=runtime_source_digest(),targets=TARGETS,
                capacity_800k='NOT_PROVEN',database_rows_modified_by_tuning=False)
    try:
        require_admin()
        database=load_viewer_database(args.config)
        if database.get('host','') not in ('','localhost','127.0.0.1','::1'):raise ResourceError('local_postgresql_required')
        report['installation']=check(args.config)
        if report['installation']['status']!='READY_TO_START':raise ResourceError('installation_check_failed')
        report['checkpoint_before']=checkpoint(database)
        if args.action=='rollback':
            if args.state is None:raise ResourceError('rollback_state_required')
            state=json.loads(args.state.read_text())
            if state['targets']!=TARGETS:raise ResourceError('invalid_rollback_state')
            recover(database,state,args.state);report['resource_status']='ROLLED_BACK'
        else:
            token=time.strftime('%Y%m%d_%H%M%S')+'_'+uuid.uuid4().hex[:8]
            apply(database,Path('private/pg_resource_backups')/token,report)
        report['checkpoint_after_restart']=checkpoint(database)
        if report['checkpoint_before']!=report['checkpoint_after_restart']:raise ResourceError('checkpoint_changed_during_tuning')
        report['status']='RESOURCES_READY'
        atomic_json(args.out,report)
        if args.probe and args.action=='apply':
            probe_out=Path('validation/d2_resources_one_window.json')
            probe(['--config',str(args.config),'--out',str(probe_out)])
            report['probe']=json.loads(probe_out.read_text())
            report['status']=report['probe']['status']
    except KeyboardInterrupt:report['status']='INTERRUPTED'
    except Exception as exc:
        report['error_type']=type(exc).__name__
        if isinstance(exc,ResourceError):report['error_code']=str(exc)
        report['status']='FAILED'
    finally:atomic_json(args.out,report)
    print(json.dumps({'status':report['status'],'output':str(args.out)}))
    return 0 if report['status'] in ('RESOURCES_READY','PUBLISHED_UNDER_BUDGET') else 2


if __name__=='__main__':raise SystemExit(main())
