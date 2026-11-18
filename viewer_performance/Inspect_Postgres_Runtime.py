"""Read-only SQL/Windows runtime inventory before choosing a restart method.

No ALTER SYSTEM, service/task control, database write, model or data copy.
Reads the existing private database binding without exporting credentials.
"""
from datetime import datetime,timezone
import json
import ntpath
import os
from pathlib import Path
import re
import sys
import uuid


def database_snapshot(connection):
    value=dict(connection.execute("""SELECT version() AS version,current_database() AS database,
        current_user AS database_role,pg_backend_pid() AS backend_pid,
        pg_postmaster_start_time()::text AS postmaster_started,
        inet_server_addr()::text AS server_address,inet_server_port() AS server_port,
        current_setting('transaction_read_only') AS read_only,
        current_setting('data_directory') AS data_directory,
        current_setting('config_file') AS config_file,
        current_setting('hba_file') AS hba_file""").fetchone())
    if value['read_only']!='on':raise ValueError('READ_ONLY_INSPECTION_CONNECTION_REQUIRED')
    # The stable postmaster PID remains meaningful after this observer closes.
    # Export only the fixed three-line header, never startup options/configs.
    try:
        header=connection.execute("SELECT pg_read_file('postmaster.pid',0,1024) AS body").fetchone()['body'].splitlines()
        value['postmaster_pid']=int(header[0]);value['pid_file_data_directory']=header[1]
        value['pid_file_started_epoch_seconds']=int(header[2])
    except Exception as exc:value['pid_header_failure']=dict(error_type=type(exc).__name__,sqlstate=getattr(exc,'sqlstate',None))
    try:value['system_identifier']=connection.execute('SELECT system_identifier::text AS id FROM pg_control_system()').fetchone()['id']
    except Exception as exc:value['system_identifier_failure']=dict(error_type=type(exc).__name__,sqlstate=getattr(exc,'sqlstate',None))
    value['settings_scope']='INSPECTION_SESSION_NOT_RUNNING_PUBLISHER_OVERRIDES'
    value['settings']=[dict(r) for r in connection.execute("""SELECT name,setting,unit,source,pending_restart
        FROM pg_settings WHERE name=ANY(%s) ORDER BY name""",(['shared_buffers','effective_cache_size',
        'work_mem','temp_buffers','track_io_timing','track_wal_io_timing','port','wal_level'],)).fetchall()]
    return value


def scrub_service(command):
    command=re.sub(r'''(?i)(password\s*=\s*)(?:'[^']*'|"[^"]*"|[^\s]+)''',r'\1<redacted>',command or '')
    command=re.sub(r'''(?i)(?<!\S)--(?:password|passwd|pw)(?:\s+|=)(?:"[^"]*"|'[^']*'|[^\s]+)''','--password <redacted>',command)
    return re.sub(r'''(?<!\S)-P\s*(?:"[^"]*"|'[^']*'|[^\s]+)''','-P <redacted>',command)


def main():
    project=Path.cwd().resolve();sys.path[:0]=[str(project),str(project/'.venv/Lib/site-packages')]
    try:
        if os.name!='nt':raise ValueError('OWNER_WINDOWS_HOST_REQUIRED')
        from viewer_performance.financial_screen import host as h
        from p24_foundation.viewer_runtime import atomic_json
        import psycopg
        from psycopg.rows import dict_row
        params=h.parameters(project);params['connect_timeout']=5
        if str(params.get('host') or 'localhost').lower() not in ('localhost','127.0.0.1','::1'):
            raise ValueError('LOCAL_CONFIGURED_DATABASE_REQUIRED')
        with psycopg.connect(**params,dbname='p24_design_viewer',autocommit=True,row_factory=dict_row,
                application_name='P24.RuntimeInspection.ReadOnly',options='-c default_transaction_read_only=on -c statement_timeout=5000') as connection:
            sql=database_snapshot(connection)
            native=h.powershell(r'''$ErrorActionPreference='Stop'
                $services=@(Get-CimInstance Win32_Service | Select-Object Name,State,StartMode,StartName,ProcessId,PathName)
                $processes=@(Get-CimInstance Win32_Process | ForEach-Object {
                    [pscustomobject]@{pid=[long]$_.ProcessId;parent_pid=[long]$_.ParentProcessId;
                        image=$_.ExecutablePath;created_ticks=$(if($_.CreationDate){[long]$_.CreationDate.ToUniversalTime().Ticks}else{$null})}
                })
                $master=Get-CimInstance Win32_Process -Filter "ProcessId=$env:P24_RUNTIME_MASTER_PID"
                $owner=$null
                if($master){try {$owner=Invoke-CimMethod -InputObject $master -MethodName GetOwner | Select-Object Domain,User,ReturnValue} catch {}}
                [pscustomobject]@{services=$services;processes=$processes;postmaster_owner=$owner;
                    caller=[Security.Principal.WindowsIdentity]::GetCurrent().Name} | ConvertTo-Json -Depth 8 -Compress''',
                {'P24_RUNTIME_MASTER_PID':str(sql.get('postmaster_pid',0))})
            processes={p['pid']:p for p in native['processes']};chain=[];pid=sql.get('postmaster_pid');seen=set();child_time=None
            while pid in processes and pid not in seen and len(seen)<32:
                row=processes[pid];created=row.get('created_ticks')
                if child_time is not None and created is not None and created>child_time:break
                chain.append(row);seen.add(pid);child_time=created;pid=row.get('parent_pid')
            services=[]
            for service in native['services']:
                if (re.search(r'postgres|pg_ctl',service['Name']+' '+(service.get('PathName') or ''),re.I)
                        or service['ProcessId'] in seen):
                    service['PathName']=scrub_service(service.get('PathName'))
                    services.append(service)
            pg=[p for p in native['processes'] if ntpath.basename(p.get('image') or '').lower() in ('postgres.exe','pg_ctl.exe')]
            final=dict(connection.execute('SELECT pg_postmaster_start_time()::text AS started').fetchone())
        report=dict(status='READ_ONLY_POSTGRES_RUNTIME_EXPORTED',observed_utc=datetime.now(timezone.utc).isoformat(),
            sql=sql,postgres_services=services,postmaster_ancestry=chain,postgres_processes=pg,
            postmaster_owner=native['postmaster_owner'],caller=native['caller'],
            same_server_during_collection=final['started']==sql['postmaster_started'],
            database_modified=False,settings_modified=False,services_started_or_stopped=False,
            credentials_exported=False)
        output=project/'AnomalyDetection/reports'/('Postgres_Runtime_'+datetime.now(timezone.utc).strftime('%Y%m%d_%H%M%S_')+uuid.uuid4().hex[:8]+'.json')
        atomic_json(output,report)
        print(json.dumps(dict(status=report['status'],output=str(output),database_modified=False,
            settings_modified=False,services_started_or_stopped=False)),flush=True);return 0
    except Exception as exc:
        print(json.dumps(dict(status='READ_ONLY_INSPECTION_INCOMPLETE',error_type=type(exc).__name__,
            code=str(exc) if isinstance(exc,ValueError) else None,sqlstate=getattr(exc,'sqlstate',None))),flush=True);return 2


if __name__=='__main__':raise SystemExit(main())
