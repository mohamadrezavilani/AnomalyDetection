"""Stop the verified loopback Viewer web process and only its live DB sessions.

Default is inspection. The LAN frontend, singleton worker, PostgreSQL service,
committed evidence and checkpoint are never stopped or changed by this tool.
"""
from pathlib import Path
import argparse
import json
import ipaddress
import os
import runpy
import subprocess
import sys


class ControlError(RuntimeError):pass


def tcp_rows(state):
    if state not in ('Listen','Established'):raise ControlError('INVALID_TCP_STATE')
    command=("$ErrorActionPreference='Stop'; $rows=@(Get-NetTCPConnection -State "+state+
        " -ErrorAction Stop | Select-Object LocalAddress,LocalPort,RemoteAddress,RemotePort,OwningProcess); "
        "ConvertTo-Json -InputObject $rows -Compress")
    result=subprocess.run(['powershell.exe','-NoProfile','-NonInteractive','-Command',command],
        capture_output=True,text=True,timeout=12)
    if result.returncode:raise ControlError('TCP_INVENTORY_UNAVAILABLE')
    return json.loads(result.stdout or '[]')


def listener():
    owners={int(r['OwningProcess']) for r in tcp_rows('Listen')
        if r['LocalAddress']=='127.0.0.1' and r['LocalPort']==5021}
    if len(owners)>1:raise ControlError('LOOPBACK_VIEWER_OWNER_NOT_UNIQUE')
    return next(iter(owners),None)


def client_endpoints(pid,server_port):
    from viewer_performance.Stop_Viewer_Worker import loopback
    return frozenset((int(r['LocalPort']),str(ipaddress.ip_address(r['LocalAddress']))) for r in tcp_rows('Established')
        if int(r['OwningProcess'])==pid and r['RemotePort']==server_port
        and loopback(r['LocalAddress']) and loopback(r['RemoteAddress']))


def control(find_listener,health,ports,open_process,backends,terminate,*,supported,stop=False,self_pid=None):
    pid=find_listener()
    result={'status':'NO_VIEWER_WEB_LISTENER','process_stopped':False,'database_modified':False,
        'checkpoint_seek_performed':False,'committed_data_deleted':False}
    if pid is None:return result
    if pid==(os.getpid() if self_pid is None else self_pid):raise ControlError('REFUSE_SELF_STOP')
    process=open_process(pid)
    try:
        observed=health();identity=observed.get('health',{})
        if (observed.get('http_status')!=200 or identity.get('status')!='ok'
                or identity.get('service')!='viewer' or identity.get('runtime_sha256') not in supported
                or not str(observed.get('server','')).startswith('Werkzeug/')):
            raise ControlError('LOOPBACK_VIEWER_HEALTH_NOT_VERIFIED')
        if process.image.replace('\\','/').rsplit('/',1)[-1].lower() not in ('python.exe','pythonw.exe'):
            raise ControlError('VIEWER_WEB_OWNER_NOT_PYTHON')
        captured=ports(pid);sessions=backends(captured)
        if any(row['backend_start']<process.created or row['worker_lock'] for row in sessions):
            raise ControlError('VIEWER_WEB_DATABASE_IDENTITY_MISMATCH')
        # The process handle and listener identify the web server. Browser
        # refreshes legitimately open/close DB connections during inspection;
        # requiring the whole connection set to stay identical prevents a
        # busy server from ever stopping. Cleanup uses only the exact backend
        # identities proven by the original TCP snapshot.
        if find_listener()!=pid:
            raise ControlError('VIEWER_WEB_OWNER_CHANGED')
        result.update(status='VIEWER_WEB_IDENTIFIED',python_pid=pid,matched_database_sessions=len(sessions))
        if stop:
            process.terminate()
            result.update(status='VIEWER_WEB_STOPPED',process_stopped=True,
                database_termination_acknowledged=sum(bool(terminate(row)) for row in sessions))
        return result
    finally:process.close()


BACKENDS_SQL="""SELECT a.pid,a.backend_start,a.client_port,host(a.client_addr) AS client_addr,
    EXISTS(SELECT 1 FROM pg_locks l WHERE l.pid=a.pid AND l.locktype='advisory'
       AND l.classid=240026 AND l.objid IN (1,2) AND l.granted) AS worker_lock
    FROM pg_stat_activity a WHERE a.datname=current_database() AND a.backend_type='client backend'
       AND a.client_port=ANY(%s) AND a.client_addr IS NOT NULL"""
TERMINATE_SQL="""SELECT pg_terminate_backend(a.pid,5000) AS terminated FROM pg_stat_activity a
    WHERE a.pid=%s AND a.backend_start=%s AND a.client_port=%s AND host(a.client_addr)=%s
      AND a.datname=current_database() AND a.backend_type='client backend'
      AND NOT EXISTS(SELECT 1 FROM pg_locks l WHERE l.pid=a.pid AND l.locktype='advisory'
         AND l.classid=240026 AND l.objid IN (1,2) AND l.granted)"""



def verified_backends(rows,endpoints,captured_before):
    """Exclude later port reuse and ambiguous endpoint identities.

    captured_before comes from PostgreSQL immediately before the OS TCP
    inventory. A backend born after that instant cannot be established as
    belonging to the process by that inventory, even if its port is reused.
    """
    matches={}
    for row in rows:
        endpoint=(row['client_port'],str(ipaddress.ip_address(row['client_addr'])))
        if endpoint in endpoints:matches.setdefault(endpoint,[]).append(row)
    return [group[0] for group in matches.values() if len(group)==1
        and group[0]['backend_start']<=captured_before]


def main(argv=None):
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--project-root',type=Path,default=Path.cwd() if __file__ in ('<stdin>','-') else Path(__file__).resolve().parents[1])
    parser.add_argument('--stop',action='store_true');args=parser.parse_args(argv)
    try:
        if os.name!='nt':raise ControlError('WINDOWS_OWNER_HOST_REQUIRED')
        project=args.project_root.resolve();root=project/'AnomalyDetection'
        launcher=runpy.run_path(str(root/'run_anomaly.py'));launcher['verify_build']()
        sys.path.insert(0,str(project));sys.path.insert(0,str(root))
        sys.meta_path.insert(0,launcher['VerifiedApplicationFinder']())
        from anomaly_detection.pg_source import installed_source_identity,read_database_config
        from anomaly_detection.source_profiles import SUPPORTED_RUNTIMES
        installed_source_identity(project)
        from viewer_performance.Stop_Viewer_Worker import WindowsProcess,loopback
        from viewer_performance.Diagnose_Viewer_Web import probe
        params=read_database_config(project/'viewer_config.local.py')
        if str(params.get('host','localhost')).lower() not in ('localhost','127.0.0.1','::1'):
            raise ControlError('LOCAL_POSTGRESQL_REQUIRED')
        for k in ('options','application_name','row_factory','autocommit'):params.pop(k,None)
        params.update(connect_timeout=3,application_name='P24.Viewer.web_control',
            options='-c default_transaction_read_only=on -c statement_timeout=7000 -c lock_timeout=100')
        import psycopg
        from psycopg.rows import dict_row
        with psycopg.connect(**params,autocommit=True,row_factory=dict_row) as conn:
            guard=conn.execute('SELECT current_database() AS db,host(inet_server_addr()) AS address,inet_server_port() AS port').fetchone()
            if guard['db']!='p24_design_viewer' or not loopback(guard['address']):
                raise ControlError('LOCAL_VIEWER_DATABASE_REQUIRED')
            captured_before=None
            def endpoints(pid):
                nonlocal captured_before
                captured_before=conn.execute('SELECT clock_timestamp() AS captured_before').fetchone()['captured_before']
                return client_endpoints(pid,guard['port'])
            def backends(endpoints):
                rows=conn.execute(BACKENDS_SQL,([port for port,address in endpoints],)).fetchall() if endpoints else []
                return verified_backends([row for row in rows if loopback(row['client_addr'])],endpoints,captured_before)
            def terminate(row):
                item=conn.execute(TERMINATE_SQL,(row['pid'],row['backend_start'],row['client_port'],row['client_addr'])).fetchone()
                return bool(item and item['terminated'])
            result=control(listener,lambda:probe('127.0.0.1',5021,'/healthz',timeout=3),
                endpoints,lambda pid:WindowsProcess(pid,allow_stop=args.stop),
                backends,terminate,supported=SUPPORTED_RUNTIMES,stop=args.stop)
        print(json.dumps(result));return 0
    except Exception as exc:
        result={'status':'VIEWER_WEB_CONTROL_BLOCKED','error_type':type(exc).__name__}
        if isinstance(exc,ControlError):result['code']=str(exc)
        print(json.dumps(result));return 2


if __name__=='__main__':raise SystemExit(main())
