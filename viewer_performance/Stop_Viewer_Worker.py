"""Identify or explicitly stop only the local Viewer singleton's Python client.

No PID from an old file is trusted. Match a connected singleton to its Windows
TCP client and stable process handle. A disconnected leftover SQL backend can
be ended only through its unchanged live lease and two successful TCP-absence
observations; that path makes no claim that an OS process was identified.
Default is observation; --stop aborts the current uncommitted publication.
Committed evidence and checkpoint are retained. The PostgreSQL service is not stopped.
"""
from __future__ import annotations
import argparse
from datetime import datetime, timezone
import ipaddress
import json
import os
from pathlib import Path
import runpy
import subprocess
import sys
import time

GUARD_SQL='SELECT current_database() AS db,host(inet_server_addr()) AS address,inet_server_port() AS port'
LEASE_SQL="""SELECT a.pid,a.backend_start,a.client_port,host(a.client_addr) AS client_addr
    FROM pg_catalog.pg_stat_activity a WHERE a.datname=current_database()
      AND a.backend_type='client backend' AND EXISTS(SELECT 1 FROM pg_catalog.pg_locks l
        WHERE l.pid=a.pid AND l.locktype='advisory' AND l.classid=240026
          AND l.objid=1 AND l.objsubid=2 AND l.mode='ExclusiveLock' AND l.granted)"""


class ControlError(RuntimeError):pass


def loopback(value):
    if not isinstance(value,str):return False
    try:
        if '/' in value:
            endpoint=ipaddress.ip_interface(value)
            if endpoint.network.prefixlen!=endpoint.ip.max_prefixlen:return False
            address=endpoint.ip
        else:address=ipaddress.ip_address(value)
    except ValueError:return False
    return address.is_loopback or bool(getattr(address,'ipv4_mapped',None) and address.ipv4_mapped.is_loopback)


def tcp_owner(client_port,server_port):
    if not all(type(v) is int and 1<=v<=65535 for v in (client_port,server_port)):
        raise ControlError('INVALID_LOCAL_TCP_PORTS')
    command=("$ErrorActionPreference='Stop'; $rows=@(Get-NetTCPConnection -State Established -ErrorAction Stop | "
        f"Where-Object {{ $_.LocalPort -eq {client_port} -and $_.RemotePort -eq {server_port} }} | "
        "Select-Object OwningProcess,RemoteAddress); ConvertTo-Json -InputObject $rows -Compress")
    result=subprocess.run(['powershell.exe','-NoProfile','-NonInteractive','-Command',command],
        capture_output=True,text=True,timeout=10)
    if result.returncode:raise ControlError('TCP_OWNER_UNAVAILABLE')
    rows=json.loads(result.stdout or '[]')
    owners={int(row['OwningProcess']) for row in rows if loopback(row['RemoteAddress'])}
    if not owners:return None
    if len(owners)!=1:raise ControlError('LOCAL_TCP_OWNER_NOT_UNIQUE')
    return owners.pop()


class WindowsProcess:
    def __init__(self,pid,*,allow_stop=False):
        import ctypes
        from ctypes import wintypes as w
        self.ctypes=ctypes;self.api=ctypes.WinDLL('kernel32',use_last_error=True)
        self.api.OpenProcess.argtypes=[w.DWORD,w.BOOL,w.DWORD];self.api.OpenProcess.restype=w.HANDLE
        self.api.CloseHandle.argtypes=[w.HANDLE];self.api.CloseHandle.restype=w.BOOL
        self.api.QueryFullProcessImageNameW.argtypes=[w.HANDLE,w.DWORD,w.LPWSTR,ctypes.POINTER(w.DWORD)]
        self.api.QueryFullProcessImageNameW.restype=w.BOOL
        self.api.GetProcessTimes.argtypes=[w.HANDLE,*([ctypes.POINTER(w.FILETIME)]*4)];self.api.GetProcessTimes.restype=w.BOOL
        self.api.TerminateProcess.argtypes=[w.HANDLE,w.UINT];self.api.TerminateProcess.restype=w.BOOL
        self.api.WaitForSingleObject.argtypes=[w.HANDLE,w.DWORD];self.api.WaitForSingleObject.restype=w.DWORD
        self.allow_stop=allow_stop
        self.handle=self.api.OpenProcess(0x1000|0x00100000|(0x0001 if allow_stop else 0),False,pid)
        if not self.handle:raise ctypes.WinError(ctypes.get_last_error())
        try:
            length=w.DWORD(32768);image=ctypes.create_unicode_buffer(length.value)
            if not self.api.QueryFullProcessImageNameW(self.handle,0,image,ctypes.byref(length)):
                raise ctypes.WinError(ctypes.get_last_error())
            self.image=image.value
            created,exited,kernel,user=(w.FILETIME() for _ in range(4))
            if not self.api.GetProcessTimes(self.handle,*[ctypes.byref(v) for v in (created,exited,kernel,user)]):
                raise ctypes.WinError(ctypes.get_last_error())
            stamp=((created.dwHighDateTime<<32)|created.dwLowDateTime)/10_000_000-11644473600
            self.created=datetime.fromtimestamp(stamp,timezone.utc)
        except BaseException:self.close();raise

    def terminate(self):
        if not self.allow_stop:raise ControlError('STOP_NOT_REQUESTED')
        if not self.api.TerminateProcess(self.handle,130):raise self.ctypes.WinError(self.ctypes.get_last_error())
        if self.api.WaitForSingleObject(self.handle,10000)!=0:raise ControlError('VIEWER_PROCESS_EXIT_TIMEOUT')

    def close(self):
        if self.handle:self.api.CloseHandle(self.handle);self.handle=None


def same_lease(a,b):
    return bool(a and b and all(a.get(k)==b.get(k) for k in ('pid','backend_start','client_port','client_addr')))


def terminate_lease(connection,value):
    rows=connection.execute('''SELECT pg_terminate_backend(a.pid,5000) AS terminated
        FROM pg_catalog.pg_stat_activity a WHERE a.pid=%s AND a.backend_start=%s
        AND a.client_port=%s AND host(a.client_addr)=%s
        AND a.backend_type='client backend' AND a.datname=current_database()
        AND EXISTS(SELECT 1 FROM pg_catalog.pg_locks l
          WHERE l.pid=a.pid AND l.locktype='advisory' AND l.classid=240026 AND l.objid=1
          AND l.objsubid=2 AND l.mode='ExclusiveLock' AND l.granted)''',
        (value['pid'],value['backend_start'],value['client_port'],value['client_addr'])).fetchall()
    return bool(rows and rows[0]['terminated'])


def observe_release(lease,first,result,*,timeout=20,clock=time.monotonic,wait=time.sleep):
    """Observe the exact server lease until released, replaced, or still pending.

    PostgreSQL can retain a lease briefly after its Windows client has exited.
    A termination acknowledgement is not itself a lock-release observation.
    """
    began=clock()
    while True:
        current=lease()
        if current is None:
            result.update(status='VIEWER_WORKER_STOPPED' if result['process_stopped'] else 'VIEWER_BACKEND_STOPPED',
                          postgres_lock_released=True,release_observation_seconds=round(clock()-began,3))
            return result
        if not same_lease(first,current):
            result.update(status='VIEWER_STOP_BLOCKED_REPLACEMENT_OWNER',postgres_lock_released=False,
                          replacement_postgres_backend_pid=current.get('pid'))
            return result
        if clock()-began>=timeout:
            result.update(status='VIEWER_BACKEND_STOP_PENDING',postgres_lock_released=False,
                          release_observation_seconds=round(clock()-began,3),retry_same_stop_command=True)
            return result
        wait(min(.25,max(0,timeout-(clock()-began))))


def control(lease,owner,open_process,cleanup,*,stop=False,self_pid=None,
            release_timeout=20,clock=time.monotonic,wait=time.sleep):
    first=lease()
    if not first:return {'status':'NO_VIEWER_LOCK_OWNER_OBSERVED','process_stopped':False}
    if not first.get('client_addr') or not loopback(first['client_addr']):raise ControlError('VIEWER_CLIENT_NOT_LOCAL')
    pid=owner(first['client_port'])
    if pid is None:
        # Recovery after a previous stop killed Python but its SQL backend was
        # still rolling back. Absence must be observed twice around a fresh,
        # unchanged server lease. Never open/kill a PID from an old status file.
        if not same_lease(first,lease()) or owner(first['client_port']) is not None:
            raise ControlError('VIEWER_LEASE_OR_TCP_OWNER_CHANGED')
        result={'status':'VIEWER_BACKEND_WITHOUT_CLIENT','python_pid':None,
            'postgres_backend_pid':first['pid'],'process_stopped':None,
            'client_process_observed':False,'checkpoint_seek_performed':False,'committed_data_deleted':False}
        if stop:
            result['backend_termination_acknowledged']=bool(cleanup(first))
            return observe_release(lease,first,result,timeout=release_timeout,clock=clock,wait=wait)
        return result
    if pid==(os.getpid() if self_pid is None else self_pid):raise ControlError('REFUSE_SELF_STOP')
    process=open_process(pid)
    try:
        if process.image.replace('\\','/').rsplit('/',1)[-1].lower() not in ('python.exe','pythonw.exe'):
            raise ControlError('VIEWER_TCP_OWNER_NOT_PYTHON')
        if process.created>first['backend_start']:raise ControlError('VIEWER_PROCESS_IDENTITY_CHANGED')
        if not same_lease(first,lease()) or owner(first['client_port'])!=pid:
            raise ControlError('VIEWER_LEASE_OR_TCP_OWNER_CHANGED')
        result={'status':'VIEWER_WORKER_IDENTIFIED','python_pid':pid,'postgres_backend_pid':first['pid'],
            'process_stopped':False,'checkpoint_seek_performed':False,'committed_data_deleted':False}
        if stop:
            process.terminate()
            # A long SQL operation may not notice a lost TCP client yet. Only
            # its unchanged, verified lease may be terminated through PG.
            remaining=lease()
            result.update(process_stopped=True,client_process_observed=True)
            if same_lease(first,remaining):
                result['backend_termination_acknowledged']=bool(cleanup(first))
            elif remaining is not None:
                result.update(status='VIEWER_STOP_BLOCKED_REPLACEMENT_OWNER',postgres_lock_released=False,
                              replacement_postgres_backend_pid=remaining.get('pid'))
                return result
            return observe_release(lease,first,result,timeout=release_timeout,clock=clock,wait=wait)
        return result
    finally:process.close()


def main(argv=None):
    parser=argparse.ArgumentParser(description=__doc__)
    default_project=Path.cwd() if __file__ in ('<stdin>','-') else Path(__file__).resolve().parents[1]
    parser.add_argument('--project-root',type=Path,default=default_project)
    parser.add_argument('--stop',action='store_true')
    args=parser.parse_args(argv);project=args.project_root.resolve();root=project/'AnomalyDetection'
    stage='verify_platform'
    try:
        if os.name!='nt':raise ControlError('WINDOWS_OWNER_HOST_REQUIRED')
        stage='verify_ad_build'
        launcher=runpy.run_path(str(root/'run_anomaly.py'));launcher['verify_build']()
        sys.path.insert(0,str(root));sys.meta_path.insert(0,launcher['VerifiedApplicationFinder']())
        from anomaly_detection.pg_source import read_database_config,installed_source_identity
        stage='verify_viewer_source'
        installed_source_identity(project)
        stage='read_database_config'
        params=read_database_config(project/'viewer_config.local.py')
        if str(params.get('host','localhost')).lower() not in ('localhost','127.0.0.1','::1'):
            raise ControlError('LOCAL_POSTGRESQL_REQUIRED')
        for key in ('options','application_name','autocommit','row_factory'):params.pop(key,None)
        params.update(connect_timeout=3,application_name='P24.Viewer.control',
            options='-c default_transaction_read_only=on -c statement_timeout=7000 -c lock_timeout=100')
        import psycopg
        from psycopg.rows import dict_row
        stage='connect_postgresql'
        with psycopg.connect(**params,autocommit=True,row_factory=dict_row) as conn:
            stage='verify_local_postgresql'
            guard=conn.execute(GUARD_SQL).fetchone()
            if guard['db']!='p24_design_viewer' or not guard['address'] or not loopback(guard['address']):
                raise ControlError('LOCAL_VIEWER_DATABASE_REQUIRED')
            def lease():
                rows=conn.execute(LEASE_SQL).fetchall()
                if len(rows)>1:raise ControlError('MULTIPLE_VIEWER_LOCK_OWNERS')
                return dict(rows[0]) if rows else None
            def cleanup(value):
                return terminate_lease(conn,value)
            stage='identify_and_control_viewer'
            result=control(lease,lambda port:tcp_owner(port,guard['port']),
                lambda pid:WindowsProcess(pid,allow_stop=args.stop),cleanup,stop=args.stop)
        print(json.dumps(result))
        if args.stop and result['status'] not in ('VIEWER_WORKER_STOPPED','VIEWER_BACKEND_STOPPED','NO_VIEWER_LOCK_OWNER_OBSERVED'):
            return 2
        return 0
    except Exception as exc:
        result={'status':'VIEWER_CONTROL_BLOCKED','stage':stage,'error_type':type(exc).__name__}
        if isinstance(exc,ControlError):result['code']=str(exc)
        for key in ('errno','winerror'):
            if type(getattr(exc,key,None)) is int:result[key]=getattr(exc,key)
        print(json.dumps(result));return 2


if __name__=='__main__':raise SystemExit(main())
