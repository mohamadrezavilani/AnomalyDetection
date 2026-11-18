"""Bounded physical-copy ownership and phase guards; never adopt an unknown DB."""
from contextlib import contextmanager
import json
import hashlib
import os
from pathlib import Path
import re
import shutil
import threading
import time
import uuid
from p24_foundation.viewer_runtime import atomic_json
from viewer_performance.financial_screen.resources import available_memory,process_usage


def behavior_sources():
    root=Path(__file__).resolve().parents[1]
    paths=list((root/'viewer_performance').glob('behavior_*.py'))
    paths += [root/p for p in ('viewer_performance/Behavior_Control.py','viewer_performance/Behavior_Release.py',
        'viewer_performance/Install_Behavior.ps1','RELEASE_MANIFEST.json','viewer_performance/FAST_WRITER_MANIFEST.json')]
    files={p.relative_to(root).as_posix():hashlib.sha256(p.read_bytes()).hexdigest() for p in sorted(set(paths))}
    return dict(files_sha256=files,source_sha256=hashlib.sha256(json.dumps(files,sort_keys=True).encode()).hexdigest())


def wal_codec(admin):
    values=admin.execute("SELECT enumvals FROM pg_settings WHERE name='wal_compression'").fetchone()['enumvals']
    for codec in ('zstd','lz4','pglz'):
        if codec in values:return codec
    raise ValueError('SUPPORTED_WAL_COMPRESSION_UNAVAILABLE')


class PhaseBudget:
    """Monitor capture/copy/oracle too, not just the timed publication lane.

    SQL has a server statement timeout as well. Samples are bounded; transient
    peaks between samples are not claimed to be hard OS memory limits.
    """
    def __init__(self,guard,deadline,*,connection=None,disk=None,reserve=8*1024**3,interval=1):
        self.guard,self.deadline,self.connection,self.disk,self.reserve=guard,deadline,connection,disk,reserve
        self.interval=interval;self.done=threading.Event();self.failure=None;self.peak=0;self.samples=0
    def check(self):
        if self.failure:raise self.failure
        self.guard()
        if time.monotonic()>=self.deadline:raise TimeoutError('BEHAVIOR_PHASE_BUDGET_EXHAUSTED')
        memory=available_memory();usage=process_usage(os.getpid())
        if memory is not None and memory<4*1024**3:raise ValueError('BEHAVIOR_OS_MEMORY_RESERVE_REACHED')
        if usage['status']=='READ':
            self.peak=max(self.peak,usage['rss_bytes'])
            if usage['rss_bytes']>2*1024**3:raise ValueError('BEHAVIOR_CLIENT_MEMORY_BUDGET_EXCEEDED')
        if self.disk and shutil.disk_usage(self.disk).free<self.reserve:raise ValueError('BEHAVIOR_DISK_RESERVE_REACHED')
        self.samples+=1
    def observe(self):
        while not self.done.wait(self.interval):
            try:self.check()
            except Exception as exc:
                self.failure=exc
                if self.connection:
                    try:self.connection.cancel()
                    except Exception:pass
                return
    def __enter__(self):
        self.check()
        self.thread=threading.Thread(target=self.observe,daemon=True);self.thread.start();return self
    def __exit__(self,*args):
        self.done.set();self.thread.join(35)
        if self.thread.is_alive():raise ValueError('BEHAVIOR_MONITOR_DID_NOT_STOP')
        if self.failure:raise self.failure
        if not any(args):self.check()


class CopyOwner:
    def __init__(self,admin,source,directory,guard,deadline):
        self.admin,self.source,self.guard,self.deadline=admin,source,guard,deadline
        self.path=Path(directory)/'allocations.json';self.run_id=uuid.uuid4().hex
        self.state=dict(version=1,run_id=self.run_id,source=source,allocations=[])
        # Never overwrite another run's recovery receipt.
        with self.path.open('x',encoding='utf-8') as stream:json.dump(self.state,stream)
    def save(self):atomic_json(self.path,self.state)
    def timeout(self,deadline):
        remaining=deadline-time.monotonic()
        if remaining<=0:raise TimeoutError('BEHAVIOR_ALLOCATION_BUDGET_EXHAUSTED')
        self.admin.execute("SELECT set_config('statement_timeout',%s,false),set_config('lock_timeout','10000',false)",
                           (str(max(1,int(remaining*1000))),))
    @staticmethod
    def validate(state):
        run=state.get('run_id','')
        if not re.fullmatch('[0-9a-f]{32}',run) or state.get('version')!=1:raise ValueError('INVALID_ALLOCATION_RECEIPT')
        for index,row in enumerate(state['allocations']):
            expected='p24_design_capacity_fs_'+run[:16]+'_'+str(index)+'_qualification'
            if row.get('name')!=expected:raise ValueError('ALLOCATION_NAME_NOT_OWNED')
    def drop(self,row,deadline):
        from psycopg import sql
        self.validate(self.state);self.timeout(deadline)
        actual=self.admin.execute("SELECT oid,shobj_description(oid,'pg_database') AS tag FROM pg_database WHERE datname=%s",(row['name'],)).fetchone()
        if actual is None:row['state']='DROPPED';self.save();return
        if row.get('oid')!=actual['oid'] or actual['tag']!='P24.BehaviorBenchmark:'+self.run_id:
            row['state']='AMBIGUOUS_NOT_DROPPED';self.save();raise ValueError('ALLOCATION_OWNERSHIP_NOT_PROVEN')
        # Closing a client socket precedes the server backend's catalog exit.
        # Briefly drain that normal race. A surviving observer still blocks;
        # no pg_terminate_backend and no DROP FORCE are used.
        until=min(deadline,time.monotonic()+5)
        while self.admin.execute('SELECT 1 FROM pg_stat_activity WHERE datname=%s LIMIT 1',(row['name'],)).fetchone():
            if time.monotonic()>=until:raise ValueError('OWNED_COPY_HAS_SESSIONS_NO_FORCE_DROP')
            time.sleep(.05)
        self.admin.execute(sql.SQL('DROP DATABASE {}').format(sql.Identifier(row['name'])))
        row['state']='DROPPED';self.save()
    @contextmanager
    def clone(self):
        from psycopg import sql
        self.guard();self.timeout(self.deadline)
        if self.admin.execute('SELECT 1 FROM pg_stat_activity WHERE datname=%s LIMIT 1',(self.source,)).fetchone():
            raise ValueError('TEMPLATE_HAS_ACTIVE_SESSIONS')
        row=dict(name='p24_design_capacity_fs_'+self.run_id[:16]+'_'+str(len(self.state['allocations']))+'_qualification',state='ALLOCATING',oid=None)
        if self.admin.execute('SELECT 1 FROM pg_database WHERE datname=%s',(row['name'],)).fetchone():
            raise ValueError('ALLOCATION_ALREADY_EXISTS_NOT_ADOPTED')
        self.state['allocations'].append(row);self.save();clock=time.monotonic()
        # Receipt precedes CREATE. A crash before recording the returned OID/tag
        # leaves an explicitly ambiguous allocation, never a guessed DROP target.
        self.admin.execute(sql.SQL('CREATE DATABASE {} TEMPLATE {} STRATEGY FILE_COPY').format(sql.Identifier(row['name']),sql.Identifier(self.source)))
        row['oid']=self.admin.execute('SELECT oid FROM pg_database WHERE datname=%s',(row['name'],)).fetchone()['oid']
        row['state']='CREATED_UNTAGGED';self.save()
        self.admin.execute(sql.SQL('COMMENT ON DATABASE {} IS {}').format(sql.Identifier(row['name']),sql.Literal('P24.BehaviorBenchmark:'+self.run_id)))
        row.update(state='OWNED',copy_seconds=time.monotonic()-clock);self.save()
        try:yield row
        finally:self.drop(row,time.monotonic()+300)
    def cleanup(self):
        failures=[];until=time.monotonic()+300
        for row in self.state['allocations']:
            if row['state']=='DROPPED':continue
            try:self.drop(row,until)
            except Exception as exc:failures.append(dict(name=row['name'],error_type=type(exc).__name__,code=str(exc) if isinstance(exc,(ValueError,TimeoutError)) else None))
        return failures
    @classmethod
    def recover(cls,admin,path):
        path=Path(path)
        if path.stat().st_size>1024*1024:raise ValueError('ALLOCATION_RECEIPT_TOO_LARGE')
        obj=object.__new__(cls);obj.admin=admin;obj.path=path;obj.state=json.loads(path.read_text());obj.validate(obj.state)
        obj.run_id=obj.state['run_id'];return obj.cleanup()
