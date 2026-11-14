"""Conservative session-memory candidate for the existing LogManagment Viewer.

Default: exactly ONE ordinary next window, bounded by the existing five-minute
profile deadline. No checkpoint seek. --worker runs continuously with the
already-authorized recent-start policy; add --resume-checkpoint to resume.

No source/config files, server settings, indexes, retention checks, timeout or
durability settings are changed. Only this process's Viewer connections get a
memory profile. Binary COPY keeps its exact bytes/order; its spool stays in RAM
up to 128 MiB, then falls back to the existing disk-spool behavior.
"""
from __future__ import annotations
import argparse
from contextlib import contextmanager
import ctypes
from datetime import datetime,timezone
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import sys
import uuid
import zipfile

BASE_RUNTIME='ffb883f6f8cc8deef5a8aa104b39186d4ed60ede1605695f5b9f267fcf4bbd33'
PROFILE_ID='viewer-memory-candidate-20261102-1'
MIB=1024**2
GIB=1024**3
TARGETS={'work_mem':('64MB',64*MIB),'temp_buffers':('128MB',128*MIB),
         'effective_cache_size':('96GB',96*GIB)}
PRESERVE=('fsync','full_page_writes','synchronous_commit','wal_level',
          'statement_timeout','lock_timeout')
NAMES=tuple(TARGETS)+('jit','shared_buffers')+PRESERVE
SETTINGS_SQL="SELECT name,setting,unit FROM pg_settings WHERE name=ANY(%s) ORDER BY name"


class ProfileError(RuntimeError):
    pass


def memory_info():
    if os.name!='nt':
        raise ProfileError('windows_owner_host_required')
    class MemoryStatus(ctypes.Structure):
        _fields_=[('length',ctypes.c_ulong),('load',ctypes.c_ulong),
          ('total',ctypes.c_ulonglong),('available',ctypes.c_ulonglong),
          ('page_total',ctypes.c_ulonglong),('page_available',ctypes.c_ulonglong),
          ('virtual_total',ctypes.c_ulonglong),('virtual_available',ctypes.c_ulonglong),
          ('extended_available',ctypes.c_ulonglong)]
    value=MemoryStatus();value.length=ctypes.sizeof(value)
    if not ctypes.windll.kernel32.GlobalMemoryStatusEx(ctypes.byref(value)):
        raise ProfileError('memory_status_unavailable')
    return {'total_bytes':value.total,'available_bytes':value.available}


def check_memory(info):
    if info['total_bytes']<128*GIB or info['available_bytes']<16*GIB:
        raise ProfileError('insufficient_memory_for_this_owner_profile')


def byte_value(row):
    factor={None:1,'B':1,'kB':1024,'8kB':8192,'MB':MIB,'GB':GIB}[row['unit']]
    return int(row['setting'])*factor


def profile_options(before):
    chosen={name:value for name,(value,target) in TARGETS.items()
            if byte_value(before[name])<target}
    if before['jit']['setting']!='off':
        chosen['jit']='off'
    return chosen


def connection_options(original, chosen):
    output=dict(original)
    if output.get('dbname')!='p24_design_viewer':
        raise ProfileError('only_p24_design_viewer_allowed')
    if str(output.get('host','localhost')).lower() not in ('localhost','127.0.0.1','::1'):
        raise ProfileError('local_owner_postgres_required')
    if set(chosen)-set(TARGETS)-{'jit'}:
        raise ProfileError('invalid_profile_parameter')
    additions=[]
    for name,value in chosen.items():
        expected='off' if name=='jit' else TARGETS[name][0]
        if value!=expected:
            raise ProfileError('invalid_profile_value')
        additions.append('-c '+name+'='+value)
    output['options']=' '.join(filter(None,[str(output.get('options') or ''),' '.join(additions)]))
    output['application_name']='p24-viewer-memory-candidate'
    return output


def spool_factory(original, *, old_limit=8*MIB, new_limit=128*MIB):
    def create(*args,**kwargs):
        args=list(args);kwargs=dict(kwargs)
        limit=args[0] if args else kwargs.get('max_size',0)
        if limit==old_limit:
            if args:args[0]=new_limit
            else:kwargs['max_size']=new_limit
        return original(*args,**kwargs)
    return create


def verify_session(before, after):
    for name in PRESERVE:
        if after[name]['setting']!=before[name]['setting']:
            raise ProfileError('protected_session_setting_changed')
    if after['shared_buffers']['setting']!=before['shared_buffers']['setting']:
        raise ProfileError('server_cache_changed_externally')
    for name,(_,minimum) in TARGETS.items():
        if byte_value(after[name])<minimum:
            raise ProfileError('profile_setting_not_active')
    if after['jit']['setting']!='off':
        raise ProfileError('profile_setting_not_active')


@contextmanager
def activate_profile(module, before, selected, sessions):
    old_init=module.ViewerDB.__init__
    old_spool=module.SpooledTemporaryFile
    def init(db,*args,**kwargs):
        if kwargs.get('sqlite_path') is not None:
            raise ProfileError('live_postgresql_required')
        kwargs=dict(kwargs)
        kwargs['config']=connection_options(kwargs.get('config') or {},selected)
        old_init(db,*args,**kwargs)
        try:
            rows=db.all(SETTINGS_SQL.replace('%s','?'),(list(NAMES),))
            after={row['name']:row for row in rows}
            verify_session(before,after)
            # The constructor has made no application-data writes. End this
            # settings-only read before the existing runner starts initialization.
            db.conn.rollback()
            sessions.append({'backend_pid':db.conn.info.backend_pid,'settings':after})
            if len(sessions)>8:del sessions[:-8]
        except BaseException:
            db.close()
            raise
    module.ViewerDB.__init__=init
    module.SpooledTemporaryFile=spool_factory(old_spool)
    try:
        yield
    finally:
        module.ViewerDB.__init__=old_init
        module.SpooledTemporaryFile=old_spool


def preflight(database):
    import psycopg
    from psycopg.rows import dict_row
    options=connection_options(database,{})
    options['connect_timeout']=min(int(options.get('connect_timeout') or 5),5)
    options.pop('autocommit',None)
    with psycopg.connect(**options,autocommit=True,row_factory=dict_row) as conn:
        conn.execute('SET default_transaction_read_only=on')
        rows=conn.execute(SETTINGS_SQL,(list(NAMES),)).fetchall()
        before={row['name']:row for row in rows}
        if not set(NAMES)<=set(before):raise ProfileError('required_setting_unavailable')
        for name in ('fsync','full_page_writes','synchronous_commit'):
            if before[name]['setting']!='on':raise ProfileError('durability_preflight_failed')
        # Released when this short preflight connection closes. The original
        # runner also enforces the worker lock, covering any subsequent race.
        if not conn.execute('SELECT pg_try_advisory_lock(240026,1) AS ok').fetchone()['ok']:
            raise ProfileError('stop_existing_viewer_worker_first')
        state=conn.execute('''SELECT next_ns,generation FROM public.viewer_live_state WHERE id=1''').fetchone()
        return before,state


def main():
    ap=argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--project-root',type=Path,default=Path.cwd())
    ap.add_argument('--worker',action='store_true',help='Continuous normal worker, recent-start default')
    ap.add_argument('--resume-checkpoint',action='store_true',help='Worker only: retain the normal next cursor')
    args=ap.parse_args()
    if args.resume_checkpoint and not args.worker:
        ap.error('The one-window profile already preserves the checkpoint; this flag is worker-only')
    root=args.project_root.resolve()
    run_id=datetime.now(timezone.utc).strftime('%Y%m%d_%H%M%S_')+uuid.uuid4().hex[:8]
    out=root/'validation'/('viewer_memory_'+run_id+'.json')
    report={'status':'STARTING','profile_id':PROFILE_ID,
      'mode':'continuous_worker' if args.worker else 'one_ordinary_window_memory_candidate',
      'tool_sha256':hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
      'base_source_files_modified':False,'private_config_modified':False,
      'global_settings_modified':False,'postgres_restart_performed':False,
      'normal_publication_may_modify_viewer_data':True,'spool_memory_limit_bytes':128*MIB,
      'old_spool_disk_fallback_preserved':True,'native_speed_improvement':'NOT_YET_PROVEN'}
    exit_code=2
    try:
        if not (root/'viewer_config.local.py').is_file():
            raise ProfileError('run_inside_existing_pishkhan24_project')
        os.chdir(root);sys.path.insert(0,str(root))
        from p24_foundation.viewer_runtime import runtime_source_digest
        report['base_runtime_source_sha256']=runtime_source_digest(root)
        if report['base_runtime_source_sha256']!=BASE_RUNTIME:
            raise ProfileError('unexpected_viewer_runtime')
        report['memory']=memory_info();check_memory(report['memory'])
        spec=importlib.util.spec_from_file_location('private_memory_profile_config',root/'viewer_config.local.py')
        cfg=importlib.util.module_from_spec(spec);spec.loader.exec_module(cfg)
        before,state=preflight(cfg.DATABASE)
        report['settings_before']=before;report['checkpoint_before']=state
        selected=profile_options(before)
        report['selected_session_overrides']=selected
        report['writer_sessions']=[]
        from p24_foundation import viewer_data
        with activate_profile(viewer_data,before,selected,report['writer_sessions']):
            if args.worker:
                from tools.run_behavior_viewer import main as runner
                argv=sys.argv
                sys.argv=['run_behavior_viewer.py','live','--config',str(root/'viewer_config.local.py'),
                  '--progress','--resume-checkpoint' if args.resume_checkpoint else '--debug-recent-start']
                try:runner();exit_code=0
                finally:sys.argv=argv
                report['status']='WORKER_STOPPED'
            else:
                from tools.profile_viewer_window import main as profile
                exit_code=profile(['--config',str(root/'viewer_config.local.py'),
                    '--max-minutes','5','--out',str(out)])
                report['window_profile']=json.loads(out.read_text(encoding='utf-8'))
                report['status']=report['window_profile']['status']
                report['checkpoint_seek_requested']=False
                report['observer_settings_scope']='separate observer connection; writer settings are in writer_sessions'
    except KeyboardInterrupt:
        report['status']='STOPPED';exit_code=130
    except SystemExit as exc:
        report['status']='RUNNER_STOPPED';exit_code=exc.code if isinstance(exc.code,int) else 2
    except Exception as exc:
        report.update(status='FAILED',error_type=type(exc).__name__,sqlstate=getattr(exc,'sqlstate',None))
        if isinstance(exc,ProfileError):report['error_code']=str(exc)
    output=root/'validation'/('viewer_memory_'+run_id+'.zip')
    output.parent.mkdir(parents=True,exist_ok=True)
    with zipfile.ZipFile(output,'w',zipfile.ZIP_DEFLATED) as archive:
        archive.writestr('memory_profile.json',json.dumps(report,ensure_ascii=False,indent=2,default=str))
    print(json.dumps({'status':report['status'],'output':str(output)}))
    return exit_code


if __name__=='__main__':
    raise SystemExit(main())
