"""Resume Viewer, optionally filling missing history with its own durable cursor.

No global PostgreSQL setting, data model, index, source cursor or durability
flag is changed. History replay preserves the main publication high-watermark.
This uses the ordinary publication/late-evidence pipeline.
"""
from contextlib import contextmanager
import argparse
import json
import os
from pathlib import Path
import sys

MIB=1024**2
GIB=1024**3
PRESERVE=('fsync','full_page_writes','synchronous_commit','wal_level','shared_buffers','statement_timeout','lock_timeout')
NAMES=('work_mem','temp_buffers','jit','wal_compression',*PRESERVE)
SETTINGS_SQL='SELECT name,setting,unit FROM pg_settings WHERE name=ANY(%s)'


def memory_limits(memory):
    # A single writer, at most 128 MiB of temp pages and 64 MiB per sort/hash
    # operation. The reserve covers multiple plan nodes and the rest of PG.
    available=min(int(memory['available_bytes']),int(memory['total_bytes']))
    if available>=6*GIB:return {'work_mem':'64MB','temp_buffers':'128MB'}
    if available>=2*GIB:return {'work_mem':'16MB','temp_buffers':'64MB'}
    return {}


def bytes_setting(row):
    return int(row['setting'])*{None:1,'B':1,'kB':1024,'8kB':8192,'MB':MIB,'GB':GIB}[row['unit']]


def choose_overrides(before,memory,compression):
    result={'jit':'off'} if before['jit']['setting']!='off' else {}
    for name,value in memory_limits(memory).items():
        target=int(value[:-2])*MIB
        if bytes_setting(before[name])<target:result[name]=value
    if compression and before['wal_compression']['setting']!=compression:result['wal_compression']=compression
    return result


def connection_options(original,overrides):
    output=dict(original)
    if not str(output.get('dbname','')).startswith('p24_design_'):
        raise ValueError('viewer_database_required')
    valid={'work_mem':{'16MB','64MB'},'temp_buffers':{'64MB','128MB'},'jit':{'off'},'wal_compression':{'zstd','lz4','pglz'}}
    if any(name not in valid or value not in valid[name] for name,value in overrides.items()):
        raise ValueError('invalid_catchup_override')
    output['options']=' '.join(filter(None,(str(output.get('options') or ''),
        ' '.join('-c '+name+'='+value for name,value in overrides.items()))))
    output['application_name']='P24.Viewer.catchup'
    return output


def supported_compression(connection):
    """Probe in short READ ONLY transactions before any publication.

    Keep an already active supported compressor. Try zstd first for entropy in hex/text index pages,
    then lz4 and pglz when a build lacks a codec. A role lacking SET privilege retains its current mode.
    """
    with connection.transaction():
        connection.execute('SET TRANSACTION READ ONLY')
        current=connection.execute("SELECT current_setting('wal_compression') AS value").fetchone()['value']
    if current in ('lz4','pglz','zstd'):return current
    for candidate in ('zstd','lz4','pglz'):
        try:
            with connection.transaction():
                connection.execute('SET TRANSACTION READ ONLY')
                connection.execute("SELECT set_config('wal_compression',%s,true)",(candidate,))
            return candidate
        except Exception as exc:
            if getattr(exc,'sqlstate',None)=='42501':return None
            if getattr(exc,'sqlstate',None) not in ('0A000','22023'):raise
    return None


@contextmanager
def activate_profile(module,before,overrides,*,notice=lambda value:None):
    original=module.ViewerDB.__init__
    def init(db,*args,**kwargs):
        if kwargs.get('sqlite_path') is not None:raise ValueError('live_postgresql_required')
        kwargs=dict(kwargs);kwargs['config']=connection_options(kwargs.get('config') or {},overrides)
        original(db,*args,**kwargs)
        try:
            actual={r['name']:r for r in db.all(SETTINGS_SQL.replace('%s','?'),(list(NAMES),))}
            if any(actual[name]['setting']!=before[name]['setting'] for name in PRESERVE):
                raise ValueError('protected_writer_setting_changed')
            for name,value in overrides.items():
                if name in ('work_mem','temp_buffers'):
                    if bytes_setting(actual[name])!=int(value[:-2])*MIB:raise ValueError('writer_profile_not_active')
                elif actual[name]['setting']!=value:raise ValueError('writer_profile_not_active')
            db.conn.rollback()
            notice({'status':'VIEWER_CATCHUP_PROFILE_VERIFIED','backend_pid':db.conn.info.backend_pid,
                'settings':{n:actual[n] for n in NAMES},'global_settings_modified':False,
                'durability_flags_changed':False,'startup_mode':'RESUME_CHECKPOINT'})
        except BaseException:
            db.close();raise
    module.ViewerDB.__init__=init
    try:yield
    finally:module.ViewerDB.__init__=original


def main(argv=None):
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--project-root',type=Path,default=Path(__file__).resolve().parents[1])
    parser.add_argument('--from-tehran-date',metavar='YYYY-MM-DD',help='Replay missing history from this date, then resume live publication')
    args=parser.parse_args(argv);root=args.project_root.resolve();sys.path.insert(0,str(root));os.chdir(root)
    try:
        from viewer_performance.Run_Viewer_Memory import memory_info,BASE_RUNTIME
        from viewer_performance.Run_Viewer_Web import existing_options
        from p24_foundation.viewer_runtime import runtime_source_digest
        from tools.check_viewer_install import verify_release
        if runtime_source_digest(root)!=BASE_RUNTIME or verify_release(root)['status']!='PASS':
            raise ValueError('viewer_release_mismatch')
        options=existing_options(root)
        if options.get('sqlite_path') or options['config'].get('dbname')!='p24_design_viewer':
            raise ValueError('local_viewer_postgresql_required')
        config=options['config']
        if str(config.get('host','localhost')).lower() not in ('localhost','127.0.0.1','::1'):
            raise ValueError('local_viewer_postgresql_required')
        memory=memory_info()
        import psycopg
        from psycopg.rows import dict_row
        params=dict(config)
        for name in ('autocommit','row_factory'):params.pop(name,None)
        params.update(connect_timeout=3,application_name='P24.Viewer.catchup.preflight')
        with psycopg.connect(**params,autocommit=True,row_factory=dict_row) as connection:
            connection.execute('SET default_transaction_read_only=on')
            before={r['name']:r for r in connection.execute(SETTINGS_SQL,(list(NAMES),)).fetchall()}
            if any(before[name]['setting']!='on' for name in ('fsync','full_page_writes','synchronous_commit')):
                raise ValueError('durability_preflight_failed')
            compression=supported_compression(connection)
        overrides=choose_overrides(before,memory,compression)
        print(json.dumps({'status':'VIEWER_CATCHUP_STARTING','selected_overrides':overrides,
            'available_memory_bytes':memory['available_bytes'],'runtime_source_sha256':BASE_RUNTIME,
            'checkpoint_seek_performed':False}),flush=True)
        from p24_foundation import viewer_data
        from tools.run_behavior_viewer import main as runner
        with activate_profile(viewer_data,before,overrides,notice=lambda value:print(json.dumps(value),flush=True)):
            from viewer_performance.history_replay import pending_day,run as replay_history
            if args.from_tehran_date:day=args.from_tehran_date
            else:
                with viewer_data.ViewerDB(**options) as probe:day=pending_day(probe)
            if day:replay_history(root,day)
            previous=sys.argv
            sys.argv=['run_behavior_viewer.py','live','--config',str(root/'viewer_config.local.py'),'--progress','--resume-checkpoint']
            try:runner()
            finally:sys.argv=previous
        return 0
    except KeyboardInterrupt:return 130
    except Exception as exc:
        print(json.dumps({'status':'VIEWER_CATCHUP_START_FAILED','error_type':type(exc).__name__,
            'code':str(exc) if isinstance(exc,ValueError) else None,'sqlstate':getattr(exc,'sqlstate',None)}));return 2


if __name__=='__main__':raise SystemExit(main())
