"""Serve the existing Viewer without schema/catalog initialization or a worker."""
from __future__ import annotations
import argparse
import ipaddress
import json
from pathlib import Path
import runpy
import sys

REQUIRED=('viewer_requests','viewer_live_state','viewer_semantic_occurrences','viewer_semantic_session_heads')


def existing_options(project):
    values=runpy.run_path(str(project/'viewer_config.local.py'))
    def local_path(value):
        path=Path(value).expanduser()
        return (path if path.is_absolute() else project/path).resolve()
    keys=local_path(values['KEYS_PATH'])
    if not keys.is_file():raise ValueError('existing_viewer_keys_required')
    if values.get('SQLITE_OFFLINE_PATH'):
        path=local_path(values['SQLITE_OFFLINE_PATH'])
        if not path.is_file():raise ValueError('existing_offline_database_required')
        return {'sqlite_path':path,'keys_path':keys}
    database=values['DATABASE']
    if database.get('dbname')!='p24_design_viewer':raise ValueError('only_p24_design_viewer_allowed')
    return {'config':database,'keys_path':keys}


def check_existing(opts,*,database_factory=None):
    if database_factory is None:
        from p24_foundation.viewer_data import ViewerDB
        database_factory=ViewerDB
    with database_factory(**opts) as db:
        if db.sqlite:
            rows=db.all("SELECT name FROM sqlite_master WHERE type='table'")
            present={row['name'] for row in rows}
        else:
            db.sql('SET TRANSACTION READ ONLY')
            db.sql('SET LOCAL statement_timeout=2000')
            db.sql('SET LOCAL lock_timeout=100')
            rows=db.all("SELECT c.relname FROM pg_catalog.pg_class c JOIN pg_catalog.pg_namespace n "
                "ON n.oid=c.relnamespace WHERE n.nspname='public' AND c.relname=ANY(%s)",(list(REQUIRED),))
            present={row['relname'] for row in rows}
        if not set(REQUIRED)<=present:raise ValueError('start_existing_viewer_worker_first')


def serve_existing(opts,*,factory=None,host='127.0.0.1'):
    if factory is None:
        from p24_foundation.viewer_ui import create_viewer_app
        factory=create_viewer_app
    address=ipaddress.ip_address(host)
    if address.is_loopback:app=factory(opts)
    else:app=factory(opts,lan_host=str(address))
    app.run(host=str(address),port=5021,use_reloader=False,debug=False)


def main(argv=None):
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--project-root',type=Path,default=Path(__file__).resolve().parents[1])
    parser.add_argument('--host',default='127.0.0.1',help='Loopback or the server private IPv4 address for LAN access')
    args=parser.parse_args(argv);project=args.project_root.resolve()
    sys.path.insert(0,str(project))
    try:
        from p24_foundation.viewer_runtime import runtime_source_digest
        declared=json.loads((project/'RELEASE_MANIFEST.json').read_text(encoding='utf-8-sig'))['runtime_source_sha256']
        if runtime_source_digest(project)!=declared:raise ValueError('viewer_runtime_manifest_mismatch')
        address=ipaddress.ip_address(args.host)
        if not address.is_loopback and not any(address in ipaddress.ip_network(n) for n in ('10.0.0.0/8','172.16.0.0/12','192.168.0.0/16')):
            raise ValueError('viewer_lan_host_must_be_private_ipv4')
        opts=existing_options(project);check_existing(opts)
        print(json.dumps({'status':'VIEWER_WEB_STARTING','url':f'http://{address}:5021/',
            'schema_initialized':False,'worker_started':False}),flush=True)
        serve_existing(opts,host=str(address))
        return 0
    except KeyboardInterrupt:return 130
    except Exception as exc:
        failure={'error_type':type(exc).__name__}
        if isinstance(exc,ValueError) and str(exc) in ('existing_viewer_keys_required','existing_offline_database_required',
                'only_p24_design_viewer_allowed','start_existing_viewer_worker_first','viewer_runtime_manifest_mismatch',
                'viewer_lan_host_must_be_private_ipv4'):
            failure['code']=str(exc)
        if type(getattr(exc,'errno',None)) is int:failure['errno']=exc.errno
        print(json.dumps({'status':'VIEWER_WEB_START_FAILED','failure':failure}));return 2


if __name__=='__main__':raise SystemExit(main())
