"""Read-only readiness check: release bytes, private binding and pilot evidence."""
from __future__ import annotations
import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import sys
ROOT=Path(__file__).resolve().parents[1];sys.path.insert(0,str(ROOT))
from p24_foundation.viewer_data import ViewerDB,utc_ns
from p24_foundation.viewer_online import live_status,checked_window,FIVE_NS
from p24_foundation.viewer_elastic import stream_key
from p24_foundation.viewer_runtime import runtime_source_digest,atomic_json
from p24_foundation.viewer_acceptance import evaluate_pilot
from p24_foundation.viewer_failure import describe_failure


def verify_release(root):
    root=Path(root);manifest_path=root/'RELEASE_MANIFEST.json'
    if not manifest_path.is_file():raise ValueError('release_manifest_missing')
    manifest=json.loads(manifest_path.read_text(encoding='utf-8-sig'))
    mismatches=[];checked=0
    for name,expected in manifest['files_sha256'].items():
        path=Path(name)
        if path.is_absolute() or '..' in path.parts:raise ValueError('invalid_release_manifest_path')
        if name.startswith('validation/') or path.suffix in ('.md','.diff'):continue
        checked+=1;target=root/path
        if not target.is_file() or hashlib.sha256(target.read_bytes()).hexdigest()!=expected:mismatches.append(name)
    if not checked:raise ValueError('empty_release_manifest')
    return dict(status='PASS' if not mismatches else 'FAIL',checked_files=checked,mismatches=mismatches)


def pilot_evidence(path):
    path=Path(path)
    if not path.is_file():return dict(status='NOT_RUN')
    try:
        report=json.loads(path.read_text(encoding='utf-8-sig'));checks=evaluate_pilot(report)
        same=report.get('runtime_source_sha256')==runtime_source_digest()
        accepted=(report.get('mode')=='live_owner_postgresql_pilot' and report.get('status')=='PASS' and
                  all(checks.values()) and same)
        return dict(status='PASS' if accepted else 'PENDING',reported_status=report.get('status'),
                    same_runtime_source=same,checks=checks)
    except (OSError,ValueError,TypeError,KeyError):return dict(status='UNREADABLE')


def check(config,*,root=ROOT,pilot=None):
    result=dict(status='FAILED',mode='read_only_viewer_installation_check',permanent_data_modified=False)
    try:
        result['release']=verify_release(root)
        if result['release']['status']!='PASS':return result
        config=Path(config).resolve()
        if not config.is_file():raise ValueError('private_config_missing')
        spec=importlib.util.spec_from_file_location('viewer_install_private',config)
        cfg=importlib.util.module_from_spec(spec);spec.loader.exec_module(cfg)
        if getattr(cfg,'SQLITE_OFFLINE_PATH',None):raise ValueError('live_installation_requires_postgresql')
        if not str(cfg.DATABASE.get('dbname','')).startswith('p24_design_'):
            raise ValueError('guard_use_viewer_database')
        keys=Path(cfg.KEYS_PATH).expanduser().resolve()
        if not keys.is_file():raise ValueError('existing_private_keys_missing')
        start=utc_ns(getattr(cfg,'LIVE_START_UTC',None))
        checked_window(start,start+FIVE_NS if isinstance(start,int) else None)
        connection=dict(cfg.DATABASE);connection.setdefault('connect_timeout',10)
        with ViewerDB(config=connection,keys_path=keys) as db:
            db.sql('SET TRANSACTION ISOLATION LEVEL REPEATABLE READ, READ ONLY')
            db.sql('SET LOCAL statement_timeout=10000')
            state=db.one('SELECT * FROM viewer_live_state WHERE id=1')
            if not state:raise ValueError('viewer_live_stream_not_initialized')
            if state['keys_fingerprint']!=db.keys.fingerprint:raise ValueError('existing_private_keys_mismatch')
            if state['start_ns']!=start or state['stream_key']!=stream_key(cfg.ELASTICSEARCH):
                raise ValueError('live_stream_or_keys_changed')
            result['live']=live_status(db)
            result['service_catalog']=db.service_catalog_status()
        result['pilot']=pilot_evidence(pilot or Path(root)/'validation/live_acceptance.json')
        result['status']='READY_TO_START'
        result['operational_acceptance']='ACCEPTED' if result['pilot']['status']=='PASS' else 'PENDING_NATIVE_PILOT'
        result['runtime_source_sha256']=runtime_source_digest()
    except Exception as exc:
        allowed={'release_manifest_missing','invalid_release_manifest_path','empty_release_manifest',
            'private_config_missing','live_installation_requires_postgresql','guard_use_viewer_database',
            'existing_private_keys_missing','viewer_live_stream_not_initialized','existing_private_keys_mismatch',
            'live_stream_or_keys_changed','invalid_closed_window'}
        result['failure']=dict(code=str(exc)) if isinstance(exc,ValueError) and str(exc) in allowed else describe_failure(exc,stage='installation_check')
    return result


def main(argv=None):
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--config',type=Path,required=True)
    parser.add_argument('--out',type=Path,default=Path('validation/installation_check.json'))
    args=parser.parse_args(argv)
    report=check(args.config);atomic_json(args.out,report)
    print(json.dumps(report,ensure_ascii=True,indent=2))
    return 0 if report['status']=='READY_TO_START' else 2


if __name__=='__main__':raise SystemExit(main())
