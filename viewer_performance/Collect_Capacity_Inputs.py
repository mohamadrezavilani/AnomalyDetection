"""Archive four existing verified captures. No DB, ES, worker or source writes.

May be executed from stdin with --project: only installed, version-checked
Viewer validation functions are used. Private config is parsed, never executed.
"""
from __future__ import annotations

import argparse
import ast
from datetime import datetime,timezone
import gc
import gzip
import hashlib
import json
from pathlib import Path
import sys
import uuid
import zipfile

EXPECTED_RUNTIME='1d74f48374eca46bb4d71592ced7461231d3b42d9d5446c0eb3bf96adac5df3f'
MAX_CAPTURE_BYTES=32*1024**2
MAX_EXPANDED_BYTES=192*1024**2
MAX_BUNDLE_BYTES=96*1024**2
FIVE=300_000_000_000


def capture_directory(project,explicit=None):
    if explicit is not None:return explicit.resolve()
    cfg=project/'viewer_config.local.py'
    value='private/viewer_captures'
    if cfg.is_file():
        tree=ast.parse(cfg.read_text(encoding='utf-8-sig'))
        for node in tree.body:
            if isinstance(node,ast.Assign) and any(isinstance(n,ast.Name) and n.id=='LIVE' for n in node.targets):
                try:live=ast.literal_eval(node.value)
                except (ValueError,TypeError):raise ValueError('capture_dir_requires_explicit_argument') from None
                if not isinstance(live,dict):raise ValueError('invalid_live_config')
                value=live.get('capture_dir',value)
    if not isinstance(value,str):raise ValueError('invalid_capture_dir')
    path=Path(value).expanduser()
    return (path if path.is_absolute() else project/path).resolve()


def select_run(candidates,count=4):
    by_start={}
    for item in candidates:
        by_start.setdefault(item['start_ns'],item)
    for end in sorted(by_start,reverse=True):
        starts=[end-(count-1-i)*FIVE for i in range(count)]
        if all(start in by_start for start in starts):return [by_start[start] for start in starts]
    return []


def collect(project,*,capture_dir=None):
    project=project.resolve();sys.path.insert(0,str(project))
    from p24_foundation.viewer_runtime import runtime_source_digest
    from p24_foundation.viewer_online import _read_verified_capture,utc_ns
    if runtime_source_digest(project)!=EXPECTED_RUNTIME:
        raise ValueError('installed_viewer_is_not_the_recorded_baseline')
    directory=capture_directory(project,capture_dir)
    if not directory.is_dir():raise ValueError('capture_directory_not_found')
    files=sorted((p for p in directory.glob('*.gz') if p.is_file()
        and p.resolve().is_relative_to(directory)),key=lambda p:p.stat().st_mtime_ns,reverse=True)[:12]
    candidates=[];skipped=0
    for path in files:
        if path.stat().st_size>MAX_CAPTURE_BYTES:
            skipped+=1;continue
        try:
            with gzip.open(path,'rb') as stream:raw=stream.read(MAX_EXPANDED_BYTES+1)
            if len(raw)>MAX_EXPANDED_BYTES:
                skipped+=1;del raw;continue
            data=json.loads(raw);del raw
            start=utc_ns(data.get('window_start'));end=utc_ns(data.get('window_end'))
            del data;gc.collect()
            proof,payload=_read_verified_capture(path,start,end)
            del payload;gc.collect()
            candidates.append(dict(path=path,start_ns=start,end_ns=end,sha256=proof['sha256'],
                records=proof['records'],compressed_bytes=path.stat().st_size))
        except (ValueError,OSError,EOFError,KeyError,TypeError):
            skipped+=1;continue
        chosen=select_run(candidates)
        if chosen:break
    else:chosen=[]
    if not chosen:raise ValueError('four_contiguous_verified_captures_not_found')
    if sum(x['compressed_bytes'] for x in chosen)>MAX_BUNDLE_BYTES:
        raise ValueError('capture_bundle_byte_budget_exceeded')
    reports=project/'AnomalyDetection/reports';reports.mkdir(parents=True,exist_ok=True)
    out=reports/('Viewer_Capacity_Inputs_'+datetime.now(timezone.utc).strftime('%Y%m%d_%H%M%S_')+uuid.uuid4().hex[:8]+'.zip')
    temporary=out.with_suffix('.tmp')
    manifest=dict(runtime_source_sha256=EXPECTED_RUNTIME,selection='latest_observed_contiguous_verified_run',
        traffic_representativeness='NOT_ESTABLISHED',source_finality='NOT_ESTABLISHED',
        database_modified=False,installation_source_modified=False,workers_restarted=False,
        scanned_files=len(candidates)+skipped,captures=[])
    try:
        with zipfile.ZipFile(temporary,'x',compression=zipfile.ZIP_STORED) as archive:
            for item in chosen:
                name=item['path'].name
                digest=hashlib.sha256()
                with item['path'].open('rb') as source,archive.open(name,'w') as target:
                    for block in iter(lambda:source.read(1024**2),b''):
                        target.write(block);digest.update(block)
                if digest.hexdigest()!=item['sha256']:
                    raise ValueError('capture_changed_during_export')
                manifest['captures'].append({**{k:v for k,v in item.items() if k!='path'},'archive_name':name})
            archive.writestr('manifest.json',json.dumps(manifest,indent=2))
        temporary.replace(out)
    finally:
        if temporary.exists():temporary.unlink()
    return dict(status='VERIFIED_CAPACITY_INPUTS_EXPORTED',output=str(out),files=len(chosen),
        database_modified=False,installation_source_modified=False,workers_restarted=False)


def main(argv=None):
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--project',type=Path,required=True)
    parser.add_argument('--capture-dir',type=Path)
    args=parser.parse_args(argv)
    try:result=collect(args.project,capture_dir=args.capture_dir)
    except Exception as exc:
        result=dict(status='CAPACITY_INPUTS_NOT_EXPORTED',error_type=type(exc).__name__,
            code=str(exc) if isinstance(exc,ValueError) else None,database_modified=False)
    print(json.dumps(result))
    return 0 if result['status']=='VERIFIED_CAPACITY_INPUTS_EXPORTED' else 2


if __name__=='__main__':raise SystemExit(main())
