"""Safely acquire five-minute ES windows for the isolated Behavior Viewer.

Requires the user's existing export_elastic_evidence.py and elastic_log_fetcher.py
on THEIR machine. Does not import to DB, alter collector, or require credentials here.

Each window: runs the existing exporter, verifies COMPLETE_EXACT_COUNTS,
SHA256, matching window bounds, returned counts, and gzip integrity; copies
only eligible exports to <out-dir>/verified. Retryable failures remain in
<out-dir>/attempts and never enter the import directory.
"""
from __future__ import annotations
import argparse
from datetime import datetime, timedelta, timezone
import gzip
import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import sys

FIVE = timedelta(minutes=5)

def parse_aware(value):
    try:
        dt=datetime.fromisoformat(value.replace('Z','+00:00'))
        if dt.tzinfo is None or dt.utcoffset() is None:raise ValueError()
        dt=dt.astimezone(timezone.utc)
        if dt.minute%5 or dt.second or dt.microsecond:raise ValueError()
        return dt
    except (ValueError,TypeError) as exc:
        raise argparse.ArgumentTypeError('Use aligned ISO 8601 with offset e.g. 2026-10-24T20:00:00+03:30') from exc

def hash_file(path):
    h=hashlib.sha256()
    with path.open('rb') as f:
        for b in iter(lambda:f.read(1024*1024),b''):h.update(b)
    return h.hexdigest()

def gzip_ok(path):
    # Integrity-verify the full gzip stream with bounded memory.
    with gzip.open(path,'rb') as f:
        while f.read(1024*1024):pass

def verify_complete_run(run, start, finish, *, accept_partitions=False):
    manifest=json.loads((run/'export_manifest.json').read_text(encoding='utf-8'))
    if manifest.get('status')!='COMPLETE_EXACT_COUNTS' or manifest.get('completed_windows')!=1 or manifest.get('expected_windows')!=1:
        raise ValueError('export_not_complete')
    windows=manifest.get('windows') or []
    if len(windows)!=1:raise ValueError('exactly_one_window_required')
    entry=windows[0]
    if datetime.fromisoformat(entry['window_start'].replace('Z','+00:00'))!=start or datetime.fromisoformat(entry['window_end'].replace('Z','+00:00'))!=finish:
        raise ValueError('window_bounds_mismatch')
    if entry.get('counts_match') is not True or entry.get('returned_records')!=entry.get('expected_total') or entry.get('unique_origins')!=entry.get('returned_records'):
        raise ValueError('window_counts_not_proven')
    if not entry.get('query_snapshot_complete'):
        if not accept_partitions or entry.get('method')!='checked_time_partitions' or not entry.get('partition_coverage_complete') or entry.get('count_before')!=entry.get('count_after'):
            raise ValueError('no_single_query_snapshot_use_explicit_accept_partitions')
    else:
        if not entry.get('reached_empty_page'):
            raise ValueError('not_reached_empty_page')
    fn=entry.get('file','')
    if not fn.startswith('logs_') or not fn.endswith('.json.gz') or '/' in fn or '\\' in fn:
        raise ValueError('invalid_dump_filename')
    p=run/fn
    if not p.is_file() or hash_file(p)!=entry.get('sha256'):
        raise ValueError('sha256_mismatch')
    gzip_ok(p)
    return p,entry

def main(argv=None):
    ap=argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--export-script',type=Path,required=True,help='Existing export_elastic_evidence.py')
    ap.add_argument('--collector',type=Path,required=True,help='Existing elastic_log_fetcher.py')
    ap.add_argument('--from-date',type=parse_aware,required=True)
    ap.add_argument('--to-date',type=parse_aware,required=True)
    ap.add_argument('--out-dir',type=Path,required=True)
    ap.add_argument('--method',choices=('auto','pit','scroll','partition'),default='auto')
    ap.add_argument('--page-size',type=int,default=2000)
    ap.add_argument('--retries',type=int,default=2,help='Retries after first failure per five-minute window')
    ap.add_argument('--attempt-timeout-seconds',type=int,default=3600,help='Maximum duration of each collector attempt')
    ap.add_argument('--accept-partitions',action='store_true',help='Allow exact-count partitions without a common PIT snapshot; mark NOT_SNAPSHOT_VERIFIED')
    args=ap.parse_args(argv)
    if args.to_date<=args.from_date:ap.error('to-date must be after from-date')
    if args.to_date>datetime.now(timezone.utc)-timedelta(seconds=60):ap.error('to-date must be at least 60 seconds in the past')
    if args.retries<0 or args.retries>10:ap.error('retries must be 0..10')
    if not 120<=args.attempt_timeout_seconds<=86400:ap.error('attempt-timeout-seconds must be 120..86400')
    if not 1<=args.page_size<=10000:ap.error('page-size must be 1..10000')
    exporter=args.export_script.resolve();collector=args.collector.resolve()
    if not exporter.is_file() or not collector.is_file():ap.error('export script or collector does not exist')
    out=args.out_dir.resolve();verified=out/'verified';attempts=out/'attempts'
    verified.mkdir(parents=True,exist_ok=True);attempts.mkdir(parents=True,exist_ok=True)
    index_file=out/'verified_index.json'
    all_index={x['filename']:x for x in json.loads(index_file.read_text('utf-8')).get('windows',[])} if index_file.is_file() else {}
    results=[];current=args.from_date
    while current<args.to_date:
        finish=current+FIVE
        if finish>args.to_date:ap.error('range should consist of full five-minute windows')
        filename='logs_'+current.strftime('%Y%m%d_%H%M%S')+'.json.gz'
        destination=verified/filename
        if destination.is_file():
            # Previously verified file: do not overwrite or silently import an
            # unverified file. The SHA and original proof are recorded in result.
            proof=all_index.get(filename)
            if proof and proof.get('sha256')==hash_file(destination) and proof.get('status') in ('VERIFIED_SNAPSHOT','EXACT_PARTITION_COUNTS_NOT_SNAPSHOT'):
                print(f'{filename}: already verified, skipped',flush=True)
                results.append(proof);current=finish;continue
            print(f'{filename}: EXISTS_WITHOUT_MATCHING_PROOF, refusing overwrite',file=sys.stderr)
            results.append(dict(filename=filename,status='FAILED',reason='existing_unverified_file'))
            current=finish;continue
        result=dict(filename=filename,window_start=current.isoformat(),window_end=finish.isoformat(),status='FAILED')
        for attempt in range(args.retries+1):
            before=set(p.resolve() for p in attempts.glob('run_*') if p.is_dir())
            cmd=[sys.executable,str(exporter),'--collector',str(collector),
                '--from-date',current.isoformat(),'--to-date',finish.isoformat(),
                '--out-dir',str(attempts),'--method',args.method,'--page-size',str(args.page_size)]
            print(f'Export {filename} try {attempt+1}/{args.retries+1}',flush=True)
            try:
                proc=subprocess.run(cmd,check=False,timeout=args.attempt_timeout_seconds)
                after=[p for p in attempts.glob('run_*') if p.is_dir() and p.resolve() not in before]
                if proc.returncode!=0 or len(after)!=1:raise ValueError('export_process_failed_or_missing_run')
                source,proof=verify_complete_run(after[0],current,finish,accept_partitions=args.accept_partitions)
                shutil.copy2(source,destination)
                if hash_file(destination)!=proof['sha256']:
                    destination.unlink(missing_ok=True);raise ValueError('copy_checksum_mismatch')
                result.update(status='VERIFIED_SNAPSHOT' if proof['query_snapshot_complete'] else 'EXACT_PARTITION_COUNTS_NOT_SNAPSHOT',
                              sha256=proof['sha256'],records=proof['returned_records'],method=proof.get('method'),attempts=attempt+1)
                break
            except (OSError,ValueError,subprocess.TimeoutExpired) as exc:
                result['reason']=type(exc).__name__+': '+str(exc)
                print(f'{filename}: not eligible: {result["reason"]}',file=sys.stderr,flush=True)
        results.append(result)
        # index after every window, resumable if a long capture is interrupted
        all_index[result['filename']]=result
        temp=out/'verified_index.json.tmp'
        temp.write_text(json.dumps(dict(status='COMPLETE' if all(r['status']!='FAILED' for r in all_index.values()) else 'PARTIAL',windows=sorted(all_index.values(),key=lambda r:r['filename'])),indent=2),encoding='utf-8')
        temp.replace(index_file)
        current=finish
    ok=[r for r in results if r['status']!='FAILED']
    failed=[r for r in results if r['status']=='FAILED']
    summary=dict(status='COMPLETE' if not failed else 'PARTIAL_EXPORT_NOT_COMPLETE',windows=len(results),eligible=len(ok),failed=len(failed),records=sum(r.get('records',0) for r in ok),verified_dir=str(verified))
    print(json.dumps(summary,ensure_ascii=False,indent=2))
    return 0 if not failed else 2

if __name__=='__main__':raise SystemExit(main())
