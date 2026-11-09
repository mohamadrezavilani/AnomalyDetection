"""Explicit supervised collection -> publication -> detector -> Persian reports.

Experimental guarded design database only. No source eviction or inferred corrections.
"""
import argparse
from datetime import timedelta
import hashlib
import json
import os
from pathlib import Path
import sys
from types import SimpleNamespace

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))
from p24_foundation.errors import FoundationError
from p24_foundation.pipeline import read_state,run,utc,validate_spec
from p24_foundation.replay import _write_report


def cycle(directory,ordinal):
    """Dedicated child; all in-flight failures require human commit reconciliation."""
    from tools.collector_pipeline import collect,generate_plan
    from tools.detect_behavior import write_report
    from p24_foundation.collector_pipeline import load_plan,publish_plan
    from p24_foundation.config import read_config,connect
    from p24_foundation.privacy import Keys
    from p24_foundation.store import FoundationStore
    from p24_foundation.publication import ObservationPublisher
    from p24_foundation.behavior import publication_window,score
    from p24_foundation.behavior_store import persist_candidates
    spec=validate_spec(read_state(directory/'spec.json'))
    if not 0<=ordinal<spec['windows']:raise FoundationError('invalid_pipeline_ordinal')
    settings=read_config(spec['config']);keys=Keys.read(settings['keys_path'])
    start=utc(spec['start'])+timedelta(minutes=5*ordinal);end=start+timedelta(minutes=5)
    job=directory/f'window_{ordinal:04d}'
    job.mkdir(mode=0o700) # Existing partial job must never be reused automatically.
    phase=lambda name:_write_report(job/'phase.json',dict(phase=name,ordinal=ordinal,production_modified=False))
    phase('capturing')
    capture=job/'capture.json'
    captured=collect(SimpleNamespace(target_root=Path(spec['target_root']),start=start.isoformat(),end=end.isoformat(),
                                    output=capture,max_runtime_seconds=spec['window_timeout_seconds']))
    if captured['status']!='captured':raise FoundationError('pipeline_capture_ineligible')
    with connect(settings['database']) as c:
        store=FoundationStore(c,keys,settings['namespace'],settings['vault_path'])
        publisher=ObservationPublisher(store);_,generation=publisher._current()
        generate_plan(SimpleNamespace(output=job/'plan.json',captures=[capture],replacements=None,stream=spec['stream'],
            index_pattern=spec['index_pattern'],expected_generation=generation,event_cutoff=end.isoformat()))
        plan=load_plan(job/'plan.json')
        phase('publishing')
        published=publish_plan(store,plan)
        # Durable identity before scoring; inspection can distinguish a later report failure.
        _write_report(job/'publication.json',published,create=True)
        refs=[]
        for previous in range(ordinal):
            prior=read_state(directory/f'window_{previous:04d}'/'result.json')
            refs.append({key:prior[key] for key in ['publication_id','start','end']})
        phase('detecting')
        if not refs:
            # No invented zero baseline and no synthetic history for the first window.
            report=dict(status='warming_up',reason='no_prior_pipeline_windows',input_kind='committed_observed_publications',
                        candidates=[],evaluated_units=0,unsupported_units=None,publication_id=published['publication_id'])
            _write_report(job/'report.json',report,create=True)
            descriptor=job/'report.html'
            fd=os.open(descriptor,os.O_CREAT|os.O_EXCL|os.O_WRONLY,0o600)
            with os.fdopen(fd,'w',encoding='utf-8') as output:
                output.write('<!doctype html><html lang="fa" dir="rtl"><meta charset="utf-8"><title>گزارش پنجره</title>'
                             '<h1>در حال تشکیل سابقه رفتاری</h1><p>برای مقایسه با رفتار قبلی، سابقه کافی موجود نیست. این وضعیت به معنی عادی بودن رفتار نیست.</p></html>')
                output.flush();os.fsync(output.fileno())
        else:
            target_spec=dict(publication_id=published['publication_id'],start=start.isoformat(),end=end.isoformat())
            with c.transaction():
                if spec['persist_candidates']:
                    report=persist_candidates(store,target_spec=target_spec,reference_specs=refs,
                        rank_cutoff=spec['rank_cutoff'],expected_generation=published['generation'])
                else:
                    c.execute('SET TRANSACTION ISOLATION LEVEL REPEATABLE READ, READ ONLY')
                    tokenize=lambda route:keys.token(settings['namespace'],'behavior_service',route)
                    target=publication_window(c,store.namespace_id,**target_spec,route_token=tokenize)
                    history=[];requests=0
                    for ref in refs:
                        item=publication_window(c,store.namespace_id,**ref,route_token=tokenize)
                        requests+=sum(map(len,item['groups'].values()))
                        if requests>100000:raise FoundationError('behavior_reference_request_limit')
                        history.append(item)
                    report=score(target,history,rank_cutoff=spec['rank_cutoff'])
                    report['input_kind']='committed_observed_publications'
            phase('writing_reports')
            write_report(job/'report.json',report)
            write_report(job/'report.html',report,format='html')
        result=dict(status='completed',ordinal=ordinal,start=start.isoformat(),end=end.isoformat(),
                    publication_id=published['publication_id'],generation=published['generation'],
                    evidence_scope='observed_only',producer_authority='unverified',
                    workflow_status='unavailable_no_reviewed_adapter',production_modified=False)
        _write_report(job/'result.json',result,create=True)
        phase('completed')
        return dict(status='completed',publication_id=result['publication_id'],generation=result['generation'])


def main(argv=None):
    parser=argparse.ArgumentParser(description=__doc__);sub=parser.add_subparsers(dest='command',required=True)
    start=sub.add_parser('start',help='Run explicit consecutive windows; rerun identical command to resume confirmed progress')
    start.add_argument('--config',type=Path,required=True);start.add_argument('--target-root',type=Path,required=True)
    start.add_argument('--state-dir',type=Path,required=True);start.add_argument('--start',required=True)
    start.add_argument('--windows',type=int,required=True);start.add_argument('--stream',required=True)
    start.add_argument('--index-pattern');start.add_argument('--rank-cutoff',required=True)
    start.add_argument('--lag-seconds',type=int,default=60);start.add_argument('--window-timeout-seconds',type=int,default=180)
    start.add_argument('--persist-candidates',action='store_true')
    status=sub.add_parser('status',help='Read safe progress only; no database or network')
    status.add_argument('--state-dir',type=Path,required=True)
    worker=sub.add_parser('_window',help=argparse.SUPPRESS);worker.add_argument('--state-dir',type=Path,required=True);worker.add_argument('--ordinal',type=int,required=True)
    args=parser.parse_args(argv)
    try:
        if args.command=='status':
            state=read_state(args.state_dir/'state.json')
            result={key:state[key] for key in ['status','completed_windows','in_flight','production_modified']}
        elif args.command=='_window':result=cycle(args.state_dir.resolve(),args.ordinal)
        else:
            from p24_foundation.config import read_config
            from p24_foundation.collector_pipeline import verified_transport
            from p24_foundation.privacy import Keys
            settings=read_config(args.config);Keys.read(settings['keys_path']);verified_transport(args.target_root)
            if args.index_pattern is None:
                from tools.collector_pipeline import load_transport
                args.index_pattern=load_transport(args.target_root).INDEX_PATTERN
            spec=dict(version='p24-pipeline.1',start=utc(args.start).isoformat(),windows=args.windows,
                lag_seconds=args.lag_seconds,window_timeout_seconds=args.window_timeout_seconds,
                config=str(args.config.resolve()),target_root=str(args.target_root.resolve()),stream=args.stream,
                index_pattern=args.index_pattern,rank_cutoff=args.rank_cutoff,persist_candidates=args.persist_candidates)
            result=run(spec,args.state_dir,[sys.executable,str(Path(__file__).resolve()),'_window'])
        print(json.dumps(result,separators=(',',':')))
        return 0 if result.get('status') in ['completed','waiting','stopped'] else 2
    except FoundationError as error:
        print(json.dumps(dict(status='FAIL',error=error.code,production_modified=False)));return 2
    except Exception:
        print(json.dumps(dict(status='FAIL',error='pipeline_operation_failed',production_modified=False)));return 2


if __name__=='__main__':raise SystemExit(main())
