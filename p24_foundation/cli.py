"""Explicit local CLI. No imports/startup connect to DB or Elasticsearch."""
from __future__ import annotations

import argparse
import json
import os
import stat
import sys
from pathlib import Path

from .config import read_config, connect
from .errors import FoundationError
from .intake import read_batch
from .privacy import Keys, generate_keys
from .store import FoundationStore, initialize
from .worker import ProjectionWorker

def read_private_session(path):
    try:
        with path.open(encoding='utf-8') as stream:
            token=stream.read(4097).strip()
        if not token or len(token)>4096:raise ValueError
    except (OSError,ValueError):raise FoundationError('private_session_file_invalid') from None
    return token

def read_private_access_token(path):
    try:
        info=path.stat()
        if os.name!='nt' and stat.S_IMODE(info.st_mode)&0o077:raise ValueError
        with path.open(encoding='utf-8') as stream:token=stream.read(4097).strip()
        if not token or len(token.encode('utf-8'))>4096:raise ValueError
    except (OSError,ValueError):raise FoundationError('private_access_token_file_invalid') from None
    return token

def main(argv=None):
    parser=argparse.ArgumentParser(description="Pishkhan24 isolated evidence foundation — p24_design_* databases only")
    parser.add_argument("--config", type=Path, help="Trusted local Python configuration; no environment or production-config discovery")
    commands=parser.add_subparsers(dest="command",required=True)
    keys=commands.add_parser("generate-keys");keys.add_argument("--path",type=Path,required=True)
    commands.add_parser("init")
    ingest=commands.add_parser("ingest")
    ingest.add_argument("--input",type=Path,required=True);ingest.add_argument("--source",required=True)
    ingest.add_argument("--start",required=True);ingest.add_argument("--end",required=True)
    project=commands.add_parser("project")
    project.add_argument("--sources",nargs="+",required=True)
    project.add_argument("--cutoff",required=True);project.add_argument("--knowledge-at",required=True)
    project.add_argument("--mode",choices=("design_fixture","online_original","historical_revised"),default="design_fixture")
    project.add_argument("--association-seconds",type=int,default=300)
    info=commands.add_parser("run");info.add_argument("--run",required=True);info.add_argument("--access-token-file",type=Path)
    request=commands.add_parser("request");request.add_argument("--run",required=True);request.add_argument("--request-id",required=True);request.add_argument("--access-token-file",type=Path)
    evidence=commands.add_parser("evidence");evidence.add_argument("--run",required=True);evidence.add_argument("--request-id",required=True);evidence.add_argument("--limit",type=int,default=100);evidence.add_argument("--cursor");evidence.add_argument("--access-token-file",type=Path)
    hold=commands.add_parser("place-evidence-hold",help="Place a permanent source-evidence hold; release and deletion are disabled")
    hold.add_argument("--snapshot",required=True);hold.add_argument("--reason",choices=("incident_review","security_investigation","legal_preservation","regulatory_preservation","operator_request","other"),required=True);hold.add_argument("--access-token-file",type=Path)
    supersede=commands.add_parser("supersede-source");supersede.add_argument("--prior",required=True);supersede.add_argument("--replacement",required=True);supersede.add_argument("--expected-prior-revision",type=int,required=True);supersede.add_argument("--reason",choices=("corrected_export","late_evidence_supersedes_partial","producer_reissued","operator_reconciled"),required=True);supersede.add_argument("--declared-by",required=True)
    enqueue=commands.add_parser("enqueue-projection");enqueue.add_argument("--sources",nargs="+",required=True);enqueue.add_argument("--cutoff",required=True);enqueue.add_argument("--knowledge-at",required=True);enqueue.add_argument("--mode",choices=("online_original","historical_revised"),required=True);enqueue.add_argument("--dedupe-key",required=True)
    claim=commands.add_parser("claim-work");claim.add_argument("--worker",required=True);claim.add_argument("--limit",type=int,default=1);claim.add_argument("--lease-seconds",type=int,default=60)
    renew=commands.add_parser("renew-work");renew.add_argument("--work",required=True);renew.add_argument("--worker",required=True);renew.add_argument("--generation",type=int,required=True);renew.add_argument("--lease-seconds",type=int,default=60)
    complete=commands.add_parser("complete-work");complete.add_argument("--work",required=True);complete.add_argument("--worker",required=True);complete.add_argument("--generation",type=int,required=True);complete.add_argument("--run",required=True,help="Sealed projection run whose exact source vector and cutoffs match this work item")
    fail=commands.add_parser("fail-work");fail.add_argument("--work",required=True);fail.add_argument("--worker",required=True);fail.add_argument("--generation",type=int,required=True);fail.add_argument("--error-code",required=True);fail.add_argument("--retryable",action="store_true");fail.add_argument("--delay-seconds",type=int,default=30)
    candidate=commands.add_parser("candidates");candidate.add_argument("--run",required=True);candidate.add_argument("--limit",type=int,default=100);candidate.add_argument("--cursor");candidate.add_argument("--access-token-file",type=Path)
    work_once=commands.add_parser("work-once",help="Process at most one queued projection item")
    work_once.add_argument("--worker",required=True);work_once.add_argument("--lease-seconds",type=int,default=120)
    work_run=commands.add_parser("work-run",help="Process a bounded number of projection items")
    work_run.add_argument("--worker",required=True);work_run.add_argument("--lease-seconds",type=int,default=120)
    work_run.add_argument("--max-items",type=int,default=100);work_run.add_argument("--max-runtime-seconds",type=int,required=True)
    work_run.add_argument("--poll-seconds",type=int,default=2)
    taxonomy=commands.add_parser("import-taxonomy-candidates",help="Import source metadata as an unpublished draft")
    taxonomy.add_argument("--collections",nargs="+",required=True,type=Path)
    taxonomy.add_argument("--error-catalog",type=Path)
    taxonomy.add_argument("--log-evidence",nargs="*",type=Path,default=[])
    session=commands.add_parser("session");session.add_argument("--run",required=True)
    session.add_argument("--session-file",type=Path,required=True,help="Private file containing SessionID; keep bearer values off the command line")
    session.add_argument("--limit",type=int,default=100);session.add_argument("--cursor");session.add_argument("--access-token-file",type=Path)
    prepare=commands.add_parser('prepare-observation',help='Prepare an immutable observed-evidence view without publishing it')
    selection=prepare.add_mutually_exclusive_group(required=True)
    selection.add_argument('--sources',nargs='+');selection.add_argument('--empty',action='store_true',help='Explicitly prepare an empty view; evidence is retained')
    prepare.add_argument('--cutoff',required=True);prepare.add_argument('--knowledge-at',required=True)
    prepare.add_argument('--expected-generation',required=True,type=int)
    prepare.add_argument('--mode',choices=('design_fixture','online_original','historical_revised'),default='historical_revised')
    prepare.add_argument('--checkpoint-every',type=int,default=64)
    prepare.add_argument('--workflow-run',help='Explicitly pin a sealed workflow projection with identical sources and time bounds')
    publish=commands.add_parser('publish-observation');publish.add_argument('--publication',required=True)
    observation=commands.add_parser('observation');observation.add_argument('--publication');observation.add_argument('--access-token-file',type=Path)
    for name in ('observed-workflows','workflow-state-evidence'):
        command=commands.add_parser(name);command.add_argument('--publication',required=True)
        command.add_argument('--access-token-file',type=Path)
        command.add_argument('--limit',type=int,default=25);command.add_argument('--cursor')
        if name=='workflow-state-evidence':command.add_argument('--state-publication',required=True)
    for name in ('observed-requests','observed-session','observed-request','observed-evidence','observed-candidates',
                 'session-journey','request-card','request-operations'):
        command=commands.add_parser(name);command.add_argument('--publication',required=True)
        command.add_argument('--access-token-file',type=Path)
        if name in ('observed-request','observed-evidence','request-card','request-operations'):command.add_argument('--request-id',required=True)
        if name in ('observed-session','session-journey'):command.add_argument('--session-file',type=Path,required=True)
        if name=='session-journey':command.add_argument('--identity-scope',choices=('assigned','conflicting'),default='assigned')
        if name not in ('observed-request','request-card'):
            command.add_argument('--limit',type=int,default=100);command.add_argument('--cursor')
    args=parser.parse_args(argv)
    try:
        if args.command=="generate-keys":
            generate_keys(args.path);result=dict(status="private_keys_created",values_printed=False)
        else:
            if args.config is None:
                raise FoundationError("local_configuration_required")
            settings=read_config(args.config)
            with connect(settings["database"]) as connection:
                if args.command=="init":
                    result=initialize(connection)
                else:
                    keys=Keys.read(settings["keys_path"])
                    access_policy=None
                    if settings["access_public_key_path"] is not None:
                        from .access import AccessPolicy,read_public_key
                        access_policy=AccessPolicy(read_public_key(settings["access_public_key_path"]),settings["namespace"],
                                                   issuer=settings["access_issuer"],audience=settings["access_audience"])
                    store=FoundationStore(connection,keys,settings["namespace"],settings["vault_path"],access_policy=access_policy)
                    access_token=read_private_access_token(args.access_token_file) if getattr(args,"access_token_file",None) else None
                    if args.command=="ingest":
                        result=store.ingest(read_batch(args.input),source_key=args.source,interval_start=args.start,interval_end=args.end)
                    elif args.command=="project":
                        result=store.project(args.sources,event_cutoff=args.cutoff,knowledge_at=args.knowledge_at,mode=args.mode,association_horizon_seconds=args.association_seconds)
                    elif args.command=="run":
                        result=store.run_info(args.run,access_token=access_token)
                    elif args.command=="request":
                        result=store.get_request(args.run,args.request_id,access_token=access_token)
                    elif args.command=="evidence":
                        result=store.request_evidence(args.run,args.request_id,limit=args.limit,cursor=args.cursor,access_token=access_token)
                    elif args.command=="place-evidence-hold":
                        result=store.place_evidence_hold(args.snapshot,reason=args.reason,access_token=access_token)
                    elif args.command=="supersede-source":
                        result=store.replace_source_snapshot(args.prior,args.replacement,expected_prior_revision=args.expected_prior_revision,reason_key=args.reason,declared_by=args.declared_by)
                    elif args.command=="enqueue-projection":
                        result=store.enqueue_projection(args.sources,event_cutoff=args.cutoff,knowledge_at=args.knowledge_at,mode=args.mode,dedupe_key=args.dedupe_key)
                    elif args.command=="claim-work":
                        result=store.claim_work(args.worker,limit=args.limit,lease_seconds=args.lease_seconds)
                    elif args.command=="renew-work":
                        result=dict(renewed=store.renew_work(args.work,args.worker,args.generation,lease_seconds=args.lease_seconds))
                    elif args.command=="complete-work":
                        result=dict(completed=store.complete_work(args.work,args.worker,args.generation,args.run))
                    elif args.command=="fail-work":
                        result=dict(result=store.fail_work(args.work,args.worker,args.generation,error_code=args.error_code,retryable=args.retryable,delay_seconds=args.delay_seconds))
                    elif args.command=="candidates":
                        result=store.candidates(args.run,limit=args.limit,cursor=args.cursor,access_token=access_token)
                    elif args.command=="work-once":
                        result=ProjectionWorker(store,settings["database"],lease_seconds=args.lease_seconds).run_once(args.worker)
                    elif args.command=="work-run":
                        result=ProjectionWorker(store,settings["database"],lease_seconds=args.lease_seconds).run_bounded(
                            args.worker,max_items=args.max_items,max_runtime_seconds=args.max_runtime_seconds,poll_seconds=args.poll_seconds)
                    elif args.command=="import-taxonomy-candidates":
                        result=store.import_taxonomy_candidates(args.collections,error_catalog_path=args.error_catalog,
                                                                log_evidence_paths=args.log_evidence)
                    elif args.command=="session":
                        token=read_private_session(args.session_file)
                        result=store.session_activity(args.run,token,limit=args.limit,cursor=args.cursor,access_token=access_token)
                    elif args.command in {'observed-workflows','workflow-state-evidence'}:
                        from .workflow_store import WorkflowStore
                        workflows=WorkflowStore(store)
                        if args.command=='observed-workflows':
                            result=workflows.for_publication(args.publication,limit=args.limit,cursor=args.cursor,access_token=access_token)
                        else:
                            result=workflows.state_evidence(args.publication,args.state_publication,limit=args.limit,cursor=args.cursor,access_token=access_token)
                    elif args.command in {'session-journey','request-card','request-operations'}:
                        from .investigation import InvestigationReader
                        reader=InvestigationReader(store)
                        if args.command=='session-journey':
                            result=reader.session(args.publication,read_private_session(args.session_file),
                                identity_scope=args.identity_scope,limit=args.limit,cursor=args.cursor,access_token=access_token)
                        elif args.command=='request-card':
                            result=reader.request(args.publication,args.request_id,access_token=access_token)
                        else:
                            result=reader.operations(args.publication,args.request_id,limit=args.limit,cursor=args.cursor,access_token=access_token)
                    elif args.command in {'prepare-observation','publish-observation','observation','observed-requests',
                                          'observed-session','observed-request','observed-evidence','observed-candidates'}:
                        from .publication import ObservationPublisher
                        publisher=ObservationPublisher(store,checkpoint_every=args.checkpoint_every if args.command=='prepare-observation' else 64)
                        if args.command=='prepare-observation':
                            result=publisher.prepare(args.sources or [],event_cutoff=args.cutoff,knowledge_at=args.knowledge_at,
                                                     expected_generation=args.expected_generation,mode=args.mode,workflow_run_id=args.workflow_run)
                        elif args.command=='publish-observation':result=publisher.publish(args.publication)
                        elif args.command=='observation':result=publisher.info(args.publication,access_token=access_token)
                        elif args.command=='observed-request':result=publisher.request(args.publication,args.request_id,access_token=access_token)
                        elif args.command=='observed-evidence':
                            result=publisher.request_evidence(args.publication,args.request_id,limit=args.limit,cursor=args.cursor,access_token=access_token)
                        elif args.command=='observed-session':
                            result=publisher.session_activity(args.publication,read_private_session(args.session_file),limit=args.limit,cursor=args.cursor,access_token=access_token)
                        elif args.command=='observed-candidates':
                            result=publisher.candidates(args.publication,limit=args.limit,cursor=args.cursor,access_token=access_token)
                        else:result=publisher.requests(args.publication,limit=args.limit,cursor=args.cursor,access_token=access_token)
        print(json.dumps(result,ensure_ascii=False,indent=2,default=str))
        return 0
    except FoundationError as error:
        print(json.dumps(dict(ok=False,error=error.code,raw_payload_printed=False)),file=sys.stderr)
        return 2
    except Exception:
        # Driver errors can include SQL values/configuration. Detailed raw
        # exception traces are deliberately not printed by the public CLI.
        print(json.dumps(dict(ok=False,error="operation_failed",raw_payload_printed=False)),file=sys.stderr)
        return 2

if __name__=="__main__":
    raise SystemExit(main())

