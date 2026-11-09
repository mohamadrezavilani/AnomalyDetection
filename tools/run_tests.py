"""Run affected finite checks; integrated mode requires explicit local config."""
from pathlib import Path
import argparse,hashlib,json,os,sys,time,unittest

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))

POSIX_PERMISSION_TEST='tests.test_access.SignedAccessTests.test_access_token_file_rejects_group_or_world_readable_credentials'
POSIX_SKIP_REASON='POSIX mode-bit check is not a Windows ACL qualification'

def source_fingerprints():
    return {p.relative_to(ROOT).as_posix():hashlib.sha256(p.read_bytes()).hexdigest()
            for top in ('p24_foundation','sql','tests','fixtures','catalogs','tools','review_ui')
            for p in sorted((ROOT/top).rglob('*')) if p.is_file() and '__pycache__' not in p.parts and p.suffix!='.pyc'}

def startup_failure(path,error):
    from p24_foundation.config import connection_error_code
    result=dict(ok=False,tests=0,failures=0,errors=1,skipped=0,mode='native_setup',
        startup_error=connection_error_code(error),production_modified=False,
        expected_skip_details=[],unexpected_skip_details=[],tested_source_sha256=source_fingerprints())
    path.parent.mkdir(parents=True,exist_ok=True)
    path.write_text(json.dumps(result,indent=2)+'\n',encoding='utf-8')
    print(json.dumps({k:v for k,v in result.items() if k!='tested_source_sha256'}))
    return 2

def classify_skips(skipped, *, platform_name=None):
    platform_name=os.name if platform_name is None else platform_name
    expected,unexpected=[],[]
    for test,reason in skipped:
        item=dict(test=test.id(),reason=reason)
        approved=platform_name=='nt' and item['test']==POSIX_PERMISSION_TEST and reason==POSIX_SKIP_REASON
        (expected if approved else unexpected).append(item)
    return dict(expected_skip_details=expected,unexpected_skip_details=unexpected)

def main():
    parser=argparse.ArgumentParser();group=parser.add_mutually_exclusive_group(required=True)
    group.add_argument('--config',type=Path);group.add_argument('--offline',action='store_true')
    parser.add_argument('--output',type=Path,default=ROOT/'validation/test_results.json')
    args=parser.parse_args();started=time.perf_counter();connection=None;server=None
    from tests import test_core
    suite=unittest.defaultTestLoader.loadTestsFromModule(test_core)
    from tests.test_access import SignedAccessTests
    suite.addTests(unittest.defaultTestLoader.loadTestsFromTestCase(SignedAccessTests))
    from tests.test_test_runner import RunnerSkipPolicyTests
    suite.addTests(unittest.defaultTestLoader.loadTestsFromTestCase(RunnerSkipPolicyTests))
    from tests.test_config_diagnostics import ConfigDiagnosticTests
    suite.addTests(unittest.defaultTestLoader.loadTestsFromTestCase(ConfigDiagnosticTests))
    from tests.test_patch_update import PatchUpdateTests
    suite.addTests(unittest.defaultTestLoader.loadTestsFromTestCase(PatchUpdateTests))
    from tests.test_source_backfill import SourceBackfillContractTests,SourceBackfillPostgresTests
    suite.addTests(unittest.defaultTestLoader.loadTestsFromTestCase(SourceBackfillContractTests))
    from tests.test_investigation import InvestigationContractTests,InvestigationPostgresTests
    suite.addTests(unittest.defaultTestLoader.loadTestsFromTestCase(InvestigationContractTests))
    from tests.test_review_ui import ReviewUITests
    suite.addTests(unittest.defaultTestLoader.loadTestsFromTestCase(ReviewUITests))
    from tests import test_milestone2r,test_request_chains,test_evidence_matrix,test_incident_briefs,test_investigation_link_identity
    for module in (test_milestone2r,test_request_chains,test_evidence_matrix,test_incident_briefs,test_investigation_link_identity):
        suite.addTests(unittest.defaultTestLoader.loadTestsFromModule(module))
    from tests.test_taxonomy import TaxonomyCandidateTests,TaxonomyPostgresTests
    suite.addTests(unittest.defaultTestLoader.loadTestsFromTestCase(TaxonomyCandidateTests))
    from tests.test_acquisition import AcquisitionTests,AcquisitionPostgresTests
    suite.addTests(unittest.defaultTestLoader.loadTestsFromTestCase(AcquisitionTests))
    from tests.test_publication import PublicationContractTests,PublicationPostgresTests
    suite.addTests(unittest.defaultTestLoader.loadTestsFromTestCase(PublicationContractTests))
    from tests.test_collector_pipeline import CollectorPipelineTests,CollectorPipelinePostgresTests
    suite.addTests(unittest.defaultTestLoader.loadTestsFromTestCase(CollectorPipelineTests))
    from tests.test_replay import ReplayTests
    suite.addTests(unittest.defaultTestLoader.loadTestsFromTestCase(ReplayTests))
    from tests.test_behavior import BehaviorTests,BehaviorPostgresTests
    suite.addTests(unittest.defaultTestLoader.loadTestsFromTestCase(BehaviorTests))
    from tests.test_historical_replay import HistoricalReplayTests
    suite.addTests(unittest.defaultTestLoader.loadTestsFromTestCase(HistoricalReplayTests))
    from tests.test_pipeline import PipelineTests,PipelinePostgresTests
    suite.addTests(unittest.defaultTestLoader.loadTestsFromTestCase(PipelineTests))
    from tests.test_behavior_binding import BehaviorBindingTests
    suite.addTests(unittest.defaultTestLoader.loadTestsFromTestCase(BehaviorBindingTests))
    if args.config:
        from p24_foundation.config import read_config,connect
        from tests.test_postgres import PostgreSQLAcceptance
        try:
            settings=read_config(args.config);connection=connect(settings['database'])
            server=connection.execute('SHOW server_version_num').fetchone()[0]
        except Exception as error:
            if connection:connection.close()
            return startup_failure(args.output,error)
        PostgreSQLAcceptance.connection=connection
        PostgreSQLAcceptance.database_config=settings["database"]
        suite.addTests(unittest.defaultTestLoader.loadTestsFromTestCase(PostgreSQLAcceptance))
        TaxonomyPostgresTests.connection=connection
        suite.addTests(unittest.defaultTestLoader.loadTestsFromTestCase(TaxonomyPostgresTests))
        AcquisitionPostgresTests.connection=connection
        suite.addTests(unittest.defaultTestLoader.loadTestsFromTestCase(AcquisitionPostgresTests))
        PublicationPostgresTests.connection=connection
        PublicationPostgresTests.database_config=settings['database']
        suite.addTests(unittest.defaultTestLoader.loadTestsFromTestCase(PublicationPostgresTests))
        CollectorPipelinePostgresTests.connection=connection
        CollectorPipelinePostgresTests.database_config=settings['database']
        suite.addTests(unittest.defaultTestLoader.loadTestsFromTestCase(CollectorPipelinePostgresTests))
        PipelinePostgresTests.connection=connection
        PipelinePostgresTests.database_config=settings["database"]
        suite.addTests(unittest.defaultTestLoader.loadTestsFromTestCase(PipelinePostgresTests))
        BehaviorPostgresTests.connection=connection
        suite.addTests(unittest.defaultTestLoader.loadTestsFromTestCase(BehaviorPostgresTests))
        SourceBackfillPostgresTests.database_config=settings['database']
        suite.addTests(unittest.defaultTestLoader.loadTestsFromTestCase(SourceBackfillPostgresTests))
        InvestigationPostgresTests.connection=connection
        suite.addTests(unittest.defaultTestLoader.loadTestsFromTestCase(InvestigationPostgresTests))
        from tests.test_workflow_store import WorkflowPostgresTests
        from tests.test_incidents import IncidentPostgresTests
        from tests.test_investigation_links import InvestigationLinksPostgresTests
        IncidentPostgresTests.connection=connection
        suite.addTests(unittest.defaultTestLoader.loadTestsFromTestCase(IncidentPostgresTests))
        InvestigationLinksPostgresTests.connection=connection
        suite.addTests(unittest.defaultTestLoader.loadTestsFromTestCase(InvestigationLinksPostgresTests))
        WorkflowPostgresTests.connection=connection
        suite.addTests(unittest.defaultTestLoader.loadTestsFromTestCase(WorkflowPostgresTests))
    try:
        result=unittest.TextTestRunner(verbosity=2).run(suite)
    finally:
        if connection:connection.close()
    skips=classify_skips(result.skipped)
    ok=result.wasSuccessful() and not skips['unexpected_skip_details']
    summary=dict(ok=ok,tests=result.testsRun,failures=len(result.failures),errors=len(result.errors),skipped=len(result.skipped),elapsed_seconds=round(time.perf_counter()-started,3),
                 mode='native_postgresql_integration' if args.config else 'offline_unit',postgres_server_version=server,production_modified=False,
                 scope='Finite sanitized real-chain replay, populated predecessor-schema upgrade, workflow persistence, incident recurrence/revisions, request deduplication, scoped review/undo/expiry, proof-pinned shared-request links, evidence-bound operator priority, concurrent review fencing, CSRF/template checks and pinned signed pagination. Trusted workflow/detector findings are synthetic; production issuer verification, identity federation, Windows ACLs, application RLS, detector usefulness, throughput and recovery qualification remain open')
    summary.update(skips)
    summary['failure_test_ids']=[test.id() for test,_ in result.failures]
    summary['error_test_ids']=[test.id() for test,_ in result.errors]
    if args.offline:
        summary['scope']='Offline parser/reconstruction, scoped outcomes, source receipts/publication contracts, signed access/privacy, Session lifecycle, synthetic workflow reconciliation and Flask request tests. PostgreSQL migrations, database persistence, target Windows and operational qualification were not run.'
    summary['platform_security_qualification']='windows_acl_not_qualified' if os.name=='nt' else 'posix_modebits_component_only'
    summary['tested_source_sha256']=source_fingerprints()
    args.output.parent.mkdir(parents=True,exist_ok=True)
    args.output.write_text(json.dumps(summary,indent=2)+'\n',encoding='utf-8')
    print(json.dumps({k:v for k,v in summary.items() if k!='tested_source_sha256'},indent=2))
    return 0 if ok else 1

if __name__=='__main__':raise SystemExit(main())

