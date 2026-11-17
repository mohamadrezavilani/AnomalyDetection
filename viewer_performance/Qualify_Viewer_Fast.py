"""Compare canonical and explicit C2/C3 writers using owned disposable DBs.

The four private captures and source identities are preserved. All initialization,
candidate preparation, per-boundary oracles and cleanup costs remain in the
receipt. No product connection or worker operation is performed.
"""
import argparse
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import sys
import tempfile
import threading
import time
import uuid


def qualify(project, bundle, *, pairs=2, notice=lambda value: None):
    project, bundle = Path(project).resolve(), Path(bundle).resolve()
    sys.path.insert(0, str(project))
    from p24_foundation.viewer_data import ViewerDB
    from p24_foundation.viewer_runtime import atomic_json
    from viewer_performance.capacity.baseline import capture_jobs, run_lane, distribution
    from viewer_performance.Qualify_Capacity_Candidate import literal_database, extract_captures, connection_environment
    from viewer_performance.fast_writer import FastWriterDB, BUILD, BASE_RUNTIME, verify_sources
    if not 1 <= pairs <= 2:
        raise ValueError('fast_qualification_pairs_must_be_1_to_2')
    source = verify_sources(project)
    config = literal_database(project)
    began = time.perf_counter()
    output = project / 'AnomalyDetection/reports' / ('Viewer_Fast_Qualification_' +
        datetime.now(timezone.utc).strftime('%Y%m%d_%H%M%S_') + uuid.uuid4().hex[:8] + '.json')
    report = dict(status='RUNNING', build_id=BUILD, implementation_source_sha256=source,
        canonical_runtime_source_sha256=BASE_RUNTIME, product_database_opened=False,
        product_database_modified=False, workers_restarted=False, qualification_databases_only=True,
        input_bundle_sha256=hashlib.sha256(bundle.read_bytes()).hexdigest(), lanes=[], checks=[],
        comparisons=[], capacity_target='NOT_ACCEPTED', eight_hour_web_ad='NOT_RUN',
        live_elasticsearch_acquisition='NOT_RUN', actual_ad_evaluation='NOT_RUN',
        cache_pressure='NOT_QUALIFIED', cold_os_cache='NOT_CONTROLLED', shared_host_load='NOT_CONTROLLED')
    created, admin = [], None
    try:
        with tempfile.TemporaryDirectory(prefix='p24-fast-private-') as folder:
            root = Path(folder)
            captures = extract_captures(bundle, root)
            jobs = capture_jobs(captures)
            from p24_foundation.privacy import generate_keys
            keys = root / 'keys.json'
            generate_keys(keys)
            with connection_environment(config):
                import psycopg
                from psycopg import sql
                parameters = dict(host=str(config.get('host', '127.0.0.1')),
                    port=int(config.get('port', 5432)), user=config['user'], connect_timeout=5)
                admin = psycopg.connect(**parameters, dbname='postgres', autocommit=True)
                if int(admin.execute('SHOW server_version_num').fetchone()[0]) < 180000:
                    raise ValueError('postgresql_18_required')
                for pair in range(pairs):
                    lanes = {}
                    order = ('canonical', 'fast') if pair % 2 == 0 else ('fast', 'canonical')
                    for variant in order:
                        name = 'p24_design_capacity_' + uuid.uuid4().hex[:16] + '_qualification'
                        admin.execute(sql.SQL('CREATE DATABASE {}').format(sql.Identifier(name)))
                        created.append(name)
                        options = dict(config=dict(parameters, dbname=name,
                            options='-c jit=off -c work_mem=64MB -c temp_buffers=128MB -c wal_compression=zstd'),
                            keys_path=keys)
                        notice(dict(status='FAST_QUALIFICATION_LANE_STARTED', pair=pair, variant=variant))
                        lane = run_lane(options, jobs, profiled=True, history=True,
                            db_type=FastWriterDB if variant == 'fast' else ViewerDB, notice=notice)
                        lane.update(pair=pair, variant=variant)
                        report['lanes'].append(lane)
                        lanes[variant] = lane
                    equal = [left['oracle'] == right['oracle'] for left, right in
                        zip(lanes['canonical']['windows'], lanes['fast']['windows'])]
                    report['checks'].append(dict(pair=pair, order=order,
                        every_publication_equal=equal, all_equal=all(equal) and len(equal)==len(jobs)))
                    def charged(lane):
                        targets = lane['windows'][1:]
                        seconds = sum(w['elapsed_to_contract_check_seconds'] for w in targets)
                        return dict(fresh_windows=sum(w['new_events']>0 for w in targets),
                            new_events=sum(w['new_events'] for w in targets),
                            publication_to_contract_seconds=seconds,
                            prepare_seconds=lane['candidate_prepare_seconds'],
                            total_charged_seconds=seconds + lane['candidate_prepare_seconds'],
                            publication_distribution=distribution([w['elapsed_to_contract_check_seconds'] for w in targets]),
                            whole_lane_including_bootstrap_diagnostics_and_oracles_seconds=
                                lane['total_lane_seconds_including_setup_diagnostics_and_oracle'])
                    original, fast = charged(lanes['canonical']), charged(lanes['fast'])
                    report['comparisons'].append(dict(pair=pair, canonical=original, fast=fast,
                        reduction_fraction=1-fast['total_charged_seconds']/original['total_charged_seconds']
                            if original['total_charged_seconds'] else None))
        report['status'] = 'PASS_FAST_EQUIVALENCE' if all(check['all_equal'] for check in report['checks']) else 'FAIL_FAST_OUTPUT_DIFFERENCE'
        if verify_sources(project) != source:
            raise ValueError('fast_qualification_source_changed')
    except Exception as exc:
        report.update(status='FAILED_FAST_QUALIFICATION', failure=dict(error_type=type(exc).__name__,
            code=str(exc) if isinstance(exc, ValueError) else None, sqlstate=getattr(exc, 'sqlstate', None)))
    finally:
        report['cleanup'] = dict(allocated=len(created), dropped=0, failures=[])
        if admin is not None:
            from psycopg import sql
            for name in created:
                try:
                    admin.execute(sql.SQL('DROP DATABASE {}').format(sql.Identifier(name)))
                    report['cleanup']['dropped'] += 1
                except Exception as exc:
                    report['cleanup']['failures'].append(dict(error_type=type(exc).__name__, sqlstate=getattr(exc, 'sqlstate', None)))
                    report['status'] = 'FAILED_FAST_CLEANUP'
            admin.close()
    report['whole_run_including_bootstrap_diagnostics_oracles_and_cleanup_seconds'] = time.perf_counter()-began
    atomic_json(output, report)
    return {key: report[key] for key in ('status','build_id','comparisons','product_database_opened',
        'product_database_modified','workers_restarted')} | dict(output=str(output), failure=report.get('failure'))


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--project', type=Path, required=True)
    parser.add_argument('--captures-zip', type=Path, required=True)
    parser.add_argument('--pairs', type=int, choices=(1,2), default=2)
    args = parser.parse_args(argv)
    done = threading.Event()
    began = time.monotonic()
    def notice(value):
        print(json.dumps(value, ensure_ascii=True), flush=True)
    def heartbeat():
        while not done.wait(15):
            notice(dict(status='FAST_QUALIFICATION_RUNNING', elapsed_seconds=round(time.monotonic()-began,1)))
    thread = threading.Thread(target=heartbeat, daemon=True)
    thread.start()
    try:
        result = qualify(args.project, args.captures_zip, pairs=args.pairs, notice=notice)
    except Exception as exc:
        result = dict(status='FAST_QUALIFICATION_BLOCKED', error_type=type(exc).__name__,
            code=str(exc) if isinstance(exc, ValueError) else None,
            product_database_opened=False, product_database_modified=False, workers_restarted=False)
    finally:
        done.set()
        thread.join(1)
    notice(result)
    return 0 if result['status']=='PASS_FAST_EQUIVALENCE' else 2


if __name__ == '__main__':
    raise SystemExit(main())
