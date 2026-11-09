"""Regression against a disposable PostgreSQL instance on loopback.

Pass a new fixture cluster's data directory and port. Never point this test
at a project database. Creating the fixture database must succeed first.
"""
import argparse
from datetime import datetime
import json
from pathlib import Path
import tempfile
from unittest.mock import patch

import psycopg
from psycopg.rows import dict_row

from anomaly_detection import BUILD_ID, CATALOG_SHA, FIVE_NS
from anomaly_detection.history_reset import run, reset_database, tehran_boundary
from anomaly_detection.history_scope import WRITER_LOCK, load_floor
from anomaly_detection.native_pg import database
from anomaly_detection.product_pipeline import apply_window, read_window
from anomaly_detection.product_source import ProductSource
from anomaly_detection.product_store import ProductStore
from anomaly_detection.scenario_traffic import read_page as read_traffic
from anomaly_detection.service_sampling import read as read_sample
from anomaly_detection.snapshot import ContractError
from anomaly_detection.temporal import TIMEZONE

ROOT = Path(__file__).resolve().parents[1]
ROLE = 'p24_anomaly_detection'
DB = 'p24_design_viewer'
TAG = 'AnomalyDetection:fixture26'
SESSION = 'a' * 64
SERVICE = 'Services.v1/WaterBills'


def request(n, at, state='active'):
    return {'request_key': f'{n:064x}', 'anchor_key': 'ba1:' + f'{n+100:064x}',
            'session_key': SESSION, 'anchor_ns': at, 'kind': 'service_execution',
            'state': state, 'revision': 1, 'root_call': SERVICE, 'root_code': 'G00000',
            'identity_state': 'assigned', 'conflicted': 0, 'request_session_key': SESSION}


def add_request(admin, row):
    admin.execute('INSERT INTO public.viewer_requests VALUES(%s,%s,%s,%s,%s,1,%s,%s)',
                  (row['request_key'], row['session_key'], row['identity_state'], row['conflicted'],
                   row['root_call'], row['anchor_ns'], row['anchor_ns']))
    keys = ('request_key', 'anchor_key', 'session_key', 'anchor_ns', 'kind', 'state', 'revision',
            'root_call', 'root_code')
    admin.execute('INSERT INTO public.viewer_semantic_occurrences VALUES(%s,%s,%s,%s,%s,%s,%s,%s,%s)',
                  tuple(row[key] for key in keys))


def source_fixture(admin, cutoff):
    admin.execute('CREATE SCHEMA anomaly_detection AUTHORIZATION ' + ROLE)
    admin.execute("COMMENT ON SCHEMA anomaly_detection IS 'AnomalyDetection:fixture26'")
    admin.execute("CREATE TABLE public.viewer_live_state(id integer PRIMARY KEY,stream_key text,"
                  "keys_fingerprint text,generation bigint,next_ns bigint,lag_seconds integer,last_success_ns bigint,last_error text)")
    admin.execute('CREATE TABLE public.viewer_semantic_checkpoint(id integer PRIMARY KEY,generation bigint,state text)')
    admin.execute('CREATE TABLE public.viewer_service_catalog_state(id integer PRIMARY KEY,fingerprint text)')
    admin.execute('CREATE TABLE public.viewer_live_windows(start_ns bigint PRIMARY KEY,end_ns bigint,generation bigint,last_publish_ns bigint)')
    admin.execute('CREATE TABLE public.viewer_requests(request_key text PRIMARY KEY,session_key text,identity_state text,'
                  'conflicted integer,root_call text,root_count bigint,root_ns bigint,started_ns bigint)')
    admin.execute('CREATE TABLE public.viewer_semantic_occurrences(request_key text PRIMARY KEY,anchor_key text,session_key text,'
                  'anchor_ns bigint,kind text,state text,revision bigint,root_call text,root_code text)')
    admin.execute('CREATE INDEX ON public.viewer_semantic_occurrences(state,anchor_ns,request_key)')
    admin.execute('GRANT SELECT ON ALL TABLES IN SCHEMA public TO ' + ROLE)
    admin.execute("INSERT INTO public.viewer_live_state VALUES(1,'fixture','keys',1,%s,600,%s,NULL)",
                  (cutoff - FIVE_NS, cutoff - FIVE_NS))
    admin.execute("INSERT INTO public.viewer_semantic_checkpoint VALUES(1,1,'ready')")
    admin.execute('INSERT INTO public.viewer_service_catalog_state VALUES(1,%s)', (CATALOG_SHA,))
    admin.execute('INSERT INTO public.viewer_live_windows VALUES(%s,%s,1,%s)',
                  (cutoff - 2 * FIVE_NS, cutoff - FIVE_NS, cutoff))
    add_request(admin, request(1, cutoff - FIVE_NS - 1))


def assert_rejected(call, reason):
    try:
        call()
    except ContractError as exc:
        assert str(exc) == reason, str(exc)
    else:
        raise AssertionError(reason)


class AbortAfterTruncate:
    def __init__(self, raw):
        self.raw = raw

    def __getattr__(self, name):
        return getattr(self.raw, name)

    def execute(self, sql, *args):
        result = self.raw.execute(sql, *args)
        if sql.startswith('TRUNCATE TABLE'):
            raise RuntimeError('fixture_fault_after_truncate')
        return result


def check_reset(admin, root, pgdata, day, cutoff):
    sha = '0' * 64
    reset = lambda **kwargs: run(root, sha, day, pg_data_dir=pgdata, **kwargs)
    checks = {}
    with database(root) as raw:
        store = ProductStore(raw)
        store.initialize()
        before = {'namespace': 'viewer:fixture', 'stream_key': 'fixture', 'keys_fingerprint': 'keys',
                  'generation': 1, 'semantic_generation': 1, 'captured_at_ns': cutoff}
        old = request(1, cutoff - FIVE_NS - 1)
        today = request(2, cutoff + 1)
        store.apply_rows([old, today], before)
        raw.execute("UPDATE anomaly_detection.adp_facts SET details='{}',details_digest='keep' "
                    'WHERE request_key=%s', (today['request_key'],))
        raw.execute('INSERT INTO anomaly_detection.adp_profiles VALUES(%s,%s,%s,%s,%s,%s,%s)',
                    (today['request_key'], SESSION, SERVICE, today['anchor_ns'], '{"fixture":true}', 'profile', cutoff))
        raw.execute('CREATE TABLE anomaly_detection.legacy_fixture(id integer PRIMARY KEY)')
        raw.execute('INSERT INTO anomaly_detection.legacy_fixture VALUES (14)')
        raw.execute('CREATE VIEW anomaly_detection.legacy_view AS SELECT * FROM anomaly_detection.legacy_fixture')
        raw.execute("INSERT INTO anomaly_detection.adp_versions(request_key,change_type,content_digest,body,observed_ns) "
                    "SELECT %s,'fixture','fixture',repeat(md5(i::text),16),%s FROM generate_series(1,20000) i",
                    (old['request_key'], old['anchor_ns']))
        plan = reset()
        assert plan['status'] == 'HISTORY_RESET_PLAN', plan
        assert load_floor(store) == 0 and plan['retained']['adp_facts']['rows'] == 1
        checks['read_only_plan_and_verified_data_volume'] = 'PASS'
        raw.execute("INSERT INTO anomaly_detection.adp_case_feedback(case_key,label,note,created_ns,case_revision) "
                    "VALUES('fixture','confirmed_suspicious','fixture',%s,1)", (cutoff,))
        blocked = reset(apply=True)
        assert blocked['reason'] == 'PROTECTED_CURRENT_CASES_OR_FEEDBACK' and load_floor(store) == 0
        raw.execute('DELETE FROM anomaly_detection.adp_case_feedback')
        checks['blocks_removal_of_current_human_review'] = 'PASS'
        with patch('anomaly_detection.history_reset.measured_free_space',
                   return_value={'project_free_bytes': 0, 'postgresql_min_free_bytes': 0}):
            assert reset(apply=True)['reason'] == 'INSUFFICIENT_FREE_DISK_FOR_TRANSACTION'
        assert load_floor(store) == 0
        checks['blocks_when_preflight_disk_reserve_is_unavailable'] = 'PASS'
        with raw.transaction():
            raw.execute('SELECT pg_advisory_xact_lock(%s)', (WRITER_LOCK,))
            assert_rejected(lambda: reset(apply=True), 'AD_WRITER_ACTIVE')
        checks['active_ad_writer_refuses_reset'] = 'PASS'
        admin.execute('CREATE TABLE public.fixture_fk(id text REFERENCES anomaly_detection.adp_facts(request_key))')
        assert_rejected(lambda: reset(apply=True), 'HISTORY_RESET_UNEXPECTED_TABLE_DEPENDENCY')
        admin.execute('DROP TABLE public.fixture_fk')
        checks['external_foreign_key_refuses_reset'] = 'PASS'
        start, _ = tehran_boundary(day)
        try:
            reset_database(AbortAfterTruncate(raw), root, TAG, start, cutoff, apply=True, pg_data_dir=pgdata)
        except RuntimeError as exc:
            assert str(exc) == 'fixture_fault_after_truncate'
        else:
            raise AssertionError('fixture fault not reached')
        assert raw.execute('SELECT COUNT(*) AS n FROM anomaly_detection.adp_facts').fetchone()['n'] == 2
        assert load_floor(store) == 0
        checks['fault_after_truncate_rolls_back_rows_and_boundary'] = 'PASS'
        kept = raw.execute('SELECT request_key,body,details,details_digest FROM anomaly_detection.adp_facts '
                           'WHERE request_key=%s', (today['request_key'],)).fetchone()
        applied = reset(apply=True)
        assert applied['status'] == 'HISTORY_RESET_APPLIED', applied
        assert applied['product_relation_bytes_reclaimed'] > 5 * 1024 * 1024, applied
        assert load_floor(store) == cutoff
        assert raw.execute('SELECT request_key,body,details,details_digest FROM anomaly_detection.adp_facts').fetchall() == [kept]
        assert raw.execute('SELECT body FROM anomaly_detection.adp_profiles').fetchone()['body'] == '{"fixture":true}'
        assert raw.execute('SELECT COUNT(*) AS n FROM anomaly_detection.adp_versions').fetchone()['n'] == 0
        assert raw.execute('SELECT id FROM anomaly_detection.legacy_view').fetchone()['id'] == 14
        assert admin.execute('SELECT count(*) AS n FROM public.viewer_requests').fetchone()['n'] == 1
        assert admin.execute('SELECT next_ns FROM public.viewer_live_state').fetchone()['next_ns'] == cutoff - FIVE_NS
        assert store.state('source_binding')['namespace'] == before['namespace']
        assert store.state('source_watermark')['generation'] == 1
        checks['real_relation_bytes_reclaimed_and_current_facts_profiles_kept'] = applied['product_relation_bytes_reclaimed']
        checks['viewer_and_legacy_rows_and_source_binding_preserved'] = 'PASS'
        store = ProductStore(raw)
        store.initialize()
        store.apply_rows([old], before)
        assert raw.execute('SELECT COUNT(*) AS n FROM anomaly_detection.adp_facts').fetchone()['n'] == 1
        checks['old_packet_cannot_restore_pre_boundary_facts'] = 'PASS'
        with patch('anomaly_detection.product_source.installed_source_identity', return_value={}):
            source = ProductSource(root.parent)
        source.analysis_floor_ns = store.history_floor_ns
        assert not source.page()['rows'] and not source.cohort(target=cutoff-FIVE_NS)['rows']
        assert read_window(source, {'target_ns': cutoff-2*FIVE_NS})['target_ns'] is None
        assert read_sample(source, {})['status'] == 'CAUGHT_UP'
        assert read_traffic(source, {'target_ns': cutoff-2*FIVE_NS})['status'] == 'CAUGHT_UP'
        checks['all_source_lanes_wait_when_published_checkpoint_precedes_boundary'] = 'PASS'
        admin.execute('UPDATE public.viewer_live_state SET generation=2,next_ns=%s', (cutoff+FIVE_NS,))
        admin.execute('UPDATE public.viewer_semantic_checkpoint SET generation=2')
        assert source.page()['source']['scope_latest_published_end_ns'] is None
        admin.execute('INSERT INTO public.viewer_live_windows VALUES(%s,%s,2,%s)',
                      (cutoff, cutoff+FIVE_NS, cutoff+FIVE_NS))
        add_request(admin, today)
        withdrawn = request(3, cutoff+2, 'withdrawn')
        add_request(admin, withdrawn)
        source.semantic_page_size = 1
        page = source.page()
        assert page['source']['scope_latest_published_end_ns'] == cutoff+FIVE_NS
        assert [r['request_key'] for r in page['rows']] == [today['request_key']] and page['has_more']
        assert [r['request_key'] for r in source.page(page['after'])['rows']] == [withdrawn['request_key']]
        packet = read_window(source, {'next_ns': cutoff-2*FIVE_NS})
        assert packet['target_ns'] == cutoff and [r['request_key'] for r in packet['rows']] == [today['request_key']]
        assert read_sample(source, {'next_ns': cutoff-2*FIVE_NS})['target_ns'] == cutoff
        assert apply_window(store, packet)['status'] == 'COMPLETE'
        checks['next_published_window_and_scoped_semantic_cursor_work'] = 'PASS'
        summary = raw.execute('SELECT xmin::text,body FROM anomaly_detection.adp_windows').fetchone()
        admin.execute('UPDATE public.viewer_live_state SET generation=3')
        admin.execute('UPDATE public.viewer_semantic_checkpoint SET generation=3')
        packet2 = read_window(source, {'target_ns': cutoff})
        assert packet2['stamp'] != packet['stamp']
        assert apply_window(store, packet2, cursor_name='overlap_cursor')['status'] == 'COMPLETE'
        assert raw.execute('SELECT xmin::text,body FROM anomaly_detection.adp_windows').fetchone() == summary
        assert raw.execute('SELECT stamp FROM anomaly_detection.adp_source_windows').fetchone()['stamp'] == packet2['stamp']
        checks['unchanged_session_summary_not_rewritten_on_new_receipt'] = 'PASS'
        assert reset(apply=True)['status'] == 'HISTORY_RESET_ALREADY_APPLIED'
        assert raw.execute('SELECT xmin::text,body FROM anomaly_detection.adp_windows').fetchone() == summary
        checks['same_cutoff_retry_keeps_new_processing'] = 'PASS'
    return checks


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--port', type=int, required=True)
    parser.add_argument('--pg-data-dir', type=Path, required=True)
    args = parser.parse_args()
    params = {'host': '127.0.0.1', 'port': args.port, 'dbname': 'postgres', 'user': 'postgres'}
    day = datetime.now(TIMEZONE).date().isoformat()
    _, cutoff = tehran_boundary(day)
    with psycopg.connect(**params, autocommit=True, row_factory=dict_row) as admin:
        version = admin.execute('SHOW server_version').fetchone()['server_version']
        admin.execute('CREATE DATABASE ' + DB)
        admin.execute('CREATE ROLE ' + ROLE + ' LOGIN NOSUPERUSER NOCREATEROLE NOCREATEDB')
    with tempfile.TemporaryDirectory(prefix='history26_fixture_', dir=ROOT/'validation') as folder:
        root = Path(folder)/'AnomalyDetection'
        (root/'data').mkdir(parents=True)
        (root/'data/pg_credentials.local.json').write_text(json.dumps({
            'installation_id': 'fixture26', 'connection': dict(params, dbname=DB, user=ROLE),
        }), encoding='utf-8')
        with psycopg.connect(**dict(params, dbname=DB), autocommit=True, row_factory=dict_row) as admin:
            source_fixture(admin, cutoff)
            checks = check_reset(admin, root, args.pg_data_dir, day, cutoff)
    print(json.dumps({'build_id': BUILD_ID, 'postgresql': version,
                      'environment': 'ISOLATED_LINUX_POSTGRESQL_FIXTURE',
                      'native_windows_owner': 'NOT_RUN', 'status': 'PASS_HISTORY_RESET_AND_SCOPED_INGEST',
                      'checks': checks}, indent=2))


if __name__ == '__main__':
    main()
