"""Small native functional check in ONE newly created synthetic Viewer database.

No server restart, ES requests, throughput pilot or changes to owner data.
The synthetic database and evidence are retained.
"""
from __future__ import annotations
import copy
from pathlib import Path
import uuid

from p24_foundation.viewer_data import ViewerDB, token
from p24_foundation.privacy import generate_keys
from p24_foundation.viewer_online import initialize_live, bind_stream, publish_capture, FIVE_NS, iso
from tools.qualify_viewer_online import projection_digest


def qualify(database, directory, progress=None):
    if not __debug__:
        raise RuntimeError('native_checks_require_assertions')
    import psycopg
    from psycopg import sql
    from tests.test_viewer_payment_correlations import scenario, event, correlation, I, B, B2, B3, FEE, PAY, PAY2
    from tests.test_viewer_online import START, verified_file
    directory = Path(directory)
    directory.mkdir(parents=True, exist_ok=False)
    name = 'p24_design_corr_' + uuid.uuid4().hex[:8] + '_qualification'
    # CREATE (without IF NOT EXISTS) ensures we can never reuse an existing DB.
    with psycopg.connect(**dict(database, dbname='postgres'), autocommit=True) as conn:
        conn.execute(sql.SQL('CREATE DATABASE {} TEMPLATE template0').format(sql.Identifier(name)))
    from p24_foundation.viewer_runtime import atomic_json
    atomic_json(directory / 'database.private.json', dict(database=name))
    config = dict(database, dbname=name)
    keys = directory / 'synthetic_keys.private.json'
    generate_keys(keys)
    checks = {}
    definitions = [
        ('free_lookup', [event(1, 'inquiry', 'Public.v1/ExchangeCurrency Line:1', 'POST (G00000 | successful)')]),
        ('free_inquiry_bill', scenario(paid=False, bill_pay=False, api='WaterBills')),
        ('paid_inquiry_only', scenario(bills=(), bill_pay=False, api='PostPackagesStatus')),
        ('paid_inquiry_three_bills', scenario(bills=(B, B2, B3), status=None)),
    ]
    with ViewerDB(config=config, keys_path=keys) as db:
        db.progress_callback = progress
        db.init(); initialize_live(db); bind_stream(db, start_ns=START, stream_key='new_synthetic_payment_correlations')
        last_rows = last_ids = last_request = None
        for index, (kind, template) in enumerate(definitions):
            start = START + index * FIVE_NS
            replacements = {value: uuid.uuid4().hex.upper() for value in (I, B, B2, B3, FEE, PAY, PAY2)}
            session = uuid.uuid4().hex.upper()
            rows = copy.deepcopy(template)
            for ordinal, row in enumerate(rows):
                row['_source_id'] = 'synthetic-native-correlations:' + str(index) + '_' + str(ordinal)
                row['RequestID'] = kind + '-' + row['RequestID']
                if row['Session'] != 'N/A':
                    row['Session'] = session
                row['@timestamp'] = iso(start + (ordinal + 1) * 1_000_000_000)
                for old, new in replacements.items():
                    row['message'] = row['message'].replace(old, new)
            path = verified_file(directory / (kind + '.gz'), rows, start)
            publish_capture(db, path, start, start + FIVE_NS)
            request_key = token(db.keys, 'request', kind + '-inquiry')
            card = db.service_payment_journey(request_key)
            if index == 0:
                assert card is None
            else:
                group = card['invoices'][0]
                assert group['invoice_id'] == replacements[I]
                assert len(group['sources']) == 1
                assert len(group['bills']) == (1 if index == 1 else 0 if index == 2 else 3)
                assert len(group['inquiry_payments']) == (0 if index == 1 else 1)
                assert len(group['bill_payments']) == (1 if index == 3 else 0)
                if index == 3:
                    assert len(group['bill_payments'][0]['targets']) == 3
                    assert group['bill_payments'][0]['outcome'] == 'unobserved'
            checks[kind] = True
            last_rows, last_ids, last_request = rows, replacements, request_key
        assert db.one("SELECT COUNT(*) AS n FROM viewer_semantic_occurrences WHERE state='active'")['n'] == 4
        assert db.semantic_sessions()['total'] == 4
        checks['payments_do_not_add_home_behaviors'] = True
        cursor = db.one('SELECT next_ns FROM viewer_live_state')['next_ns']
        anchors = db.all('SELECT * FROM viewer_semantic_session_heads ORDER BY session_key')
        late = correlation(99, 'late-native-status', 'PaymentKey-Status',
                           dict(PaymentKey=last_ids[PAY], Status='Success'), session='N/A', start=START + 3 * FIVE_NS)
        late['_source_id'] = 'synthetic-native-correlations:late'
        path = verified_file(directory / 'late.gz', last_rows + [late], START + 3 * FIVE_NS)
        publish_capture(db, path, START + 3 * FIVE_NS, START + 4 * FIVE_NS, mode='manual_recheck')
        assert db.service_payment_journey(last_request)['invoices'][0]['bill_payments'][0]['outcome'] == 'success'
        assert db.one('SELECT next_ns FROM viewer_live_state')['next_ns'] == cursor
        assert db.all('SELECT * FROM viewer_semantic_session_heads ORDER BY session_key') == anchors
        checks['late_sessionless_status_preserves_cursor_and_anchors'] = True
        before = projection_digest(db)
        raw_before = db.one('SELECT COUNT(*) AS n FROM viewer_raw_events')['n']
        publish_capture(db, path, START + 3 * FIVE_NS, START + 4 * FIVE_NS, mode='manual_recheck')
        assert projection_digest(db) == before
        assert db.one('SELECT COUNT(*) AS n FROM viewer_raw_events')['n'] == raw_before
        checks['duplicate_recheck_idempotent'] = True
        failure = copy.deepcopy(late)
        failure['_source_id'] = 'synthetic-native-correlations:fault'
        failure['RequestID'] = 'native-fault-status'
        failure['@timestamp'] = iso(cursor + 1_000_000_000)
        failure['message'] = failure['message'].replace('Success', 'Failed')
        fail_path = verified_file(directory / 'rollback.gz', [failure], cursor)
        def fault(stage):
            if stage == 'before_commit':
                raise RuntimeError('native_payment_test_rollback')
        try:
            publish_capture(db, fail_path, cursor, cursor + FIVE_NS, fault=fault)
        except RuntimeError as exc:
            assert str(exc) == 'native_payment_test_rollback'
        else:
            raise AssertionError('fault not reached')
        assert projection_digest(db) == before
        assert db.one('SELECT COUNT(*) AS n FROM viewer_raw_events')['n'] == raw_before
        assert db.one('SELECT next_ns FROM viewer_live_state')['next_ns'] == cursor
        checks['new_relationships_rollback_atomically'] = True
        db.rebuild(); db.rebuild_payment_contract(); db.build_semantic_index()
        assert projection_digest(db) == before
        checks['incremental_equals_full_projection'] = True
    return dict(status='PASS', database=name, checks=checks, created_empty_database=True,
                scope='small_native_functional_only_not_capacity_recovery_or_financial_settlement')
