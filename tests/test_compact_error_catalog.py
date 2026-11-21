import tempfile
from pathlib import Path
import unittest
from unittest.mock import MagicMock, patch
from flask import render_template

from compact_product.error_catalog import catalog_records, definitions
from compact_product.presentation import data_note
from compact_product.web import create_app
from compact_product.config import Config


class ErrorCatalogTests(unittest.TestCase):
    def test_all_supplied_rows_and_updated_definition(self):
        rows = [r for r in catalog_records() if "source_file" in r]
        self.assertEqual(len(rows), 1925)
        self.assertEqual(len({r['source_file'] for r in rows}), 8)
        self.assertEqual(len({r['entry_id'] for r in rows}), len(rows))
        by_code = {r['code']: r for r in rows}
        r = by_code['GR0010']
        self.assertEqual(r['log_symbol'], 'ServiceUnavailable')
        self.assertEqual(r['source_row'], 11)
        self.assertEqual(r['source_file'], 'Pishkhan24-ErrorCodes.xlsx')
        self.assertIn('امکان برقراری ارتباط', r['user_message_fa'])
        self.assertEqual(by_code['GD2148']['definition_state'], 'complete_definition')
        self.assertIn('یکطرفه', by_code['GD2148']['user_message_fa'])
        self.assertEqual(sum(bool(r['user_message_fa']) for r in rows), 905)
        self.assertNotIn('G00000', by_code)  # no fabricated workbook description

    def test_owner_success_definition_has_honest_provenance(self):
        rows = [r for r in catalog_records() if r['code'] == 'G00000']
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]['user_message_fa'], 'موفقیت سرویس')
        self.assertEqual(rows[0]['source']['kind'], 'owner_definition')
        self.assertNotIn('source_file', rows[0])
        app = create_app(Config(), {}, 'test', secret='test')
        with app.test_request_context('/'):
            template = app.jinja_env.from_string("{% from 'result.html' import result %}{{ result('G00000', entries, true) }}")
            html = template.render(entries={'G00000': [dict(message_fa=rows[0]['user_message_fa'], log_symbol=None, source=rows[0]['source'])]})
        self.assertIn('موفقیت سرویس', html)
        self.assertIn('تعریف صریح مالک پروژه', html)
        self.assertNotIn('برگهٔ', html)

    def test_changed_source_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            p = Path(tmp) / 'catalogs'
            p.mkdir()
            (p / 'error_code_catalog.json').write_text('{}')
            with self.assertRaisesRegex(ValueError, 'source_bytes_changed'):
                catalog_records(tmp)

    def test_lookup_is_batched_read_only_and_retains_ambiguous_definitions(self):
        db = MagicMock()
        db.execute.return_value.fetchone.return_value = {'name': 'table'}
        db.execute.return_value.fetchall.return_value = [
            dict(code='X', code_system='first', message_fa='one'),
            dict(code='X', code_system='second', message_fa='two'),
        ]
        result = definitions(db, 'p24_compact_test', ['X', None, 'X', 'Y'])
        self.assertEqual(len(result['X']), 2)
        self.assertEqual(db.execute.call_count, 2)
        sql, args = db.execute.call_args.args
        self.assertTrue(sql.startswith('SELECT'))
        self.assertEqual(args[1], ['X', 'Y'])
        db.reset_mock()
        self.assertEqual(definitions(db, 'p24_compact_test', []), {})
        db.execute.assert_not_called()
        db.execute.return_value.fetchone.return_value = {'name': None}
        self.assertEqual(definitions(db, 'p24_compact_test', ['X']), {})
        self.assertEqual(db.execute.call_count, 1)

    def test_result_notes_unknown_and_escaping(self):
        app = create_app(Config(), {}, 'test', secret='test')
        row = dict(api='Services.v1/InvoiceRegister', request_id='request', session_id='session',
            observed_at_ns=0, result_code='GR0010', revision=1,
            quality=['output_binding_unconfirmed', 'unresolved_dispatch'],
            state={'inputs': [], 'outputs': []})
        body = dict(operation_role='unknown', service_key=None, features={})
        entry = dict(message_fa='<script>alert(1)</script>', log_symbol='ServiceUnavailable',
            source=dict(file='Pishkhan24-ErrorCodes.xlsx', sheet='Sheet1', row=11))
        with app.test_request_context('/behaviors/test'):
            html = render_template('behavior.html', title='جزئیات رفتار', row=row, body=body,
                code_definitions={'GR0010': [entry]})
            self.assertIn('Services.v1/InvoiceRegister', html)
            self.assertIn('2 توضیح دربارهٔ شواهد', html)
            self.assertIn(data_note('unresolved_dispatch'), html)
            self.assertIn('نقش مشخص نشده', html)
            self.assertNotIn('نکتهٔ کیفیت', html)
            self.assertNotIn('<script>alert', html)
            self.assertIn('&lt;script&gt;', html)
            self.assertIn('Pishkhan24-ErrorCodes.xlsx', html)
            self.assertIn('ردیف 11', html)
            # Missing and ambiguous definitions remain explicit.
            template = app.jinja_env.from_string("{% from 'result.html' import result %}{{ result(code, entries, true) }}")
            self.assertIn('در دسترس نیست', template.render(code='missing', entries={}))
            entry['message_fa'] = None
            self.assertIn('شرح فارسی', template.render(code='X', entries={'X': [entry]}))
            self.assertIn('انتساب قطعی نیست', template.render(code='X', entries={'X': [entry,entry]}))

    def test_sessions_preserve_selected_scope_and_do_one_catalog_batch(self):
        with patch('compact_product.web.Store') as store, patch('compact_product.web.definitions', return_value={}) as lookup:
            store.return_value.conn.execute.return_value.fetchall.return_value = [dict(
                behavior_id='b', api='Core.v1/LoginByOTP', service_key=None, result_code='GR0010',
                quality=[], observed_at_ns=0, session_id='s', request_id='r')]
            client = create_app(Config(), {}, 'test', secret='test').test_client()
            response = client.get('/sessions?q=s&scope=all')
            self.assertEqual(response.status_code, 200)
            html = response.get_data(as_text=True)
            self.assertIn('name="scope" value="all"', html)
            lookup.assert_called_once()
            self.assertEqual(lookup.call_args.args[2], ['GR0010'])
