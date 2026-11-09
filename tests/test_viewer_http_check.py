"""Safe HTTP diagnosis cannot alter the previously measured publisher."""
import io
import json
import logging
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
from urllib.error import HTTPError

from LogManagment_HTTP_Check import HTTPDiagnostics,observe_http,route_kind,safe_error,main
from tools import run_viewer_pilot as pilot


class HTTPCheckTests(unittest.TestCase):
    def test_routes_do_not_expose_identifiers_or_queries(self):
        key='a'*64
        self.assertEqual(route_kind('http://127.0.0.1:1234/'),'home')
        self.assertEqual(route_kind('http://127.0.0.1/session/'+key+'/behavior?private=SECRET'),'session')
        self.assertEqual(route_kind('/request/'+key),'request')
        self.assertEqual(route_kind('/unrecognized/SECRET'),'other')

    def test_status_sqlstate_and_exception_chain_without_secrets(self):
        class SQLFailure(Exception):sqlstate='57014'
        try:
            try:raise SQLFailure('PRIVATE_SQL_VALUES')
            except SQLFailure:raise RuntimeError('PRIVATE_TEXT') from None
        except RuntimeError as exc:record=safe_error(exc)
        self.assertEqual(record['sqlstate'],'57014')
        self.assertNotIn('PRIVATE',json.dumps(record))
        record=safe_error(HTTPError('http://SECRET',500,'SECRET',{'SECRET':'SECRET'},io.BytesIO(b'SECRET')))
        self.assertEqual(record['http_status'],500);self.assertNotIn('SECRET',json.dumps(record))

    def test_request_failure_reaches_original_probe_and_dependencies_restore(self):
        failure=HTTPError('http://private',503,'SECRET',{},io.BytesIO(b'SECRET'))
        diag=HTTPDiagnostics();diag.stage='ingest_merge'
        with patch.object(pilot,'urlopen',side_effect=failure) as original:
            factory=pilot.create_viewer_app;console=pilot.ProgressConsole
            with self.assertRaises(HTTPError),observe_http(diag):pilot.urlopen('http://127.0.0.1/')
            self.assertIs(pilot.urlopen,original)
            self.assertIs(pilot.create_viewer_app,factory);self.assertIs(pilot.ProgressConsole,console)
        event=diag.snapshot()['client_failures'][0]
        self.assertEqual(event['http_status'],503);self.assertEqual(event['publisher_stage'],'ingest_merge')
        self.assertNotIn('SECRET',json.dumps(diag.snapshot()))

    def test_body_read_timeout_is_counted_and_not_hidden(self):
        class Response:
            def __enter__(self):return self
            def __exit__(self,*args):pass
            def read(self):raise TimeoutError('SECRET')
        diag=HTTPDiagnostics()
        with patch.object(pilot,'urlopen',return_value=Response()),observe_http(diag):
            with self.assertRaises(TimeoutError):
                with pilot.urlopen('/') as response:response.read()
        self.assertEqual(diag.client_error_count,1)
        self.assertEqual(diag.snapshot()['client_failures'][0]['exception_type'],'TimeoutError')

    def test_successful_response_and_server_error_have_separate_counts(self):
        from flask import Flask
        app=Flask('http-check-fixture')
        @app.get('/')
        def broken():
            try:raise ValueError('SECRET')
            except ValueError:app.logger.exception('SECRET')
            return 'error',500
        diag=HTTPDiagnostics()
        with patch.object(pilot,'create_viewer_app',return_value=app), \
                patch.object(pilot,'urlopen',return_value=io.BytesIO('فارسی'.encode())),observe_http(diag):
            generated=pilot.create_viewer_app({})
            with pilot.urlopen('/') as response:self.assertEqual(response.read().decode(),'فارسی')
            with patch.object(app.logger,'handlers',[h for h in app.logger.handlers if h.__class__.__name__=='SafeErrors']):
                self.assertEqual(generated.test_client().get('/').status_code,500)
        result=diag.snapshot()
        self.assertEqual(result['successful_requests_by_route'],{'home':1})
        self.assertEqual(result['client_error_count'],0);self.assertEqual(result['server_error_count'],1)
        self.assertNotIn('SECRET',json.dumps(result))

    def test_details_are_bounded_but_all_failures_count(self):
        diag=HTTPDiagnostics()
        for _ in range(75):diag.failure('client','home',TimeoutError('SECRET'),1)
        report=diag.snapshot()
        self.assertEqual(report['client_error_count'],75);self.assertEqual(len(report['client_failures']),50)

    def test_short_check_uses_existing_pilot_limits_without_accepting_prior_errors(self):
        with tempfile.TemporaryDirectory() as folder:
            output=Path(folder)/'http.json'
            def run(args):
                self.assertEqual(args[args.index('--windows')+1],'2')
                self.assertEqual(args[args.index('--rechecks')+1],'0')
                self.assertEqual(args[args.index('--max-minutes')+1],'12')
                child=Path(args[args.index('--out')+1])
                child.write_text(json.dumps({'status':'SMOKE_PASS','http_errors':0}))
                return 0
            with patch('tools.check_viewer_install.check',return_value={'status':'READY_TO_START'}), \
                    patch.object(pilot,'main',side_effect=run):
                self.assertEqual(main(['--config','unused.py','--out',str(output)]),0)
            report=json.loads(output.read_text())
            self.assertTrue(report['client_error_diagnostics_complete'])
            self.assertEqual(report['prior_http_errors_resolved'],'NOT_PROVEN')

    def test_failed_check_returns_failure_and_safe_report(self):
        with tempfile.TemporaryDirectory() as folder:
            output=Path(folder)/'http.json'
            with patch('tools.check_viewer_install.check',return_value={'status':'READY_TO_START'}), \
                    patch.object(pilot,'main',side_effect=RuntimeError('SECRET')):
                self.assertEqual(main(['--config','unused.py','--out',str(output)]),2)
            self.assertEqual(json.loads(output.read_text())['status'],'FAILED')
            self.assertNotIn('SECRET',output.read_text())


if __name__=='__main__':unittest.main()
