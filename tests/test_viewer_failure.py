"""Preserve actionable machine causes through hidden worker exceptions."""
import io
import json
import socket
import unittest
from unittest.mock import patch
from urllib.error import HTTPError,URLError

from p24_foundation.viewer_failure import describe_failure
from tests.test_viewer_online import START


class ViewerFailureDiagnosticsTests(unittest.TestCase):
    def hidden(self,root):
        try:
            try:raise root
            except Exception:raise RuntimeError('capture_or_publication_failed') from None
        except RuntimeError as wrapper:return describe_failure(wrapper)

    def test_http_status_and_type_survive_hidden_cause_without_secrets(self):
        payload={'error':{'type':'security_exception','reason':'PRIVATE_REASON password=DO_NOT_SHOW'}}
        e=HTTPError('http://PRIVATE_HOST/_search?token=DO_NOT_SHOW',403,
                    'PRIVATE_ERROR',{'Authorization':'PRIVATE_AUTH'},io.BytesIO(json.dumps(payload).encode()))
        r=self.hidden(e);text=json.dumps(r)
        self.assertEqual(r['http_status'],403);self.assertEqual(r['elasticsearch_error_type'],'security_exception')
        self.assertEqual(r['code'],'es_permission_denied')
        for secret in ('PRIVATE','DO_NOT_SHOW','Authorization','password='):self.assertNotIn(secret,text)

    def test_dns_and_timeout_inside_url_error_have_distinct_codes(self):
        self.assertEqual(self.hidden(URLError(socket.gaierror(-2,'SECRET_HOST')))['code'],'dns_resolution_failed')
        self.assertEqual(self.hidden(URLError(TimeoutError('SECRET_URL')))['code'],'connection_or_capture_timeout')

    def test_sqlstate_without_driver_error_message(self):
        class SQLFailure(Exception):sqlstate='42703'
        r=self.hidden(SQLFailure('SQL WITH PRIVATE CUSTOMER VALUES'))
        self.assertEqual(r['sqlstate'],'42703');self.assertNotIn('PRIVATE',json.dumps(r))

    def test_known_integrity_error_is_visible_and_arbitrary_value_is_hidden(self):
        self.assertEqual(self.hidden(ValueError('incomplete_search_page'))['code'],'incomplete_search_page')
        self.assertEqual(self.hidden(ValueError('PRIVATE_RAW_PAYLOAD'))['code'],'unexpected_error')
        self.assertNotIn('PRIVATE',json.dumps(self.hidden(ValueError('PRIVATE_RAW_PAYLOAD'))))

    def test_malformed_http_body_does_not_escape_report(self):
        r=self.hidden(HTTPError('http://private',502,'PRIVATE',{},io.BytesIO(b'<html>PRIVATE</html>')))
        self.assertEqual(r['code'],'es_gateway_error');self.assertNotIn('PRIVATE',json.dumps(r))

    def test_online_ingest_preserves_sql_cause_and_rolls_back(self):
        import tempfile
        from pathlib import Path
        from p24_foundation.viewer_data import ViewerDB
        from p24_foundation.privacy import generate_keys
        from p24_foundation.viewer_online import LiveWorker,initialize_live,bind_stream,FIVE_NS
        from tests.test_viewer_online import verified_file
        from tests.test_viewer_r6_service_journey import log
        class SQLFailure(Exception):sqlstate='42703'
        with tempfile.TemporaryDirectory() as t:
            root=Path(t);generate_keys(root/'keys')
            with ViewerDB(sqlite_path=root/'data',keys_path=root/'keys') as db:
                db.init();initialize_live(db);bind_stream(db,start_ns=START,stream_key='failure_fixture')
                path=verified_file(root/'window.gz',[log(1,'q','Services.v1/WaterBills Line:1','POST (G00000 | successful)')])
                original=db.sql
                def failing_sql(statement,params=()):
                    if 'INSERT INTO viewer_events(' in statement:raise SQLFailure('PRIVATE_SQL_PARAMETER')
                    return original(statement,params)
                with patch.object(db,'sql',side_effect=failing_sql):
                    try:LiveWorker(db,lambda *args:path).step(now=START+FIVE_NS+60_000_000_000)
                    except RuntimeError as e:detail=describe_failure(e)
                    else:self.fail('Expected injected SQL failure')
                self.assertEqual(detail['sqlstate'],'42703')
                self.assertEqual(db.one('SELECT COUNT(*) AS n FROM viewer_events')['n'],0)
                self.assertEqual(db.one('SELECT next_ns FROM viewer_live_state')['next_ns'],START)
                self.assertNotIn('PRIVATE',json.dumps(detail))

    def test_pilot_preserves_http_diagnostic_and_creates_report_on_failure(self):
        # Exercise the real pilot entry point, replacing only its dependencies.
        import tempfile
        from pathlib import Path
        from tools import run_viewer_pilot as pilot
        from contextlib import nullcontext,redirect_stdout
        with tempfile.TemporaryDirectory() as t:
            root=Path(t);config=root/'config.py';keys=root/'keys';keys.write_text('fixture')
            config.write_text('KEYS_PATH = '+repr(str(keys))+'\nDATABASE = {}\nELASTICSEARCH = {}\nLIVE_START_UTC="2026-10-24T04:15:00Z"\n')
            class DB:
                def __enter__(self):return self
                def __exit__(self,*a):pass
                def init(self):pass
                def one(self,*a,**k):return {'next_ns':START}
            class Worker:
                def __init__(self,*a,**k):pass
                def step(self,*a,**k):
                    try:raise HTTPError('http://private',401,'PRIVATE',{},io.BytesIO(b'{}'))
                    except Exception:raise RuntimeError('capture_or_publication_failed') from None
            class Server:
                server_port=12345
                def serve_forever(self):pass
                def shutdown(self):pass
                def server_close(self):pass
            with patch.object(pilot,'ViewerDB',return_value=DB()),patch.object(pilot,'single_worker',side_effect=lambda *a:nullcontext()),patch.object(pilot,'initialize_live'),patch.object(pilot,'bind_stream'),patch.object(pilot,'live_status',return_value={'backlog_windows':6}),patch.object(pilot,'ElasticREST'),patch.object(pilot,'ElasticCapture'),patch.object(pilot,'LiveWorker',Worker),patch.object(pilot,'make_server',return_value=Server()),patch.object(pilot,'urlopen',side_effect=OSError()),redirect_stdout(io.StringIO()) as output:
                out=root/'result.json'
                self.assertEqual(pilot.main(['--config',str(config),'--out',str(out)]),2)
            report=json.loads(out.read_text())
            self.assertEqual(report['failure']['http_status'],401)
            self.assertEqual(report['failure']['code'],'es_authentication_failed')
            self.assertEqual(report['windows'],[])
            self.assertNotIn('PRIVATE',out.read_text()+output.getvalue())

if __name__=='__main__':unittest.main()
