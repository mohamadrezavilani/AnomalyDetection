"""Starting only Web must never initialize schema or synchronize catalogs."""
import importlib.util
from pathlib import Path
import unittest
from unittest.mock import Mock
import http.client
from http.server import BaseHTTPRequestHandler,ThreadingHTTPServer
import json
import threading

spec=importlib.util.spec_from_file_location('existing_web',Path(__file__).resolve().parents[1]/'viewer_performance/Run_Viewer_Web.py')
web=importlib.util.module_from_spec(spec);spec.loader.exec_module(web)


class ExistingWebTests(unittest.TestCase):
    def test_postgres_preflight_only_reads_metadata_with_a_bounded_read_only_transaction(self):
        db=Mock();db.sqlite=False;db.all.return_value=[{'relname':name} for name in web.REQUIRED]
        factory=Mock();factory.return_value.__enter__=Mock(return_value=db);factory.return_value.__exit__=Mock(return_value=False)
        web.check_existing({'config':{'dbname':'p24_design_viewer'}},database_factory=factory)
        db.init.assert_not_called();db.init_semantic_index.assert_not_called();db.sync_service_catalog.assert_not_called()
        self.assertEqual(db.sql.call_args_list[0].args[0],'SET TRANSACTION READ ONLY')
        self.assertTrue(db.all.call_args.args[0].startswith('SELECT '))
        self.assertIn('pg_catalog.pg_class',db.all.call_args.args[0])

    def test_missing_schema_is_reported_instead_of_creating_it(self):
        db=Mock();db.sqlite=False;db.all.return_value=[]
        factory=Mock();factory.return_value.__enter__=Mock(return_value=db);factory.return_value.__exit__=Mock(return_value=False)
        with self.assertRaisesRegex(ValueError,'start_existing_viewer_worker_first'):
            web.check_existing({},database_factory=factory)
        db.init.assert_not_called()

    def test_only_the_existing_app_is_started_on_loopback_without_reloader(self):
        factory=Mock();options={'fixture':'existing'}
        web.serve_existing(options,factory=factory)
        factory.assert_called_once_with(options)
        factory.return_value.run.assert_called_once_with(host='127.0.0.1',port=5021,use_reloader=False,debug=False)

    def test_explicit_lan_binding_reaches_the_factory_and_listener_together(self):
        factory=Mock();options={'fixture':'existing'}
        web.serve_existing(options,factory=factory,host='10.20.30.40')
        factory.assert_called_once_with(options,lan_host='10.20.30.40')
        factory.return_value.run.assert_called_once_with(host='10.20.30.40',port=5021,use_reloader=False,debug=False)

    def test_known_lan_gateway_failure_chooses_loopback_without_changing_access_host(self):
        host='10.20.30.40'
        binding=web.choose_bind_host(host,probe=lambda h:{'http_status':502,'server':'BaseHTTP/0.6 Python/3.12'})
        self.assertEqual(binding,'127.0.0.1')
        factory=Mock();web.serve_existing({},factory=factory,host=host,bind_host=binding)
        factory.assert_called_once_with({},lan_host=host)
        self.assertEqual(factory.return_value.run.call_args.kwargs['host'],'127.0.0.1')
        for result in ({'http_status':500,'server':'BaseHTTP/0.6'}, {'http_status':502,'server':'OtherServer'}, {'error_type':'ConnectionRefusedError'}):
            self.assertEqual(web.choose_bind_host(host,probe=lambda h:result),host)

    def test_existing_http_proxy_becomes_healthy_after_its_loopback_backend_starts(self):
        from p24_foundation.viewer_ui import create_viewer_app
        from p24_foundation.viewer_runtime import runtime_source_digest
        from viewer_performance.Diagnose_Viewer_Web import probe
        from werkzeug.serving import make_server
        backend_port=[None]
        class Proxy(BaseHTTPRequestHandler):
            def log_message(self,*args):pass
            def do_GET(self):
                if backend_port[0] is None:
                    self.send_response(502);self.end_headers();self.wfile.write(b'Local service unavailable');return
                connection=http.client.HTTPConnection('127.0.0.1',backend_port[0],timeout=2)
                try:
                    connection.request('GET',self.path,headers={'Host':self.headers.get('Host')})
                    response=connection.getresponse();body=response.read()
                    self.send_response(response.status);self.send_header('Content-Length',str(len(body)));self.end_headers();self.wfile.write(body)
                finally:connection.close()
        proxy=ThreadingHTTPServer(('127.0.0.1',0),Proxy);proxy.daemon_threads=True
        proxy_thread=threading.Thread(target=proxy.serve_forever,daemon=True);proxy_thread.start()
        backend=None;thread=None
        try:
            host='10.20.30.40'
            binding=web.choose_bind_host(host,probe=lambda h:probe('127.0.0.1',proxy.server_port,'/healthz'))
            self.assertEqual(binding,'127.0.0.1')
            backend=make_server(binding,0,create_viewer_app({},lan_host=host))
            backend_port[0]=backend.server_port
            thread=threading.Thread(target=backend.serve_forever,daemon=True);thread.start()
            client=http.client.HTTPConnection('127.0.0.1',proxy.server_port,timeout=2)
            try:
                client.request('GET','/healthz',headers={'Host':host+':5021'})
                response=client.getresponse();data=json.loads(response.read())
                self.assertEqual(response.status,200)
                self.assertTrue(response.getheader('Server').startswith('BaseHTTP/'))
                self.assertEqual(data['service'],'viewer');self.assertEqual(data['runtime_sha256'],runtime_source_digest())
            finally:client.close()
        finally:
            if backend is not None:backend.shutdown();backend.server_close()
            proxy.shutdown();proxy.server_close();proxy_thread.join(2)
            if thread is not None:thread.join(2)


if __name__=='__main__':unittest.main()
