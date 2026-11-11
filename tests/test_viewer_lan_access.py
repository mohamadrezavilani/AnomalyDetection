"""Explicit private-LAN access keeps host/client guards and page layout intact."""
import unittest
import os
from p24_foundation.viewer_ui import create_viewer_app


class ViewerLanTests(unittest.TestCase):
    @unittest.skipUnless(os.name=='nt','native Windows HTTP listener')
    def test_windows_listener_serves_a_real_health_request(self):
        import http.client,json,threading
        from werkzeug.serving import make_server
        server=make_server('127.0.0.1',0,create_viewer_app({}));server.timeout=5
        thread=threading.Thread(target=server.handle_request,daemon=True);thread.start()
        try:
            connection=http.client.HTTPConnection('127.0.0.1',server.server_port,timeout=3)
            try:
                connection.request('GET','/healthz');response=connection.getresponse()
                self.assertEqual(response.status,200)
                self.assertEqual(json.loads(response.read())['service'],'viewer')
            finally:connection.close()
        finally:thread.join(timeout=5);server.server_close()

    def test_default_still_rejects_remote_clients_and_untrusted_hosts(self):
        client=create_viewer_app({}).test_client()
        self.assertEqual(client.get('/healthz',environ_base={'REMOTE_ADDR':'10.20.30.41'}).status_code,403)
        self.assertEqual(client.get('/healthz',base_url='http://10.20.30.40:5021/').status_code,400)
        self.assertEqual(client.get('/healthz').json['service'],'viewer')

    def test_explicit_private_host_allows_private_clients_and_keeps_public_clients_out(self):
        client=create_viewer_app({},lan_host='10.20.30.40').test_client()
        url='http://10.20.30.40:5021/'
        for address in ('10.20.30.41','10.1.2.3','192.168.1.2','127.0.0.1'):
            result=client.get('/healthz',base_url=url,environ_base={'REMOTE_ADDR':address})
            self.assertEqual(result.status_code,200,address)
            self.assertEqual(result.json['status'],'ok')
            self.assertEqual(len(result.json['runtime_sha256']),64)
            self.assertEqual(result.headers['Cache-Control'],'no-store')
        for address in ('8.8.8.8','198.51.100.1','not-an-address'):
            self.assertEqual(client.get('/healthz',base_url=url,environ_base={'REMOTE_ADDR':address}).status_code,403)
        self.assertEqual(client.get('/healthz',base_url='http://untrusted.example/',environ_base={'REMOTE_ADDR':'10.20.30.41'}).status_code,400)

    def test_public_or_wildcard_bind_is_not_enabled_by_the_lan_option(self):
        for address in ('0.0.0.0','8.8.8.8','198.51.100.1','example.com'):
            with self.assertRaises(ValueError):create_viewer_app({},lan_host=address)


if __name__=='__main__':unittest.main()
