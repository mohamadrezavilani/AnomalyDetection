"""Differentiate an actual Viewer from a proxy or a different HTTP process."""
import importlib.util
from pathlib import Path
import unittest
from unittest.mock import patch

FILE = Path(__file__).resolve().parents[1]/'viewer_performance/Diagnose_Viewer_Web.py'
SPEC = importlib.util.spec_from_file_location('direct_viewer_web', FILE)
web = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(web)


class DirectWebTests(unittest.TestCase):
    def test_direct_http_does_not_use_proxy_environment(self):
        class Response:
            status = 502
            def getheader(self, name):return 'BaseHTTP/0.6 Python/3.12'
            def read(self, size):return b'Local service unavailable'
        with patch.object(web.http.client, 'HTTPConnection') as factory:
            factory.return_value.getresponse.return_value = Response()
            with patch.dict(web.os.environ, {'HTTP_PROXY': 'http://invalid.invalid:99', 'NO_PROXY': ''}):
                result = web.probe('127.0.0.1', 5021, '/healthz')
            factory.assert_called_once_with('127.0.0.1', 5021, timeout=5)
            self.assertEqual(result, {'http_status': 502, 'server': 'BaseHTTP/0.6 Python/3.12', 'direct_socket': True})

    def test_home_diagnostic_does_not_read_or_export_customer_html(self):
        with patch.object(web.http.client, 'HTTPConnection') as factory:
            factory.return_value.getresponse.return_value.status = 500
            factory.return_value.getresponse.return_value.getheader.return_value = 'Werkzeug'
            result = web.probe('127.0.0.1', 5021, '/')
            factory.return_value.getresponse.return_value.read.assert_not_called()
            self.assertEqual(result['http_status'], 500)


if __name__ == '__main__':
    unittest.main()
