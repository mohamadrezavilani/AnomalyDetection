"""Actionable configuration failures without source, passwords or driver text."""
from contextlib import redirect_stdout
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from p24_foundation.config import read_config
from p24_foundation.errors import FoundationError
from tools.check_local_config import check


CONFIG='''DATABASE = {"host":"127.0.0.1","port":5432,"dbname":"p24_design_check","user":"postgres","password":"PRIVATE_PASSWORD"}
NAMESPACE = "local-test"
KEYS_PATH = "private/evidence.keys.json"
VAULT_PATH = "private/evidence_vault"
'''


class ConfigDiagnosticTests(unittest.TestCase):
    def setUp(self):
        self.directory=tempfile.TemporaryDirectory()
        self.path=Path(self.directory.name)/'config.local.py'

    def tearDown(self):
        self.directory.cleanup()

    def write(self,source):
        self.path.write_text(source,encoding='utf-8')

    def test_valid_config_loads_without_private_key_files_or_network(self):
        self.write(CONFIG)
        with patch('tools.check_local_config.connect',side_effect=AssertionError('must not connect')):
            result=check(self.path)
        self.assertEqual(result['status'],'PASS')
        self.assertTrue(result['password_configured'])
        self.assertNotIn('PRIVATE_PASSWORD',json.dumps(result))
        self.assertFalse(result['private_keys_required_for_native_tests'])

    def test_missing_file_is_distinguished(self):
        self.assertEqual(check(self.path)['error'],'local_configuration_file_missing')
        with self.assertRaisesRegex(FoundationError,'local_configuration_file_missing'):
            read_config(self.path)

    def test_missing_required_fields_are_identified_by_name(self):
        for name in ('DATABASE','NAMESPACE','KEYS_PATH','VAULT_PATH'):
            self.write('\n'.join(line for line in CONFIG.splitlines() if not line.startswith(name+' =')))
            self.assertEqual(check(self.path)['error'],'configuration_missing_'+name.lower())

    def test_syntax_reports_line_number_without_source_or_password(self):
        self.write(CONFIG+'PASSWORD = "PRIVATE_PASSWORD"\nBROKEN = (\n')
        result=check(self.path)
        self.assertEqual(result['error'],'local_configuration_syntax_error')
        self.assertEqual(result['line'],6)
        self.assertNotIn('PRIVATE_PASSWORD',json.dumps(result))

    def test_unquoted_password_and_config_prints_never_echo(self):
        self.write('print("PRIVATE_PASSWORD")\nDATABASE = PRIVATE_PASSWORD\n')
        output=io.StringIO()
        with redirect_stdout(output):
            result=check(self.path)
        self.assertEqual(result['error'],'local_configuration_execution_failed')
        self.assertNotIn('PRIVATE_PASSWORD',output.getvalue()+json.dumps(result))

    def test_windows_path_escape_is_diagnosed_without_echoing_the_path(self):
        self.write(CONFIG+'EXTRA_PATH = "C:\\Users\\Administrator\\private"\n')
        result=check(self.path)
        self.assertEqual(result['error'],'local_configuration_syntax_error')
        self.assertNotIn('Administrator',json.dumps(result))

    def test_driver_authentication_error_is_classified_without_private_message(self):
        self.write(CONFIG)
        class AuthError(Exception):
            sqlstate='28P01'
        with patch('tools.check_local_config.connect',side_effect=AuthError('PRIVATE_PASSWORD')):
            result=check(self.path,ping=True)
        self.assertEqual(result['error'],'database_authentication_failed')
        self.assertNotIn('PRIVATE_PASSWORD',json.dumps(result))

    def test_application_database_guard_stays_enabled(self):
        self.write(CONFIG.replace('p24_design_check','pishkhan24_shadow'))
        self.assertEqual(check(self.path)['error'],'database_requires_disposable_name')

    def test_native_startup_failure_writes_result_instead_of_losing_diagnostic(self):
        from tools.run_tests import startup_failure
        path=Path(self.directory.name)/'result.json'
        output=io.StringIO()
        with redirect_stdout(output):
            self.assertEqual(startup_failure(path,FoundationError('configuration_missing_namespace')),2)
        result=json.loads(path.read_text(encoding='utf-8'))
        self.assertEqual(result['startup_error'],'configuration_missing_namespace')
        self.assertEqual(result['tests'],0)
        self.assertNotIn('PRIVATE_PASSWORD',output.getvalue())
