import copy,importlib,json,re,subprocess,sys,tempfile,unittest
from pathlib import Path
from unittest.mock import patch

from p24_foundation.config import validate_database_config
from p24_foundation.errors import FoundationError
from p24_foundation.intake import decode_batch
from p24_foundation.parser import sql_parameters,client_context
from p24_foundation.privacy import Keys,Vault,canonical
from p24_foundation.reconstruction import select_events,reconstruct,registration_candidates
from p24_foundation.time import parse_time,microsecond_cutoff
from tests.helpers import ROOT,TEST_KEYS,MANIFEST,fixture,document,batch,normalized

class TimeAndIntakeTests(unittest.TestCase):
    def test_exact_seventh_digit_offset_and_floor(self):
        t=parse_time('2026-10-20T10:58:22.4406337+03:30')
        self.assertEqual(t.floor.isoformat(),'2026-10-20T07:28:22.440633+00:00')
        self.assertEqual(t.epoch_ns%1000,700);self.assertEqual(t.fraction_digits,7)
    def test_final_nanosecond_does_not_round_into_next_window(self):
        a=parse_time('2026-10-20T07:29:59.999999999Z');b=parse_time('2026-10-20T07:30:00Z')
        self.assertEqual(b.epoch_ns-a.epoch_ns,1)
        self.assertEqual(a.floor.isoformat(),'2026-10-20T07:29:59.999999+00:00')
    def test_naive_invalid_and_too_precise_times_are_rejected(self):
        for value in ('2026-10-20T11:00:00','2026-02-30T11:00:00Z','2026-10-20T11:00:00.1234567890Z','2026-10-20T11:00:00+24:00'):
            with self.subTest(value=value),self.assertRaises(FoundationError):parse_time(value)
    def test_projection_cutoff_cannot_silently_lose_nanoseconds(self):
        with self.assertRaises(FoundationError):microsecond_cutoff('2026-10-20T11:00:00.0000001Z')
    def test_pre_epoch_time_uses_floor(self):
        a=parse_time('1969-12-31T23:59:59.9999999Z')
        self.assertEqual(a.epoch_ns,-100);self.assertEqual(a.floor.isoformat(),'1969-12-31T23:59:59.999999+00:00')
    def test_actual_export_counts_ignore_wrapper_progress_total(self):
        data=fixture('ip_activity.sanitized.json')
        self.assertEqual(len(data.records),36);self.assertIsNone(data.coverage['query_total'])
        self.assertFalse(data.coverage['query_complete']);self.assertFalse(data.coverage['source_window_complete'])
    def test_json_array_stream_and_fields_only_formats(self):
        a=document();b=document(rid='B',oid='B')
        self.assertEqual(len(decode_batch((json.dumps(a)+'\n'+json.dumps(b)).encode()).records),2)
        self.assertEqual(len(batch([a,b]).records),2)
        self.assertEqual(fixture('session_activity.sanitized.json').coverage['fields_only_records'],33)
    def test_partial_timeout_and_shard_failure_do_not_look_complete(self):
        for extra in ({'timed_out':True},{'_shards':{'failed':1}}):
            with self.assertRaises(FoundationError):decode_batch(json.dumps({'hits':{'hits':[]},**extra}).encode())
        with self.assertRaises(FoundationError):decode_batch(b'{"isPartial":true,"rawResponse":{"hits":{"hits":[]}}}')
    def test_exact_query_total_is_not_source_manifest_completeness(self):
        data=decode_batch(json.dumps({'hits':{'total':{'value':1,'relation':'eq'},'hits':[document()]}}).encode())
        self.assertTrue(data.coverage['query_complete']);self.assertFalse(data.coverage['source_window_complete'])
    def test_limits_malformed_json_and_nonfinite_numbers(self):
        for value in (b'{secret=',b'{"fields":{"x":[NaN]}}',b''):
            with self.assertRaises(FoundationError) as e:decode_batch(value)
            self.assertNotIn('secret=',str(e.exception))
        with self.assertRaises(FoundationError):decode_batch(b'[]',max_bytes=1)
        with self.assertRaises(FoundationError):decode_batch(json.dumps([document(),document()]).encode(),max_records=1)

class ParserAndReconstructionTests(unittest.TestCase):
    def test_provider_body_failure_and_success_log_are_separate(self):
        e=normalized(list(fixture('boundary.sanitized.json').records))
        provider=next(x['descriptor'] for x in e if x['descriptor']['role']=='provider')
        self.assertEqual(provider['operation_outcome'],'failure')
        self.assertEqual([(o['code'],o['layer']) for o in provider['outcomes']],[('G00000','platform_log'),('GD2016','provider_body')])
    def test_real_boundary_partition_and_final_request_counts(self):
        events=normalized(list(fixture('boundary.sanitized.json').records))
        early=reconstruct(select_events(events,parse_time('2026-10-20T07:30:00Z').epoch_ns))[0]
        full=reconstruct(select_events(events,parse_time('2026-10-20T07:35:00Z').epoch_ns))[0]
        self.assertEqual((early['selected_event_count'],early['client_completion_state'],early['final_outcome']),(11,'not_observed','unknown'))
        self.assertEqual((full['selected_event_count'],full['sql_observation_count'],full['provider_observation_count'],full['distinct_client_request_count']),(14,12,1,1))
        self.assertEqual((full['outcome_code'],full['final_outcome']),('GD2016','failure'))
    def test_real_session_phase_and_outcome_counts(self):
        events=normalized(list(fixture('session_activity.sanitized.json').records))
        results=reconstruct(select_events(events,parse_time('2026-10-20T07:40:00Z').epoch_ns))
        self.assertEqual(len(results),10)
        self.assertEqual(sum(s['final_outcome']=='failure' for s in results),4)
        self.assertEqual(sum(s['classification']['phase']=='otp_generation' for s in results),1)
        self.assertEqual(sum(s['classification']['phase']=='application_support' for s in results),5)
        self.assertEqual(len({s['session_key'] for s in results}),1)
        self.assertEqual(len({u for s in results for u in s['client_contexts']}),2)
    def test_registration_versions_application_labels_and_missing_identity(self):
        events=normalized(list(fixture('registration.sanitized.json').records))
        results=reconstruct(select_events(events,parse_time('2026-10-20T07:40:00Z').epoch_ns))
        self.assertEqual(len(results),2)
        self.assertTrue(all(s['identity_state']=='missing' for s in results))
        self.assertEqual({e['descriptor']['application_label'] for e in events if e['descriptor']['application_label']},{'ewano','pishkhan24'})
        self.assertTrue(all(e['time'].fraction_digits==7 for e in events))
    def test_structured_session_retained_without_sql_or_ip(self):
        d=document(ip='N/A');result=reconstruct(select_events(normalized([d]),parse_time('2026-10-20T07:40:00Z').epoch_ns))[0]
        self.assertEqual(result['identity_state'],'known');self.assertEqual(result['ip_keys'],[])
    def test_conflicting_structured_and_sql_sessions_do_not_choose_first(self):
        d=document(path='DBPath.app.ud_prc_userSessionHasAccess',message='(Command Text: ud_prc_userSessionHasAccess)(Code: 1)(Result: OK)(SQL Parameters: @session=OTHER_SESSION @action=v1/ConfigBasic)')
        result=reconstruct(select_events(normalized([d]),parse_time('2026-10-20T07:40:00Z').epoch_ns))[0]
        self.assertEqual(result['identity_state'],'conflicting');self.assertIsNone(result['session_key'])
    def test_target_session_parameter_is_not_used_as_actor(self):
        d=document(session='N/A',path='DBPath.app.ud_prc_userSessionTerminate',message='(Command Text: ud_prc_userSessionTerminate)(Code: 1)(Result: OK)(SQL Parameters: @SessionID=TARGET_SESSION)')
        self.assertEqual(normalized([d])[0]['descriptor']['session_candidates'],[])
    def test_sql_parameters_keep_empty_values_and_json_delimiters(self):
        params,state=sql_parameters('(SQL Parameters: @session= @data={"text":" @password=inside","n":[1,2]} @action=v1/ConfigBasic)')
        self.assertEqual(state,'complete');self.assertEqual(set(params),{'session','data','action'});self.assertEqual(params['session'],'')
        self.assertIn('@password=inside',params['data'])
    def test_duplicate_parameter_and_unbalanced_body_mark_parse_error(self):
        self.assertEqual(sql_parameters('(SQL Parameters: @session=A @session=B)')[1],'parse_error')
        self.assertEqual(sql_parameters('(SQL Parameters: @data={"a":1)')[1],'parse_error')
    def test_native_ua_is_context_and_signature_is_not_exposed(self):
        context=client_context('BuildVersion:(12) Model:(M1) Device:(D1) AppVersion:(6.7.0) Sign:(SECRET_SIGNATURE_123)')
        self.assertEqual(context['format'],'structured_native_reported');self.assertTrue(context['signature_present'])
        self.assertNotIn('SECRET_SIGNATURE_123',json.dumps(context));self.assertNotIn('M1',json.dumps(context))
    def test_password_otp_and_arbitrary_payload_do_not_enter_descriptor(self):
        d=document(path='DBPath.app.ud_prc_userCredentialValidate',message='(Command Text: ud_prc_userCredentialValidate)(Code: 1)(Result: OK)(SQL Parameters: @username=PRIVATE_PHONE_123 @password=SECRET_PASS_123 @data={"Token":"SECRET_TOKEN_123"} @otpCode=SECRET_OTP_123)')
        e=normalized([d])[0];public=json.dumps(e['payload'])
        for value in ('PRIVATE_PHONE_123','SECRET_PASS_123','SECRET_TOKEN_123','SECRET_OTP_123'):self.assertNotIn(value,public)
        self.assertEqual(e['descriptor']['secret_fields_present'],['otpcode','password'])
    def test_unknown_code_remains_unknown(self):
        d=document(message='POST https://fixture.invalid/a HTTP/1.1 (G00002 | Undocumented)')
        result=reconstruct(select_events(normalized([d]),parse_time('2026-10-20T07:40:00Z').epoch_ns))[0]
        self.assertEqual((result['outcome_code'],result['final_outcome']),('G00002','unknown'))
    def test_originless_similar_rows_preserve_multiplicity(self):
        d=document();d.pop('_id');events=normalized([d,copy.deepcopy(d)])
        self.assertEqual(len({e['event_key'] for e in events}),2)
        self.assertTrue(all(e['identity_kind']=='fingerprint_ambiguous' for e in events))
    def test_inconsistent_time_representations_remain_unavailable(self):
        d=document();d['fields']={'@timestamp':['2026-10-20T08:00:00Z']}
        events=normalized([d]);selection=select_events(events,parse_time('2026-10-20T09:00:00Z').epoch_ns)
        self.assertEqual(len(selection['unavailable']),1);self.assertEqual(selection['selected'],[])
    def test_multiple_client_completions_are_not_latest_line_wins(self):
        a=document();b=document(oid='other-origin',at='2026-10-20T07:30:01Z',message='POST https://fixture.invalid/a HTTP/1.1 (G00002 | Unknown)')
        result=reconstruct(select_events(normalized([a,b]),parse_time('2026-10-20T07:40:00Z').epoch_ns))[0]
        self.assertEqual(result['client_completion_state'],'conflicting');self.assertEqual(result['final_outcome'],'conflicting')
        self.assertEqual(result['distinct_client_request_count'],1)

class PrivacyAndSafetyTests(unittest.TestCase):
    def test_personal_tokens_are_stable_typed_and_namespace_scoped(self):
        a=TEST_KEYS.token('n','session','A')
        self.assertEqual(a,TEST_KEYS.token('n','session','A'))
        self.assertNotEqual(a,TEST_KEYS.token('other','session','A'))
        self.assertNotEqual(a,TEST_KEYS.token('n','ip','A'))
    def test_archive_encryption_replay_and_wrong_context(self):
        with tempfile.TemporaryDirectory() as path:
            vault=Vault(path,TEST_KEYS,'namespace-A');original=b'{"password":"PRIVATE_ORIGINAL_123"}'
            a=vault.put(original);b=vault.put(original)
            self.assertEqual(a,b);self.assertEqual(vault.read(a['digest']),original)
            self.assertNotIn(b'PRIVATE_ORIGINAL_123',(Path(path)/a['storage_key']).read_bytes())
            with self.assertRaises(FoundationError):Vault(path,TEST_KEYS,'namespace-B').read(a['digest'])
    def test_archive_tampering_fails_authentication(self):
        with tempfile.TemporaryDirectory() as path:
            v=Vault(path,TEST_KEYS,'A');a=v.put(b'original');p=Path(path)/a['storage_key'];b=p.read_bytes();p.write_bytes(b[:-1]+bytes([b[-1]^1]))
            with self.assertRaises(FoundationError):v.read(a['digest'])
    def test_production_database_and_nonloopback_are_rejected(self):
        for value in ({'host':'127.0.0.1','dbname':'pishkhan24_shadow','user':'postgres'}, {'host':'remote.example','dbname':'p24_design_test','user':'postgres'}):
            with self.assertRaises(FoundationError):validate_database_config(value)
    def test_imports_do_not_connect_or_read_config(self):
        with patch('psycopg.connect',side_effect=AssertionError('Unexpected connection')):
            for name in ('p24_foundation','p24_foundation.parser','p24_foundation.store','p24_foundation.cli'):
                importlib.reload(importlib.import_module(name))
    def test_cli_errors_do_not_echo_malformed_payload(self):
        result=subprocess.run([sys.executable,'-m','p24_foundation','init'],cwd=ROOT,capture_output=True,text=True)
        self.assertEqual(result.returncode,2)
        self.assertEqual(json.loads(result.stderr)['error'],'local_configuration_required')

