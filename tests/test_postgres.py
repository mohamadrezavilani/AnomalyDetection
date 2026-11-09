import copy,json,random,tempfile,unittest,uuid,subprocess,sys,threading,time
from datetime import datetime,timedelta,timezone
from pathlib import Path
from unittest.mock import patch

import psycopg
from p24_foundation.errors import FoundationError
from p24_foundation.parser import normalize_event
from p24_foundation.privacy import Keys
from p24_foundation.store import FoundationStore,initialize
from p24_foundation.worker import ProjectionWorker
from tests.helpers import ROOT,TEST_KEYS,MANIFEST,fixture,document,batch,issue_test_access_token,test_access_policy,TEST_ACCESS_PRIVATE_KEY

class PostgreSQLAcceptance(unittest.TestCase):
    connection=None
    @classmethod
    def setUpClass(cls):
        if cls.connection is None:
            raise unittest.SkipTest('Use tools/run_tests.py --config with an isolated PostgreSQL database')
        initialize(cls.connection)
    def setUp(self):
        self.c=self.connection;self.tmp=tempfile.TemporaryDirectory()
        self.namespace='fixture_'+uuid.uuid4().hex
        self.access_token=issue_test_access_token(self.namespace)
        self.store=FoundationStore(self.c,TEST_KEYS,self.namespace,Path(self.tmp.name)/'vault',access_policy=test_access_policy(self.namespace))
    def tearDown(self):self.tmp.cleanup()
    def ingest(self,name='ip_activity.sanitized.json',source='source-A',at='2026-10-20T07:40:00Z',rows=None):
        return self.store.ingest(fixture(name) if rows is None else batch(rows),source_key=source,
                                 interval_start='2026-10-20T07:25:00Z',interval_end='2026-10-20T07:45:00Z',
                                 observed_at=at,receive_time_basis='synthetic_fixture')
    def project(self,ids,cutoff='2026-10-20T07:40:00Z',known='2026-10-20T07:45:00Z',mode='design_fixture'):
        return self.store.project([x['snapshot_id'] for x in ids],event_cutoff=cutoff,knowledge_at=known,mode=mode)
    def count(self,table):
        allowed={'source_snapshot','raw_object','event_identity','event_version','request_source','foundation_row_membership','foundation_event_descriptor','logical_request','projection_run','source_head','foundation_access_audit','foundation_access_decision','foundation_evidence_hold','foundation_work_item','foundation_work_attempt','foundation_source_replacement','foundation_projection_source_choice'}
        self.assertIn(table,allowed)
        return self.c.execute('SELECT count(*) FROM p24_next.'+table+' WHERE namespace_id=%s',(self.store.namespace_id,)).fetchone()[0]
    def test_real_overlapping_exports_preserve_36_origins_and_11_requests(self):
        a=self.ingest();b=self.ingest('session_activity.sanitized.json','source-B')
        run=self.project([a,b])
        self.assertEqual((run['distinct_client_requests'],run['selected_request_events'],run['known_sessions']),(11,36,1))
        self.assertEqual((self.count('foundation_row_membership'),self.count('event_version'),self.count('event_identity')),(69,36,36))
        self.assertFalse(run['authoritative_source_heads_published']);self.assertEqual(self.count('source_head'),0)
    def test_real_session_activity_and_UA_change_remain_one_session(self):
        run=self.project([self.ingest('session_activity.sanitized.json')])
        page=self.store.session_activity(run['run_id'],MANIFEST['anchors']['session_token'],access_token=self.access_token)
        self.assertEqual((page['total_requests'],len(page['items'])),(10,10))
        self.assertEqual(sum(s['final_outcome']=='failure' for s in page['items']),4)
        self.assertEqual(len({u for s in page['items'] for u in s['client_contexts']}),2)
        self.assertEqual(sum(s['classification']['phase']=='otp_generation' for s in page['items']),1)
    def test_boundary_early_run_stays_unknown_and_later_run_fails(self):
        source=self.ingest('boundary.sanitized.json')
        early=self.project([source],cutoff='2026-10-20T07:30:00Z')
        later=self.project([source],cutoff='2026-10-20T07:35:00Z')
        request=MANIFEST['anchors']['boundary_request_id']
        a=self.store.get_request(early['run_id'],request,access_token=self.access_token);b=self.store.get_request(later['run_id'],request,access_token=self.access_token)
        self.assertEqual((a['selected_event_count'],a['final_outcome'],a['client_completion_state']),(11,'unknown','not_observed'))
        self.assertEqual((b['selected_event_count'],b['sql_observation_count'],b['provider_observation_count'],b['final_outcome']),(14,12,1,'failure'))
        self.assertEqual(self.store.get_request(early['run_id'],request,access_token=self.access_token),a)
    def test_log_body_SQL_and_client_outcomes_keep_their_scopes(self):
        run=self.project([self.ingest('boundary.sanitized.json')])
        summary=self.store.get_request(run['run_id'],MANIFEST['anchors']['boundary_request_id'],access_token=self.access_token)
        observations=[r['observation'] for r in summary['outcomes']]
        self.assertTrue(any(o['code']=='G00000' and o['role']=='provider' for o in observations))
        self.assertTrue(any(o['code']=='GD2016' and o['layer']=='provider_body' for o in observations))
        self.assertTrue(any(o['layer']=='sql_result' and o['outcome']=='success' for o in observations))
        self.assertEqual((summary['outcome_code'],summary['final_outcome']),('GD2016','failure'))
    def test_registration_candidate_does_not_change_verified_session_ownership(self):
        a=self.ingest();b=self.ingest('registration.sanitized.json','registrations')
        run=self.project([a,b]);items=self.store.candidates(run['run_id'],access_token=self.access_token)['items']
        self.assertEqual(len(items),1);self.assertEqual(items[0]['basis']['state'],'inferred_candidate')
        self.assertFalse(items[0]['basis']['verified_session_issuance'])
        self.assertTrue(items[0]['basis']['same_parsed_client_context'])
        reg=self.store.get_request(run['run_id'],MANIFEST['anchors']['registration_v2_request_id'],access_token=self.access_token)
        self.assertIsNone(reg['session_key']);self.assertEqual(reg['identity_state'],'missing')
        self.assertEqual(self.store.session_activity(run['run_id'],MANIFEST['anchors']['session_token'],access_token=self.access_token)['total_requests'],10)
    def test_registration_candidates_use_signed_stable_pages(self):
        registrations=fixture('registration.sanitized.json').records
        template=next(row for row in registrations if row['_source']['CallPath'].startswith('Core.v1/DeviceRegister'))
        original_id=template['_source']['RequestID']
        cloned=[]
        for index,row in enumerate(registrations):
            if row['_source']['RequestID']!=original_id:continue
            item=copy.deepcopy(row)
            request_id=str(uuid.uuid5(uuid.NAMESPACE_URL,'registration-page-'+str(index)))
            item['_id']='candidate-page-'+str(index)
            for container in ('_source','fields'):
                if container not in item:continue
                values=item[container]
                values['RequestID']=request_id if container=='_source' else [request_id]
                values['IP']='198.51.100.11' if container=='_source' else ['198.51.100.11']
                if 'message' in values:
                    if container=='_source':values['message']=values['message'].replace('203.0.113.30','198.51.100.11')
                    else:values['message']=[text.replace('203.0.113.30','198.51.100.11') for text in values['message']]
            cloned.append(item)
        registration_source=self.ingest('registration.sanitized.json','registrations-paged',rows=list(registrations)+cloned)
        activity_source=self.ingest()
        run=self.project([registration_source,activity_source])
        first=self.store.candidates(run['run_id'],limit=1,access_token=self.access_token)
        self.assertEqual(first['total_candidates'],2)
        self.assertEqual(len(first['items']),1)
        self.assertIsNotNone(first['next_cursor'])
        second=self.store.candidates(run['run_id'],limit=1,cursor=first['next_cursor'],access_token=self.access_token)
        self.assertEqual(len(second['items']),1)
        self.assertIsNone(second['next_cursor'])
        self.assertNotEqual(first['items'][0]['registration_request_key'],second['items'][0]['registration_request_key'])
        with self.assertRaises(FoundationError):
            self.store.candidates(run['run_id'],limit=1,cursor=first['next_cursor']+'x',access_token=self.access_token)
    def test_high_precision_representation_enriches_same_origin_without_duplicates(self):
        a=self.ingest();b=self.ingest('registration.sanitized.json','registrations')
        run=self.project([a,b])
        self.assertEqual(run['selection_states']['selected'],39)
        self.assertEqual(run['distinct_client_requests'],12)
        self.assertNotIn('ambiguous',run['selection_states'])
        self.assertEqual(self.count('event_identity'),39)
        self.assertEqual(self.count('event_version'),42)
        row=self.c.execute("SELECT source_time_epoch_ns,source_time_fraction_digits,source_event_time FROM p24_next.event_version WHERE namespace_id=%s AND source_time_fraction_digits=7 ORDER BY source_event_time DESC LIMIT 1",(self.store.namespace_id,)).fetchone()
        self.assertEqual(int(row[0])%1000,700);self.assertEqual(row[1],7)
    def test_repeated_intake_is_idempotent_and_preserves_coverage(self):
        a=self.ingest();before=[self.count(t) for t in ('source_snapshot','event_version','foundation_row_membership')]
        b=self.ingest(at='2026-10-20T08:00:00Z')
        self.assertTrue(b['reused']);self.assertEqual(a['snapshot_id'],b['snapshot_id'])
        self.assertEqual(before,[self.count(t) for t in ('source_snapshot','event_version','foundation_row_membership')])
    def test_repeated_and_reordered_projection_vectors_reuse_sealed_run(self):
        a=self.ingest();b=self.ingest('session_activity.sanitized.json','B')
        first=self.project([a,b]);second=self.project([b,a,a])
        self.assertEqual(first,second);self.assertEqual(self.count('projection_run'),1)
    def test_duplicates_inside_source_preserve_row_membership(self):
        d=document();source=self.ingest(rows=[d,copy.deepcopy(d)])
        run=self.project([source])
        self.assertEqual((self.count('foundation_row_membership'),self.count('event_version')),(2,1))
        self.assertEqual((run['distinct_client_requests'],run['selected_request_events']),(1,1))
    def test_unknown_origin_fingerprints_do_not_collapse_distinct_rows(self):
        a=document();a.pop('_id');source=self.ingest(rows=[a,copy.deepcopy(a)])
        run=self.project([source]);summary=self.store.get_request(run['run_id'],'request-A',access_token=self.access_token)
        self.assertEqual(summary['origin_identity_ambiguous_count'],2)
        self.assertEqual(summary['client_completion_state'],'conflicting')
    def test_conflicting_origin_versions_are_not_last_arrival_wins(self):
        a=document();b=copy.deepcopy(a);b['_source']['message']='POST https://fixture.invalid/a HTTP/1.1 (G00002 | Unknown)'
        first=self.ingest(rows=[a]);second=self.ingest(source='B',rows=[b])
        run=self.project([first,second]);summary=self.store.get_request(run['run_id'],'request-A',access_token=self.access_token)
        self.assertEqual(run['selection_states'].get('ambiguous'),1)
        self.assertEqual(summary['final_outcome'],'unknown');self.assertEqual(summary['ambiguous_event_count'],1)
        self.assertEqual(summary['distinct_client_request_count'],0)
    def test_explicit_new_empty_source_does_not_erase_other_support(self):
        d=document();a=self.ingest(rows=[d]);b=self.ingest(source='B',rows=[d]);empty=self.ingest(source='B',rows=[])
        run=self.project([a,empty]);self.assertEqual(run['distinct_client_requests'],1)
        self.assertEqual(self.count('source_snapshot'),3)
        self.assertEqual(self.count('event_version'),1)
        objects=self.c.execute('SELECT storage_key FROM p24_next.raw_object WHERE namespace_id=%s',(self.store.namespace_id,)).fetchall()
        self.assertEqual(len(set(objects)),3)
        self.assertEqual(self.project([empty])['distinct_client_requests'],0)
    def test_synthetic_late_arrival_and_knowledge_bounds(self):
        docs=list(fixture('boundary.sanitized.json').records)
        first=[h for h in docs if h['fields']['@timestamp'][0]<'2026-10-20T07:30:00Z']
        later=[h for h in docs if h not in first]
        a=self.ingest(source='early',rows=first,at='2026-10-20T07:30:01Z')
        b=self.ingest(source='late',rows=later,at='2026-10-20T07:40:00Z')
        old=self.project([a],cutoff='2026-10-20T07:35:00Z',known='2026-10-20T07:32:00Z',mode='online_original')
        with self.assertRaises(FoundationError):self.project([a,b],cutoff='2026-10-20T07:35:00Z',known='2026-10-20T07:32:00Z',mode='online_original')
        with self.assertRaises(FoundationError):self.project([a,b],cutoff='2026-10-20T07:35:00Z',known='2026-10-20T07:32:00Z',mode='historical_revised')
        revised=self.project([a,b],cutoff='2026-10-20T07:35:00Z',known='2026-10-20T07:45:00Z',mode='historical_revised')
        request=MANIFEST['anchors']['boundary_request_id']
        self.assertEqual(self.store.get_request(old['run_id'],request,access_token=self.access_token)['final_outcome'],'unknown')
        self.assertEqual(self.store.get_request(revised['run_id'],request,access_token=self.access_token)['final_outcome'],'failure')
    def test_incomplete_search_export_never_publishes_authoritative_head(self):
        source=self.ingest();self.project([source])
        flags=self.c.execute('SELECT source_complete,ordering_status FROM p24_next.source_snapshot WHERE namespace_id=%s',(self.store.namespace_id,)).fetchall()
        self.assertEqual(flags,[(False,'unverified')]);self.assertEqual(self.count('source_head'),0)
    def test_namespace_and_key_mismatch_are_rejected(self):
        source=self.ingest()
        other_namespace='other_'+uuid.uuid4().hex
        other=FoundationStore(self.c,TEST_KEYS,other_namespace,Path(self.tmp.name)/'other',access_policy=test_access_policy(other_namespace))
        with self.assertRaises(FoundationError):other.project([source['snapshot_id']],event_cutoff='2026-10-20T07:40:00Z',knowledge_at='2026-10-20T07:45:00Z')
        bad=Keys(b'\x44'*32,b'\x22'*32,'test_v1')
        with self.assertRaises(FoundationError):FoundationStore(self.c,bad,self.namespace,Path(self.tmp.name)/'bad')
    def test_session_keeps_missing_or_changed_IP(self):
        a=document(rid='A',oid='A',ip='N/A');b=document(rid='B',oid='B',ip='203.0.113.6')
        run=self.project([self.ingest(rows=[a,b])])
        page=self.store.session_activity(run['run_id'],'SESSION_A',access_token=self.access_token)
        self.assertEqual(page['total_requests'],2);self.assertEqual(run['known_sessions'],1)
    def test_601_requests_reachable_with_stable_signed_pagination(self):
        base=datetime(2026,10,20,7,26,tzinfo=timezone.utc)
        rows=[document(rid='R'+str(i),oid='O'+str(i),at=(base+timedelta(seconds=i)).isoformat(),session='LARGE_SESSION',ip='198.51.100.'+str(10+i%2)) for i in range(601)]
        run=self.project([self.ingest(rows=rows)])
        seen=[];cursor=None
        while True:
            page=self.store.session_activity(run['run_id'],'LARGE_SESSION',limit=100,cursor=cursor,access_token=self.access_token)
            self.assertEqual(page['total_requests'],601)
            seen.extend(s['request_key'] for s in page['items']);cursor=page['next_cursor']
            if cursor is None:break
        self.assertEqual(len(seen),601);self.assertEqual(len(set(seen)),601)
    def test_cursor_tampering_or_scope_change_is_rejected(self):
        run=self.project([self.ingest('session_activity.sanitized.json')])
        token=MANIFEST['anchors']['session_token'];page=self.store.session_activity(run['run_id'],token,limit=2,access_token=self.access_token)
        cursor=page['next_cursor'];self.assertIsNotNone(cursor)
        with self.assertRaises(FoundationError):self.store.session_activity(run['run_id'],token,cursor=cursor+'x',access_token=self.access_token)
        with self.assertRaises(FoundationError):self.store.session_activity(run['run_id'],'OTHER_SESSION',cursor=cursor,access_token=self.access_token)
    def test_sealed_run_and_source_rows_are_immutable_in_database(self):
        source=self.ingest();run=self.project([source])
        for sql,args in [
            ("UPDATE p24_next.projection_run SET state='draft' WHERE namespace_id=%s AND run_id=%s",(self.store.namespace_id,uuid.UUID(run['run_id']))),
            ("DELETE FROM p24_next.foundation_request_summary WHERE namespace_id=%s AND run_id=%s",(self.store.namespace_id,uuid.UUID(run['run_id']))),
            ("DELETE FROM p24_next.foundation_row_membership WHERE namespace_id=%s",(self.store.namespace_id,))]:
            with self.assertRaises(psycopg.Error):
                with self.c.transaction():self.c.execute(sql,args)
    def test_failed_ingest_rolls_back_database_rows(self):
        import p24_foundation.store as module
        original=module.execute_many;calls=0
        def fail_later(c,sql,rows,**kwargs):
            nonlocal calls
            calls+=1
            if calls==4:raise FoundationError('synthetic_transaction_failure')
            return original(c,sql,rows,**kwargs)
        with patch('p24_foundation.store.execute_many',side_effect=fail_later):
            with self.assertRaises(FoundationError):self.ingest(rows=[document()])
        self.assertEqual(self.count('source_snapshot'),0);self.assertEqual(self.count('event_version'),0)
        run=self.project([self.ingest(rows=[document()])]);self.assertEqual(run['distinct_client_requests'],1)
    def test_mutated_decoded_records_cannot_diverge_from_archived_bytes(self):
        original=batch([document()]);original.records[0]['_source']['RequestID']='MUTATED'
        source=self.store.ingest(original,source_key='source',interval_start='2026-10-20T07:25:00Z',interval_end='2026-10-20T07:45:00Z')
        run=self.project([source]);self.assertEqual(self.store.get_request(run['run_id'],'request-A',access_token=self.access_token)['distinct_client_request_count'],1)
        with self.assertRaises(FoundationError):self.store.get_request(run['run_id'],'MUTATED',access_token=self.access_token)
    def test_password_values_and_individual_hashes_not_in_public_storage(self):
        secret='SYNTHETIC_CREDENTIAL_7829'
        d=document(path='DBPath.app.ud_prc_userCredentialValidate',message='(Command Text: ud_prc_userCredentialValidate)(Code: 1)(Result: OK)(SQL Parameters: @password='+secret+')')
        run=self.project([self.ingest(rows=[d])])
        exposed=json.dumps(self.store.get_request(run['run_id'],'request-A',access_token=self.access_token))
        rows=self.c.execute('SELECT descriptor FROM p24_next.foundation_event_descriptor WHERE namespace_id=%s',(self.store.namespace_id,)).fetchall()
        self.assertNotIn(secret,exposed+json.dumps(rows))
        for path in (Path(self.tmp.name)/'vault').iterdir():self.assertNotIn(secret.encode(),path.read_bytes())
    def test_unknown_time_remains_retained_unavailable_evidence(self):
        d=document(at='2026-10-20T11:00:00')
        source=self.ingest(rows=[d]);run=self.project([source])
        self.assertEqual(self.count('event_version'),1)
        self.assertEqual(run['selection_states'].get('unavailable'),1)
        self.assertEqual(run['distinct_client_requests'],0)


    def test_session_facts_keep_exact_metadata_and_SQL_paths(self):
        d=document(path='DBPath.app.ud_prc_userSessionHasAccess',message='(Command Text: ud_prc_userSessionHasAccess)(Code: 1)(Result: OK)(SQL Parameters: @session=SESSION_A @action=v1/ConfigBasic)')
        self.ingest(rows=[d])
        rows=self.c.execute("SELECT field_path,direction FROM p24_next.extracted_fact WHERE namespace_id=%s AND fact_key='session_candidate'",(self.store.namespace_id,)).fetchall()
        self.assertEqual(set(rows),{('_source.Session','metadata'),('message.SQL.Parameters.session','sql_parameter')})
    def test_CLI_full_workflow_with_real_fixture_and_private_session_file(self):
        private=Path(self.tmp.name)
        keyfile=private/'keys.json';config=private/'config.py'
        namespace='cli_'+uuid.uuid4().hex
        from cryptography.hazmat.primitives import serialization
        access_public=private/'access-public.pem'
        access_public.write_bytes(TEST_ACCESS_PRIVATE_KEY.public_key().public_bytes(serialization.Encoding.PEM,serialization.PublicFormat.SubjectPublicKeyInfo))
        access_file=private/'access.private';access_file.write_text(issue_test_access_token(namespace),encoding='utf-8');access_file.chmod(0o600)
        config.write_text('DATABASE='+repr(self.database_config)+'\nNAMESPACE='+repr(namespace)+'\nKEYS_PATH="keys.json"\nVAULT_PATH="vault_cli"\nACCESS_PUBLIC_KEY_PATH='+repr(str(access_public))+'\n',encoding='utf-8')
        def call(*args,ok=True):
            read_commands={'run','observation','request','evidence','candidates','session','observed-session','observed-request','observed-evidence','observed-requests','observed-candidates'}
            if args and args[0] in read_commands:args=(args[0],'--access-token-file',str(access_file),*args[1:])
            result=subprocess.run([sys.executable,'-m','p24_foundation','--config',str(config),*args],cwd=ROOT,capture_output=True,text=True,encoding='utf-8')
            self.assertEqual(result.returncode,0 if ok else 2,result.stderr)
            return json.loads(result.stdout if ok else result.stderr)
        self.assertFalse(call('generate-keys','--path',str(keyfile))['values_printed'])
        call('init')
        source=call('ingest','--input',str(ROOT/'fixtures/session_activity.sanitized.json'),'--source','cli-session','--start','2026-10-20T07:25:00Z','--end','2026-10-20T07:45:00Z')
        run=call('project','--sources',source['snapshot_id'],'--cutoff','2026-10-20T07:40:00Z','--knowledge-at','2026-10-20T07:45:00Z','--mode','design_fixture')
        self.assertEqual(run['distinct_client_requests'],10)
        self.assertEqual(call('run','--run',run['run_id'])['distinct_client_requests'],10)
        session_file=private/'session.txt';session_file.write_text(MANIFEST['anchors']['session_token'],encoding='utf-8')
        page=call('session','--run',run['run_id'],'--session-file',str(session_file),'--limit','2')
        self.assertEqual(page['total_requests'],10);self.assertIsNotNone(page['next_cursor'])
        page2=call('session','--run',run['run_id'],'--session-file',str(session_file),'--limit','2','--cursor',page['next_cursor'])
        self.assertNotEqual(page['items'][0]['request_key'],page2['items'][0]['request_key'])
        self.assertEqual(call('candidates','--run',run['run_id'])['items'],[])
        knowledge_at=datetime.now(timezone.utc).isoformat()
        queued=call('enqueue-projection','--sources',source['snapshot_id'],'--cutoff',knowledge_at,
                    '--knowledge-at',knowledge_at,'--mode','online_original','--dedupe-key','cli-work')
        self.assertEqual(call('work-once','--worker','cli-worker','--lease-seconds','10')['status'],'completed')
        self.assertEqual(self.c.execute('SELECT state FROM p24_next.foundation_work_item WHERE work_id=%s',
                         (uuid.UUID(queued['work_id']),)).fetchone(),('completed',))
        replay=subprocess.run([sys.executable,str(ROOT/'tools/replay_examples.py'),'--config',str(config)],cwd=ROOT,capture_output=True,text=True,encoding='utf-8')
        self.assertEqual(replay.returncode,0,replay.stderr);self.assertTrue(json.loads(replay.stdout)['ok'])
        self.assertEqual(call('request','--run',run['run_id'],'--request-id','ABSENT',ok=False)['error'],'request_not_available')
        config.write_text('DATABASE='+repr({**self.database_config,'dbname':'pishkhan24_shadow'})+'\nNAMESPACE="unsafe"\nKEYS_PATH="keys.json"\nVAULT_PATH="vault"\n',encoding='utf-8')
        self.assertEqual(call('init',ok=False)['error'],'database_requires_disposable_name')

    def test_failed_projection_rolls_back_partial_publication(self):
        source=self.ingest()
        import p24_foundation.store as module
        original=module.execute_many
        def fail_on_operations(connection,statement,rows,**kwargs):
            if 'INSERT INTO p24_next.operation_projection' in statement:raise FoundationError('injected_projection_failure')
            return original(connection,statement,rows,**kwargs)
        with patch.object(module,'execute_many',side_effect=fail_on_operations):
            with self.assertRaises(FoundationError):self.project([source])
        self.assertEqual(self.count('projection_run'),0)
        self.assertEqual(self.count('source_snapshot'),1)
        self.assertEqual(self.project([source])['distinct_client_requests'],11)
    def test_initialization_is_idempotent_and_rejects_checksum_drift(self):
        self.assertEqual(initialize(self.c)['status'],'initialized')
        with self.c.transaction():
            self.c.execute("UPDATE p24_next.design_version SET content_sha256=%s WHERE version_key='p24-foundation.2a.1'",('f'*64,))
            with self.assertRaises(FoundationError) as caught:initialize(self.c)
            self.assertEqual(caught.exception.code,'migration_checksum_mismatch')
            raise psycopg.Rollback()

    def test_explicit_source_replacement_replays_only_in_new_vector(self):
        docs=list(fixture('boundary.sanitized.json').records)
        corrected=[d for d in docs if not d.get('fields',{}).get('CallPath',[''])[0].startswith('Services.v3/ElectricBillsExport')]
        old=self.ingest(source='correctable',rows=docs);before=self.project([old])
        rid=MANIFEST['anchors']['boundary_request_id']
        self.assertEqual(self.store.get_request(before['run_id'],rid,access_token=self.access_token)['final_outcome'],'failure')
        new=self.ingest(source='correctable',rows=corrected)
        with self.assertRaises(FoundationError):self.store.replace_source_snapshot(old['snapshot_id'],new['snapshot_id'],expected_prior_revision=2,reason_key='corrected_export',declared_by='reviewer')
        revision=self.store.replace_source_snapshot(old['snapshot_id'],new['snapshot_id'],expected_prior_revision=1,reason_key='corrected_export',declared_by='reviewer')
        self.assertTrue(revision['prior_runs_unchanged']);self.assertEqual(revision['assertion'],'operator_declared_not_producer_verified')
        later=self.project([old,new])
        summary=self.store.get_request(later['run_id'],rid,access_token=self.access_token)
        self.assertEqual((summary['selected_event_count'],summary['final_outcome']),(13,'unknown'))
        self.assertEqual(self.store.get_request(before['run_id'],rid,access_token=self.access_token)['final_outcome'],'failure')
        choices={x['snapshot_id']:x['choice'] for x in later['source_selection']}
        self.assertEqual(choices[old['snapshot_id']],'replaced_by_selected_descendant')
        self.assertEqual(choices[new['snapshot_id']],'included')
        self.assertEqual(self.count('foundation_source_replacement'),1)
        self.assertEqual(self.count('source_head'),0)
    def test_replacing_one_source_preserves_another_sources_support(self):
        d=document();old=self.ingest(source='same-export',rows=[d]);support=self.ingest(source='independent-export',rows=[d]);empty=self.ingest(source='same-export',rows=[])
        self.store.replace_source_snapshot(old['snapshot_id'],empty['snapshot_id'],expected_prior_revision=1,reason_key='corrected_export',declared_by='reviewer')
        with_support=self.project([old,support,empty]);without=self.project([old,empty])
        self.assertEqual(with_support['distinct_client_requests'],1);self.assertEqual(without['distinct_client_requests'],0)
        self.assertEqual(with_support['selected_request_events'],1)
        self.assertEqual(self.count('source_head'),0)
    def test_source_replacement_chain_selects_latest_declared_descendant(self):
        a=self.ingest(source='chain',rows=[document()]);b=self.ingest(source='chain',rows=[]);c=self.ingest(source='chain',rows=[document(oid='origin-later')])
        self.store.replace_source_snapshot(a['snapshot_id'],b['snapshot_id'],expected_prior_revision=1,reason_key='corrected_export',declared_by='reviewer')
        self.store.replace_source_snapshot(b['snapshot_id'],c['snapshot_id'],expected_prior_revision=2,reason_key='producer_reissued',declared_by='reviewer')
        run=self.project([a,b,c]);self.assertEqual(run['distinct_client_requests'],1)
        choices={x['snapshot_id']:x['choice'] for x in run['source_selection']}
        self.assertEqual([k for k,v in choices.items() if v=='included'],[c['snapshot_id']])
    def test_request_evidence_is_source_linked_paginated_and_audited(self):
        source=self.ingest('boundary.sanitized.json');run=self.project([source]);rid=MANIFEST['anchors']['boundary_request_id']
        page=self.store.request_evidence(run['run_id'],rid,limit=5,access_token=self.access_token)
        self.assertEqual((page['total_event_versions'],len(page['items'])),(14,5));self.assertIsNotNone(page['next_cursor'])
        self.assertTrue(page['items'][0]['provenance']);self.assertEqual(page['items'][0]['provenance'][0]['snapshot_id'],source['snapshot_id'])
        all_items=list(page['items']);cursor=page['next_cursor']
        while cursor:
            nxt=self.store.request_evidence(run['run_id'],rid,limit=5,cursor=cursor,access_token=self.access_token)
            all_items.extend(nxt['items']);cursor=nxt['next_cursor']
        self.assertEqual(len(all_items),14);self.assertEqual(len({x['event_version_id'] for x in all_items}),14)
        with self.assertRaises(FoundationError):self.store.request_evidence(run['run_id'],'different-request',cursor=page['next_cursor'],access_token=self.access_token)
        self.assertEqual(self.count('foundation_access_audit'),3)
        audit=self.c.execute('SELECT principal_claim,object_token FROM p24_next.foundation_access_audit WHERE namespace_id=%s ORDER BY accessed_at',(self.store.namespace_id,)).fetchall()
        expected=self.store.keys.token(self.namespace,'principal','operator-test')
        self.assertTrue(all(principal==expected for principal,_ in audit))
        self.assertTrue(all(rid not in token for _,token in audit))
    def test_access_audit_cannot_be_edited_or_deleted(self):
        run=self.project([self.ingest(rows=[document()])]);self.store.get_request(run['run_id'],'request-A',access_token=self.access_token)
        audit_id=self.c.execute('SELECT audit_id FROM p24_next.foundation_access_audit WHERE namespace_id=%s',(self.store.namespace_id,)).fetchone()[0]
        for statement in ("UPDATE p24_next.foundation_access_audit SET purpose_key='test' WHERE namespace_id=%s AND audit_id=%s",'DELETE FROM p24_next.foundation_access_audit WHERE namespace_id=%s AND audit_id=%s'):
            with self.assertRaises(psycopg.errors.RaiseException):self.c.execute(statement,(self.store.namespace_id,audit_id))

    def test_access_denials_are_audited_without_disclosing_request_existence(self):
        run=self.project([self.ingest(rows=[document()])])
        with self.assertRaises(FoundationError) as denied:self.store.get_request(run['run_id'],'request-A')
        self.assertEqual(denied.exception.code,'access_denied')
        officer=issue_test_access_token(self.namespace,('preservation_officer',))
        with self.assertRaises(FoundationError):self.store.get_request(run['run_id'],'does-not-exist',access_token=officer)
        rows=self.c.execute("SELECT action_key,authentication_state,decision,reason_key FROM p24_next.foundation_access_decision WHERE namespace_id=%s ORDER BY occurred_at",(self.store.namespace_id,)).fetchall()
        self.assertEqual(rows,[('read_request','missing','denied','missing_credential'),('read_request','role_insufficient','denied','insufficient_role')])
        self.assertNotIn('request-A',json.dumps(rows));self.assertNotIn('does-not-exist',json.dumps(rows))

    def test_signed_access_requires_verified_role_and_uses_opaque_audit_subject(self):
        run=self.project([self.ingest(rows=[document()])])
        officer=issue_test_access_token(self.namespace,('preservation_officer',))
        with self.assertRaises(FoundationError):self.store.get_request(run['run_id'],'request-A',access_token=officer)
        summary=self.store.get_request(run['run_id'],'request-A',access_token=self.access_token)
        self.assertEqual(summary['distinct_client_request_count'],1)
        row=self.c.execute("SELECT principal_key,credential_fingerprint,decision,reason_key FROM p24_next.foundation_access_decision WHERE namespace_id=%s ORDER BY occurred_at DESC LIMIT 1",(self.store.namespace_id,)).fetchone()
        self.assertEqual(row[0],self.store.keys.token(self.namespace,'principal','operator-test'))
        self.assertEqual((row[2],row[3]),('allowed','authorized'))
        self.assertNotIn('operator-test',str(row));self.assertNotIn(self.access_token,str(row))

    def test_run_metadata_requires_signed_access_and_logs_opaque_audit(self):
        run=self.project([self.ingest(rows=[document()])])
        with self.assertRaises(FoundationError) as denied:
            self.store.run_info(run['run_id'])
        self.assertEqual(denied.exception.code,'access_denied')
        result=self.store.run_info(run['run_id'],access_token=self.access_token)
        self.assertEqual(result['distinct_client_requests'],1)
        row=self.c.execute("SELECT object_kind,object_token,authentication_state,principal_claim FROM p24_next.foundation_access_audit WHERE namespace_id=%s ORDER BY accessed_at DESC LIMIT 1",(self.store.namespace_id,)).fetchone()
        self.assertEqual((row[0],row[2]),('projection_run','verified_signed_credential'))
        self.assertNotIn(run['run_id'],row[1]);self.assertNotIn('operator-test',row[3])

    def test_evidence_hold_is_append_only_and_blocks_retention_execution(self):
        source=self.ingest(rows=[document(message='(Command Text: ud_prc_login)(Code: 1)(Result: Ok)(SQL Parameters: @password=SECRET_HOLD_TEST @otpCode=OTP_HOLD_TEST @receiverIdentifier=PHONE_HOLD_TEST)')])
        officer=issue_test_access_token(self.namespace,('preservation_officer',))
        with self.assertRaises(FoundationError):self.store.place_evidence_hold(source['snapshot_id'],reason='incident_review',access_token=self.access_token)
        placed=self.store.place_evidence_hold(source['snapshot_id'],reason='security_investigation',reference='case-sensitive-reference',access_token=officer)
        self.assertEqual(placed['state'],'active_indefinitely');self.assertFalse(placed['evidence_deleted'])
        hold=self.c.execute("SELECT snapshot_id,reason_key,reference_key,placed_by_key FROM p24_next.foundation_evidence_hold WHERE namespace_id=%s",(self.store.namespace_id,)).fetchone()
        self.assertEqual(str(hold[0]),source['snapshot_id']);self.assertEqual(hold[1],'security_investigation')
        self.assertNotIn('case-sensitive-reference',str(hold));self.assertNotIn('operator-test',str(hold))
        object_id=self.c.execute("SELECT object_id FROM p24_next.raw_object WHERE namespace_id=%s AND snapshot_id=%s",(self.store.namespace_id,uuid.UUID(source['snapshot_id']))).fetchone()[0]
        with self.assertRaises(psycopg.errors.RaiseException):self.c.execute("DELETE FROM p24_next.raw_object WHERE namespace_id=%s AND object_id=%s",(self.store.namespace_id,object_id))
        with self.assertRaises(psycopg.errors.RaiseException):self.c.execute("UPDATE p24_next.foundation_evidence_hold SET reason_key='other' WHERE namespace_id=%s",(self.store.namespace_id,))
        with self.assertRaises(psycopg.errors.RaiseException):self.c.execute("DELETE FROM p24_next.foundation_evidence_hold WHERE namespace_id=%s",(self.store.namespace_id,))
        self.c.execute("INSERT INTO p24_next.retention_policy(namespace_id,policy_version,data_class,proposed_days,approved_at,approved_by,state) VALUES(%s,'test-retention','raw_source',30,clock_timestamp(),'reviewer','approved')",(self.store.namespace_id,))
        args=(self.store.namespace_id,uuid.uuid4(),object_id,'test-retention','raw_source',True,'approved','a'*64,'reviewer')
        with self.assertRaises(psycopg.errors.RaiseException):
            self.c.execute("INSERT INTO p24_next.retention_disposition(namespace_id,disposition_id,object_id,policy_version,data_class,dry_run,state,hold_check_manifest_sha256,actor_key) VALUES(%s,%s,%s,%s,%s,%s,%s,%s,%s)",args)
        args=(self.store.namespace_id,uuid.uuid4(),object_id,'test-retention','raw_source',False,'executed','a'*64,'reviewer')
        with self.assertRaises(psycopg.errors.RaiseException):
            self.c.execute("INSERT INTO p24_next.retention_disposition(namespace_id,disposition_id,object_id,policy_version,data_class,dry_run,state,hold_check_manifest_sha256,actor_key) VALUES(%s,%s,%s,%s,%s,%s,%s,%s,%s)",args)
        run=self.project([source]);safe=self.store.request_evidence(run['run_id'],'request-A',access_token=self.access_token)
        rendered=json.dumps(safe,ensure_ascii=False)
        for sensitive in ('SECRET_HOLD_TEST','OTP_HOLD_TEST','PHONE_HOLD_TEST','case-sensitive-reference'):
            self.assertNotIn(sensitive,rendered)
    def test_projection_queue_dedup_retry_fencing_and_reclaim(self):
        source=self.ingest();ids=[source['snapshot_id']]
        args=dict(event_cutoff='2026-10-20T07:40:00Z',knowledge_at='2026-10-20T07:45:00Z',mode='online_original')
        queued=self.store.enqueue_projection(ids,dedupe_key='window-1',**args);same=self.store.enqueue_projection(ids,dedupe_key='window-1',**args)
        self.assertEqual(queued['work_id'],same['work_id']);self.assertTrue(same['reused'])
        with self.assertRaises(FoundationError):self.store.enqueue_projection(ids,dedupe_key='window-1',event_cutoff='2026-10-20T07:35:00Z',knowledge_at=args['knowledge_at'],mode=args['mode'])
        other_source=self.ingest(source='source-B')
        other=self.store.enqueue_projection([other_source['snapshot_id']],dedupe_key='window-2',**args)
        claimed=self.store.claim_work('worker-A',limit=2)
        self.assertEqual({x['work_id'] for x in claimed},{queued['work_id'],other['work_id']})
        source_by_work={queued['work_id']:source['snapshot_id'],other['work_id']:other_source['snapshot_id']}
        first=claimed[0];self.assertTrue(self.store.renew_work(first['work_id'],'worker-A',first['lease_generation']))
        self.assertEqual(self.store.fail_work(first['work_id'],'worker-A',first['lease_generation'],error_code='temporary_io',retryable=True,delay_seconds=0),'retry')
        retry=self.store.claim_work('worker-B',limit=1)[0]
        self.assertEqual(retry['work_id'],first['work_id']);self.assertGreater(retry['lease_generation'],first['lease_generation'])
        first_run=self.store.project([source_by_work[first['work_id']]],event_cutoff=args['event_cutoff'],knowledge_at=args['knowledge_at'],mode=args['mode'])
        other_source_id=next(sid for wid,sid in source_by_work.items() if wid!=first['work_id'])
        mismatched_run=self.store.project([other_source_id],event_cutoff=args['event_cutoff'],knowledge_at=args['knowledge_at'],mode=args['mode'])
        with self.assertRaises(FoundationError):self.store.complete_work(retry['work_id'],'worker-B',retry['lease_generation'],mismatched_run['run_id'])
        self.assertFalse(self.store.complete_work(retry['work_id'],'worker-A',first['lease_generation'],first_run['run_id']))
        self.assertTrue(self.store.complete_work(retry['work_id'],'worker-B',retry['lease_generation'],first_run['run_id']))
        next_item=next(x for x in claimed if x['work_id']!=first['work_id'])
        self.c.execute("UPDATE p24_next.foundation_work_item SET lease_until=clock_timestamp()-interval '1 second' WHERE namespace_id=%s AND work_id=%s",(self.store.namespace_id,uuid.UUID(next_item['work_id'])))
        reclaimed=self.store.claim_work('worker-C',limit=1)[0]
        next_run=self.store.project([source_by_work[next_item['work_id']]],event_cutoff=args['event_cutoff'],knowledge_at=args['knowledge_at'],mode=args['mode'])
        self.assertEqual(reclaimed['work_id'],next_item['work_id']);self.assertFalse(self.store.complete_work(reclaimed['work_id'],'worker-A',next_item['lease_generation'],next_run['run_id']))
        self.assertTrue(self.store.complete_work(reclaimed['work_id'],'worker-C',reclaimed['lease_generation'],next_run['run_id']))
        self.assertEqual(self.count('foundation_work_attempt'),8)
        self.assertEqual(self.c.execute("SELECT count(*) FROM p24_next.foundation_work_item WHERE namespace_id=%s AND state='completed'",(self.store.namespace_id,)).fetchone()[0],2)
        results={str(row[0]) for row in self.c.execute("SELECT result_run_id FROM p24_next.foundation_work_item WHERE namespace_id=%s AND state='completed'",(self.store.namespace_id,)).fetchall()}
        self.assertEqual(results,{first_run['run_id'],next_run['run_id']})
    def test_projection_queue_claims_oldest_event_cutoff_first(self):
        source=self.ingest()
        args=dict(source_ids=[source['snapshot_id']],knowledge_at='2026-10-20T07:45:00Z',mode='online_original')
        work={cutoff:self.store.enqueue_projection(event_cutoff=cutoff,dedupe_key='fair-'+str(index),**args)['work_id']
              for index,cutoff in enumerate(('2026-10-20T07:40:00Z','2026-10-20T07:25:00Z','2026-10-20T07:35:00Z'))}
        claim=self.store.claim_work('fair-worker',limit=1)[0]
        self.assertEqual(claim['work_id'],work['2026-10-20T07:25:00Z'])
        column=self.c.execute('SELECT event_cutoff_ns::text FROM p24_next.foundation_work_item WHERE namespace_id=%s AND work_id=%s',(self.store.namespace_id,uuid.UUID(claim['work_id']))).fetchone()[0]
        self.assertEqual(column,str(1792481100000000000))
    def test_integrated_projection_worker_completes_matching_result(self):
        source=self.ingest()
        queued=self.store.enqueue_projection([source['snapshot_id']],event_cutoff='2026-10-20T07:40:00Z',
            knowledge_at='2026-10-20T07:45:00Z',mode='online_original',dedupe_key='worker-end-to-end')
        outcome=ProjectionWorker(self.store,self.database_config,lease_seconds=10).run_once('integrated-worker')
        self.assertEqual((outcome['status'],outcome['claimed'],outcome['completed']),('completed',1,True))
        self.assertEqual(outcome['work_id'],queued['work_id'])
        row=self.c.execute('SELECT state,result_run_id FROM p24_next.foundation_work_item WHERE namespace_id=%s AND work_id=%s',(self.store.namespace_id,uuid.UUID(queued['work_id']))).fetchone()
        self.assertEqual((row[0],str(row[1])),('completed',outcome['run_id']))
        self.assertEqual(self.store.run_info(outcome['run_id'],access_token=self.access_token)['mode'],'online_original')
    def test_integrated_worker_renews_lease_on_an_independent_connection(self):
        source=self.ingest()
        queued=self.store.enqueue_projection([source['snapshot_id']],event_cutoff='2026-10-20T07:40:00Z',
            knowledge_at='2026-10-20T07:45:00Z',mode='online_original',dedupe_key='worker-heartbeat')
        worker=ProjectionWorker(self.store,self.database_config,lease_seconds=10)
        worker.heartbeat_interval_seconds=0.02
        original=self.store.project
        def delayed_projection(*args,**kwargs):
            time.sleep(0.12)
            return original(*args,**kwargs)
        with patch.object(self.store,'project',side_effect=delayed_projection):
            outcome=worker.run_once('heartbeat-worker')
        self.assertEqual(outcome['status'],'completed')
        self.assertGreaterEqual(self.c.execute("SELECT count(*) FROM p24_next.foundation_work_attempt WHERE namespace_id=%s AND work_id=%s AND action='renewed'",(self.store.namespace_id,uuid.UUID(queued['work_id']))).fetchone()[0],1)
    def test_integrated_projection_worker_dead_letters_rejected_projection_safely(self):
        source=self.ingest()
        queued=self.store.enqueue_projection([source['snapshot_id']],event_cutoff='2026-10-20T07:40:00Z',
            knowledge_at='2026-10-20T07:45:00Z',mode='online_original',dedupe_key='worker-invalid-mode')
        with patch.object(self.store,'project',side_effect=FoundationError('invalid_projection')):
            outcome=ProjectionWorker(self.store,self.database_config,lease_seconds=10).run_once('rejecting-worker')
        self.assertEqual((outcome['status'],outcome['error']),('dead','projection_rejected'))
        self.assertEqual(outcome['work_id'],queued['work_id'])
        self.assertEqual(self.c.execute('SELECT state,last_error_code FROM p24_next.foundation_work_item WHERE namespace_id=%s AND work_id=%s',(self.store.namespace_id,uuid.UUID(queued['work_id']))).fetchone(),('dead','projection_rejected'))
    def test_projection_queue_attempt_limit_is_audited_and_dead_lettered(self):
        source=self.ingest();self.store.enqueue_projection([source['snapshot_id']],event_cutoff='2026-10-20T07:40:00Z',knowledge_at='2026-10-20T07:45:00Z',mode='online_original',dedupe_key='exhaustion')
        for generation in range(1,9):
            claim=self.store.claim_work('bounded-worker',lease_seconds=10)[0]
            self.assertEqual(claim['lease_generation'],generation)
            self.c.execute("UPDATE p24_next.foundation_work_item SET lease_until=clock_timestamp()-interval '1 second' WHERE namespace_id=%s AND work_id=%s",(self.store.namespace_id,uuid.UUID(claim['work_id'])))
        self.assertEqual(self.store.claim_work('bounded-worker'),[])
        self.assertEqual(self.c.execute("SELECT state,attempt_count,last_error_code FROM p24_next.foundation_work_item WHERE namespace_id=%s",(self.store.namespace_id,)).fetchone(),('dead',8,'attempt_limit'))
        self.assertEqual(self.c.execute("SELECT action,error_code FROM p24_next.foundation_work_attempt WHERE namespace_id=%s ORDER BY recorded_at DESC LIMIT 1",(self.store.namespace_id,)).fetchone(),('lease_exhausted','attempt_limit'))
    def test_concurrent_work_claims_do_not_duplicate_a_lease(self):
        sources=[self.ingest(source='work-a'),self.ingest(source='work-b')]
        for i,source in enumerate(sources):self.store.enqueue_projection([source['snapshot_id']],event_cutoff='2026-10-20T07:40:00Z',knowledge_at='2026-10-20T07:45:00Z',mode='online_original',dedupe_key='parallel-'+str(i))
        cfg=self.database_config;barrier=threading.Barrier(2);claimed=[];errors=[]
        def run(worker):
            try:
                with psycopg.connect(**cfg,autocommit=True) as c:
                    store=FoundationStore(c,TEST_KEYS,self.namespace,Path(self.tmp.name)/('other_'+worker))
                    barrier.wait(timeout=5);claimed.extend(store.claim_work(worker,limit=1))
            except Exception as exc:errors.append(type(exc).__name__)
        threads=[threading.Thread(target=run,args=('parallel-A',)),threading.Thread(target=run,args=('parallel-B',))]
        for t in threads:t.start()
        for t in threads:t.join(timeout=10)
        self.assertFalse(errors);self.assertTrue(all(not t.is_alive() for t in threads))
        self.assertEqual(len(claimed),2);self.assertEqual(len({x['work_id'] for x in claimed}),2)
