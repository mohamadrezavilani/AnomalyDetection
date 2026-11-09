import json
import tempfile
import unittest
import uuid
from pathlib import Path

from p24_foundation.intake import decode_batch
from p24_foundation.store import FoundationStore,initialize
from p24_foundation.taxonomy import error_catalog_candidates,observed_callpath_candidates,observed_request_action_candidates,postman_candidates,reconcile_action_candidates_with_postman
from p24_foundation.error_reconciliation import observed_code_operation_candidates
from tests.helpers import ROOT,TEST_KEYS,document


class TaxonomyCandidateTests(unittest.TestCase):
    def test_postman_extracts_only_safe_route_metadata_and_real_item_pointers(self):
        secret="SYNTHETIC_SECRET_98432"
        data={"info":{"name":"Core API"},"item":[
            {"name":"LoginByOTP","request":{"method":"POST","url":{"raw":"{{baseUrl}}/core.svc/v1/LoginByOTP?phone=09120000000"},"header":[{"key":"Authorization","value":secret}],"body":{"raw":secret}}},
            {"name":"No URL","request":{"method":"GET"}},
            {"name":"Dynamic","request":{"method":"POST","url":"https://api.example.test/path/09123456789/550e8400-e29b-41d4-a716-446655440000?secret="+secret}}
        ]}
        c=postman_candidates(json.dumps(data).encode(),locator="Core.postman_collection.json")
        self.assertEqual((len(c.mappings),len(c.unresolved)),(3,2))
        self.assertEqual((c.mappings[0]["method"],c.mappings[0]["exact_endpoint"]),("POST","/core.svc/v1/LoginByOTP"))
        self.assertIsNone(c.mappings[1]["exact_endpoint"])
        self.assertEqual(c.mappings[2]["exact_endpoint"],"/path/:redacted/:redacted")
        for value in (secret,"09120000000","09123456789","550e8400-e29b-41d4-a716-446655440000"):
            self.assertNotIn(value,repr(c))
        nested={"item":[{"name":"Folder","item":[{"name":"ConfigBasic","request":{"method":"POST","url":"https://api.example.test/v1/ConfigBasic"}}]}]}
        n=postman_candidates(json.dumps(nested).encode(),locator="nested.json")
        self.assertEqual(n.mappings[0]["item_path"],"/item/0/item/0")
        self.assertEqual(n.mappings[0]["folder_path"],["Folder"])

    def test_duplicate_routes_stay_distinct_unresolved_candidates(self):
        data={"item":[{"name":label,"request":{"method":"POST","url":"https://api.example.test/v1/InvoiceRegister"}} for label in ("First","Second")]}
        c=postman_candidates(json.dumps(data).encode(),locator="Services.json")
        self.assertEqual(len(c.mappings),2)
        self.assertTrue(all(m["classification_state"]=="unresolved" for m in c.mappings))

    def test_code_dictionary_keeps_code_system_and_unbound_scope(self):
        d={"sources":[{"code_system":"Example","file_name":"Example.xlsx","sha256":"a"*64}],
           "records":[{"code_system":"Example","code":"EX0001","source_file":"Example.xlsx","source_sheet":"Sheet1","source_row":2,
                       "source_cells":{"A2":"EX0001"},"definition_state":"code_only","meaning_authority":"no_meaning_supplied"}]}
        row=error_catalog_candidates(d)["records"][0]
        self.assertEqual((row["code_system"],row["operation_binding_state"],row["meaning_authority"]),("Example","not_established_by_workbook","no_definition_supplied"))
        self.assertIsNone(row["user_message_fa"]);self.assertIsNone(row["technical_symbol"])

    def test_supplied_postman_inventory_reports_conflicts_without_semantic_guesses(self):
        manifest=json.loads((ROOT/"catalogs/postman_candidate_manifest.json").read_text())
        inventory=json.loads((ROOT/"catalogs/postman_route_candidates.json").read_text())
        collisions=json.loads((ROOT/"catalogs/postman_route_conflicts.json").read_text())
        self.assertEqual((manifest["request_items"],manifest["items_with_resolved_routes"],manifest["items_missing_or_redacted_route"]),(219,218,1))
        self.assertEqual((manifest["unique_method_route_pairs"],len(collisions["conflicts"])),(212,6))
        self.assertFalse(manifest["semantic_fields_inferred"]);self.assertFalse(manifest["request_bodies_headers_auth_values_or_responses_exported"])
        self.assertEqual(len(inventory["items"]),219)
        self.assertTrue(all(i["mapping_state"]=="candidate" and i["service_key"] is None and i["business_phase"]=="unknown" and i["initiation"]=="unknown" and i["security_class"]=="unknown" for i in inventory["items"]))
        register=next(i for i in inventory["items"] if i["request_name"]=="DeviceRegister")
        self.assertIn("manual_semantic_review_suggested",register["manual_review_hints"])
        self.assertNotIn("security_sensitive",register["manual_review_hints"])

    def test_log_candidates_keep_roles_counts_and_omit_identity_values(self):
        reg_bytes=(ROOT/"fixtures/registration.sanitized.json").read_bytes()
        ping_bytes=(ROOT/"fixtures/taxonomy/provider_ping.sanitized.json").read_bytes()
        reg=observed_callpath_candidates(reg_bytes,locator="registration.sanitized.json",keys=TEST_KEYS,namespace="test")
        ping=observed_callpath_candidates(ping_bytes,locator="provider_ping.sanitized.json",keys=TEST_KEYS,namespace="test")
        http=next(m for m in reg.mappings if m["exact_endpoint"]=="Core.v1/DeviceRegister")
        sql=next(m for m in reg.mappings if m["exact_endpoint"].endswith(".ud_prc_userSessionCreate"))
        provider=next(m for m in ping.mappings if m["exact_endpoint"]=="EwanoApi.Ping")
        self.assertEqual((http["source_role"],http["method"],http["observed_event_count"],http["distinct_request_count"]),("client_http","POST",1,1))
        self.assertEqual((sql["source_role"],sql["observed_event_count"],sql["distinct_request_count"]),("sql",2,2))
        self.assertEqual((provider["source_role"],provider["observed_event_count"],provider["distinct_request_count"]),("provider",1,1))
        public=repr(reg)+repr(ping)
        for data in (reg_bytes,ping_bytes):
            for record in decode_batch(data).records:
                values=record.get("fields") or record.get("_source") or {}
                for field in ("RequestID","IP","Session"):
                    value=values.get(field)
                    if isinstance(value,list):value=value[0] if value else None
                    if isinstance(value,str) and value not in {"","N/A"}:self.assertNotIn(value,public)
        for marker in ("clientId","transactionId"):self.assertNotIn(marker,public)

    def test_observed_inventory_is_aggregate_and_semantically_unresolved(self):
        d=json.loads((ROOT/"catalogs/observed_callpath_candidates.json").read_text())
        groups=[g for source in d["sources"] for g in source["callpath_groups"]]
        self.assertEqual((len(d["sources"]),len(groups)),(5,39))
        self.assertTrue(all(g["mapping_state"]=="candidate" and g["service_key"] is None and g["business_phase"]=="unknown" and g["initiation"]=="unknown" and g["security_class"]=="unknown" for g in groups))
        self.assertFalse(d["semantic_classifications_inferred"]);self.assertFalse(d["session_ip_account_or_payload_values_exported"])
        text=json.dumps(d)
        for forbidden in ("SYNTHETIC-PROVIDER-PING","clientId","transactionId",'"IP"','"Session"'):self.assertNotIn(forbidden,text)

    def test_request_action_crosswalk_counts_request_once_and_keeps_ambiguous_targets_unpaired(self):
        def access(oid,action,rid='LINKED_REQUEST'):
            name='ud_prc_userSessionHasAccess'
            return document(rid=rid,oid=oid,path='DBPath.pishkhan24.application.'+name,
                message=f'(Command Text: {name})(Code: 1)(Result: Ok)(SQL Parameters: @session=SESSION_PRIVATE @action={action})')
        rows=[document(rid='LINKED_REQUEST',oid='client',path='Core.v1/ConfigBasic Line:153'),
              access('access-1','v1/ConfigBasic'),access('access-2','v1/ConfigBasic'),
              document(rid='LINKED_REQUEST',oid='other',path='DBPath.app.ud_prc_unrelated',
                message='(Command Text: ud_prc_unrelated)(Code: 1)(Result: Ok)(SQL Parameters: @action=v9/IgnoreMe)')]
        result=observed_request_action_candidates(json.dumps(rows).encode(),locator='safe.sanitized.json',keys=TEST_KEYS,namespace='crosswalk-test')
        self.assertEqual(result['pair_count'],1)
        pair=result['pairs'][0]
        self.assertEqual((pair['client_http_endpoint'],pair['access_check_action']),('Core.v1/ConfigBasic','v1/ConfigBasic'))
        self.assertEqual((pair['request_projections'],pair['distinct_client_http_requests'],pair['access_check_sql_observations']),(1,1,2))
        self.assertEqual(pair['client_http_outcomes']['success'],1)
        self.assertEqual((pair['mapping_state'],pair['mapping_authority'],pair['execution_proven']),('same_request_co_observation_candidate','unverified','no'))
        self.assertNotIn('LINKED_REQUEST',json.dumps(result));self.assertNotIn('SESSION_PRIVATE',json.dumps(result));self.assertNotIn('IgnoreMe',json.dumps(result))

        ambiguous=observed_request_action_candidates(json.dumps([
            document(rid='AMBIG',oid='client',path='Core.v1/ConfigBasic Line:1'),
            access('access-1','v1/ConfigBasic',rid='AMBIG'),
            document(rid='AMBIG',oid='access-2',path='DBPath.pishkhan24.application.ud_prc_userSessionHasAccess',
                message='(Command Text: ud_prc_userSessionHasAccess)(Code: 1)(Result: Ok)(SQL Parameters: @action=v1/LoginByOTP)')
        ]).encode(),locator='ambiguous.sanitized.json',keys=TEST_KEYS,namespace='crosswalk-test')
        self.assertEqual(ambiguous['pair_count'],0)
        self.assertEqual(ambiguous['ambiguous_request_counts']['multiple_access_actions_in_request'],1)

    def test_registration_crosswalk_preserves_http_and_access_action_versions(self):
        value=observed_request_action_candidates((ROOT/'fixtures/registration.sanitized.json').read_bytes(),
            locator='registration.sanitized.json',keys=TEST_KEYS,namespace='crosswalk-test')
        pairs={(p['client_http_endpoint'],p['access_check_action']):p['distinct_client_http_requests'] for p in value['pairs']}
        self.assertEqual(pairs[('Core.v1/DeviceRegister','v1/DeviceRegister')],1)
        self.assertEqual(pairs[('Core.v2/DeviceRegister','v2/DeviceRegister')],1)
        self.assertEqual(value['distinct_client_http_requests'] if 'distinct_client_http_requests' in value else sum(pairs.values()),2)

    def test_saved_action_crosswalk_is_reproducible_sanitized_and_not_summed_across_sources(self):
        from tools.export_action_crosswalk_candidates import build
        paths=[ROOT/'fixtures'/name for name in ('ip_activity.sanitized.json','session_activity.sanitized.json',
            'boundary.sanitized.json','registration.sanitized.json','taxonomy/provider_ping.sanitized.json')]
        generated=build(paths)
        saved=json.loads((ROOT/'catalogs/action_crosswalk_candidates.json').read_text(encoding='utf-8'))
        self.assertEqual(generated,saved)
        self.assertEqual((saved['version'],saved['status'],len(saved['sources'])),
            ('p24-action-crosswalk-candidate.1','unpublished_same_request_co_observation_candidates',5))
        self.assertEqual(saved['source_counts_must_not_be_summed'], 'source fixtures can overlap; no cross-source union is asserted')
        registration=next(s for s in saved['sources'] if s['locator']=='registration.sanitized.json')
        self.assertEqual(registration['pair_count'],2)
        markers=[]
        for source in paths:
            for record in decode_batch(source.read_bytes()).records:
                fields=record.get('fields') or record.get('_source') or {}
                for name in ('RequestID','IP','Session'):
                    value=fields.get(name)
                    if isinstance(value,list):value=value[0] if value else None
                    if isinstance(value,str) and value not in {'','N/A'}:markers.append(value)
        rendered=json.dumps(saved)
        self.assertTrue(all(value not in rendered for value in markers))
        self.assertNotIn('SQL Parameters:',rendered)
        self.assertNotIn('transactionId',rendered)

    def test_action_to_postman_reconciliation_preserves_version_conflicts_as_candidates(self):
        action={"source_counts_must_not_be_summed":"overlap","sources":[{"locator":"fixture.json","source_sha256":"a"*64,"pairs":[
            {"client_http_endpoint":"Core.v1/ConfigBasic","access_check_action":"v1/ConfigBasic","distinct_client_http_requests":5},
            {"client_http_endpoint":"Core.v2/DeviceRegister","access_check_action":"v2/DeviceRegister","distinct_client_http_requests":1},
            {"client_http_endpoint":"Services.v3/ElectricBillsExport","access_check_action":"v3/ElectricBillsExport","distinct_client_http_requests":1},
            {"client_http_endpoint":"Core.v9/Unknown","access_check_action":"v9/Unknown","distinct_client_http_requests":1}]}]}
        postman={"items":[
            {"collection":"Core","item_path":"/item/6","request_name":"ConfigBasic","method":"POST","endpoint":"/core.svc/v1/ConfigBasic","endpoint_state":"resolved"},
            {"collection":"Core","item_path":"/item/10","request_name":"DeviceRegister","method":"POST","endpoint":"/core.svc/v1/DeviceRegister","endpoint_state":"resolved"},
            {"collection":"Services","item_path":"/item/10","request_name":"ElectricBillsExport","method":"POST","endpoint":"/services.svc/v2/ElectricBillsExport","endpoint_state":"resolved"}]}
        result=reconcile_action_candidates_with_postman(action,postman)
        rows={p['access_check_action']:p for p in result['sources'][0]['pairs']}
        self.assertEqual(rows['v1/ConfigBasic']['postman_candidate_state'],'exact_documented_path_suffix_candidate')
        self.assertEqual(rows['v2/DeviceRegister']['postman_candidate_state'],'request_name_match_version_or_path_unresolved')
        self.assertEqual(rows['v3/ElectricBillsExport']['postman_candidate_state'],'request_name_match_version_or_path_unresolved')
        self.assertEqual(rows['v9/Unknown']['postman_candidate_state'],'no_literal_postman_candidate')
        self.assertTrue(all(p['authority']=='candidate_only' and p['execution_proven']=='no' for p in rows.values()))
        self.assertEqual(rows['v1/ConfigBasic']['endpoint_action_relation'],'same_suffix_candidate')

    def test_saved_action_postman_reconciliation_is_reproducible_and_does_not_publish_taxonomy(self):
        from tools.reconcile_action_api_candidates import build
        action=json.loads((ROOT/'catalogs/action_crosswalk_candidates.json').read_text(encoding='utf-8'))
        postman=json.loads((ROOT/'catalogs/postman_route_candidates.json').read_text(encoding='utf-8'))
        conflicts=json.loads((ROOT/'catalogs/postman_route_conflicts.json').read_text(encoding='utf-8'))
        saved=json.loads((ROOT/'catalogs/action_api_reconciliation_candidates.json').read_text(encoding='utf-8'))
        self.assertEqual(build(action,postman,conflicts),saved)
        states={p['postman_candidate_state'] for s in saved['sources'] for p in s['pairs']}
        self.assertIn('exact_documented_path_suffix_candidate',states)
        self.assertIn('request_name_match_version_or_path_unresolved',states)
        self.assertTrue(all(p['authority']=='candidate_only' and p['execution_proven']=='no' for s in saved['sources'] for p in s['pairs']))
        self.assertFalse(saved['semantic_classifications_inferred'])
        self.assertFalse(saved['identity_values_or_payloads_exported'])

    def test_error_code_layers_stay_separate_and_chain_context_is_request_scoped(self):
        catalog=json.loads((ROOT/'catalogs/error_code_catalog.json').read_text(encoding='utf-8'))
        data=(ROOT/'fixtures/boundary.sanitized.json').read_bytes()
        result=observed_code_operation_candidates(data,locator='boundary.sanitized.json',keys=TEST_KEYS,
            namespace='error-chain-test',code_catalog=catalog)
        provider=next(g for g in result['groups'] if g['operation_role']=='provider' and g['code']=='GD2016' and g['evidence_layer']=='provider_body')
        self.assertEqual((provider['operation_callpath'],provider['recorded_outcome']),
            ('ClientAyanCoInquiry.ElectricityBillInquiryGetBillImage','failure'))
        self.assertEqual(provider['codebook_candidate_state'],'single_code_entry_symbol_unavailable')
        self.assertEqual(provider['codebook_candidates'][0]['code_system'],'WebCrawler')
        self.assertEqual(provider['codebook_candidates'][0]['operation_binding_state'],'not_established_by_workbook')
        self.assertEqual(provider['same_request_contexts'],[{'client_http_endpoints':['Services.v3/ElectricBillsExport'],
            'access_check_actions':['v3/ElectricBillsExport'],'distinct_request_count':1,
            'link_state':'same_request_co_observation_candidate'}])

        log_success=next(g for g in result['groups'] if g['operation_role']=='provider' and g['code']=='G00000')
        workflow=next(g for g in result['groups'] if g['operation_role']=='sql' and g['code']=='GD2016')
        self.assertEqual((log_success['evidence_layer'],log_success['recorded_outcome'],log_success['codebook_candidate_state']),
            ('platform_log','success','no_literal_codebook_entry'))
        self.assertEqual((workflow['evidence_layer'],workflow['recorded_outcome']),('workflow_body','unknown'))
        self.assertNotIn('Code 1',[g['code'] for g in result['groups']])

    def test_provider_ping_code_definition_does_not_override_recorded_unknown_outcome(self):
        catalog=json.loads((ROOT/'catalogs/error_code_catalog.json').read_text(encoding='utf-8'))
        data=(ROOT/'fixtures/taxonomy/provider_ping.sanitized.json').read_bytes()
        result=observed_code_operation_candidates(data,locator='provider_ping.sanitized.json',keys=TEST_KEYS,
            namespace='error-chain-test',code_catalog=catalog)
        group=next(g for g in result['groups'] if g['code']=='GR0010')
        self.assertEqual((group['operation_role'],group['operation_callpath'],group['recorded_outcome']),
            ('provider','EwanoApi.Ping','unknown'))
        self.assertEqual(group['codebook_candidate_state'],'single_code_and_symbol_candidate')
        self.assertFalse(group['operation_binding_proven']=='yes')
        self.assertEqual(group['same_request_contexts'][0]['client_http_endpoints'],[])
        self.assertNotIn('SYNTHETIC-PROVIDER-PING',json.dumps(result))

    def test_saved_error_operation_catalog_reproduces_without_identity_or_payloads(self):
        from tools.export_error_operation_candidates import build
        paths=[ROOT/'fixtures'/name for name in ('ip_activity.sanitized.json','session_activity.sanitized.json',
            'boundary.sanitized.json','registration.sanitized.json','taxonomy/provider_ping.sanitized.json')]
        catalog=json.loads((ROOT/'catalogs/error_code_catalog.json').read_text(encoding='utf-8'))
        saved=json.loads((ROOT/'catalogs/error_operation_candidates.json').read_text(encoding='utf-8'))
        self.assertEqual(build(paths,catalog),saved)
        self.assertEqual((saved['version'],len(saved['sources']),sum(s['group_count'] for s in saved['sources'])),
            ('p24-observed-code-operation-candidate.1',5,19))
        markers=[]
        for path in paths:
            for record in decode_batch(path.read_bytes()).records:
                fields=record.get('fields') or record.get('_source') or {}
                for field in ('RequestID','IP','Session'):
                    value=fields.get(field)
                    if isinstance(value,list):value=value[0] if value else None
                    if isinstance(value,str) and value not in {'','N/A'}:markers.append(value)
        rendered=json.dumps(saved,ensure_ascii=False)
        self.assertTrue(all(value not in rendered for value in markers))
        for forbidden in ('SQL Parameters:','transactionId','invoiceuniqueid','userAgent','@otpCode='):
            self.assertNotIn(forbidden,rendered)
        self.assertFalse(saved['code_systems_globally_assumed'])
        self.assertFalse(saved['raw_request_ids_ips_sessions_parameters_or_payloads_exported'])


class TaxonomyPostgresTests(unittest.TestCase):
    connection=None
    @classmethod
    def setUpClass(cls):
        if cls.connection is None:raise unittest.SkipTest("isolated PostgreSQL configuration required")
        initialize(cls.connection)

    def test_candidate_import_is_draft_safe_and_repeatable(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);secret="SYNTHETIC_AUTH_VALUE_9921"
            collection=root/"Core.postman_collection.json"
            collection.write_text(json.dumps({"info":{"name":"Core"},"item":[
                {"name":"DeviceRegister","request":{"method":"POST","url":"https://api.example.test/core.svc/v2/DeviceRegister?token="+secret,"header":[{"key":"Authorization","value":secret}],"body":{"raw":secret}}},
                {"name":"Missing route","request":{"method":"POST"}}]}))
            catalog_path=root/"error_code_catalog.json"
            catalog_path.write_text(json.dumps({"sources":[{"code_system":"Example","file_name":"Example.xlsx","sha256":"a"*64}],
                "records":[{"code_system":"Example","code":"EX0001","source_file":"Example.xlsx","source_sheet":"Codes","source_row":2,"source_cells":{"A2":"EX0001"},"definition_state":"complete_definition","user_message_fa":"تعریف نمونه","log_symbol":"ExampleFailure"},
                           {"code_system":"Example","code":"EX0002","source_file":"Example.xlsx","source_sheet":"Codes","source_row":3,"source_cells":{"A3":"EX0002"},"definition_state":"code_only","meaning_authority":"no_meaning_supplied"}]},ensure_ascii=False),encoding="utf-8")
            logs=[ROOT/"fixtures/registration.sanitized.json",ROOT/"fixtures/taxonomy/provider_ping.sanitized.json"]
            c=self.connection;store=FoundationStore(c,TEST_KEYS,"taxonomy_"+uuid.uuid4().hex,root/"vault")
            result=store.import_taxonomy_candidates([collection],error_catalog_path=catalog_path,log_evidence_paths=logs)
            self.assertEqual((result["postman_request_items"],result["unresolved_endpoint_items"],result["literal_error_code_rows"]),(2,1,2))
            self.assertEqual((result["observed_log_files"],result["observed_log_callpath_candidates"],result["unresolved_log_records"]),(2,5,0))
            self.assertFalse(result["published"]);self.assertFalse(result["semantic_classifications_inferred"])
            tid=uuid.UUID(result["taxonomy_id"]);params=(store.namespace_id,tid)
            self.assertEqual(c.execute("SELECT state FROM p24_next.taxonomy_release WHERE namespace_id=%s AND taxonomy_id=%s",params).fetchone(),("draft",))
            rows=c.execute("SELECT source_role,exact_endpoint,method,service_key,phase_key,status,match_contract::text FROM p24_next.service_mapping WHERE namespace_id=%s AND taxonomy_id=%s",params).fetchall()
            self.assertEqual(len(rows),7)
            self.assertTrue(all(r[3] is None and r[4]=="unknown" and r[5]=="candidate" for r in rows))
            self.assertIn(("provider","EwanoApi.Ping",None,None,"unknown","candidate"),[r[:6] for r in rows])
            self.assertEqual(c.execute("SELECT match_contract->>'observed_event_count',match_contract->>'distinct_request_count' FROM p24_next.service_mapping WHERE namespace_id=%s AND taxonomy_id=%s AND exact_endpoint='EwanoApi.Ping'",params).fetchone(),("1","1"))
            for forbidden in (secret,"SYNTHETIC-PROVIDER-PING","clientId","transactionId",'"IP"','"Session"'):self.assertNotIn(forbidden,json.dumps(rows))
            entries=c.execute("SELECT code,definition_state,meaning_authority,operation_binding_state,user_message_fa FROM p24_next.catalog_code_entry WHERE namespace_id=%s AND taxonomy_id=%s ORDER BY code",params).fetchall()
            self.assertEqual(entries,[("EX0001","complete_definition","supplied_catalog_definition","not_established_by_workbook","تعریف نمونه"),("EX0002","code_only","no_definition_supplied","not_established_by_workbook",None)])
            again=store.import_taxonomy_candidates([collection],error_catalog_path=catalog_path,log_evidence_paths=logs)
            self.assertEqual(again["taxonomy_id"],result["taxonomy_id"])
            self.assertEqual(c.execute("SELECT count(*) FROM p24_next.service_mapping WHERE namespace_id=%s AND taxonomy_id=%s",params).fetchone(),(7,))
