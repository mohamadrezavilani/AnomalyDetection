import unittest
from compact_behavior.context import from_log, combine, empty, observe, MAX_VALUES
from compact_behavior.extract import facts, materialize, canonical
from tests.test_compact_extract import row, extract

SQL='DBPath.pishkhan24.application.ud_prc_userSessionHasAccess'


class CompactContextTests(unittest.TestCase):
    def test_benchmark_policy_exception_never_hides_content_changes(self):
        from copy import deepcopy
        from compact_behavior.extract import digest
        from tools.Benchmark_Compact_Context import signature_without_policy_stamp
        state=extract([row()])['req-1'];body=materialize('test',state)
        old=deepcopy(body);old['features']['behavior_policy_version']='meaningful-api-roles-1'
        a,_=signature_without_policy_stamp(old,state,digest)
        b,_=signature_without_policy_stamp(body,state,digest)
        self.assertEqual(a,b)
        changed=deepcopy(body);changed['features']['service_rate_eligible']=False
        self.assertNotEqual(a,signature_without_policy_stamp(changed,state,digest)[0])
        self.assertEqual(body['features']['behavior_policy_version'],'meaningful-api-roles-2')
        changed['features']['behavior_policy_version']='unreviewed-version'
        with self.assertRaises(ValueError):signature_without_policy_stamp(changed,state,digest)

    def test_benchmark_accepts_only_exact_hash_or_explicit_v1_v2_stamp_transition(self):
        from copy import deepcopy
        from tools.Benchmark_Compact_Context import parity
        data=dict(baseline=dict(behavior_hash='a',behavior_hash_without_policy_stamp='same',behavior_policies=['meaningful-api-roles-1']),
            candidate=dict(behavior_hash='b',behavior_hash_without_policy_stamp='same',behavior_policies=['meaningful-api-roles-2']))
        self.assertFalse(parity(data)['same_behavior_hash'])
        self.assertTrue(parity(data)['behavior_parity_accepted'])
        changed=deepcopy(data);changed['candidate']['behavior_hash_without_policy_stamp']='different'
        self.assertFalse(parity(changed)['behavior_parity_accepted'])
        changed=deepcopy(data);changed['candidate']['behavior_policies']=['meaningful-api-roles-3']
        self.assertFalse(parity(changed)['behavior_parity_accepted'])

    def test_blank_fragments_never_erase_one_observed_value(self):
        records=[dict(row(),IP=''),dict(row(path=SQL,message='(SQL Parameters: @session=s @userAgent=Example Browser @ipAddress=192.0.2.8 @action=v1/WaterBills)'),IP='N/A'),dict(row(),IP='192.0.2.8'),dict(row(),IP=None)]
        state=extract(records)['req-1']; context=state['request_context']['values']
        self.assertEqual([x['value'] for x in context['ip']],['192.0.2.8'])
        self.assertEqual([x['value'] for x in context['user_agent']],['Example Browser'])
        self.assertEqual(state['sessions'],['session-1'])
        self.assertNotIn('request_context',materialize('test',state)['features'])

    def test_valid_ipv4_ipv6_and_conflicting_field_variants(self):
        c=from_log({'_source':{'IP':['','192.0.2.1','garbage']},'fields':{'IP':['2001:0db8::1','::ffff:192.0.2.1']}})
        self.assertEqual([x['value'] for x in c['values']['ip']],['192.0.2.1','2001:db8::1'])
        self.assertFalse(from_log({'IP':'not an IP','UserAgent':'N/A'}))
        self.assertFalse(from_log({'IP':'1'*10000,'UserAgent':''}))

    def test_context_merge_is_bounded_order_independent_and_keeps_conflicts(self):
        contexts=[from_log({'IP':f'192.0.2.{i}','UserAgent':f'Agent{i}'}) for i in range(20)]
        a=b={}
        for c in contexts:a=combine(a,c)
        for c in reversed(contexts):b=combine(b,c)
        self.assertEqual(a,b)
        self.assertEqual(len(a['values']['ip']),MAX_VALUES)
        self.assertIn('ip_variants',a['limited'])
        self.assertEqual(combine(a,{}),a)
        self.assertEqual(combine(a,a),a)
        c=empty();observe(c,'user_agent','x'*2000,'test')
        self.assertNotIn('user_agent',c['values']);self.assertIn('user_agent_length',c['limited'])

    def test_sql_extras_are_allowlisted_and_request_scoped(self):
        r=row(path='DBPath.pishkhan24.application.ud_prc_userSessionCreate', message='(SQL Parameters: @session=s @application=mobile @platform=Android @version=5.0 @rsaKey=DO-NOT-STORE @userAgent=Browser @ipAddress=192.0.2.9)')
        state=extract([r])['req-1']; rendered=canonical(state['request_context'])
        self.assertNotIn('DO-NOT-STORE',rendered)
        self.assertIn('app_version',rendered)
        self.assertIn('Android',rendered)
        other=extract([r,row(request='other')])['other']['request_context']
        self.assertNotIn('ip',other['values'])
        self.assertEqual(other['values']['http_method'][0]['value'],'POST')

    def test_first_evidence_time_is_preserved_without_inventing_unknown_time(self):
        a=from_log({'IP':'192.0.2.1'}, 100)
        b=from_log({'IP':'192.0.2.1'}, 200)
        self.assertEqual(combine(a,b)['values']['ip'][0]['first_ns'],100)
        c=combine(a,from_log({'IP':'192.0.2.1'}))['values']['ip'][0]
        self.assertTrue(c['undated']);self.assertEqual(c['first_ns'],100)

    def test_metadata_does_not_change_existing_features_or_quality(self):
        a=materialize('test',facts(row()))
        b=materialize('test',facts(dict(row(),IP='192.0.2.1',UserAgent='Browser')))
        self.assertEqual(a,b)
        state=extract([row(message='Input:{"UserAgent":"Browser","Amount":1} Output:{}')])['req-1']
        self.assertEqual(state['request_context']['values']['user_agent'][0]['value'],'Browser')
        self.assertTrue(state['request_context']['values']['user_agent'][0]['sources'][0].startswith('payload.'))
