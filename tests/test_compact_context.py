import unittest
from compact_behavior.context import from_log, combine, empty, observe, MAX_VALUES
from compact_behavior.extract import facts, materialize, canonical
from tests.test_compact_extract import row, extract

SQL='DBPath.pishkhan24.application.ud_prc_userSessionHasAccess'


class CompactContextTests(unittest.TestCase):
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

    def test_metadata_does_not_change_existing_features_or_quality(self):
        a=materialize('test',facts(row()))
        b=materialize('test',facts(dict(row(),IP='192.0.2.1',UserAgent='Browser')))
        self.assertEqual(a,b)
        state=extract([row(message='Input:{"UserAgent":"Browser","Amount":1} Output:{}')])['req-1']
        self.assertEqual(state['request_context']['values']['user_agent'][0]['value'],'Browser')
        self.assertTrue(state['request_context']['values']['user_agent'][0]['sources'][0].startswith('payload.'))
