import unittest
from flask import render_template
from compact_product.request_context import observed_context
from compact_product.web import create_app
from compact_product.config import Config


class RequestContextTests(unittest.TestCase):
    def test_existing_payload_only_with_provenance_and_no_inference(self):
        state = dict(inputs=[dict(path='ClientAyanCoExample', basis='supporting', value={
            'UserAgent': 'Example Browser', 'nested': {'IP': '192.0.2.1'},
            'Session': 'session', 'Authorization': 'not-a-displayed-context-field'})], outputs=[])
        result = observed_context(state)
        self.assertEqual([r['label'] for r in result['items']], ['User-Agent', 'IP'])
        self.assertEqual(result['items'][0]['source'], 'ClientAyanCoExample')
        self.assertEqual(result['items'][1]['location'], '$.nested.IP')
        self.assertTrue(result['scan_complete'])
        self.assertNotIn('Authorization', str(result))
        # The display helper never creates or changes stored data.
        self.assertEqual(state['inputs'][0]['value']['UserAgent'], 'Example Browser')

    def test_bounded_conflicts_missing_and_features_only(self):
        state = dict(inputs=[dict(path='a',value={'user_agent':'A'}),dict(path='b',value={'UserAgent':'B'})], outputs=[])
        self.assertEqual([x['value'] for x in observed_context(state)['items']], ['A','B'])
        result = observed_context({'inputs':[dict(representation='FEATURES_ONLY_V1', feature_snapshot={'UserAgent':'not raw'})]})
        self.assertTrue(result['features_only'])
        self.assertEqual(result['items'], [])
        state={'inputs':[dict(value={'userAgent':'x'*3000, 'other':[{'IP':'192.0.2.1'}]*40})]}
        result=observed_context(state)
        self.assertLessEqual(len(result['items']),20)
        self.assertEqual(len(result['items'][0]['value']),2048)
        self.assertTrue(result['items'][0]['truncated'])
        self.assertFalse(result['scan_complete'])
        result=observed_context({'inputs':[dict(value=list(range(3000)))]})
        self.assertFalse(result['scan_complete'])

    def test_details_escape_observed_metadata_and_explain_missing_data(self):
        app=create_app(Config(),{},'test',secret='test')
        row=dict(api='Core.v1/LoginByOTP',request_id='r',session_id='s',observed_at_ns=0,
            result_code='G00000',revision=1,quality=[],state=dict(inputs=[],outputs=[]))
        body=dict(operation_role='user_management',service_key=row['api'],features={})
        with app.test_request_context('/behaviors/test'):
            html=render_template('behavior.html',title='test',row=row,body=body,code_definitions={},request_context=observed_context(row['state']))
            self.assertIn('مشخصات محیطی قابل نمایش',html)
            row['state']['inputs']=[dict(path='Core.v1/LoginByOTP',basis='public_api',value={'UserAgent':'<img src=x onerror=alert(1)>','IP':'192.0.2.1'})]
            html=render_template('behavior.html',title='test',row=row,body=body,code_definitions={},request_context=observed_context(row['state']))
            self.assertIn('192.0.2.1',html)
            self.assertNotIn('<img src=x',html)
            self.assertIn('&lt;img src=x',html)
            self.assertIn('$.UserAgent',html)
            self.assertIn('لزوماً IP تأییدشدهٔ کاربر نیست',html)
