"""Regression checks for the errors observed in native Windows installation.

These are offline compatibility checks, NOT native PostgreSQL or Flask browser validation.
"""
from __future__ import annotations
import gzip
import json
import re
import tempfile
import unittest
from pathlib import Path
from jinja2 import Environment, FileSystemLoader, StrictUndefined
from p24_foundation.viewer_data import ViewerDB
from p24_foundation.privacy import generate_keys

ROOT=Path(__file__).resolve().parents[1]

class StrictPgPercentConnection:
    """Simulate psycopg3's % placeholder validator atop SQLite for unit coverage."""
    def __init__(self,conn):
        self.conn=conn
        # Placeholder-only harness; native locking is qualified separately.
        self.conn.create_function('pg_advisory_xact_lock',2,lambda *args:0)
    def execute(self,sql,params=()):
        converted=[];i=0
        while i<len(sql):
            if sql[i]!='%':converted.append(sql[i]);i+=1;continue
            if i+1 >=len(sql):raise AssertionError('trailing percent in SQL')
            marker=sql[i+1]
            if marker=='s':converted.append('?')
            elif marker=='%':converted.append('%')
            else:raise AssertionError('invalid psycopg placeholder: %'+marker)
            i+=2
        statement=''.join(converted)
        if statement.startswith('SELECT body.value FROM viewer_events e CROSS JOIN LATERAL'):
            # SQLite cannot parse PostgreSQL LATERAL. This adapter validates
            # placeholders only; the real fenced query/plan is qualified by
            # qualify_viewer_postgres, not by this portable harness.
            raw=re.search(r'SELECT b\.(raw_session_id|raw_request_id) AS value',statement).group(1)
            scope=re.search(r'WHERE e\.(session_key|request_key)=\?',statement).group(1)
            statement=('SELECT b.'+raw+' AS value FROM viewer_events e JOIN viewer_raw_events b '+
                'ON b.origin_key=e.origin_key AND b.version_key=e.version_key '+
                'WHERE e.'+scope+'=? AND b.'+raw+' IS NOT NULL LIMIT 1')
        return self.conn.execute(statement,params)
    def commit(self):return self.conn.commit()
    def rollback(self):return self.conn.rollback()


class NativeInstallRegressionTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup)
        root=Path(self.tmp.name)
        self.keys=root/'keys.json';generate_keys(self.keys)
        self.db=ViewerDB(sqlite_path=root/'db.sqlite3',keys_path=self.keys)
        self.addCleanup(self.db.close)
        self.db.init()
        self.window=root/'sample.json.gz'
        sample=[{'@timestamp':'2026-10-24T04:19:10.1000001Z','RequestID':'11111111-1111-4111-8111-111111111111',
                 'Session':'ABCD1234ABCD1234ABCD1234ABCD1234','IP':'192.0.2.123',
                 'CallPath':'Services.v1/InvoiceRegister Line:101','level':'Info',
                 'message':'POST https://example.test/InvoiceRegister (G00000 | successful)',
                 '_source_id':'logs-test-20261024:unique-doc'}]
        with gzip.open(self.window,'wt',encoding='utf-8') as out:
            json.dump({'window_start':'2026-10-24T04:15:00Z','window_end':'2026-10-24T04:20:00Z',
                       'count':1,'logs':sample},out)

    def test_postgres_placeholder_format_on_rebuild_and_business_reconcile(self):
        self.db.ingest([self.window])
        original_connection=self.db.conn
        self.db.conn=StrictPgPercentConnection(original_connection)
        self.db.sqlite=False
        try:
            result=self.db.rebuild()
            self.assertEqual(result['requests'],1)
            self.assertEqual(self.db.all("SELECT * FROM viewer_actions")[0]['initiation'],'confirmed_automatic')
        finally:
            self.db.conn=original_connection
            self.db.sqlite=True

    def test_jinja_pages_iterate_dict_items_not_method(self):
        env=Environment(loader=FileSystemLoader(str(ROOT/'review_ui/templates')),
                        undefined=StrictUndefined,autoescape=True)
        from p24_foundation.viewer_display_time import tehran_time
        env.filters['tehran_time']=tehran_time
        env.globals['url_for']=lambda endpoint,**kwargs:'/test'
        basic=dict(version='offline-test')
        sample_session=dict(session_key='abc',alias='نشست تست',started_fa='امروز',ended_fa='امروز',
                           requests=1,events=3,business_count=1,latest_business='ElectricBills',raw_session_id='ABCD')
        home=env.get_template('viewer_home.html').render(**basic,stats=dict(events=3,requests=1,session_ids=1,actions=1),
                result={'items':[sample_session],'total':1},page=1,limit=25,search='',ip='',start='',end='')
        self.assertIn('نشست تست',home)
        action=dict(when_fa='امروز',label='استعلام قبض',name='ElectricBills',target_type='ElectricBills',
                    target_alias='abc',initiation='unknown',current_outcome='success',root_code='G00000',
                    event_count=3,sql_count=1,action_key='abcd')
        session=env.get_template('viewer_session.html').render(**basic,result={'items':[action],'total':1},
                info=dict(requests=1,from_fa='شروع',to_fa='پایان'),key='abc',page=1,limit=25,
                category='business',service='',outcome='')
        self.assertIn('استعلام قبض',session)
        evidence={'items':[dict(when_fa='امروز',kind='sql',callpath='DBPath.test',code='G00000',observation=None,
                               variant_count=1,filename='sample.json.gz',row_number=0)],'total':1}
        request=env.get_template('viewer_request.html').render(**basic,card=dict(session_key='abc',root_call='Core.test',
                root_code='G00000',event_count=1,sql_count=1,provider_count=0,identity_state='assigned',
                from_fa='امروز',to_fa='امروز',conflicted=False,request_key='abc'),
                evidence=evidence,page=1,limit=25)
        self.assertIn('DBPath.test',request)
        self.assertIn('sample.json.gz',request)

if __name__=='__main__':unittest.main()
