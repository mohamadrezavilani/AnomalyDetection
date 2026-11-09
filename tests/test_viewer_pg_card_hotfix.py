"""PostgreSQL placeholder safety for R5 contract cards; SQLite executes same SQL."""
import gzip
import json
import tempfile
import unittest
from pathlib import Path
from p24_foundation.privacy import generate_keys
from p24_foundation.viewer_data import ViewerDB

class PaymentContractCardPgTests(unittest.TestCase):
    def test_payment_card_sql_binds_like_wildcards(self):
        with tempfile.TemporaryDirectory() as tmp:
            folder=Path(tmp)
            key=folder/'keys.json'
            generate_keys(key)
            with ViewerDB(sqlite_path=folder/'db.sqlite',keys_path=key) as db:
                db.init()
                req='12345678-1234-1234-1234-1234567890ab'
                rows=[dict(_source_id='pgtest:'+str(i),RequestID=req,
                           Session='1234567890abcdef1234567890abcdef',
                           CallPath=call,IP='192.0.2.21',
                           **{'@timestamp':'2026-10-24T04:15:05Z'},message=message)
                    for i,(call,message) in enumerate([
                        ('Core.v1/WalletPayment Line:1084','POST (G00000 | successful)'),
                        ('ClientAyanCoTopUp.PaymentDirectByMasterWallet Line:88','provider (G00000 | successful)'),
                    ])]
                path=folder/'w.json.gz'
                with gzip.open(path,'wt',encoding='utf-8') as f:
                    json.dump(dict(window_start='2026-10-24T04:15:00Z',window_end='2026-10-24T04:20:00Z',count=len(rows),logs=rows),f)
                self.assertEqual(db.ingest([path])[0]['status'],'IMPORTED')
                db.rebuild()
                db.rebuild_payment_contract()
                seen=[]
                old_sql=db.sql
                def strict_sql(statement,params=()):
                    if 'SELECT DISTINCT callpath FROM viewer_events' in statement:
                        seen.append((statement,params))
                        # psycopg3's placeholder lexer sees literal %Payment... as %P.
                        self.assertNotIn("LIKE '%",statement)
                        self.assertEqual(statement.count('LIKE ?'),3)
                        self.assertEqual(len(params),4)
                    return old_sql(statement,params)
                db.sql=strict_sql
                rkey=db.lookup_request(req)['request_key']
                for data in (db.request(rkey),db.action(rkey)):
                    self.assertEqual(data['payment_contract']['method_axes']['execution_route'],'provider_master_wallet')
                self.assertGreaterEqual(len(seen),2)

if __name__=='__main__':unittest.main()
