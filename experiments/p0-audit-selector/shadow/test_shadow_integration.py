"""Test full shadow run() using a simulated read-only PG connection."""
import json
import os
from pathlib import Path
from shutil import copytree
import subprocess
import sys
from tempfile import TemporaryDirectory
import unittest

HERE=Path(__file__).resolve().parent
SOURCE=Path(os.environ.get('P24_AD_TEST_ROOT',HERE.parents[2])).resolve()

class ShadowIntegrationTests(unittest.TestCase):
    def test_shadow_from_foreign_working_directory(self):
        script=r'''
import sys,types,contextlib,json
from pathlib import Path
root=Path(sys.argv[1]);project=Path(sys.argv[2]);sys.path.insert(0,str(root))
class Result:
 def __init__(self,rows):self.rows=rows
 def fetchall(self):return self.rows
 def fetchone(self):return self.rows[0] if self.rows else None
class Conn:
 def __init__(self):self.reads=0
 def __enter__(self):return self
 def __exit__(self,*args):pass
 @contextlib.contextmanager
 def transaction(self):yield
 def execute(self,sql,args=()):
  if sql.startswith('SET TRANSACTION'):return Result([])
  assert sql.startswith('SELECT '),sql[:100]
  self.reads+=1
  if 'current_database() AS name' in sql:
   return Result([dict(name='p24_design_viewer',role='p24_anomaly_detection',ro='on',oid=42)])
  if 'FROM anomaly_detection.adp_state' in sql:
   return Result([dict(body=json.dumps(dict(session_key='s0030',target_ns=9970,visit_until_ns=0)))])
  if sql.startswith('SELECT DISTINCT s.job_session,s.target_ns'):
   assert 'adp_source_windows' in sql and 's.source_kind' in sql
   assert sql.count('%s')==len(args)
   scopes=[(10000-i,'s%04d'%i) for i in range(100)]
   for k in range(0,len(args)-1,2):scopes=[item for item in scopes if item<(args[k],args[k+1])]
   rows=[dict(target_ns=n,job_session=s) for n,s in scopes[:args[-1]]]
   return Result(rows)
  if sql.startswith('SELECT f.request_key'):
   assert sql.count('%s')==len(args)
   if args[0]=='s0000':return Result([{'request_key':'PRIVATE'}])
   return Result([])
  raise AssertionError(sql[:140])
mod=types.ModuleType('psycopg');rows=types.ModuleType('psycopg.rows')
rows.dict_row=object();mod.connect=lambda **kw: Conn()
sys.modules['psycopg']=mod;sys.modules['psycopg.rows']=rows
import P24_AD_P0_Split_Qualification as helper
helper.pg_config=lambda _:dict(host='FAKE')
import P24_AD_P0_Shadow_Qualification as shadow
(project/'AnomalyDetection'/'RELEASE_MANIFEST.json').write_text(json.dumps({
 'build_id':shadow.REQUIRED_BUILD,'source_sha256':shadow.REQUIRED_SHA}),encoding='utf-8')
result=shadow.run(project,reference_db_oid=42)
assert result['status']=='COMPLETE_READ_ONLY',result
assert result['candidate_scope_sql_source_aligned']
assert result['selection']=='DUE_FOUND',result
assert result['turns']>=3,result
assert result['scope_queries']>3,result
assert result['due_queries']>=70,result
assert not result['database_changed']
assert result['memory_only_state_saves']>0
print('PASS SHADOW FRESH IMPORT',result['turns'],result['due_queries'])
'''
        with TemporaryDirectory(prefix='p24-shadow-') as temporary:
            folder=Path(temporary)
            project=folder/'fixture'
            copytree(SOURCE/'AnomalyDetection'/'anomaly_detection',project/'AnomalyDetection'/'anomaly_detection')
            completed=subprocess.run([sys.executable,'-B','-c',script,str(HERE),str(project)],
                cwd=folder,env={**os.environ,'PYTHONPATH':''},capture_output=True,text=True,timeout=30)
        self.assertEqual(completed.returncode,0,completed.stdout+'\n'+completed.stderr)
        self.assertIn('PASS SHADOW FRESH IMPORT',completed.stdout)

if __name__=='__main__':unittest.main(verbosity=2)
