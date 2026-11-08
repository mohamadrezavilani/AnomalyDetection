from pathlib import Path
import json
from transport import Engine
from anomaly_detection import BUILD_ID
from anomaly_detection.sql_budget import statement_budget
from anomaly_detection.product_store import ProductStore
from anomaly_detection.case_summary import render
from anomaly_detection.unified_review import progress
from anomaly_detection.runtime_statistics import collect
ROOT=Path(__file__).resolve().parents[2]
e=Engine()
try:
 r=e.connect();r.execute('CREATE SCHEMA anomaly_detection');s=ProductStore(r);s.initialize()
 r.execute("SET statement_timeout='3s'")
 value=lambda:r.execute("SELECT current_setting('statement_timeout') AS value").fetchone()['value']
 with r.transaction():
  r.execute('SET TRANSACTION READ ONLY')
  with r.transaction():r.execute("SET LOCAL statement_timeout='200ms'")
  assert value()=='200ms'
 r.execute("SET statement_timeout='3s'")
 checks={'original_successful_savepoint_leaks_200ms_into_parent':'REPRODUCED_SQL'}
 with r.transaction():
  r.execute('SET TRANSACTION READ ONLY')
  with statement_budget(r,200):assert value()=='200ms'
  assert value()=='3s'
  try:
   with statement_budget(r,200):r.execute("DO $$ BEGIN RAISE EXCEPTION 'fixture' USING ERRCODE='57014'; END $$")
  except Exception as ex:assert ex.sqlstate=='57014'
  assert value()=='3s'
  collect(s,[('ok',lambda:1)]);assert value()=='3s'
  progress(s);assert value()=='3s'
  render(s,{});assert value()=='3s'
 checks.update(successful_and_cancelled_nested_budget_restore_parent='PASS',statistics_progress_and_page_preserve_3s_in_readonly_parent='PASS')
 report={'build_id':BUILD_ID,'status':'PASS_NESTED_STATEMENT_BUDGET_RESTORATION','checks':checks,'owner_connections':0,'native_windows_postgresql24':'NOT_RUN','production_accuracy':'NOT_MEASURED'}
 (ROOT/'validation/PRODUCT_revision24.json').write_text(json.dumps(report,indent=2)+'\n');print(json.dumps(report))
finally:e.close()
