"""Collector contract on 51 synthetic cases; no owner connection."""
import importlib.util
import json
from pathlib import Path
from tempfile import TemporaryDirectory
import zipfile
from transport import Engine
from anomaly_detection import FIVE_NS,BUILD_ID
from anomaly_detection.product_store import ProductStore
from anomaly_detection.product_pipeline import apply_window,owned_context
from anomaly_detection.snapshot import canonical,digest
from check_revision16 import merged_packet,T
from check_revision10 import SERVICES

ROOT=Path(__file__).resolve().parents[2]
from anomaly_detection import case_export as module



class Cursor:
    def __init__(self,raw,name,fail=False):self.raw=raw;self.name=name;self.fail=fail
    def __enter__(self):return self
    def __exit__(self,kind,*args):
        if kind is None:self.raw.execute('CLOSE "'+self.name+'"')
    def execute(self,sql,args):
        if self.fail:self.raw.execute('SELECT * FROM anomaly_detection.this_table_does_not_exist')
        assert sql.startswith('SELECT ')
        self.raw.execute('DECLARE "'+self.name+'" NO SCROLL CURSOR FOR '+sql,args)
    def fetchmany(self,n):return self.raw.execute('FETCH FORWARD '+str(n)+' FROM "'+self.name+'"').fetchall()


class Connection:
    def __init__(self,raw,fail=None):self.raw=raw;self.fail=fail
    def transaction(self):return self.raw.transaction()
    def execute(self,*a):return self.raw.execute(*a)
    def cursor(self,*,name):return Cursor(self.raw,name,self.fail==name)


def footprint(raw):
    names=('adp_cases','adp_case_signals','adp_case_requests','adp_jobs','adp_facts','adp_state','adp_population_jobs')
    return {n:dict(raw.execute('SELECT COUNT(*) AS n,md5(string_agg(row_to_json(t)::text,\'\' ORDER BY row_to_json(t)::text)) AS digest FROM anomaly_detection.'+n+' t').fetchone()) for n in names}


def main():
    engine=Engine()
    try:
        raw=engine.connect();raw.execute('CREATE SCHEMA anomaly_detection');store=ProductStore(raw);store.initialize()
        actors=[f'{i+1000:064x}' for i in range(51)]
        packet=merged_packet(T,[(s,5,T+1) for s in actors],100000)
        for row in packet['rows']:row['root_call']=SERVICES[3]
        apply_window(store,packet,cursor_name='fixture')
        raw.execute("UPDATE anomaly_detection.adp_facts SET details=jsonb_build_object('source_present',true,'semantic',body::jsonb,'quality',jsonb_build_object('evidence_available',true))::text")
        for actor in actors:
            job=dict(raw.execute('SELECT * FROM anomaly_detection.adp_jobs WHERE session_key=%s',(actor,)).fetchone())
            context=owned_context(store,job);context['evidence_verified']=True
            decisions=[]
            for span in (FIVE_NS,12*FIVE_NS):
                model={'model_id':'fixture:'+digest([actor,span]),'cutoff_ns':T,'expected':1,'reference_unit':'canonical_executions'}
                decisions.append({'finding_key':'pf1:'+digest([actor,span]),'session_key':actor,'target_ns':T,
                    'family':'continuous_rate','dimension':'activity','service_path':SERVICES[3],
                    'status':'CANDIDATE','observed':5,'expected':1,'duration_ns':span,'begin_ns':T,'end_ns':T+FIVE_NS,
                    'span_evidence_verified':True,'single_signal_review_eligible':True,'score':5,'reason':'EXPORT_FIXTURE_NOT_REAL_ANOMALY','model':model})
            decisions.append({'finding_key':'pf1:'+digest([actor,'timing']),'family':'timing_regularization','dimension':'timing',
                'status':'INSUFFICIENT_DATA','reason':'EXPORT_FIXTURE_COLD_REFERENCE','service_path':SERVICES[3]})
            assert store.complete(job,context,decisions,T+FIVE_NS)['status']=='APPLIED'
        baseline=footprint(raw)
        raw.execute('CREATE ROLE p24_anomaly_detection NOINHERIT')
        raw.execute('GRANT USAGE ON SCHEMA anomaly_detection TO p24_anomaly_detection')
        raw.execute('GRANT SELECT ON ALL TABLES IN SCHEMA anomaly_detection TO p24_anomaly_detection')
        reader=engine.connect(user='p24_anomaly_detection')
        with TemporaryDirectory(dir=ROOT/'validation') as temp:
            path=Path(temp)/'complete.zip'
            with zipfile.ZipFile(path,'w',zipfile.ZIP_DEFLATED) as archive:
                report=module.collect(Connection(reader),archive,{'build_id':'SYNTHETIC_16'},seconds=60)
            assert report['status']=='COMPLETE_READ_ONLY_CASE_REVIEW',report
            assert report['snapshot']['role']=='p24_anomaly_detection' and report['snapshot']['read_only']=='on'
            with zipfile.ZipFile(path) as archive:
                rows=lambda name:[json.loads(line) for line in archive.read(name+'.jsonl').decode().splitlines()]
                assert len(rows('cases'))==51 and len(rows('case_signals'))==102 and len(rows('case_models'))==102
                assert len(rows('case_members'))==510 and len(rows('case_facts'))==255
                assert all(not r['stale_actor_input'] for r in rows('cases'))
                summary=rows('family_readiness')
                assert any(r['family']=='timing_regularization' and r['status']=='INSUFFICIENT_DATA' and r['decisions']==51 for r in summary),summary
                assert not any('credential' in n or 'local.py' in n for n in archive.namelist())
            with zipfile.ZipFile(Path(temp)/'partial.zip','w') as archive:
                small=module.collect(Connection(reader),archive,{},seconds=60,max_bytes=1000)
            assert small['status']=='PARTIAL_READ_ONLY_CASE_REVIEW' and small['not_attempted']
            failed_index=next(i for i,(name,_,_) in enumerate(module.datasets()) if name=='case_findings')
            with zipfile.ZipFile(Path(temp)/'failure.zip','w') as archive:
                failed=module.collect(Connection(reader,fail='ad_case_review_'+str(failed_index)),archive,{},seconds=60)
            assert failed['status']=='PARTIAL_READ_ONLY_CASE_REVIEW'
            assert next(r for r in failed['datasets'] if r['name']=='case_findings.jsonl')['sqlstate']=='42P01'
            assert next(r for r in failed['datasets'] if r['name']=='case_models.jsonl')['complete']
        assert footprint(raw)==baseline
        result={'build_id':BUILD_ID,'collector':module.VERSION,'status':'PASS_ISOLATED_POSTGRESQL_WASM','synthetic_cases_exported':51,
            'overlapping_signal_members':510,'unique_facts':255,'read_only_snapshot':True,
            'all_case_models_and_family_readiness':True,'size_limit_and_failed_read_are_explicitly_partial':True,
            'failed_read_savepoint_recovers_for_other_datasets':True,'database_fingerprint_unchanged':True,
            'owner_connection':False,'native_windows_export':'NOT_RUN','actual_owner_case_accuracy':'NOT_PROVEN_BY_THIS_EXPORTER_TEST'}
        (ROOT/'validation/PRODUCT_export17.json').write_text(json.dumps(result,indent=2)+'\n');print(json.dumps(result))
    finally:engine.close()


if __name__=='__main__':main()
