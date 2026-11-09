"""Manual evidence smoke over a bounded original sample; only aggregate output."""
import argparse,gzip,hashlib,json,tempfile,time
from pathlib import Path
from p24_foundation.privacy import generate_keys
from p24_foundation.viewer_data import ViewerDB
args=argparse.ArgumentParser(description=__doc__)
args.add_argument('--source',type=Path,required=True)
args.add_argument('--out',type=Path)
args=args.parse_args()
raw=args.source
start=time.perf_counter()
with gzip.open(raw,'rt',encoding='utf8') as f:data=json.load(f)
assert data['count'] == len(data['logs'])
original_n=len(data['logs'])
data['logs']=data['logs'][:2500]
data['count']=len(data['logs'])
with tempfile.TemporaryDirectory() as d:
    p=Path(d); file=p/'sample.json.gz';key=p/'keys.json'
    with gzip.open(file,'wt',encoding='utf8') as f:json.dump(data,f,ensure_ascii=False)
    generate_keys(key)
    with ViewerDB(sqlite_path=p/'db.db',keys_path=key) as db:
        db.init();ingested=db.ingest([file]);model=db.rebuild();roles=db.service_roles(25)
        paths=[r['service_path'] for r in roles['items']]
        if paths:
            sample=db.requests_page(25,0,service_path_filter=paths[0]);assert sample['total'] == roles['items'][0]['requests']
            assert all(r['root_call'].split(' Line:',1)[0]==paths[0] for r in sample['items'])
        assert sum(roles['role_totals'].values()) == roles['global_total']
        assert db.raw_coverage()['complete']
        report={'source_file':raw.name,'source_bytes_sha256':hashlib.sha256(raw.read_bytes()).hexdigest(),
                'source_window_rows':original_n,'sample_type':'first_2500_source_rows','sample_rows':2500,
                'result':'PASS','events':model['events'],'requests':model['requests'],
                'catalog_services':roles['global_total'],'role_totals':roles['role_totals'],
                'exact_service_filter_checked':bool(paths),'full_raw_saved':True,
                'duration_seconds':round(time.perf_counter()-start,3),'runtime':'SQLite, Python '+__import__('platform').python_version()}
        print(json.dumps(report,ensure_ascii=False,indent=2))
        if args.out:
            out=args.out;out.parent.mkdir(parents=True,exist_ok=True)
            out.write_text(json.dumps(report,ensure_ascii=False,indent=2)+'\n',encoding='utf8')
