"""WIP handoff helper: regenerate strict source pins; does not qualify a release.

Run only after source edits are complete. This helper never opens a database.
"""
from pathlib import Path
import hashlib,json,re,sys
r=Path(__file__).resolve().parents[1];sys.path.insert(0,str(r))
from p24_foundation.viewer_runtime import runtime_source_digest
runtime=runtime_source_digest(r)
# Only explicitly staged/tracked public inputs may join the inventory.
import subprocess
tracked=set(subprocess.check_output(['git','ls-files'],cwd=r,text=True).splitlines())
# Runtime boundaries outside the AD source digest use exactly the current pin.
for name in ('viewer_performance/fast_writer.py','viewer_performance/Run_Viewer_Memory.py','viewer_performance/Collect_Capacity_Inputs.py','viewer_performance/Qualify_Capacity_Candidate.py','viewer_performance/Run_Viewer_Index_Probe_UTF8.py','viewer_performance/capacity/origin_filter.py'):
 p=r/name;s=p.read_text();s=re.sub(r"(BASE_RUNTIME\s*=\s*)['\"][a-f0-9]{64}['\"]",lambda m:m[1]+repr(runtime),s)
 # Qualification/collector use EXPECTED_RUNTIME instead of BASE_RUNTIME.
 s=re.sub(r"(EXPECTED_RUNTIME\s*=\s*)['\"][a-f0-9]{64}['\"]",lambda m:m[1]+repr(runtime),s)
 p.write_text(s)
p=r/'viewer_performance/fast_writer.py';s=p.read_text().replace("BUILD = 'VIEWER-20261117-C2C3-OBSERVED'","BUILD = 'VIEWER-20261117-BEHAVIOR-SCOPE'");p.write_text(s)
p=r/'AnomalyDetection/anomaly_detection/source_profiles.py';s=p.read_text();count=sum(1 for folder in ('p24_foundation','tools','review_ui','catalogs') for p in(r/folder).rglob('*') if p.is_file() and p.suffix in('.py','.html','.css','.js','.json','.csv') and '__pycache__' not in p.parts)
if 'R311_RUNTIME=' in s:
 s=re.sub(r"R311_RUNTIME='[^']+'",'R311_RUNTIME='+repr(runtime),s);s=re.sub(r'R311_FILES=\d+','R311_FILES='+str(count),s)
else:
 s=s.replace('SUPPORTED_RUNTIMES=frozenset(',f'R311_RUNTIME={runtime!r}\nR311_FILES={count}\nSUPPORTED_RUNTIMES=frozenset(').replace('R39_RUNTIME,R310_RUNTIME))','R39_RUNTIME,R310_RUNTIME,R311_RUNTIME))')
 s+='\n\ndef r311_release_allowed(manifest_runtime,actual_runtime,file_count):\n    return bool(manifest_runtime==R311_RUNTIME and actual_runtime==R311_RUNTIME and file_count==R311_FILES)\n'
p.write_text(s)
p=r/'AnomalyDetection/anomaly_detection/pg_source.py';s=p.read_text().replace('r39_release_allowed,r310_release_allowed\n','r39_release_allowed,r310_release_allowed,r311_release_allowed\n').replace('r310_release_allowed(declared,actual,count)),','r310_release_allowed(declared,actual,count) or r311_release_allowed(declared,actual,count)),');p.write_text(s)
for name in ('AnomalyDetection/anomaly_detection/__init__.py','AnomalyDetection/run_anomaly.py'):
 p=r/name;p.write_text(p.read_text().replace('AD-20261116-REFERENCE-CONTRACT','AD-20261117-BEHAVIOR-SCOPE'))
p=r/'tests/test_viewer_launcher_bytes.py';p.write_text(p.read_text().replace("profiles['R310_RUNTIME']","profiles['R311_RUNTIME']").replace("module['EXPECTED_BUILD'],'AD-20261116-REFERENCE-CONTRACT'","module['EXPECTED_BUILD'],'AD-20261117-BEHAVIOR-SCOPE'"))
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def save(p,d):p.write_text(json.dumps(d,ensure_ascii=False,indent=2)+'\n')
# AD strict inventory retains all old test/fixture members and adds current sources.
p=r/'AnomalyDetection/RELEASE_MANIFEST.json';d=json.loads(p.read_text());entries=d['files_sha256']
for folder,suffix in(('anomaly_detection','.py'),('tests','.py'),('fixtures','.json')):
 for q in(p.parent/folder).rglob('*'+suffix):
  if '__pycache__' not in q.parts and q.relative_to(r).as_posix() in tracked:entries[q.relative_to(p.parent).as_posix()]=sha(q)
for name in list(entries):entries[name]=sha(p.parent/name)
d['source_sha256']=hashlib.sha256(json.dumps(entries,sort_keys=True,separators=(',',':')).encode()).hexdigest();d['build_id']='AD-20261117-BEHAVIOR-SCOPE';d['viewer_runtime_sha256']=runtime
save(p,d)
for manifest in ('viewer_performance/CAPACITY_MANIFEST.json','viewer_performance/FAST_WRITER_MANIFEST.json'):
 p=r/manifest;d=json.loads(p.read_text());entries=d['files_sha256']
 for name in list(entries):entries[name]=sha(r/name)
 for key in ('runtime_source_sha256','base_runtime_source_sha256','root_runtime_source_sha256'):
  if key in d:d[key]=runtime
 d['source_sha256']=hashlib.sha256(json.dumps(entries,sort_keys=True,separators=(',',':')).encode()).hexdigest()
 if 'FAST_WRITER' in manifest:
  d.update(build_id='VIEWER-20261117-BEHAVIOR-SCOPE',canonical_runtime_files_changed=True,canonical_data_contract_changed=True,schema_migration='additive_explicit_product_scope',activation='explicit_product_scope_under_stopped_writers')
 save(p,d)
p=r/'RELEASE_MANIFEST.json';d=json.loads(p.read_text());entries=d['files_sha256']
# Staging is the deliberate public inventory boundary. Never include arbitrary
# untracked configs, exports, logs, temporary scripts or customer captures.
public_folders=('p24_foundation/','tools/','review_ui/','catalogs/','viewer_performance/','tests/','AnomalyDetection/anomaly_detection/','AnomalyDetection/tests/','.github/workflows/')
public_root={'AGENTS.md','VIEWER_README_FA.md','Pishkhan24_Project_Roadmap.md','BEHAVIOR_SCOPE_HANDOFF_FA.md','FINANCIAL_SCOPE_FA.md'}
for name in tracked:
 if name=='RELEASE_MANIFEST.json' or '.local.' in name or any(p in name.split('/') for p in ('reports','data','private','__pycache__')):continue
 if name in public_root or name.startswith(public_folders) and (r/name).suffix in ('.py','.ps1','.cmd','.md','.json','.yml','.html','.css','.js','.csv'):
  entries[name]=sha(r/name)
for name in list(entries):entries[name]=sha(r/name)
d['release_status']='REVIEW_CANDIDATE_OWNER_CAPACITY_NOT_ACCEPTED';d['runtime_source_sha256']=runtime;d['release_id']='VIEWER-20261117-BEHAVIOR-SCOPE';d['anomaly_build_id']='AD-20261117-BEHAVIOR-SCOPE';save(p,d)
print(json.dumps(dict(runtime=runtime,files=count,ad=d.get('anomaly_build_id'),root_members=len(entries))))
