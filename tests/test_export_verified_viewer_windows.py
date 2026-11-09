"""Offline exporter tests; no real Elasticsearch or user database is touched."""
import gzip,hashlib,json,subprocess,sys,tempfile,unittest
from pathlib import Path

SCRIPT=Path(__file__).resolve().parents[1]/'tools/export_verified_viewer_windows.py'
TEST_EXPORTER='''
import argparse,datetime,gzip,hashlib,json,pathlib
p=argparse.ArgumentParser()
for x in ('collector','from-date','to-date','out-dir','method','page-size'):p.add_argument('--'+x)
a=p.parse_args()
start=datetime.datetime.fromisoformat(a.from_date)
end=datetime.datetime.fromisoformat(a.to_date)
root=pathlib.Path(a.out_dir);root.mkdir(exist_ok=True,parents=True)
run=root/('run_'+start.strftime('%Y%m%d_%H%M'))
run.mkdir()
fn='logs_'+start.astimezone(datetime.timezone.utc).strftime('%Y%m%d_%H%M%S')+'.json.gz'
data=dict(window_start=start.isoformat(),window_end=end.isoformat(),count=1,logs=[{'message':'x'}])
with gzip.open(run/fn,'wt') as f:json.dump(data,f)
hash=hashlib.sha256((run/fn).read_bytes()).hexdigest()
entry=dict(file=fn,sha256=hash,window_start=start.isoformat(),window_end=end.isoformat(),counts_match=True,returned_records=1,expected_total=1,unique_origins=1,query_snapshot_complete=True,reached_empty_page=True,method='pit_search_after')
manifest=dict(status='COMPLETE_EXACT_COUNTS',expected_windows=1,completed_windows=1,windows=[entry])
(run/'export_manifest.json').write_text(json.dumps(manifest))
'''
class ExportWindowsTests(unittest.TestCase):
    def test_resume_and_verified_copy(self):
        with tempfile.TemporaryDirectory() as td:
            root=Path(td);(root/'fake_exporter.py').write_text(TEST_EXPORTER)
            (root/'collector.py').write_text('pass')
            cmd=[sys.executable,str(SCRIPT),'--collector',str(root/'collector.py'),
                 '--export-script',str(root/'fake_exporter.py'),
                 '--from-date','2026-10-20T08:20:00+03:30','--to-date','2026-10-20T08:30:00+03:30',
                 '--out-dir',str(root/'new'),'--retries','0']
            x=subprocess.run(cmd,capture_output=True,text=True)
            self.assertEqual(x.returncode,0,x.stdout+x.stderr)
            self.assertEqual(len(list((root/'new'/'verified').glob('*.json.gz'))),2)
            self.assertEqual(json.loads((root/'new'/'verified_index.json').read_text())['status'],'COMPLETE')
            y=subprocess.run(cmd,capture_output=True,text=True)
            self.assertEqual(y.returncode,0,y.stdout+y.stderr)
            self.assertIn('already verified',y.stdout)
    def test_incomplete_proof_rejected(self):
        with tempfile.TemporaryDirectory() as td:
            root=Path(td);s=TEST_EXPORTER.replace("'COMPLETE_EXACT_COUNTS'","'PARTIAL_EXPORT_NOT_COMPLETE'")
            (root/'fake_exporter.py').write_text(s);(root/'collector.py').write_text('pass')
            x=subprocess.run([sys.executable,str(SCRIPT),'--collector',str(root/'collector.py'),
                '--export-script',str(root/'fake_exporter.py'), '--retries','0',
                '--from-date','2026-10-20T08:20:00+03:30','--to-date','2026-10-20T08:25:00+03:30',
                '--out-dir',str(root/'new')],capture_output=True,text=True)
            self.assertEqual(x.returncode,2,x.stdout+x.stderr)
            self.assertFalse(list((root/'new'/'verified').glob('*.json.gz')))
if __name__=='__main__':unittest.main()
