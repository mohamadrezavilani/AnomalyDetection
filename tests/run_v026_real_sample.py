"""Read-only 20-Oct source smoke; synthetic trimmed gzip and disposable SQLite."""
from __future__ import annotations
import gzip,json,sys,tempfile
from pathlib import Path
from collections import Counter
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))
from p24_foundation.viewer_data import ViewerDB
from p24_foundation.privacy import generate_keys

def main():
    raw=Path(sys.argv[1] if len(sys.argv)>1 else '/mnt/data/logs_20261020_082000.json.gz')
    with gzip.open(raw,'rt') as f:data=json.load(f)
    selected={r.get('RequestID') for r in data['logs'] if any(
       word in str(r.get('CallPath','')) for word in ('/WalletPayment','/BillsPayment','/InvoicePayment','/UserBasketPayment','/EwanoPayment','/CnpgPayment','/UserWalletCharge'))}
    selected=set(list(sorted(selected))[:130])
    sample=[r for r in data['logs'] if r.get('RequestID') in selected]
    with tempfile.TemporaryDirectory() as tmp:
        folder=Path(tmp);keys=folder/'k.json';generate_keys(keys)
        target=folder/'source.json.gz'
        with gzip.open(target,'wt') as f:json.dump(dict(window_start=data['window_start'],window_end=data['window_end'],count=len(sample),logs=sample),f)
        with ViewerDB(sqlite_path=folder/'viewer.db',keys_path=keys) as db:
            db.init();status=db.ingest([target]);base=db.rebuild();contract=db.rebuild_payment_contract()
            by_axis={r['axis']:r['n'] for r in db.all('SELECT axis,COUNT(*) n FROM viewer_contract_observations GROUP BY axis')}
            by_relation={r['relation_type']:r['n'] for r in db.all('SELECT relation_type,COUNT(*) n FROM viewer_contract_edges GROUP BY relation_type')}
            assert status[0]['status']=='IMPORTED',status
            assert contract['scanned_events']>0
            assert base['requests']>0
            print(json.dumps(dict(sample_rows=len(sample),source_full_rows=len(data['logs']),request_groups=base['requests'],contract=contract,axes=by_axis,relations=by_relation,coverage=db.raw_coverage()),ensure_ascii=False,indent=2))
if __name__=='__main__':main()
