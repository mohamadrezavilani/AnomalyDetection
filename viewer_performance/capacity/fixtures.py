"""Deterministic, non-customer corpus with explicit cross-window risk cases."""
from __future__ import annotations

from datetime import datetime, timezone
import gzip
import hashlib
import json

START=1792701000000000000  # 1 Aban 1405, Tehran midnight.
FIVE=300_000_000_000


def iso(ns):
    return datetime.fromtimestamp(ns/1e9,timezone.utc).isoformat()


def row(number,request,call,message,start,*,session='a'*32):
    return dict(_source_id='capacity-fixture:'+str(number),
        **{'@timestamp':iso(start+1_000_000_000)},RequestID=request,Session=session,
        IP='192.0.2.40',CallPath=call,message=message,level='Info')


def sql(payment):
    return '(Command Text: ud_prc_paymentExists)(Code: 1)(Result: Ok)(SQL Parameters: @paymentKey='+payment+')'


def write(path,rows,start):
    proof=dict(expected_total=len(rows),total_relation='eq',returned_records=len(rows),
        unique_origins=len({r['_source_id'] for r in rows}),counts_match=True,
        query_snapshot_complete=True,reached_empty_page=True)
    data=dict(window_start=iso(start),window_end=iso(start+FIVE),count=len(rows),
        complete=True,logs=rows,verification=proof)
    with path.open('wb') as raw:
        with gzip.GzipFile(filename='',fileobj=raw,mode='wb',mtime=0) as stream:
            stream.write(json.dumps(data,sort_keys=True,separators=(',',':')).encode())
    return path


def corpus(root,counts=(16,64,256)):
    jobs=[];first=None
    for window,count in enumerate(counts):
        start=START+window*FIVE;rows=[]
        for n in range(count):
            base=window*1_000_000+n*3
            rid=f'w{window}-r{n}'
            rows.extend((row(base,rid,'Services.v1/WaterBills Line:1','POST (G00000 | successful)',start),
                row(base+1,rid,'DBPath.x.ud_prc_paymentExists',sql('p'+rid),start),
                row(base+2,rid,'ClientFixture.Request Line:1','Output:[]',start)))
        if window==0:
            rows.extend((row(9_000_000,'late','ClientAyanCoTopUp.ProductReserve Line:1','Output:[]',start),
                row(9_000_001,'pay','Core.v1/WalletPayment Line:1','POST (G00000 | successful)',start),
                row(9_000_002,'pay','DBPath.x.ud_prc_paymentExists',sql('shared-payment'),start)))
            first=rows
        elif window==1:
            rows.extend((row(9_000_003,'late','Services.v1/TopUpProductPurchase Line:1','POST (G00000 | successful)',start),
                row(9_000_004,'callback','DBPath.x.ud_prc_paymentExists',sql('shared-payment'),start)))
        else:
            rows.append(row(9_000_005,'pay','ClientFixture.Final Line:1','Output:[]',start))
        path=write(root/f'window-{window}.gz',rows,start)
        jobs.append(dict(path=path,start=start,mode='forward',kind=('light','normal','heavy')[window],
            records=len(rows),sha256=hashlib.sha256(path.read_bytes()).hexdigest()))
    # A rival version in another RequestID must retract an already published
    # request. The changed event stays in its original event-time window.
    changed=[dict(r) for r in first]
    changed[0].update(RequestID='rival-owner',message='POST (GD2016 | fail)')
    path=write(root/'conflict.gz',changed,START)
    jobs.append(dict(path=path,start=START,mode='recheck',kind='cross_request_conflict',
        records=len(changed),sha256=hashlib.sha256(path.read_bytes()).hexdigest()))
    return jobs
