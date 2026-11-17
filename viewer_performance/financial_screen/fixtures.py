"""Same new input at different retained-history sizes; no customer evidence."""
import gzip
import hashlib
import json

from viewer_performance.capacity.fixtures import corpus as original,write,row,sql,START,FIVE


def corpus(root,counts=(16,64,256)):
    jobs=original(root,counts)
    # Distinct asserted actors share a typed payment across publication borders.
    # Include the original copy on both rechecks so the proof remains complete.
    for ordinal,job in enumerate(jobs):
        with gzip.open(job['path'],'rt',encoding='utf-8') as stream:rows=json.load(stream)['logs']
        if ordinal in (0,3,4):
            rows.extend((row(90_000_010,'financial-actor-a','Core.v1/WalletPayment Line:1',
                'POST (G00000 | successful)',job['start'],session='b'*32),
                row(90_000_011,'financial-actor-a','DBPath.x.ud_prc_paymentExists',
                sql('screen-shared-payment'),job['start'],session='b'*32)))
        if ordinal==1:
            rows.extend((row(90_000_012,'financial-actor-b','Core.v1/WalletPayment Line:1',
                'POST (G00000 | successful)',job['start'],session='c'*32),
                row(90_000_013,'financial-actor-b','DBPath.x.ud_prc_paymentExists',
                sql('screen-shared-payment'),job['start'],session='c'*32)))
        write(job['path'],rows,job['start']);job.update(records=len(rows),sha256=hashlib.sha256(job['path'].read_bytes()).hexdigest())
    return jobs


def seed(root,start,requests):
    if not requests:return []
    rows=[]
    for n in range(requests):
        rid='screen-retained-'+str(n)
        rows.extend((row(100_000_000+n*2,rid,'Services.v1/WaterBills Line:1',
            'POST (G00000 | successful)',start-FIVE),
            row(100_000_001+n*2,rid,'DBPath.x.ud_prc_paymentExists',
                sql('screen-shared-payment' if n%16==0 else 'screen-old-'+str(n)),start-FIVE)))
    path=write(root/'retained-history.gz',rows,start-FIVE)
    return [dict(path=path,start=start-FIVE,mode='forward',kind='retained_history_setup',
        records=len(rows),sha256=hashlib.sha256(path.read_bytes()).hexdigest())]
