"""Four complete post-release ES windows with replayable, pseudonymous identity fields."""
import gzip
import hashlib
import hmac
import json
import os
from pathlib import Path
import re
from collections import Counter,defaultdict
from datetime import datetime, timezone
from uuid import uuid4
from zipfile import ZipFile, ZIP_STORED

from account_behavior.identity import Evidence,normalize,observed
from compact_behavior import FIVE
from compact_behavior.extract import field,identity,instant,iso,LINE
from compact_behavior.source import ElasticWindow, settings, retryable_source_failure


class AccountWindow(ElasticWindow):
    """Override only the source projection; retain the verified PIT/scroll traversal."""
    def request(self,path,body=None,method='POST'):
        if body is not None and '_source' in body:
            body=dict(body,_source=['@timestamp','CallPath','RequestID','UserID','Session'])
        return super().request(path,body,method)


class Aliases:
    def __init__(self):
        self.key=os.urandom(32)
        self.users={}

    def request(self,value):
        return hmac.new(self.key,value.encode(),hashlib.sha256).hexdigest()

    def user(self,value):
        if isinstance(value,list):
            return [self.user(v) for v in value[:2]]
        uid,reason=normalize(value)
        if uid is None:
            if reason=='NULL':return None
            if reason=='ZERO_UNATTRIBUTED':return '0' if isinstance(value,str) else 0
            if reason=='EMPTY':return ''
            if reason=='MASKED':return '****'
            return 'INVALID'
        number=self.users.setdefault(uid,len(self.users)+1)
        return str(number) if isinstance(value,str) else number


def projected(hit, aliases):
    """No payload, literal request/user IDs, URL, token, IP or UA is shared."""
    source=hit['_source']
    row={'@timestamp':source['@timestamp']}
    request,_=field(hit,'RequestID')
    request=identity(request)
    if request and set(request)!={'*'}:
        row['RequestID']=aliases.request(request)
    path,_=field(hit,'CallPath')
    if isinstance(path,str):
        path=LINE.sub('',path).strip()
        if re.fullmatch(r'[A-Za-z][A-Za-z0-9_./+:-]{0,250}',path):
            row['CallPath']=path
    if 'UserID' in source:row['UserID']=aliases.user(source['UserID'])
    projected_hit={'_source':row}
    fields=hit.get('fields')
    if isinstance(fields,dict) and 'UserID' in fields:
        projected_hit['fields']={'UserID':aliases.user(fields['UserID'])}
    return projected_hit


def shape(value):
    if isinstance(value,list):return 'array:'+(','.join(sorted({type(x).__name__ for x in value})) or 'empty')
    return type(value).__name__


def write_window(source,path,aliases,start):
    states={};data=Counter();types=Counter();session_shapes=Counter();services=defaultdict(Counter)
    large_ids=0
    with gzip.open(path,'wt',encoding='utf-8',newline='') as f:
        f.write('{"logs":[')
        for n,hit in enumerate(source.records()):
            src=hit['_source']; uid,reason=observed(hit); data[reason]+=1
            large_ids+=int(uid is not None and uid>2**53-1)
            types[shape(src['UserID']) if 'UserID' in src else 'absent']+=1
            session=src.get('Session')
            session_shapes['absent' if 'Session' not in src else 'masked' if isinstance(session,str) and session and set(session)=={'*'} else 'present']+=1
            safe=projected(hit,aliases)
            if observed(safe)[1] != reason:
                raise ValueError('pseudonymous_projection_changed_identity_quality')
            safe_row=safe['_source']
            rid=safe_row.get('RequestID')
            at=instant(safe_row['@timestamp'])
            if not start<=at<start+FIVE:raise ValueError('record_outside_source_window')
            if rid:
                states[rid]=states.get(rid,Evidence()).merge(Evidence.from_row(safe,at))
            path_name=safe_row.get('CallPath','')
            if re.fullmatch(r'(?:Services|Core)\.v\d+/\w+',path_name):services[path_name][reason]+=1
            if n:f.write(',')
            f.write(json.dumps(safe,ensure_ascii=True,separators=(',',':')))
        m=source.metadata
        if m.get('complete') is not True or sum(data.values())!=m.get('count') or m['count']!=m.get('expected_count'):
            raise ValueError('unverified_source_window')
        f.write('],"complete":true,"count":'+str(m['count'])+',"expected_count":'+str(m['count'])+',"window_start":'+json.dumps(iso(start))+',"window_end":'+json.dumps(iso(start+FIVE))+'}')
    return states,dict(start=iso(start),end=iso(start+FIVE),records=m['count'],request_ids=len(states),
        identity_by_log_line=dict(data),identity_by_request=dict(Counter(s.resolve()[1] for s in states.values())),
        user_id_source_types=dict(types),verified_ids_above_js_safe_integer_lines=large_ids,
        session_presence=dict(session_shapes),service_log_lines=dict(services),
        source_completeness=m.get('completeness_basis'),source_method=m['method'])


def capture(project,output,start,windows=4):
    first=instant(start)
    if first%FIVE or not 1<=windows<=12:
        raise ValueError('aligned_five_minute_windows_required')
    if first+windows*FIVE>int(datetime.now(timezone.utc).timestamp())*10**9:
        raise ValueError('sample_range_ends_in_future')
    config=settings(Path(project)/'viewer_config.local.py')['ELASTICSEARCH']
    path=Path(output)/('Core_UserID_Samples_'+uuid4().hex[:12])
    path.mkdir(parents=True,exist_ok=False)
    local=path/'sources';local.mkdir()
    aliases=Aliases();all_states={};window_counts=Counter()
    coverage=dict(contract='p24-core-userid-1',purpose='IDENTITY_ONLY_PSEUDONYMOUS_PROJECTION',windows=[])
    for i in range(windows):
        begin=first+i*FIVE
        filename=local/f'window_{i+1:02}.json.gz'
        for attempt in range(3):
            try:
                src=AccountWindow(config,begin,begin+FIVE,page_size=max(64,500//(4**attempt)),budget=180)
                states,report=write_window(src,filename,aliases,begin)
                break
            except Exception as exc:
                if attempt==2 or not retryable_source_failure(exc):raise
        coverage['windows'].append(report)
        for rid,state in states.items():
            all_states[rid]=all_states.get(rid,Evidence()).merge(state)
            window_counts[rid]+=1
        print(json.dumps(dict(status='SAMPLED_COMPLETE_WINDOW',ordinal=i+1,records=report['records'])),flush=True)
    coverage.update(request_ids=len(all_states),cross_window_requests=sum(n>1 for n in window_counts.values()),
        merged_identity=dict(Counter(s.resolve()[1] for s in all_states.values())),
        distinct_verified_accounts=len({uid for s in all_states.values() for uid,status in [s.resolve()] if status=='VERIFIED'}))
    coverage['identity_check']='VERIFIED_IDS_OBSERVED' if coverage['distinct_verified_accounts'] else 'NO_VERIFIED_IDS_IN_SAMPLE'
    (local/'coverage.json').write_text(json.dumps(coverage,ensure_ascii=False,indent=2),encoding='utf-8')
    partial=path.with_suffix('.zip.partial')
    with ZipFile(partial,'x',ZIP_STORED) as z:
        for item in sorted(local.iterdir()):z.write(item,item.name)
    with ZipFile(partial) as z:
        if z.testzip():raise ValueError('sample_zip_crc_mismatch')
    final=path.with_suffix('.zip');partial.rename(final)
    return dict(status='IDENTITY_SAMPLE_COMPLETE',send_this_file=str(final),windows=windows,
                requests=coverage['request_ids'],accounts=coverage['distinct_verified_accounts'],
                identity_check=coverage['identity_check'],database_modified=False)
