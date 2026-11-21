"""Bounded JSON/gzip files and direct ES pages. Raw records are never written."""
from __future__ import annotations
import ast
import base64
import gzip
import hashlib
import json
from pathlib import Path
import ssl
import time
from urllib.error import HTTPError
from urllib.parse import quote, urlsplit
from urllib.request import Request, urlopen
from .extract import instant, iso, LimitExceeded


class ElasticPageError(ValueError):
    def __init__(self,code,details):
        super().__init__(code);self.details=details


def response_summary(response):
    """Only protocol metadata; never document hits, PIT IDs or credentials."""
    if not isinstance(response,dict):return {'response_type':type(response).__name__}
    shards=response.get('_shards');hits=response.get('hits')
    def shape(value):return type(value).__name__
    summary={'fields':sorted(response),'timed_out':response.get('timed_out'),
        'timed_out_present':'timed_out' in response,'terminated_early':response.get('terminated_early'),
        'took':response.get('took'),'shards_type':shape(shards),'hits_type':shape(hits)}
    if isinstance(shards,dict):
        summary['shards']={k:shards.get(k) for k in ['total','successful','skipped','failed']}
        summary['shard_value_types']={k:shape(shards.get(k)) for k in ['total','successful','skipped','failed']}
        failures=shards.get('failures')
        if isinstance(failures,list):
            summary['shard_failures']=[{'status':v.get('status'),'reason_type':(v.get('reason') or {}).get('type')
                if isinstance(v.get('reason'),dict) else shape(v.get('reason'))} for v in failures[:8] if isinstance(v,dict)]
    if isinstance(hits,dict):
        summary['total_hits']=hits.get('total');summary['returned_hits']=len(hits['hits']) if isinstance(hits.get('hits'),list) else None
    if isinstance(response.get('error'),dict):summary['error_type']=response['error'].get('type')
    return summary


def settings(path):
    values={}
    def literal(n):
        if isinstance(n,ast.Name):return values[n.id]
        if isinstance(n,ast.Dict):return {literal(k):literal(v) for k,v in zip(n.keys,n.values)}
        if isinstance(n,ast.Call) and isinstance(n.func,ast.Name) and n.func.id=='dict' and not n.args:
            return {k.arg:literal(k.value) for k in n.keywords}
        return ast.literal_eval(n)
    for node in ast.parse(Path(path).read_text(encoding='utf-8-sig')).body:
        if isinstance(node,ast.Assign):
            for target in node.targets:
                if isinstance(target,ast.Name):
                    try:values[target.id]=literal(node.value)
                    except (KeyError,ValueError,TypeError):pass
    if not isinstance(values.get('DATABASE'),dict):raise ValueError('literal_DATABASE_required')
    return values


class WindowFile:
    """A streaming top-level object reader, including metadata after the array."""
    def __init__(self,path,*,max_value_chars=16_777_216):
        self.path=Path(path);self.metadata={};self.count=0;self.limit=max_value_chars
    def records(self):
        opener=gzip.open if self.path.suffix=='.gz' else open
        decoder=json.JSONDecoder();buffer='';eof=False
        with opener(self.path,'rt',encoding='utf-8-sig') as file:
            def fill():
                nonlocal buffer,eof
                block=file.read(65536);eof=not block;buffer+=block
            def ws():
                nonlocal buffer
                while True:
                    buffer=buffer.lstrip()
                    if buffer or eof:return
                    fill()
            def take(char):
                nonlocal buffer
                ws()
                if not buffer.startswith(char):raise ValueError('invalid_window_json')
                buffer=buffer[len(char):]
            def value():
                nonlocal buffer
                while True:
                    ws()
                    try:v,end=decoder.raw_decode(buffer)
                    except (ValueError,RecursionError):
                        if eof:raise ValueError('incomplete_window_json') from None
                        if len(buffer)>self.limit:raise LimitExceeded('source_record_size_limit')
                        fill();continue
                    if not eof and (end==len(buffer) or (isinstance(v,(int,float)) and buffer[end:end+1] not in ',]} \t\n\r:')):
                        fill();continue
                    if end>self.limit:raise LimitExceeded('source_record_size_limit')
                    buffer=buffer[end:];return v
            take('{');first=True;seen=set()
            while True:
                ws()
                if buffer.startswith('}'):take('}');break
                if not first:take(',')
                first=False;key=value();take(':')
                if not isinstance(key,str) or key in seen:raise ValueError('duplicate_window_property')
                seen.add(key)
                if key!='logs':self.metadata[key]=value();continue
                take('[');initial=True
                while True:
                    ws()
                    if buffer.startswith(']'):take(']');break
                    if not initial:take(',')
                    initial=False;record=value()
                    if not isinstance(record,dict):raise ValueError('source_record_not_object')
                    self.count+=1;yield record
            ws()
            if buffer:raise ValueError('trailing_window_json')
            if 'logs' not in seen or self.metadata.get('complete') is not True:raise ValueError('source_window_incomplete')
            if type(self.metadata.get('count')) is not int or self.metadata['count']!=self.count:
                raise ValueError('source_count_mismatch')
            begin=instant(self.metadata.get('window_start'));end=instant(self.metadata.get('window_end'))
            if end-begin!=300_000_000_000:raise ValueError('source_window_not_five_minutes')


class ElasticWindow:
    def __init__(self,config,start_ns,end_ns,*,page_size=5000,budget=180):
        self.config=config;self.start=start_ns;self.end=end_ns;self.page_size=page_size;self.budget=budget
        self.metadata={};self.count=0;self.network_seconds=0.;self.pages=0
        self.response_diagnostics=[]
        root=str(config.get('host','')).rstrip('/');parts=urlsplit(root)
        if parts.scheme not in ('http','https') or not parts.netloc or parts.username:raise ValueError('invalid_elastic_host')
        self.root=root;self.index=config.get('index_pattern')
        if not isinstance(self.index,str) or not self.index:raise ValueError('elastic_index_required')
        if not 1<=page_size<=10000:raise ValueError('invalid_page_size')
        self.context=ssl.create_default_context() if config.get('verify_certs',True) else ssl._create_unverified_context()
    @property
    def namespace(self):return hashlib.sha256(json.dumps([self.root,self.index],separators=(',',':')).encode()).hexdigest()
    def request(self,path,body=None,method='POST'):
        remaining=self.deadline-time.monotonic()
        if remaining<=0:raise TimeoutError('elastic_window_deadline')
        headers={'Content-Type':'application/json'};cfg=self.config
        if cfg.get('username') or cfg.get('password'):
            headers['Authorization']='Basic '+base64.b64encode((str(cfg.get('username',''))+':'+str(cfg.get('password',''))).encode()).decode()
        req=Request(self.root+path,None if body is None else json.dumps(body).encode(),headers,method=method)
        started=time.monotonic()
        try:
            with urlopen(req,timeout=min(remaining,60),context=self.context) as response:
                data=response.read(33_554_433)
                if len(data)>33_554_432:raise LimitExceeded('elastic_page_bytes_limit')
                return json.loads(data)
        finally:self.network_seconds+=time.monotonic()-started
    @staticmethod
    def checked(response,expected=None):
        details=response_summary(response)
        if not isinstance(response,dict):raise ElasticPageError('elastic_partial_page',dict(details,rejected_checks=['response_not_object']))
        shards=response.get('_shards',{})
        rejected=[]
        if response.get('timed_out') is not False:rejected.append('timed_out_not_explicit_false')
        if response.get('terminated_early') is True:rejected.append('terminated_early')
        if not isinstance(shards,dict):rejected.append('shards_not_object');shards={}
        if any(type(shards.get(k)) is not int or shards[k]<0 for k in ['total','successful']):rejected.append('invalid_shard_counts')
        if type(shards.get('failed')) is not int or shards['failed']!=0:rejected.append('failed_shards_not_zero_integer')
        if shards.get('successful')!=shards.get('total'):rejected.append('successful_shards_not_total')
        if rejected:raise ElasticPageError('elastic_partial_page',dict(details,rejected_checks=rejected))
        hits=response.get('hits',{})
        if not isinstance(hits,dict):raise ElasticPageError('elastic_hits_required',details)
        total=hits.get('total')
        if isinstance(total,dict) and total.get('relation')=='eq':total=total.get('value')
        if total is None:total=expected
        if type(total) is not int or total<0 or (expected is not None and total!=expected):raise ElasticPageError('elastic_inexact_count',dict(details,expected_total=expected))
        if not isinstance(hits.get('hits'),list):raise ElasticPageError('elastic_hits_required',details)
        return hits['hits'],total
    def records(self):
        self.deadline=time.monotonic()+self.budget;pit=sid=None;expected=None;last=None;use_pit=True
        index=quote(self.index,safe='*,_-:.')
        body=dict(size=self.page_size,track_total_hits=True,query={'range':{'@timestamp':{'gte':iso(self.start),'lt':iso(self.end)}}},
                  _source=['@timestamp','CallPath','RequestID','Session','message','ExecutionTime'])
        try:
            try:opened=self.request('/'+index+'/_pit?keep_alive=3m&allow_partial_search_results=false');pit=opened.get('id')
            except HTTPError as exc:
                if exc.code not in (400,404,405,501):raise
                exc.close();use_pit=False
            if use_pit and not isinstance(pit,str):raise ValueError('elastic_pit_id_required')
            while True:
                if use_pit:
                    query=dict(body,pit={'id':pit,'keep_alive':'3m'},sort=['_shard_doc'])
                    if last is not None:query.update(search_after=last,track_total_hits=False)
                    response=self.request('/_search?allow_partial_search_results=false',query)
                    pit=response.get('pit_id',pit)
                elif sid is None:response=self.request('/'+index+'/_search?scroll=3m',dict(body,sort=['_doc']))
                else:response=self.request('/_search/scroll',{'scroll':'3m','scroll_id':sid})
                if not use_pit:sid=response.get('_scroll_id',sid)
                self.response_diagnostics.append(dict(method='pit_search_after' if use_pit else 'scroll',
                    page=self.pages+1,summary=response_summary(response)))
                self.response_diagnostics=self.response_diagnostics[-4:]
                hits,total=self.checked(response,expected);expected=total;self.pages+=1
                if not hits:break
                for hit in hits:
                    if use_pit:
                        cursor=hit.get('sort')
                        if not isinstance(cursor,list) or len(cursor)!=1 or type(cursor[0]) is not int or (last is not None and cursor<=last):
                            raise ValueError('elastic_nonmonotonic_cursor')
                        last=cursor
                    if not isinstance(hit.get('_source'),dict):raise ValueError('elastic_source_missing')
                    self.count+=1
                    if self.count>expected:raise ValueError('elastic_count_exceeded')
                    yield hit
                if self.count==expected:break
                if not use_pit and not sid:raise ValueError('elastic_scroll_missing')
            if self.count!=expected:raise ValueError('elastic_incomplete_window')
            self.metadata=dict(window_start=iso(self.start),window_end=iso(self.end),complete=True,count=self.count,
                               method='pit_search_after' if use_pit else 'scroll',pages=self.pages)
        finally:
            # Close the most recently returned handle even when a page failed.
            previous=self.deadline;self.deadline=max(previous,time.monotonic()+5)
            try:
                if pit:self.request('/_pit',{'id':pit},method='DELETE')
                elif sid:self.request('/_search/scroll',{'scroll_id':[sid]},method='DELETE')
            except Exception:pass
