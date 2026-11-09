"""Embedded REST capture for Viewer, preferring PIT/search_after snapshots.

Uses the proven evidence exporter's PIT path; legacy-only servers may use
strict scroll capture. No legacy config imports, cursor or detector calls.
Pages stream to a private immutable gzip capture; no 100k/64-MiB truncate cap.
"""
from __future__ import annotations

import base64
import gzip
import hashlib
import json
import os
from pathlib import Path
import ssl
import tempfile
import time
from urllib.parse import quote, urlsplit
from urllib.error import HTTPError
from urllib.request import Request,urlopen

from .viewer_online import iso,checked_window,hash_file


class ElasticREST:
    def __init__(self,settings):
        self.root=str(settings.get('host','')).rstrip('/')
        parts=urlsplit(self.root)
        if parts.scheme not in ('http','https') or not parts.netloc or parts.username or parts.password:
            raise ValueError('set_private_elasticsearch_host')
        self.index=settings.get('index_pattern','')
        if not isinstance(self.index,str) or not self.index or len(self.index)>500:
            raise ValueError('set_private_elasticsearch_index')
        self.username=settings.get('username') or '';self.password=settings.get('password') or ''
        self.context=ssl.create_default_context() if settings.get('verify_certs',True) else ssl._create_unverified_context()
        self.timeout=settings.get('request_timeout_seconds',60)
        if not 1<=self.timeout<=300:raise ValueError('invalid_es_request_timeout')

    def request(self,path,body=None,*,method='POST',timeout=None):
        headers={'Content-Type':'application/json'}
        if self.username or self.password:
            headers['Authorization']='Basic '+base64.b64encode((self.username+':'+self.password).encode()).decode()
        # PIT opening requires a bodyless POST on supported older clusters.
        data=None if body is None else json.dumps(body).encode()
        req=Request(self.root+path,data,headers,method=method)
        with urlopen(req,timeout=min(timeout or self.timeout,self.timeout),context=self.context) as response:
            return json.load(response)

    def search(self,body,timeout):
        return self.request('/'+quote(self.index,safe='*,_-:.')+'/_search?scroll=10m',body,timeout=timeout)

    def scroll(self,sid,timeout):
        return self.request('/_search/scroll',{'scroll_id':sid,'scroll':'10m'},timeout=timeout)

    def clear(self,sid):
        return self.request('/_search/scroll',{'scroll_id':[sid]},method='DELETE',timeout=10)

    def open_pit(self,timeout):
        return self.request('/'+quote(self.index,safe='*,_-:.')+'/_pit?keep_alive=10m',timeout=timeout)

    def pit_search(self,body,timeout):
        return self.request('/_search?allow_partial_search_results=false',body,timeout=timeout)

    def close_pit(self,pit_id):
        return self.request('/_pit',{'id':pit_id},method='DELETE',timeout=10)


def stream_key(settings):
    # Do not bind to passwords (rotation is safe), nor expose host/index in UI.
    return hashlib.sha256(json.dumps([str(settings.get('host','')).rstrip('/'),
        settings.get('index_pattern'), '@timestamp','five_minute_all_levels'],ensure_ascii=True).encode()).hexdigest()


def checked_shards(shards):
    if (not isinstance(shards,dict) or
        any(type(shards.get(k)) is not int or shards[k]<0 for k in ('total','successful','failed')) or
        shards['failed']!=0 or shards['successful']!=shards['total']):
        raise ValueError('incomplete_search_page')


def checked_page(response,*,expected_total=None):
    if not isinstance(response,dict):raise ValueError('invalid_search_page')
    if response.get('timed_out') is not False or response.get('terminated_early') is True:
        raise ValueError('incomplete_search_page')
    checked_shards(response.get('_shards'))
    hits=response.get('hits')
    if not isinstance(hits,dict) or not isinstance(hits.get('hits'),list):raise ValueError('invalid_search_hits')
    total=hits.get('total')
    # Subsequent PIT pages omit total when track_total_hits=False. Their count
    # is pinned by the FIRST exact count in that same PIT, never by live _count.
    if total is None and type(expected_total) is int:exact=expected_total
    elif type(total) is int:exact=total
    elif isinstance(total,dict) and total.get('relation')=='eq' and type(total.get('value')) is int:
        exact=total['value']
    else:raise ValueError('inexact_search_total')
    if exact<0:raise ValueError('invalid_search_total')
    return hits['hits'],exact


class ElasticCapture:
    def __init__(self,transport,out_dir,*,page_size=5000,max_seconds=240):
        if type(page_size) is not int or not 1<=page_size<=10000:raise ValueError('invalid_es_page_size')
        if not 10<=max_seconds<=86400:raise ValueError('invalid_capture_budget')
        self.transport=transport;self.out=Path(out_dir);self.page_size=page_size;self.max_seconds=max_seconds

    def __call__(self,start,end,*,cancel_event=None):
        from .viewer_data import utc_ns
        checked_window(start,end);self.out.mkdir(parents=True,exist_ok=True)
        begin=time.monotonic();deadline=begin+self.max_seconds
        def remaining():
            if cancel_event is not None and cancel_event.is_set():raise TimeoutError('capture_cancelled')
            left=deadline-time.monotonic()
            if left<=0:raise TimeoutError('capture_budget_expired')
            return max(0.1,left)
        query={'query':{'bool':{'filter':[{'range':{'@timestamp':{'gte':iso(start),'lt':iso(end)}}}]}},
               'sort':['_doc'],'size':self.page_size,'track_total_hits':True,'_source':True,
               'terminate_after':0}
        temp=None
        sid=pit_id=None;seen=set();pages=[];count=0;expected=None;last_sort=None
        use_pit=all(callable(getattr(self.transport,name,None)) for name in ('open_pit','pit_search','close_pit'))
        fallback=None
        try:
            if use_pit:
                try:opened=self.transport.open_pit(remaining())
                except HTTPError as exc:
                    # Only an unsupported PIT opening may use legacy scroll.
                    # Authorization, failed pages and lost PITs never fall back.
                    if exc.code not in (400,404,405,501):raise
                    use_pit=False;fallback='pit_open_http_'+str(exc.code)
                    exc.close()
                else:
                    pit_id=opened.get('id') if isinstance(opened,dict) else None
                    if not isinstance(pit_id,str) or not pit_id:raise ValueError('pit_id_missing')
                    if '_shards' in opened:checked_shards(opened['_shards'])
                    query['sort']=['_shard_doc']
            def get_pit_page():
                body=dict(query,pit={'id':pit_id,'keep_alive':'10m'})
                if last_sort is not None:
                    body['search_after']=[last_sort];body['track_total_hits']=False
                return self.transport.pit_search(body,remaining())
            fd,temp=tempfile.mkstemp(prefix='capture_',suffix='.partial',dir=self.out)
            with os.fdopen(fd,'wb') as output:
                # mtime=0 makes equivalent traversals reproducible except order.
                with gzip.GzipFile(fileobj=output,mode='wb',mtime=0,filename='') as gz:
                    head=dict(window_start=iso(start),window_end=iso(end),complete=True)
                    gz.write((json.dumps(head,separators=(',',':'))[:-1]+',"logs":[').encode())
                    response=get_pit_page() if use_pit else self.transport.search(query,remaining())
                    while True:
                        # Always retain the newest cursor, including a failed page.
                        if use_pit:
                            new_pit=response.get('pit_id') if isinstance(response,dict) else None
                            if new_pit is not None:
                                if not isinstance(new_pit,str) or not new_pit:raise ValueError('pit_id_invalid')
                                pit_id=new_pit
                        else:sid=response.get('_scroll_id',sid) if isinstance(response,dict) else sid
                        hits,total=checked_page(response,expected_total=expected if use_pit else None)
                        if expected is None:expected=total
                        if total!=expected:raise ValueError('search_total_changed')
                        for hit in hits:
                            if not isinstance(hit,dict):raise ValueError('invalid_search_hit')
                            if use_pit:
                                sort=hit.get('sort')
                                if (not isinstance(sort,list) or len(sort)!=1 or type(sort[0]) is not int
                                    or (last_sort is not None and sort[0]<=last_sort)):
                                    raise ValueError('pit_sort_cursor_invalid')
                                last_sort=sort[0]
                            index=hit.get('_index');docid=hit.get('_id');source=hit.get('_source')
                            if not isinstance(index,str) or not index or not isinstance(docid,str) or not docid or not isinstance(source,dict):
                                raise ValueError('missing_stable_search_identity')
                            identity=(index,docid)
                            if identity in seen:raise ValueError('duplicate_search_origin')
                            seen.add(identity)
                            at=utc_ns(source.get('@timestamp'))
                            if at is None or not start<=at<end:raise ValueError('search_event_outside_window')
                            row=dict(source)
                            if '_source_id' in source:
                                key='_original_source'
                                while key in row:key='_'+key
                                row[key]=dict(source)
                            row['_source_id']=index+':'+docid
                            if count:gz.write(b',')
                            gz.write(json.dumps(row,ensure_ascii=False,separators=(',',':'),allow_nan=False).encode())
                            count+=1
                            if count>expected:raise ValueError('search_count_exceeded')
                        pages.append(dict(ordinal=len(pages)+1,returned=len(hits),cumulative=count,exact_total=total))
                        if not hits:break
                        if use_pit:response=get_pit_page()
                        else:
                            if not isinstance(sid,str) or not sid:raise ValueError('search_cursor_missing')
                            response=self.transport.scroll(sid,remaining())
                    if count!=expected:raise ValueError('search_count_mismatch')
                    remaining()
                    proof=dict(expected_total=expected,total_relation='eq',returned_records=count,
                        unique_origins=len(seen),counts_match=True,query_snapshot_complete=True,
                        reached_empty_page=True,method='pit_search_after' if use_pit else 'single_scroll',
                        snapshot_consistency='single_pit_view' if use_pit else 'single_scroll_view',
                        source_finality='not_established',query=query,pages=pages)
                    if fallback:proof['adapter_fallback']=fallback
                    tail=json.dumps(dict(count=count,verification=proof),ensure_ascii=False,separators=(',',':'))
                    gz.write(('],'+tail[1:]).encode())
                output.flush();os.fsync(output.fileno())
            digest=hash_file(temp)
            path=self.out/('logs_'+iso(start)[:19].replace('-','').replace(':','').replace('T','_')+'_'+digest+'.json.gz')
            if path.exists():
                if hash_file(path)!=digest:raise ValueError('existing_capture_hash_mismatch')
                os.unlink(temp)
            else:os.replace(temp,path)
            return path
        finally:
            if pit_id:
                try:self.transport.close_pit(pit_id)
                except Exception:pass
            if sid:
                try:self.transport.clear(sid)
                except Exception:pass
            if temp and os.path.exists(temp):os.unlink(temp)
