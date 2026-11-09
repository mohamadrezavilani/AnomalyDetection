"""PIT pagination fixes terminated scroll without admitting partial windows."""
from __future__ import annotations
import copy
import gzip
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
from urllib.error import HTTPError

from p24_foundation.viewer_elastic import ElasticREST,ElasticCapture
from p24_foundation.viewer_online import validate_capture,FIVE_NS
from tests.test_viewer_online import START,FakeElastic,es_page
from tests.test_viewer_r6_service_journey import log


def hit(n):
    return dict(_index='synthetic-index',_id=str(n),sort=[n],
        _source=log(n,'q'+str(n),'Services.v1/WaterBills Line:1','POST (G00000 | successful)'))


def pit_page(hits,total=3,pit='pit-new',**extra):
    page=es_page(hits,total=total);page.pop('_scroll_id');page['pit_id']=pit
    if total is None:page['hits'].pop('total')
    page.update(extra);return page


class PitTransport(FakeElastic):
    def __init__(self,pages,*,opening=None):
        super().__init__([]);self.pages=iter(pages);self.closed=[];self.pit_queries=[]
        self.opening=opening or {'id':'pit-first','_shards':{'total':1,'successful':1,'failed':0}}
    def open_pit(self,timeout):
        if isinstance(self.opening,BaseException):raise self.opening
        return self.opening
    def pit_search(self,body,timeout):
        self.pit_queries.append(copy.deepcopy(body))
        response=next(self.pages)
        if isinstance(response,BaseException):raise response
        return response
    def close_pit(self,pit_id):self.closed.append(pit_id)
    def search(self,*args):raise AssertionError('Scroll must not be used when PIT opens')


class ViewerPitCaptureTests(unittest.TestCase):
    def test_proven_pit_path_replaces_terminated_scroll_and_rotates_cursor(self):
        transport=PitTransport([pit_page([hit(1),hit(2)],pit='p2'),
            pit_page([hit(3)],total=None,pit='p3'),pit_page([],total=None,pit='p4')])
        with tempfile.TemporaryDirectory() as folder:
            path=ElasticCapture(transport,folder)(START,START+FIVE_NS)
            proof=validate_capture(path,START,START+FIVE_NS)
            self.assertEqual(proof['records'],3)
            self.assertEqual(proof['proof']['method'],'pit_search_after')
            self.assertEqual(transport.pit_queries[0]['sort'],['_shard_doc'])
            self.assertTrue(transport.pit_queries[0]['track_total_hits'])
            self.assertEqual(transport.pit_queries[0]['terminate_after'],0)
            self.assertEqual(transport.pit_queries[1]['search_after'],[2])
            self.assertFalse(transport.pit_queries[1]['track_total_hits'])
            self.assertEqual(transport.pit_queries[1]['pit']['id'],'p2')
            self.assertEqual(transport.closed,['p4'])

    def test_empty_pit_is_a_complete_zero_window(self):
        with tempfile.TemporaryDirectory() as folder:
            t=PitTransport([pit_page([],total=0)])
            p=ElasticCapture(t,folder)(START,START+FIVE_NS)
            self.assertEqual(validate_capture(p,START,START+FIVE_NS)['records'],0)

    def test_pit_partial_timeout_bad_count_and_lost_cursor_never_publish(self):
        cases=[
            [pit_page([hit(1)],terminated_early=True)],
            [pit_page([hit(1)],timed_out=True)],
            [pit_page([hit(1)],_shards={'total':2,'successful':1,'failed':1})],
            [pit_page([hit(1)],total=None)],
            [pit_page([hit(1)],total=2),pit_page([],total=None)],
            [pit_page([hit(1)]),pit_page([hit(2)],total=4)],
            [pit_page([hit(1)]),pit_page([hit(1)],total=None)],
            [pit_page([dict(hit(1),sort=None)])],
            [pit_page([dict(hit(1),sort=[True])])],
            [pit_page([hit(2),hit(1)])],
            [pit_page([hit(1)]),TimeoutError('expired PIT')],
        ]
        for i,pages in enumerate(cases):
            with self.subTest(case=i),tempfile.TemporaryDirectory() as folder:
                t=PitTransport(pages)
                with self.assertRaises(Exception):ElasticCapture(t,folder)(START,START+FIVE_NS)
                self.assertFalse(list(Path(folder).iterdir()))
                self.assertTrue(t.closed)

    def test_partial_pit_open_and_forbidden_open_do_not_fall_back(self):
        cases=[{'id':'pit-bad','_shards':{'total':2,'successful':1,'failed':1}},
               HTTPError('http://private',403,'private',{},io.BytesIO(b'{}'))]
        for opening in cases:
            with tempfile.TemporaryDirectory() as folder:
                t=PitTransport([],opening=opening)
                with self.assertRaises(Exception):ElasticCapture(t,folder)(START,START+FIVE_NS)
                self.assertFalse(list(Path(folder).iterdir()))
                self.assertFalse(t.pit_queries)

    def test_unsupported_pit_only_falls_back_to_strict_complete_scroll(self):
        class Legacy(FakeElastic):
            def open_pit(self,timeout):raise HTTPError('http://private',404,'not supported',{},io.BytesIO(b'{}'))
            def pit_search(self,*args):raise AssertionError('PIT unavailable')
            def close_pit(self,*args):raise AssertionError('No PIT opened')
        with tempfile.TemporaryDirectory() as folder:
            t=Legacy([es_page([hit(1)],total=1),es_page([],total=1)])
            p=ElasticCapture(t,folder)(START,START+FIVE_NS)
            proof=validate_capture(p,START,START+FIVE_NS)['proof']
            self.assertEqual(proof['method'],'single_scroll')
            self.assertEqual(proof['adapter_fallback'],'pit_open_http_404')
        with tempfile.TemporaryDirectory() as folder:
            t=Legacy([es_page([],terminated_early=True)])
            with self.assertRaises(ValueError):ElasticCapture(t,folder)(START,START+FIVE_NS)
            self.assertFalse(list(Path(folder).iterdir()))

    def test_rest_opens_bodyless_pit_and_searches_without_scroll(self):
        transport=ElasticREST({'host':'http://example.invalid:9200','index_pattern':'logs-*'})
        response=io.BytesIO(b'{"id":"pit-1"}')
        with patch('p24_foundation.viewer_elastic.urlopen',return_value=response) as request:
            transport.open_pit(5)
            req=request.call_args.args[0]
            self.assertIsNone(req.data)
            self.assertEqual(req.method,'POST')
            self.assertIn('/logs-*/_pit?keep_alive=10m',req.full_url)
        with patch.object(transport,'request',return_value={}) as request:
            transport.pit_search({'pit':{'id':'p'}},5)
            self.assertEqual(request.call_args.args[0],'/_search?allow_partial_search_results=false')

    def test_real_rest_to_atomic_publisher_bypasses_reproduced_terminated_scroll(self):
        from http.server import ThreadingHTTPServer,BaseHTTPRequestHandler
        import threading
        from p24_foundation.viewer_data import ViewerDB
        from p24_foundation.privacy import generate_keys
        from p24_foundation.viewer_online import LiveWorker,initialize_live,bind_stream
        from p24_foundation.viewer_elastic import checked_page
        paths=[];sources=[hit(1),hit(2),hit(3)]
        class Handler(BaseHTTPRequestHandler):
            def log_message(self,*args):pass
            def respond(self,payload):
                data=json.dumps(payload).encode();self.send_response(200)
                self.send_header('Content-Type','application/json');self.send_header('Content-Length',str(len(data)));self.end_headers();self.wfile.write(data)
            def do_POST(self):
                paths.append(self.path)
                raw=self.rfile.read(int(self.headers.get('Content-Length',0)))
                body=json.loads(raw) if raw else {}
                if '/_pit?' in self.path:
                    self.respond({'id':'pit-http','_shards':{'total':1,'successful':1,'failed':0}})
                elif 'scroll=' in self.path:
                    self.respond(es_page([],terminated_early=True))
                else:
                    after=body.get('search_after',[-1])[0]
                    rows=[r for r in sources if r['sort'][0]>after][:2]
                    self.respond(pit_page(rows,total=3 if body['track_total_hits'] else None,pit='pit-http'))
            def do_DELETE(self):
                self.rfile.read(int(self.headers.get('Content-Length',0)));self.respond({'succeeded':True})
        server=ThreadingHTTPServer(('127.0.0.1',0),Handler)
        thread=threading.Thread(target=server.serve_forever,daemon=True);thread.start()
        try:
            transport=ElasticREST({'host':'http://127.0.0.1:'+str(server.server_port),'index_pattern':'logs-*'})
            with self.assertRaisesRegex(ValueError,'incomplete_search_page'):
                checked_page(transport.search({},5))
            with tempfile.TemporaryDirectory() as folder:
                root=Path(folder);generate_keys(root/'keys')
                with ViewerDB(sqlite_path=root/'viewer',keys_path=root/'keys') as db:
                    db.init();initialize_live(db);bind_stream(db,start_ns=START,stream_key='synthetic_http_pit')
                    worker=LiveWorker(db,ElasticCapture(transport,root/'captures'))
                    result=worker.step(now=START+FIVE_NS+60_000_000_000)
                    self.assertEqual(result['status'],'PUBLISHED');self.assertEqual(result['records'],3)
                    self.assertEqual(db.one('SELECT next_ns FROM viewer_live_state')['next_ns'],START+FIVE_NS)
                    worker.step(now=START+FIVE_NS+60_000_000_000)
                    self.assertEqual(db.one('SELECT COUNT(*) AS n FROM viewer_events')['n'],3)
                    self.assertTrue(all('/_search?' not in p or 'allow_partial_search_results=false' in p or 'scroll=' in p for p in paths))
        finally:server.shutdown();server.server_close();thread.join(timeout=2)

if __name__=='__main__':unittest.main()
