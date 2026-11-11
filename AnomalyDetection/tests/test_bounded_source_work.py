"""Disk admission and bounded request-content reads preserve pending work."""
from contextlib import contextmanager
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch
import json
import sys
import unittest
import zlib

sys.path.append(str(Path(__file__).resolve().parents[2]))
from anomaly_detection.viewer_priority import ViewerPriority
from anomaly_detection.request_profiles import read


class PriorityTests(unittest.TestCase):
    def test_busy_writer_defers_background_but_fairness_and_resume_are_finite(self):
        now=[0.];busy=[True];calls=[]
        source=SimpleNamespace(viewer_writer_busy=lambda:calls.append(1) or busy[0])
        clock=SimpleNamespace(monotonic=lambda:now[0]);policy=ViewerPriority()
        self.assertFalse(policy.admit(source,clock)['admitted'])
        now[0]=.5;self.assertFalse(policy.admit(source,clock)['admitted']);self.assertEqual(len(calls),1)
        now[0]=30.;self.assertEqual(policy.admit(source,clock)['mode'],'BOUNDED_FAIRNESS_CYCLE')
        now[0]=30.5;self.assertFalse(policy.admit(source,clock)['admitted'])
        busy[0]=False;now[0]=31.1
        self.assertEqual(policy.admit(source,clock)['mode'],'VIEWER_IDLE')
        busy[0]=True;now[0]=32.2
        self.assertFalse(policy.admit(source,clock)['admitted'])

    def test_unavailable_probe_does_not_claim_idle(self):
        def denied():raise PermissionError()
        policy=ViewerPriority()
        with self.assertRaises(PermissionError):policy.admit(SimpleNamespace(viewer_writer_busy=denied),SimpleNamespace(monotonic=lambda:0))
        self.assertFalse(policy.observed)
        self.assertEqual(policy.admit(SimpleNamespace(viewer_writer_busy=denied),SimpleNamespace(monotonic=lambda:1))['mode'],'PROBE_UNAVAILABLE')

    def test_slow_background_cycle_still_yields_after_completion(self):
        now=[0.];clock=SimpleNamespace(monotonic=lambda:now[0])
        source=SimpleNamespace(viewer_writer_busy=lambda:True);policy=ViewerPriority()
        self.assertFalse(policy.admit(source,clock)['admitted'])
        now[0]=30.;self.assertTrue(policy.admit(source,clock)['admitted'])
        now[0]=75.;self.assertFalse(policy.admit(source,clock)['admitted'])
        now[0]=104.;self.assertFalse(policy.admit(source,clock)['admitted'])
        now[0]=105.;self.assertTrue(policy.admit(source,clock)['admitted'])

    def test_test_sources_without_priority_probe_keep_existing_behavior(self):
        self.assertEqual(ViewerPriority().admit(object(),SimpleNamespace(monotonic=lambda:0)),
                         {'admitted':True,'mode':'NO_VIEWER_PROBE'})


class ContentBatchTests(unittest.TestCase):
    def source(self,count=4,conflicted=False):
        root='Services.v1/Fixture';key='a'*64;actor='b'*64;queries=[]
        request={'request_key':key,'session_key':actor,'root_call':root,'root_ns':10,'started_ns':10,
                 'ended_ns':20,'identity_state':'assigned','conflicted':False,'root_count':1,'root_code':'G00000'}
        events=[{'origin_key':f'{n:064x}','version_key':f'{n+100:064x}','request_key':key,'session_key':actor,
                 'ip_key':'c'*64,'at_ns':10+n,'callpath':root if n==0 else 'ClientFixture.Call',
                 'kind':'client' if n==0 else 'provider','variant_count':2 if conflicted and n==0 else 1,
                 'raw_available':True} for n in range(count)]
        def q(statement,parameters=(),*,cap):
            queries.append((statement,list(parameters),cap))
            if statement.startswith('SELECT * FROM public.viewer_requests'):return [request]
            if statement.startswith('SELECT s.*'):return [{'state':'active','root_call':root,'anchor_ns':10,'anchor_key':'anchor','revision':1}]
            if ' AS variant_count,' in statement:return events
            if statement.startswith('SELECT l.'):return []
            if statement.startswith('SELECT k.origin_key'):
                return [{'origin_key':parameters[n],'version_key':parameters[n+1],
                         'payload':zlib.compress(json.dumps({'message':'Input:{"BillID":"001"} Output:{"Result":true}'}).encode())}
                        for n in range(0,len(parameters),2)]
            if statement.startswith('SELECT o.axis'):return []
            if statement.startswith('SELECT e.ip_key'):return [{'ip_key':'c'*64,'raw_ip':'192.0.2.1'}]
            raise AssertionError(statement)
        @contextmanager
        def snapshot():yield q
        return SimpleNamespace(project=Path(__file__).resolve().parents[2],snapshot=snapshot,metadata=lambda q:{'generation':1}),key,queries

    def test_raw_messages_are_one_exact_batch_instead_of_per_event_queries(self):
        source,key,queries=self.source()
        with patch('anomaly_detection.viewer_bridge.reader',return_value=SimpleNamespace()):packet=read(source,key)
        body_queries=[q for q in queries if q[0].startswith('SELECT k.origin_key')]
        self.assertEqual(len(body_queries),1);self.assertEqual(len(body_queries[0][1]),8)
        self.assertEqual(body_queries[0][2],4);self.assertIn('OFFSET 0',body_queries[0][0])
        self.assertTrue(packet['profile']['qualified']);self.assertTrue(packet['profile']['input_complete'])
        event_query=next(q[0] for q in queries if ' AS variant_count,' in q[0])
        self.assertIn('LIMIT 2',event_query);self.assertIn('LIMIT 513) e',event_query)

    def test_conflicting_origin_remains_unqualified_and_is_not_read_as_valid_raw(self):
        source,key,queries=self.source(conflicted=True)
        with patch('anomaly_detection.viewer_bridge.reader',return_value=SimpleNamespace()):packet=read(source,key)
        self.assertFalse(packet['profile']['qualified'])
        body=next(q for q in queries if q[0].startswith('SELECT k.origin_key'))
        self.assertEqual(body[2],3)

    def test_event_overflow_is_explicitly_incomplete_and_not_silently_sampled(self):
        source,key,queries=self.source(count=13)
        with patch('anomaly_detection.viewer_bridge.reader',return_value=SimpleNamespace()):packet=read(source,key)
        self.assertFalse(packet['profile']['input_complete'])
        self.assertIn('CONTENT_EVENT_LIMIT',packet['profile']['issues'])
        self.assertFalse(any(q[0].startswith('SELECT k.origin_key') for q in queries))


if __name__=='__main__':unittest.main()
