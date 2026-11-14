"""Web stop binds HTTP identity, live TCP owner and process handle together."""
from datetime import datetime,timedelta,timezone
import os
from pathlib import Path
import subprocess
import sys
import time
import unittest
from unittest.mock import patch
from viewer_performance import Stop_Viewer_Web as web

STAMP=datetime(2026,11,14,tzinfo=timezone.utc)
class Process:
    image='E:\\Python\\python.exe';created=STAMP
    stopped=False;closed=False
    def terminate(self):self.stopped=True
    def close(self):self.closed=True


class WebControlTests(unittest.TestCase):
    def setUp(self):
        self.process=Process();self.cleaned=[]
        self.sessions=[{'pid':6000,'backend_start':STAMP+timedelta(seconds=1),'client_port':40001,'client_addr':'127.0.0.1','worker_lock':False}]
        self.health={'http_status':200,'server':'Werkzeug/3.1','health':{'status':'ok','service':'viewer','runtime_sha256':'known'}}
    def run_control(self,**overrides):
        args={'find_listener':lambda:2002,'health':lambda:self.health,'ports':lambda pid:frozenset({40001}),
            'open_process':lambda pid:self.process,'backends':lambda ports:self.sessions,
            'terminate':lambda row:self.cleaned.append(row) or True,'supported':{'known'},'self_pid':9999}
        args.update(overrides);return web.control(**args)
    def test_inspection_does_not_stop_process_or_database_sessions(self):
        self.assertEqual(self.run_control()['status'],'VIEWER_WEB_IDENTIFIED')
        self.assertFalse(self.process.stopped);self.assertFalse(self.cleaned);self.assertTrue(self.process.closed)
    def test_stop_cleans_only_sessions_matched_before_the_verified_web_process_exits(self):
        self.assertEqual(self.run_control(stop=True)['status'],'VIEWER_WEB_STOPPED')
        self.assertTrue(self.process.stopped);self.assertEqual(self.cleaned,self.sessions)
    def test_missing_listener_is_idempotent_and_does_not_open_any_process(self):
        self.assertEqual(self.run_control(find_listener=lambda:None)['status'],'NO_VIEWER_WEB_LISTENER')
        self.assertFalse(self.process.closed);self.assertFalse(self.cleaned)
    def test_proxy_unknown_source_or_other_service_is_never_stopped(self):
        for change in ('proxy','unknown','other'):
            self.setUp()
            if change=='proxy':self.health['server']='BaseHTTP/0.6, Werkzeug/3.1'
            if change=='unknown':self.health['health']['runtime_sha256']='unknown'
            if change=='other':self.health['health']['service']='other'
            with self.assertRaises(web.ControlError):self.run_control(stop=True)
            self.assertFalse(self.process.stopped);self.assertFalse(self.cleaned)
    def test_worker_lock_non_python_process_and_recycled_identity_block_stop(self):
        for change in ('worker','image','recycled'):
            self.setUp()
            if change=='worker':self.sessions[0]['worker_lock']=True
            if change=='image':self.process.image='E:\\postgres.exe'
            if change=='recycled':self.process.created=STAMP+timedelta(seconds=2)
            with self.assertRaises(web.ControlError):self.run_control(stop=True)
            self.assertFalse(self.process.stopped);self.assertFalse(self.cleaned)
    def test_replaced_listener_still_blocks_stop(self):
        observations=iter((2002,2003))
        with self.assertRaises(web.ControlError):
            self.run_control(stop=True,find_listener=lambda:next(observations))
        self.assertFalse(self.process.stopped);self.assertFalse(self.cleaned)

    def test_connection_churn_does_not_block_stopping_the_same_verified_web_process(self):
        calls=[]
        def changing(pid):
            calls.append(pid)
            return frozenset({40001}) if len(calls)==1 else frozenset({40002,40003})
        result=self.run_control(stop=True,ports=changing)
        self.assertEqual(result['status'],'VIEWER_WEB_STOPPED')
        self.assertTrue(self.process.stopped);self.assertEqual(self.cleaned,self.sessions)
        self.assertEqual(calls,[2002])

    def test_disappearing_backends_are_not_a_reason_to_leave_the_web_server_running(self):
        result=self.run_control(stop=True,terminate=lambda row:False)
        self.assertEqual(result['status'],'VIEWER_WEB_STOPPED')
        self.assertEqual(result['database_termination_acknowledged'],0)
        self.assertTrue(self.process.stopped)

    def test_port_reuse_after_tcp_snapshot_or_ambiguous_backend_is_not_terminated(self):
        original=self.sessions[0]
        endpoints=frozenset({(40001,'127.0.0.1')})
        cutoff=STAMP+timedelta(seconds=2)
        self.assertEqual(web.verified_backends([original],endpoints,cutoff),[original])
        later=dict(original,pid=7000,backend_start=cutoff+timedelta(microseconds=1))
        self.assertEqual(web.verified_backends([later],endpoints,cutoff),[])
        self.assertEqual(web.verified_backends([original,dict(original,pid=7001)],endpoints,cutoff),[])
        self.assertEqual(web.verified_backends([dict(original,client_port=40002)],endpoints,cutoff),[])

    def test_tcp_query_failure_is_not_an_absent_listener(self):
        with patch.object(web.subprocess,'run',return_value=subprocess.CompletedProcess([],1,'','access denied')):
            with self.assertRaises(web.ControlError):web.listener()
    def test_stdin_bootstrap_can_load_before_the_installation_is_updated(self):
        source=Path(web.__file__).read_text()
        result=subprocess.run([sys.executable,'-B','-','--help'],input=source,text=True,capture_output=True,timeout=10)
        self.assertEqual(result.returncode,0,result.stderr);self.assertIn('--project-root',result.stdout)

    @unittest.skipUnless(os.name=='nt','native Windows listener and process handle')
    def test_native_windows_stops_a_live_loopback_flask_process(self):
        from viewer_performance.Stop_Viewer_Worker import WindowsProcess
        from viewer_performance.Diagnose_Viewer_Web import probe
        from p24_foundation.viewer_runtime import runtime_source_digest
        if web.listener() is not None:self.skipTest('loopback test port already in use')
        child=subprocess.Popen([sys.executable,'-B','-c',"from p24_foundation.viewer_ui import create_viewer_app; create_viewer_app({}).run(host='127.0.0.1',port=5021,use_reloader=False,debug=False)"],
            cwd=Path(__file__).resolve().parents[1],stdin=subprocess.DEVNULL,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
        try:
            deadline=time.monotonic()+10
            while time.monotonic()<deadline:
                if probe('127.0.0.1',5021,'/healthz',timeout=1).get('http_status')==200:break
                time.sleep(.1)
            result=web.control(web.listener,lambda:probe('127.0.0.1',5021,'/healthz'),lambda pid:frozenset(),
                lambda pid:WindowsProcess(pid,allow_stop=True),lambda ports:[],lambda row:False,
                supported={runtime_source_digest()},stop=True)
            self.assertEqual(result['status'],'VIEWER_WEB_STOPPED');self.assertIsNone(web.listener())
            child.wait(timeout=5)
        finally:
            if child.poll() is None:child.terminate();child.wait(timeout=5)


if __name__=='__main__':unittest.main()
