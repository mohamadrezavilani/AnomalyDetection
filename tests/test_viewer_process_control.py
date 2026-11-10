"""Stopping a Viewer requires a live DB lease, TCP mapping and stable OS handle."""
from datetime import datetime,timezone,timedelta
import importlib.util
import os
from pathlib import Path
import subprocess
import socket
import sys
import unittest

spec=importlib.util.spec_from_file_location('viewer_control',Path(__file__).resolve().parents[1]/'viewer_performance/Stop_Viewer_Worker.py')
control=importlib.util.module_from_spec(spec);spec.loader.exec_module(control)
STAMP=datetime(2026,11,9,tzinfo=timezone.utc)


class Process:
    image='C:\\Python312\\python.exe'
    created=STAMP-timedelta(seconds=2)
    def __init__(self):self.stopped=False;self.closed=False
    def terminate(self):self.stopped=True
    def close(self):self.closed=True


class ProcessControlTests(unittest.TestCase):
    def setUp(self):
        self.lease={'pid':7001,'backend_start':STAMP,'client_port':40001,'client_addr':'127.0.0.1'}
        self.process=Process();self.cleaned=[]
    def run_control(self,*,stop=False,lease=None,owner=None):
        return control.control(lease or (lambda:dict(self.lease)),owner or (lambda _:2002),
            lambda pid:self.process,self.cleaned.append,stop=stop,self_pid=9999)

    def test_inspection_never_stops_or_cleans_a_session(self):
        result=self.run_control()
        self.assertEqual(result['status'],'VIEWER_WORKER_IDENTIFIED')
        self.assertEqual(result['python_pid'],2002)
        self.assertEqual(result['postgres_backend_pid'],7001)
        self.assertFalse(self.process.stopped);self.assertFalse(self.cleaned);self.assertTrue(self.process.closed)
    def test_postgresql_full_host_masks_are_accepted_but_networks_and_remote_hosts_are_rejected(self):
        for address in ('127.0.0.1','127.0.0.1/32','::1','::1/128','::ffff:127.0.0.1/128'):
            self.assertTrue(control.loopback(address),address)
            self.lease['client_addr']=address
            result=self.run_control()
            self.assertEqual(result['status'],'VIEWER_WORKER_IDENTIFIED')
            self.assertFalse(self.process.stopped)
        for address in ('192.0.2.1/32','2001:db8::1/128','::ffff:192.0.2.1/128',
                '127.0.0.0/8','127.0.0.1/0','::1/0','not-an-address','',None,2130706433):
            self.assertFalse(control.loopback(address),address)
        for address in ('127.0.0.1/0','192.0.2.1/32'):
            self.process=Process();self.lease['client_addr']=address
            with self.assertRaises(control.ControlError):self.run_control(stop=True)
            self.assertFalse(self.process.stopped);self.assertFalse(self.cleaned)
    def test_explicit_stop_terminates_only_the_verified_client_then_its_unchanged_lease(self):
        result=self.run_control(stop=True)
        self.assertTrue(self.process.stopped);self.assertTrue(self.process.closed)
        self.assertEqual(self.cleaned,[self.lease]);self.assertTrue(result['process_stopped'])
        self.assertFalse(result['checkpoint_seek_performed']);self.assertFalse(result['committed_data_deleted'])
    def test_recycled_pid_or_non_python_client_cannot_be_stopped(self):
        for image,created in (('C:\\PostgreSQL\\postgres.exe',STAMP-timedelta(seconds=2)),
                ('C:\\Python312\\python.exe',STAMP+timedelta(seconds=2))):
            self.process=Process();self.process.image=image;self.process.created=created
            with self.assertRaises(control.ControlError):self.run_control(stop=True)
            self.assertFalse(self.process.stopped);self.assertFalse(self.cleaned);self.assertTrue(self.process.closed)
    def test_changed_lease_or_tcp_owner_cannot_be_stopped(self):
        for change_lease in (False,True):
            self.process=Process();calls=[]
            def lease():
                calls.append(1)
                return dict(self.lease,pid=8001) if change_lease and len(calls)>1 else dict(self.lease)
            owners=iter((2002,2003))
            with self.assertRaises(control.ControlError):
                self.run_control(stop=True,lease=lease,owner=(lambda _:2002) if change_lease else (lambda _:next(owners)))
            self.assertFalse(self.process.stopped);self.assertFalse(self.cleaned);self.assertTrue(self.process.closed)
    def test_remote_owner_and_self_owner_are_rejected(self):
        self.lease['client_addr']='192.0.2.1'
        with self.assertRaises(control.ControlError):self.run_control(stop=True)
        self.lease['client_addr']='::1'
        with self.assertRaises(control.ControlError):self.run_control(stop=True,owner=lambda _:9999)
        self.assertFalse(self.process.stopped)
    def test_no_lease_is_not_a_claim_that_all_python_processes_are_stopped(self):
        result=self.run_control(stop=True,lease=lambda:None)
        self.assertEqual(result['status'],'NO_VIEWER_LOCK_OWNER_OBSERVED')
        self.assertFalse(result['process_stopped']);self.assertFalse(self.process.stopped)
    def test_a_replacement_owner_is_never_cleaned_up(self):
        observations=iter((dict(self.lease),dict(self.lease),dict(self.lease,pid=8001)))
        self.run_control(stop=True,lease=lambda:next(observations))
        self.assertTrue(self.process.stopped);self.assertFalse(self.cleaned)


@unittest.skipUnless(os.name=='nt','Windows kernel API test')
class WindowsHandleTests(unittest.TestCase):
    def test_real_tcp_mapping_and_verified_handle_stop_only_our_client_child(self):
        with socket.socket() as server:
            server.bind(('127.0.0.1',0));server.listen(1);server.settimeout(10)
            port=server.getsockname()[1]
            child=subprocess.Popen([sys.executable,'-c',
                f"import socket,time;s=socket.create_connection(('127.0.0.1',{port}));time.sleep(30)"])
            try:
                connection,address=server.accept()
                with connection:
                    value={'pid':7001,'backend_start':datetime.now(timezone.utc),
                        'client_port':address[1],'client_addr':'127.0.0.1'}
                    cleaned=[]
                    result=control.control(lambda:dict(value),lambda p:control.tcp_owner(p,port),
                        lambda p:control.WindowsProcess(p,allow_stop=True),cleaned.append,stop=True)
                    self.assertEqual(result['python_pid'],child.pid)
                    self.assertTrue(result['process_stopped']);self.assertEqual(cleaned,[value])
                self.assertIsNotNone(child.wait(timeout=5))
            finally:
                if child.poll() is None:child.terminate();child.wait(timeout=5)

    def test_real_handle_identifies_and_stops_only_our_throwaway_python_child(self):
        child=subprocess.Popen([sys.executable,'-c','import time;time.sleep(30)'])
        try:
            handle=control.WindowsProcess(child.pid,allow_stop=True)
            try:
                self.assertIn(Path(handle.image).name.lower(),('python.exe','pythonw.exe'))
                # Windows process FILETIME and Python's wall clock can differ
                # by a millisecond. Compare stable kernel identities instead.
                parent=control.WindowsProcess(os.getpid())
                second=control.WindowsProcess(child.pid)
                try:
                    self.assertLessEqual(parent.created,handle.created)
                    self.assertEqual(handle.created,second.created)
                finally:second.close();parent.close()
                handle.terminate()
            finally:handle.close()
            self.assertIsNotNone(child.wait(timeout=5))
        finally:
            if child.poll() is None:child.terminate();child.wait(timeout=5)
    def test_read_only_handle_refuses_termination_without_explicit_permission(self):
        child=subprocess.Popen([sys.executable,'-c','import time;time.sleep(30)'])
        try:
            handle=control.WindowsProcess(child.pid)
            try:
                with self.assertRaisesRegex(control.ControlError,'STOP_NOT_REQUESTED'):handle.terminate()
                self.assertIsNone(child.poll())
            finally:handle.close()
        finally:
            if child.poll() is None:child.terminate();child.wait(timeout=5)


if __name__=='__main__':unittest.main()
