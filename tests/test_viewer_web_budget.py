"""Repeated browser refreshes cannot accumulate unbounded database readers."""
import threading
import unittest
from unittest.mock import patch
from p24_foundation import viewer_ui as ui


class WebBudgetTests(unittest.TestCase):
    def test_two_readers_are_admitted_and_the_next_request_fails_without_a_connection(self):
        entered=threading.Event();release=threading.Event();opened=[];closed=[];results=[]
        class DB:
            sqlite=True
            def __init__(self,**opts):opened.append(self)
            def sql(self,*args):pass
            def close(self):closed.append(self)
            def semantic_sessions(self,*args):
                if len(opened)==2:entered.set()
                release.wait(5)
                return {}
        with patch.object(ui,'ViewerDB',DB),patch.object(ui,'render_template',return_value='page'),patch('p24_foundation.viewer_online.live_history_coverage',return_value={}),patch('p24_foundation.viewer_online.live_status',return_value={}):
            app=ui.create_viewer_app({})
            def request():
                with app.test_client() as client:results.append(client.get('/').status_code)
            workers=[threading.Thread(target=request) for _ in range(2)]
            for worker in workers:worker.start()
            try:
                self.assertTrue(entered.wait(3))
                with app.test_client() as client:
                    self.assertEqual(client.get('/').status_code,503)
                    self.assertEqual(client.get('/healthz').status_code,200)
                self.assertEqual(len(opened),2)
            finally:
                release.set()
                for worker in workers:worker.join(3)
            self.assertEqual(results,[200,200]);self.assertEqual(len(closed),2)
            with app.test_client() as client:self.assertEqual(client.get('/').status_code,200)
            self.assertEqual(len(closed),3)

    def test_web_session_has_local_read_limits_and_does_not_modify_worker_options(self):
        options={'dbname':'p24_design_viewer','options':'-c work_mem=8MB'};captured=[]
        class DB:
            sqlite=False
            def __init__(self,**opts):captured.append(opts['config'])
            def sql(self,*args):pass
            def close(self):pass
            def semantic_sessions(self,*args):return {}
        with patch.object(ui,'ViewerDB',DB),patch.object(ui,'render_template',return_value='page'),patch('p24_foundation.viewer_online.live_history_coverage',return_value={}),patch('p24_foundation.viewer_online.live_status',return_value={}):
            with ui.create_viewer_app({'config':options}).test_client() as client:self.assertEqual(client.get('/').status_code,200)
        self.assertEqual(options,{'dbname':'p24_design_viewer','options':'-c work_mem=8MB'})
        self.assertEqual(captured[0]['application_name'],'P24.Viewer.web')
        for value in ('statement_timeout=2000','lock_timeout=100','idle_in_transaction_session_timeout=5000','max_parallel_workers_per_gather=0'):
            self.assertIn(value,captured[0]['options'])

    def test_timeout_returns_unavailable_and_releases_reader_admission(self):
        class Timeout(Exception):sqlstate='57014'
        class DB:
            sqlite=True
            def __init__(self,**opts):pass
            def sql(self,*args):pass
            def close(self):pass
            def semantic_sessions(self,*args):raise Timeout()
        with patch.object(ui,'ViewerDB',DB),patch.object(ui,'render_template',return_value='page'),patch('p24_foundation.viewer_online.live_history_coverage',return_value={}):
            with ui.create_viewer_app({}).test_client() as client:
                for _ in range(4):
                    response=client.get('/')
                    self.assertEqual(response.status_code,503)
                    self.assertEqual(response.headers['Retry-After'],'2')


if __name__=='__main__':unittest.main()
