"""Recent-start seeks preserve evidence and expose, rather than fill, gaps."""
import contextlib
import io
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

from p24_foundation.privacy import generate_keys
from p24_foundation.viewer_data import ViewerDB, token
from p24_foundation.viewer_elastic import stream_key
from p24_foundation.viewer_online import (FIVE_NS, SECOND_NS, initialize_live, bind_stream,
    publish_capture, resume_recent, live_status, single_worker, iso)
from p24_foundation.viewer_ui import create_viewer_app
from tests.test_viewer_online import START, verified_file
from tests.test_viewer_r6_service_journey import log
from tools.run_behavior_viewer import main as cli


class RecentStartTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(); self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name); self.keys = self.root / 'keys.json'
        generate_keys(self.keys)
        self.opts = dict(sqlite_path=self.root / 'viewer.db', keys_path=self.keys)
        self.db = ViewerDB(**self.opts); self.addCleanup(self.db.close)
        self.db.init(); initialize_live(self.db)
        self.es = dict(host='http://example.invalid', index_pattern='logs-*')
        bind_stream(self.db, start_ns=START, stream_key=stream_key(self.es))
        self.publish(START, 'existing')
        self.now = START + 100 * FIVE_NS + 60 * SECOND_NS

    def publish(self, start, request, *, mode='forward', call='Services.v1/WaterBills Line:1'):
        row = log(start // FIVE_NS, request, call, 'POST (G00000 | successful)')
        row['@timestamp'] = iso(start + SECOND_NS)
        path = verified_file(self.root / (request + str(start) + '.json.gz'), [row], start)
        return publish_capture(self.db, path, start, start + FIVE_NS, mode=mode)

    def evidence_snapshot(self):
        tables = self.db.all("SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'")
        return {r['name']: sorted(json.dumps(v, sort_keys=True, default=lambda b: bytes(b).hex()) for v in self.db.all('SELECT * FROM ' + r['name']))
            for r in tables if r['name'] not in ('viewer_live_state', 'viewer_live_resumes')}

    def test_seek_keeps_all_evidence_projections_roles_keys_and_original_binding(self):
        self.db.update_service_role('Services.v1/WaterBills', 'unknown', 'unknown', 'operator choice')
        before = self.evidence_snapshot(); key_bytes = self.keys.read_bytes()
        original = self.db.one('SELECT * FROM viewer_live_state')
        result = resume_recent(self.db, now=self.now)
        self.assertEqual(result['status'], 'RESCHEDULED')
        self.assertEqual(result['skipped_windows'], 97)
        self.assertEqual(self.evidence_snapshot(), before)
        self.assertEqual(self.keys.read_bytes(), key_bytes)
        state = self.db.one('SELECT * FROM viewer_live_state')
        for name in ('start_ns', 'stream_key', 'keys_fingerprint', 'generation', 'last_success_ns', 'last_event_ns'):
            self.assertEqual(state[name], original[name], name)
        self.assertEqual(state['next_ns'], START + 98 * FIVE_NS)
        self.assertEqual(result['live']['historical_gap_windows'], 97)
        self.assertEqual(result['live']['backlog_windows'], 2)
        self.assertTrue(result['live']['history_has_gaps'])

    def test_both_injected_failures_rollback_cursor_and_audit_together(self):
        original = self.db.one('SELECT * FROM viewer_live_state'); before = self.evidence_snapshot()
        for point in ('after_resume_receipt', 'before_resume_commit'):
            def fault(stage):
                if stage == point: raise RuntimeError('controlled')
            with self.assertRaisesRegex(RuntimeError, 'controlled'):
                resume_recent(self.db, now=self.now, fault=fault)
            self.assertEqual(self.db.one('SELECT * FROM viewer_live_state'), original)
            self.assertEqual(self.db.one('SELECT COUNT(*) AS n FROM viewer_live_resumes')['n'], 0)
            self.assertEqual(self.evidence_snapshot(), before)

    def test_restart_uses_recent_checkpoint_without_changing_config_binding(self):
        resume_recent(self.db, now=self.now)
        with ViewerDB(**self.opts) as restarted:
            initialize_live(restarted)
            bind_stream(restarted, start_ns=START, stream_key=stream_key(self.es))
            self.assertEqual(restarted.one('SELECT next_ns FROM viewer_live_state')['next_ns'], START + 98 * FIVE_NS)
            self.assertEqual(live_status(restarted, now=self.now)['historical_gap_windows'], 97)

    def test_repeat_is_noop_and_new_forward_still_requires_exact_checkpoint(self):
        resume_recent(self.db, now=self.now)
        self.assertEqual(resume_recent(self.db, now=self.now)['status'], 'NO_CHANGE')
        self.assertEqual(self.db.one('SELECT COUNT(*) AS n FROM viewer_live_resumes')['n'], 1)
        with self.assertRaisesRegex(ValueError, 'noncontiguous'):
            self.publish(START + FIVE_NS, 'must_not_fake_forward')
        self.publish(START + 98 * FIVE_NS, 'recent')
        self.assertEqual(resume_recent(self.db, now=self.now)['status'], 'NO_CHANGE')
        self.assertEqual(self.db.one('SELECT next_ns FROM viewer_live_state')['next_ns'], START + 99 * FIVE_NS)

    def test_real_backfill_reduces_gap_without_advancing_recent_cursor_or_double_counting(self):
        recent_now = START + 6 * FIVE_NS + 60 * SECOND_NS
        resume_recent(self.db, now=recent_now)
        self.assertEqual(live_status(self.db, now=recent_now)['historical_gap_windows'], 3)
        for n in (2, 1, 3):
            self.publish(START + n * FIVE_NS, 'backfill_' + str(n), mode='manual_recheck')
            self.publish(START + n * FIVE_NS, 'backfill_' + str(n), mode='manual_recheck')
            self.assertEqual(self.db.one('SELECT next_ns FROM viewer_live_state')['next_ns'], START + 4 * FIVE_NS)
        status = live_status(self.db, now=recent_now)
        self.assertFalse(status['history_has_gaps'])
        self.assertEqual(status['historical_gap_windows'], 0)
        self.assertEqual(status['history_resume_count'], 1)

    def test_later_evidence_still_stitches_by_request_and_authoritative_session(self):
        before = self.db.lookup_request('existing')
        resume_recent(self.db, now=self.now)
        self.publish(START + 98 * FIVE_NS, 'existing', call='ClientAyanCoInquiry.WaterBills Line:1')
        after = self.db.lookup_request('existing')
        self.assertEqual(before['request_key'], after['request_key'])
        self.assertEqual(before['session_key'], after['session_key'])
        self.assertEqual(self.db.one('SELECT COUNT(*) AS n FROM viewer_requests')['n'], 1)
        self.assertEqual(after['event_count'], 2)

    def test_invalid_seek_arguments_never_change_state(self):
        before = self.db.one('SELECT * FROM viewer_live_state')
        for value in (0, -1, 289, True, 2.5):
            with self.assertRaisesRegex(ValueError, 'invalid_recent_window_count'):
                resume_recent(self.db, lookback_windows=value, now=self.now)
        with self.assertRaisesRegex(ValueError, 'invalid_recent_start_time'):
            resume_recent(self.db, now=True)
        self.assertEqual(before, self.db.one('SELECT * FROM viewer_live_state'))

    def test_pre_resume_schema_remains_readable_and_read_only(self):
        self.db.sql('DROP TABLE viewer_live_resumes'); self.db.conn.commit()
        status = live_status(self.db, now=self.now)
        self.assertFalse(status['history_has_gaps'])
        self.assertEqual(status['continuous_published_from_utc'], iso(START))
        self.assertIsNone(self.db.one("SELECT name FROM sqlite_master WHERE name='viewer_live_resumes'"))

    def config(self):
        path = self.root / 'private.py'
        path.write_text('KEYS_PATH=' + repr(str(self.keys)) + '\nSQLITE_OFFLINE_PATH=' + repr(str(self.opts['sqlite_path'])) +
            '\nLIVE_START_UTC=' + repr(iso(START)) + '\nELASTICSEARCH=' + repr(self.es) +
            '\nLIVE=' + repr(dict(capture_dir=str(self.root), lag_seconds=60, overlap_windows=2)) + '\n')
        return path

    def test_cli_does_not_contact_es_edit_config_or_replace_keys(self):
        config = self.config(); original = config.read_bytes(); key_bytes = self.keys.read_bytes()
        output = io.StringIO()
        with patch.object(sys, 'argv', ['viewer', 'live-recent', '--config', str(config)]), \
             patch('p24_foundation.viewer_online.now_ns', return_value=self.now), \
             patch('p24_foundation.viewer_elastic.ElasticREST') as es, \
             patch('p24_foundation.viewer_runtime.atomic_json') as report, contextlib.redirect_stdout(output):
            cli()
        es.assert_not_called(); report.assert_called_once()
        self.assertEqual(json.loads(output.getvalue())['status'], 'RESCHEDULED')
        self.assertEqual(config.read_bytes(), original); self.assertEqual(self.keys.read_bytes(), key_bytes)

    def test_cli_refuses_active_worker_before_any_state_change(self):
        config = self.config(); before = self.db.one('SELECT * FROM viewer_live_state')
        output = io.StringIO()
        with single_worker(self.db, self.root / 'viewer_worker.lock'), \
             patch.object(sys, 'argv', ['viewer', 'live-recent', '--config', str(config)]), \
             contextlib.redirect_stdout(output), self.assertRaises(SystemExit):
            cli()
        self.assertEqual(json.loads(output.getvalue())['failure']['code'], 'viewer_worker_already_running')
        self.assertEqual(before, self.db.one('SELECT * FROM viewer_live_state'))

    def test_gap_notice_appears_on_home_request_and_session_pages(self):
        resume_recent(self.db, now=self.now)
        app = create_viewer_app(self.opts); app.config['TESTING'] = True
        request_key = token(self.db.keys, 'request', 'existing')
        session_key = self.db.lookup_request('existing')['session_key']
        before = self.db.one('SELECT * FROM viewer_live_state')
        with app.test_client() as client:
            for path in ('/', '/request/' + request_key, '/session/' + session_key + '/behavior'):
                response = client.get(path)
                self.assertEqual(response.status_code, 200, path)
                self.assertIn('فاصلهٔ پردازش‌نشده'.encode(), response.data)
            status = client.get('/live-status').get_json()
            self.assertEqual(status['historical_gap_windows'], 97)
        self.assertEqual(before, self.db.one('SELECT * FROM viewer_live_state'))

    def launch(self, step, *flags, command='live'):
        config=self.config()
        with patch.object(sys,'argv',['viewer',command,'--config',str(config),'--no-prefetch',*flags]), \
             patch('p24_foundation.viewer_online.LiveWorker.step',autospec=True,side_effect=step), \
             patch('p24_foundation.viewer_online.now_ns',side_effect=lambda:self.now), \
             patch('p24_foundation.viewer_elastic.ElasticREST'), \
             patch('p24_foundation.viewer_runtime.ProgressConsole'), \
             patch('p24_foundation.viewer_runtime.atomic_json'), \
             patch('tools.run_behavior_viewer.time.sleep'):
            cli()

    def test_debug_default_applies_to_existing_config_and_each_new_process(self):
        before=self.evidence_snapshot();seen=[]
        def stop(worker,**kw):
            seen.append(worker.db.one('SELECT next_ns FROM viewer_live_state')['next_ns'])
            raise KeyboardInterrupt
        self.launch(stop)
        self.assertEqual(seen,[START+99*FIVE_NS])
        self.assertEqual(self.db.one('SELECT COUNT(*) AS n FROM viewer_live_resumes')['n'],1)
        self.assertEqual(before,self.evidence_snapshot())
        self.now+=10*FIVE_NS
        self.launch(stop)
        self.assertEqual(seen[-1],START+109*FIVE_NS)
        self.assertEqual(self.db.one('SELECT COUNT(*) AS n FROM viewer_live_resumes')['n'],2)
        self.assertEqual(before,self.evidence_snapshot())

    def test_retry_in_same_process_never_seeks_past_failed_window(self):
        seen=[]
        def retry_then_stop(worker,**kw):
            seen.append(worker.db.one('SELECT next_ns FROM viewer_live_state')['next_ns'])
            if len(seen)==1:
                self.now+=20*FIVE_NS
                raise RuntimeError('controlled publication failure')
            raise KeyboardInterrupt
        self.launch(retry_then_stop)
        self.assertEqual(seen,[START+99*FIVE_NS]*2)
        self.assertEqual(self.db.one('SELECT COUNT(*) AS n FROM viewer_live_resumes')['n'],1)

    def test_explicit_continuous_mode_preserves_checkpoint(self):
        before=self.db.one('SELECT next_ns FROM viewer_live_state')['next_ns']
        def stop(worker,**kw):raise KeyboardInterrupt
        self.launch(stop,'--resume-checkpoint')
        self.assertEqual(self.db.one('SELECT next_ns FROM viewer_live_state')['next_ns'],before)
        self.assertEqual(self.db.one('SELECT COUNT(*) AS n FROM viewer_live_resumes')['n'],0)

    def test_config_can_disable_debug_for_future_continuous_operation(self):
        config=self.config()
        config.write_text(config.read_text()+"\nLIVE['debug_recent_start']=False\n")
        before=self.db.one('SELECT next_ns FROM viewer_live_state')['next_ns']
        with patch.object(self,'config',return_value=config):
            self.launch(lambda worker,**kw:(_ for _ in ()).throw(KeyboardInterrupt))
        self.assertEqual(self.db.one('SELECT next_ns FROM viewer_live_state')['next_ns'],before)

    def test_launcher_recent_flag_overrides_legacy_config_without_reseeking_on_retries(self):
        config=self.config()
        config.write_text(config.read_text()+"\nLIVE['debug_recent_start']=False\n")
        with patch.object(self,'config',return_value=config):
            self.launch(lambda worker,**kw:(_ for _ in ()).throw(KeyboardInterrupt), '--debug-recent-start')
        self.assertEqual(self.db.one('SELECT next_ns FROM viewer_live_state')['next_ns'],START+99*FIVE_NS)
        self.assertEqual(self.db.one('SELECT COUNT(*) AS n FROM viewer_live_resumes')['n'],1)

    def test_one_shot_keeps_cursor_unless_debug_explicitly_requested(self):
        before=self.db.one('SELECT next_ns FROM viewer_live_state')['next_ns']
        self.launch(lambda worker,**kw:{'status':'WAITING'},command='live-once')
        self.assertEqual(self.db.one('SELECT next_ns FROM viewer_live_state')['next_ns'],before)
        self.launch(lambda worker,**kw:{'status':'WAITING'},'--debug-recent-start',command='live-once')
        self.assertEqual(self.db.one('SELECT next_ns FROM viewer_live_state')['next_ns'],START+99*FIVE_NS)

    def test_debug_start_respects_lag_and_never_selects_partial_window(self):
        self.now-=SECOND_NS
        self.launch(lambda worker,**kw:(_ for _ in ()).throw(KeyboardInterrupt))
        next_ns=self.db.one('SELECT next_ns FROM viewer_live_state')['next_ns']
        self.assertEqual(next_ns,START+98*FIVE_NS)
        self.assertLessEqual(next_ns+FIVE_NS,self.now-60*SECOND_NS)

    def test_debug_start_refuses_second_worker_before_seek(self):
        before=self.db.one('SELECT * FROM viewer_live_state')
        with single_worker(self.db,self.root/'viewer_worker.lock'),self.assertRaises(SystemExit):
            self.launch(lambda worker,**kw:(_ for _ in ()).throw(KeyboardInterrupt))
        self.assertEqual(self.db.one('SELECT * FROM viewer_live_state'),before)
        self.assertEqual(self.db.one('SELECT COUNT(*) AS n FROM viewer_live_resumes')['n'],0)
