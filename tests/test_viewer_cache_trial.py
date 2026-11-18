"""Cache headroom gates and reversible ALTER SYSTEM on disposable PostgreSQL."""
import os
from contextlib import ExitStack,redirect_stdout
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch,MagicMock
from viewer_performance import Trial_Viewer_Cache as trial
from viewer_performance.Trial_Viewer_Cache import (GIB,TARGETS,memory_guard,
    settings_snapshot,set_parameters,restore_parameters)


class MemoryTests(unittest.TestCase):
    def test_32_gib_minus_firmware_and_19_gib_available_fit(self):
        memory_guard(dict(total_bytes=32*GIB-1024**2,available_bytes=19*GIB),
                     {'shared_buffers':{'setting':str(8*GIB//8192)}})

    def test_low_headroom_or_insufficient_machine_cannot_change_settings(self):
        for total,available,code in [(16*GIB,12*GIB,'REQUIRES_AT_LEAST'),
                (32*GIB,7*GIB,'OS_RESERVE')]:
            with self.subTest(total=total),self.assertRaisesRegex(ValueError,code):
                memory_guard(dict(total_bytes=total,available_bytes=available),
                             {'shared_buffers':{'setting':str(8*GIB//8192)}})

    def test_repeating_an_already_applied_trial_does_not_restart_it(self):
        with self.assertRaisesRegex(ValueError,'NO_RESTART_NEEDED'):
            memory_guard(dict(total_bytes=32*GIB,available_bytes=19*GIB),
                         {'shared_buffers':{'setting':str(12*GIB//8192)}})


class LifecycleTests(unittest.TestCase):
    """Exercise orchestration and error recovery; Windows service I/O is mocked."""
    def scenario(self,*,restart_failure=False,sql_recovery_failure=False,external_config=False):
        from viewer_performance.financial_screen import host
        from viewer_performance import Behavior_Release,Run_Viewer_Memory
        from viewer_performance import writer_identity
        from tools import check_viewer_install
        events=[]
        with tempfile.TemporaryDirectory() as temp,ExitStack() as stack:
            root=Path(temp);data=root/'pgdata';data.mkdir()
            (root/'AnomalyDetection/reports').mkdir(parents=True)
            config=data/'postgresql.auto.conf';config.write_bytes(b'original-config\n')
            task=dict(Name='P24-Viewer-Worker',Path='\\',State='Ready',Enabled=True,Actions=[])
            plan=dict(viewer_restart=['viewer_performance/Run_Viewer_Fast.py','--trial'],
                      active={r:True for r in ('ad_worker','ad_web','viewer','viewer_web')},task_restore=[task])
            release=root/'release.json';release.write_text(json.dumps(dict(status='PREVIOUS_ROLES_RESTORED',
                before=dict(restore_plan=plan),restore_failures=[])))
            before=dict(effective={name:dict(setting=value,unit='8kB' if name=='shared_buffers' else None)
                for name,value in [('shared_buffers',str(8*GIB//8192)),('track_io_timing','off'),('track_wal_io_timing','off')]},auto={})
            after=dict(effective={name:dict(setting=value) for name,value in [
                ('shared_buffers',str(12*GIB//8192)),('track_io_timing','on'),('track_wal_io_timing','on')]},auto=TARGETS)
            db=MagicMock();db.closed=False
            db.execute.return_value.fetchone.return_value={'data_directory':str(data)}
            reader=MagicMock();reader.__enter__.return_value=reader
            reader.execute.return_value.fetchall.return_value=[dict(cancelled=True)]
            restarts=[0]
            def powershell(code,*args):
                if 'Get-CimInstance' in code:
                    return dict(Name='postgresql-x64-18',State='Running',PathName='pg_ctl.exe runservice -D "'+str(data)+'"')
                if 'Restart-Service' in code:
                    events.append('restart');restarts[0]+=1
                    if restart_failure and restarts[0]==1:
                        if external_config:config.write_bytes(b'unrelated-admin-change\n')
                        raise TimeoutError('simulated service start failure')
                if 'Stop-Service' in code:events.append('stop-service');return dict(state='Stopped')
                if 'Start-Service' in code:events.append('start-service')
                return dict(status='RESTARTED')
            def apply(db,settings):events.append('apply');config.write_bytes(b'trial-config\n')
            def undo(db,settings):
                events.append('undo-settings')
                if sql_recovery_failure:raise ConnectionError('service unavailable')
            def restore(project,receipt,state):
                events.append('restore-roles');state['status']='PREVIOUS_ROLES_RESTORED'
                for t in state['disabled_tasks']:host.task_change(t,True)
            replacements=[(trial,'require_windows_admin',lambda:None),
                (check_viewer_install,'verify_release',lambda p:dict(status='PASS')),
                (Run_Viewer_Memory,'memory_info',lambda:dict(total_bytes=32*GIB,available_bytes=19*GIB)),
                (host,'parameters',lambda p:{}),(host,'powershell',powershell),
                (host,'inventory',lambda p:dict(tasks=[task])),
                (host,'task_change',lambda t,on:events.append('enable-task' if on else 'disable-task')),
                (host,'stop_role',lambda p,r:events.append('stop-'+r)),
                (host,'product_reader',lambda p:reader),(host,'cursors',lambda r:dict()),
                (writer_identity,'read_identity',lambda *args:dict(backend_pid=1,backend_start='2',application_name='verified')),
                (Behavior_Release,'restore',restore),(trial,'settings_snapshot',MagicMock(side_effect=[before,after])),
                (trial,'set_parameters',apply),(trial,'restore_parameters',undo)]
            for module,name,value in replacements:stack.enter_context(patch.object(module,name,value))
            stack.enter_context(patch('psycopg.connect',return_value=db))
            previous=Path.cwd();os.chdir(root);stack.callback(os.chdir,previous)
            output=io.StringIO()
            with redirect_stdout(output):code=trial.main(['--release-receipt',str(release)])
            receipts=list((root/'AnomalyDetection/reports').glob('Viewer_Cache_Trial_*/cache.json'))
            self.assertEqual(len(receipts),1,output.getvalue());receipt=receipts[0]
            return code,json.loads(receipt.read_text()),events,config.read_bytes()

    def test_apply_restores_roles_before_reenabling_the_original_task(self):
        code,state,events,_=self.scenario()
        self.assertEqual(code,0);self.assertEqual(state['status'],'CACHE_TRIAL_APPLIED_ROLES_RESTORED')
        self.assertLess(events.index('stop-viewer'),events.index('apply'))
        self.assertLess(events.index('restart'),events.index('restore-roles'))
        self.assertLess(events.index('restore-roles'),events.index('enable-task'))
        self.assertEqual(state['new_database_copies'],0);self.assertFalse(state['checkpoint_seek_performed'])

    def test_failed_restart_restores_previous_settings_and_the_roles(self):
        code,state,events,_=self.scenario(restart_failure=True)
        self.assertEqual(code,2);self.assertTrue(state['settings_restored_after_failure'])
        self.assertLess(events.index('undo-settings'),events.index('restore-roles'))

    def test_failed_server_start_can_restore_unchanged_auto_conf_without_sql(self):
        code,state,events,config=self.scenario(restart_failure=True,sql_recovery_failure=True)
        self.assertEqual(code,2);self.assertTrue(state['settings_restored_after_failure'])
        self.assertEqual(config,b'original-config\n')
        self.assertLess(events.index('start-service'),events.index('restore-roles'))

    def test_config_changed_by_another_operator_is_never_overwritten(self):
        code,state,events,config=self.scenario(restart_failure=True,sql_recovery_failure=True,external_config=True)
        self.assertEqual(code,2);self.assertIn('AUTO_CONF_CHANGED',state['settings_restore_failure']['code'])
        self.assertEqual(config,b'unrelated-admin-change\n')


@unittest.skipUnless(os.environ.get('P24_DELTA_PG_HOST'),'private disposable PG18 required')
class NativeSettingsTests(unittest.TestCase):
    def setUp(self):
        import psycopg
        from psycopg.rows import dict_row
        self.admin=psycopg.connect(host=os.environ['P24_DELTA_PG_HOST'],
            port=int(os.environ['P24_DELTA_PG_PORT']),user=os.environ.get('P24_DELTA_PG_USER','postgres'),
            dbname='postgres',autocommit=True,row_factory=dict_row)
        self.before=settings_snapshot(self.admin)
        self.addCleanup(self.admin.close)
        self.addCleanup(lambda:restore_parameters(self.admin,self.before))

    def test_native_trial_writes_three_settings_without_restart_or_data_mutation(self):
        self.admin.execute('CREATE TEMP TABLE cache_trial_witness(id int PRIMARY KEY, body text)')
        self.admin.execute("INSERT INTO cache_trial_witness VALUES(1,'unchanged checkpoint witness')")
        started=self.admin.execute('SELECT pg_postmaster_start_time() AS value').fetchone()['value']
        set_parameters(self.admin,TARGETS)
        changed=settings_snapshot(self.admin)
        self.assertEqual(changed['auto'],TARGETS)
        self.assertEqual(changed['effective']['shared_buffers']['setting'],self.before['effective']['shared_buffers']['setting'])
        self.assertEqual(self.admin.execute('SELECT pg_postmaster_start_time() AS value').fetchone()['value'],started)
        self.assertEqual(self.admin.execute('SELECT * FROM cache_trial_witness').fetchall(),
                         [{'id':1,'body':'unchanged checkpoint witness'}])
        restore_parameters(self.admin,self.before)
        self.assertEqual(settings_snapshot(self.admin)['auto'],self.before['auto'])

    def test_existing_overrides_are_restored_and_unknown_parameters_are_refused(self):
        set_parameters(self.admin,{'track_io_timing':'on','track_wal_io_timing':'off'})
        custom=settings_snapshot(self.admin)
        set_parameters(self.admin,TARGETS)
        restore_parameters(self.admin,custom)
        self.assertEqual(settings_snapshot(self.admin)['auto'],custom['auto'])
        with self.assertRaisesRegex(ValueError,'UNSUPPORTED_CACHE_PARAMETER'):
            set_parameters(self.admin,{'fsync':'off'})


if __name__=='__main__':unittest.main()
