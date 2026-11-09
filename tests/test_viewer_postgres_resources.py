"""Resource changes bind to the intended service and have guarded recovery."""
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from tools.apply_postgres_resources import (choose_service,size_bytes,restore_local,digest,
    ResourceError,TARGETS,TARGET_BYTES,DURABILITY,set_setting,recover,main,apply,config_validation)


def pending_resource_rows(auto):
    return [dict(seqno=n,sourcefile=str(auto),sourceline=n,name=name,setting=value,
                 context='postmaster' if name in ('shared_buffers','wal_buffers') else 'sighup',
                 applied=name not in ('shared_buffers','wal_buffers'),
                 error='setting could not be applied' if name in ('shared_buffers','wal_buffers') else None)
            for n,(name,value) in enumerate(TARGETS.items(),1)]


class ResourceConnection:
    def __init__(self,rows):self.rows=rows;self.statements=[]
    def __enter__(self):return self
    def __exit__(self,*args):pass
    def execute(self,statement,*args):
        self.statements.append(str(statement))
        if 'pg_file_settings' in str(statement):return self
        if 'pending_restart' in str(statement):self.result={'n':0}
        else:self.result={'ok':True}
        return self
    def fetchall(self):return self.rows
    def fetchone(self):return self.result


class PostgresResourceTests(unittest.TestCase):
    def test_expected_postmaster_errors_allow_restart_only_after_validated_writes(self):
        auto=Path('C:/pg/data/postgresql.auto.conf')
        c=ResourceConnection(pending_resource_rows(auto))
        self.assertEqual(config_validation(c,auto)['status'],'INVALID')
        result=config_validation(c,auto,targets_written=True)
        self.assertEqual(result,{'status':'READY_FOR_RESTART',
                                'restart_required':['shared_buffers','wal_buffers'],'errors':[]})

    def test_genuine_errors_stop_restart_and_never_expose_config_values(self):
        import json
        auto=Path('C:/pg/data/postgresql.auto.conf')
        rows=pending_resource_rows(auto)
        rows.append(dict(seqno=5,sourcefile='C:/pg/data/postgresql.conf',sourceline=40,
                         name=None,setting='SECRET',applied=False,context=None,error='syntax error: SECRET'))
        result=config_validation(ResourceConnection(rows),auto,targets_written=True)
        self.assertEqual(result['status'],'INVALID')
        self.assertEqual(result['errors'][0]['reason'],'CONFIG_ERROR')
        self.assertNotIn('SECRET',json.dumps(result))

    def test_same_generic_error_for_wrong_value_or_context_or_file_is_not_ignored(self):
        auto=Path('C:/pg/data/postgresql.auto.conf')
        for changed in ({'setting':'wrong'}, {'context':'sighup'},
                        {'sourcefile':'C:/pg/data2/postgresql.auto.conf'},
                        {'error':'another error'}, {'applied':True}):
            with self.subTest(changed=changed):
                rows=pending_resource_rows(auto);rows[0].update(changed)
                self.assertEqual(config_validation(ResourceConnection(rows),auto,targets_written=True)['status'],'INVALID')

    def test_sighup_errors_and_shadowed_or_missing_targets_block_restart(self):
        auto=Path('C:/pg/data/postgresql.auto.conf')
        scenarios=[]
        rows=pending_resource_rows(auto);rows[2].update(applied=False,error='setting could not be applied');scenarios.append(rows)
        rows=pending_resource_rows(auto);rows.append(dict(rows[0],seqno=5,setting='256MB',applied=True,error=None));scenarios.append(rows)
        rows=pending_resource_rows(auto)[1:];scenarios.append(rows)
        rows=pending_resource_rows(auto);rows[2].update(applied=False);scenarios.append(rows)
        for rows in scenarios:
            with self.subTest(rows=rows):
                self.assertEqual(config_validation(ResourceConnection(rows),auto,targets_written=True)['status'],'INVALID')

    def test_full_apply_reaches_one_restart_and_verifies_active_settings(self):
        with tempfile.TemporaryDirectory() as folder:
            root=Path(folder);auto=root/'postgresql.auto.conf';auto.write_text('# original\n')
            c=ResourceConnection([]);writes=[]
            before={'identity':'owner-instance','data':str(root),'port':'5432',
                    'settings':{name:{'setting':'1','unit':'MB','pending_restart':False} for name in TARGETS}}
            before['settings'].update({name:{'setting':'on' if name!='wal_level' else 'replica',
                                            'unit':None,'pending_restart':False} for name in DURABILITY})
            after=dict(before,settings={name:dict(row) for name,row in before['settings'].items()})
            for name,value in TARGET_BYTES.items():after['settings'][name].update(setting=str(value),unit='B')

            def write(conn,name,value):
                writes.append((name,value));auto.write_text(str(writes))
                if len(writes)==len(TARGETS):conn.rows=pending_resource_rows(auto)

            report={}
            with patch('tools.apply_postgres_resources.require_admin'), \
                    patch('tools.apply_postgres_resources.connect',return_value=c), \
                    patch('tools.apply_postgres_resources.snapshot',return_value=before), \
                    patch('tools.apply_postgres_resources.windows_service',return_value='exact-service'), \
                    patch('tools.apply_postgres_resources.shutil.disk_usage') as disk, \
                    patch('tools.apply_postgres_resources.overrides',return_value={}), \
                    patch('tools.apply_postgres_resources.set_setting',side_effect=write), \
                    patch('tools.apply_postgres_resources.restart_service') as restart, \
                    patch('tools.apply_postgres_resources.wait_ready',return_value=after):
                disk.return_value.free=100*1024**3
                apply({},root/'backup',report)
            self.assertEqual(report['resource_status'],'APPLIED_AND_RESTARTED')
            self.assertEqual(dict(writes),TARGETS)
            restart.assert_called_once_with('exact-service')
            self.assertFalse(any('pg_reload_conf' in s for s in c.statements))
            self.assertEqual((root/'backup/postgresql.auto.conf.before').read_text(),'# original\n')

    def test_full_apply_invalid_config_restores_four_settings_without_restart(self):
        with tempfile.TemporaryDirectory() as folder:
            root=Path(folder);auto=root/'postgresql.auto.conf';auto.write_text('# original\n')
            c=ResourceConnection([]);writes=[]
            before={'identity':'owner-instance','data':str(root),'port':'5432',
                    'settings':{name:{'setting':'1','unit':'MB','pending_restart':False} for name in TARGETS}}

            def write(conn,name,value):
                writes.append((name,value));auto.write_text(str(writes))
                if len(writes)==len(TARGETS):
                    conn.rows=pending_resource_rows(auto)
                    conn.rows[2].update(applied=False,error='setting could not be applied')

            report={}
            with patch('tools.apply_postgres_resources.require_admin'), \
                    patch('tools.apply_postgres_resources.connect',return_value=c), \
                    patch('tools.apply_postgres_resources.snapshot',return_value=before), \
                    patch('tools.apply_postgres_resources.windows_service',return_value='exact-service'), \
                    patch('tools.apply_postgres_resources.shutil.disk_usage') as disk, \
                    patch('tools.apply_postgres_resources.overrides',return_value={'shared_buffers':'128MB'}), \
                    patch('tools.apply_postgres_resources.set_setting',side_effect=write), \
                    patch('tools.apply_postgres_resources.restart_service') as restart:
                disk.return_value.free=100*1024**3
                with self.assertRaisesRegex(ResourceError,'new_postgres_config_error'):
                    apply({},root/'backup',report)
            self.assertEqual(report['resource_status'],'ROLLED_BACK_BEFORE_RESTART')
            self.assertEqual(writes[4:],[('shared_buffers','128MB'),('wal_buffers',None),
                                        ('max_wal_size',None),('min_wal_size',None)])
            restart.assert_not_called()

    def test_exact_data_directory_not_prefix_or_first_service(self):
        services=[{'Name':'wrong','PathName':'pg_ctl runservice -D "C:\\pg\\data2"','ProcessId':10},
                  {'Name':'right','PathName':'pg_ctl runservice -D "C:\\pg\\data"','ProcessId':11}]
        self.assertEqual(choose_service(services,'c:/pg/data'),'right')
        self.assertEqual(choose_service(services,'D:/relocated-data',11),'right')

    def test_ambiguous_or_absent_service_is_rejected(self):
        row={'Name':'one','PathName':'pg_ctl -D "C:\\pg\\data"'}
        with self.assertRaises(ResourceError):choose_service([row,dict(row,Name='two')],'C:\\pg\\data')
        with self.assertRaises(ResourceError):choose_service([row],'D:\\other')

    def test_postgres_units_are_bytes_not_megabytes(self):
        self.assertEqual(size_bytes({'setting':'1048576','unit':'8kB'}),8*1024**3)
        self.assertEqual(size_bytes({'setting':'8192','unit':'MB'}),8*1024**3)
        self.assertEqual(size_bytes({'setting':'2048','unit':'8kB'}),16*1024**2)

    def test_offline_config_restore_is_exact_and_rejects_external_edits(self):
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp);target=root/'postgresql.auto.conf';backup=root/'before.conf'
            original=b"# original\nshared_buffers='128MB'\nother_setting='keep me'\n"
            backup.write_bytes(original);target.write_bytes(b"shared_buffers='8GB'\n")
            state={'data':str(root),'backup_file':str(backup),'before_hash':digest(backup),'after_hash':digest(target)}
            restore_local(state)
            self.assertEqual(target.read_bytes(),original)
            target.write_bytes(b"# changed by administrator\n")
            with self.assertRaisesRegex(ResourceError,'config_changed_externally'):restore_local(state)
            self.assertEqual(target.read_bytes(),b"# changed by administrator\n")

    def test_corrupt_backup_is_not_written_to_server(self):
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp);target=root/'postgresql.auto.conf';backup=root/'before.conf'
            target.write_bytes(b'new');backup.write_bytes(b'old')
            state={'data':str(root),'backup_file':str(backup),'before_hash':digest(backup),'after_hash':digest(target)}
            backup.write_bytes(b'corrupt')
            with self.assertRaisesRegex(ResourceError,'config_backup_corrupt'):restore_local(state)
            self.assertEqual(target.read_bytes(),b'new')

    def test_only_approved_parameters_and_parameter_specific_reset(self):
        class Connection:
            def __init__(self):self.statements=[]
            def execute(self,statement):self.statements.append(statement.as_string())
        conn=Connection()
        set_setting(conn,'shared_buffers','8GB');set_setting(conn,'min_wal_size',None)
        self.assertIn('8GB',conn.statements[0]);self.assertIn('RESET "min_wal_size"',conn.statements[1])
        self.assertFalse(any('RESET ALL' in s for s in conn.statements))
        with self.assertRaises(ResourceError):set_setting(conn,'fsync','off')
        self.assertEqual(set(TARGETS),{'shared_buffers','wal_buffers','max_wal_size','min_wal_size'})

    def test_connected_recovery_preserves_unrelated_configuration(self):
        class Connection:
            def __enter__(self):return self
            def __exit__(self,*args):pass
            def execute(self,statement):pass
        before={name:{'setting':str(n),'unit':'MB','pending_restart':False} for name,n in
                [('shared_buffers',128),('wal_buffers',4),('max_wal_size',1024),('min_wal_size',80)]}
        state={'identity':'server-one','before_overrides':{'shared_buffers':'128MB'},
               'settings':before,'service':'selected-service'}
        writes=[]
        with tempfile.TemporaryDirectory() as temp, patch('tools.apply_postgres_resources.connect',return_value=Connection()), \
                patch('tools.apply_postgres_resources.snapshot',return_value={'identity':'server-one'}), \
                patch('tools.apply_postgres_resources.overrides',return_value=dict(TARGETS)), \
                patch('tools.apply_postgres_resources.set_setting',side_effect=lambda c,n,v:writes.append((n,v))), \
                patch('tools.apply_postgres_resources.restart_service') as restart, \
                patch('tools.apply_postgres_resources.wait_ready',return_value={'settings':before}):
            recover({},state,Path(temp)/'state.json')
        self.assertEqual(dict(writes),{'shared_buffers':'128MB','wal_buffers':None,'max_wal_size':None,'min_wal_size':None})
        restart.assert_called_once_with('selected-service')

    def test_connected_recovery_refuses_changed_server_identity(self):
        class Connection:
            def __enter__(self):return self
            def __exit__(self,*args):pass
        with patch('tools.apply_postgres_resources.connect',return_value=Connection()), \
                patch('tools.apply_postgres_resources.snapshot',return_value={'identity':'different'}), \
                patch('tools.apply_postgres_resources.set_setting') as modify:
            with self.assertRaisesRegex(ResourceError,'server_identity_changed'):
                recover({}, {'identity':'original'},Path('unused'))
            modify.assert_not_called()

    def test_failed_resource_application_never_starts_live_probe(self):
        import json
        with tempfile.TemporaryDirectory() as folder:
            output=Path(folder)/'result.json'
            with patch('tools.apply_postgres_resources.require_admin'), \
                    patch('tools.apply_postgres_resources.load_viewer_database',return_value={'host':'127.0.0.1'}), \
                    patch('tools.apply_postgres_resources.check',return_value={'status':'READY_TO_START'}), \
                    patch('tools.apply_postgres_resources.checkpoint',return_value={'generation':48}), \
                    patch('tools.apply_postgres_resources.apply',side_effect=ResourceError('new_postgres_config_error')), \
                    patch('tools.apply_postgres_resources.probe') as run_probe:
                result=main(['--config','unused.py','--probe','--out',str(output)])
            self.assertEqual(result,2)
            self.assertEqual(json.loads(output.read_text())['status'],'FAILED')
            run_probe.assert_not_called()

    def test_successful_resource_application_preserves_checkpoint_and_then_probes_once(self):
        import json
        with tempfile.TemporaryDirectory() as folder:
            output=Path(folder)/'result.json'
            def run_probe(args):
                path=Path(args[args.index('--out')+1]);path.parent.mkdir(parents=True,exist_ok=True)
                path.write_text(json.dumps({'status':'PUBLISHED_UNDER_BUDGET','checkpoint_consistent':True}))
            with patch('tools.apply_postgres_resources.require_admin'), \
                    patch('tools.apply_postgres_resources.load_viewer_database',return_value={'host':'127.0.0.1'}), \
                    patch('tools.apply_postgres_resources.check',return_value={'status':'READY_TO_START'}), \
                    patch('tools.apply_postgres_resources.checkpoint',return_value={'generation':48}), \
                    patch('tools.apply_postgres_resources.apply'), \
                    patch('tools.apply_postgres_resources.probe',side_effect=run_probe) as run_once, \
                    patch('tools.apply_postgres_resources.Path',wraps=Path) as paths:
                # Keep the generated intermediate report isolated from release evidence.
                original=Path('validation/d2_resources_one_window.json')
                paths.side_effect=lambda value:Path(folder)/'probe.json' if value==str(original) else Path(value)
                result=main(['--config','unused.py','--probe','--out',str(output)])
            self.assertEqual(result,0)
            self.assertEqual(json.loads(output.read_text())['status'],'PUBLISHED_UNDER_BUDGET')
            run_once.assert_called_once()


if __name__=='__main__':unittest.main()
