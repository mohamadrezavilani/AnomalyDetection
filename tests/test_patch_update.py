import hashlib
import importlib.util
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

SPEC=importlib.util.spec_from_file_location('batch2h_patch_support',Path(__file__).resolve().parents[1]/'tools/batch2h_patch_support.py')
SUPPORT=importlib.util.module_from_spec(SPEC);SPEC.loader.exec_module(SUPPORT)


class PatchUpdateTests(unittest.TestCase):
    def item(self,name,old,new):
        sha=lambda b:hashlib.sha256(b).hexdigest() if b is not None else None
        return dict(path=name,old_sha256=sha(old),new_sha256=sha(new.encode()),content=new)

    def test_modified_file_blocks_every_write(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);(root/'one.py').write_bytes(b'expected');(root/'two.py').write_bytes(b'local edit')
            files=[self.item('one.py',b'expected','first = 1\n'),self.item('two.py',b'baseline','second = 2\n')]
            with self.assertRaises(SUPPORT.PatchError):SUPPORT.install_files(root,files)
            self.assertEqual((root/'one.py').read_bytes(),b'expected')
            self.assertFalse((root/'private').exists())

    def test_backup_preserves_bytes_and_reapply_is_idempotent(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);(root/'one.py').write_bytes(b'# original\r\n')
            files=[self.item('one.py',b'# original\r\n','value = 1\n'),self.item('tests/new.py',None,'value = 2\n')]
            backup=SUPPORT.install_files(root,files)
            self.assertEqual((backup/'one.py').read_bytes(),b'# original\r\n')
            self.assertEqual((root/'tests/new.py').read_text(),'value = 2\n')
            self.assertIsNone(SUPPORT.install_files(root,files))

    def test_file_write_failure_restores_previously_written_files(self):
        for use_alias in (False,True):
            with self.subTest(noncanonical_path=use_alias),tempfile.TemporaryDirectory() as tmp:
                root=Path(tmp)
                if use_alias:
                    (root/'path-alias').mkdir()
                    root=root/'path-alias'/'..'
                (root/'one.py').write_bytes(b'# old one');(root/'two.py').write_bytes(b'# old two')
                files=[self.item('one.py',b'# old one','value = 1\n'),self.item('two.py',b'# old two','value = 2\n')]
                second=(root/'two.py').resolve();injected=[]
                original=SUPPORT.atomic_write
                def fail_second(path,data):
                    if path.resolve()==second and data==b'value = 2\n':
                        # Verify a real partial update before forcing rollback.
                        self.assertEqual((root/'one.py').read_bytes(),b'value = 1\n')
                        injected.append(path)
                        raise OSError('injected write failure')
                    return original(path,data)
                with patch.object(SUPPORT,'atomic_write',side_effect=fail_second):
                    with self.assertRaises(SUPPORT.PatchError):SUPPORT.install_files(root,files)
                self.assertEqual(len(injected),1,'The intended file-write failure must actually fire.')
                self.assertEqual((root/'one.py').read_bytes(),b'# old one')
                self.assertEqual((root/'two.py').read_bytes(),b'# old two')

    def test_application_database_is_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp)
            for relative in ['p24_foundation/config.py','tools/run_tests.py']:
                p=root/relative;p.parent.mkdir(parents=True,exist_ok=True);p.touch()
            (root/'db_config.local.py').write_text("DATABASE={'host':'127.0.0.1','dbname':'pishkhan24_shadow'}\n")
            with self.assertRaises(SUPPORT.PatchError):SUPPORT.validate_test_target(root)
