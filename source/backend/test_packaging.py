import importlib.util
from pathlib import Path
import tempfile
import unittest

spec = importlib.util.spec_from_file_location('assemble', Path(__file__).resolve().parents[2] / 'work' / 'assemble.py')
assembly = importlib.util.module_from_spec(spec)
spec.loader.exec_module(assembly)

class PackagingTests(unittest.TestCase):
    def test_rebuild_discards_stale_files(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            for relative in ('work/native-ui', 'work/backend-python/KdbxBackend', 'work/package/Provider', 'source/upstream/src/KeePassPasskeyProvider.Package/Assets'):
                target = root / relative
                target.mkdir(parents=True)
                (target / 'fixture.txt').write_text('new')
                (target / 'runtime.dll').write_bytes(b'fixture-runtime')
                (target / 'native.PDB').write_bytes(b'fixture-symbols')
            (root / 'source/upstream/LICENSE').write_text('fixture')
            staging = root / 'work/package-native'
            staging.mkdir()
            (staging / 'obsolete.dll').write_text('old')
            assembly.assemble(root)
            self.assertFalse((staging / 'obsolete.dll').exists())
            self.assertEqual((staging / 'Backend/fixture.txt').read_text(), 'new')
            self.assertTrue((staging / 'AppxManifest.xml').is_file())
            for relative in ('', 'Provider', 'Backend'):
                self.assertFalse((staging / relative / 'native.PDB').exists())
                self.assertEqual((staging / relative / 'runtime.dll').read_bytes(), b'fixture-runtime')
            self.assertTrue((root / 'work/package/Provider/native.PDB').exists())
