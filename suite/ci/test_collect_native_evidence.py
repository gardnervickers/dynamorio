import json
from pathlib import Path
import tempfile
import unittest

from collect_native_evidence import collect


class CollectorTests(unittest.TestCase):
    def test_tail_and_total_limits_and_manifest(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            logs = root / "native-evidence"
            logs.mkdir()
            (logs / "a.log").write_bytes(b"0123456789")
            (logs / "b.log").write_bytes(b"abcdefghij")
            (logs / "c.log").write_bytes(b"omit")
            artifact = root / "artifact"
            collect(root, artifact, file_limit=6, total_limit=9)
            self.assertEqual((artifact / "native-evidence/a.log").read_bytes(), b"456789")
            self.assertEqual((artifact / "native-evidence/b.log").read_bytes(), b"hij")
            self.assertFalse((artifact / "native-evidence/c.log").exists())
            manifest = json.loads((artifact / "manifest.json").read_text())
            self.assertEqual(manifest["retained_bytes"], 9)
            self.assertTrue(manifest["files"][0]["truncated"])
            self.assertTrue(manifest["files"][2]["omitted"])

    def test_count_limit_and_links_and_unselected_files(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            logs = root / "native-evidence"
            logs.mkdir()
            (logs / "a.log").symlink_to(root / "outside.txt")
            (root / "outside.txt").write_text("outside")
            (logs / "b.log").write_text("one")
            (logs / "c.log").write_text("two")
            (logs / "binary.so").write_bytes(b"binary")
            artifact = root / "artifact"
            collect(root, artifact, count_limit=1)
            self.assertTrue((artifact / "native-evidence/b.log").exists())
            self.assertFalse((artifact / "native-evidence/a.log").exists())
            self.assertFalse((artifact / "native-evidence/c.log").exists())
            self.assertFalse((artifact / "native-evidence/binary.so").exists())


if __name__ == "__main__":
    unittest.main()
