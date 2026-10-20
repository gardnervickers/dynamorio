"""Synthetic failure evidence tests; no JVM or translated application runs."""
from contextlib import redirect_stderr, redirect_stdout
import io
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import run


class FailureEvidence(unittest.TestCase):
    def test_translated_diagnostics_record_nmethod_addresses(self):
        directory = Path("/phase/translated")
        self.assertEqual(
            run.hotspot_diagnostics(directory),
            ["-XX:+UnlockDiagnosticVMOptions", "-XX:+LogCompilation",
             "-XX:LogFile=/phase/translated/hotspot.log"],
        )

    def test_retains_failure_before_cleanup_with_finite_text(self):
        with tempfile.TemporaryDirectory() as reports:
            error = RuntimeError("original failed oracle")
            with patch.dict(os.environ, {"SEEDBOX_TEST_REPORT_DIR": reports}):
                with self.assertRaises(RuntimeError) as raised:
                    with run.working_directory("jfr-default-seed1") as base:
                        directory = base / "translated"
                        directory.mkdir()
                        (directory / "jvm.log").write_bytes(
                            b"HEAD" + b"x" * (2 * run.DIAGNOSTIC_LIMIT) + b"TAIL")
                        (directory / "hotspot.log").write_text(
                            '<nmethod compile_id="72" address="0x7f0012345000"/>')
                        (directory / "hs_err_123.log").write_text("actual JVM crash report")
                        (directory / "command.json").write_text(json.dumps(["java", "-XX:+UseZGC"]))
                        (directory / "core.123").write_bytes(b"not text evidence")
                        (directory / "hs_err_link.log").symlink_to(directory / "core.123")
                        raise error
            self.assertIs(raised.exception, error)
            self.assertFalse(base.exists())
            retained, = Path(reports).iterdir()
            phase = retained / "translated"
            self.assertEqual({p.name for p in phase.iterdir()},
                             {"jvm.log", "hotspot.log", "hs_err_123.log", "command.json"})
            log = (phase / "jvm.log").read_bytes()
            self.assertLessEqual(len(log), run.DIAGNOSTIC_LIMIT)
            self.assertTrue(log.startswith(b"HEAD") and log.endswith(b"TAIL"))
            self.assertIn(b"truncated", log)
            self.assertEqual((phase / "hs_err_123.log").read_text(), "actual JVM crash report")
            self.assertIn("0x7f0012345000", (phase / "hotspot.log").read_text())

    def test_success_removes_scratch_and_retains_nothing(self):
        with tempfile.TemporaryDirectory() as reports:
            with patch.dict(os.environ, {"SEEDBOX_TEST_REPORT_DIR": reports}):
                with run.working_directory("jfr-default-seed1") as base:
                    (base / "jvm.log").write_text("successful scratch")
            self.assertFalse(base.exists())
            self.assertEqual(list(Path(reports).iterdir()), [])

    def test_unavailable_report_directory_preserves_original_exception(self):
        for report in (None, "/dev/null/not-a-directory"):
            with self.subTest(report=report):
                with patch.dict(os.environ, {}, clear=True):
                    if report is not None:
                        os.environ["SEEDBOX_TEST_REPORT_DIR"] = report
                    with self.assertRaisesRegex(ValueError, "original failure"):
                        with run.working_directory("jfr-default-seed1"):
                            raise ValueError("original failure")

    def test_failed_child_and_timeout_remain_failures(self):
        with tempfile.TemporaryDirectory() as reports:
            with patch.dict(os.environ, {"SEEDBOX_TEST_REPORT_DIR": reports}):
                for result in ((255, "", "internal crash"), TimeoutError("phase timeout")):
                    with self.subTest(result=result):
                        with patch.object(run, "execute_phase") as execute:
                            if isinstance(result, Exception):
                                execute.side_effect = result
                                failure = TimeoutError
                            else:
                                execute.return_value = result
                                failure = AssertionError
                            with self.assertRaises(failure):
                                with run.working_directory("jfr-default-seed1") as base:
                                    phase = base / "translated"
                                    phase.mkdir()
                                    (phase / "jvm.log").write_text("last JIT event")
                                    run.execute(Path("/unused"), ["java", "-XX:+UseZGC"], phase)
                self.assertEqual(len(list(Path(reports).glob("*/translated/jvm.log"))), 2)


if __name__ == "__main__":
    # The prepared fixture adapter supplies ROOT and a human-readable label.
    # unittest owns only its own arguments; no stress scenario is executed.
    with redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
        result = unittest.TextTestRunner().run(unittest.defaultTestLoader.loadTestsFromTestCase(FailureEvidence))
    if not result.wasSuccessful():
        for _, detail in result.errors + result.failures:
            print(detail)
        raise SystemExit(1)
    print(f"jvm diagnostics: PASS ({result.testsRun} synthetic checks)")
