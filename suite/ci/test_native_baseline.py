import json
from pathlib import Path
import tempfile
import unittest

import native_baseline as gate


class NativeGateTests(unittest.TestCase):
    def inventory(self, arch="x86_64"):
        names = gate.SHARED + (gate.ARM if arch == "aarch64" else gate.X86)
        return {"tests": [{"name": "code_api|" + n} for n in names]}

    def test_each_arch_requires_all_named_tests(self):
        for arch, count in (("x86_64", len(gate.SHARED + gate.X86)),
                            ("aarch64", len(gate.SHARED + gate.ARM))):
            self.assertEqual(len(gate.select_tests(self.inventory(arch), arch)), count)

    def test_empty_and_partial_inventory_fail(self):
        for tests in ([], self.inventory()["tests"][:-1]):
            with self.assertRaises(ValueError):
                gate.select_tests({"tests": tests}, "x86_64")

    def test_no_substring_match(self):
        inv = self.inventory()
        inv["tests"][0]["name"] += ".native"
        with self.assertRaises(ValueError):
            gate.select_tests(inv, "x86_64")

    def test_disabled_and_wrong_arch_fail(self):
        inv = self.inventory()
        inv["tests"][0]["properties"] = [{"name": "DISABLED", "value": True}]
        with self.assertRaises(ValueError):
            gate.select_tests(inv, "x86_64")
        with self.assertRaises(ValueError):
            gate.select_tests(self.inventory(), "arm64")

    def test_all_option_variants_selected(self):
        inv = self.inventory()
        inv["tests"].append({"name": "no_code_api|linux.sigaction"})
        self.assertIn("no_code_api|linux.sigaction", gate.select_tests(inv, "x86_64"))

    def test_junit_rejects_skips_failures_missing_duplicate_and_notrun(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "junit.xml"
            for xml in (
                '<testcase name="required" status="run"/>',
                '<testcase name="required" status="run"><skipped/></testcase>',
                '<testcase name="required" status="run"><failure/></testcase>',
                '<testcase name="required" status="run"><error/></testcase>',
                '<testcase name="required" status="notrun"/>',
                '',
                '<testcase name="required" status="run"/>' * 2,
            ):
                path.write_text('<testsuite>' + xml + '</testsuite>')
                if xml == '<testcase name="required" status="run"/>':
                    gate.verify_results(path, ["required"])
                else:
                    with self.assertRaises(ValueError):
                        gate.verify_results(path, ["required"])


if __name__ == "__main__":
    unittest.main()
