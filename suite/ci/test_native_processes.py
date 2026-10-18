"""Real Linux process trees; deadlines are forced only after positive readiness."""
import contextlib
import io
import json
import os
from pathlib import Path
import select
import signal
import socket
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

import native_baseline as gate


FIXTURE = """
import json
import os
import signal
import socket
import sys

signal.signal(signal.SIGTERM, signal.SIG_IGN if sys.argv[2] == 'ignore' else signal.SIG_DFL)
signal.signal(signal.SIGUSR1, lambda *_: sys.exit(0))
leader = os.getpid()
if os.fork() == 0:
    signal.signal(signal.SIGTERM, signal.SIG_IGN)
    if sys.argv[3] == 'regroup':
        os.setpgid(0, 0)
    if os.fork() == 0:
        with socket.socket(socket.AF_UNIX) as ready:
            ready.connect(sys.argv[1])
            ready.sendall((json.dumps([leader, os.getppid(), os.getpid()]) + '\\n').encode())
    while True:
        signal.pause()
while True:
    signal.pause()
"""


class NativeProcessTests(unittest.TestCase):
    @contextlib.contextmanager
    def tree(self, *, ignore_term=False, successful_leader=False, real_ctest=False,
             new_group=False):
        with tempfile.TemporaryDirectory(prefix="dr-ci-process-") as directory:
            root = Path(directory)
            fixture = root / "fixture.py"
            fixture.write_text(FIXTURE)
            address = str(root / "ready.sock")
            with socket.socket(socket.AF_UNIX) as ready:
                ready.bind(address)
                ready.listen(1)
                ready.settimeout(30)
                command = [sys.executable, str(fixture), address,
                           "ignore" if ignore_term else "default",
                           "regroup" if new_group else "inherit"]
                if real_ctest:
                    args = " ".join('"' + arg + '"' for arg in command)
                    (root / "CTestTestfile.cmake").write_text(f"add_test(required {args})\n")
                    command = ["ctest", "--test-dir", str(root), "--no-tests=error", "-Q"]
                state = {"root": root, "command": command, "signals": [], "pidfds": []}
                original_popen = subprocess.Popen
                original_killpg = os.killpg

                def launch(requested, **kwargs):
                    self.assertTrue(kwargs.get("start_new_session"),
                                    "fixtures must never join the test runner's session")
                    state["requested"] = requested
                    process = original_popen(command, **kwargs)
                    state["process"] = process
                    communicate = process.communicate

                    def after_readiness(*, timeout):
                        with ready.accept()[0] as connection:
                            connection.settimeout(30)
                            with connection.makefile("r") as stream:
                                pids = json.loads(stream.readline())
                        # Open exit signals while every fixture is known to be alive.
                        state["pidfds"] = [os.pidfd_open(pid) for pid in pids]
                        state["pids"] = pids
                        if successful_leader:
                            os.kill(pids[0], signal.SIGUSR1)
                            return communicate(timeout=30)
                        # Exercise Popen's real TimeoutExpired path after readiness,
                        # without assuming that startup finishes within a short timer.
                        return communicate(timeout=0)

                    process.communicate = after_readiness
                    return process

                def record_signal(group, sig):
                    process = state["process"]
                    self.assertIn(group, [process.pid] + state.get("pids", []))
                    self.assertNotEqual(group, os.getpgrp())
                    state["signals"].append((sig, process.poll()))
                    return original_killpg(group, sig)

                try:
                    with mock.patch.object(gate.subprocess, "Popen", side_effect=launch), \
                            mock.patch.object(gate.os, "killpg", side_effect=record_signal):
                        yield state
                finally:
                    # Clean only this test's group, including when a regression makes
                    # a positive exit wait fail. Never signal the test runner's group.
                    process = state.get("process")
                    if process is not None:
                        for group in {process.pid} | set(state.get("pids", [])):
                            try:
                                original_killpg(group, signal.SIGKILL)
                            except ProcessLookupError:
                                pass
                        process.wait(timeout=30)
                    for fd in state["pidfds"]:
                        os.close(fd)

    def assert_tree_exited(self, state):
        pending = set(state["pidfds"])
        self.assertEqual(len(pending), 3)
        while pending:
            exited, _, _ = select.select(list(pending), [], [], 30)
            self.assertTrue(exited, "fixture exit signal did not arrive")
            pending.difference_update(exited)
        signals = [sig for sig, _ in state["signals"]]
        self.assertIn(signal.SIGTERM, signals)
        self.assertIn(signal.SIGKILL, signals)

    def test_timeout_kills_children_after_leader_exits(self):
        with self.tree() as state:
            with self.assertRaisesRegex(TimeoutError, "regression.*5400-second deadline"):
                gate.run_bounded(state["command"], timeout=5400,
                                 description="regression")
            self.assertEqual(state["signals"][-1][1], -signal.SIGTERM)
            self.assert_tree_exited(state)

    def test_timeout_escalates_when_leader_ignores_term(self):
        with self.tree(ignore_term=True) as state, \
                mock.patch.object(gate, "TERMINATE_GRACE", 0):
            with self.assertRaises(TimeoutError):
                gate.run_bounded(state["command"], timeout=5400, description="regression")
            self.assertEqual(state["process"].returncode, -signal.SIGKILL)
            self.assert_tree_exited(state)

    def test_timeout_retires_descendants_that_create_another_group(self):
        with self.tree(new_group=True) as state:
            with self.assertRaises(TimeoutError):
                gate.run_bounded(state["command"], timeout=5400, description="regression")
            self.assertEqual(state["signals"][-1][1], -signal.SIGTERM)
            self.assert_tree_exited(state)

    def test_successful_leader_still_retires_descendants(self):
        with self.tree(successful_leader=True) as state:
            result = gate.run_bounded(state["command"], timeout=5400,
                                      description="regression")
            self.assertEqual(result.returncode, 0)
            self.assertEqual(state["signals"][-1][1], 0)
            self.assert_tree_exited(state)

    def test_real_ctest_timeout_retires_test_child_and_grandchild(self):
        with self.tree(real_ctest=True) as state:
            with self.assertRaises(TimeoutError):
                gate.run_bounded(state["command"], timeout=5400, description="CTest")
            self.assert_tree_exited(state)

    def test_inventory_timeout_is_bounded_and_retires_descendants(self):
        with self.tree() as state, \
                mock.patch.object(sys, "argv", ["gate", str(state["root"]),
                                               str(state["root"] / "evidence"), "x86_64"]), \
                mock.patch.object(gate.platform, "machine", return_value="x86_64"):
            with self.assertRaisesRegex(TimeoutError, "CTest inventory.*60-second deadline"):
                gate.main()
            self.assertIn("--show-only=json-v1", state["requested"])
            self.assert_tree_exited(state)

    def test_captured_output_and_nonzero_status_are_preserved(self):
        result = gate.run_bounded(
            [sys.executable, "-c", "print('inventory-error'); raise SystemExit(7)"],
            timeout=30, description="inventory", capture_output=True)
        self.assertEqual(result.returncode, 7)
        self.assertEqual(result.stdout, "inventory-error\n")

    def test_inventory_failure_stops_before_selection(self):
        with tempfile.TemporaryDirectory() as directory, \
                mock.patch.object(sys, "argv", ["gate", directory, directory, "x86_64"]), \
                mock.patch.object(gate.platform, "machine", return_value="x86_64"), \
                mock.patch.object(gate, "run_bounded", return_value=
                                  subprocess.CompletedProcess([], 7, "bad inventory")) as run, \
                contextlib.redirect_stderr(io.StringIO()) as stderr:
            with self.assertRaises(SystemExit) as error:
                gate.main()
            self.assertEqual(error.exception.code, 7)
            self.assertIn("CTest inventory failed (exit 7)", stderr.getvalue())
            self.assertEqual(run.call_count, 1)
            self.assertEqual(run.call_args.kwargs["timeout"], gate.INVENTORY_TIMEOUT)

    def test_ctest_failure_propagates_even_with_passing_junit(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            inventory = json.dumps({"tests": [{"name": "required"}]})

            def run(command, **kwargs):
                if "--show-only=json-v1" in command:
                    return subprocess.CompletedProcess(command, 0, inventory)
                (root / "junit.xml").write_text(
                    '<testsuite><testcase name="required" status="run"/></testsuite>')
                return subprocess.CompletedProcess(command, 7)

            with mock.patch.object(sys, "argv", ["gate", directory, directory, "x86_64"]), \
                    mock.patch.object(gate.platform, "machine", return_value="x86_64"), \
                    mock.patch.object(gate, "SHARED", ("required",)), \
                    mock.patch.object(gate, "X86", ()), \
                    mock.patch.object(gate, "run_bounded", side_effect=run), \
                    contextlib.redirect_stdout(io.StringIO()):
                with self.assertRaises(SystemExit) as error:
                    gate.main()
                self.assertEqual(error.exception.code, 7)


if __name__ == "__main__":
    unittest.main()
