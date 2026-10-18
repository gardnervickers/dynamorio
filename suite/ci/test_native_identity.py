"""Model permissible PID recycling without allocating IDs or sending real signals."""
import os
from pathlib import Path
import signal
import sys
import unittest
from unittest import mock

import native_baseline as gate


class ExitedLeader:
    # In production this is an unreaped SessionProcess, not a recycled SID.
    pid = 70001

    def wait(self, timeout):
        return 0


class IdentityTests(unittest.TestCase):
    def test_recycling_never_signals_foreign_task(self):
        # Same TERM/KILL snapshots as the independent R2 reproducer, extended
        # across acquisition/validation/signal. Also runnable against old helper.
        for phase in (signal.SIGTERM, signal.SIGKILL):
            for boundary in ('snapshot', 'open', 'stat', 'validated', 'signal'):
                with self.subTest(phase=phase.name, boundary=boundary):
                    self.recycling(phase, boundary)

    def recycling(self, phase, boundary):
        pid = 70002
        current = 'owned'
        handles = {}
        signalled = []
        calls = 0

        def recycle():
            nonlocal current
            current = 'foreign'

        def snapshot(session):
            nonlocal calls
            self.assertEqual(session, ExitedLeader.pid)
            calls += 1
            if calls == (1 if phase == signal.SIGTERM else 2):
                if boundary == 'snapshot':
                    recycle()
                return {pid: pid}
            return {}

        def acquire(requested):
            self.assertEqual(requested, pid)
            handles[999] = current
            if boundary == 'open':
                recycle()
            return 999

        def stat(path):
            self.assertEqual(path, Path(f'/proc/{pid}/stat'))
            sid = ExitedLeader.pid if current == 'owned' else 80001
            data = f'{pid} (name with ) spaces) S 1 {pid} {sid} 0'.encode()
            if boundary == 'stat':
                recycle()
            return data

        def ready(fds, *_):
            result = [fd for fd in fds if handles[fd] != current]
            if boundary == 'validated':
                recycle()
            return result, [], []

        def pidfd_signal(fd, sig):
            if handles[fd] != current:
                raise ProcessLookupError()
            signalled.append((handles[fd], sig))
            if boundary == 'signal':
                recycle()

        def numeric_signal(group, sig):
            self.assertEqual(group, pid)
            signalled.append((current, sig))

        with mock.patch.object(gate, 'session_members', side_effect=snapshot), \
                mock.patch.object(gate.os, 'pidfd_open', side_effect=acquire), \
                mock.patch.object(Path, 'read_bytes', stat), \
                mock.patch.object(gate.select, 'select', side_effect=ready), \
                mock.patch.object(gate.signal, 'pidfd_send_signal', side_effect=pidfd_signal), \
                mock.patch.object(gate.os, 'killpg', side_effect=numeric_signal), \
                mock.patch.object(gate.os, 'close'):
            gate.terminate_session(ExitedLeader())
        self.assertNotIn('foreign', [owner for owner, _ in signalled])
        # Validation cannot simply disable cleanup: a live validated owner gets
        # the requested signal; after it exits the same descriptor cannot hit reuse.
        self.assertEqual(signalled, [('owned', phase)] if boundary == 'signal' else [])

    def test_completed_leader_is_waitable_until_cleanup_finishes(self):
        terminate = gate.terminate_session
        observed = []

        def cleanup(process):
            self.assertEqual(process.returncode, 7)
            for operation in (process.poll, process.wait, process._internal_poll,
                              process._wait):
                self.assertEqual(operation(), 7)
                status = os.waitid(os.P_PID, process.pid,
                                   os.WEXITED | os.WNOWAIT | os.WNOHANG)
                self.assertEqual(status.si_pid, process.pid)
                self.assertEqual(os.getsid(process.pid), process.pid)
            observed.append(process.pid)
            terminate(process)
            self.assertEqual(os.waitid(os.P_PID, process.pid,
                                       os.WEXITED | os.WNOWAIT).si_pid, process.pid)

        with mock.patch.object(gate, 'terminate_session', side_effect=cleanup):
            result = gate.run_bounded([sys.executable, '-c', 'raise SystemExit(7)'],
                                      timeout=30, description='anchor')
        self.assertEqual(result.returncode, 7)
        self.assertEqual(len(observed), 1)
        with self.assertRaises(ChildProcessError):
            os.waitid(os.P_PID, observed[0], os.WEXITED | os.WNOHANG)

    def test_ignored_sigchld_rejected_before_launch(self):
        with mock.patch.object(gate.signal, 'getsignal', return_value=signal.SIG_IGN), \
                mock.patch.object(gate, 'SessionProcess') as launch:
            with self.assertRaisesRegex(RuntimeError, 'waitable children'):
                gate.run_bounded(['unused'], timeout=30, description='invalid waiter')
            launch.assert_not_called()

    def test_cleanup_failure_is_not_success_and_reaps_anchor(self):
        seen = []

        def fail(process):
            seen.append(process.pid)
            raise TimeoutError('cleanup failed')

        with mock.patch.object(gate, 'terminate_session', side_effect=fail):
            with self.assertRaisesRegex(TimeoutError, 'cleanup failed'):
                gate.run_bounded([sys.executable, '-c', 'pass'],
                                 timeout=30, description='cleanup-error')
        with self.assertRaises(ChildProcessError):
            os.waitid(os.P_PID, seen[0], os.WEXITED | os.WNOHANG)


if __name__ == '__main__':
    unittest.main()
