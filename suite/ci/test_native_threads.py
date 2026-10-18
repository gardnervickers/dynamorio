"""Real pthread_exit descendants: leader state is not process exit evidence."""
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


class NativeThreadTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.directory = tempfile.TemporaryDirectory(prefix='dr-ci-threads-')
        cls.addClassCleanup(cls.directory.cleanup)
        cls.fixture = Path(cls.directory.name) / 'thread_fixture'
        subprocess.run([os.environ.get('CC', 'cc'), '-pthread',
                        str(Path(__file__).with_name('native_thread_fixture.c')),
                        '-o', str(cls.fixture)], check=True)

    def check_cleanup(self, timeout_mode):
        with tempfile.TemporaryDirectory(prefix='dr-ci-thread-sock-') as directory, \
                socket.socket(socket.AF_UNIX) as listener:
            address = str(Path(directory) / 'ready.sock')
            listener.bind(address)
            listener.listen()
            listener.settimeout(30)
            original = gate.SessionProcess
            state = {}

            def launch(*args, **kwargs):
                process = original(*args, **kwargs)
                state['process'] = process
                communicate = process.communicate

                def ready(**kw):
                    connection, _ = listener.accept()
                    state['connection'] = connection
                    connection.settimeout(30)
                    with connection.makefile('rb') as stream:
                        pid = int(stream.readline())
                    state['fd'] = os.pidfd_open(pid)
                    fields = gate.process_fields(Path('/proc') / str(pid))
                    self.assertEqual(fields[0], b'Z')
                    self.assertEqual(int(fields[3]), process.pid)
                    # Positive response proves a live worker AFTER main exited.
                    connection.sendall(b'?')
                    with connection.makefile('rb') as stream:
                        self.assertEqual(stream.readline(), b'alive\n')
                    return communicate(timeout=0) if timeout_mode else communicate(**kw)

                process.communicate = ready
                return process

            code = ('import subprocess,sys; subprocess.Popen(sys.argv[1:], '
                    'stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, '
                    'stderr=subprocess.DEVNULL)')
            if timeout_mode:
                code += '; import signal; signal.pause()'
            try:
                with mock.patch.object(gate, 'SessionProcess', side_effect=launch):
                    command = [sys.executable, '-c', code, str(self.fixture), address]
                    if timeout_mode:
                        with self.assertRaisesRegex(TimeoutError, '30-second deadline'):
                            gate.run_bounded(command, timeout=30, description='thread fixture')
                    else:
                        result = gate.run_bounded(command, timeout=30,
                                                  description='thread fixture')
                        self.assertEqual(result.returncode, 0)
                # Positive whole-thread-group exit, not a timed absence of output.
                self.assertTrue(select.select([state['fd']], [], [], 30)[0],
                                'worker thread survived cleanup')
                self.assertEqual(gate.session_members(state['process'].pid), {})
            finally:
                if 'fd' in state:
                    try:
                        signal.pidfd_send_signal(state['fd'], signal.SIGKILL)
                    except ProcessLookupError:
                        pass
                    self.assertTrue(select.select([state['fd']], [], [], 30)[0])
                    os.close(state['fd'])
                if 'connection' in state:
                    state['connection'].close()

    def test_success_retires_descendant_with_exited_main_thread(self):
        self.check_cleanup(timeout_mode=False)

    def test_timeout_retires_descendant_with_exited_main_thread(self):
        self.check_cleanup(timeout_mode=True)


if __name__ == '__main__':
    unittest.main()
