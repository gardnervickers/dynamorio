"""Bounded native CI regression gate, not the full precommit suite."""
import json
import os
from pathlib import Path
import platform
import re
import select
import signal
import subprocess
import sys
import time
import xml.etree.ElementTree as ET

# Existing release_11.3.0-1 tests, not the historical fork's extra tests.
SHARED = (
    "common.getretaddr", "api.ir", "api.ir_regdeps", "api.ir-static",
    "api.detach", "api.detach_signal", "linux.sigaction", "linux.sigmask",
    "linux.sigsuspend", "linux.signest", "linux.signal_pre_syscall",
    "linux.signal_racesys", "pthreads.ptsig", "client.signal",
    "client.cleancallsig", "client.mangle_suspend", "client.drmgr-test",
    "client.drreg-test", "client.drwrap-drreg-test",
)
X86 = ("linux.sigcontext", "linux.synchall-restore")
ARM = ("client.ldstex", "api.ir_v80", "api.ir_v81", "api.opnd")

INVENTORY_TIMEOUT = 60
TEST_TIMEOUT = 5400
TERMINATE_GRACE = 5
KILL_GRACE = 5


class SessionProcess(subprocess.Popen):
    """Observe completion without reaping our session-ID ownership anchor.

    This single-threaded helper is the child's sole waiter. communicate() calls
    wait(), so both wait and poll must leave the leader (even a zombie) attached
    until cleanup has finished. A pidfd alone does NOT reserve a numeric PID.
    """

    def poll(self):
        if self.returncode is None:
            status = os.waitid(os.P_PID, self.pid,
                               os.WEXITED | os.WNOHANG | os.WNOWAIT)
            if status is not None:
                self.returncode = (status.si_status if status.si_code == os.CLD_EXITED
                                   else -status.si_status)
        return self.returncode

    def wait(self, timeout=None):
        if self.returncode is not None:
            return self.returncode
        with_pidfd = os.pidfd_open(self.pid)
        try:
            if self.poll() is None:
                if not select.select([with_pidfd], [], [],
                                     None if timeout is None else max(0, timeout))[0]:
                    raise subprocess.TimeoutExpired(self.args, timeout)
            return self.poll()
        finally:
            os.close(with_pidfd)

    # Popen's KeyboardInterrupt and destructor paths use these internal hooks.
    _wait = wait

    def _internal_poll(self, _deadstate=None):
        return self.poll()

    def reap(self):
        # Called only after the last session scan/signal, including on failure.
        self.wait(timeout=KILL_GRACE)
        os.waitpid(self.pid, 0)


def session_members(session):
    """Snapshot candidates only; numeric identities are never signal targets."""
    members = {}
    for entry in Path("/proc").iterdir():
        if not entry.name.isdecimal():
            continue
        fields = process_fields(entry)
        if fields and int(fields[3]) == session and fields[0] not in (b"Z", b"X"):
            members[int(entry.name)] = int(fields[2])
    return members


def process_fields(entry):
    try:
        stat = (entry / "stat").read_bytes()
    except (FileNotFoundError, ProcessLookupError, PermissionError):
        return None
    # comm can itself contain spaces or ')'.
    return stat[stat.rfind(b")") + 2:].split()


def owned_pidfd(pid, session):
    """Acquire identity BEFORE validation, then prove it survived that read.

    If the number recycled before open, membership rejects the replacement.
    If it recycled between open and stat, the old pidfd is readable and rejected.
    After validation, pidfd_send_signal can only signal the validated task, even
    if it exits and its number is reused. The unreaped leader reserves the SID.
    """
    try:
        fd = os.pidfd_open(pid)
    except ProcessLookupError:
        return None
    try:
        fields = process_fields(Path("/proc") / str(pid))
        if (fields and int(fields[3]) == session and fields[0] not in (b"Z", b"X")
                and not select.select([fd], [], [], 0)[0]):
            return fd
    except BaseException:
        os.close(fd)
        raise
    os.close(fd)
    return None


def signal_members(session, members, sig):
    exits = []
    try:
        for pid in members:
            fd = owned_pidfd(pid, session)
            if fd is not None:
                exits.append(fd)
                try:
                    signal.pidfd_send_signal(fd, sig)
                except ProcessLookupError:
                    pass
        return exits
    except BaseException:
        for fd in exits:
            os.close(fd)
        raise


def terminate_session(process):
    """Retire session members while the unreaped leader anchors ownership."""
    try:
        exits = signal_members(process.pid, session_members(process.pid), signal.SIGTERM)
        for fd in exits:
            os.close(fd)
        try:
            process.wait(timeout=TERMINATE_GRACE)
        except subprocess.TimeoutExpired:
            pass
    finally:
        # drrun -killpg creates another group. Rescan after exits/signals to
        # include those groups and children forked during TERM handling.
        deadline = time.monotonic() + KILL_GRACE
        while members := session_members(process.pid):
            exits = signal_members(process.pid, members, signal.SIGKILL)
            try:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise TimeoutError("owned CTest session did not exit after SIGKILL")
                if exits:
                    select.select(exits, [], [], remaining)
            finally:
                for fd in exits:
                    os.close(fd)
        process.wait(timeout=max(0, deadline - time.monotonic()))


def run_bounded(command, *, timeout, description, capture_output=False):
    """Bound a Linux command and retire its private session on every exit path."""
    if signal.getsignal(signal.SIGCHLD) == signal.SIG_IGN:
        raise RuntimeError("CTest session ownership requires waitable children (SIGCHLD)")
    process = SessionProcess(
        command, start_new_session=True, text=True,
        stdout=subprocess.PIPE if capture_output else None)
    try:
        try:
            output, _ = process.communicate(timeout=timeout)
        except subprocess.TimeoutExpired:
            raise TimeoutError(
                f"{description} exceeded its {timeout}-second deadline; "
                "terminating its process session") from None
        return subprocess.CompletedProcess(command, process.returncode, output)
    finally:
        try:
            terminate_session(process)
        finally:
            try:
                process.reap()
            finally:
                if process.stdout is not None:
                    process.stdout.close()


def select_tests(inventory, arch):
    if arch not in ("x86_64", "aarch64"):
        raise ValueError(f"unsupported architecture: {arch}")
    required = SHARED + (ARM if arch == "aarch64" else X86)
    selected = []
    for base in required:
        matches = [t for t in inventory["tests"]
                   if t["name"] == base or t["name"].endswith("|" + base)]
        if not matches:
            raise ValueError(f"required test is not registered: {base}")
        for test in matches:
            props = {p["name"]: p["value"] for p in test.get("properties", [])}
            if props.get("DISABLED"):
                raise ValueError(f"required test is disabled: {test['name']}")
            selected.append(test["name"])
    return sorted(set(selected))


def verify_results(path, selected):
    cases = ET.parse(path).getroot().findall(".//testcase")
    names = [case.get("name") for case in cases]
    if sorted(names) != sorted(selected):
        raise ValueError(f"JUnit inventory mismatch: expected {selected}, got {names}")
    for case in cases:
        if (case.get("status") != "run" or
                any(case.find(tag) is not None for tag in ("skipped", "failure", "error"))):
            raise ValueError(f"required test did not pass: {case.get('name')}")


def main():
    build, evidence, arch = sys.argv[1:]
    if platform.machine() != arch:
        raise ValueError(f"expected native {arch}, got {platform.machine()}")
    evidence = Path(evidence).resolve()
    evidence.mkdir(parents=True, exist_ok=True)
    discovery = run_bounded(
        ["ctest", "--test-dir", build, "--show-only=json-v1"],
        timeout=INVENTORY_TIMEOUT, description="CTest inventory", capture_output=True)
    if discovery.returncode:
        print(f"error: CTest inventory failed (exit {discovery.returncode})", file=sys.stderr)
        raise SystemExit(discovery.returncode)
    inventory = discovery.stdout
    (evidence / "inventory.json").write_text(inventory)
    selected = select_tests(json.loads(inventory), arch)
    (evidence / "required-tests.json").write_text(json.dumps(selected, indent=2) + "\n")
    print(f"Required {arch} tests ({len(selected)}): {selected}", flush=True)
    # Escape full names, including DR's literal option-prefix '|' characters.
    regex = "^(" + "|".join(re.escape(name) for name in selected) + ")$"
    junit = evidence / "junit.xml"
    junit.unlink(missing_ok=True)  # Never accept an earlier invocation's results.
    # No retries or continue-on-error: known detach_signal failure stays a failure.
    result = run_bounded([
        "ctest", "--test-dir", build, "--output-on-failure", "--no-tests=error",
        "--timeout", "900", "--parallel", "2", "--output-junit", str(junit),
        "-R", regex,
    ], timeout=TEST_TIMEOUT, description="CTest regression gate")
    verify_results(junit, selected)  # Also reject CTest-skipped / missing tests on rc0.
    if result.returncode:
        raise SystemExit(result.returncode)


if __name__ == "__main__":
    try:
        main()
    except TimeoutError as error:
        raise SystemExit(f"error: {error}") from None
