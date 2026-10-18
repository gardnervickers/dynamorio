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


def session_members(session):
    """Read Linux process metadata, retaining only our live private session."""
    members = {}
    for entry in Path("/proc").iterdir():
        if not entry.name.isdecimal():
            continue
        try:
            stat = (entry / "stat").read_bytes()
        except (FileNotFoundError, ProcessLookupError, PermissionError):
            continue
        # comm can itself contain spaces or ')'; fields after its final ')' are
        # state, ppid, pgrp, session, ... . Zombies cannot execute or fork.
        fields = stat[stat.rfind(b")") + 2:].split()
        if int(fields[3]) == session and fields[0] not in (b"Z", b"X"):
            members[int(entry.name)] = int(fields[2])
    return members


def signal_groups(members, sig):
    for group in set(members.values()):
        try:
            os.killpg(group, sig)
        except ProcessLookupError:
            pass


def terminate_session(process):
    """Retire all owned groups even when the session leader has exited."""
    signal_groups(session_members(process.pid), signal.SIGTERM)
    try:
        process.wait(timeout=TERMINATE_GRACE)
    except subprocess.TimeoutExpired:
        pass
    finally:
        # drrun -killpg creates another group within our session. Discover groups
        # again after TERM, rather than treating the leader's exit as completion.
        deadline = time.monotonic() + KILL_GRACE
        while members := session_members(process.pid):
            exits = []
            try:
                for pid in members:
                    try:
                        exits.append(os.pidfd_open(pid))
                    except ProcessLookupError:
                        pass
                signal_groups(members, signal.SIGKILL)
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
    process = subprocess.Popen(
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
