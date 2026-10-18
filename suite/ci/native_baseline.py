"""Bounded native CI regression gate, not the full precommit suite."""
import json
from pathlib import Path
import platform
import re
import subprocess
import sys
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
    inventory = subprocess.check_output(
        ["ctest", "--test-dir", build, "--show-only=json-v1"], text=True)
    (evidence / "inventory.json").write_text(inventory)
    selected = select_tests(json.loads(inventory), arch)
    (evidence / "required-tests.json").write_text(json.dumps(selected, indent=2) + "\n")
    print(f"Required {arch} tests ({len(selected)}): {selected}", flush=True)
    # Escape full names, including DR's literal option-prefix '|' characters.
    regex = "^(" + "|".join(re.escape(name) for name in selected) + ")$"
    junit = evidence / "junit.xml"
    junit.unlink(missing_ok=True)  # Never accept an earlier invocation's results.
    # No retries or continue-on-error: known detach_signal failure stays a failure.
    result = subprocess.run([
        "ctest", "--test-dir", build, "--output-on-failure", "--no-tests=error",
        "--timeout", "900", "--parallel", "2", "--output-junit", str(junit),
        "-R", regex,
    ], timeout=5400, check=False)
    verify_results(junit, selected)  # Also reject CTest-skipped / missing tests on rc0.
    if result.returncode:
        raise SystemExit(result.returncode)


if __name__ == "__main__":
    main()
