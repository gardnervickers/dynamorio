"""Finite source scenarios; source_oracle preserves the original model and floors.

No compilation, download, affinity setting, cached references, or generic-client
substitution for the ARM progress client occurs here. Each JVM is a fresh process.
"""
import argparse
from contextlib import contextmanager
import json
import os
from pathlib import Path
import platform
import re
import sys
import tempfile

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from phase import execute as execute_phase

from source_oracle import BASE_JVM, SCENARIOS, FLOORS, XLOG, count_log


# The checker already owns a retained report directory and a bounded artifact
# collector. Preserve only JVM text evidence before TemporaryDirectory removes
# the failing phase, including exceptions/timeouts and failed stress floors.
DIAGNOSTIC_LIMIT = 1024 * 1024


def retain_failure(base, case):
    report = os.environ.get("SEEDBOX_TEST_REPORT_DIR")
    if not report:
        print("jvm diagnostics unavailable: SEEDBOX_TEST_REPORT_DIR is unset", file=sys.stderr)
        return
    try:
        destination = Path(tempfile.mkdtemp(prefix="jvm-" + case + "-", dir=report))
        count = 0
        for mode in ("native1", "native2", "xint", "translated"):
            directory = base / mode
            paths = [directory / "command.json", directory / "jvm.log",
                     directory / "hotspot.log"]
            paths += sorted(directory.glob("hs_err_*.log"))[:2]
            for path in paths:
                if path.is_symlink() or not path.is_file():
                    continue
                with path.open("rb") as source:
                    size = os.fstat(source.fileno()).st_size
                    data = source.read(DIAGNOSTIC_LIMIT)
                    if size > DIAGNOSTIC_LIMIT:
                        marker = b"\n[JVM diagnostic truncated: head and tail]\n"
                        half = (DIAGNOSTIC_LIMIT - len(marker)) // 2
                        source.seek(-half, os.SEEK_END)
                        data = data[:half] + marker + source.read(half)
                target = destination / mode / path.name
                target.parent.mkdir(exist_ok=True)
                target.write_bytes(data)
                count += 1
                print(f"jvm diagnostic {mode}/{path.name}: {len(data)}/{size} bytes", flush=True)
        print(f"jvm failure diagnostics: {destination} ({count} files)", flush=True)
    except OSError as error:
        # Failure to publish evidence must not replace the original failure.
        print(f"jvm diagnostic retention failed: {error}", file=sys.stderr)


@contextmanager
def working_directory(case):
    with tempfile.TemporaryDirectory(prefix="dr-jvm-") as temporary:
        base = Path(temporary)
        try:
            yield base
        except BaseException:
            retain_failure(base, case)
            raise


def execute(root, command, directory):
    (directory / "command.json").write_text(json.dumps(command, indent=2) + "\n")
    env = {"DYNAMORIO_CONFIGDIR": str(directory), "HOME": str(directory)}
    status, stdout, stderr = execute_phase(root, command, directory, env)
    assert status == 0, (command, status, stdout, stderr)
    results = [line for line in stdout.splitlines() if line.startswith("RESULT ")]
    assert len(results) == 1, (command, stdout, stderr)
    assert re.search(r"\bmismatches=0\b", results[0]), results[0]
    assert not list(directory.glob("hs_err*")), (command, stdout, stderr)
    return results[0], stdout, stderr


class InsufficientStress(Exception):
    pass


def hotspot_diagnostics(directory):
    """Returns non-semantic HotSpot logging flags for the translated phase."""
    return ["-XX:+UnlockDiagnosticVMOptions", "-XX:+LogCompilation",
            "-XX:LogFile=" + str(directory / "hotspot.log")]


def run(root, case, seed_offset=0):
    cases = {
        "deopt-shared-diagnostic": ("DeoptCycle", 1, 40000, "default", "observe"),
        "ic-seedbox-seed1": ("IcNull", 1, 100000, "seedbox", False),
        "ic-default-seed1-ops50000": ("IcNull", 1, 50000, "default", False),
        "deopt-client-seed1-b50000": ("DeoptCycle", 1, 40000, "seedbox", True),
        "ic-client-seed2-b50000": ("IcNull", 2, 50000, "seedbox", True),
        "jfr-default-seed1": ("JfrNpe", 1, 300000, "default", False),
        "redefine-default-seed1": ("Redefine", 1, 20, "default", False),
    }
    scenario, seed, ops, profile, client = cases[case]
    seed += seed_offset
    arm = platform.machine() == "aarch64"
    # The ARM profile contains ARM-only instructions/options. x86 runs the
    # shared application oracle under default DR, explicitly a different profile.
    if client is True and not arm:
        raise RuntimeError("original ARM progress profile requires native ARM; no x86 substitute")
    java = root / "runtimes/java/bin/java"
    jar = root / "share/translator/jvm/jitstress.jar"
    dr = [str(root / "runtime/bin64/drrun"), "-use_dll",
          str(root / "runtime/lib64/release/libdynamorio.so")]
    if profile == "seedbox" and arm:
        dr += ["-opt_speed", "-disable_traces", "-ldstex2cas",
               "-no_hw_cache_consistency", "-fake_ctr_dic"]
    if client == "observe":
        vm = java.resolve().parent.parent / "lib/server/libjvm.so"
        assert vm.is_file(), vm
        dr += ["-c", str(root / "lib/libtranslator_observe.so"), str(vm)]
    elif client:
        dr += ["-c", str(root / "lib/libtranslator_progress.so"),
               "--instructions-per-progress-call", "50000"]
    sc = SCENARIOS[scenario]
    with working_directory(case) as base:
        results = []
        for mode in ("native1", "native2", "xint", "translated"):
            directory = base / mode
            directory.mkdir()
            flags = BASE_JVM + sc["jvm"] + (["-Xint"] if mode == "xint" else [])
            flags += ["-XX:ErrorFile=" + str(directory / "hs_err_%p.log"),
                      XLOG.format(log=directory / "jvm.log"), "-javaagent:" + str(jar),
                      "-Djava.io.tmpdir=" + str(directory), "-Dscenario=" + scenario,
                      "-Dseed=" + str(seed), "-Dops=" + str(ops),
                      "-Dthreads=" + str(sc["threads"]), "-cp", str(jar), "JitStress"]
            if mode == "translated":
                # A DR-internal crash prevents HotSpot's hs_err handler from mapping
                # the code-cache address.  Keep HotSpot's nmethod address map instead.
                flags[0:0] = hotspot_diagnostics(directory)
            command = [str(java)] + flags
            if mode == "translated":
                command = dr + ["--"] + command
            print(case, mode, "seed", seed, flush=True)
            result, stdout, stderr = execute(root, command, directory)
            results.append(result)
            if mode == "translated":
                counts = count_log(str(directory / "jvm.log"), stdout, sc["c2_target"])
                floors = {k: max(1, int(v * ops / sc["ops"])) for k, v in FLOORS[scenario].items()}
                if not all(counts[k] >= v for k, v in floors.items()):
                    raise InsufficientStress((case, seed, counts, floors))
                if client:
                    evidence = re.search(r"path-cost: exit app=[1-9][0-9]* vm=(\d+)" if client == "observe" else r"a64_progress_like: (\d+) refills", stderr)
                    assert evidence and int(evidence[1]) > 0, stderr
                    print(case, "executed client evidence:", evidence[0], flush=True)
                print(case, "counts", counts, "floors", floors, flush=True)
        assert len(set(results)) == 1, (case, results)
    print(case + ": PASS " + ("shared diagnostic profile" if client == "observe" else "original ARM profile" if arm else "shared x86 default profile"))


if __name__ == "__main__":
    # A direct invocation owns the same whole-tree group as the Rust wrapper.
    if os.getpgrp() != os.getpid():
        os.setpgid(0, 0)
    parser = argparse.ArgumentParser()
    parser.add_argument("root", type=Path)
    parser.add_argument("case")
    args = parser.parse_args()
    attempts = 3 if args.case in {
        "ic-seedbox-seed1", "ic-default-seed1-ops50000",
        "deopt-client-seed1-b50000", "ic-client-seed2-b50000",
    } else 1
    for attempt in range(attempts):
        try:
            run(args.root.resolve(), args.case, attempt * 100)
            break
        except InsufficientStress as error:
            print("INSUFFICIENT_STRESS", error, flush=True)
            if attempt + 1 == attempts:
                raise
