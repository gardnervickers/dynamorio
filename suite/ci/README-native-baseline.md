# Native Seedbox baseline

`ci-native-baseline.yml` validates this fork's maintained
`seedbox/release_11.3.0-1-backports` source on native Linux x86-64 and ARM64.
The initial baseline is upstream `release_11.3.0-1`
(`6847bb210bea0ca11d1bf47704383d6a075da490`) plus exactly four Seedbox patches,
ending at `108a0c133744f500a375dfc284c6ecab1ad24d66`.
CI changes do not add runtime fixes or alter those patch semantics.

## Events and execution

Pushes to the maintained branch and the explicit bootstrap topic
`seedbox/ci-native-baseline` run the two jobs. There are no wildcard push,
pull-request, schedule, deployment, or repository-dispatch triggers. Manual
dispatch is also declared, restricted to these same two branch refs. GitHub's
[dispatch discovery rules](https://docs.github.com/en/actions/reference/workflows-and-actions/events-that-trigger-workflows#workflow_dispatch)
can make a new manual-only workflow unavailable before it reaches the default
branch; the explicit topic push permits initial execution without changing
`master`, the default branch, or Actions policy. Repository Actions must already
be enabled. If no run is created, report that blocker; do not change policy to
obtain a green check.

The inherited upstream workflows keep their definitions, with every job gated
to `DynamoRIO/dynamorio`. Their upstream runner pools, broad matrices, mail,
and package/docs deployment jobs must not execute in this fork. This is a
workflow-level guard in the candidate, not a repository policy change.

Each native job checks out the event's immutable `github.sha`, verifies HEAD
and `uname -m`, and records recursive dependency SHAs, CPU information and
compiler versions. The elfutils GitHub mirror supplies the unchanged gitlink;
dependencies are never updated with `--remote`. The initial gitlinks are:

- elfutils: `c1058da5a450e33e72b72abb53bc3ffd7f6b361b`
- libipt: `c848a85c3104e2f5780741f85de5c9e65476ece2`
- zlib: `21767c654d31d2dccdde4330529775c6c5fd5389`

The only runner labels are `ubuntu-24.04` and `ubuntu-24.04-arm`, standard
[GitHub-hosted runners](https://docs.github.com/en/actions/reference/runners/github-hosted-runners).
No emulation, custom self-hosted pools, larger runners, or KVM is requested.
Permissions are `contents: read`; checkout does not persist credentials.
The two jobs have independent results and a 120-minute limit. Four build
workers and two test processes bound concurrency; same-ref runs queue without
cancelling existing diagnostic runs. Actions are pinned by commit; Ubuntu
images and apt dependencies remain moving inputs, recorded rather than claimed
to be hermetic.

## Build and regression scope

Use GCC 13, the Ubuntu 24.04 compiler generation. Configure a 64-bit release
build (`DEBUG=OFF`) with extensions, clients, tools, samples and tests enabled. Build all
configured targets, including core, `drrun`, `drmgr`, `drreg` and `drcontainers`.
Only docs are excluded. Samples must remain enabled: this release assigns ARM
test properties to sample tests without guarding `BUILD_SAMPLES`. Keep warnings
as errors. A timed `drrun`
echo smoke must exit successfully and produce the expected marker.

`native_baseline.py` selects existing release tests by exact base name, with
all registered option variants. `SHARED`, `X86` and `ARM` are the required
inventory: IR, signal delivery/masks/nesting, attach/detach, suspend, and SDK
extension regressions, plus AArch64 exclusive-access and operand/IR tests.
Names from the historical 218-commit fork, such as `linux.execveat` and the
`a64_prop_*` tests, are absent from this release and are not silently imported.
This bounded regression gate is not the complete DR precommit/nightly suite,
debug-build coverage, a dedicated oracle for every Seedbox patch, or Seedbox
Driver/guest qualification.

Empty/missing/disabled required tests fail selection. The exact inventory and
selection are retained. CTest has a 900-second default per-test timeout and a
90-minute aggregate bound; explicit upstream timeouts can take precedence.
Inventory discovery has a separate 60-second bound. Each command runs in a
private Linux session. On completion or failure, cleanup sends TERM to that
session's groups, waits up to five seconds for the leader, then sends KILL to
remaining groups with a five-second cleanup bound. It tracks session membership
through `/proc`, including groups created by `drrun -killpg` and descendants
whose leader already exited. Exit notifications bound waiting; a deadline is
reported as an error. This does not signal processes outside the owned session.
No retries, failure allowlists or `continue-on-error` are used. JUnit must
contain every selected test exactly once, with passing status and no skip,
failure or error. `api.detach_signal` stays required even if it fails.

Always-run artifact collection retains input/accounting evidence and text logs,
up to 64 files, 2 MiB per file, 20 MiB total payload, plus a truncation/omission
manifest. Large files retain their tails. Artifacts expire after three days;
complete build trees and binaries are excluded. Logs are useful on failure
but cannot substitute for an executed native job.

## Focused checks

```sh
PYTHONDONTWRITEBYTECODE=1 python3 -m unittest discover -s suite/ci -p 'test_*.py' -v
actionlint .github/workflows/ci-native-baseline.yml
git diff --check
```

For local native execution, configure/build outside the source tree using the
same CMake options and an appropriate project development shell, then run:

```sh
python3 suite/ci/native_baseline.py /path/to/build /path/to/evidence "$(uname -m)"
```

Worker checks are focused. The independent reviewer owns one complete
applicable suite run on the candidate. Record native run URLs and failures in
the issue/PR handoff, separately from helper/static checks.
