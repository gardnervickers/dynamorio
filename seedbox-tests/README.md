# Seedbox downstream DynamoRIO suite

This maintained fork owns the native Linux x86-64 and AArch64 black-box suite:
application and public SDK clients, saved inputs/corpora, case inventories,
provenance and licenses, and the Rust cases and their runners. The sources were
relocated from Seedbox c8e024ec9f72232c72d9c7a33cfb99f2a65a36a7
(`crates/seedbox-machine/tests/dynamorio{.rs,_isolated.rs,/}`). Historical paths
in inventories and provenance refer to their original source; retain them.
Rust files now follow ordinary relative module layout, without `#[path]`
attributes. The isolated target shares the canonical Unix process runner through
one source symlink, preserving both existing libtest module paths. Only module
attributes and relative embedded-data paths changed; case bodies are unchanged.

Original source provenance includes Seedbox f32472b7fe470367b7eddecde1ac53ad299f3a3e
and its DynamoRIO 356c1821045a4b5678d0813e132074324623df6e; family manifests
record the exact source commits and adaptations. Preserve all author/copyright
notices and license files beside their sources.

Seedbox remains the execution adapter: its existing `seedbox-machine` Cargo test
targets point directly to `dynamorio.rs` and `dynamorio_isolated.rs`, using its
existing dev-dependencies and feature gates. There is no separate Rust workspace
or fork CI. Seedbox CI builds and runs this suite on both architectures. Its Nix
fixture recipe builds `dynamorio/CMakeLists.txt` directly with the selected fork's
matching public SDK/runtime and genuine release/debug configurations. Runtime
tests use prepared packages, never retrieve or compile dependencies.

From a Seedbox checkout, initialize its submodules, enter its Nix development
shell, and use `cargo test -p seedbox-machine --features dynamorio-tests --test
dynamorio` with `SEEDBOX_DYNAMORIO_FIXTURES` and
`SEEDBOX_DYNAMORIO_DEBUG_FIXTURES` selecting the prepared Nix fixture packages.
The `dynamorio-isolated-tests` target additionally requires explicitly delegated
namespace/pids capabilities. See Seedbox's `docs/internals.md` for preparation
and its checker/CI for suite selection. Seedbox's time policy scans this directory
(including Rust helpers and C syscall subjects), not upstream DR tests. The
narrow subject-timer marker has its existing per-call bound/invariant contract.

Seedbox machine, backend, guest/PV/TCG and application integration tests and
general shared test support remain in Seedbox. These cases use public process
and SDK behavior and do not validate private DR internals or the guest epoch ABI.
