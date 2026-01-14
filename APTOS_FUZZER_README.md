# Aptos Fuzzer Overview

This repository started based on a Sui Move fuzzer and now includes an Aptos option. The Aptos path keeps the same architecture (fuzzer + workers + mutator + runner), but swaps in Aptos-specific compilation and execution using the Aptos framework and `FakeExecutor`. Additionally, this repository explores improved feedback metrics for fuzzing. For details, see https://github.com/rubujubi/move-fuzzer.

## Dependencies

The Aptos fuzzer relies on a few local and upstream dependencies:

- **`aptos-core` submodule**: provides Aptos Move framework, VM, executor, and Move tooling (`move-package`, `move-binary-format`, etc.). Currently pointed at `https://github.com/rubujubi/aptos-core` on branch `l1-migration-with-fixes`.

Branch `l1-migration-with-fixes` exists to fix several issues I found when trying to integrate the fuzzer.

1) 

```
error[E0597]: `dst` does not live long enough
   --> /aptos/aptos-core/aptos-move/framework/src/natives/cryptography/bulletproofs.rs:195:41
    |
174 |     dst: Vec<u8>,
    |     --- binding `dst` declared here
...
195 |     let mut ver_trans = Transcript::new(dst.as_slice());
    |                         ----------------^^^^-
    |                         |               |
    |                         |               borrowed value does not live long enough
    |                         argument requires that `dst` is borrowed for `'static`
...
208 | }
    | - `dst` dropped here while still borrowed
```

Fix reference: https://github.com/aptos-labs/aptos-core/issues/10325


2）https://github.com/rubujubi/aptos-core/commit/b8706f68f2007d6377585a09e2ed04fb3e19e108

3）https://github.com/rubujubi/aptos-core/commit/a0aa7a182e8e3cbe10af0b5e0bdc0972f5f5a6fc

## Architecture at a Glance

The fuzzer is split into a few reusable pieces, each with a clear file home:

- **Fuzzer core**: orchestrates threads, UI, and global state.
  - `src/fuzzer/fuzzer.rs` (thread startup, runner selection, build logic)
  - `src/fuzzer/config.rs` (config schema + load)
  - `src/fuzzer/stats.rs` (shared stats, gas tracking)
  - `src/fuzzer/coverage.rs` and `src/fuzzer/crash.rs` (coverage/crash models)
- **Workers**: drive the fuzzing loop and reporting.
  - `src/worker/stateless_worker.rs` (stateless loop, corpus/crash reporting)
  - `src/worker/stateful_worker.rs` (call-sequence generation, state resets)
  - `src/worker/worker.rs` (worker trait + events)
- **Mutator**: generates and mutates Move inputs.
  - `src/mutator/sui_mutator.rs` (current mutator, used for Aptos too)
  - `src/mutator/mutator.rs` and `src/mutator/types.rs` (mutator trait + input types)
- **Runners**: chain-specific execution engines.
  - Aptos stateless runner: `src/runner/stateless_runner/aptos_runner.rs`
  - Aptos stateful runner: `src/runner/stateful_runner/aptos_runner.rs`
  - Aptos helpers + registry: `src/runner/aptos_helpers/`
  - Aptos ABI/input helpers: `src/runner/stateless_runner/aptos_runner_utils.rs`
  - Runner traits + chain selection: `src/runner/runner.rs` and `src/runner/chain.rs`

## Aptos Compilation Flow

The Aptos runner compiles Move packages from source using `aptos_framework::BuiltPackage` so that:

- runtime metadata (resource groups, attribute checks, etc.) is injected correctly,
- packages are compiled with Aptos Move v2.1 language/compiler settings,
- compiled bytecode and package metadata are ready for publishing into the executor.

The fuzzer calls this from `Fuzzer::build_test_modules` in `src/fuzzer/fuzzer.rs`.

## Stateless Fuzzing (Aptos)

Stateless mode runs a single entry function repeatedly without committing state:

1. The runner extracts ABI information from source to determine parameter types.
2. The package is compiled and published to a `FakeExecutor`.
3. Optional `fuzz_init` is called once if it exists.
4. Each fuzz iteration:
   - generated inputs are converted into `TransactionArgument` values,
   - a transaction is built and executed,
   - the result is checked for crashes.

In stateless mode **write sets are not applied**, and the same sequence number is reused to keep state stable across runs. This makes execution fast and repeatable while still exercising transaction validation.

## Stateful Fuzzing (Aptos)

Stateful mode builds **sequences of calls** and commits state between them:

1. The package is compiled and published into the executor.
2. Optional helper initialization and `fuzz_init` are called once.
3. For each iteration, the worker:
   - selects a random call sequence (mix of fuzz-prefixed and target functions),
   - mutates inputs with gas feedback,
   - executes calls in order and **applies write sets**,
   - resets state by re-running setup for the next sequence.

This mode is closer to on-chain behavior and useful for catching multi-step or state-dependent bugs.

## Aptos Helpers

Some Aptos contracts require structured inputs or initialization that random mutation will never reach. The `aptos_helpers` map in the config lets you attach helper logic to a function:

```json
"aptos_helpers": {
  "usdcx::mint": "usdcx_mint_v1"
}
```

Helpers can:
- provide initialization arguments (`initialize` entry function),
- transform raw fuzz inputs into valid, contract-specific payloads.

See `src/runner/aptos_helpers/` for existing helpers and registration.


