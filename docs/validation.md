# Validation performed

Everything below was executed against the tree that produced commit
`v1.0.0`. Nothing in this file is projected or estimated.

## Toolchain

| Item | Value |
| --- | --- |
| Host | Windows 11 (10.0.26300), x64 |
| Compiler | MSVC 19.44.35207 (Visual Studio 2022 Build Tools 17.14) |
| CMake | 4.3.2 |
| Generator | Ninja |
| Strictness | `/W4 /WX /permissive- /utf-8 /Zc:__cplusplus /external:W0` |

No test timeout is configured anywhere: not in CTest, not in the presets, not in
the code. The suite runs plainly to completion.

## Suite results

`isf_tests` exercises 101 cases. Every configuration ran the entire suite.

| Configuration | Result | First-party warnings | Sanitizer reports |
| --- | --- | --- | --- |
| Debug | **101 / 101 passed, 0 failed checks** | 0 | n/a |
| Release | **101 / 101 passed, 0 failed checks** | 0 | n/a |
| Debug + AddressSanitizer | **101 / 101 passed, 0 failed checks** | 0 | **0** |

The AddressSanitizer build used MSVC `/fsanitize=address` with the dynamic
runtime shipped in the Visual Studio C++ AddressSanitizer component
(`clang_rt.asan_dbg_dynamic-x86_64.dll`), and the suite ran with that runtime on
`PATH`. The instrumentation was confirmed present in the generated build rules
for all 28 translation units (library, tools, and tests).

## Static analysis

```
cmake -G Ninja -S . -B build/analyze -DCMAKE_BUILD_TYPE=Release -DISF_ENABLE_ANALYZE=ON
```

The MSVC analyzer ran over all 11 first-party library translation units
(`/analyze /analyze:external-`). **0 analyzer warnings.** The analyzer was
confirmed to be present in the generated build rules; it is not a no-op.

## What the suite proves

| Area | Cases | Evidence |
| --- | --- | --- |
| Canonical encoding and hashing | 10 | SHA-256 published vectors, streaming vs one-shot, fixed little-endian layout, bounds-checked decoding, strict UTF-8 |
| Stable public surface | 9 | every enumerator has a stable name, classification is total, range checks reject boundaries, version and format identifiers agree |
| Authority and fencing | 8 | bootstrap exactly once, no role escalation, bounded revocation, unknown and revoked authorities, stale epoch, stale revision, force fence |
| Lifecycle | 12 | full lifecycle to Closed, report vs accepted, matching severity evidence, duplicate reports, terminal incidents, illegal transitions, ownership handoff, scope amendment, escalation and constrained de-escalation, merge, cross-class override, successor lineage |
| Evidence gates | 10 | acknowledgement is not containment, alarm silence is not clearance, a requested mitigation is not an observed effect, recovery started is not proven, resolved is not closed, closure authority depends on the class, contradicting observations block resolution, recovered observations are not silently fresh, reopen invalidates prior attestations, the reopen limit |
| Idempotent replay | 9 | retries replay instead of committing twice, key reuse for a different intent is refused, replay outranks stale preconditions, replay survives a restart and a fencing change, receipts match exactly, preview and commit agree |
| Persistence | 8 | reopen reproduces the whole state, identical operation sequences produce byte-identical segments and manifests, checkpoint policy, segment rotation across the digest chain, clean vs unclean restart epochs, repeated open/close cycles, idempotent close |
| Corruption refusal | 9 | truncated manifest, flipped bits, wrong magic, wrong version, allocator zeroed, checkpoint ahead of the generation, non-contiguous segment indices, missing and short segments, garbage past the committed length, unknown operation kinds, hostile segment names |
| Adversarial | 9 | capacity limits, allocator and epoch exhaustion refusing to wrap, malformed text, path shapes, invalid Unicode, long paths, reparse points, double open, query bounds |
| Seeded property walks | 3 | five seeds x 300 steps plus a determinism pair; invariants after every mutation; preview/commit agreement on every request; live state compared field by field against a fresh replay |
| Concurrency | 4 | readers observe only committed state, simultaneous identical requests commit exactly once, observers run outside the lock and may re-enter, observer replacement under load |
| Multiprocess and crash | 4 | exclusive authority, kernel release on abrupt death, no inherited authority, crash at five durable boundaries, abrupt kill mid-flight against a reference run |

## Real multiprocess and crash results

`MultiProcess.MutationAuthorityIsExclusiveAndReleasedByDeath`

* A second process is refused with `StoreLocked` (exit code 3) while the first
  holds the store.
* The holder is ended with `TerminateProcess`; the successor opens the same
  store, observes `incarnation + 1` and `control epoch + 1`, and the third
  process is refused again while the successor holds it.
* A clean close leaves the epoch unchanged for the next incumbent.

`MultiProcess.CrashAtEveryDurableBoundaryRecoversToOneWholeGeneration`

For each of `before_append`, `after_write`, `after_flush`, `before_publish`,
and `after_publish`, the worker is terminated at generation 50 with
`TerminateProcess` (exit code 70). After reopening from a fresh process:

| Boundary | Recovered generation | Committed? |
| --- | --- | --- |
| `before_append` | 49 | no |
| `after_write` | 49 | no |
| `after_flush` | 49 | no |
| `before_publish` | 49 | no |
| `after_publish` | 50 | yes |

In every case the record count and audit length equal the generation exactly,
and every recovered incident is the expected prefix with revision 1.

`MultiProcess.AbruptKillMidCommitLeavesAWholeGenerationAndAPrefixOfHistory`

A worker commits continuously; the parent waits for it to announce at least
generation 60 and then kills it. The recovered generation is always the
announced generation or exactly one more — never anything in between, never a
torn record. The recovered incidents are compared against a completed reference
run of the same workload and match it item by item as a prefix.

## Package, install, and downstream consumption

1. `cmake --install build/release --prefix build/install` — the installed tree
   contains the public headers, `isf.lib`, `isfConfig.cmake`,
   `isfConfigVersion.cmake`, `isfTargets.cmake`, and the licence documents.
2. A copy of `examples/consumer` is configured out of tree with
   `-DCMAKE_PREFIX_PATH=<install>` and `find_package(isf 1.0 CONFIG REQUIRED)`.
3. It compiles, links against the installed artifact, and runs:

```
reported incident 1 at generation 4
stale actor refused with StaleControlEpoch
after restart: incident 1 is Reported with severity Major at revision 1
consumer ok, library version 1.0.0
```

## Benchmark

`isfbench 2000`, Release, single writer, synthetic workload of 2000 reported
incidents over a modelled rack set. Every reported commit includes the full
durability cost: segment `FlushFileBuffers`, staged manifest `FlushFileBuffers`,
read-back verification, and an atomic `MoveFileExW` publish on a real NTFS
volume.

| Measurement | EveryCommit | OnCheckpoint |
| --- | --- | --- |
| Durable commits | 2000 | 2000 |
| Wall clock | 23.914 s | 16.664 s |
| Throughput | 83.6 commits/s | 120.0 commits/s |
| Cost per commit | 11.957 ms | 8.332 ms |
| Recovery (2005 records) | 0.033 s (59,907 records/s) | 0.029 s (69,895 records/s) |

Reads over 20,000 iterations: `GetIncident` 0.006 s (3.5 M reads/s),
`ListIncidents` with a 1000-row page 1.782 s (11.2 k reads/s).

The `EveryCommit` policy stores a digest of the whole materialized state on
every commit; `OnCheckpoint` refreshes that digest only at an explicit
checkpoint and on clean close. The measured difference — about 3.6 ms per
commit and no recovery penalty at this scale — is the real cost of that choice.

## Defects found and repaired during hardening

Every one of these was found by running the proofs, and each is now covered by
a regression case.

| # | Defect | Consequence | Found by |
| --- | --- | --- | --- |
| 1 | The decision result defaulted to `Denied` | Every successful operation returned an empty "Ok" refusal | first full suite run |
| 2 | `PrepareReportEffect` restored the stale incident allocator after allocating | A second report reused incident 1 and was silently dropped by the identity map | lifecycle suite |
| 3 | The idempotency index never stored the request intent digest | Every retry of a committed operation was refused `IdempotencyConflict` | idempotency suite |
| 4 | The manifest decoder never consumed past its own trailing checksum | No store could ever be reopened | restart tests |
| 5 | A failed `Open` left a half-constructed fabric | The destructor dereferenced a null store and the process crashed | AddressSanitizer |
| 6 | Segment rotation restarted the digest chain from zero | A rotated store failed recovery with a chain mismatch | rotation test |
| 7 | Segment-name parsing accumulated digits without an overflow guard | A hostile 20-digit name could wrap into a valid index | adversarial suite |
| 8 | `FabricStatus::store_path` returned the extended-length path | The reported path was refused by `Open`, so it was not round-trippable | property suite |
| 9 | A `ReopenTrigger` could not be recorded against a closed incident | Reopening was impossible | gate suite |
| 10 | Test macro `ISF_CHECK_EQ` bound references into temporaries | Stack-use-after-scope in the harness | AddressSanitizer |
| 11 | `isfctl` reused idempotency keys between bootstrap and seeding | The worker failed, and one proof waited forever for progress that could not come | hanging test |

Defects 4, 5, and 11 are the interesting ones: none of them is reachable
without actually reopening a store, actually failing an open, or actually
running a second process.
