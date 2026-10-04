# Incident State Fabric

Authoritative lifecycle state for facility incidents: identity, class, severity,
affected scope, evidence, ownership, containment, recovery, and closure — as
durable, fenced, auditable authority rather than loosely coupled alarms and
tickets.

* **Version** 1.0.0
* **Language** C++20
* **Platform** Windows x64 (validated); see *Limitations*
* **Dependencies** none at runtime

```cpp
#include "isf/isf.h"

isf::OpenOptions options;
options.path = "D:/facility/incidents";
isf::IncidentFabricPtr fabric = std::move(isf::IncidentFabric::Open(options)).value();

isf::ReportIncidentRequest report;
report.header = /* actor, control epoch, idempotency key */;
report.cls = isf::IncidentClass::Cooling;
report.reported_severity = isf::Severity::Major;
report.summary = "chiller 3 tripped on high condenser pressure";
report.scope.objects.push_back(isf::ObjectRef{isf::ObjectKind::Chiller, "chiller-3"});
report.source_system = "bms";
report.source_event_id = "evt-8813";

// Preview and commit share one decision function, so they cannot disagree.
const auto preview = fabric->Preview(isf::AnyRequest{report});
const auto receipt = fabric->ReportIncident(report);
```

## Systems boundary

Incident State Fabric owns the **authoritative incident**. It answers: which
incident exists now, what objects and obligations does it affect, what
severity and lifecycle state is authoritative, which evidence supports that
state, who owns the response, and when may containment, recovery, and closure
be declared?

**Owned**

* stable incident identity, typed class and severity;
* affected-object and failure-domain references;
* evidence records with provenance, classification, and generation binding;
* ownership, assignment, and handoff;
* legal lifecycle transitions and the evidence gates in front of them;
* escalation and constrained de-escalation;
* containment, recovery, and closure evidence gates;
* lineage: merge parents and successor predecessors;
* revision, generation, and control-epoch binding and stale-actor fencing;
* idempotent replay of lost responses;
* durable, append-only audit history.

**Not owned**

Telemetry collection, specialist electrical or cooling diagnosis, actuation,
degraded-mode policy, recovery sequencing, workload migration, rack
evacuation, and the internals of adjacent recovery services. The fabric
consumes evidence those owners produce and records the decisions facility
authority is entitled to make; it never claims to perform their work.

## Invariants the implementation enforces

1. **A report is not an accepted incident.** Acceptance requires a concrete
   class, a concrete severity, and a current severity assessment from the
   severity authority.
2. **Severity evidence is not severity authority.** The role that may change a
   severity is read from the registered authority, never from the request.
3. **Acknowledgement is not containment.** A missing containment proof is
   reported as exactly that confusion.
4. **A requested mitigation is not an observed effect.**
5. **Recovery started is not recovery proven.**
6. **Resolved is not closed.** Closure requires current evidence and a role
   appropriate to the incident class.
7. **No incident closes because alarms went quiet.** Alarm silence is a
   different evidence kind and never satisfies clearance.
8. **Every transition binds the exact incident revision and control epoch.**
   Stale actors cannot mutate newer state.
9. **Recovered dynamic observations do not become fresh.** They are promoted
   only by an explicit, audited re-establishment.
10. **A lost response never causes a second mutation.** Idempotent replay is
    resolved before any fencing or precondition check, so a retry after a
    restart returns the original receipt.
11. **Commit order, not wall-clock arrival, governs authority.** De-escalation
    windows are measured in durable generations.
12. **Canonical output never depends on container order or thread timing.**
    Two stores that observe the same operation sequence produce byte-identical
    files.

## Lifecycle

```
Reported -> Accepted -> Contained -> Recovering -> Recovered -> Resolved -> Closed
   |            |            |            |            |           |
   |            +------------+------------+------------+-----------+   (Resolve)
   +-> Rejected        Closed -> Reopened -> ...        +-> Superseded
```

Each arrow is a durable record, and each is guarded. The full gate table — every
required evidence kind, every minimum role, and every rule about which facts may
not be conflated — is in [docs/semantics.md](docs/semantics.md).

## Persistence and recovery

The store is an append-only record log plus a manifest that names the exact
committed byte range of every segment. The **manifest rename is the single
commit point**:

```
segment append -> FlushFileBuffers -> staged manifest -> FlushFileBuffers ->
read back and verify -> atomic MoveFileExW publish
```

Records chain by digest, so truncation, reordering, and single-byte damage are
detectable; the chain continues across segment boundaries. Recovery verifies the
manifest checksum, the segment table, every record digest, the cross-segment
chain, the generator sequence, the whole-state checkpoint, and the identity
allocators, and refuses anything ambiguous, corrupt, truncated, incompatible, or
partially published. Details: [docs/persistence.md](docs/persistence.md).

Mutation authority is exclusive: a Win32 `LockFileEx` lock is held for the
session, so a second process is refused with `StoreLocked`. The lock is owned by
the kernel, so an abrupt death releases it with no cooperative act; the
successor gets a new incarnation and an advanced control epoch, and every actor
that held the old epoch is fenced.

## Concurrency

* One process owns mutation authority for a store.
* Reads run concurrently with each other behind a shared lock; a commit is
  serialised behind a single writer.
* The observer callback runs **after** the internal lock is released, so an
  observer may re-enter the fabric, including committing again.
* Every public call acquires the internal lock exactly once and never calls
  another public method. The full call-path audit is in
  [docs/deadlock-audit.md](docs/deadlock-audit.md).

## Failure semantics

Every operation returns either a value or a `Status` carrying a stable
`ErrorCode` and a deterministic message. Failures are refusals, never partial
application. Groups:

| Group | Codes |
| --- | --- |
| Request shape | `InvalidArgument`, `NotFound`, `AlreadyExists`, `Conflict`, `LimitExceeded`, `Unsupported` |
| Domain rules | `IllegalTransition`, `GateUnsatisfied`, `NotCurrentEvidence`, `ReopenLimitReached`, `DuplicateIdentity` |
| Authority and fencing | `Unauthorized`, `AuthorityRevoked`, `AuthorityUnknown`, `StaleControlEpoch`, `StaleRevision`, `IdempotencyConflict` |
| Arithmetic | `Overflow` — counters, generations, epochs, and identifiers refuse to wrap |
| Store | `StoreLocked`, `StoreCorrupt`, `StoreIncompatible`, `StoreIoError`, `StoreClosed`, `IntegrityFailure`, `UnsafePath`, `ResourceExhausted` |

If a durable commit fails part way through, the in-memory view may be ahead of
the log, so the fabric refuses every operation except `GetStatus` until it is
reopened. `FabricStatus::write_failed` reports that state.

## REAL, SYNTHETIC, UNSUPPORTED

**REAL** — genuinely exercised by this repository's proofs:

* process-local and cross-process exclusion through the Win32 kernel lock;
* durability through `FlushFileBuffers` plus an atomic manifest replace on a
  real NTFS volume;
* abrupt process termination with `TerminateProcess` and deterministic
  termination at named commit boundaries;
* recovery by reopening the store from a fresh process;
* Windows path handling including long paths, reserved device names, invalid
  Unicode, parent references, and reparse points;
* CMake package export, installation to a clean prefix, and an out-of-tree
  consumer using `find_package`.

**SYNTHETIC** — modelled, not measured:

* facility topology: racks, rows, power feeds, cooling loops, zones;
* incident reports, severity assessments, containment and recovery proofs;
* all benchmark workloads.

**UNSUPPORTED** — not implemented or not validated:

* no BMS, DCIM, PDU, UPS, generator, cooling, accelerator, RDMA, InfiniBand, or
  NVLink integration of any kind, and no vendor SDK usage;
* no actuation, no recovery sequencing, no workload migration, no rack
  evacuation;
* no network transport: the fabric is an in-process library over a local store;
* no multi-writer replication and no consensus;
* no POSIX build: `platform.cpp` uses Win32 locking, atomic replacement, and
  flush semantics, and CMake refuses to configure elsewhere.

## Limitations

* One writer per store. There is no distributed coordination.
* The store is a single directory on a locally attached volume; network
  filesystems are not validated and their rename and flush semantics may not
  provide the commit point this design relies on.
* The digest chain is an integrity mechanism, not a signature. It detects
  corruption and accidental divergence; it does not authenticate a hostile
  writer that has filesystem access.
* Runtime capacity limits (`StoreLimits`) are process policy, not format
  properties: the same log can be accepted under generous limits and refused
  under tight ones. They are reported in `FabricStatus` and never change the
  canonical state.
* `StateDigestPolicy::EveryCommit` costs time proportional to the size of the
  store on every commit. `OnCheckpoint` trades that cost for a coarser
  whole-state check; the allocator and session commitments are unconditional in
  both.
* A store is bound to format version 1. A future incompatible format will be
  refused rather than migrated.

## Build

Requirements: Windows x64, CMake 3.25 or newer, a C++20 toolchain (MSVC 19.3x
validated), and Ninja or the Visual Studio generator.

```bat
:: from a Developer Command Prompt (vcvars64.bat)
cmake -G Ninja -S . -B build/release -DCMAKE_BUILD_TYPE=Release
cmake --build build/release
ctest --test-dir build/release --output-on-failure
```

Or use the shipped presets:

```bat
cmake --preset ninja-release
cmake --build --preset release
ctest --preset release
```

Options: `ISF_BUILD_TESTS`, `ISF_BUILD_TOOLS`, `ISF_ENABLE_ASAN`,
`ISF_ENABLE_ANALYZE`, `ISF_WARNINGS_AS_ERRORS`.

## Install and consume

```bat
cmake --install build/release --prefix C:/isf
```

```cmake
find_package(isf 1.0 CONFIG REQUIRED)
target_link_libraries(my_service PRIVATE isf::isf)
```

The installed package ships the public headers, the static library, and
`isfConfig.cmake` / `isfConfigVersion.cmake` / `isfTargets.cmake`. A complete
downstream project is in [examples/consumer](examples/consumer).

## Tools

* `isfctl` — `status`, `hold`, and `seed` against a store. Used by the
  documentation and as the independent second process in the multiprocess and
  crash proofs.
* `isfbench` — measures completed durable commits, recovery, and reads, with
  the durability cost actually claimed.

## Validation

The proof suite is `isf_tests` (run through `ctest`). It covers unit, gate,
lifecycle, authority, idempotency, persistence, corruption, adversarial,
seeded property, concurrency, multiprocess, and crash-recovery obligations, and
it includes real independent OS processes and real abrupt terminations at named
durable commit boundaries. What was actually run, and what each result means, is
recorded in [docs/validation.md](docs/validation.md).

## Documentation

* [docs/architecture.md](docs/architecture.md) — layers, data model, the
  decision function, effects and replay
* [docs/semantics.md](docs/semantics.md) — lifecycle, gate tables, generations
  and fencing, duplicate reports, reopen versus successor
* [docs/persistence.md](docs/persistence.md) — file layout, record and manifest
  formats, the commit point, recovery, exclusion
* [docs/deadlock-audit.md](docs/deadlock-audit.md) — the manual lock and
  reentrancy audit
* [docs/validation.md](docs/validation.md) — exactly what was executed and what
  it proved
* [docs/real-synthetic-unsupported.md](docs/real-synthetic-unsupported.md) —
  proof provenance in detail

## License

Apache License 2.0. Copyright 2026 Summon Software Labs. No telemetry transmission.
