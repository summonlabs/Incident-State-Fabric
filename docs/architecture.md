# Architecture

## Systems boundary

Incident State Fabric (DCCP boundary 50) owns the **authoritative lifecycle of
facility incidents**. It answers one question:

> Which incident exists now, what objects and obligations does it affect, what
> severity and lifecycle state is authoritative, which evidence supports that
> state, who owns the response, and when may containment, recovery, and closure
> be declared?

It owns:

* stable incident identity;
* typed incident class and severity;
* affected-object and failure-domain references;
* evidence records with provenance and generation binding;
* ownership and assignment;
* legal lifecycle transitions and the gates in front of them;
* escalation and constrained de-escalation;
* containment, recovery, and closure evidence gates;
* lineage: merge parents and successor predecessors;
* revision, generation, and control-epoch binding;
* idempotent replay of lost responses;
* durable, append-only audit history.

It explicitly does **not** own telemetry collection, specialist electrical or
cooling diagnosis, actuation, degraded-mode policy, recovery sequencing,
workload migration, rack evacuation, or the internals of adjacent recovery
services. It consumes evidence those owners produce and records the decisions
that facility authority is entitled to make.

## Layers

```
include/isf/          public API - value types, requests, IncidentFabric
src/fabric.cpp        the public class: locking, decisions, reads, session
src/types.cpp         stable names, policy tables, request dispatch
src/detail/evaluate   the single decision function (gates, authority, replay)
src/detail/request_codec  request shape validation and intent digests
src/detail/state      authoritative in-memory state, effects, replay, digests
src/detail/store      segments, manifest, the commit point, recovery
src/detail/format     record framing and manifest encoding
src/detail/canonical  canonical byte encoding and text validation
src/detail/crypto     SHA-256
src/detail/platform   the only file that talks to the operating system
```

Only `src/detail/platform.cpp` is platform-specific. Everything above it works
on canonical byte buffers and value types.

## Data model

| Concept | Meaning |
| --- | --- |
| `IncidentId` | Stable identity, allocated once, never reused. |
| `Generation` | Count of durably committed records. The only ordering that governs authority. |
| `ControlEpoch` | Fencing token for the process that currently owns mutation authority. |
| `revision` | Per-incident counter, advanced by every committed change to that incident. |
| `observation_generation` | Bumped when an incident becomes Recovered; demotes every earlier dynamic observation to history. |
| `attestation_generation` | Bumped when an incident is reopened; invalidates every earlier durable attestation. |
| `EvidenceId` | Stable identity of one evidence record, never reused. |
| `AuthorityId` | Registered actor. Roles live only in the registry, never on the wire. |

Evidence is classified into exactly two kinds, and the classification is part
of the documented semantics:

* **DynamicObservation** — Report, SeverityAssessment, Acknowledgement,
  EffectObservation, MitigationRequest, AlarmSilence. Valid only inside the
  incident's current observation generation.
* **DurableAttestation** — ContainmentProof, RecoveryProof, EffectCleared,
  ClosureAttestation, ReopenTrigger, MaintenanceWindowNotice. Survives
  observation-generation changes; invalidated only by a reopen.

## The decision function

`src/detail/evaluate.cpp` holds one function, `EvaluateRequest`, used by both
the durable commit path and the read-only `Preview` path. It resolves, in a
fixed and observable order:

1. request shape;
2. idempotent replay of an already-committed operation;
3. control-epoch fencing;
4. authority resolution and role;
5. runtime capacity limits;
6. operation semantics and evidence gates.

Because both paths call the same function, a preview can never disagree with
what a commit would do — an invariant the property suite asserts on every step.

The function is pure: it never mutates state. It returns either an *effect* to
commit, a *replayed receipt*, or a *denial* with a deterministically ordered
list of gate failures.

## Effects and replay

The log stores **effects**, not requests. An effect is the complete post-image
of everything one operation changed, so recovery applies effects blindly
instead of re-running policy. A later change to gate logic therefore cannot
silently rewrite history.

`ApplyEffect` is the only place authoritative state changes. It refuses a log
that is internally inconsistent — a creation effect that reuses an existing
identifier, an effect whose generation is not the next one — and reports it as
`StoreCorrupt`.
