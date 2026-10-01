# Lifecycle and gate semantics

## States

```
Reported -> Accepted -> Contained -> Recovering -> Recovered -> Resolved -> Closed
   |            |            |            |            |           |          |
   |            +------------+------------+------------+-----------+          |
   |                          (Resolve is legal from any of these)             |
   +-> Rejected                    Closed -> Reopened -> (back into the flow)  |
   +-> Superseded                                                                |
```

* **Reported** — a report exists. A report is not an accepted incident.
* **Accepted** — triaged into an authoritative incident with a concrete class
  and severity.
* **Contained** — containment is proven by a current attestation.
* **Recovering** — recovery has started. Starting recovery is not proof of it.
* **Recovered** — recovery is proven; the observation generation advances.
* **Resolved** — the effect is no longer observed.
* **Closed** — closure is attested by authority appropriate to the class.
* **Reopened** — a closed incident re-entered the operational lifecycle; both
  generations advance.
* **Rejected**, **Superseded** — terminal.

## What is kept separate from what

The fabric refuses to conflate facts that happen to arrive together. When a
required record is missing but a related one is present, the denial names the
confusion explicitly rather than only reporting an absence:

| Required | Never satisfied by |
| --- | --- |
| ContainmentProof | Acknowledgement, MitigationRequest |
| EffectCleared | AlarmSilence, Acknowledgement, MitigationRequest |
| RecoveryProof | MitigationRequest, ContainmentProof |
| SeverityAssessment | Acknowledgement |
| ClosureAttestation | AlarmSilence |
| ReopenTrigger | AlarmSilence |

> No incident may close because alarms went quiet.

## Gates by transition

| Transition | From | Required current evidence | Minimum role | Extra |
| --- | --- | --- | --- | --- |
| Accept | Reported | Report, plus the referenced SeverityAssessment | IncidentCommander | concrete class and severity |
| RejectReport | Reported | — | DutyManager | rationale |
| RecordEvidence | any live state, or Closed for a ReopenTrigger | — | Operator | attestations need a rationale |
| WithdrawEvidence | live | existing current evidence | Operator | rationale |
| ReestablishEvidence | live | historic, non-withdrawn evidence | IncidentCommander | rationale |
| AmendSeverity (up) | past Reported | ≥1 SeverityAssessment asserting the new severity | IncidentCommander | — |
| AmendSeverity (down) | past Reported | ≥2 SeverityAssessments from **distinct** authorities asserting the new severity | DutyManager | quiet window in generations |
| AmendScope | live | — | IncidentCommander | non-empty, different |
| AssignOwner | live | — | IncidentCommander | registered, active, different |
| DeclareContained | Accepted, Reopened | ContainmentProof | IncidentCommander | — |
| StartRecovery | Contained | containment still current | IncidentCommander | — |
| DeclareRecovered | Recovering | RecoveryProof | IncidentCommander | advances the observation generation |
| Resolve | Accepted, Contained, Recovering, Recovered, Reopened | EffectCleared | class policy (DutyManager) | containment proven for classes that require it; recovery proven if recovery was started; no later contradicting EffectObservation |
| Close | Resolved | ClosureAttestation, EffectCleared, plus ContainmentProof / RecoveryProof where the class requires them | class policy (DutyManager or FacilityDirector) | — |
| Reopen | Closed | ReopenTrigger | class closure role | at most 2 reopens |
| MergeIncident | both live | — | FacilityDirector | cross-class needs an explicit override |
| CreateSuccessor | — | — | DutyManager | predecessor revision must match |

Class policy:

| Class | Containment | Recovery | Closure role |
| --- | --- | --- | --- |
| Power, Cooling, Network, Compute, Storage, FireSuppression, WaterIngress, Structural, Environmental | required | required | FacilityDirector |
| PhysicalSecurity | required | not required | DutyManager |

## Generation, revision, and fencing

* Every mutation carries the **control epoch** the caller observed. A request
  minted against a previous incarnation of the store is refused with
  `StaleControlEpoch`.
* Every mutation that touches an existing incident carries the **exact
  revision** the caller believes is current. A mismatch is refused with
  `StaleRevision`.
* The control epoch advances when a store is opened after a session that did
  not close cleanly, and when `ForceFence` is committed. A clean restart keeps
  the epoch: a planned restart is not a fencing event.
* Recovered dynamic observations never become fresh on their own. They are
  promoted back into the current observation generation only by an explicit,
  audited `ReestablishEvidence`.
* De-escalation windows are measured in **durable generations**, never in wall
  clock time.

## Duplicate reports

A report may carry a source identity (`source_system` plus
`source_event_id`). Reports sharing that identity are duplicates:

* if the incident the identity already names is live, the new report is
  appended to it as additional evidence and the receipt says
  `duplicate_report`;
* if it is terminal, a new incident is opened and the identity is repointed at
  it, so a recurrence is never folded into a closed incident;
* a report with no source identity is never deduplicated.

## Reopen versus successor

* **Reopen** keeps the identity, advances the observation and attestation
  generations, and is capped at two per incident. Every prior attestation
  becomes historic and closure must be re-earned with fresh evidence.
* **CreateSuccessor** opens a new identity that carries a lineage reference to
  the predecessor. The predecessor is left exactly as it was.
