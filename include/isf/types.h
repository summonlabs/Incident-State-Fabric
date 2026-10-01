// Incident State Fabric - DCCP boundary 50
// Copyright 2026 Summon Software Labs.
// Licensed under the Apache License, Version 2.0.

#ifndef ISF_TYPES_H
#define ISF_TYPES_H

#include <cstdint>
#include <string_view>

namespace isf {

// ---------------------------------------------------------------------------
// Strongly typed identifiers
// ---------------------------------------------------------------------------
//
// Every identifier is a distinct type so that an IncidentId can never be
// passed where an EvidenceId is expected. Value 0 is never allocated and means
// "absent".

template <typename Tag>
class StrongId {
 public:
  using value_type = std::uint64_t;

  constexpr StrongId() noexcept = default;
  constexpr explicit StrongId(std::uint64_t raw) noexcept : value_(raw) {}

  [[nodiscard]] constexpr std::uint64_t value() const noexcept { return value_; }
  [[nodiscard]] constexpr bool valid() const noexcept { return value_ != 0; }
  constexpr explicit operator bool() const noexcept { return valid(); }

  friend constexpr bool operator==(StrongId a, StrongId b) noexcept { return a.value_ == b.value_; }
  friend constexpr bool operator!=(StrongId a, StrongId b) noexcept { return a.value_ != b.value_; }
  friend constexpr bool operator<(StrongId a, StrongId b) noexcept { return a.value_ < b.value_; }
  friend constexpr bool operator<=(StrongId a, StrongId b) noexcept { return a.value_ <= b.value_; }
  friend constexpr bool operator>(StrongId a, StrongId b) noexcept { return a.value_ > b.value_; }
  friend constexpr bool operator>=(StrongId a, StrongId b) noexcept { return a.value_ >= b.value_; }

 private:
  std::uint64_t value_ = 0;
};

struct IncidentIdTag {};
struct EvidenceIdTag {};
struct AuthorityIdTag {};
struct GenerationTag {};

using IncidentId = StrongId<IncidentIdTag>;
using EvidenceId = StrongId<EvidenceIdTag>;
using AuthorityId = StrongId<AuthorityIdTag>;

/// Durable commit generation. The generation is the count of durably committed
/// records and is the only ordering that governs authority. A generation is
/// never reused and never decreased.
using Generation = StrongId<GenerationTag>;

/// Control epoch: a fencing token for the process that currently owns
/// mutation authority over a store. Every open of a store that was not closed
/// cleanly advances the epoch, so a request minted against the previous
/// incarnation is refused instead of silently mutating newer state. Unlike the
/// other identifiers, epoch 0 is a legal (pre-open) value, so this is a plain
/// value type rather than a StrongId.
struct ControlEpoch {
  std::uint64_t value = 0;

  friend constexpr bool operator==(ControlEpoch a, ControlEpoch b) noexcept { return a.value == b.value; }
  friend constexpr bool operator!=(ControlEpoch a, ControlEpoch b) noexcept { return a.value != b.value; }
  friend constexpr bool operator<(ControlEpoch a, ControlEpoch b) noexcept { return a.value < b.value; }
};

/// Caller supplied idempotency key. Two requests sharing a key describe the
/// same logical operation; the store resolves the second one as a replay of the
/// first instead of committing a second mutation.
struct IdempotencyKey {
  std::uint64_t hi = 0;
  std::uint64_t lo = 0;

  constexpr IdempotencyKey() noexcept = default;
  constexpr IdempotencyKey(std::uint64_t high, std::uint64_t low) noexcept : hi(high), lo(low) {}

  [[nodiscard]] constexpr bool valid() const noexcept { return hi != 0 || lo != 0; }

  friend constexpr bool operator==(const IdempotencyKey& a, const IdempotencyKey& b) noexcept {
    return a.hi == b.hi && a.lo == b.lo;
  }
  friend constexpr bool operator!=(const IdempotencyKey& a, const IdempotencyKey& b) noexcept {
    return !(a == b);
  }
  friend constexpr bool operator<(const IdempotencyKey& a, const IdempotencyKey& b) noexcept {
    return a.hi != b.hi ? a.hi < b.hi : a.lo < b.lo;
  }
};

// ---------------------------------------------------------------------------
// Incident typing
// ---------------------------------------------------------------------------

/// Ordered severity. Higher values are more severe. c Unclassified is not a
/// severity an accepted incident may carry.
enum class Severity : std::uint8_t {
  Unclassified = 0,
  Informational = 1,
  Minor = 2,
  Major = 3,
  Critical = 4,
  Catastrophic = 5,
};
inline constexpr std::uint8_t kSeverityMin = 0;
inline constexpr std::uint8_t kSeverityMax = 5;

enum class IncidentClass : std::uint8_t {
  Unclassified = 0,
  Power = 1,
  Cooling = 2,
  Network = 3,
  Compute = 4,
  Storage = 5,
  FireSuppression = 6,
  WaterIngress = 7,
  PhysicalSecurity = 8,
  Structural = 9,
  Environmental = 10,
};
inline constexpr std::uint8_t kIncidentClassMax = 10;

/// Authoritative lifecycle. Distinct from the alarm or ticket that prompted it.
enum class LifecycleState : std::uint8_t {
  Reported = 1,
  Accepted = 2,
  Contained = 3,
  Recovering = 4,
  Recovered = 5,
  Resolved = 6,
  Closed = 7,
  Reopened = 8,
  Rejected = 9,
  Superseded = 10,
};
inline constexpr std::uint8_t kLifecycleStateMax = 10;

/// Authority attached to an actor. The role in a request is never trusted on
/// its own; it must match the role registered for that authority.
enum class AuthorityRole : std::uint8_t {
  None = 0,
  Observer = 1,
  Operator = 2,
  IncidentCommander = 3,
  DutyManager = 4,
  FacilityDirector = 5,
};
inline constexpr std::uint8_t kAuthorityRoleMax = 5;

enum class ObjectKind : std::uint8_t {
  Unknown = 0,
  Room = 1,
  Hall = 2,
  Row = 3,
  Rack = 4,
  Pdu = 5,
  Ups = 6,
  Generator = 7,
  Busway = 8,
  Crac = 9,
  Chiller = 10,
  CoolingLoop = 11,
  Switch = 12,
  Router = 13,
  Server = 14,
  StorageArray = 15,
  FirePanel = 16,
  SuppressionZone = 17,
  AccessPanel = 18,
  Sensor = 19,
  Workload = 20,
  Other = 255,
};

enum class FailureDomainKind : std::uint8_t {
  Unknown = 0,
  PowerFeed = 1,
  CoolingLoop = 2,
  NetworkPlane = 3,
  Zone = 4,
  Hall = 5,
  Room = 6,
  Row = 7,
  Utility = 8,
  Other = 255,
};

enum class EvidenceKind : std::uint8_t {
  Report = 1,
  SeverityAssessment = 2,
  Acknowledgement = 3,
  EffectObservation = 4,
  MitigationRequest = 5,
  AlarmSilence = 6,
  ContainmentProof = 7,
  RecoveryProof = 8,
  EffectCleared = 9,
  ClosureAttestation = 10,
  ReopenTrigger = 11,
  MaintenanceWindowNotice = 12,
};
inline constexpr std::uint8_t kEvidenceKindMax = 12;

/// Evidence is classified into exactly two kinds.
///
/// DynamicObservation records a measurement of the facility at a moment. It is
/// valid only inside the incident's current observation generation; a recovered
/// incident demotes every earlier observation to history and freshness must be
/// re-established explicitly.
///
/// DurableAttestation records a deliberate, authority-backed assertion about
/// the incident (containment proven, recovery proven, effect cleared, closure
/// attested). It stays valid across observation generations until the incident
/// is reopened, which invalidates every prior attestation.
enum class EvidenceClass : std::uint8_t {
  DynamicObservation = 1,
  DurableAttestation = 2,
};

/// Every durably committed operation. Values are part of the on-disk format and
/// must never be renumbered.
enum class OpKind : std::uint32_t {
  SessionOpen = 1,
  SessionClose = 2,

  RegisterAuthority = 10,
  RevokeAuthority = 11,
  ForceFence = 12,

  ReportIncident = 20,
  AcceptIncident = 21,
  RejectReport = 22,
  RecordEvidence = 23,
  WithdrawEvidence = 24,
  ReestablishEvidence = 25,
  AmendSeverity = 26,
  AmendScope = 27,
  AssignOwner = 28,

  DeclareContained = 30,
  StartRecovery = 31,
  DeclareRecovered = 32,
  ResolveIncident = 33,
  CloseIncident = 34,
  ReopenIncident = 35,
  CreateSuccessor = 36,
  MergeIncident = 37,
};

// ---------------------------------------------------------------------------
// Stable names
// ---------------------------------------------------------------------------

[[nodiscard]] const char* ToString(Severity value) noexcept;
[[nodiscard]] const char* ToString(IncidentClass value) noexcept;
[[nodiscard]] const char* ToString(LifecycleState value) noexcept;
[[nodiscard]] const char* ToString(AuthorityRole value) noexcept;
[[nodiscard]] const char* ToString(ObjectKind value) noexcept;
[[nodiscard]] const char* ToString(FailureDomainKind value) noexcept;
[[nodiscard]] const char* ToString(EvidenceKind value) noexcept;
[[nodiscard]] const char* ToString(EvidenceClass value) noexcept;
[[nodiscard]] const char* ToString(OpKind value) noexcept;

/// Evidence classification for a kind. Deterministic, total, and part of the
/// documented semantics.
[[nodiscard]] EvidenceClass ClassifyEvidence(EvidenceKind kind) noexcept;

/// True when the state admits no further lifecycle transition other than the
/// explicitly documented exceptions.
[[nodiscard]] bool IsTerminal(LifecycleState state) noexcept;

/// True for states in which the incident is still operationally live.
[[nodiscard]] bool IsLive(LifecycleState state) noexcept;

[[nodiscard]] bool IsKnownSeverity(std::uint8_t raw) noexcept;
[[nodiscard]] bool IsKnownIncidentClass(std::uint8_t raw) noexcept;
[[nodiscard]] bool IsKnownLifecycleState(std::uint8_t raw) noexcept;
[[nodiscard]] bool IsKnownAuthorityRole(std::uint8_t raw) noexcept;
[[nodiscard]] bool IsKnownEvidenceKind(std::uint8_t raw) noexcept;
[[nodiscard]] bool IsKnownOpKind(std::uint32_t raw) noexcept;

}  // namespace isf

#endif  // ISF_TYPES_H
