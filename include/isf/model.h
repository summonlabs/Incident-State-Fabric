// Incident State Fabric - DCCP boundary 50
// Copyright 2026 Summon Software Labs.
// Licensed under the Apache License, Version 2.0.
//
// Value types describing authoritative incident state, plus the static policy
// tables that make every decision reproducible.

#ifndef ISF_MODEL_H
#define ISF_MODEL_H

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

#include "isf/result.h"
#include "isf/types.h"

namespace isf {

// ---------------------------------------------------------------------------
// Format constants. These are part of persistence format v1 and may not change
// without bumping the format version.
// ---------------------------------------------------------------------------
struct FormatLimits {
  static constexpr std::uint16_t kVersion = 1;
  static constexpr std::uint64_t kSegmentTargetBytes = 4ull * 1024 * 1024;
  static constexpr std::uint64_t kMaxSegmentBytes = 64ull * 1024 * 1024;
  static constexpr std::uint64_t kMaxRecordBytes = 1ull * 1024 * 1024;
  static constexpr std::uint64_t kMaxManifestBytes = 1ull * 1024 * 1024;
  static constexpr std::uint32_t kMaxSegments = 4096;
  static constexpr std::size_t kSegmentSuffixDigits = 20;
  static constexpr char kStoreFormatId[8] = {'I', 'S', 'F', 'S', 'T', 'O', 'R', 'E'};
};

/// Bounds on free-text and collection fields. Values are validated before a
/// request reaches the durable commit path.
struct FieldLimits {
  static constexpr std::size_t kToken = 128;
  static constexpr std::size_t kSummary = 512;
  static constexpr std::size_t kRationale = 1024;
  static constexpr std::size_t kDetail = 4096;
  static constexpr std::size_t kName = 128;
  static constexpr std::size_t kScopeObjects = 256;
  static constexpr std::size_t kScopeDomains = 64;
};

/// Numeric policy constants. Every window is measured in durable generations,
/// never in wall-clock time.
struct PolicyConstants {
  static constexpr std::uint64_t kMaxReopens = 2;
  static constexpr std::uint64_t kDeescalationQuietGenerations = 4;
  static constexpr std::uint64_t kDeescalationConfirmations = 2;
  static constexpr std::uint32_t kMaxListPage = 1000;
};

// ---------------------------------------------------------------------------
// Affected scope
// ---------------------------------------------------------------------------

struct ObjectRef {
  ObjectKind kind = ObjectKind::Unknown;
  std::string id;

  friend bool operator==(const ObjectRef& a, const ObjectRef& b) noexcept {
    return a.kind == b.kind && a.id == b.id;
  }
  friend bool operator!=(const ObjectRef& a, const ObjectRef& b) noexcept { return !(a == b); }
  friend bool operator<(const ObjectRef& a, const ObjectRef& b) noexcept {
    if (a.kind != b.kind) return a.kind < b.kind;
    return a.id < b.id;
  }
};

struct FailureDomainRef {
  FailureDomainKind kind = FailureDomainKind::Unknown;
  std::string id;

  friend bool operator==(const FailureDomainRef& a, const FailureDomainRef& b) noexcept {
    return a.kind == b.kind && a.id == b.id;
  }
  friend bool operator!=(const FailureDomainRef& a, const FailureDomainRef& b) noexcept { return !(a == b); }
  friend bool operator<(const FailureDomainRef& a, const FailureDomainRef& b) noexcept {
    if (a.kind != b.kind) return a.kind < b.kind;
    return a.id < b.id;
  }
};

/// The objects and failure domains an incident is authoritative over. Always
/// held sorted and de-duplicated so canonical output never depends on the order
/// the caller supplied.
struct AffectedScope {
  std::vector<ObjectRef> objects;
  std::vector<FailureDomainRef> failure_domains;

  [[nodiscard]] bool empty() const noexcept { return objects.empty() && failure_domains.empty(); }

  friend bool operator==(const AffectedScope& a, const AffectedScope& b) noexcept {
    return a.objects == b.objects && a.failure_domains == b.failure_domains;
  }
  friend bool operator!=(const AffectedScope& a, const AffectedScope& b) noexcept { return !(a == b); }
};

/// Sort and de-duplicate in place. Returns the same scope for chaining.
AffectedScope& Canonicalize(AffectedScope& scope);

// ---------------------------------------------------------------------------
// Class policy
// ---------------------------------------------------------------------------

struct IncidentClassPolicy {
  bool requires_containment = true;
  bool requires_recovery = true;
  AuthorityRole resolution_role = AuthorityRole::DutyManager;
  AuthorityRole closure_role = AuthorityRole::FacilityDirector;
};

[[nodiscard]] IncidentClassPolicy PolicyFor(IncidentClass cls) noexcept;

// ---------------------------------------------------------------------------
// Authoritative views
// ---------------------------------------------------------------------------

struct AuthorityView {
  AuthorityId id;
  std::string name;
  AuthorityRole role = AuthorityRole::None;
  bool active = false;
  Generation registered_at;
  Generation revoked_at;
  std::string rationale;
};

struct LifecycleEvent {
  OpKind op = OpKind::SessionOpen;
  Generation at;
  LifecycleState from = LifecycleState::Reported;
  LifecycleState to = LifecycleState::Reported;
  Severity from_severity = Severity::Unclassified;
  Severity to_severity = Severity::Unclassified;
  AuthorityId actor;
  std::uint64_t revision = 0;
  std::string rationale;
};

struct IncidentSummary {
  IncidentId id;
  IncidentClass cls = IncidentClass::Unclassified;
  Severity severity = Severity::Unclassified;
  LifecycleState state = LifecycleState::Reported;
  std::uint64_t revision = 0;
  AuthorityId owner;
  Generation created_at;
  Generation updated_at;
  std::uint64_t evidence_count = 0;
  std::string summary;
};

struct IncidentView {
  IncidentId id;
  IncidentClass cls = IncidentClass::Unclassified;
  Severity severity = Severity::Unclassified;
  LifecycleState state = LifecycleState::Reported;
  std::uint64_t revision = 0;
  std::uint64_t observation_generation = 1;
  std::uint64_t attestation_generation = 1;
  std::uint64_t reopen_count = 0;
  bool recovery_started = false;
  bool containment_declared = false;
  AuthorityId owner;
  AuthorityId reported_by;
  AuthorityId accepting_authority;
  AffectedScope scope;
  std::string summary;
  std::string source_system;
  std::string source_event_id;
  IncidentId parent;
  IncidentId predecessor;
  Generation created_at;
  Generation updated_at;
  Generation last_escalation_at;
  std::uint64_t escalation_count = 0;
  std::vector<LifecycleEvent> history;
};

struct EvidenceView {
  EvidenceId id;
  IncidentId incident;
  EvidenceKind kind = EvidenceKind::Report;
  EvidenceClass cls = EvidenceClass::DynamicObservation;
  AuthorityId source;
  Generation recorded_at;
  std::uint64_t observation_generation = 1;
  std::uint64_t attestation_generation = 1;
  bool withdrawn = false;
  Generation withdrawn_at;
  AuthorityId withdrawn_by;
  AffectedScope subject;
  Severity asserted_severity = Severity::Unclassified;
  bool effect_present = false;
  std::string rationale;
  std::string source_system;
  std::string source_event_id;
  std::string detail;

  /// True when this record is admissible for the incident's current
  /// generations. Recomputed on every read; never stored.
  bool current = false;
};

/// Lineage of an incident: the successor chain it descends from and the
/// incidents that descend from it. Merge parents and successor predecessors are
/// both reported so reopen-versus-successor behaviour stays auditable.
struct LineageView {
  IncidentId subject;
  std::vector<IncidentSummary> predecessors;
  std::vector<IncidentSummary> successors;
  std::vector<IncidentSummary> merged_children;
};

struct AuditEntry {
  Generation generation;
  OpKind op = OpKind::SessionOpen;
  AuthorityId actor;
  IncidentId incident;
  std::uint64_t incident_revision = 0;
  std::string summary;
};

// ---------------------------------------------------------------------------
// Outcomes
// ---------------------------------------------------------------------------

struct CommitReceipt {
  Generation generation;
  IdempotencyKey key;
  OpKind op = OpKind::SessionOpen;
  bool replayed = false;
  bool created_incident = false;
  bool duplicate_report = false;
  IncidentId incident;
  std::uint64_t incident_revision = 0;
  EvidenceId evidence;
  AuthorityId authority;
};

/// A single reason a request would be refused. Emitted in a stable order so
/// denial reports are byte-identical across runs.
struct GateFailure {
  ErrorCode code = ErrorCode::Ok;
  EvidenceKind required_kind = EvidenceKind::Report;
  std::string field;
  std::string detail;
};

struct TransitionPreview {
  bool would_commit = false;
  ErrorCode code = ErrorCode::Ok;
  std::string detail;
  std::vector<GateFailure> failures;
  LifecycleState from_state = LifecycleState::Reported;
  LifecycleState to_state = LifecycleState::Reported;
  Severity from_severity = Severity::Unclassified;
  Severity to_severity = Severity::Unclassified;
  std::uint64_t from_revision = 0;
  std::uint64_t to_revision = 0;
  bool replayed = false;
  IncidentId incident;
};

// ---------------------------------------------------------------------------
// Queries
// ---------------------------------------------------------------------------

struct ListQuery {
  std::uint32_t offset = 0;
  std::uint32_t limit = 100;
};

struct AuditQuery {
  Generation from;
  std::uint32_t limit = 100;
};

// ---------------------------------------------------------------------------
// Status
// ---------------------------------------------------------------------------

struct StoreLimits {
  std::uint64_t max_incidents = 1'000'000;
  std::uint64_t max_evidence_per_incident = 4'096;
  std::uint64_t max_authorities = 4'096;
  std::uint64_t max_idempotency_entries = 1'000'000;
  std::uint64_t max_audit_entries = 4'000'000;
};

enum class StateDigestPolicy : std::uint8_t {
  /// Recompute and store the whole-state digest on every durable commit.
  EveryCommit = 1,
  /// Store the digest only at explicit checkpoints and on clean close.
  OnCheckpoint = 2,
};

struct OpenOptions {
  /// UTF-8 filesystem path of the store directory.
  std::string path;
  bool create_if_missing = true;
  /// Refuse to operate when the store root is a symbolic link, junction, or
  /// other reparse point. Off by default so a deployment that deliberately
  /// aliases storage must opt in explicitly.
  bool allow_reparse_root = false;
  StateDigestPolicy state_digest = StateDigestPolicy::EveryCommit;
  StoreLimits limits{};
};

struct FabricStatus {
  std::string store_path;
  std::string format_id;
  std::uint16_t format_version = 0;
  Generation generation;
  ControlEpoch control_epoch;
  std::uint64_t incarnation = 0;
  bool session_open = false;
  bool last_close_clean = false;
  std::uint32_t segment_count = 0;
  std::uint64_t record_count = 0;
  std::uint64_t incident_count = 0;
  std::uint64_t evidence_count = 0;
  std::uint64_t authority_count = 0;
  std::uint64_t idempotency_count = 0;
  std::uint64_t audit_count = 0;
  std::string state_digest_hex;
  std::uint64_t recovered_tail_bytes = 0;
  std::uint64_t removed_orphan_segments = 0;
  std::uint64_t removed_test_hook_records = 0;
  /// Set when a durable commit failed part way through. The in-memory view may
  /// then be ahead of the durable log, so every operation except GetStatus is
  /// refused until the store is reopened.
  bool write_failed = false;
  std::string state_digest_policy;
};

}  // namespace isf

#endif  // ISF_MODEL_H
