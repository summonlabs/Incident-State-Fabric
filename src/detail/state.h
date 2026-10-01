// Incident State Fabric - DCCP boundary 50
// Copyright 2026 Summon Software Labs.
// Licensed under the Apache License, Version 2.0.
//
// Authoritative in-memory state and the effect record that is written to the
// log. An effect is the complete post-image of everything one operation
// changed, so replay applies effects blindly instead of re-running policy.
// That makes recovery independent of later changes to gate logic.

#ifndef ISF_DETAIL_STATE_H
#define ISF_DETAIL_STATE_H

#include <cstddef>
#include <cstdint>
#include <map>
#include <string>
#include <vector>

#include "detail/crypto.h"
#include "detail/format.h"
#include "isf/model.h"
#include "isf/result.h"
#include "isf/types.h"

namespace isf::detail {

struct AuthorityRecord {
  AuthorityId id;
  std::string name;
  AuthorityRole role = AuthorityRole::None;
  bool active = false;
  Generation registered_at;
  Generation revoked_at;
  std::string rationale;
};

struct IncidentRecord {
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
  std::vector<EvidenceId> evidence_ids;
};

struct EvidenceRecord {
  EvidenceId id;
  IncidentId incident;
  EvidenceKind kind = EvidenceKind::Report;
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
};

struct IdemRecord {
  IdempotencyKey key;
  Digest256 intent;
  Generation generation;
  CommitReceipt receipt;
};

struct State {
  Generation generation;
  ControlEpoch control_epoch;
  std::uint64_t incarnation = 0;
  bool session_open = false;
  bool last_close_clean = true;
  std::uint64_t next_incident_id = 1;
  std::uint64_t next_evidence_id = 1;
  std::uint64_t next_authority_id = 1;

  std::map<AuthorityId, AuthorityRecord> authorities;
  std::map<std::string, AuthorityId> authority_names;
  std::map<IncidentId, IncidentRecord> incidents;
  std::map<EvidenceId, EvidenceRecord> evidence;
  std::map<IdempotencyKey, IdemRecord> idempotency;
  std::map<std::string, IncidentId> report_dedup;
  std::vector<AuditEntry> audit;

  [[nodiscard]] const AuthorityRecord* FindAuthority(AuthorityId id) const;
  [[nodiscard]] const IncidentRecord* FindIncident(IncidentId id) const;
  [[nodiscard]] const EvidenceRecord* FindEvidence(EvidenceId id) const;
  [[nodiscard]] IncidentRecord* MutableIncident(IncidentId id);
  [[nodiscard]] EvidenceRecord* MutableEvidence(EvidenceId id);
  [[nodiscard]] StateCounters Counters() const;
};

/// Deduplication token built from the reporting source. Never empty: callers
/// that supply no source identity get no duplicate suppression.
[[nodiscard]] std::string ReportDedupToken(const std::string& source_system,
                                           const std::string& source_event_id);

/// The complete description of one durable operation.
struct Effect {
  OpKind op = OpKind::SessionOpen;
  Generation generation;
  AuthorityId actor;
  IdempotencyKey key;
  /// Digest of the request intent that produced this effect. It is persisted so
  /// that replay rebuilds the idempotency index byte for byte.
  Digest256 intent;
  std::uint64_t request_epoch = 0;

  std::uint64_t incarnation = 0;
  std::uint64_t control_epoch_after = 0;
  bool session_open = false;
  bool clean_close = false;

  AuthorityId authority;
  std::string authority_name;
  AuthorityRole authority_role = AuthorityRole::None;
  bool authority_active = false;

  IncidentId incident;
  std::uint64_t incident_revision = 0;
  IncidentClass cls = IncidentClass::Unclassified;
  Severity severity = Severity::Unclassified;
  LifecycleState state = LifecycleState::Reported;
  AffectedScope scope;
  AuthorityId owner;
  bool recovery_started = false;
  bool containment_declared = false;
  std::uint64_t observation_generation = 0;
  std::uint64_t attestation_generation = 0;
  std::uint64_t reopen_count = 0;
  std::uint64_t escalation_count = 0;
  Generation last_escalation_at;
  std::string summary;
  std::string source_system;
  std::string source_event_id;

  IncidentId secondary_incident;
  std::uint64_t secondary_revision = 0;
  LifecycleState secondary_state = LifecycleState::Reported;
  bool cross_class = false;

  EvidenceId evidence;
  EvidenceKind evidence_kind = EvidenceKind::Report;
  bool evidence_withdrawn = false;
  bool evidence_reestablished = false;
  AffectedScope evidence_subject;
  Severity evidence_asserted_severity = Severity::Unclassified;
  bool evidence_effect_present = false;
  std::string evidence_rationale;
  std::string evidence_source_system;
  std::string evidence_source_event_id;
  std::string evidence_detail;

  std::uint64_t next_incident_id = 0;
  std::uint64_t next_evidence_id = 0;
  std::uint64_t next_authority_id = 0;

  bool created_incident = false;
  bool duplicate_report = false;

  std::string rationale;
};

/// The receipt a committed effect produces. Both the live commit path and
/// replay use this function, so a replayed receipt is byte-identical to the
/// original by construction.
[[nodiscard]] CommitReceipt ReceiptFor(const Effect& effect);

[[nodiscard]] std::vector<std::byte> EncodeEffect(const Effect& effect);
[[nodiscard]] Result<Effect> DecodeEffect(OpKind op, const std::byte* data, std::size_t length);

/// Apply one committed effect. Returns an error only for a log that is
/// internally inconsistent, which recovery reports as StoreCorrupt.
[[nodiscard]] Status ApplyEffect(State& state, const Effect& effect);

/// Deterministic digest of the entire authoritative state.
[[nodiscard]] Digest256 ComputeStateDigest(const State& state);

/// Canonical, caller-independent audit text for a committed effect.
[[nodiscard]] std::string DescribeEffect(const Effect& effect);

[[nodiscard]] bool IsEvidenceCurrent(const EvidenceRecord& evidence, const IncidentRecord& incident);

[[nodiscard]] AuthorityView ToView(const AuthorityRecord& record);
[[nodiscard]] IncidentSummary ToSummary(const IncidentRecord& record);
[[nodiscard]] IncidentView ToView(const IncidentRecord& record);
[[nodiscard]] EvidenceView ToView(const EvidenceRecord& record, const IncidentRecord& incident);

}  // namespace isf::detail

#endif  // ISF_DETAIL_STATE_H
