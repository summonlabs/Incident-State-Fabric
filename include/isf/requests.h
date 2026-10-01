// Incident State Fabric - DCCP boundary 50
// Copyright 2026 Summon Software Labs.
// Licensed under the Apache License, Version 2.0.
//
// Request types. Every mutation carries an actor, a fencing epoch, an
// idempotency key, and - for anything that touches an existing incident - the
// exact incident revision the caller believes is current.

#ifndef ISF_REQUESTS_H
#define ISF_REQUESTS_H

#include <cstdint>
#include <string>
#include <variant>
#include <vector>

#include "isf/model.h"
#include "isf/types.h"

namespace isf {

struct ActorRef {
  /// Registered authority performing the operation. Zero is only legal for the
  /// single bootstrap registration on an empty registry.
  AuthorityId authority;
  /// Fencing token observed by the caller.
  ControlEpoch epoch;
};

struct MutationHeader {
  ActorRef actor;
  IdempotencyKey key;
};

// ---------------------------------------------------------------------------
// Authority registry
// ---------------------------------------------------------------------------

struct RegisterAuthorityRequest {
  MutationHeader header;
  std::string name;
  AuthorityRole role = AuthorityRole::Observer;
  std::string rationale;
};

struct RevokeAuthorityRequest {
  MutationHeader header;
  AuthorityId target;
  std::string rationale;
};

/// Advance the control epoch so that every outstanding actor is fenced.
struct ForceFenceRequest {
  MutationHeader header;
  std::string rationale;
};

// ---------------------------------------------------------------------------
// Reporting and triage
// ---------------------------------------------------------------------------

struct ReportIncidentRequest {
  MutationHeader header;
  IncidentClass cls = IncidentClass::Unclassified;
  Severity reported_severity = Severity::Unclassified;
  std::string summary;
  AffectedScope scope;
  std::string source_system;
  std::string source_event_id;
  std::string detail;
};

struct AcceptIncidentRequest {
  MutationHeader header;
  IncidentId incident;
  std::uint64_t expected_revision = 0;
  IncidentClass cls = IncidentClass::Unclassified;
  Severity severity = Severity::Unclassified;
  /// Current SeverityAssessment evidence whose asserted severity matches
  /// \c severity. Acknowledging a report is not severity evidence.
  EvidenceId severity_evidence;
  AuthorityId owner;
  std::string rationale;
};

struct RejectReportRequest {
  MutationHeader header;
  IncidentId incident;
  std::uint64_t expected_revision = 0;
  std::string rationale;
};

// ---------------------------------------------------------------------------
// Evidence
// ---------------------------------------------------------------------------

struct RecordEvidenceRequest {
  MutationHeader header;
  IncidentId incident;
  std::uint64_t expected_revision = 0;
  EvidenceKind kind = EvidenceKind::Report;
  AffectedScope subject;
  Severity asserted_severity = Severity::Unclassified;
  bool effect_present = false;
  std::string rationale;
  std::string source_system;
  std::string source_event_id;
  std::string detail;
};

struct WithdrawEvidenceRequest {
  MutationHeader header;
  IncidentId incident;
  std::uint64_t expected_revision = 0;
  EvidenceId evidence;
  std::string rationale;
};

/// Explicitly promote a historic dynamic observation into the incident's
/// current observation generation. Recovered observations never become fresh on
/// their own.
struct ReestablishEvidenceRequest {
  MutationHeader header;
  IncidentId incident;
  std::uint64_t expected_revision = 0;
  EvidenceId evidence;
  std::string rationale;
};

// ---------------------------------------------------------------------------
// Incident content
// ---------------------------------------------------------------------------

struct AmendSeverityRequest {
  MutationHeader header;
  IncidentId incident;
  std::uint64_t expected_revision = 0;
  Severity severity = Severity::Unclassified;
  /// Current SeverityAssessment evidence supporting \c severity.
  std::vector<EvidenceId> supporting_evidence;
  std::string rationale;
};

struct AmendScopeRequest {
  MutationHeader header;
  IncidentId incident;
  std::uint64_t expected_revision = 0;
  AffectedScope scope;
  std::string rationale;
};

struct AssignOwnerRequest {
  MutationHeader header;
  IncidentId incident;
  std::uint64_t expected_revision = 0;
  AuthorityId owner;
  std::string rationale;
};

// ---------------------------------------------------------------------------
// Lifecycle
// ---------------------------------------------------------------------------

struct DeclareContainedRequest {
  MutationHeader header;
  IncidentId incident;
  std::uint64_t expected_revision = 0;
  /// Current ContainmentProof. An acknowledgement never satisfies this gate.
  EvidenceId proof;
  std::string rationale;
};

struct StartRecoveryRequest {
  MutationHeader header;
  IncidentId incident;
  std::uint64_t expected_revision = 0;
  std::string rationale;
};

struct DeclareRecoveredRequest {
  MutationHeader header;
  IncidentId incident;
  std::uint64_t expected_revision = 0;
  /// Current RecoveryProof. Starting recovery does not prove it.
  EvidenceId proof;
  std::string rationale;
};

struct ResolveIncidentRequest {
  MutationHeader header;
  IncidentId incident;
  std::uint64_t expected_revision = 0;
  /// Current EffectCleared. Alarm silence is a different evidence kind and is
  /// never accepted here.
  EvidenceId clearance;
  std::string rationale;
};

struct CloseIncidentRequest {
  MutationHeader header;
  IncidentId incident;
  std::uint64_t expected_revision = 0;
  /// Current ClosureAttestation.
  EvidenceId attestation;
  std::string rationale;
};

struct ReopenIncidentRequest {
  MutationHeader header;
  IncidentId incident;
  std::uint64_t expected_revision = 0;
  /// Current ReopenTrigger recorded before the reopen.
  EvidenceId trigger;
  std::string rationale;
};

struct CreateSuccessorRequest {
  MutationHeader header;
  IncidentId predecessor;
  std::uint64_t expected_predecessor_revision = 0;
  IncidentClass cls = IncidentClass::Unclassified;
  Severity reported_severity = Severity::Unclassified;
  std::string summary;
  AffectedScope scope;
  std::string source_system;
  std::string source_event_id;
  std::string detail;
  std::string rationale;
};

struct MergeIncidentRequest {
  MutationHeader header;
  IncidentId survivor;
  std::uint64_t expected_survivor_revision = 0;
  IncidentId absorbed;
  std::uint64_t expected_absorbed_revision = 0;
  bool allow_cross_class = false;
  std::string rationale;
};

using AnyRequest = std::variant<RegisterAuthorityRequest,
                                RevokeAuthorityRequest,
                                ForceFenceRequest,
                                ReportIncidentRequest,
                                AcceptIncidentRequest,
                                RejectReportRequest,
                                RecordEvidenceRequest,
                                WithdrawEvidenceRequest,
                                ReestablishEvidenceRequest,
                                AmendSeverityRequest,
                                AmendScopeRequest,
                                AssignOwnerRequest,
                                DeclareContainedRequest,
                                StartRecoveryRequest,
                                DeclareRecoveredRequest,
                                ResolveIncidentRequest,
                                CloseIncidentRequest,
                                ReopenIncidentRequest,
                                CreateSuccessorRequest,
                                MergeIncidentRequest>;

[[nodiscard]] const MutationHeader& HeaderOf(const AnyRequest& request) noexcept;
[[nodiscard]] OpKind KindOf(const AnyRequest& request) noexcept;

}  // namespace isf

#endif  // ISF_REQUESTS_H
