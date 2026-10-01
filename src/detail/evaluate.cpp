// Incident State Fabric - DCCP boundary 50
// Copyright 2026 Summon Software Labs.
// Licensed under the Apache License, Version 2.0.

#include "detail/evaluate.h"

#include <algorithm>
#include <string>
#include <tuple>
#include <type_traits>
#include <utility>

#include "detail/canonical.h"
#include "detail/request_codec.h"

namespace isf::detail {
namespace {

// ---------------------------------------------------------------------------
// Gate failure bookkeeping
// ---------------------------------------------------------------------------

Status Deny(Evaluation& evaluation, ErrorCode code, std::string detail) {
  evaluation.kind = DecisionKind::Denied;
  evaluation.denial = Status::Error(code, std::move(detail));
  return evaluation.denial;
}

void Fail(Evaluation& evaluation, ErrorCode code, EvidenceKind kind, std::string field,
          std::string detail) {
  GateFailure failure;
  failure.code = code;
  failure.required_kind = kind;
  failure.field = std::move(field);
  failure.detail = std::move(detail);
  evaluation.failures.push_back(std::move(failure));
}

[[nodiscard]] Status FinishGates(Evaluation& evaluation) {
  if (evaluation.failures.empty()) return Status::Ok();
  std::sort(evaluation.failures.begin(), evaluation.failures.end(),
            [](const GateFailure& a, const GateFailure& b) {
              return std::tie(a.code, a.required_kind, a.field, a.detail) <
                     std::tie(b.code, b.required_kind, b.field, b.detail);
            });
  std::string detail = "transition refused:";
  for (const GateFailure& failure : evaluation.failures) {
    detail += " [";
    detail += ToString(failure.code);
    detail += "] ";
    detail += failure.field;
    detail += ": ";
    detail += failure.detail;
    detail += ";";
  }
  return Deny(evaluation, ErrorCode::GateUnsatisfied, std::move(detail));
}

// ---------------------------------------------------------------------------
// Checked arithmetic
// ---------------------------------------------------------------------------

[[nodiscard]] Status NextValue(std::uint64_t current, const char* field, std::uint64_t& out) {
  if (current == UINT64_MAX) {
    return Status::Error(ErrorCode::Overflow, std::string(field) + " would overflow");
  }
  out = current + 1;
  return Status::Ok();
}

// ---------------------------------------------------------------------------
// Evaluation context
// ---------------------------------------------------------------------------

struct Guard {
  const State& state;
  const StoreLimits& limits;
  Evaluation& evaluation;
  const AuthorityRecord* actor = nullptr;
  bool bootstrap = false;

  [[nodiscard]] bool denied() const noexcept {
    return evaluation.kind == DecisionKind::Denied;
  }
  [[nodiscard]] AuthorityRole role() const noexcept {
    return bootstrap ? AuthorityRole::FacilityDirector : actor->role;
  }
  [[nodiscard]] AuthorityId actor_id() const noexcept {
    return actor == nullptr ? AuthorityId{} : actor->id;
  }
};

[[nodiscard]] Status RequireRole(Guard& guard, AuthorityRole minimum, const char* what) {
  if (guard.denied()) return guard.evaluation.denial;
  const AuthorityRole held = guard.role();
  if (held < minimum) {
    return Deny(guard.evaluation, ErrorCode::Unauthorized,
                std::string(what) + " requires role " + ToString(minimum) +
                    " or higher but the caller holds " + ToString(held));
  }
  return Status::Ok();
}

// ---------------------------------------------------------------------------
// Evidence gates
// ---------------------------------------------------------------------------

struct KindHint {
  EvidenceKind missing;
  EvidenceKind confusing;
  const char* detail;
};

/// Pairs that must never be conflated. When a required evidence kind is absent
/// but the incident holds a current record of a related kind, the denial names
/// the confusion explicitly instead of only reporting a missing record.
constexpr KindHint kKindHints[] = {
    {EvidenceKind::ContainmentProof, EvidenceKind::Acknowledgement,
     "acknowledging a report is not containment"},
    {EvidenceKind::ContainmentProof, EvidenceKind::MitigationRequest,
     "a requested mitigation is not containment"},
    {EvidenceKind::EffectCleared, EvidenceKind::AlarmSilence,
     "quiescent alarms are not evidence that the effect cleared"},
    {EvidenceKind::EffectCleared, EvidenceKind::Acknowledgement,
     "acknowledgement is not evidence that the effect cleared"},
    {EvidenceKind::EffectCleared, EvidenceKind::MitigationRequest,
     "a requested mitigation is not an observed effect"},
    {EvidenceKind::RecoveryProof, EvidenceKind::MitigationRequest,
     "a requested mitigation does not prove recovery"},
    {EvidenceKind::RecoveryProof, EvidenceKind::ContainmentProof,
     "containment does not prove recovery"},
    {EvidenceKind::SeverityAssessment, EvidenceKind::Acknowledgement,
     "acknowledgement is not severity evidence"},
    {EvidenceKind::ClosureAttestation, EvidenceKind::AlarmSilence,
     "closure may not rest on alarm silence"},
    {EvidenceKind::ReopenTrigger, EvidenceKind::AlarmSilence,
     "alarm silence is not a reason to reopen an incident"},
};

template <typename Predicate>
[[nodiscard]] const EvidenceRecord* FindCurrent(const State& state, const IncidentRecord& incident,
                                                EvidenceKind kind, Predicate predicate) {
  const EvidenceRecord* best = nullptr;
  for (const EvidenceId id : incident.evidence_ids) {
    const EvidenceRecord* record = state.FindEvidence(id);
    if (record == nullptr || record->kind != kind) continue;
    if (!IsEvidenceCurrent(*record, incident)) continue;
    if (!predicate(*record)) continue;
    if (best == nullptr || record->id < best->id) best = record;
  }
  return best;
}

[[nodiscard]] bool HasCurrentOfKind(const State& state, const IncidentRecord& incident,
                                    EvidenceKind kind) {
  return FindCurrent(state, incident, kind, [](const EvidenceRecord&) { return true; }) != nullptr;
}

/// Records a gate failure for a missing current evidence record, preferring the
/// most specific "these are different things" explanation.
void RequireEvidence(Guard& guard, const IncidentRecord& incident, EvidenceKind kind,
                     const char* field) {
  if (guard.denied()) return;
  if (HasCurrentOfKind(guard.state, incident, kind)) return;
  for (const KindHint& hint : kKindHints) {
    if (hint.missing != kind) continue;
    if (HasCurrentOfKind(guard.state, incident, hint.confusing)) {
      Fail(guard.evaluation, ErrorCode::GateUnsatisfied, kind, field, hint.detail);
      return;
    }
  }
  std::string detail = "no current ";
  detail += ToString(kind);
  detail += " is recorded for this incident in its current evidence generation";
  Fail(guard.evaluation, ErrorCode::GateUnsatisfied, kind, field, std::move(detail));
}

/// A named reference that must be a current record of a specific kind.
void RequireReferencedEvidence(Guard& guard, const IncidentRecord& incident, EvidenceId id,
                               EvidenceKind kind, const char* field) {
  if (guard.denied()) return;
  const EvidenceRecord* record = guard.state.FindEvidence(id);
  if (record == nullptr) {
    Fail(guard.evaluation, ErrorCode::NotFound, kind, field,
         "evidence " + std::to_string(id.value()) + " does not exist");
    return;
  }
  if (record->incident != incident.id) {
    Fail(guard.evaluation, ErrorCode::Conflict, kind, field,
         "evidence " + std::to_string(id.value()) + " belongs to a different incident");
    return;
  }
  if (record->kind != kind) {
    std::string detail = "evidence ";
    detail += std::to_string(id.value());
    detail += " is ";
    detail += ToString(record->kind);
    detail += ", not ";
    detail += ToString(kind);
    Fail(guard.evaluation, ErrorCode::GateUnsatisfied, kind, field, std::move(detail));
    return;
  }
  if (record->withdrawn) {
    Fail(guard.evaluation, ErrorCode::NotCurrentEvidence, kind, field,
         "evidence " + std::to_string(id.value()) + " has been withdrawn");
    return;
  }
  if (!IsEvidenceCurrent(*record, incident)) {
    Fail(guard.evaluation, ErrorCode::NotCurrentEvidence, kind, field,
         "evidence " + std::to_string(id.value()) +
             " belongs to an earlier evidence generation and must be re-established explicitly");
  }
}

// ---------------------------------------------------------------------------
// Incident lookup
// ---------------------------------------------------------------------------

struct IncidentRef {
  const IncidentRecord* record = nullptr;
  std::uint64_t next_revision = 0;
};

[[nodiscard]] bool LookupIncident(Guard& guard, IncidentId id, std::uint64_t expected_revision,
                                  IncidentRef& out) {
  const IncidentRecord* record = guard.state.FindIncident(id);
  if (record == nullptr) {
    Deny(guard.evaluation, ErrorCode::NotFound,
         "incident " + std::to_string(id.value()) + " does not exist");
    return false;
  }
  if (record->revision != expected_revision) {
    Deny(guard.evaluation, ErrorCode::StaleRevision,
         "incident " + std::to_string(id.value()) + " is at revision " +
             std::to_string(record->revision) + " but the request bound revision " +
             std::to_string(expected_revision));
    return false;
  }
  std::uint64_t next_revision = 0;
  const Status status = NextValue(record->revision, "incident revision", next_revision);
  if (!status.ok()) {
    Deny(guard.evaluation, status.code(), status.message());
    return false;
  }
  out.record = record;
  out.next_revision = next_revision;
  guard.evaluation.from_state = record->state;
  guard.evaluation.to_state = record->state;
  guard.evaluation.from_severity = record->severity;
  guard.evaluation.to_severity = record->severity;
  guard.evaluation.from_revision = record->revision;
  guard.evaluation.to_revision = next_revision;
  guard.evaluation.incident = record->id;
  return true;
}

[[nodiscard]] Status RequireLiveIncident(Guard& guard, const IncidentRecord& incident,
                                         const char* what) {
  if (IsLive(incident.state)) return Status::Ok();
  return Deny(guard.evaluation, ErrorCode::IllegalTransition,
              std::string(what) + " is not possible for an incident in state " +
                  ToString(incident.state));
}

[[nodiscard]] bool RequireRegisteredAuthority(Guard& guard, AuthorityId id, const char* what,
                                              const AuthorityRecord*& out) {
  const AuthorityRecord* record = guard.state.FindAuthority(id);
  if (record == nullptr) {
    Deny(guard.evaluation, ErrorCode::AuthorityUnknown,
         std::string(what) + " references authority " + std::to_string(id.value()) +
             " which is not registered");
    return false;
  }
  if (!record->active) {
    Deny(guard.evaluation, ErrorCode::AuthorityRevoked,
         std::string(what) + " references authority " + std::to_string(id.value()) +
             " which has been revoked");
    return false;
  }
  out = record;
  return true;
}

// ---------------------------------------------------------------------------
// Operation evaluation
// ---------------------------------------------------------------------------

void EvalRegisterAuthority(Guard& guard, const RegisterAuthorityRequest& request) {
  const auto existing = guard.state.authority_names.find(request.name);
  if (existing != guard.state.authority_names.end()) {
    Deny(guard.evaluation, ErrorCode::AlreadyExists,
         "authority name '" + request.name + "' is already registered");
    return;
  }
  if (!guard.bootstrap) {
    const Status status = RequireRole(guard, AuthorityRole::DutyManager,
                                      "registering an authority");
    if (!status.ok()) return;
    if (guard.role() < request.role) {
      Deny(guard.evaluation, ErrorCode::Unauthorized,
           std::string("cannot grant role ") + ToString(request.role) + " from role " +
               ToString(guard.role()));
      return;
    }
  }
  std::uint64_t next_authority = 0;
  const Status status = NextValue(guard.state.next_authority_id, "authority identifier",
                                  next_authority);
  if (!status.ok()) {
    Deny(guard.evaluation, status.code(), status.message());
    return;
  }
  Effect& effect = guard.evaluation.effect;
  effect.authority = AuthorityId{guard.state.next_authority_id};
  effect.authority_name = request.name;
  effect.authority_role = request.role;
  effect.authority_active = true;
  effect.next_authority_id = next_authority;
  effect.next_incident_id = guard.state.next_incident_id;
  effect.next_evidence_id = guard.state.next_evidence_id;
}

void EvalRevokeAuthority(Guard& guard, const RevokeAuthorityRequest& request) {
  const AuthorityRecord* target = nullptr;
  if (!RequireRegisteredAuthority(guard, request.target, "revocation", target)) return;
  const Status status = RequireRole(guard, AuthorityRole::DutyManager, "revoking an authority");
  if (!status.ok()) return;
  if (guard.role() < target->role) {
    Deny(guard.evaluation, ErrorCode::Unauthorized,
         std::string("cannot revoke an authority holding role ") + ToString(target->role) +
             " from role " + ToString(guard.role()));
    return;
  }
  if (target->id == guard.actor_id()) {
    Deny(guard.evaluation, ErrorCode::Conflict,
         "an authority may not revoke itself; a peer with sufficient role must do it");
    return;
  }
  Effect& effect = guard.evaluation.effect;
  effect.authority = target->id;
  effect.next_authority_id = guard.state.next_authority_id;
  effect.next_incident_id = guard.state.next_incident_id;
  effect.next_evidence_id = guard.state.next_evidence_id;
}

void EvalForceFence(Guard& guard, const ForceFenceRequest&) {
  const Status status = RequireRole(guard, AuthorityRole::FacilityDirector,
                                    "advancing the control epoch");
  if (!status.ok()) return;
  std::uint64_t next_epoch = 0;
  const Status bumped = NextValue(guard.state.control_epoch.value, "control epoch", next_epoch);
  if (!bumped.ok()) {
    Deny(guard.evaluation, bumped.code(), bumped.message());
    return;
  }
  Effect& effect = guard.evaluation.effect;
  effect.control_epoch_after = next_epoch;
  effect.next_authority_id = guard.state.next_authority_id;
  effect.next_incident_id = guard.state.next_incident_id;
  effect.next_evidence_id = guard.state.next_evidence_id;
}

void EvalReportIncident(Guard& guard, const ReportIncidentRequest& request) {
  const Status role = RequireRole(guard, AuthorityRole::Operator, "reporting an incident");
  if (!role.ok()) return;
  if (request.scope.empty()) {
    Deny(guard.evaluation, ErrorCode::InvalidArgument,
         "a report must name at least one affected object or failure domain");
    return;
  }
  AffectedScope scope = request.scope;
  const Status canonical = ValidateAndCanonicalizeScope(scope, "scope");
  if (!canonical.ok()) {
    Deny(guard.evaluation, canonical.code(), canonical.message());
    return;
  }

  const std::string token = ReportDedupToken(request.source_system, request.source_event_id);
  const IncidentRecord* existing = nullptr;
  if (!token.empty()) {
    const auto it = guard.state.report_dedup.find(token);
    if (it != guard.state.report_dedup.end()) {
      const IncidentRecord* candidate = guard.state.FindIncident(it->second);
      if (candidate != nullptr && IsLive(candidate->state)) existing = candidate;
    }
  }

  Effect& effect = guard.evaluation.effect;
  effect.scope = scope;
  effect.summary = request.summary;
  effect.source_system = request.source_system;
  effect.source_event_id = request.source_event_id;
  effect.owner = guard.actor_id();
  effect.cls = request.cls;
  effect.severity = request.reported_severity;
  effect.state = LifecycleState::Reported;
  effect.evidence_kind = EvidenceKind::Report;
  effect.evidence_subject = scope;
  effect.evidence_asserted_severity = request.reported_severity;
  effect.evidence_rationale = request.summary;
  effect.evidence_source_system = request.source_system;
  effect.evidence_source_event_id = request.source_event_id;
  effect.evidence_detail = request.detail;

  if (existing != nullptr) {
    std::uint64_t next_revision = 0;
    const Status status = NextValue(existing->revision, "incident revision", next_revision);
    if (!status.ok()) {
      Deny(guard.evaluation, status.code(), status.message());
      return;
    }
    effect.created_incident = false;
    effect.duplicate_report = true;
    effect.incident = existing->id;
    effect.incident_revision = next_revision;
    effect.next_incident_id = guard.state.next_incident_id;
    effect.state = existing->state;
    effect.cls = existing->cls;
    effect.severity = existing->severity;
    guard.evaluation.incident = existing->id;
    guard.evaluation.from_state = existing->state;
    guard.evaluation.to_state = existing->state;
    guard.evaluation.from_revision = existing->revision;
    guard.evaluation.to_revision = next_revision;
  } else {
    std::uint64_t next_incident = 0;
    const Status status = NextValue(guard.state.next_incident_id, "incident identifier",
                                    next_incident);
    if (!status.ok()) {
      Deny(guard.evaluation, status.code(), status.message());
      return;
    }
    effect.created_incident = true;
    effect.duplicate_report = false;
    effect.incident = IncidentId{guard.state.next_incident_id};
    effect.incident_revision = 1;
    effect.next_incident_id = next_incident;
    guard.evaluation.incident = effect.incident;
    guard.evaluation.from_state = LifecycleState::Reported;
    guard.evaluation.to_state = LifecycleState::Reported;
    guard.evaluation.from_revision = 0;
    guard.evaluation.to_revision = 1;
    guard.evaluation.from_severity = Severity::Unclassified;
    guard.evaluation.to_severity = request.reported_severity;
  }

  std::uint64_t next_evidence = 0;
  const Status status = NextValue(guard.state.next_evidence_id, "evidence identifier",
                                  next_evidence);
  if (!status.ok()) {
    Deny(guard.evaluation, status.code(), status.message());
    return;
  }
  effect.evidence = EvidenceId{guard.state.next_evidence_id};
  effect.next_evidence_id = next_evidence;
  effect.next_authority_id = guard.state.next_authority_id;
}

void EvalCreateSuccessor(Guard& guard, const CreateSuccessorRequest& request) {
  const Status role = RequireRole(guard, AuthorityRole::DutyManager,
                                  "creating a successor incident");
  if (!role.ok()) return;
  const IncidentRecord* predecessor = guard.state.FindIncident(request.predecessor);
  if (predecessor == nullptr) {
    Deny(guard.evaluation, ErrorCode::NotFound,
         "predecessor incident " + std::to_string(request.predecessor.value()) +
             " does not exist");
    return;
  }
  if (predecessor->revision != request.expected_predecessor_revision) {
    Deny(guard.evaluation, ErrorCode::StaleRevision,
         "predecessor incident is at revision " + std::to_string(predecessor->revision) +
             " but the request bound revision " +
             std::to_string(request.expected_predecessor_revision));
    return;
  }
  if (request.scope.empty()) {
    Deny(guard.evaluation, ErrorCode::InvalidArgument,
         "a successor incident must name at least one affected object or failure domain");
    return;
  }
  AffectedScope scope = request.scope;
  const Status canonical = ValidateAndCanonicalizeScope(scope, "scope");
  if (!canonical.ok()) {
    Deny(guard.evaluation, canonical.code(), canonical.message());
    return;
  }
  std::uint64_t next_incident = 0;
  std::uint64_t next_evidence = 0;
  Status status = NextValue(guard.state.next_incident_id, "incident identifier", next_incident);
  if (!status.ok()) {
    Deny(guard.evaluation, status.code(), status.message());
    return;
  }
  status = NextValue(guard.state.next_evidence_id, "evidence identifier", next_evidence);
  if (!status.ok()) {
    Deny(guard.evaluation, status.code(), status.message());
    return;
  }
  Effect& effect = guard.evaluation.effect;
  effect.created_incident = true;
  effect.incident = IncidentId{guard.state.next_incident_id};
  effect.incident_revision = 1;
  effect.secondary_incident = predecessor->id;
  effect.cls = request.cls;
  effect.severity = request.reported_severity;
  effect.state = LifecycleState::Reported;
  effect.scope = scope;
  effect.summary = request.summary;
  effect.source_system = request.source_system;
  effect.source_event_id = request.source_event_id;
  effect.owner = guard.actor_id();
  effect.evidence = EvidenceId{guard.state.next_evidence_id};
  effect.evidence_kind = EvidenceKind::Report;
  effect.evidence_subject = scope;
  effect.evidence_asserted_severity = request.reported_severity;
  effect.evidence_rationale = request.rationale;
  effect.evidence_source_system = request.source_system;
  effect.evidence_source_event_id = request.source_event_id;
  effect.evidence_detail = request.detail;
  effect.next_incident_id = next_incident;
  effect.next_evidence_id = next_evidence;
  effect.next_authority_id = guard.state.next_authority_id;
  guard.evaluation.incident = effect.incident;
  guard.evaluation.to_revision = 1;
}

void EvalAcceptIncident(Guard& guard, const AcceptIncidentRequest& request) {
  const Status role = RequireRole(guard, AuthorityRole::IncidentCommander,
                                  "accepting a report");
  if (!role.ok()) return;
  IncidentRef ref;
  if (!LookupIncident(guard, request.incident, request.expected_revision, ref)) return;
  const IncidentRecord& incident = *ref.record;
  if (incident.state != LifecycleState::Reported) {
    Deny(guard.evaluation, ErrorCode::IllegalTransition,
         std::string("only a reported incident can be accepted; this incident is ") +
             ToString(incident.state));
    return;
  }
  if (incident.scope.empty()) {
    Fail(guard.evaluation, ErrorCode::GateUnsatisfied, EvidenceKind::Report, "scope",
         "the incident has no affected objects or failure domains");
  }
  RequireReferencedEvidence(guard, incident, request.severity_evidence,
                            EvidenceKind::SeverityAssessment, "severity_evidence");
  const EvidenceRecord* assessment = guard.state.FindEvidence(request.severity_evidence);
  if (assessment != nullptr && assessment->incident == incident.id &&
      assessment->kind == EvidenceKind::SeverityAssessment &&
      assessment->asserted_severity != request.severity) {
    Fail(guard.evaluation, ErrorCode::GateUnsatisfied, EvidenceKind::SeverityAssessment,
         "severity_evidence",
         std::string("the referenced assessment asserts ") +
             ToString(assessment->asserted_severity) + " but the request asserts " +
             ToString(request.severity));
  }
  if (!HasCurrentOfKind(guard.state, incident, EvidenceKind::Report)) {
    RequireEvidence(guard, incident, EvidenceKind::Report, "report");
  }
  const Status gates = FinishGates(guard.evaluation);
  if (!gates.ok()) return;

  AuthorityId owner = guard.actor_id();
  if (request.owner.valid()) {
    const AuthorityRecord* record = nullptr;
    if (!RequireRegisteredAuthority(guard, request.owner, "owner assignment", record)) return;
    owner = record->id;
  }

  Effect& effect = guard.evaluation.effect;
  effect.incident = incident.id;
  effect.incident_revision = ref.next_revision;
  effect.cls = request.cls;
  effect.severity = request.severity;
  effect.state = LifecycleState::Accepted;
  effect.owner = owner;
  effect.next_incident_id = guard.state.next_incident_id;
  effect.next_evidence_id = guard.state.next_evidence_id;
  effect.next_authority_id = guard.state.next_authority_id;
  guard.evaluation.to_state = LifecycleState::Accepted;
  guard.evaluation.to_severity = request.severity;
}

void EvalRejectReport(Guard& guard, const RejectReportRequest& request) {
  const Status role = RequireRole(guard, AuthorityRole::DutyManager, "rejecting a report");
  if (!role.ok()) return;
  IncidentRef ref;
  if (!LookupIncident(guard, request.incident, request.expected_revision, ref)) return;
  if (ref.record->state != LifecycleState::Reported) {
    Deny(guard.evaluation, ErrorCode::IllegalTransition,
         std::string("only a reported incident can be rejected; this incident is ") +
             ToString(ref.record->state));
    return;
  }
  Effect& effect = guard.evaluation.effect;
  effect.incident = ref.record->id;
  effect.incident_revision = ref.next_revision;
  effect.state = LifecycleState::Rejected;
  effect.next_incident_id = guard.state.next_incident_id;
  effect.next_evidence_id = guard.state.next_evidence_id;
  effect.next_authority_id = guard.state.next_authority_id;
  guard.evaluation.to_state = LifecycleState::Rejected;
}

void EvalRecordEvidence(Guard& guard, const RecordEvidenceRequest& request) {
  const Status role = RequireRole(guard, AuthorityRole::Operator, "recording evidence");
  if (!role.ok()) return;
  IncidentRef ref;
  if (!LookupIncident(guard, request.incident, request.expected_revision, ref)) return;
  // A reopen trigger is the one observation that must be recordable against a
  // closed incident: it is the evidence that justifies reopening it.
  const bool reopen_trigger =
      request.kind == EvidenceKind::ReopenTrigger && ref.record->state == LifecycleState::Closed;
  if (!reopen_trigger) {
    const Status live = RequireLiveIncident(guard, *ref.record, "recording evidence");
    if (!live.ok()) return;
  }
  if (ref.record->evidence_ids.size() >= guard.limits.max_evidence_per_incident) {
    Deny(guard.evaluation, ErrorCode::ResourceExhausted,
         "the incident has reached the configured evidence limit");
    return;
  }
  AffectedScope subject = request.subject;
  const Status canonical = ValidateAndCanonicalizeScope(subject, "subject scope");
  if (!canonical.ok()) {
    Deny(guard.evaluation, canonical.code(), canonical.message());
    return;
  }
  std::uint64_t next_evidence = 0;
  const Status status = NextValue(guard.state.next_evidence_id, "evidence identifier",
                                  next_evidence);
  if (!status.ok()) {
    Deny(guard.evaluation, status.code(), status.message());
    return;
  }
  Effect& effect = guard.evaluation.effect;
  effect.incident = ref.record->id;
  effect.incident_revision = ref.next_revision;
  effect.evidence = EvidenceId{guard.state.next_evidence_id};
  effect.evidence_kind = request.kind;
  effect.evidence_subject = subject;
  effect.evidence_asserted_severity = request.asserted_severity;
  effect.evidence_effect_present = request.effect_present;
  effect.evidence_rationale = request.rationale;
  effect.evidence_source_system = request.source_system;
  effect.evidence_source_event_id = request.source_event_id;
  effect.evidence_detail = request.detail;
  effect.next_incident_id = guard.state.next_incident_id;
  effect.next_evidence_id = next_evidence;
  effect.next_authority_id = guard.state.next_authority_id;
}

void EvalWithdrawEvidence(Guard& guard, const WithdrawEvidenceRequest& request) {
  const Status role = RequireRole(guard, AuthorityRole::Operator, "withdrawing evidence");
  if (!role.ok()) return;
  IncidentRef ref;
  if (!LookupIncident(guard, request.incident, request.expected_revision, ref)) return;
  const Status live = RequireLiveIncident(guard, *ref.record, "withdrawing evidence");
  if (!live.ok()) return;
  const EvidenceRecord* record = guard.state.FindEvidence(request.evidence);
  if (record == nullptr || record->incident != ref.record->id) {
    Deny(guard.evaluation, ErrorCode::NotFound,
         "evidence " + std::to_string(request.evidence.value()) +
             " does not belong to this incident");
    return;
  }
  if (record->withdrawn) {
    Deny(guard.evaluation, ErrorCode::Conflict,
         "evidence " + std::to_string(request.evidence.value()) + " is already withdrawn");
    return;
  }
  Effect& effect = guard.evaluation.effect;
  effect.incident = ref.record->id;
  effect.incident_revision = ref.next_revision;
  effect.evidence = record->id;
  effect.evidence_kind = record->kind;
  effect.evidence_withdrawn = true;
  effect.next_incident_id = guard.state.next_incident_id;
  effect.next_evidence_id = guard.state.next_evidence_id;
  effect.next_authority_id = guard.state.next_authority_id;
}

void EvalReestablishEvidence(Guard& guard, const ReestablishEvidenceRequest& request) {
  const Status role = RequireRole(guard, AuthorityRole::IncidentCommander,
                                  "re-establishing evidence freshness");
  if (!role.ok()) return;
  IncidentRef ref;
  if (!LookupIncident(guard, request.incident, request.expected_revision, ref)) return;
  const Status live = RequireLiveIncident(guard, *ref.record, "re-establishing evidence");
  if (!live.ok()) return;
  const EvidenceRecord* record = guard.state.FindEvidence(request.evidence);
  if (record == nullptr || record->incident != ref.record->id) {
    Deny(guard.evaluation, ErrorCode::NotFound,
         "evidence " + std::to_string(request.evidence.value()) +
             " does not belong to this incident");
    return;
  }
  if (record->withdrawn) {
    Deny(guard.evaluation, ErrorCode::NotCurrentEvidence,
         "withdrawn evidence cannot be re-established; record a new observation instead");
    return;
  }
  if (IsEvidenceCurrent(*record, *ref.record)) {
    Deny(guard.evaluation, ErrorCode::Conflict,
         "evidence " + std::to_string(request.evidence.value()) +
             " is already current; re-establishment is only meaningful for historic evidence");
    return;
  }
  Effect& effect = guard.evaluation.effect;
  effect.incident = ref.record->id;
  effect.incident_revision = ref.next_revision;
  effect.evidence = record->id;
  effect.evidence_kind = record->kind;
  effect.evidence_reestablished = true;
  effect.next_incident_id = guard.state.next_incident_id;
  effect.next_evidence_id = guard.state.next_evidence_id;
  effect.next_authority_id = guard.state.next_authority_id;
}

void EvalAmendSeverity(Guard& guard, const AmendSeverityRequest& request) {
  IncidentRef ref;
  if (!LookupIncident(guard, request.incident, request.expected_revision, ref)) return;
  const IncidentRecord& incident = *ref.record;
  if (!IsLive(incident.state)) {
    Deny(guard.evaluation, ErrorCode::IllegalTransition,
         std::string("severity cannot change while the incident is ") + ToString(incident.state));
    return;
  }
  if (incident.state == LifecycleState::Reported) {
    Deny(guard.evaluation, ErrorCode::IllegalTransition,
         "a reported incident takes its severity from acceptance, not from an amendment");
    return;
  }
  if (request.severity == incident.severity) {
    Deny(guard.evaluation, ErrorCode::Conflict,
         std::string("the incident already carries severity ") + ToString(request.severity));
    return;
  }
  const bool escalating = request.severity > incident.severity;
  const Status role = RequireRole(guard, escalating ? AuthorityRole::IncidentCommander
                                                    : AuthorityRole::DutyManager,
                                  escalating ? "escalating severity" : "de-escalating severity");
  if (!role.ok()) return;

  std::vector<AuthorityId> distinct;
  for (const EvidenceId id : request.supporting_evidence) {
    RequireReferencedEvidence(guard, incident, id, EvidenceKind::SeverityAssessment,
                              "supporting_evidence");
    const EvidenceRecord* record = guard.state.FindEvidence(id);
    if (record == nullptr || record->incident != incident.id) continue;
    if (record->asserted_severity != request.severity) {
      Fail(guard.evaluation, ErrorCode::GateUnsatisfied, EvidenceKind::SeverityAssessment,
           "supporting_evidence",
           "assessment " + std::to_string(id.value()) + " asserts " +
               ToString(record->asserted_severity) + " rather than " +
               ToString(request.severity));
      continue;
    }
    if (std::find(distinct.begin(), distinct.end(), record->source) == distinct.end()) {
      distinct.push_back(record->source);
    }
  }

  if (!escalating) {
    if (distinct.size() < PolicyConstants::kDeescalationConfirmations) {
      Fail(guard.evaluation, ErrorCode::GateUnsatisfied, EvidenceKind::SeverityAssessment,
           "supporting_evidence",
           "de-escalation requires assessments from at least " +
               std::to_string(PolicyConstants::kDeescalationConfirmations) +
               " distinct authorities; the request supplies " +
               std::to_string(distinct.size()));
    }
    if (incident.escalation_count > 0) {
      const std::uint64_t quiet = guard.state.generation.value() -
                                  incident.last_escalation_at.value();
      if (quiet < PolicyConstants::kDeescalationQuietGenerations) {
        Fail(guard.evaluation, ErrorCode::GateUnsatisfied, EvidenceKind::SeverityAssessment,
             "quiet_period",
             "de-escalation requires " +
                 std::to_string(PolicyConstants::kDeescalationQuietGenerations) +
                 " durable generations since the last escalation; only " +
                 std::to_string(quiet) + " have elapsed");
      }
    }
  }
  const Status gates = FinishGates(guard.evaluation);
  if (!gates.ok()) return;

  Effect& effect = guard.evaluation.effect;
  effect.incident = incident.id;
  effect.incident_revision = ref.next_revision;
  effect.severity = request.severity;
  effect.escalation_count = incident.escalation_count;
  effect.last_escalation_at = incident.last_escalation_at;
  if (escalating) {
    std::uint64_t next = 0;
    const Status status = NextValue(incident.escalation_count, "escalation count", next);
    if (!status.ok()) {
      Deny(guard.evaluation, status.code(), status.message());
      return;
    }
    effect.escalation_count = next;
    effect.last_escalation_at = guard.state.generation;
  }
  effect.next_incident_id = guard.state.next_incident_id;
  effect.next_evidence_id = guard.state.next_evidence_id;
  effect.next_authority_id = guard.state.next_authority_id;
  guard.evaluation.to_severity = request.severity;
}

void EvalAmendScope(Guard& guard, const AmendScopeRequest& request) {
  const Status role = RequireRole(guard, AuthorityRole::IncidentCommander,
                                  "amending the affected scope");
  if (!role.ok()) return;
  IncidentRef ref;
  if (!LookupIncident(guard, request.incident, request.expected_revision, ref)) return;
  const Status live = RequireLiveIncident(guard, *ref.record, "amending the affected scope");
  if (!live.ok()) return;
  AffectedScope scope = request.scope;
  const Status canonical = ValidateAndCanonicalizeScope(scope, "scope");
  if (!canonical.ok()) {
    Deny(guard.evaluation, canonical.code(), canonical.message());
    return;
  }
  if (scope.empty()) {
    Deny(guard.evaluation, ErrorCode::InvalidArgument,
         "an incident must remain authoritative over at least one object or failure domain");
    return;
  }
  if (scope == ref.record->scope) {
    Deny(guard.evaluation, ErrorCode::Conflict,
         "the requested scope is identical to the incident's current scope");
    return;
  }
  Effect& effect = guard.evaluation.effect;
  effect.incident = ref.record->id;
  effect.incident_revision = ref.next_revision;
  effect.scope = scope;
  effect.next_incident_id = guard.state.next_incident_id;
  effect.next_evidence_id = guard.state.next_evidence_id;
  effect.next_authority_id = guard.state.next_authority_id;
}

void EvalAssignOwner(Guard& guard, const AssignOwnerRequest& request) {
  const Status role = RequireRole(guard, AuthorityRole::IncidentCommander,
                                  "handing off ownership");
  if (!role.ok()) return;
  IncidentRef ref;
  if (!LookupIncident(guard, request.incident, request.expected_revision, ref)) return;
  const Status live = RequireLiveIncident(guard, *ref.record, "handing off ownership");
  if (!live.ok()) return;
  const AuthorityRecord* owner = nullptr;
  if (!RequireRegisteredAuthority(guard, request.owner, "ownership handoff", owner)) return;
  if (owner->id == ref.record->owner) {
    Deny(guard.evaluation, ErrorCode::Conflict,
         "authority " + std::to_string(owner->id.value()) +
             " already owns this incident");
    return;
  }
  Effect& effect = guard.evaluation.effect;
  effect.incident = ref.record->id;
  effect.incident_revision = ref.next_revision;
  effect.owner = owner->id;
  effect.next_incident_id = guard.state.next_incident_id;
  effect.next_evidence_id = guard.state.next_evidence_id;
  effect.next_authority_id = guard.state.next_authority_id;
}

void EvalDeclareContained(Guard& guard, const DeclareContainedRequest& request) {
  const Status role = RequireRole(guard, AuthorityRole::IncidentCommander,
                                  "declaring containment");
  if (!role.ok()) return;
  IncidentRef ref;
  if (!LookupIncident(guard, request.incident, request.expected_revision, ref)) return;
  const IncidentRecord& incident = *ref.record;
  if (incident.state != LifecycleState::Accepted && incident.state != LifecycleState::Reopened) {
    Deny(guard.evaluation, ErrorCode::IllegalTransition,
         std::string("containment can only be declared for an accepted or reopened incident; "
                     "this incident is ") +
             ToString(incident.state));
    return;
  }
  RequireReferencedEvidence(guard, incident, request.proof, EvidenceKind::ContainmentProof,
                            "proof");
  if (!HasCurrentOfKind(guard.state, incident, EvidenceKind::ContainmentProof)) {
    RequireEvidence(guard, incident, EvidenceKind::ContainmentProof, "proof");
  }
  const Status gates = FinishGates(guard.evaluation);
  if (!gates.ok()) return;

  Effect& effect = guard.evaluation.effect;
  effect.incident = incident.id;
  effect.incident_revision = ref.next_revision;
  effect.state = LifecycleState::Contained;
  effect.containment_declared = true;
  effect.next_incident_id = guard.state.next_incident_id;
  effect.next_evidence_id = guard.state.next_evidence_id;
  effect.next_authority_id = guard.state.next_authority_id;
  guard.evaluation.to_state = LifecycleState::Contained;
}

void EvalStartRecovery(Guard& guard, const StartRecoveryRequest& request) {
  const Status role = RequireRole(guard, AuthorityRole::IncidentCommander, "starting recovery");
  if (!role.ok()) return;
  IncidentRef ref;
  if (!LookupIncident(guard, request.incident, request.expected_revision, ref)) return;
  const IncidentRecord& incident = *ref.record;
  if (incident.state != LifecycleState::Contained) {
    Deny(guard.evaluation, ErrorCode::IllegalTransition,
         std::string("recovery can only start once containment is proven; this incident is ") +
             ToString(incident.state));
    return;
  }
  if (!HasCurrentOfKind(guard.state, incident, EvidenceKind::ContainmentProof)) {
    Fail(guard.evaluation, ErrorCode::NotCurrentEvidence, EvidenceKind::ContainmentProof,
         "containment",
         "the containment proof is no longer current, so containment must be re-proven before "
         "recovery starts");
  }
  const Status gates = FinishGates(guard.evaluation);
  if (!gates.ok()) return;

  Effect& effect = guard.evaluation.effect;
  effect.incident = incident.id;
  effect.incident_revision = ref.next_revision;
  effect.state = LifecycleState::Recovering;
  effect.recovery_started = true;
  effect.next_incident_id = guard.state.next_incident_id;
  effect.next_evidence_id = guard.state.next_evidence_id;
  effect.next_authority_id = guard.state.next_authority_id;
  guard.evaluation.to_state = LifecycleState::Recovering;
}

void EvalDeclareRecovered(Guard& guard, const DeclareRecoveredRequest& request) {
  const Status role = RequireRole(guard, AuthorityRole::IncidentCommander,
                                  "declaring recovery proven");
  if (!role.ok()) return;
  IncidentRef ref;
  if (!LookupIncident(guard, request.incident, request.expected_revision, ref)) return;
  const IncidentRecord& incident = *ref.record;
  if (incident.state != LifecycleState::Recovering) {
    Deny(guard.evaluation, ErrorCode::IllegalTransition,
         std::string("recovery can only be proven while recovery is in progress; this incident "
                     "is ") +
             ToString(incident.state));
    return;
  }
  RequireReferencedEvidence(guard, incident, request.proof, EvidenceKind::RecoveryProof, "proof");
  if (!HasCurrentOfKind(guard.state, incident, EvidenceKind::RecoveryProof)) {
    RequireEvidence(guard, incident, EvidenceKind::RecoveryProof, "proof");
    if (!guard.denied() && incident.state == LifecycleState::Recovering) {
      Fail(guard.evaluation, ErrorCode::GateUnsatisfied, EvidenceKind::RecoveryProof, "proof",
           "recovery has started but starting recovery does not prove it");
    }
  }
  const Status gates = FinishGates(guard.evaluation);
  if (!gates.ok()) return;

  std::uint64_t next_observation = 0;
  const Status status = NextValue(incident.observation_generation,
                                  "observation generation", next_observation);
  if (!status.ok()) {
    Deny(guard.evaluation, status.code(), status.message());
    return;
  }
  Effect& effect = guard.evaluation.effect;
  effect.incident = incident.id;
  effect.incident_revision = ref.next_revision;
  effect.state = LifecycleState::Recovered;
  effect.recovery_started = true;
  effect.observation_generation = next_observation;
  effect.attestation_generation = incident.attestation_generation;
  effect.next_incident_id = guard.state.next_incident_id;
  effect.next_evidence_id = guard.state.next_evidence_id;
  effect.next_authority_id = guard.state.next_authority_id;
  guard.evaluation.to_state = LifecycleState::Recovered;
}

void EvalResolve(Guard& guard, const ResolveIncidentRequest& request) {
  IncidentRef ref;
  if (!LookupIncident(guard, request.incident, request.expected_revision, ref)) return;
  const IncidentRecord& incident = *ref.record;
  switch (incident.state) {
    case LifecycleState::Accepted:
    case LifecycleState::Contained:
    case LifecycleState::Recovering:
    case LifecycleState::Recovered:
    case LifecycleState::Reopened:
      break;
    default:
      Deny(guard.evaluation, ErrorCode::IllegalTransition,
           std::string("an incident in state ") + ToString(incident.state) +
               " cannot be resolved");
      return;
  }
  const IncidentClassPolicy policy = PolicyFor(incident.cls);
  const Status role = RequireRole(guard, policy.resolution_role, "resolving an incident");
  if (!role.ok()) return;

  RequireReferencedEvidence(guard, incident, request.clearance, EvidenceKind::EffectCleared,
                            "clearance");
  if (!HasCurrentOfKind(guard.state, incident, EvidenceKind::EffectCleared)) {
    RequireEvidence(guard, incident, EvidenceKind::EffectCleared, "clearance");
  }
  if (policy.requires_containment && !incident.containment_declared) {
    Fail(guard.evaluation, ErrorCode::GateUnsatisfied, EvidenceKind::ContainmentProof,
         "containment",
         std::string("incidents of class ") + ToString(incident.cls) +
             " cannot be resolved before containment is proven");
  }
  if (policy.requires_recovery && incident.recovery_started &&
      !HasCurrentOfKind(guard.state, incident, EvidenceKind::RecoveryProof)) {
    Fail(guard.evaluation, ErrorCode::NotCurrentEvidence, EvidenceKind::RecoveryProof, "recovery",
         "recovery was started but no current recovery proof remains");
  }
  const EvidenceRecord* clearance = guard.state.FindEvidence(request.clearance);
  if (clearance != nullptr && clearance->incident == incident.id &&
      clearance->kind == EvidenceKind::EffectCleared) {
    for (const EvidenceId id : incident.evidence_ids) {
      const EvidenceRecord* other = guard.state.FindEvidence(id);
      if (other == nullptr || other->kind != EvidenceKind::EffectObservation) continue;
      if (!IsEvidenceCurrent(*other, incident)) continue;
      if (!other->effect_present) continue;
      if (other->recorded_at <= clearance->recorded_at) continue;
      Fail(guard.evaluation, ErrorCode::GateUnsatisfied, EvidenceKind::EffectObservation,
           "effect",
           "observation " + std::to_string(other->id.value()) +
               " recorded after the clearance still reports the effect as present");
      break;
    }
  }
  const Status gates = FinishGates(guard.evaluation);
  if (!gates.ok()) return;

  Effect& effect = guard.evaluation.effect;
  effect.incident = incident.id;
  effect.incident_revision = ref.next_revision;
  effect.state = LifecycleState::Resolved;
  effect.recovery_started = incident.recovery_started;
  effect.next_incident_id = guard.state.next_incident_id;
  effect.next_evidence_id = guard.state.next_evidence_id;
  effect.next_authority_id = guard.state.next_authority_id;
  guard.evaluation.to_state = LifecycleState::Resolved;
}

void EvalClose(Guard& guard, const CloseIncidentRequest& request) {
  IncidentRef ref;
  if (!LookupIncident(guard, request.incident, request.expected_revision, ref)) return;
  const IncidentRecord& incident = *ref.record;
  if (incident.state != LifecycleState::Resolved) {
    Deny(guard.evaluation, ErrorCode::IllegalTransition,
         std::string("only a resolved incident can be closed; this incident is ") +
             ToString(incident.state));
    return;
  }
  const IncidentClassPolicy policy = PolicyFor(incident.cls);
  const Status role = RequireRole(guard, policy.closure_role, "closing an incident");
  if (!role.ok()) return;

  RequireReferencedEvidence(guard, incident, request.attestation,
                            EvidenceKind::ClosureAttestation, "attestation");
  if (!HasCurrentOfKind(guard.state, incident, EvidenceKind::ClosureAttestation)) {
    RequireEvidence(guard, incident, EvidenceKind::ClosureAttestation, "attestation");
  }
  if (!HasCurrentOfKind(guard.state, incident, EvidenceKind::EffectCleared)) {
    RequireEvidence(guard, incident, EvidenceKind::EffectCleared, "clearance");
  }
  if (policy.requires_containment &&
      !HasCurrentOfKind(guard.state, incident, EvidenceKind::ContainmentProof)) {
    RequireEvidence(guard, incident, EvidenceKind::ContainmentProof, "containment");
  }
  if (policy.requires_recovery && incident.recovery_started &&
      !HasCurrentOfKind(guard.state, incident, EvidenceKind::RecoveryProof)) {
    RequireEvidence(guard, incident, EvidenceKind::RecoveryProof, "recovery");
  }
  const Status gates = FinishGates(guard.evaluation);
  if (!gates.ok()) return;

  Effect& effect = guard.evaluation.effect;
  effect.incident = incident.id;
  effect.incident_revision = ref.next_revision;
  effect.state = LifecycleState::Closed;
  effect.recovery_started = incident.recovery_started;
  effect.next_incident_id = guard.state.next_incident_id;
  effect.next_evidence_id = guard.state.next_evidence_id;
  effect.next_authority_id = guard.state.next_authority_id;
  guard.evaluation.to_state = LifecycleState::Closed;
}

void EvalReopen(Guard& guard, const ReopenIncidentRequest& request) {
  IncidentRef ref;
  if (!LookupIncident(guard, request.incident, request.expected_revision, ref)) return;
  const IncidentRecord& incident = *ref.record;
  if (incident.state != LifecycleState::Closed) {
    Deny(guard.evaluation, ErrorCode::IllegalTransition,
         std::string("only a closed incident can be reopened; this incident is ") +
             ToString(incident.state));
    return;
  }
  const IncidentClassPolicy policy = PolicyFor(incident.cls);
  const Status role = RequireRole(guard, policy.closure_role, "reopening an incident");
  if (!role.ok()) return;
  if (incident.reopen_count >= PolicyConstants::kMaxReopens) {
    Deny(guard.evaluation, ErrorCode::ReopenLimitReached,
         "this incident has already been reopened " + std::to_string(incident.reopen_count) +
             " times; create a successor incident instead");
    return;
  }
  RequireReferencedEvidence(guard, incident, request.trigger, EvidenceKind::ReopenTrigger,
                            "trigger");
  if (!HasCurrentOfKind(guard.state, incident, EvidenceKind::ReopenTrigger)) {
    RequireEvidence(guard, incident, EvidenceKind::ReopenTrigger, "trigger");
  }
  const Status gates = FinishGates(guard.evaluation);
  if (!gates.ok()) return;

  std::uint64_t next_observation = 0;
  std::uint64_t next_attestation = 0;
  std::uint64_t next_reopens = 0;
  Status status = NextValue(incident.observation_generation, "observation generation",
                            next_observation);
  if (!status.ok()) {
    Deny(guard.evaluation, status.code(), status.message());
    return;
  }
  status = NextValue(incident.attestation_generation, "attestation generation", next_attestation);
  if (!status.ok()) {
    Deny(guard.evaluation, status.code(), status.message());
    return;
  }
  status = NextValue(incident.reopen_count, "reopen count", next_reopens);
  if (!status.ok()) {
    Deny(guard.evaluation, status.code(), status.message());
    return;
  }
  Effect& effect = guard.evaluation.effect;
  effect.incident = incident.id;
  effect.incident_revision = ref.next_revision;
  effect.state = LifecycleState::Reopened;
  effect.observation_generation = next_observation;
  effect.attestation_generation = next_attestation;
  effect.reopen_count = next_reopens;
  effect.recovery_started = incident.recovery_started;
  effect.next_incident_id = guard.state.next_incident_id;
  effect.next_evidence_id = guard.state.next_evidence_id;
  effect.next_authority_id = guard.state.next_authority_id;
  guard.evaluation.to_state = LifecycleState::Reopened;
}

void EvalMerge(Guard& guard, const MergeIncidentRequest& request) {
  const Status role = RequireRole(guard, AuthorityRole::FacilityDirector, "merging incidents");
  if (!role.ok()) return;
  IncidentRef survivor_ref;
  if (!LookupIncident(guard, request.survivor, request.expected_survivor_revision, survivor_ref)) {
    return;
  }
  IncidentRef absorbed_ref;
  if (!LookupIncident(guard, request.absorbed, request.expected_absorbed_revision, absorbed_ref)) {
    return;
  }
  const IncidentRecord& survivor = *survivor_ref.record;
  const IncidentRecord& absorbed = *absorbed_ref.record;
  if (!IsLive(survivor.state)) {
    Fail(guard.evaluation, ErrorCode::IllegalTransition, EvidenceKind::Report, "survivor",
         std::string("the survivor is already ") + ToString(survivor.state));
  }
  if (!IsLive(absorbed.state)) {
    Fail(guard.evaluation, ErrorCode::IllegalTransition, EvidenceKind::Report, "absorbed",
         std::string("the absorbed incident is already ") + ToString(absorbed.state));
  }
  if (survivor.predecessor.valid() && survivor.predecessor == absorbed.id) {
    Fail(guard.evaluation, ErrorCode::Conflict, EvidenceKind::Report, "absorbed",
         "the absorbed incident is the survivor's own predecessor");
  }
  if (survivor.cls != absorbed.cls && !request.allow_cross_class) {
    Fail(guard.evaluation, ErrorCode::GateUnsatisfied, EvidenceKind::Report, "absorbed",
         "merging incidents of different classes requires an explicit cross-class override");
  }
  const Status gates = FinishGates(guard.evaluation);
  if (!gates.ok()) return;

  AffectedScope merged = survivor.scope;
  merged.objects.insert(merged.objects.end(), absorbed.scope.objects.begin(),
                        absorbed.scope.objects.end());
  merged.failure_domains.insert(merged.failure_domains.end(),
                                absorbed.scope.failure_domains.begin(),
                                absorbed.scope.failure_domains.end());
  Canonicalize(merged);

  Effect& effect = guard.evaluation.effect;
  effect.incident = survivor.id;
  effect.incident_revision = survivor_ref.next_revision;
  effect.state = survivor.state;
  effect.scope = merged;
  effect.secondary_incident = absorbed.id;
  effect.secondary_revision = absorbed_ref.next_revision;
  effect.secondary_state = LifecycleState::Superseded;
  effect.cross_class = survivor.cls != absorbed.cls;
  effect.next_incident_id = guard.state.next_incident_id;
  effect.next_evidence_id = guard.state.next_evidence_id;
  effect.next_authority_id = guard.state.next_authority_id;
  guard.evaluation.to_state = survivor.state;
}

// ---------------------------------------------------------------------------
// Dispatch
// ---------------------------------------------------------------------------

void Dispatch(Guard& guard, const AnyRequest& request) {
  std::visit(
      [&guard](const auto& typed) {
        using T = std::decay_t<decltype(typed)>;
        if constexpr (std::is_same_v<T, RegisterAuthorityRequest>) {
          EvalRegisterAuthority(guard, typed);
        } else if constexpr (std::is_same_v<T, RevokeAuthorityRequest>) {
          EvalRevokeAuthority(guard, typed);
        } else if constexpr (std::is_same_v<T, ForceFenceRequest>) {
          EvalForceFence(guard, typed);
        } else if constexpr (std::is_same_v<T, ReportIncidentRequest>) {
          EvalReportIncident(guard, typed);
        } else if constexpr (std::is_same_v<T, AcceptIncidentRequest>) {
          EvalAcceptIncident(guard, typed);
        } else if constexpr (std::is_same_v<T, RejectReportRequest>) {
          EvalRejectReport(guard, typed);
        } else if constexpr (std::is_same_v<T, RecordEvidenceRequest>) {
          EvalRecordEvidence(guard, typed);
        } else if constexpr (std::is_same_v<T, WithdrawEvidenceRequest>) {
          EvalWithdrawEvidence(guard, typed);
        } else if constexpr (std::is_same_v<T, ReestablishEvidenceRequest>) {
          EvalReestablishEvidence(guard, typed);
        } else if constexpr (std::is_same_v<T, AmendSeverityRequest>) {
          EvalAmendSeverity(guard, typed);
        } else if constexpr (std::is_same_v<T, AmendScopeRequest>) {
          EvalAmendScope(guard, typed);
        } else if constexpr (std::is_same_v<T, AssignOwnerRequest>) {
          EvalAssignOwner(guard, typed);
        } else if constexpr (std::is_same_v<T, DeclareContainedRequest>) {
          EvalDeclareContained(guard, typed);
        } else if constexpr (std::is_same_v<T, StartRecoveryRequest>) {
          EvalStartRecovery(guard, typed);
        } else if constexpr (std::is_same_v<T, DeclareRecoveredRequest>) {
          EvalDeclareRecovered(guard, typed);
        } else if constexpr (std::is_same_v<T, ResolveIncidentRequest>) {
          EvalResolve(guard, typed);
        } else if constexpr (std::is_same_v<T, CloseIncidentRequest>) {
          EvalClose(guard, typed);
        } else if constexpr (std::is_same_v<T, ReopenIncidentRequest>) {
          EvalReopen(guard, typed);
        } else if constexpr (std::is_same_v<T, CreateSuccessorRequest>) {
          EvalCreateSuccessor(guard, typed);
        } else if constexpr (std::is_same_v<T, MergeIncidentRequest>) {
          EvalMerge(guard, typed);
        }
      },
      request);
}

}  // namespace

Evaluation EvaluateRequest(const State& state, const AnyRequest& request, const StoreLimits& limits,
                           const Digest256& intent) {
  Evaluation evaluation;
  const MutationHeader& header = HeaderOf(request);

  // 1. Request shape.
  const Status shape = ValidateRequestShape(request);
  if (!shape.ok()) {
    Deny(evaluation, shape.code(), shape.message());
    return evaluation;
  }

  // 2. Idempotent replay of an already-committed operation. This precedes every
  //    fencing and pre-condition check: a lost response must never turn into a
  //    second consequential mutation, even across a restart.
  const auto existing = state.idempotency.find(header.key);
  if (existing != state.idempotency.end()) {
    if (!(existing->second.intent == intent)) {
      Deny(evaluation, ErrorCode::IdempotencyConflict,
           "idempotency key is already bound to a different operation");
      return evaluation;
    }
    evaluation.kind = DecisionKind::Replay;
    evaluation.receipt = existing->second.receipt;
    evaluation.receipt.replayed = true;
    evaluation.incident = existing->second.receipt.incident;
    evaluation.from_revision = existing->second.receipt.incident_revision;
    evaluation.to_revision = existing->second.receipt.incident_revision;
    return evaluation;
  }

  // 3. Control-epoch fencing.
  if (header.actor.epoch != state.control_epoch) {
    Deny(evaluation, ErrorCode::StaleControlEpoch,
         "the request carries control epoch " + std::to_string(header.actor.epoch.value) +
             " but the store is at epoch " + std::to_string(state.control_epoch.value));
    return evaluation;
  }

  // 4. Authority resolution.
  Guard guard{state, limits, evaluation};
  if (!header.actor.authority.valid()) {
    if (std::holds_alternative<RegisterAuthorityRequest>(request) && state.authorities.empty()) {
      guard.bootstrap = true;
    } else {
      Deny(evaluation, ErrorCode::AuthorityUnknown,
           "a registered authority identifier is required for this operation");
      return evaluation;
    }
  } else {
    const AuthorityRecord* actor = state.FindAuthority(header.actor.authority);
    if (actor == nullptr) {
      Deny(evaluation, ErrorCode::AuthorityUnknown,
           "authority " + std::to_string(header.actor.authority.value()) +
               " is not registered");
      return evaluation;
    }
    if (!actor->active) {
      Deny(evaluation, ErrorCode::AuthorityRevoked,
           "authority " + std::to_string(header.actor.authority.value()) + " has been revoked");
      return evaluation;
    }
    guard.actor = actor;
  }

  // 5. Capacity.
  const Status capacity = CheckCapacity(state, limits, KindOf(request));
  if (!capacity.ok()) {
    Deny(evaluation, capacity.code(), capacity.message());
    return evaluation;
  }

  // 6. Semantics.
  Effect& effect = evaluation.effect;
  effect.op = KindOf(request);
  effect.actor = guard.actor_id();
  effect.key = header.key;
  effect.intent = intent;
  effect.request_epoch = header.actor.epoch.value;
  effect.rationale = std::visit(
      [](const auto& typed) -> std::string {
        using T = std::decay_t<decltype(typed)>;
        if constexpr (std::is_same_v<T, ReportIncidentRequest>) {
          return typed.summary;
        } else if constexpr (std::is_same_v<T, CreateSuccessorRequest>) {
          return typed.rationale.empty() ? typed.summary : typed.rationale;
        } else {
          return typed.rationale;
        }
      },
      request);

  std::uint64_t next_generation = 0;
  const Status generation = NextValue(state.generation.value(), "generation", next_generation);
  if (!generation.ok()) {
    Deny(evaluation, generation.code(), generation.message());
    return evaluation;
  }
  effect.generation = Generation{next_generation};

  Dispatch(guard, request);
  if (evaluation.kind == DecisionKind::Denied) return evaluation;
  if (evaluation.kind != DecisionKind::Undecided) return evaluation;

  evaluation.kind = DecisionKind::Commit;
  evaluation.receipt = ReceiptFor(effect);
  evaluation.incident = effect.incident;
  return evaluation;
}

}  // namespace isf::detail
