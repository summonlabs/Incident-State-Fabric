// Incident State Fabric - DCCP boundary 50
// Copyright 2026 Summon Software Labs.
// Licensed under the Apache License, Version 2.0.

#include "detail/request_codec.h"

#include <algorithm>
#include <cstdint>

#include "detail/canonical.h"
#include "detail/state.h"

namespace isf::detail {
namespace {

void EncodeScope(Encoder& encoder, const AffectedScope& scope) {
  encoder.U32(static_cast<std::uint32_t>(scope.objects.size()));
  for (const ObjectRef& object : scope.objects) {
    encoder.U8(static_cast<std::uint8_t>(object.kind));
    encoder.Text(object.id);
  }
  encoder.U32(static_cast<std::uint32_t>(scope.failure_domains.size()));
  for (const FailureDomainRef& domain : scope.failure_domains) {
    encoder.U8(static_cast<std::uint8_t>(domain.kind));
    encoder.Text(domain.id);
  }
}

void EncodeKey(Encoder& encoder, const IdempotencyKey& key) {
  encoder.U64(key.hi);
  encoder.U64(key.lo);
}

[[nodiscard]] Status Bad(std::string detail) {
  return Status::Error(ErrorCode::InvalidArgument, std::move(detail));
}

[[nodiscard]] Status RequireToken(const std::string& text, std::size_t maximum, const char* field,
                                  bool optional) {
  if (text.empty()) {
    if (optional) return Status::Ok();
    return Bad(std::string(field) + " is required and must not be empty");
  }
  if (!IsValidToken(text, maximum)) {
    return Bad(std::string(field) + " must be well-formed UTF-8 without control characters and at"
                                   " most " +
               std::to_string(maximum) + " bytes");
  }
  return Status::Ok();
}

[[nodiscard]] Status RequireFreeText(const std::string& text, std::size_t maximum,
                                     const char* field) {
  if (!IsValidFreeText(text, maximum)) {
    return Bad(std::string(field) + " must be well-formed UTF-8 without NUL and at most " +
               std::to_string(maximum) + " bytes");
  }
  return Status::Ok();
}

[[nodiscard]] bool ScopeWithinLimits(const AffectedScope& scope) {
  return scope.objects.size() <= FieldLimits::kScopeObjects &&
         scope.failure_domains.size() <= FieldLimits::kScopeDomains;
}

[[nodiscard]] Status ValidateScopeShape(const AffectedScope& scope, const char* field) {
  if (!ScopeWithinLimits(scope)) {
    return Status::Error(ErrorCode::LimitExceeded,
                         std::string(field) + " exceeds the maximum number of references");
  }
  for (const ObjectRef& object : scope.objects) {
    if (!IsValidToken(object.id, FieldLimits::kToken)) {
      return Bad(std::string(field) + " contains an object identifier that is not a valid token");
    }
  }
  for (const FailureDomainRef& domain : scope.failure_domains) {
    if (!IsValidToken(domain.id, FieldLimits::kToken)) {
      return Bad(std::string(field) +
                 " contains a failure domain identifier that is not a valid token");
    }
  }
  return Status::Ok();
}

}  // namespace

Status ValidateAndCanonicalizeScope(AffectedScope& scope, const char* field) {
  Canonicalize(scope);
  return ValidateScopeShape(scope, field);
}

Digest256 ComputeIntentDigest(const AnyRequest& request) {
  Encoder encoder;
  encoder.U32(static_cast<std::uint32_t>(KindOf(request)));
  const MutationHeader& header = HeaderOf(request);
  encoder.U64(header.actor.authority.value());
  EncodeKey(encoder, header.key);

  std::visit(
      [&encoder](const auto& typed) {
        using T = std::decay_t<decltype(typed)>;
        if constexpr (std::is_same_v<T, RegisterAuthorityRequest>) {
          encoder.Text(typed.name);
          encoder.U8(static_cast<std::uint8_t>(typed.role));
          encoder.Text(typed.rationale);
        } else if constexpr (std::is_same_v<T, RevokeAuthorityRequest>) {
          encoder.U64(typed.target.value());
          encoder.Text(typed.rationale);
        } else if constexpr (std::is_same_v<T, ForceFenceRequest>) {
          encoder.Text(typed.rationale);
        } else if constexpr (std::is_same_v<T, ReportIncidentRequest>) {
          encoder.U8(static_cast<std::uint8_t>(typed.cls));
          encoder.U8(static_cast<std::uint8_t>(typed.reported_severity));
          encoder.Text(typed.summary);
          EncodeScope(encoder, typed.scope);
          encoder.Text(typed.source_system);
          encoder.Text(typed.source_event_id);
          encoder.Text(typed.detail);
        } else if constexpr (std::is_same_v<T, AcceptIncidentRequest>) {
          encoder.U64(typed.incident.value());
          encoder.U64(typed.expected_revision);
          encoder.U8(static_cast<std::uint8_t>(typed.cls));
          encoder.U8(static_cast<std::uint8_t>(typed.severity));
          encoder.U64(typed.severity_evidence.value());
          encoder.U64(typed.owner.value());
          encoder.Text(typed.rationale);
        } else if constexpr (std::is_same_v<T, RejectReportRequest>) {
          encoder.U64(typed.incident.value());
          encoder.U64(typed.expected_revision);
          encoder.Text(typed.rationale);
        } else if constexpr (std::is_same_v<T, RecordEvidenceRequest>) {
          encoder.U64(typed.incident.value());
          encoder.U64(typed.expected_revision);
          encoder.U8(static_cast<std::uint8_t>(typed.kind));
          EncodeScope(encoder, typed.subject);
          encoder.U8(static_cast<std::uint8_t>(typed.asserted_severity));
          encoder.Bool(typed.effect_present);
          encoder.Text(typed.rationale);
          encoder.Text(typed.source_system);
          encoder.Text(typed.source_event_id);
          encoder.Text(typed.detail);
        } else if constexpr (std::is_same_v<T, WithdrawEvidenceRequest>) {
          encoder.U64(typed.incident.value());
          encoder.U64(typed.expected_revision);
          encoder.U64(typed.evidence.value());
          encoder.Text(typed.rationale);
        } else if constexpr (std::is_same_v<T, ReestablishEvidenceRequest>) {
          encoder.U64(typed.incident.value());
          encoder.U64(typed.expected_revision);
          encoder.U64(typed.evidence.value());
          encoder.Text(typed.rationale);
        } else if constexpr (std::is_same_v<T, AmendSeverityRequest>) {
          encoder.U64(typed.incident.value());
          encoder.U64(typed.expected_revision);
          encoder.U8(static_cast<std::uint8_t>(typed.severity));
          encoder.U32(static_cast<std::uint32_t>(typed.supporting_evidence.size()));
          for (const EvidenceId id : typed.supporting_evidence) encoder.U64(id.value());
          encoder.Text(typed.rationale);
        } else if constexpr (std::is_same_v<T, AmendScopeRequest>) {
          encoder.U64(typed.incident.value());
          encoder.U64(typed.expected_revision);
          EncodeScope(encoder, typed.scope);
          encoder.Text(typed.rationale);
        } else if constexpr (std::is_same_v<T, AssignOwnerRequest>) {
          encoder.U64(typed.incident.value());
          encoder.U64(typed.expected_revision);
          encoder.U64(typed.owner.value());
          encoder.Text(typed.rationale);
        } else if constexpr (std::is_same_v<T, DeclareContainedRequest>) {
          encoder.U64(typed.incident.value());
          encoder.U64(typed.expected_revision);
          encoder.U64(typed.proof.value());
          encoder.Text(typed.rationale);
        } else if constexpr (std::is_same_v<T, StartRecoveryRequest>) {
          encoder.U64(typed.incident.value());
          encoder.U64(typed.expected_revision);
          encoder.Text(typed.rationale);
        } else if constexpr (std::is_same_v<T, DeclareRecoveredRequest>) {
          encoder.U64(typed.incident.value());
          encoder.U64(typed.expected_revision);
          encoder.U64(typed.proof.value());
          encoder.Text(typed.rationale);
        } else if constexpr (std::is_same_v<T, ResolveIncidentRequest>) {
          encoder.U64(typed.incident.value());
          encoder.U64(typed.expected_revision);
          encoder.U64(typed.clearance.value());
          encoder.Text(typed.rationale);
        } else if constexpr (std::is_same_v<T, CloseIncidentRequest>) {
          encoder.U64(typed.incident.value());
          encoder.U64(typed.expected_revision);
          encoder.U64(typed.attestation.value());
          encoder.Text(typed.rationale);
        } else if constexpr (std::is_same_v<T, ReopenIncidentRequest>) {
          encoder.U64(typed.incident.value());
          encoder.U64(typed.expected_revision);
          encoder.U64(typed.trigger.value());
          encoder.Text(typed.rationale);
        } else if constexpr (std::is_same_v<T, CreateSuccessorRequest>) {
          encoder.U64(typed.predecessor.value());
          encoder.U64(typed.expected_predecessor_revision);
          encoder.U8(static_cast<std::uint8_t>(typed.cls));
          encoder.U8(static_cast<std::uint8_t>(typed.reported_severity));
          encoder.Text(typed.summary);
          EncodeScope(encoder, typed.scope);
          encoder.Text(typed.source_system);
          encoder.Text(typed.source_event_id);
          encoder.Text(typed.detail);
          encoder.Text(typed.rationale);
        } else if constexpr (std::is_same_v<T, MergeIncidentRequest>) {
          encoder.U64(typed.survivor.value());
          encoder.U64(typed.expected_survivor_revision);
          encoder.U64(typed.absorbed.value());
          encoder.U64(typed.expected_absorbed_revision);
          encoder.Bool(typed.allow_cross_class);
          encoder.Text(typed.rationale);
        }
      },
      request);
  return ComputeSha256(encoder.data().data(), encoder.size());
}

Status ValidateRequestShape(const AnyRequest& request) {
  const MutationHeader& header = HeaderOf(request);
  if (!header.key.valid()) {
    return Bad("an idempotency key is required for every mutation");
  }
  if (!IsKnownOpKind(static_cast<std::uint32_t>(KindOf(request)))) {
    return Bad("operation kind is not known to this build");
  }

  Status status = Status::Ok();
  std::visit(
      [&status](const auto& typed) {
        using T = std::decay_t<decltype(typed)>;
        if constexpr (std::is_same_v<T, RegisterAuthorityRequest>) {
          status = RequireToken(typed.name, FieldLimits::kName, "authority name", false);
          if (!status.ok()) return;
          if (!IsKnownAuthorityRole(static_cast<std::uint8_t>(typed.role)) ||
              typed.role == AuthorityRole::None) {
            status = Bad("authority role must be a known non-zero role");
            return;
          }
          status = RequireFreeText(typed.rationale, FieldLimits::kRationale, "rationale");
          if (!status.ok()) return;
          if (typed.rationale.empty()) status = Bad("registration rationale is required");
        } else if constexpr (std::is_same_v<T, RevokeAuthorityRequest>) {
          if (!typed.target.valid()) {
            status = Bad("revocation target authority is required");
            return;
          }
          status = RequireFreeText(typed.rationale, FieldLimits::kRationale, "rationale");
          if (!status.ok()) return;
          if (typed.rationale.empty()) status = Bad("revocation rationale is required");
        } else if constexpr (std::is_same_v<T, ForceFenceRequest>) {
          status = RequireFreeText(typed.rationale, FieldLimits::kRationale, "rationale");
          if (!status.ok()) return;
          if (typed.rationale.empty()) status = Bad("fencing rationale is required");
        } else if constexpr (std::is_same_v<T, ReportIncidentRequest>) {
          if (!IsKnownIncidentClass(static_cast<std::uint8_t>(typed.cls))) {
            status = Bad("incident class is not known to this build");
            return;
          }
          if (!IsKnownSeverity(static_cast<std::uint8_t>(typed.reported_severity))) {
            status = Bad("reported severity is not known to this build");
            return;
          }
          status = RequireToken(typed.summary, FieldLimits::kSummary, "summary", false);
          if (!status.ok()) return;
          status = ValidateScopeShape(typed.scope, "scope");
          if (!status.ok()) return;
          status = RequireToken(typed.source_system, FieldLimits::kToken, "source system", true);
          if (!status.ok()) return;
          status = RequireToken(typed.source_event_id, FieldLimits::kToken, "source event id", true);
          if (!status.ok()) return;
          if (typed.source_system.empty() != typed.source_event_id.empty()) {
            status = Bad("source system and source event id must be supplied together");
            return;
          }
          status = RequireFreeText(typed.detail, FieldLimits::kDetail, "detail");
        } else if constexpr (std::is_same_v<T, AcceptIncidentRequest>) {
          if (!typed.incident.valid()) {
            status = Bad("incident identifier is required");
            return;
          }
          if (!IsKnownIncidentClass(static_cast<std::uint8_t>(typed.cls)) ||
              typed.cls == IncidentClass::Unclassified) {
            status = Bad("accepting a report requires a concrete incident class");
            return;
          }
          if (!IsKnownSeverity(static_cast<std::uint8_t>(typed.severity)) ||
              typed.severity == Severity::Unclassified) {
            status = Bad("accepting a report requires a concrete severity");
            return;
          }
          if (!typed.severity_evidence.valid()) {
            status = Bad("accepting a report requires a severity assessment reference");
            return;
          }
          status = RequireFreeText(typed.rationale, FieldLimits::kRationale, "rationale");
        } else if constexpr (std::is_same_v<T, RejectReportRequest>) {
          if (!typed.incident.valid()) {
            status = Bad("incident identifier is required");
            return;
          }
          status = RequireFreeText(typed.rationale, FieldLimits::kRationale, "rationale");
          if (!status.ok()) return;
          if (typed.rationale.empty()) status = Bad("rejection rationale is required");
        } else if constexpr (std::is_same_v<T, RecordEvidenceRequest>) {
          if (!typed.incident.valid()) {
            status = Bad("incident identifier is required");
            return;
          }
          if (!IsKnownEvidenceKind(static_cast<std::uint8_t>(typed.kind))) {
            status = Bad("evidence kind is not known to this build");
            return;
          }
          if (!IsKnownSeverity(static_cast<std::uint8_t>(typed.asserted_severity))) {
            status = Bad("asserted severity is not known to this build");
            return;
          }
          if (typed.kind == EvidenceKind::SeverityAssessment &&
              typed.asserted_severity == Severity::Unclassified) {
            status = Bad("a severity assessment must assert a concrete severity");
            return;
          }
          if (typed.kind == EvidenceKind::EffectCleared && typed.effect_present) {
            status = Bad("clearance evidence cannot assert that the effect is still present");
            return;
          }
          status = ValidateScopeShape(typed.subject, "subject scope");
          if (!status.ok()) return;
          status = RequireFreeText(typed.rationale, FieldLimits::kRationale, "rationale");
          if (!status.ok()) return;
          status = RequireToken(typed.source_system, FieldLimits::kToken, "source system", true);
          if (!status.ok()) return;
          status = RequireToken(typed.source_event_id, FieldLimits::kToken, "source event id", true);
          if (!status.ok()) return;
          status = RequireFreeText(typed.detail, FieldLimits::kDetail, "detail");
          if (!status.ok()) return;
          if (ClassifyEvidence(typed.kind) == EvidenceClass::DurableAttestation &&
              typed.rationale.empty()) {
            status = Bad("durable attestations require a non-empty rationale");
          }
        } else if constexpr (std::is_same_v<T, WithdrawEvidenceRequest> ||
                             std::is_same_v<T, ReestablishEvidenceRequest>) {
          if (!typed.incident.valid() || !typed.evidence.valid()) {
            status = Bad("incident and evidence identifiers are required");
            return;
          }
          status = RequireFreeText(typed.rationale, FieldLimits::kRationale, "rationale");
          if (!status.ok()) return;
          if (typed.rationale.empty()) {
            status = Bad(std::string(std::is_same_v<T, WithdrawEvidenceRequest> ? "withdrawal"
                                                                                : "re-establishment") +
                         " rationale is required");
          }
        } else if constexpr (std::is_same_v<T, AmendSeverityRequest>) {
          if (!typed.incident.valid()) {
            status = Bad("incident identifier is required");
            return;
          }
          if (!IsKnownSeverity(static_cast<std::uint8_t>(typed.severity)) ||
              typed.severity == Severity::Unclassified) {
            status = Bad("severity amendments require a concrete severity");
            return;
          }
          if (typed.supporting_evidence.empty()) {
            status = Bad("severity amendments require at least one supporting assessment");
            return;
          }
          if (typed.supporting_evidence.size() > 64) {
            status = Status::Error(ErrorCode::LimitExceeded,
                                   "too many supporting assessments were supplied");
            return;
          }
          for (const EvidenceId id : typed.supporting_evidence) {
            if (!id.valid()) {
              status = Bad("supporting assessment identifiers must be non-zero");
              return;
            }
          }
          status = RequireFreeText(typed.rationale, FieldLimits::kRationale, "rationale");
          if (!status.ok()) return;
          if (typed.rationale.empty()) status = Bad("severity amendment rationale is required");
        } else if constexpr (std::is_same_v<T, AmendScopeRequest>) {
          if (!typed.incident.valid()) {
            status = Bad("incident identifier is required");
            return;
          }
          status = ValidateScopeShape(typed.scope, "scope");
          if (!status.ok()) return;
          status = RequireFreeText(typed.rationale, FieldLimits::kRationale, "rationale");
          if (!status.ok()) return;
          if (typed.rationale.empty()) status = Bad("scope amendment rationale is required");
        } else if constexpr (std::is_same_v<T, AssignOwnerRequest>) {
          if (!typed.incident.valid() || !typed.owner.valid()) {
            status = Bad("incident and owner identifiers are required");
            return;
          }
          status = RequireFreeText(typed.rationale, FieldLimits::kRationale, "rationale");
          if (!status.ok()) return;
          if (typed.rationale.empty()) status = Bad("ownership handoff rationale is required");
        } else if constexpr (std::is_same_v<T, DeclareContainedRequest> ||
                             std::is_same_v<T, DeclareRecoveredRequest> ||
                             std::is_same_v<T, ResolveIncidentRequest> ||
                             std::is_same_v<T, CloseIncidentRequest> ||
                             std::is_same_v<T, ReopenIncidentRequest>) {
          if (!typed.incident.valid()) {
            status = Bad("incident identifier is required");
            return;
          }
          status = RequireFreeText(typed.rationale, FieldLimits::kRationale, "rationale");
          if (!status.ok()) return;
          if (typed.rationale.empty()) status = Bad("a rationale is required for this transition");
        } else if constexpr (std::is_same_v<T, StartRecoveryRequest>) {
          if (!typed.incident.valid()) {
            status = Bad("incident identifier is required");
            return;
          }
          status = RequireFreeText(typed.rationale, FieldLimits::kRationale, "rationale");
          if (!status.ok()) return;
          if (typed.rationale.empty()) status = Bad("a rationale is required for this transition");
        } else if constexpr (std::is_same_v<T, CreateSuccessorRequest>) {
          if (!typed.predecessor.valid()) {
            status = Bad("predecessor incident identifier is required");
            return;
          }
          if (!IsKnownIncidentClass(static_cast<std::uint8_t>(typed.cls))) {
            status = Bad("incident class is not known to this build");
            return;
          }
          if (!IsKnownSeverity(static_cast<std::uint8_t>(typed.reported_severity))) {
            status = Bad("reported severity is not known to this build");
            return;
          }
          status = RequireToken(typed.summary, FieldLimits::kSummary, "summary", false);
          if (!status.ok()) return;
          status = ValidateScopeShape(typed.scope, "scope");
          if (!status.ok()) return;
          status = RequireToken(typed.source_system, FieldLimits::kToken, "source system", true);
          if (!status.ok()) return;
          status = RequireToken(typed.source_event_id, FieldLimits::kToken, "source event id", true);
          if (!status.ok()) return;
          status = RequireFreeText(typed.detail, FieldLimits::kDetail, "detail");
          if (!status.ok()) return;
          status = RequireFreeText(typed.rationale, FieldLimits::kRationale, "rationale");
          if (!status.ok()) return;
          if (typed.rationale.empty()) status = Bad("successor rationale is required");
        } else if constexpr (std::is_same_v<T, MergeIncidentRequest>) {
          if (!typed.survivor.valid() || !typed.absorbed.valid()) {
            status = Bad("survivor and absorbed incident identifiers are required");
            return;
          }
          if (typed.survivor == typed.absorbed) {
            status = Bad("an incident cannot be merged into itself");
            return;
          }
          status = RequireFreeText(typed.rationale, FieldLimits::kRationale, "rationale");
          if (!status.ok()) return;
          if (typed.rationale.empty()) status = Bad("merge rationale is required");
        }
      },
      request);
  return status;
}

Status CheckCapacity(const State& state, const StoreLimits& limits, OpKind op) {
  if (state.audit.size() >= limits.max_audit_entries) {
    return Status::Error(ErrorCode::ResourceExhausted,
                         "the store has reached its configured audit entry limit");
  }
  if (state.idempotency.size() >= limits.max_idempotency_entries) {
    return Status::Error(ErrorCode::ResourceExhausted,
                         "the store has reached its configured idempotency index limit");
  }
  switch (op) {
    case OpKind::RegisterAuthority:
      if (state.authorities.size() >= limits.max_authorities) {
        return Status::Error(ErrorCode::ResourceExhausted,
                             "the store has reached its configured authority limit");
      }
      break;
    case OpKind::ReportIncident:
    case OpKind::CreateSuccessor:
      if (state.incidents.size() >= limits.max_incidents) {
        return Status::Error(ErrorCode::ResourceExhausted,
                             "the store has reached its configured incident limit");
      }
      break;
    default:
      break;
  }
  return Status::Ok();
}

}  // namespace isf::detail
