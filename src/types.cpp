// Incident State Fabric - DCCP boundary 50
// Copyright 2026 Summon Software Labs.
// Licensed under the Apache License, Version 2.0.

#include "isf/types.h"

#include <algorithm>
#include <type_traits>
#include <variant>

#include "isf/model.h"
#include "isf/requests.h"
#include "isf/version.h"

namespace isf {

const char* VersionString() noexcept { return ISF_VERSION_STRING; }

Version LibraryVersion() noexcept { return Version{}; }

const char* StoreFormatIdentifier() noexcept { return "ISFSTORE"; }

std::uint16_t StoreFormatVersion() noexcept { return 1; }

const char* ToString(Severity value) noexcept {
  switch (value) {
    case Severity::Unclassified: return "Unclassified";
    case Severity::Informational: return "Informational";
    case Severity::Minor: return "Minor";
    case Severity::Major: return "Major";
    case Severity::Critical: return "Critical";
    case Severity::Catastrophic: return "Catastrophic";
  }
  return "Unknown";
}

const char* ToString(IncidentClass value) noexcept {
  switch (value) {
    case IncidentClass::Unclassified: return "Unclassified";
    case IncidentClass::Power: return "Power";
    case IncidentClass::Cooling: return "Cooling";
    case IncidentClass::Network: return "Network";
    case IncidentClass::Compute: return "Compute";
    case IncidentClass::Storage: return "Storage";
    case IncidentClass::FireSuppression: return "FireSuppression";
    case IncidentClass::WaterIngress: return "WaterIngress";
    case IncidentClass::PhysicalSecurity: return "PhysicalSecurity";
    case IncidentClass::Structural: return "Structural";
    case IncidentClass::Environmental: return "Environmental";
  }
  return "Unknown";
}

const char* ToString(LifecycleState value) noexcept {
  switch (value) {
    case LifecycleState::Reported: return "Reported";
    case LifecycleState::Accepted: return "Accepted";
    case LifecycleState::Contained: return "Contained";
    case LifecycleState::Recovering: return "Recovering";
    case LifecycleState::Recovered: return "Recovered";
    case LifecycleState::Resolved: return "Resolved";
    case LifecycleState::Closed: return "Closed";
    case LifecycleState::Reopened: return "Reopened";
    case LifecycleState::Rejected: return "Rejected";
    case LifecycleState::Superseded: return "Superseded";
  }
  return "Unknown";
}

const char* ToString(AuthorityRole value) noexcept {
  switch (value) {
    case AuthorityRole::None: return "None";
    case AuthorityRole::Observer: return "Observer";
    case AuthorityRole::Operator: return "Operator";
    case AuthorityRole::IncidentCommander: return "IncidentCommander";
    case AuthorityRole::DutyManager: return "DutyManager";
    case AuthorityRole::FacilityDirector: return "FacilityDirector";
  }
  return "Unknown";
}

const char* ToString(ObjectKind value) noexcept {
  switch (value) {
    case ObjectKind::Unknown: return "Unknown";
    case ObjectKind::Room: return "Room";
    case ObjectKind::Hall: return "Hall";
    case ObjectKind::Row: return "Row";
    case ObjectKind::Rack: return "Rack";
    case ObjectKind::Pdu: return "Pdu";
    case ObjectKind::Ups: return "Ups";
    case ObjectKind::Generator: return "Generator";
    case ObjectKind::Busway: return "Busway";
    case ObjectKind::Crac: return "Crac";
    case ObjectKind::Chiller: return "Chiller";
    case ObjectKind::CoolingLoop: return "CoolingLoop";
    case ObjectKind::Switch: return "Switch";
    case ObjectKind::Router: return "Router";
    case ObjectKind::Server: return "Server";
    case ObjectKind::StorageArray: return "StorageArray";
    case ObjectKind::FirePanel: return "FirePanel";
    case ObjectKind::SuppressionZone: return "SuppressionZone";
    case ObjectKind::AccessPanel: return "AccessPanel";
    case ObjectKind::Sensor: return "Sensor";
    case ObjectKind::Workload: return "Workload";
    case ObjectKind::Other: return "Other";
  }
  return "Unknown";
}

const char* ToString(FailureDomainKind value) noexcept {
  switch (value) {
    case FailureDomainKind::Unknown: return "Unknown";
    case FailureDomainKind::PowerFeed: return "PowerFeed";
    case FailureDomainKind::CoolingLoop: return "CoolingLoop";
    case FailureDomainKind::NetworkPlane: return "NetworkPlane";
    case FailureDomainKind::Zone: return "Zone";
    case FailureDomainKind::Hall: return "Hall";
    case FailureDomainKind::Room: return "Room";
    case FailureDomainKind::Row: return "Row";
    case FailureDomainKind::Utility: return "Utility";
    case FailureDomainKind::Other: return "Other";
  }
  return "Unknown";
}

const char* ToString(EvidenceKind value) noexcept {
  switch (value) {
    case EvidenceKind::Report: return "Report";
    case EvidenceKind::SeverityAssessment: return "SeverityAssessment";
    case EvidenceKind::Acknowledgement: return "Acknowledgement";
    case EvidenceKind::EffectObservation: return "EffectObservation";
    case EvidenceKind::MitigationRequest: return "MitigationRequest";
    case EvidenceKind::AlarmSilence: return "AlarmSilence";
    case EvidenceKind::ContainmentProof: return "ContainmentProof";
    case EvidenceKind::RecoveryProof: return "RecoveryProof";
    case EvidenceKind::EffectCleared: return "EffectCleared";
    case EvidenceKind::ClosureAttestation: return "ClosureAttestation";
    case EvidenceKind::ReopenTrigger: return "ReopenTrigger";
    case EvidenceKind::MaintenanceWindowNotice: return "MaintenanceWindowNotice";
  }
  return "Unknown";
}

const char* ToString(EvidenceClass value) noexcept {
  switch (value) {
    case EvidenceClass::DynamicObservation: return "DynamicObservation";
    case EvidenceClass::DurableAttestation: return "DurableAttestation";
  }
  return "Unknown";
}

const char* ToString(OpKind value) noexcept {
  switch (value) {
    case OpKind::SessionOpen: return "SessionOpen";
    case OpKind::SessionClose: return "SessionClose";
    case OpKind::RegisterAuthority: return "RegisterAuthority";
    case OpKind::RevokeAuthority: return "RevokeAuthority";
    case OpKind::ForceFence: return "ForceFence";
    case OpKind::ReportIncident: return "ReportIncident";
    case OpKind::AcceptIncident: return "AcceptIncident";
    case OpKind::RejectReport: return "RejectReport";
    case OpKind::RecordEvidence: return "RecordEvidence";
    case OpKind::WithdrawEvidence: return "WithdrawEvidence";
    case OpKind::ReestablishEvidence: return "ReestablishEvidence";
    case OpKind::AmendSeverity: return "AmendSeverity";
    case OpKind::AmendScope: return "AmendScope";
    case OpKind::AssignOwner: return "AssignOwner";
    case OpKind::DeclareContained: return "DeclareContained";
    case OpKind::StartRecovery: return "StartRecovery";
    case OpKind::DeclareRecovered: return "DeclareRecovered";
    case OpKind::ResolveIncident: return "ResolveIncident";
    case OpKind::CloseIncident: return "CloseIncident";
    case OpKind::ReopenIncident: return "ReopenIncident";
    case OpKind::CreateSuccessor: return "CreateSuccessor";
    case OpKind::MergeIncident: return "MergeIncident";
  }
  return "Unknown";
}

const char* ToString(ErrorCode code) noexcept {
  switch (code) {
    case ErrorCode::Ok: return "Ok";
    case ErrorCode::InvalidArgument: return "InvalidArgument";
    case ErrorCode::NotFound: return "NotFound";
    case ErrorCode::AlreadyExists: return "AlreadyExists";
    case ErrorCode::Conflict: return "Conflict";
    case ErrorCode::LimitExceeded: return "LimitExceeded";
    case ErrorCode::Unsupported: return "Unsupported";
    case ErrorCode::IllegalTransition: return "IllegalTransition";
    case ErrorCode::GateUnsatisfied: return "GateUnsatisfied";
    case ErrorCode::NotCurrentEvidence: return "NotCurrentEvidence";
    case ErrorCode::ReopenLimitReached: return "ReopenLimitReached";
    case ErrorCode::DuplicateIdentity: return "DuplicateIdentity";
    case ErrorCode::Unauthorized: return "Unauthorized";
    case ErrorCode::AuthorityRevoked: return "AuthorityRevoked";
    case ErrorCode::AuthorityUnknown: return "AuthorityUnknown";
    case ErrorCode::StaleControlEpoch: return "StaleControlEpoch";
    case ErrorCode::StaleRevision: return "StaleRevision";
    case ErrorCode::IdempotencyConflict: return "IdempotencyConflict";
    case ErrorCode::Overflow: return "Overflow";
    case ErrorCode::StoreLocked: return "StoreLocked";
    case ErrorCode::StoreCorrupt: return "StoreCorrupt";
    case ErrorCode::StoreIncompatible: return "StoreIncompatible";
    case ErrorCode::StoreIoError: return "StoreIoError";
    case ErrorCode::StoreClosed: return "StoreClosed";
    case ErrorCode::IntegrityFailure: return "IntegrityFailure";
    case ErrorCode::UnsafePath: return "UnsafePath";
    case ErrorCode::ResourceExhausted: return "ResourceExhausted";
    case ErrorCode::InternalError: return "InternalError";
  }
  return "Unknown";
}

EvidenceClass ClassifyEvidence(EvidenceKind kind) noexcept {
  switch (kind) {
    case EvidenceKind::Report:
    case EvidenceKind::SeverityAssessment:
    case EvidenceKind::Acknowledgement:
    case EvidenceKind::EffectObservation:
    case EvidenceKind::MitigationRequest:
    case EvidenceKind::AlarmSilence:
      return EvidenceClass::DynamicObservation;
    case EvidenceKind::ContainmentProof:
    case EvidenceKind::RecoveryProof:
    case EvidenceKind::EffectCleared:
    case EvidenceKind::ClosureAttestation:
    case EvidenceKind::ReopenTrigger:
    case EvidenceKind::MaintenanceWindowNotice:
      return EvidenceClass::DurableAttestation;
  }
  return EvidenceClass::DynamicObservation;
}

bool IsTerminal(LifecycleState state) noexcept {
  switch (state) {
    case LifecycleState::Closed:
    case LifecycleState::Rejected:
    case LifecycleState::Superseded:
      return true;
    default:
      return false;
  }
}

bool IsLive(LifecycleState state) noexcept { return !IsTerminal(state); }

bool IsKnownSeverity(std::uint8_t raw) noexcept { return raw <= kSeverityMax; }

bool IsKnownIncidentClass(std::uint8_t raw) noexcept { return raw <= kIncidentClassMax; }

bool IsKnownLifecycleState(std::uint8_t raw) noexcept {
  return raw >= 1 && raw <= kLifecycleStateMax;
}

bool IsKnownAuthorityRole(std::uint8_t raw) noexcept { return raw <= kAuthorityRoleMax; }

bool IsKnownEvidenceKind(std::uint8_t raw) noexcept {
  return raw >= 1 && raw <= kEvidenceKindMax;
}

bool IsKnownOpKind(std::uint32_t raw) noexcept {
  switch (static_cast<OpKind>(raw)) {
    case OpKind::SessionOpen:
    case OpKind::SessionClose:
    case OpKind::RegisterAuthority:
    case OpKind::RevokeAuthority:
    case OpKind::ForceFence:
    case OpKind::ReportIncident:
    case OpKind::AcceptIncident:
    case OpKind::RejectReport:
    case OpKind::RecordEvidence:
    case OpKind::WithdrawEvidence:
    case OpKind::ReestablishEvidence:
    case OpKind::AmendSeverity:
    case OpKind::AmendScope:
    case OpKind::AssignOwner:
    case OpKind::DeclareContained:
    case OpKind::StartRecovery:
    case OpKind::DeclareRecovered:
    case OpKind::ResolveIncident:
    case OpKind::CloseIncident:
    case OpKind::ReopenIncident:
    case OpKind::CreateSuccessor:
    case OpKind::MergeIncident:
      return true;
    default:
      return false;
  }
}

AffectedScope& Canonicalize(AffectedScope& scope) {
  std::sort(scope.objects.begin(), scope.objects.end());
  scope.objects.erase(std::unique(scope.objects.begin(), scope.objects.end()), scope.objects.end());
  std::sort(scope.failure_domains.begin(), scope.failure_domains.end());
  scope.failure_domains.erase(
      std::unique(scope.failure_domains.begin(), scope.failure_domains.end()),
      scope.failure_domains.end());
  return scope;
}

IncidentClassPolicy PolicyFor(IncidentClass cls) noexcept {
  IncidentClassPolicy policy;
  switch (cls) {
    case IncidentClass::PhysicalSecurity:
      policy.requires_containment = true;
      policy.requires_recovery = false;
      policy.resolution_role = AuthorityRole::DutyManager;
      policy.closure_role = AuthorityRole::DutyManager;
      break;
    case IncidentClass::Unclassified:
    case IncidentClass::Power:
    case IncidentClass::Cooling:
    case IncidentClass::Network:
    case IncidentClass::Compute:
    case IncidentClass::Storage:
    case IncidentClass::FireSuppression:
    case IncidentClass::WaterIngress:
    case IncidentClass::Structural:
    case IncidentClass::Environmental:
      policy.requires_containment = true;
      policy.requires_recovery = true;
      policy.resolution_role = AuthorityRole::DutyManager;
      policy.closure_role = AuthorityRole::FacilityDirector;
      break;
  }
  return policy;
}

const MutationHeader& HeaderOf(const AnyRequest& request) noexcept {
  return std::visit(
      [](const auto& typed) -> const MutationHeader& { return typed.header; }, request);
}

namespace {

/// Indexed by AnyRequest's alternative order, which is asserted below. A table
/// keeps the mapping total and free of unreachable fallbacks.
constexpr OpKind kOpKindByAlternative[] = {
    OpKind::RegisterAuthority,   OpKind::RevokeAuthority,    OpKind::ForceFence,
    OpKind::ReportIncident,      OpKind::AcceptIncident,     OpKind::RejectReport,
    OpKind::RecordEvidence,      OpKind::WithdrawEvidence,   OpKind::ReestablishEvidence,
    OpKind::AmendSeverity,       OpKind::AmendScope,         OpKind::AssignOwner,
    OpKind::DeclareContained,    OpKind::StartRecovery,      OpKind::DeclareRecovered,
    OpKind::ResolveIncident,     OpKind::CloseIncident,      OpKind::ReopenIncident,
    OpKind::CreateSuccessor,     OpKind::MergeIncident,
};

static_assert(std::size(kOpKindByAlternative) == std::variant_size_v<AnyRequest>,
              "the operation table must cover every request alternative in order");

}  // namespace

OpKind KindOf(const AnyRequest& request) noexcept {
  return kOpKindByAlternative[request.index()];
}

}  // namespace isf
