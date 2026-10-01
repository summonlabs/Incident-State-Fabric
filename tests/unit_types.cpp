// Incident State Fabric - DCCP boundary 50
// Copyright 2026 Summon Software Labs.
// Licensed under the Apache License, Version 2.0.

#include <array>
#include <string>
#include <variant>

#include "isf/isf.h"
#include "test_framework.h"

ISF_TEST(Types, StableNamesCoverEveryEnumerator) {
  for (std::uint8_t raw = 0; raw <= isf::kSeverityMax; ++raw) {
    const char* name = isf::ToString(static_cast<isf::Severity>(raw));
    ISF_CHECK(name != nullptr && *name != '\0');
    ISF_CHECK(std::string(name) != "Unknown");
  }
  for (std::uint8_t raw = 0; raw <= isf::kIncidentClassMax; ++raw) {
    ISF_CHECK(std::string(isf::ToString(static_cast<isf::IncidentClass>(raw))) != "Unknown");
  }
  for (std::uint8_t raw = 1; raw <= isf::kLifecycleStateMax; ++raw) {
    ISF_CHECK(std::string(isf::ToString(static_cast<isf::LifecycleState>(raw))) != "Unknown");
  }
  for (std::uint8_t raw = 0; raw <= isf::kAuthorityRoleMax; ++raw) {
    ISF_CHECK(std::string(isf::ToString(static_cast<isf::AuthorityRole>(raw))) != "Unknown");
  }
  for (std::uint8_t raw = 1; raw <= isf::kEvidenceKindMax; ++raw) {
    ISF_CHECK(std::string(isf::ToString(static_cast<isf::EvidenceKind>(raw))) != "Unknown");
  }
  std::uint32_t known_operations = 0;
  for (std::uint32_t raw = 1; raw <= 0xffffu; ++raw) {
    if (!isf::IsKnownOpKind(raw)) continue;
    ++known_operations;
    ISF_CHECK(std::string(isf::ToString(static_cast<isf::OpKind>(raw))) != "Unknown");
  }
  ISF_CHECK_EQ(known_operations, std::uint32_t{22});
}

ISF_TEST(Types, EvidenceClassificationIsTotal) {
  const std::array<isf::EvidenceKind, 6> dynamic{{
      isf::EvidenceKind::Report, isf::EvidenceKind::SeverityAssessment,
      isf::EvidenceKind::Acknowledgement, isf::EvidenceKind::EffectObservation,
      isf::EvidenceKind::MitigationRequest, isf::EvidenceKind::AlarmSilence}};
  for (const isf::EvidenceKind kind : dynamic) {
    ISF_CHECK_EQ(isf::ClassifyEvidence(kind), isf::EvidenceClass::DynamicObservation);
  }
  const std::array<isf::EvidenceKind, 6> durable{{
      isf::EvidenceKind::ContainmentProof, isf::EvidenceKind::RecoveryProof,
      isf::EvidenceKind::EffectCleared, isf::EvidenceKind::ClosureAttestation,
      isf::EvidenceKind::ReopenTrigger, isf::EvidenceKind::MaintenanceWindowNotice}};
  for (const isf::EvidenceKind kind : durable) {
    ISF_CHECK_EQ(isf::ClassifyEvidence(kind), isf::EvidenceClass::DurableAttestation);
  }
}

ISF_TEST(Types, KnownRangeChecksRejectBoundaries) {
  ISF_CHECK(isf::IsKnownSeverity(0));
  ISF_CHECK(isf::IsKnownSeverity(isf::kSeverityMax));
  ISF_CHECK(!isf::IsKnownSeverity(static_cast<std::uint8_t>(isf::kSeverityMax + 1)));
  ISF_CHECK(isf::IsKnownIncidentClass(isf::kIncidentClassMax));
  ISF_CHECK(!isf::IsKnownIncidentClass(static_cast<std::uint8_t>(isf::kIncidentClassMax + 1)));
  ISF_CHECK(isf::IsKnownLifecycleState(1));
  ISF_CHECK(!isf::IsKnownLifecycleState(0));
  ISF_CHECK(isf::IsKnownLifecycleState(isf::kLifecycleStateMax));
  ISF_CHECK(!isf::IsKnownLifecycleState(static_cast<std::uint8_t>(isf::kLifecycleStateMax + 1)));
  ISF_CHECK(isf::IsKnownAuthorityRole(0));
  ISF_CHECK(!isf::IsKnownAuthorityRole(static_cast<std::uint8_t>(isf::kAuthorityRoleMax + 1)));
  ISF_CHECK(isf::IsKnownEvidenceKind(1));
  ISF_CHECK(!isf::IsKnownEvidenceKind(0));
  ISF_CHECK(!isf::IsKnownEvidenceKind(static_cast<std::uint8_t>(isf::kEvidenceKindMax + 1)));
  ISF_CHECK(isf::IsKnownOpKind(1));
  ISF_CHECK(isf::IsKnownOpKind(37));
  ISF_CHECK(!isf::IsKnownOpKind(38));
  ISF_CHECK(!isf::IsKnownOpKind(0));
  ISF_CHECK(!isf::IsKnownOpKind(240));
  ISF_CHECK(!isf::IsKnownOpKind(0xffffffffu));
}

ISF_TEST(Types, TerminalAndLiveStatesAreComplements) {
  for (std::uint8_t raw = 1; raw <= isf::kLifecycleStateMax; ++raw) {
    const auto state = static_cast<isf::LifecycleState>(raw);
    ISF_CHECK_EQ(isf::IsTerminal(state), !isf::IsLive(state));
  }
  ISF_CHECK(isf::IsTerminal(isf::LifecycleState::Closed));
  ISF_CHECK(isf::IsTerminal(isf::LifecycleState::Rejected));
  ISF_CHECK(isf::IsTerminal(isf::LifecycleState::Superseded));
  ISF_CHECK(!isf::IsTerminal(isf::LifecycleState::Reopened));
  ISF_CHECK(!isf::IsTerminal(isf::LifecycleState::Resolved));
}

ISF_TEST(Types, ScopeCanonicalizationIsOrderAndDuplicateIndependent) {
  isf::AffectedScope first;
  first.objects.push_back(isf::ObjectRef{isf::ObjectKind::Rack, "b"});
  first.objects.push_back(isf::ObjectRef{isf::ObjectKind::Rack, "a"});
  first.objects.push_back(isf::ObjectRef{isf::ObjectKind::Rack, "a"});
  first.failure_domains.push_back(isf::FailureDomainRef{isf::FailureDomainKind::Row, "z"});
  first.failure_domains.push_back(isf::FailureDomainRef{isf::FailureDomainKind::PowerFeed, "p"});

  isf::AffectedScope second;
  second.objects.push_back(isf::ObjectRef{isf::ObjectKind::Rack, "a"});
  second.objects.push_back(isf::ObjectRef{isf::ObjectKind::Rack, "b"});
  second.failure_domains.push_back(isf::FailureDomainRef{isf::FailureDomainKind::PowerFeed, "p"});
  second.failure_domains.push_back(isf::FailureDomainRef{isf::FailureDomainKind::Row, "z"});

  isf::Canonicalize(first);
  isf::Canonicalize(second);
  ISF_CHECK(first == second);
  ISF_CHECK_EQ(first.objects.size(), std::size_t{2});
  ISF_CHECK_EQ(first.objects[0].id, std::string("a"));
  ISF_CHECK_EQ(first.failure_domains[0].id, std::string("p"));
}

ISF_TEST(Types, ClassPolicyTableIsStable) {
  const isf::IncidentClassPolicy power = isf::PolicyFor(isf::IncidentClass::Power);
  ISF_CHECK(power.requires_containment);
  ISF_CHECK(power.requires_recovery);
  ISF_CHECK_EQ(power.resolution_role, isf::AuthorityRole::DutyManager);
  ISF_CHECK_EQ(power.closure_role, isf::AuthorityRole::FacilityDirector);

  const isf::IncidentClassPolicy security = isf::PolicyFor(isf::IncidentClass::PhysicalSecurity);
  ISF_CHECK(security.requires_containment);
  ISF_CHECK(!security.requires_recovery);
  ISF_CHECK_EQ(security.closure_role, isf::AuthorityRole::DutyManager);

  const isf::IncidentClassPolicy cooling = isf::PolicyFor(isf::IncidentClass::Cooling);
  ISF_CHECK_EQ(cooling.closure_role, isf::AuthorityRole::FacilityDirector);
}

ISF_TEST(Types, VersionIsConsistentAcrossHeaderAndLibrary) {
  ISF_CHECK_EQ(isf::VersionString(), std::string("1.0.0"));
  ISF_CHECK(isf::HeaderVersion() == isf::LibraryVersion());
  ISF_CHECK_EQ(isf::LibraryVersion().major, std::uint32_t{1});
  ISF_CHECK_EQ(isf::LibraryVersion().minor, std::uint32_t{0});
  ISF_CHECK_EQ(isf::LibraryVersion().patch, std::uint32_t{0});
  ISF_CHECK_EQ(isf::StoreFormatIdentifier(), std::string("ISFSTORE"));
  ISF_CHECK_EQ(isf::StoreFormatVersion(), std::uint16_t{1});
}

namespace {

[[nodiscard]] std::vector<isf::AnyRequest> EveryRequestKind() {
  isf::MutationHeader header;
  header.actor.authority = isf::AuthorityId{1};
  header.actor.epoch = isf::ControlEpoch{1};
  header.key = isf::IdempotencyKey{1, 1};
  std::vector<isf::AnyRequest> requests;
  requests.push_back(isf::RegisterAuthorityRequest{});
  requests.push_back(isf::RevokeAuthorityRequest{});
  requests.push_back(isf::ForceFenceRequest{});
  requests.push_back(isf::ReportIncidentRequest{});
  requests.push_back(isf::AcceptIncidentRequest{});
  requests.push_back(isf::RejectReportRequest{});
  requests.push_back(isf::RecordEvidenceRequest{});
  requests.push_back(isf::WithdrawEvidenceRequest{});
  requests.push_back(isf::ReestablishEvidenceRequest{});
  requests.push_back(isf::AmendSeverityRequest{});
  requests.push_back(isf::AmendScopeRequest{});
  requests.push_back(isf::AssignOwnerRequest{});
  requests.push_back(isf::DeclareContainedRequest{});
  requests.push_back(isf::StartRecoveryRequest{});
  requests.push_back(isf::DeclareRecoveredRequest{});
  requests.push_back(isf::ResolveIncidentRequest{});
  requests.push_back(isf::CloseIncidentRequest{});
  requests.push_back(isf::ReopenIncidentRequest{});
  requests.push_back(isf::CreateSuccessorRequest{});
  requests.push_back(isf::MergeIncidentRequest{});
  return requests;
}

}  // namespace

ISF_TEST(Types, EveryRequestKindHasADistinctOperation) {
  std::vector<isf::OpKind> seen;
  for (const isf::AnyRequest& request : EveryRequestKind()) {
    const isf::OpKind kind = isf::KindOf(request);
    ISF_CHECK(isf::IsKnownOpKind(static_cast<std::uint32_t>(kind)));
    for (const isf::OpKind existing : seen) {
      ISF_CHECK(kind != existing);
    }
    seen.push_back(kind);
  }
  ISF_CHECK_EQ(seen.size(), std::size_t{20});
}

ISF_TEST(Types, HeaderOfReturnsTheRequestsOwnHeader) {
  isf::ForceFenceRequest request;
  request.header.key = isf::IdempotencyKey{11, 22};
  request.header.actor.authority = isf::AuthorityId{7};
  isf::AnyRequest any{request};
  ISF_CHECK_EQ(isf::HeaderOf(any).key, request.header.key);
  ISF_CHECK_EQ(isf::HeaderOf(any).actor.authority, request.header.actor.authority);
  ISF_CHECK_EQ(isf::KindOf(any), isf::OpKind::ForceFence);
}
