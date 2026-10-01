// Incident State Fabric - DCCP boundary 50
// Copyright 2026 Summon Software Labs.
// Licensed under the Apache License, Version 2.0.

#include "isf/isf.h"
#include "test_framework.h"
#include "test_support.h"

using isftest::DenialSays;
using isftest::Fixture;
using isftest::Key;

ISF_TEST(Authority, BootstrapIsAllowedExactlyOnce) {
  Fixture fixture("auth-bootstrap", isf::StateDigestPolicy::EveryCommit);

  // The fixture already bootstrapped its director, so an anonymous registration
  // is no longer a legitimate bootstrap.
  isf::RegisterAuthorityRequest second;
  second.header.actor.authority = isf::AuthorityId{};
  second.header.actor.epoch = fixture.Epoch();
  second.header.key = Key(fixture.NextKey());
  second.name = "impostor";
  second.role = isf::AuthorityRole::FacilityDirector;
  second.rationale = "second bootstrap";
  ISF_EXPECT_ERROR(fixture.fabric().RegisterAuthority(second), isf::ErrorCode::AuthorityUnknown);
}

ISF_TEST(Authority, FreshStoreRequiresABootstrapBeforeAnythingElse) {
  isftest::ScratchDir scratch("auth-fresh");
  auto fabric = isf::IncidentFabric::Open(isftest::StoreOptions(scratch.path()));
  ISF_REQUIRE(fabric.ok());

  isf::ReportIncidentRequest report;
  report.header.actor.authority = isf::AuthorityId{};
  report.header.actor.epoch = isftest::CurrentEpoch(*fabric.value());
  report.header.key = Key(1);
  report.cls = isf::IncidentClass::Power;
  report.reported_severity = isf::Severity::Major;
  report.summary = "no authority";
  report.scope = isftest::RackScope("rack-a");
  report.source_system = "synthetic";
  report.source_event_id = "x";
  ISF_EXPECT_ERROR(fabric.value()->ReportIncident(report), isf::ErrorCode::AuthorityUnknown);
}

ISF_TEST(Authority, RolesCannotBeEscalated) {
  Fixture fixture("auth-escalate", isf::StateDigestPolicy::EveryCommit);

  isf::RegisterAuthorityRequest escalate;
  escalate.header = fixture.Header(fixture.commander);
  escalate.name = "self-appointed";
  escalate.role = isf::AuthorityRole::FacilityDirector;
  escalate.rationale = "role escalation attempt";
  ISF_EXPECT_ERROR(fixture.fabric().RegisterAuthority(escalate), isf::ErrorCode::Unauthorized);

  isf::RegisterAuthorityRequest peer;
  peer.header = fixture.Header(fixture.observer);
  peer.name = "observer-created";
  peer.role = isf::AuthorityRole::Operator;
  peer.rationale = "observer cannot create roles";
  ISF_EXPECT_ERROR(fixture.fabric().RegisterAuthority(peer), isf::ErrorCode::Unauthorized);

  isf::RegisterAuthorityRequest duplicate;
  duplicate.header = fixture.Header(fixture.director);
  duplicate.name = "observer";
  duplicate.role = isf::AuthorityRole::Observer;
  duplicate.rationale = "duplicate name";
  ISF_EXPECT_ERROR(fixture.fabric().RegisterAuthority(duplicate), isf::ErrorCode::AlreadyExists);
}

ISF_TEST(Authority, RevocationIsBoundedAndTerminal) {
  Fixture fixture("auth-revoke", isf::StateDigestPolicy::EveryCommit);

  isf::RevokeAuthorityRequest by_observer;
  by_observer.header = fixture.Header(fixture.observer);
  by_observer.target = fixture.operator_role;
  by_observer.rationale = "observer cannot revoke";
  ISF_EXPECT_ERROR(fixture.fabric().RevokeAuthority(by_observer), isf::ErrorCode::Unauthorized);

  isf::RevokeAuthorityRequest upward;
  upward.header = fixture.Header(fixture.commander);
  upward.target = fixture.director;
  upward.rationale = "cannot revoke above your role";
  ISF_EXPECT_ERROR(fixture.fabric().RevokeAuthority(upward), isf::ErrorCode::Unauthorized);

  isf::RevokeAuthorityRequest self;
  self.header = fixture.Header(fixture.director);
  self.target = fixture.director;
  self.rationale = "self revocation";
  ISF_EXPECT_ERROR(fixture.fabric().RevokeAuthority(self), isf::ErrorCode::Conflict);

  isf::RevokeAuthorityRequest revoke;
  revoke.header = fixture.Header(fixture.director);
  revoke.target = fixture.observer;
  revoke.rationale = "observer no longer needed";
  ISF_REQUIRE(fixture.fabric().RevokeAuthority(revoke).ok());

  isf::ForceFenceRequest fenced;
  fenced.header = fixture.Header(fixture.observer);
  fenced.rationale = "revoked authority attempts work";
  fenced.header.key = Key(fixture.NextKey());
  ISF_EXPECT_ERROR(fixture.fabric().ForceFence(fenced), isf::ErrorCode::AuthorityRevoked);
}

ISF_TEST(Authority, UnknownAuthorityIsRefused) {
  Fixture fixture("auth-unknown", isf::StateDigestPolicy::EveryCommit);
  isf::ForceFenceRequest request;
  request.header.actor.authority = isf::AuthorityId{987654};
  request.header.actor.epoch = fixture.Epoch();
  request.header.key = Key(fixture.NextKey());
  request.rationale = "unknown authority";
  ISF_EXPECT_ERROR(fixture.fabric().ForceFence(request), isf::ErrorCode::AuthorityUnknown);
}

ISF_TEST(Authority, StaleControlEpochIsFenced) {
  Fixture fixture("auth-epoch", isf::StateDigestPolicy::EveryCommit);
  const isf::ControlEpoch observed = fixture.Epoch();

  isf::ForceFenceRequest fence;
  fence.header = fixture.Header(fixture.director);
  fence.rationale = "deliberate fencing";
  ISF_REQUIRE(fixture.fabric().ForceFence(fence).ok());
  ISF_CHECK_EQ(fixture.Epoch().value, observed.value + 1);

  isf::ReportIncidentRequest stale;
  stale.header.actor.authority = fixture.operator_role;
  stale.header.actor.epoch = observed;
  stale.header.key = Key(fixture.NextKey());
  stale.cls = isf::IncidentClass::Power;
  stale.reported_severity = isf::Severity::Major;
  stale.summary = "stale actor";
  stale.scope = isftest::RackScope("rack-a");
  stale.source_system = "synthetic";
  stale.source_event_id = "stale-1";
  ISF_EXPECT_ERROR(fixture.fabric().ReportIncident(stale), isf::ErrorCode::StaleControlEpoch);
}

ISF_TEST(Authority, ForceFenceRequiresFacilityDirector) {
  Fixture fixture("auth-fence-role", isf::StateDigestPolicy::EveryCommit);
  isf::ForceFenceRequest request;
  request.header = fixture.Header(fixture.manager);
  request.rationale = "manager cannot fence";
  ISF_EXPECT_ERROR(fixture.fabric().ForceFence(request), isf::ErrorCode::Unauthorized);
}

ISF_TEST(Authority, StaleRevisionIsRefused) {
  Fixture fixture("auth-revision", isf::StateDigestPolicy::EveryCommit);
  const isf::IncidentId incident = isftest::ReportIncident(fixture, "revision guard", "rack-a");
  const std::uint64_t revision = isftest::RevisionOf(fixture.fabric(), incident);
  ISF_CHECK_EQ(revision, std::uint64_t{1});

  isf::RecordEvidenceRequest evidence;
  evidence.header = fixture.Header(fixture.operator_role);
  evidence.incident = incident;
  evidence.expected_revision = revision;
  evidence.kind = isf::EvidenceKind::Acknowledgement;
  evidence.rationale = "ack";
  ISF_REQUIRE(fixture.fabric().RecordEvidence(evidence).ok());

  evidence.header = fixture.Header(fixture.operator_role);
  evidence.rationale = "stale ack";
  ISF_EXPECT_ERROR(fixture.fabric().RecordEvidence(evidence), isf::ErrorCode::StaleRevision);
}

ISF_TEST(Authority, RoleIsTakenFromTheRegistryNotTheRequest) {
  // There is no role field on the wire at all: the only place a role lives is
  // the registered authority record, so a caller cannot assert one.
  Fixture fixture("auth-role-source", isf::StateDigestPolicy::EveryCommit);
  const auto listed = fixture.fabric().ListAuthorities(isf::ListQuery{0, 100});
  ISF_REQUIRE(listed.ok());
  bool found_commander = false;
  for (const isf::AuthorityView& view : listed.value()) {
    if (view.id == fixture.commander) {
      found_commander = true;
      ISF_CHECK_EQ(view.role, isf::AuthorityRole::IncidentCommander);
      ISF_CHECK(view.active);
    }
  }
  ISF_CHECK(found_commander);
}
