// Incident State Fabric - DCCP boundary 50
// Copyright 2026 Summon Software Labs.
// Licensed under the Apache License, Version 2.0.

#include <string>

#include "isf/isf.h"
#include "test_framework.h"
#include "test_support.h"

using isftest::Fixture;
using isftest::IncidentOf;
using isftest::Key;
using isftest::RackScope;
using isftest::RevisionOf;

namespace {

[[nodiscard]] isf::ReportIncidentRequest Report(std::uint64_t key, const std::string& event) {
  isf::ReportIncidentRequest request;
  request.header.key = Key(key);
  request.cls = isf::IncidentClass::Power;
  request.reported_severity = isf::Severity::Major;
  request.summary = "idempotent report";
  request.scope = RackScope("rack-q1");
  request.source_system = "synthetic-dcim";
  request.source_event_id = event;
  return request;
}

}  // namespace

ISF_TEST(Idempotency, TheSameRequestReplaysInsteadOfCommittingTwice) {
  Fixture fixture("idem-replay", isf::StateDigestPolicy::EveryCommit);

  isf::ReportIncidentRequest request = Report(4242, "event-a");
  request.header.actor.authority = fixture.operator_role;
  request.header.actor.epoch = fixture.Epoch();

  const auto first = fixture.fabric().ReportIncident(request);
  ISF_REQUIRE(first.ok());
  ISF_CHECK(!first.value().replayed);

  const auto status_after_first = fixture.fabric().GetStatus();
  ISF_REQUIRE(status_after_first.ok());

  const auto second = fixture.fabric().ReportIncident(request);
  ISF_REQUIRE(second.ok());
  ISF_CHECK(second.value().replayed);
  ISF_CHECK_EQ(second.value().generation, first.value().generation);
  ISF_CHECK_EQ(second.value().incident, first.value().incident);

  const auto status_after_second = fixture.fabric().GetStatus();
  ISF_REQUIRE(status_after_second.ok());
  ISF_CHECK_EQ(status_after_second.value().generation, status_after_first.value().generation);
  ISF_CHECK_EQ(status_after_second.value().incident_count, std::uint64_t{1});
  ISF_CHECK_EQ(status_after_second.value().audit_count, status_after_first.value().audit_count);

  // A hundred retries of the same request still produce exactly one incident.
  for (int attempt = 0; attempt < 100; ++attempt) {
    const auto retry = fixture.fabric().ReportIncident(request);
    ISF_REQUIRE(retry.ok());
    ISF_CHECK(retry.value().replayed);
  }
  const auto final_status = fixture.fabric().GetStatus();
  ISF_REQUIRE(final_status.ok());
  ISF_CHECK_EQ(final_status.value().incident_count, std::uint64_t{1});
  ISF_CHECK_EQ(final_status.value().audit_count, status_after_first.value().audit_count);
}

ISF_TEST(Idempotency, ReusingAKeyForADifferentOperationIsRefused) {
  Fixture fixture("idem-conflict", isf::StateDigestPolicy::EveryCommit);
  isf::ReportIncidentRequest request = Report(777, "event-b");
  request.header.actor.authority = fixture.operator_role;
  request.header.actor.epoch = fixture.Epoch();
  ISF_REQUIRE(fixture.fabric().ReportIncident(request).ok());

  isf::ReportIncidentRequest different = request;
  different.summary = "different intent";
  const auto refused = fixture.fabric().ReportIncident(different);
  ISF_REQUIRE(!refused.ok());
  ISF_CHECK_EQ(refused.status().code(), isf::ErrorCode::IdempotencyConflict);

  isf::RejectReportRequest other_kind;
  other_kind.header = request.header;
  other_kind.incident = isf::IncidentId{1};
  other_kind.expected_revision = 1;
  other_kind.rationale = "different operation entirely";
  ISF_EXPECT_ERROR(fixture.fabric().RejectReport(other_kind),
                   isf::ErrorCode::IdempotencyConflict);
}

ISF_TEST(Idempotency, AKeyIsRequired) {
  Fixture fixture("idem-required", isf::StateDigestPolicy::EveryCommit);
  isf::ReportIncidentRequest request = Report(1, "event-c");
  request.header.key = isf::IdempotencyKey{};
  request.header.actor.authority = fixture.operator_role;
  request.header.actor.epoch = fixture.Epoch();
  ISF_EXPECT_ERROR(fixture.fabric().ReportIncident(request), isf::ErrorCode::InvalidArgument);
}

ISF_TEST(Idempotency, ReplayOutranksStalePreconditions) {
  Fixture fixture("idem-stale", isf::StateDigestPolicy::EveryCommit);
  isf::ReportIncidentRequest request = Report(31337, "event-d");
  request.header.actor.authority = fixture.operator_role;
  request.header.actor.epoch = fixture.Epoch();
  const auto first = fixture.fabric().ReportIncident(request);
  ISF_REQUIRE(first.ok());

  // Advance the control epoch so that the original request is stale by fencing.
  isf::ForceFenceRequest fence;
  fence.header = fixture.Header(fixture.director);
  fence.rationale = "fence everyone";
  ISF_REQUIRE(fixture.fabric().ForceFence(fence).ok());
  ISF_CHECK(fixture.Epoch().value != request.header.actor.epoch.value);

  // The lost response is retried with the old epoch. It is demonstrably the same
  // already-committed operation, so it replays rather than being rejected.
  const auto replay = fixture.fabric().ReportIncident(request);
  ISF_REQUIRE(replay.ok());
  ISF_CHECK(replay.value().replayed);
  ISF_CHECK_EQ(replay.value().generation, first.value().generation);
}

ISF_TEST(Idempotency, ReplaySurvivesARestartAndAFencingChange) {
  Fixture fixture("idem-restart", isf::StateDigestPolicy::EveryCommit);
  isf::ReportIncidentRequest request = Report(9001, "event-e");
  request.header.actor.authority = fixture.operator_role;
  request.header.actor.epoch = fixture.Epoch();
  const auto first = fixture.fabric().ReportIncident(request);
  ISF_REQUIRE(first.ok());

  isf::ForceFenceRequest fence;
  fence.header = fixture.Header(fixture.director);
  fence.rationale = "fence before restart";
  ISF_REQUIRE(fixture.fabric().ForceFence(fence).ok());
  fixture.Restart();
  ISF_CHECK(fixture.Epoch().value != request.header.actor.epoch.value);
  const auto replay = fixture.fabric().ReportIncident(request);
  ISF_REQUIRE(replay.ok());
  ISF_CHECK(replay.value().replayed);
  ISF_CHECK_EQ(replay.value().generation, first.value().generation);
  ISF_CHECK_EQ(replay.value().incident, first.value().incident);
}

ISF_TEST(Idempotency, ReplayedReceiptsMatchTheOriginalExactly) {
  Fixture fixture("idem-receipt", isf::StateDigestPolicy::EveryCommit);
  isf::ReportIncidentRequest request = Report(2024, "event-f");
  request.header.actor.authority = fixture.operator_role;
  request.header.actor.epoch = fixture.Epoch();
  const auto first = fixture.fabric().ReportIncident(request);
  ISF_REQUIRE(first.ok());
  fixture.Restart();
  const auto replay = fixture.fabric().ReportIncident(request);
  ISF_REQUIRE(replay.ok());

  const isf::CommitReceipt& a = first.value();
  const isf::CommitReceipt& b = replay.value();
  ISF_CHECK_EQ(a.generation, b.generation);
  ISF_CHECK_EQ(a.op, b.op);
  ISF_CHECK_EQ(a.incident, b.incident);
  ISF_CHECK_EQ(a.incident_revision, b.incident_revision);
  ISF_CHECK_EQ(a.evidence, b.evidence);
  ISF_CHECK_EQ(a.authority, b.authority);
  ISF_CHECK_EQ(a.key, b.key);
  ISF_CHECK_EQ(a.created_incident, b.created_incident);
  ISF_CHECK(!a.replayed);
  ISF_CHECK(b.replayed);
}

ISF_TEST(Idempotency, PreviewAndCommitAgreeOnReplay) {
  Fixture fixture("idem-preview", isf::StateDigestPolicy::EveryCommit);
  isf::ReportIncidentRequest request = Report(555, "event-g");
  request.header.actor.authority = fixture.operator_role;
  request.header.actor.epoch = fixture.Epoch();

  const auto preview_before = fixture.fabric().Preview(isf::AnyRequest{request});
  ISF_REQUIRE(preview_before.ok());
  ISF_CHECK(preview_before.value().would_commit);
  ISF_CHECK(!preview_before.value().replayed);

  ISF_REQUIRE(fixture.fabric().ReportIncident(request).ok());

  const auto preview_after = fixture.fabric().Preview(isf::AnyRequest{request});
  ISF_REQUIRE(preview_after.ok());
  ISF_CHECK(preview_after.value().would_commit);
  ISF_CHECK(preview_after.value().replayed);

  const auto committed = fixture.fabric().ReportIncident(request);
  ISF_REQUIRE(committed.ok());
  ISF_CHECK(committed.value().replayed);
}

ISF_TEST(Idempotency, APreviewNeverMutatesTheStore) {
  Fixture fixture("idem-preview-pure", isf::StateDigestPolicy::EveryCommit);
  const auto before = fixture.fabric().GetStatus();
  ISF_REQUIRE(before.ok());

  isf::ReportIncidentRequest request = Report(8080, "event-h");
  request.header.actor.authority = fixture.operator_role;
  request.header.actor.epoch = fixture.Epoch();
  for (int attempt = 0; attempt < 10; ++attempt) {
    const auto preview = fixture.fabric().Preview(isf::AnyRequest{request});
    ISF_REQUIRE(preview.ok());
    ISF_CHECK(preview.value().would_commit);
  }

  const auto after = fixture.fabric().GetStatus();
  ISF_REQUIRE(after.ok());
  ISF_CHECK_EQ(after.value().generation, before.value().generation);
  ISF_CHECK_EQ(after.value().incident_count, std::uint64_t{0});

  // A preview of a doomed request reports the denial the commit will produce.
  request.header.actor.epoch = isf::ControlEpoch{9999};
  const auto doomed = fixture.fabric().Preview(isf::AnyRequest{request});
  ISF_REQUIRE(doomed.ok());
  ISF_CHECK(!doomed.value().would_commit);
  ISF_CHECK_EQ(doomed.value().code, isf::ErrorCode::StaleControlEpoch);
  ISF_EXPECT_ERROR(fixture.fabric().ReportIncident(request), isf::ErrorCode::StaleControlEpoch);
}

ISF_TEST(Idempotency, ReplayingACommittedCloseDoesNotReopenOrReclose) {
  Fixture fixture("idem-close", isf::StateDigestPolicy::EveryCommit);
  const auto accepted = isftest::AcceptFreshIncident(fixture, isf::IncidentClass::PhysicalSecurity,
                                                     isf::Severity::Minor, "close replay",
                                                     "rack-q9");
  const isf::IncidentId incident = accepted.id;
  const isf::EvidenceId containment = isftest::RecordEvidence(
      fixture, incident, RevisionOf(fixture.fabric(), incident), isf::EvidenceKind::ContainmentProof,
      isf::Severity::Unclassified, "secured");
  isf::DeclareContainedRequest contained;
  contained.header = fixture.Header(fixture.commander);
  contained.incident = incident;
  contained.expected_revision = RevisionOf(fixture.fabric(), incident);
  contained.proof = containment;
  contained.rationale = "secured";
  ISF_REQUIRE(fixture.fabric().DeclareContained(contained).ok());
  const isf::EvidenceId cleared = isftest::RecordEvidence(
      fixture, incident, RevisionOf(fixture.fabric(), incident), isf::EvidenceKind::EffectCleared,
      isf::Severity::Unclassified, "clear");
  isf::ResolveIncidentRequest resolve;
  resolve.header = fixture.Header(fixture.manager);
  resolve.incident = incident;
  resolve.expected_revision = RevisionOf(fixture.fabric(), incident);
  resolve.clearance = cleared;
  resolve.rationale = "resolved";
  ISF_REQUIRE(fixture.fabric().ResolveIncident(resolve).ok());
  const isf::EvidenceId attestation = isftest::RecordEvidence(
      fixture, incident, RevisionOf(fixture.fabric(), incident),
      isf::EvidenceKind::ClosureAttestation, isf::Severity::Unclassified, "attested");
  isf::CloseIncidentRequest close;
  close.header = fixture.Header(fixture.manager);
  close.incident = incident;
  close.expected_revision = RevisionOf(fixture.fabric(), incident);
  close.attestation = attestation;
  close.rationale = "closed";
  const auto first = fixture.fabric().CloseIncident(close);
  ISF_REQUIRE(first.ok());

  const auto retry = fixture.fabric().CloseIncident(close);
  ISF_REQUIRE(retry.ok());
  ISF_CHECK(retry.value().replayed);
  ISF_CHECK_EQ(IncidentOf(fixture.fabric(), incident).state, isf::LifecycleState::Closed);
  ISF_CHECK_EQ(IncidentOf(fixture.fabric(), incident).revision, first.value().incident_revision);
}
