// Incident State Fabric - DCCP boundary 50
// Copyright 2026 Summon Software Labs.
// Licensed under the Apache License, Version 2.0.

#include <string>

#include "isf/isf.h"
#include "test_framework.h"
#include "test_support.h"

using isftest::AcceptFreshIncident;
using isftest::DenialSays;
using isftest::Fixture;
using isftest::IncidentOf;
using isftest::Key;
using isftest::RackScope;
using isftest::RecordEvidence;
using isftest::ReportIncident;
using isftest::RevisionOf;

namespace {

/// Drives a Power incident from Reported to Closed through the documented
/// evidence gates and returns its identifier.
[[nodiscard]] isf::IncidentId ClosePowerIncident(Fixture& fixture, const std::string& rack) {
  const auto accepted = AcceptFreshIncident(fixture, isf::IncidentClass::Power,
                                            isf::Severity::Major, "power loss in " + rack, rack);
  const isf::IncidentId incident = accepted.id;

  const isf::EvidenceId containment = RecordEvidence(
      fixture, incident, RevisionOf(fixture.fabric(), incident), isf::EvidenceKind::ContainmentProof,
      isf::Severity::Unclassified, "containment verified at the rack");

  isf::DeclareContainedRequest contained;
  contained.header = fixture.Header(fixture.commander);
  contained.incident = incident;
  contained.expected_revision = RevisionOf(fixture.fabric(), incident);
  contained.proof = containment;
  contained.rationale = "containment verified";
  ISF_MUST(fixture.fabric().DeclareContained(contained));

  isf::StartRecoveryRequest recovery;
  recovery.header = fixture.Header(fixture.commander);
  recovery.incident = incident;
  recovery.expected_revision = RevisionOf(fixture.fabric(), incident);
  recovery.rationale = "recovery authorised";
  ISF_MUST(fixture.fabric().StartRecovery(recovery));

  const isf::EvidenceId proof = RecordEvidence(
      fixture, incident, RevisionOf(fixture.fabric(), incident), isf::EvidenceKind::RecoveryProof,
      isf::Severity::Unclassified, "all affected racks report healthy");

  isf::DeclareRecoveredRequest recovered;
  recovered.header = fixture.Header(fixture.commander);
  recovered.incident = incident;
  recovered.expected_revision = RevisionOf(fixture.fabric(), incident);
  recovered.proof = proof;
  recovered.rationale = "recovery proven";
  ISF_MUST(fixture.fabric().DeclareRecovered(recovered));

  const isf::EvidenceId cleared = RecordEvidence(
      fixture, incident, RevisionOf(fixture.fabric(), incident), isf::EvidenceKind::EffectCleared,
      isf::Severity::Unclassified, "effect no longer observed");

  isf::ResolveIncidentRequest resolve;
  resolve.header = fixture.Header(fixture.manager);
  resolve.incident = incident;
  resolve.expected_revision = RevisionOf(fixture.fabric(), incident);
  resolve.clearance = cleared;
  resolve.rationale = "effect cleared";
  ISF_MUST(fixture.fabric().ResolveIncident(resolve));

  const isf::EvidenceId attestation = RecordEvidence(
      fixture, incident, RevisionOf(fixture.fabric(), incident),
      isf::EvidenceKind::ClosureAttestation, isf::Severity::Unclassified,
      "facility director attests closure");

  isf::CloseIncidentRequest close;
  close.header = fixture.Header(fixture.director);
  close.incident = incident;
  close.expected_revision = RevisionOf(fixture.fabric(), incident);
  close.attestation = attestation;
  close.rationale = "closure attested";
  ISF_MUST(fixture.fabric().CloseIncident(close));
  return incident;
}

}  // namespace

ISF_TEST(Lifecycle, FullPowerLifecycleReachesClosed) {
  Fixture fixture("life-full", isf::StateDigestPolicy::EveryCommit);
  const isf::IncidentId incident = ClosePowerIncident(fixture, "rack-a1");

  const isf::IncidentView view = IncidentOf(fixture.fabric(), incident);
  ISF_CHECK_EQ(view.state, isf::LifecycleState::Closed);
  ISF_CHECK_EQ(view.cls, isf::IncidentClass::Power);
  ISF_CHECK_EQ(view.severity, isf::Severity::Major);
  ISF_CHECK_EQ(view.observation_generation, std::uint64_t{2});
  ISF_CHECK_EQ(view.attestation_generation, std::uint64_t{1});
  ISF_CHECK(view.recovery_started);
  ISF_CHECK(view.containment_declared);
  ISF_CHECK_EQ(view.owner, fixture.commander);
  ISF_CHECK_EQ(view.history.size(), std::size_t{7});

  // The recorded history is the authoritative narrative of the incident.
  const char* expected[] = {"AcceptIncident", "DeclareContained", "StartRecovery",
                            "DeclareRecovered", "ResolveIncident", "CloseIncident"};
  ISF_REQUIRE(view.history.size() >= 7);
  for (std::size_t index = 1; index < view.history.size(); ++index) {
    ISF_CHECK_EQ(std::string(isf::ToString(view.history[index].op)),
                 std::string(expected[index - 1]));
  }
}

ISF_TEST(Lifecycle, ReportIsNotAnAcceptedIncident) {
  Fixture fixture("life-report", isf::StateDigestPolicy::EveryCommit);
  const isf::IncidentId incident = ReportIncident(fixture, "unverified alarm", "rack-b2");
  const isf::IncidentView view = IncidentOf(fixture.fabric(), incident);
  ISF_CHECK_EQ(view.state, isf::LifecycleState::Reported);
  ISF_CHECK_EQ(view.cls, isf::IncidentClass::Power);
  ISF_CHECK_EQ(view.severity, isf::Severity::Major);
  ISF_CHECK_EQ(view.accepting_authority, isf::AuthorityId{});
  ISF_CHECK_EQ(view.history.size(), std::size_t{1});

  // Acceptance without a severity assessment from the severity authority fails.
  isf::AcceptIncidentRequest accept;
  accept.header = fixture.Header(fixture.commander);
  accept.incident = incident;
  accept.expected_revision = RevisionOf(fixture.fabric(), incident);
  accept.cls = isf::IncidentClass::Power;
  accept.severity = isf::Severity::Critical;
  accept.severity_evidence = isf::EvidenceId{};
  accept.rationale = "no evidence";
  ISF_EXPECT_ERROR(fixture.fabric().AcceptIncident(accept), isf::ErrorCode::InvalidArgument);
}

ISF_TEST(Lifecycle, AcceptanceRequiresMatchingSeverityEvidence) {
  Fixture fixture("life-severity", isf::StateDigestPolicy::EveryCommit);
  const isf::IncidentId incident = ReportIncident(fixture, "severity evidence", "rack-b3");
  const isf::EvidenceId minor = RecordEvidence(
      fixture, incident, RevisionOf(fixture.fabric(), incident),
      isf::EvidenceKind::SeverityAssessment, isf::Severity::Minor, "assessment says minor");

  isf::AcceptIncidentRequest accept;
  accept.header = fixture.Header(fixture.commander);
  accept.incident = incident;
  accept.expected_revision = RevisionOf(fixture.fabric(), incident);
  accept.cls = isf::IncidentClass::Power;
  accept.severity = isf::Severity::Catastrophic;
  accept.severity_evidence = minor;
  accept.rationale = "claiming catastrophic";
  const auto receipt = fixture.fabric().AcceptIncident(accept);
  ISF_REQUIRE(!receipt.ok());
  ISF_CHECK_EQ(receipt.status().code(), isf::ErrorCode::GateUnsatisfied);
  ISF_CHECK(DenialSays(receipt.status(), "asserts Minor but the request asserts Catastrophic"));
}

ISF_TEST(Lifecycle, DuplicateReportsAttachToTheLiveIncident) {
  Fixture fixture("life-duplicate", isf::StateDigestPolicy::EveryCommit);

  isf::ReportIncidentRequest first;
  first.header = fixture.Header(fixture.operator_role);
  first.cls = isf::IncidentClass::Power;
  first.reported_severity = isf::Severity::Major;
  first.summary = "same event";
  first.scope = RackScope("rack-c1");
  first.source_system = "synthetic-dcim";
  first.source_event_id = "event-77";
  const auto first_receipt = fixture.fabric().ReportIncident(first);
  ISF_REQUIRE(first_receipt.ok());
  ISF_CHECK(first_receipt.value().created_incident);

  isf::ReportIncidentRequest duplicate = first;
  duplicate.header = fixture.Header(fixture.operator_role);
  const auto second_receipt = fixture.fabric().ReportIncident(duplicate);
  ISF_REQUIRE(second_receipt.ok());
  ISF_CHECK(!second_receipt.value().created_incident);
  ISF_CHECK(second_receipt.value().duplicate_report);
  ISF_CHECK_EQ(second_receipt.value().incident, first_receipt.value().incident);

  const isf::IncidentView view = IncidentOf(fixture.fabric(), first_receipt.value().incident);
  ISF_CHECK_EQ(view.state, isf::LifecycleState::Reported);
  ISF_CHECK_EQ(view.revision, std::uint64_t{2});

  const auto evidence = fixture.fabric().ListEvidence(view.id, isf::ListQuery{0, 100});
  ISF_REQUIRE(evidence.ok());
  ISF_CHECK_EQ(evidence.value().size(), std::size_t{2});
  ISF_CHECK_EQ(evidence.value()[0].kind, isf::EvidenceKind::Report);
  ISF_CHECK_EQ(evidence.value()[1].kind, isf::EvidenceKind::Report);
  ISF_CHECK(evidence.value()[0].source_event_id == "event-77");
}

ISF_TEST(Lifecycle, ReportWithNoSourceIdentityIsNeverDeduplicated) {
  Fixture fixture("life-nodedup", isf::StateDigestPolicy::EveryCommit);
  isf::ReportIncidentRequest request;
  request.header = fixture.Header(fixture.operator_role);
  request.cls = isf::IncidentClass::Cooling;
  request.reported_severity = isf::Severity::Minor;
  request.summary = "anonymous report";
  request.scope = RackScope("rack-c2");
  const auto first = fixture.fabric().ReportIncident(request);
  ISF_REQUIRE(first.ok());
  request.header = fixture.Header(fixture.operator_role);
  const auto second = fixture.fabric().ReportIncident(request);
  ISF_REQUIRE(second.ok());
  ISF_CHECK(second.value().created_incident);
  ISF_CHECK(first.value().incident != second.value().incident);
}

ISF_TEST(Lifecycle, ClosedIncidentDoesNotAbsorbDuplicateReports) {
  Fixture fixture("life-dedup-terminal", isf::StateDigestPolicy::EveryCommit);

  isf::ReportIncidentRequest request;
  request.header = fixture.Header(fixture.operator_role);
  request.cls = isf::IncidentClass::Power;
  request.reported_severity = isf::Severity::Minor;
  request.summary = "recurring event";
  request.scope = RackScope("rack-c3");
  request.source_system = "synthetic-dcim";
  request.source_event_id = "event-99";
  const auto first = fixture.fabric().ReportIncident(request);
  ISF_REQUIRE(first.ok());

  isf::RejectReportRequest reject;
  reject.header = fixture.Header(fixture.manager);
  reject.incident = first.value().incident;
  reject.expected_revision = RevisionOf(fixture.fabric(), first.value().incident);
  reject.rationale = "not a real incident";
  ISF_REQUIRE(fixture.fabric().RejectReport(reject).ok());

  request.header = fixture.Header(fixture.operator_role);
  const auto second = fixture.fabric().ReportIncident(request);
  ISF_REQUIRE(second.ok());
  ISF_CHECK(second.value().created_incident);
  ISF_CHECK(second.value().incident != first.value().incident);
}

ISF_TEST(Lifecycle, IllegalTransitionsAreRefused) {
  Fixture fixture("life-illegal", isf::StateDigestPolicy::EveryCommit);
  const auto accepted = AcceptFreshIncident(fixture, isf::IncidentClass::Power,
                                            isf::Severity::Major, "illegal transitions", "rack-d1");
  const isf::IncidentId incident = accepted.id;

  isf::AcceptIncidentRequest accept_again;
  accept_again.header = fixture.Header(fixture.commander);
  accept_again.incident = incident;
  accept_again.expected_revision = RevisionOf(fixture.fabric(), incident);
  accept_again.cls = isf::IncidentClass::Power;
  accept_again.severity = isf::Severity::Major;
  accept_again.severity_evidence = isf::EvidenceId{1};
  accept_again.rationale = "accept twice";
  ISF_EXPECT_ERROR(fixture.fabric().AcceptIncident(accept_again),
                   isf::ErrorCode::IllegalTransition);

  isf::StartRecoveryRequest early;
  early.header = fixture.Header(fixture.commander);
  early.incident = incident;
  early.expected_revision = RevisionOf(fixture.fabric(), incident);
  early.rationale = "recovery before containment";
  ISF_EXPECT_ERROR(fixture.fabric().StartRecovery(early), isf::ErrorCode::IllegalTransition);

  isf::ResolveIncidentRequest resolve;
  resolve.header = fixture.Header(fixture.manager);
  resolve.incident = incident;
  resolve.expected_revision = RevisionOf(fixture.fabric(), incident);
  resolve.clearance = isf::EvidenceId{1};
  resolve.rationale = "resolve before containment";
  const auto refused = fixture.fabric().ResolveIncident(resolve);
  ISF_REQUIRE(!refused.ok());
  ISF_CHECK_EQ(refused.status().code(), isf::ErrorCode::GateUnsatisfied);
  ISF_CHECK(DenialSays(refused.status(), "cannot be resolved before containment is proven"));

  isf::CloseIncidentRequest close;
  close.header = fixture.Header(fixture.director);
  close.incident = incident;
  close.expected_revision = RevisionOf(fixture.fabric(), incident);
  close.attestation = isf::EvidenceId{1};
  close.rationale = "close an accepted incident";
  ISF_EXPECT_ERROR(fixture.fabric().CloseIncident(close), isf::ErrorCode::IllegalTransition);

  isf::RejectReportRequest reject;
  reject.header = fixture.Header(fixture.manager);
  reject.incident = incident;
  reject.expected_revision = RevisionOf(fixture.fabric(), incident);
  reject.rationale = "reject an accepted incident";
  ISF_EXPECT_ERROR(fixture.fabric().RejectReport(reject), isf::ErrorCode::IllegalTransition);
}

ISF_TEST(Lifecycle, OwnerHandoffAndScopeAmendmentAreAudited) {
  Fixture fixture("life-owner", isf::StateDigestPolicy::EveryCommit);
  const auto accepted = AcceptFreshIncident(fixture, isf::IncidentClass::Cooling,
                                            isf::Severity::Major, "owner handoff", "rack-e1");
  const isf::IncidentId incident = accepted.id;

  isf::AssignOwnerRequest assign;
  assign.header = fixture.Header(fixture.commander);
  assign.incident = incident;
  assign.expected_revision = RevisionOf(fixture.fabric(), incident);
  assign.owner = fixture.manager;
  assign.rationale = "shift handover";
  ISF_REQUIRE(fixture.fabric().AssignOwner(assign).ok());
  ISF_CHECK_EQ(IncidentOf(fixture.fabric(), incident).owner, fixture.manager);

  assign.header = fixture.Header(fixture.commander);
  assign.expected_revision = RevisionOf(fixture.fabric(), incident);
  assign.rationale = "no-op handover";
  ISF_EXPECT_ERROR(fixture.fabric().AssignOwner(assign), isf::ErrorCode::Conflict);

  isf::AmendScopeRequest scope;
  scope.header = fixture.Header(fixture.commander);
  scope.incident = incident;
  scope.expected_revision = RevisionOf(fixture.fabric(), incident);
  scope.scope = isftest::TwoRackScope("rack-e1", "rack-e2");
  scope.rationale = "blast radius grew";
  ISF_REQUIRE(fixture.fabric().AmendScope(scope).ok());
  const isf::IncidentView view = IncidentOf(fixture.fabric(), incident);
  ISF_CHECK_EQ(view.scope.objects.size(), std::size_t{2});

  scope.header = fixture.Header(fixture.commander);
  scope.expected_revision = RevisionOf(fixture.fabric(), incident);
  ISF_EXPECT_ERROR(fixture.fabric().AmendScope(scope), isf::ErrorCode::Conflict);
}

ISF_TEST(Lifecycle, EscalationAndConstrainedDeescalation) {
  Fixture fixture("life-severity-change", isf::StateDigestPolicy::EveryCommit);
  const auto accepted = AcceptFreshIncident(fixture, isf::IncidentClass::Power,
                                            isf::Severity::Major, "severity movement", "rack-f1");
  const isf::IncidentId incident = accepted.id;

  // Escalation needs one assessment from the severity authority.
  const isf::EvidenceId critical = RecordEvidence(
      fixture, incident, RevisionOf(fixture.fabric(), incident),
      isf::EvidenceKind::SeverityAssessment, isf::Severity::Critical, "condition worsened");
  isf::AmendSeverityRequest escalate;
  escalate.header = fixture.Header(fixture.commander);
  escalate.incident = incident;
  escalate.expected_revision = RevisionOf(fixture.fabric(), incident);
  escalate.severity = isf::Severity::Critical;
  escalate.supporting_evidence = {critical};
  escalate.rationale = "escalate";
  ISF_REQUIRE(fixture.fabric().AmendSeverity(escalate).ok());
  ISF_CHECK_EQ(IncidentOf(fixture.fabric(), incident).severity, isf::Severity::Critical);

  // De-escalation immediately after escalation is refused by the quiet window.
  const isf::EvidenceId minor_a = RecordEvidence(
      fixture, incident, RevisionOf(fixture.fabric(), incident),
      isf::EvidenceKind::SeverityAssessment, isf::Severity::Minor, "first confirmation");
  const isf::EvidenceId minor_b = isftest::RecordEvidenceWith(
      fixture, fixture.manager, incident, RevisionOf(fixture.fabric(), incident),
      isf::EvidenceKind::SeverityAssessment, isf::Severity::Minor, false, "second confirmation");
  isf::AmendSeverityRequest deescalate;
  deescalate.header = fixture.Header(fixture.manager);
  deescalate.incident = incident;
  deescalate.expected_revision = RevisionOf(fixture.fabric(), incident);
  deescalate.severity = isf::Severity::Minor;
  deescalate.supporting_evidence = {minor_a, minor_b};
  deescalate.rationale = "de-escalate too soon";
  const auto too_soon = fixture.fabric().AmendSeverity(deescalate);
  ISF_REQUIRE(!too_soon.ok());
  ISF_CHECK(DenialSays(too_soon.status(), "durable generations since the last escalation"));

  // A single confirmation is not enough no matter how long we wait.
  RecordEvidence(fixture, incident, RevisionOf(fixture.fabric(), incident),
                 isf::EvidenceKind::Acknowledgement, isf::Severity::Unclassified, "filler one");
  RecordEvidence(fixture, incident, RevisionOf(fixture.fabric(), incident),
                 isf::EvidenceKind::Acknowledgement, isf::Severity::Unclassified, "filler two");
  RecordEvidence(fixture, incident, RevisionOf(fixture.fabric(), incident),
                 isf::EvidenceKind::Acknowledgement, isf::Severity::Unclassified, "filler three");
  deescalate.header = fixture.Header(fixture.manager);
  deescalate.expected_revision = RevisionOf(fixture.fabric(), incident);
  deescalate.supporting_evidence = {minor_a};
  const auto too_few = fixture.fabric().AmendSeverity(deescalate);
  ISF_REQUIRE(!too_few.ok());
  ISF_CHECK(DenialSays(too_few.status(), "at least 2 distinct authorities"));

  // The same authority confirming twice is one authority.
  const isf::EvidenceId minor_c = RecordEvidence(
      fixture, incident, RevisionOf(fixture.fabric(), incident),
      isf::EvidenceKind::SeverityAssessment, isf::Severity::Minor, "same authority again");
  deescalate.header = fixture.Header(fixture.manager);
  deescalate.expected_revision = RevisionOf(fixture.fabric(), incident);
  deescalate.supporting_evidence = {minor_a, minor_c};
  const auto same_authority = fixture.fabric().AmendSeverity(deescalate);
  ISF_REQUIRE(!same_authority.ok());
  ISF_CHECK(DenialSays(same_authority.status(), "at least 2 distinct authorities"));

  // With the quiet window satisfied and two distinct authorities it succeeds.
  for (int index = 0; index < 4; ++index) {
    RecordEvidence(fixture, incident, RevisionOf(fixture.fabric(), incident),
                   isf::EvidenceKind::Acknowledgement, isf::Severity::Unclassified,
                   "quiet period filler");
  }
  deescalate.header = fixture.Header(fixture.manager);
  deescalate.expected_revision = RevisionOf(fixture.fabric(), incident);
  deescalate.supporting_evidence = {minor_a, minor_b};
  ISF_REQUIRE(fixture.fabric().AmendSeverity(deescalate).ok());
  ISF_CHECK_EQ(IncidentOf(fixture.fabric(), incident).severity, isf::Severity::Minor);
}

ISF_TEST(Lifecycle, MergeAbsorbsAndUnionsScope) {
  Fixture fixture("life-merge", isf::StateDigestPolicy::EveryCommit);
  const auto survivor = AcceptFreshIncident(fixture, isf::IncidentClass::Cooling,
                                            isf::Severity::Major, "cooling survivor", "rack-g1");
  const auto absorbed = AcceptFreshIncident(fixture, isf::IncidentClass::Cooling,
                                            isf::Severity::Minor, "cooling duplicate", "rack-g2");

  isf::MergeIncidentRequest merge;
  merge.header = fixture.Header(fixture.director);
  merge.survivor = survivor.id;
  merge.expected_survivor_revision = RevisionOf(fixture.fabric(), survivor.id);
  merge.absorbed = absorbed.id;
  merge.expected_absorbed_revision = RevisionOf(fixture.fabric(), absorbed.id);
  merge.rationale = "one incident";
  ISF_REQUIRE(fixture.fabric().MergeIncident(merge).ok());

  const isf::IncidentView survivor_view = IncidentOf(fixture.fabric(), survivor.id);
  const isf::IncidentView absorbed_view = IncidentOf(fixture.fabric(), absorbed.id);
  ISF_CHECK_EQ(absorbed_view.state, isf::LifecycleState::Superseded);
  ISF_CHECK_EQ(absorbed_view.parent, survivor.id);
  ISF_CHECK_EQ(survivor_view.state, isf::LifecycleState::Accepted);
  ISF_CHECK_EQ(survivor_view.scope.objects.size(), std::size_t{2});

  const auto lineage = fixture.fabric().GetLineage(survivor.id);
  ISF_REQUIRE(lineage.ok());
  ISF_CHECK_EQ(lineage.value().merged_children.size(), std::size_t{1});
  ISF_CHECK_EQ(lineage.value().merged_children[0].id, absorbed.id);
}

ISF_TEST(Lifecycle, CrossClassMergeNeedsAnExplicitOverride) {
  Fixture fixture("life-merge-class", isf::StateDigestPolicy::EveryCommit);
  const auto power = AcceptFreshIncident(fixture, isf::IncidentClass::Power, isf::Severity::Major,
                                         "power incident", "rack-h1");
  const auto cooling = AcceptFreshIncident(fixture, isf::IncidentClass::Cooling,
                                           isf::Severity::Major, "cooling incident", "rack-h2");

  isf::MergeIncidentRequest merge;
  merge.header = fixture.Header(fixture.director);
  merge.survivor = power.id;
  merge.expected_survivor_revision = RevisionOf(fixture.fabric(), power.id);
  merge.absorbed = cooling.id;
  merge.expected_absorbed_revision = RevisionOf(fixture.fabric(), cooling.id);
  merge.rationale = "cross class";
  const auto refused = fixture.fabric().MergeIncident(merge);
  ISF_REQUIRE(!refused.ok());
  ISF_CHECK(DenialSays(refused.status(), "cross-class override"));

  merge.header = fixture.Header(fixture.director);
  merge.expected_survivor_revision = RevisionOf(fixture.fabric(), power.id);
  merge.expected_absorbed_revision = RevisionOf(fixture.fabric(), cooling.id);
  merge.allow_cross_class = true;
  ISF_REQUIRE(fixture.fabric().MergeIncident(merge).ok());

  merge.header = fixture.Header(fixture.director);
  merge.survivor = cooling.id;
  merge.absorbed = power.id;
  merge.expected_survivor_revision = RevisionOf(fixture.fabric(), cooling.id);
  merge.expected_absorbed_revision = RevisionOf(fixture.fabric(), power.id);
  merge.allow_cross_class = true;
  ISF_EXPECT_ERROR(fixture.fabric().MergeIncident(merge), isf::ErrorCode::GateUnsatisfied);
}

ISF_TEST(Lifecycle, SuccessorCarriesLineageAndLeavesThePredecessorIntact) {
  Fixture fixture("life-successor", isf::StateDigestPolicy::EveryCommit);
  const isf::IncidentId first = ClosePowerIncident(fixture, "rack-i1");
  const isf::IncidentView closed_view = IncidentOf(fixture.fabric(), first);
  ISF_CHECK_EQ(closed_view.state, isf::LifecycleState::Closed);

  isf::CreateSuccessorRequest successor;
  successor.header = fixture.Header(fixture.director);
  successor.predecessor = first;
  successor.expected_predecessor_revision = RevisionOf(fixture.fabric(), first);
  successor.cls = isf::IncidentClass::Power;
  successor.reported_severity = isf::Severity::Major;
  successor.summary = "recurrence";
  successor.scope = RackScope("rack-i1");
  successor.source_system = "synthetic-dcim";
  successor.source_event_id = "event-successor";
  successor.rationale = "new incident with lineage";
  const auto receipt = fixture.fabric().CreateSuccessor(successor);
  ISF_REQUIRE(receipt.ok());
  ISF_CHECK(receipt.value().created_incident);

  const isf::IncidentView new_view = IncidentOf(fixture.fabric(), receipt.value().incident);
  ISF_CHECK_EQ(new_view.state, isf::LifecycleState::Reported);
  ISF_CHECK_EQ(new_view.predecessor, first);
  ISF_CHECK_EQ(IncidentOf(fixture.fabric(), first).state, isf::LifecycleState::Closed);

  const auto lineage = fixture.fabric().GetLineage(receipt.value().incident);
  ISF_REQUIRE(lineage.ok());
  ISF_CHECK_EQ(lineage.value().predecessors.size(), std::size_t{1});
  ISF_CHECK_EQ(lineage.value().predecessors[0].id, first);
}
