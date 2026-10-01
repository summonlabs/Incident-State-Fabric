// Incident State Fabric - DCCP boundary 50
// Copyright 2026 Summon Software Labs.
// Licensed under the Apache License, Version 2.0.
//
// These are the proofs that the fabric keeps distinct facts distinct.

#include <string>

#include "isf/isf.h"
#include "test_framework.h"
#include "test_support.h"

using isftest::AcceptFreshIncident;
using isftest::DenialSays;
using isftest::Fixture;
using isftest::IncidentOf;
using isftest::RackScope;
using isftest::RecordEvidence;
using isftest::RevisionOf;

namespace {

[[nodiscard]] isf::IncidentId BringToContained(Fixture& fixture, const std::string& rack) {
  const auto accepted = AcceptFreshIncident(fixture, isf::IncidentClass::Power,
                                            isf::Severity::Major, "gated incident " + rack, rack);
  const isf::IncidentId incident = accepted.id;
  const isf::EvidenceId proof = RecordEvidence(
      fixture, incident, RevisionOf(fixture.fabric(), incident), isf::EvidenceKind::ContainmentProof,
      isf::Severity::Unclassified, "containment verified");
  isf::DeclareContainedRequest contained;
  contained.header = fixture.Header(fixture.commander);
  contained.incident = incident;
  contained.expected_revision = RevisionOf(fixture.fabric(), incident);
  contained.proof = proof;
  contained.rationale = "contained";
  if (!fixture.fabric().DeclareContained(contained).ok()) return isf::IncidentId{};
  return incident;
}

}  // namespace

ISF_TEST(Gates, AcknowledgementIsNotContainment) {
  Fixture fixture("gate-ack", isf::StateDigestPolicy::EveryCommit);
  const auto accepted = AcceptFreshIncident(fixture, isf::IncidentClass::Power,
                                            isf::Severity::Major, "ack only", "rack-j1");
  const isf::IncidentId incident = accepted.id;
  const isf::EvidenceId acknowledgement = RecordEvidence(
      fixture, incident, RevisionOf(fixture.fabric(), incident),
      isf::EvidenceKind::Acknowledgement, isf::Severity::Unclassified, "operator acknowledged");

  isf::DeclareContainedRequest contained;
  contained.header = fixture.Header(fixture.commander);
  contained.incident = incident;
  contained.expected_revision = RevisionOf(fixture.fabric(), incident);
  contained.proof = acknowledgement;
  contained.rationale = "acknowledged so contained";
  const auto refused = fixture.fabric().DeclareContained(contained);
  ISF_REQUIRE(!refused.ok());
  ISF_CHECK_EQ(refused.status().code(), isf::ErrorCode::GateUnsatisfied);
  ISF_CHECK(DenialSays(refused.status(), "is Acknowledgement, not ContainmentProof"));
}

ISF_TEST(Gates, MissingContainmentNamesTheConfusion) {
  Fixture fixture("gate-ack-missing", isf::StateDigestPolicy::EveryCommit);
  const auto accepted = AcceptFreshIncident(fixture, isf::IncidentClass::Power,
                                            isf::Severity::Major, "ack only two", "rack-j2");
  const isf::IncidentId incident = accepted.id;
  RecordEvidence(fixture, incident, RevisionOf(fixture.fabric(), incident),
                 isf::EvidenceKind::Acknowledgement, isf::Severity::Unclassified, "acknowledged");

  isf::DeclareContainedRequest contained;
  contained.header = fixture.Header(fixture.commander);
  contained.incident = incident;
  contained.expected_revision = RevisionOf(fixture.fabric(), incident);
  contained.proof = isf::EvidenceId{};
  contained.rationale = "no proof at all";
  const auto refused = fixture.fabric().DeclareContained(contained);
  ISF_REQUIRE(!refused.ok());
  ISF_CHECK(DenialSays(refused.status(), "acknowledging a report is not containment"));
}

ISF_TEST(Gates, AlarmSilenceIsNotClearance) {
  Fixture fixture("gate-alarm", isf::StateDigestPolicy::EveryCommit);
  const isf::IncidentId incident = BringToContained(fixture, "rack-k1");
  ISF_REQUIRE(incident.valid());

  RecordEvidence(fixture, incident, RevisionOf(fixture.fabric(), incident),
                 isf::EvidenceKind::AlarmSilence, isf::Severity::Unclassified,
                 "no alarms for thirty minutes");

  isf::ResolveIncidentRequest resolve;
  resolve.header = fixture.Header(fixture.manager);
  resolve.incident = incident;
  resolve.expected_revision = RevisionOf(fixture.fabric(), incident);
  resolve.clearance = isf::EvidenceId{};
  resolve.rationale = "alarms are quiet";
  const auto refused = fixture.fabric().ResolveIncident(resolve);
  ISF_REQUIRE(!refused.ok());
  ISF_CHECK_EQ(refused.status().code(), isf::ErrorCode::GateUnsatisfied);
  ISF_CHECK(DenialSays(refused.status(), "quiescent alarms are not evidence that the effect cleared"));

  ISF_CHECK_EQ(IncidentOf(fixture.fabric(), incident).state, isf::LifecycleState::Contained);
}

ISF_TEST(Gates, RequestedMitigationIsNotAnObservedEffect) {
  Fixture fixture("gate-mitigation", isf::StateDigestPolicy::EveryCommit);
  const isf::IncidentId incident = BringToContained(fixture, "rack-k2");
  ISF_REQUIRE(incident.valid());
  RecordEvidence(fixture, incident, RevisionOf(fixture.fabric(), incident),
                 isf::EvidenceKind::MitigationRequest, isf::Severity::Unclassified,
                 "please transfer the workload");

  isf::ResolveIncidentRequest resolve;
  resolve.header = fixture.Header(fixture.manager);
  resolve.incident = incident;
  resolve.expected_revision = RevisionOf(fixture.fabric(), incident);
  resolve.clearance = isf::EvidenceId{};
  resolve.rationale = "mitigation requested";
  const auto refused = fixture.fabric().ResolveIncident(resolve);
  ISF_REQUIRE(!refused.ok());
  ISF_CHECK(DenialSays(refused.status(), "a requested mitigation is not an observed effect"));
}

ISF_TEST(Gates, RecoveryStartedIsNotRecoveryProven) {
  Fixture fixture("gate-recovery", isf::StateDigestPolicy::EveryCommit);
  const isf::IncidentId incident = BringToContained(fixture, "rack-k3");
  ISF_REQUIRE(incident.valid());

  isf::StartRecoveryRequest recovery;
  recovery.header = fixture.Header(fixture.commander);
  recovery.incident = incident;
  recovery.expected_revision = RevisionOf(fixture.fabric(), incident);
  recovery.rationale = "recovery authorised";
  ISF_REQUIRE(fixture.fabric().StartRecovery(recovery).ok());

  isf::DeclareRecoveredRequest recovered;
  recovered.header = fixture.Header(fixture.commander);
  recovered.incident = incident;
  recovered.expected_revision = RevisionOf(fixture.fabric(), incident);
  recovered.proof = isf::EvidenceId{};
  recovered.rationale = "we started recovery so it is proven";
  const auto refused = fixture.fabric().DeclareRecovered(recovered);
  ISF_REQUIRE(!refused.ok());
  ISF_CHECK(DenialSays(refused.status(), "starting recovery does not prove it"));

  ISF_CHECK_EQ(IncidentOf(fixture.fabric(), incident).state, isf::LifecycleState::Recovering);
}

ISF_TEST(Gates, ResolvedIsNotClosed) {
  Fixture fixture("gate-resolved", isf::StateDigestPolicy::EveryCommit);
  const auto accepted = AcceptFreshIncident(fixture, isf::IncidentClass::PhysicalSecurity,
                                            isf::Severity::Major, "security incident", "rack-l1");
  const isf::IncidentId incident = accepted.id;
  const isf::EvidenceId proof = RecordEvidence(
      fixture, incident, RevisionOf(fixture.fabric(), incident), isf::EvidenceKind::ContainmentProof,
      isf::Severity::Unclassified, "access path secured");
  isf::DeclareContainedRequest contained;
  contained.header = fixture.Header(fixture.commander);
  contained.incident = incident;
  contained.expected_revision = RevisionOf(fixture.fabric(), incident);
  contained.proof = proof;
  contained.rationale = "secured";
  ISF_REQUIRE(fixture.fabric().DeclareContained(contained).ok());

  const isf::EvidenceId cleared = RecordEvidence(
      fixture, incident, RevisionOf(fixture.fabric(), incident), isf::EvidenceKind::EffectCleared,
      isf::Severity::Unclassified, "no unauthorised access remains");
  isf::ResolveIncidentRequest resolve;
  resolve.header = fixture.Header(fixture.manager);
  resolve.incident = incident;
  resolve.expected_revision = RevisionOf(fixture.fabric(), incident);
  resolve.clearance = cleared;
  resolve.rationale = "resolved";
  ISF_REQUIRE(fixture.fabric().ResolveIncident(resolve).ok());
  ISF_CHECK_EQ(IncidentOf(fixture.fabric(), incident).state, isf::LifecycleState::Resolved);

  isf::CloseIncidentRequest close;
  close.header = fixture.Header(fixture.manager);
  close.incident = incident;
  close.expected_revision = RevisionOf(fixture.fabric(), incident);
  close.attestation = isf::EvidenceId{};
  close.rationale = "resolved means closed";
  const auto refused = fixture.fabric().CloseIncident(close);
  ISF_REQUIRE(!refused.ok());
  ISF_CHECK_EQ(refused.status().code(), isf::ErrorCode::GateUnsatisfied);
  ISF_CHECK(DenialSays(refused.status(), "ClosureAttestation"));
  ISF_CHECK_EQ(IncidentOf(fixture.fabric(), incident).state, isf::LifecycleState::Resolved);
}

ISF_TEST(Gates, ClosureAuthorityDependsOnTheIncidentClass) {
  Fixture fixture("gate-class-role", isf::StateDigestPolicy::EveryCommit);

  // A physical security incident may be closed by a duty manager.
  const auto security = AcceptFreshIncident(fixture, isf::IncidentClass::PhysicalSecurity,
                                            isf::Severity::Major, "security close", "rack-m1");
  const isf::IncidentId security_id = security.id;
  const isf::EvidenceId security_proof = RecordEvidence(
      fixture, security_id, RevisionOf(fixture.fabric(), security_id),
      isf::EvidenceKind::ContainmentProof, isf::Severity::Unclassified, "secured");
  isf::DeclareContainedRequest contained;
  contained.header = fixture.Header(fixture.commander);
  contained.incident = security_id;
  contained.expected_revision = RevisionOf(fixture.fabric(), security_id);
  contained.proof = security_proof;
  contained.rationale = "secured";
  ISF_REQUIRE(fixture.fabric().DeclareContained(contained).ok());
  const isf::EvidenceId security_cleared = RecordEvidence(
      fixture, security_id, RevisionOf(fixture.fabric(), security_id),
      isf::EvidenceKind::EffectCleared, isf::Severity::Unclassified, "clear");
  isf::ResolveIncidentRequest resolve;
  resolve.header = fixture.Header(fixture.manager);
  resolve.incident = security_id;
  resolve.expected_revision = RevisionOf(fixture.fabric(), security_id);
  resolve.clearance = security_cleared;
  resolve.rationale = "resolved";
  ISF_REQUIRE(fixture.fabric().ResolveIncident(resolve).ok());
  const isf::EvidenceId security_attestation = RecordEvidence(
      fixture, security_id, RevisionOf(fixture.fabric(), security_id),
      isf::EvidenceKind::ClosureAttestation, isf::Severity::Unclassified, "attested");
  isf::CloseIncidentRequest close;
  close.header = fixture.Header(fixture.manager);
  close.incident = security_id;
  close.expected_revision = RevisionOf(fixture.fabric(), security_id);
  close.attestation = security_attestation;
  close.rationale = "duty manager closes security";
  ISF_REQUIRE(fixture.fabric().CloseIncident(close).ok());

  // The same authority cannot close a power incident.
  const auto power = AcceptFreshIncident(fixture, isf::IncidentClass::Power,
                                         isf::Severity::Major, "power close", "rack-m2");
  const isf::IncidentId power_id = power.id;
  const isf::EvidenceId power_proof = RecordEvidence(
      fixture, power_id, RevisionOf(fixture.fabric(), power_id),
      isf::EvidenceKind::ContainmentProof, isf::Severity::Unclassified, "contained");
  contained.header = fixture.Header(fixture.commander);
  contained.incident = power_id;
  contained.expected_revision = RevisionOf(fixture.fabric(), power_id);
  contained.proof = power_proof;
  ISF_REQUIRE(fixture.fabric().DeclareContained(contained).ok());
  isf::StartRecoveryRequest recovery;
  recovery.header = fixture.Header(fixture.commander);
  recovery.incident = power_id;
  recovery.expected_revision = RevisionOf(fixture.fabric(), power_id);
  recovery.rationale = "recover";
  ISF_REQUIRE(fixture.fabric().StartRecovery(recovery).ok());
  const isf::EvidenceId power_recovery = RecordEvidence(
      fixture, power_id, RevisionOf(fixture.fabric(), power_id), isf::EvidenceKind::RecoveryProof,
      isf::Severity::Unclassified, "recovered");
  isf::DeclareRecoveredRequest recovered;
  recovered.header = fixture.Header(fixture.commander);
  recovered.incident = power_id;
  recovered.expected_revision = RevisionOf(fixture.fabric(), power_id);
  recovered.proof = power_recovery;
  recovered.rationale = "proven";
  ISF_REQUIRE(fixture.fabric().DeclareRecovered(recovered).ok());
  const isf::EvidenceId power_cleared = RecordEvidence(
      fixture, power_id, RevisionOf(fixture.fabric(), power_id),
      isf::EvidenceKind::EffectCleared, isf::Severity::Unclassified, "clear");
  resolve.header = fixture.Header(fixture.manager);
  resolve.incident = power_id;
  resolve.expected_revision = RevisionOf(fixture.fabric(), power_id);
  resolve.clearance = power_cleared;
  ISF_REQUIRE(fixture.fabric().ResolveIncident(resolve).ok());
  const isf::EvidenceId power_attestation = RecordEvidence(
      fixture, power_id, RevisionOf(fixture.fabric(), power_id),
      isf::EvidenceKind::ClosureAttestation, isf::Severity::Unclassified, "attested");
  close.header = fixture.Header(fixture.manager);
  close.incident = power_id;
  close.expected_revision = RevisionOf(fixture.fabric(), power_id);
  close.attestation = power_attestation;
  close.rationale = "duty manager attempts a power closure";
  ISF_EXPECT_ERROR(fixture.fabric().CloseIncident(close), isf::ErrorCode::Unauthorized);

  close.header = fixture.Header(fixture.director);
  close.expected_revision = RevisionOf(fixture.fabric(), power_id);
  ISF_REQUIRE(fixture.fabric().CloseIncident(close).ok());
}

ISF_TEST(Gates, ContradictingObservationBlocksResolution) {
  Fixture fixture("gate-contradiction", isf::StateDigestPolicy::EveryCommit);
  const isf::IncidentId incident = BringToContained(fixture, "rack-n1");
  ISF_REQUIRE(incident.valid());

  const isf::EvidenceId cleared = RecordEvidence(
      fixture, incident, RevisionOf(fixture.fabric(), incident), isf::EvidenceKind::EffectCleared,
      isf::Severity::Unclassified, "momentarily clear");
  isftest::RecordEvidenceWith(fixture, fixture.operator_role, incident,
                              RevisionOf(fixture.fabric(), incident),
                              isf::EvidenceKind::EffectObservation, isf::Severity::Unclassified,
                              true, "effect is present again");

  isf::ResolveIncidentRequest resolve;
  resolve.header = fixture.Header(fixture.manager);
  resolve.incident = incident;
  resolve.expected_revision = RevisionOf(fixture.fabric(), incident);
  resolve.clearance = cleared;
  resolve.rationale = "resolve anyway";
  const auto refused = fixture.fabric().ResolveIncident(resolve);
  ISF_REQUIRE(!refused.ok());
  ISF_CHECK(DenialSays(refused.status(), "still reports the effect as present"));

  // Withdrawing the contradicting observation unblocks the transition.
  const auto evidence = fixture.fabric().ListEvidence(incident, isf::ListQuery{0, 100});
  ISF_REQUIRE(evidence.ok());
  isf::EvidenceId observation;
  for (const isf::EvidenceView& view : evidence.value()) {
    if (view.kind == isf::EvidenceKind::EffectObservation) observation = view.id;
  }
  ISF_REQUIRE(observation.valid());
  isf::WithdrawEvidenceRequest withdraw;
  withdraw.header = fixture.Header(fixture.operator_role);
  withdraw.incident = incident;
  withdraw.expected_revision = RevisionOf(fixture.fabric(), incident);
  withdraw.evidence = observation;
  withdraw.rationale = "observation was a sensor glitch";
  ISF_REQUIRE(fixture.fabric().WithdrawEvidence(withdraw).ok());

  resolve.header = fixture.Header(fixture.manager);
  resolve.expected_revision = RevisionOf(fixture.fabric(), incident);
  ISF_REQUIRE(fixture.fabric().ResolveIncident(resolve).ok());
}

ISF_TEST(Gates, RecoveredObservationsAreNotSilentlyFresh) {
  Fixture fixture("gate-freshness", isf::StateDigestPolicy::EveryCommit);
  const auto accepted = AcceptFreshIncident(fixture, isf::IncidentClass::Power,
                                            isf::Severity::Major, "freshness", "rack-o1");
  const isf::IncidentId incident = accepted.id;
  const isf::EvidenceId proof = RecordEvidence(
      fixture, incident, RevisionOf(fixture.fabric(), incident), isf::EvidenceKind::ContainmentProof,
      isf::Severity::Unclassified, "contained");
  isf::DeclareContainedRequest contained;
  contained.header = fixture.Header(fixture.commander);
  contained.incident = incident;
  contained.expected_revision = RevisionOf(fixture.fabric(), incident);
  contained.proof = proof;
  contained.rationale = "contained";
  ISF_REQUIRE(fixture.fabric().DeclareContained(contained).ok());

  const isf::EvidenceId temperature = isftest::RecordEvidenceWith(
      fixture, fixture.operator_role, incident, RevisionOf(fixture.fabric(), incident),
      isf::EvidenceKind::EffectObservation, isf::Severity::Unclassified, false,
      "intake temperature back to nominal");
  const auto before = fixture.fabric().GetEvidence(temperature);
  ISF_REQUIRE(before.ok());
  ISF_CHECK(before.value().current);

  isf::StartRecoveryRequest recovery;
  recovery.header = fixture.Header(fixture.commander);
  recovery.incident = incident;
  recovery.expected_revision = RevisionOf(fixture.fabric(), incident);
  recovery.rationale = "recover";
  ISF_REQUIRE(fixture.fabric().StartRecovery(recovery).ok());
  const isf::EvidenceId recovery_proof = RecordEvidence(
      fixture, incident, RevisionOf(fixture.fabric(), incident), isf::EvidenceKind::RecoveryProof,
      isf::Severity::Unclassified, "recovered");
  isf::DeclareRecoveredRequest recovered;
  recovered.header = fixture.Header(fixture.commander);
  recovered.incident = incident;
  recovered.expected_revision = RevisionOf(fixture.fabric(), incident);
  recovered.proof = recovery_proof;
  recovered.rationale = "proven";
  ISF_REQUIRE(fixture.fabric().DeclareRecovered(recovered).ok());

  const auto after = fixture.fabric().GetEvidence(temperature);
  ISF_REQUIRE(after.ok());
  ISF_CHECK(!after.value().current);
  ISF_CHECK_EQ(after.value().observation_generation, std::uint64_t{1});
  ISF_CHECK_EQ(IncidentOf(fixture.fabric(), incident).observation_generation, std::uint64_t{2});

  // Durable attestations survive the observation generation change.
  const auto containment_view = fixture.fabric().GetEvidence(proof);
  ISF_REQUIRE(containment_view.ok());
  ISF_CHECK(containment_view.value().current);

  // Freshness is restored only by an explicit, audited act.
  isf::ReestablishEvidenceRequest reestablish;
  reestablish.header = fixture.Header(fixture.commander);
  reestablish.incident = incident;
  reestablish.expected_revision = RevisionOf(fixture.fabric(), incident);
  reestablish.evidence = temperature;
  reestablish.rationale = "sensor re-read confirms nominal intake";
  ISF_REQUIRE(fixture.fabric().ReestablishEvidence(reestablish).ok());
  const auto restored = fixture.fabric().GetEvidence(temperature);
  ISF_REQUIRE(restored.ok());
  ISF_CHECK(restored.value().current);
  ISF_CHECK_EQ(restored.value().observation_generation, std::uint64_t{2});

  reestablish.header = fixture.Header(fixture.commander);
  reestablish.expected_revision = RevisionOf(fixture.fabric(), incident);
  ISF_EXPECT_ERROR(fixture.fabric().ReestablishEvidence(reestablish), isf::ErrorCode::Conflict);
}

ISF_TEST(Gates, ReopenInvalidatesEveryPriorAttestation) {
  Fixture fixture("gate-reopen", isf::StateDigestPolicy::EveryCommit);

  // Close a security incident, which a duty manager may do.
  const auto accepted = AcceptFreshIncident(fixture, isf::IncidentClass::PhysicalSecurity,
                                            isf::Severity::Major, "reopen", "rack-p1");
  const isf::IncidentId incident = accepted.id;
  const isf::EvidenceId containment = RecordEvidence(
      fixture, incident, RevisionOf(fixture.fabric(), incident), isf::EvidenceKind::ContainmentProof,
      isf::Severity::Unclassified, "secured");
  isf::DeclareContainedRequest contained;
  contained.header = fixture.Header(fixture.commander);
  contained.incident = incident;
  contained.expected_revision = RevisionOf(fixture.fabric(), incident);
  contained.proof = containment;
  contained.rationale = "secured";
  ISF_REQUIRE(fixture.fabric().DeclareContained(contained).ok());
  const isf::EvidenceId cleared = RecordEvidence(
      fixture, incident, RevisionOf(fixture.fabric(), incident), isf::EvidenceKind::EffectCleared,
      isf::Severity::Unclassified, "clear");
  isf::ResolveIncidentRequest resolve;
  resolve.header = fixture.Header(fixture.manager);
  resolve.incident = incident;
  resolve.expected_revision = RevisionOf(fixture.fabric(), incident);
  resolve.clearance = cleared;
  resolve.rationale = "resolved";
  ISF_REQUIRE(fixture.fabric().ResolveIncident(resolve).ok());
  const isf::EvidenceId attestation = RecordEvidence(
      fixture, incident, RevisionOf(fixture.fabric(), incident),
      isf::EvidenceKind::ClosureAttestation, isf::Severity::Unclassified, "attested");
  isf::CloseIncidentRequest close;
  close.header = fixture.Header(fixture.manager);
  close.incident = incident;
  close.expected_revision = RevisionOf(fixture.fabric(), incident);
  close.attestation = attestation;
  close.rationale = "closed";
  ISF_REQUIRE(fixture.fabric().CloseIncident(close).ok());

  const isf::EvidenceId trigger = RecordEvidence(
      fixture, incident, RevisionOf(fixture.fabric(), incident), isf::EvidenceKind::ReopenTrigger,
      isf::Severity::Unclassified, "door forced again");
  isf::ReopenIncidentRequest reopen;
  reopen.header = fixture.Header(fixture.manager);
  reopen.incident = incident;
  reopen.expected_revision = RevisionOf(fixture.fabric(), incident);
  reopen.trigger = trigger;
  reopen.rationale = "recurrence";
  ISF_REQUIRE(fixture.fabric().ReopenIncident(reopen).ok());
  ISF_CHECK_EQ(IncidentOf(fixture.fabric(), incident).state, isf::LifecycleState::Reopened);

  for (const isf::EvidenceId id : {containment, cleared, attestation, trigger}) {
    const auto view = fixture.fabric().GetEvidence(id);
    ISF_REQUIRE(view.ok());
    ISF_CHECK(!view.value().current);
  }

  // Closing again requires freshly recorded attestations in the new generation.
  close.header = fixture.Header(fixture.manager);
  close.expected_revision = RevisionOf(fixture.fabric(), incident);
  const auto refused = fixture.fabric().CloseIncident(close);
  ISF_REQUIRE(!refused.ok());
  ISF_CHECK_EQ(refused.status().code(), isf::ErrorCode::IllegalTransition);

  resolve.header = fixture.Header(fixture.manager);
  resolve.expected_revision = RevisionOf(fixture.fabric(), incident);
  const auto blocked = fixture.fabric().ResolveIncident(resolve);
  ISF_REQUIRE(!blocked.ok());
  ISF_CHECK(DenialSays(blocked.status(), "must be re-established explicitly"));
}

ISF_TEST(Gates, ReopenRequiresATriggerAndIsBounded) {
  Fixture fixture("gate-reopen-limit", isf::StateDigestPolicy::EveryCommit);
  const auto accepted = AcceptFreshIncident(fixture, isf::IncidentClass::PhysicalSecurity,
                                            isf::Severity::Minor, "reopen limit", "rack-p2");
  const isf::IncidentId incident = accepted.id;
  const isf::EvidenceId containment = RecordEvidence(
      fixture, incident, RevisionOf(fixture.fabric(), incident), isf::EvidenceKind::ContainmentProof,
      isf::Severity::Unclassified, "secured");
  isf::DeclareContainedRequest contained;
  contained.header = fixture.Header(fixture.commander);
  contained.incident = incident;
  contained.expected_revision = RevisionOf(fixture.fabric(), incident);
  contained.proof = containment;
  contained.rationale = "secured";
  ISF_REQUIRE(fixture.fabric().DeclareContained(contained).ok());
  const isf::EvidenceId cleared = RecordEvidence(
      fixture, incident, RevisionOf(fixture.fabric(), incident), isf::EvidenceKind::EffectCleared,
      isf::Severity::Unclassified, "clear");
  isf::ResolveIncidentRequest resolve;
  resolve.header = fixture.Header(fixture.manager);
  resolve.incident = incident;
  resolve.expected_revision = RevisionOf(fixture.fabric(), incident);
  resolve.clearance = cleared;
  resolve.rationale = "resolved";
  ISF_REQUIRE(fixture.fabric().ResolveIncident(resolve).ok());
  const isf::EvidenceId attestation = RecordEvidence(
      fixture, incident, RevisionOf(fixture.fabric(), incident),
      isf::EvidenceKind::ClosureAttestation, isf::Severity::Unclassified, "attested");
  isf::CloseIncidentRequest close;
  close.header = fixture.Header(fixture.manager);
  close.incident = incident;
  close.expected_revision = RevisionOf(fixture.fabric(), incident);
  close.attestation = attestation;
  close.rationale = "closed";
  ISF_REQUIRE(fixture.fabric().CloseIncident(close).ok());

  isf::ReopenIncidentRequest reopen;
  reopen.header = fixture.Header(fixture.manager);
  reopen.incident = incident;
  reopen.expected_revision = RevisionOf(fixture.fabric(), incident);
  reopen.trigger = isf::EvidenceId{};
  reopen.rationale = "no trigger";
  const auto refused = fixture.fabric().ReopenIncident(reopen);
  ISF_REQUIRE(!refused.ok());
  ISF_CHECK(DenialSays(refused.status(), "ReopenTrigger"));

  std::uint64_t expected_reopens = 0;
  for (std::uint64_t attempt = 0; attempt < isf::PolicyConstants::kMaxReopens; ++attempt) {
    const isf::EvidenceId trigger = RecordEvidence(
        fixture, incident, RevisionOf(fixture.fabric(), incident), isf::EvidenceKind::ReopenTrigger,
        isf::Severity::Unclassified, "trigger " + std::to_string(attempt));
    reopen.header = fixture.Header(fixture.manager);
    reopen.expected_revision = RevisionOf(fixture.fabric(), incident);
    reopen.trigger = trigger;
    reopen.rationale = "recurrence";
    ISF_REQUIRE(fixture.fabric().ReopenIncident(reopen).ok());
    ++expected_reopens;
    ISF_CHECK_EQ(IncidentOf(fixture.fabric(), incident).reopen_count, expected_reopens);

    // Re-close so the next reopen is legal again.
    const isf::EvidenceId fresh_containment = RecordEvidence(
        fixture, incident, RevisionOf(fixture.fabric(), incident),
        isf::EvidenceKind::ContainmentProof, isf::Severity::Unclassified, "secured again");
    contained.header = fixture.Header(fixture.commander);
    contained.expected_revision = RevisionOf(fixture.fabric(), incident);
    contained.proof = fresh_containment;
    ISF_REQUIRE(fixture.fabric().DeclareContained(contained).ok());
    const isf::EvidenceId fresh_cleared = RecordEvidence(
        fixture, incident, RevisionOf(fixture.fabric(), incident), isf::EvidenceKind::EffectCleared,
        isf::Severity::Unclassified, "clear again");
    resolve.header = fixture.Header(fixture.manager);
    resolve.expected_revision = RevisionOf(fixture.fabric(), incident);
    resolve.clearance = fresh_cleared;
    ISF_REQUIRE(fixture.fabric().ResolveIncident(resolve).ok());
    const isf::EvidenceId fresh_attestation = RecordEvidence(
        fixture, incident, RevisionOf(fixture.fabric(), incident),
        isf::EvidenceKind::ClosureAttestation, isf::Severity::Unclassified, "attested again");
    close.header = fixture.Header(fixture.manager);
    close.expected_revision = RevisionOf(fixture.fabric(), incident);
    close.attestation = fresh_attestation;
    ISF_REQUIRE(fixture.fabric().CloseIncident(close).ok());
  }

  const isf::EvidenceId final_trigger = RecordEvidence(
      fixture, incident, RevisionOf(fixture.fabric(), incident), isf::EvidenceKind::ReopenTrigger,
      isf::Severity::Unclassified, "one too many");
  reopen.header = fixture.Header(fixture.manager);
  reopen.expected_revision = RevisionOf(fixture.fabric(), incident);
  reopen.trigger = final_trigger;
  ISF_EXPECT_ERROR(fixture.fabric().ReopenIncident(reopen), isf::ErrorCode::ReopenLimitReached);
}
