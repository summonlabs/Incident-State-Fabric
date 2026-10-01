// Incident State Fabric - DCCP boundary 50
// Copyright 2026 Summon Software Labs.
// Licensed under the Apache License, Version 2.0.

#include <algorithm>
#include <filesystem>
#include <string>
#include <vector>

#include "detail/crypto.h"
#include "detail/state.h"
#include "detail/store.h"
#include "isf/isf.h"
#include "support/store_builder.h"
#include "test_framework.h"
#include "test_support.h"

using isftest::Fixture;
using isftest::Key;
using isftest::RecordEvidence;
using isftest::ReportIncident;
using isftest::RevisionOf;
using isftest::ScratchDir;
using isftest::StoreOptions;
using isftest::Utf8;

namespace {

struct Snapshot {
  isf::Generation generation;
  std::uint64_t epoch = 0;
  std::uint64_t incarnation = 0;
  std::vector<isf::IncidentSummary> incidents;
  std::vector<isf::AuditEntry> audit;
};

[[nodiscard]] Snapshot Capture(isf::IncidentFabric& fabric) {
  Snapshot snapshot;
  const auto status = fabric.GetStatus();
  if (status.ok()) {
    snapshot.generation = status.value().generation;
    snapshot.epoch = status.value().control_epoch.value;
    snapshot.incarnation = status.value().incarnation;
  }
  const auto incidents = fabric.ListIncidents(isf::ListQuery{0, 1000});
  if (incidents.ok()) snapshot.incidents = incidents.value();
  const auto audit = fabric.ReadAudit(isf::AuditQuery{isf::Generation{}, 1000});
  if (audit.ok()) snapshot.audit = audit.value();
  return snapshot;
}

}  // namespace

ISF_TEST(Persistence, ReopenReproducesTheWholeAuthoritativeState) {
  Fixture fixture("persist-reopen", isf::StateDigestPolicy::EveryCommit);
  const auto accepted = isftest::AcceptFreshIncident(fixture, isf::IncidentClass::Power,
                                                     isf::Severity::Critical, "durable incident",
                                                     "rack-r1");
  const isf::IncidentId incident = accepted.id;
  RecordEvidence(fixture, incident, RevisionOf(fixture.fabric(), incident),
                 isf::EvidenceKind::ContainmentProof, isf::Severity::Unclassified, "contained");

  const isf::IncidentView before = isftest::IncidentOf(fixture.fabric(), incident);
  const Snapshot before_snapshot = Capture(fixture.fabric());

  fixture.Restart();

  const isf::IncidentView after = isftest::IncidentOf(fixture.fabric(), incident);
  const Snapshot after_snapshot = Capture(fixture.fabric());

  ISF_CHECK_EQ(after.id, before.id);
  ISF_CHECK_EQ(after.cls, before.cls);
  ISF_CHECK_EQ(after.severity, before.severity);
  ISF_CHECK_EQ(after.state, before.state);
  ISF_CHECK_EQ(after.revision, before.revision);
  ISF_CHECK_EQ(after.observation_generation, before.observation_generation);
  ISF_CHECK_EQ(after.attestation_generation, before.attestation_generation);
  ISF_CHECK_EQ(after.owner, before.owner);
  ISF_CHECK_EQ(after.scope, before.scope);
  ISF_CHECK_EQ(after.history.size(), before.history.size());
  ISF_CHECK_EQ(after.created_at, before.created_at);
  ISF_CHECK_EQ(after.updated_at, before.updated_at);

  // A restart appends a session-close record and then a session-open record.
  ISF_CHECK_EQ(after_snapshot.incidents.size(), before_snapshot.incidents.size());
  ISF_CHECK_EQ(after_snapshot.audit.size(), before_snapshot.audit.size() + 2);
  for (std::size_t index = 0; index < before_snapshot.audit.size(); ++index) {
    ISF_CHECK_EQ(after_snapshot.audit[index].generation, before_snapshot.audit[index].generation);
    ISF_CHECK_EQ(after_snapshot.audit[index].summary, before_snapshot.audit[index].summary);
  }
  ISF_CHECK_EQ(after_snapshot.incarnation, before_snapshot.incarnation + 1);

  const auto evidence = fixture.fabric().ListEvidence(incident, isf::ListQuery{0, 100});
  ISF_REQUIRE(evidence.ok());
  ISF_CHECK_EQ(evidence.value().size(), std::size_t{3});
}

ISF_TEST(Persistence, IdenticalOperationSequencesProduceIdenticalBytes) {
  ScratchDir first("persist-bytes-a");
  ScratchDir second("persist-bytes-b");

  const auto run = [](const std::string& path) {
    auto fabric = isf::IncidentFabric::Open(StoreOptions(path));
    if (!fabric.ok()) return false;
    isf::RegisterAuthorityRequest bootstrap;
    bootstrap.header.actor.authority = isf::AuthorityId{};
    bootstrap.header.actor.epoch = isftest::CurrentEpoch(*fabric.value());
    bootstrap.header.key = Key(1);
    bootstrap.name = "director";
    bootstrap.role = isf::AuthorityRole::FacilityDirector;
    bootstrap.rationale = "deterministic";
    if (!fabric.value()->RegisterAuthority(bootstrap).ok()) return false;

    isf::RegisterAuthorityRequest role;
    role.header = isftest::Header(*fabric.value(), isf::AuthorityId{1}, 2);
    role.name = "operator";
    role.role = isf::AuthorityRole::Operator;
    role.rationale = "deterministic";
    if (!fabric.value()->RegisterAuthority(role).ok()) return false;

    for (int index = 0; index < 5; ++index) {
      isf::ReportIncidentRequest report;
      report.header = isftest::Header(*fabric.value(), isf::AuthorityId{2},
                                      static_cast<std::uint64_t>(10 + index));
      report.cls = isf::IncidentClass::Cooling;
      report.reported_severity = isf::Severity::Major;
      report.summary = "deterministic report " + std::to_string(index);
      report.scope = isftest::RackScope("rack-s" + std::to_string(index));
      report.source_system = "synthetic";
      report.source_event_id = "det-" + std::to_string(index);
      if (!fabric.value()->ReportIncident(report).ok()) return false;
    }
    return fabric.value()->Close().ok();
  };

  ISF_REQUIRE(run(first.path()));
  ISF_REQUIRE(run(second.path()));

  const std::filesystem::path first_dir = first.fs_path() / "segments";
  const std::filesystem::path second_dir = second.fs_path() / "segments";
  std::vector<std::string> first_names;
  std::vector<std::string> second_names;
  for (const auto& entry : std::filesystem::directory_iterator(first_dir)) {
    first_names.push_back(entry.path().filename().string());
  }
  for (const auto& entry : std::filesystem::directory_iterator(second_dir)) {
    second_names.push_back(entry.path().filename().string());
  }
  ISF_CHECK_EQ(first_names.size(), second_names.size());
  ISF_REQUIRE(!first_names.empty());

  for (const std::string& name : first_names) {
    const auto a = isftest::ReadWholeFile(Utf8(first_dir / name));
    const auto b = isftest::ReadWholeFile(Utf8(second_dir / name));
    ISF_CHECK_EQ(a.size(), b.size());
    ISF_CHECK(a == b);
  }

  const auto manifest_a = isftest::ReadWholeFile(Utf8(first.fs_path() / "MANIFEST"));
  const auto manifest_b = isftest::ReadWholeFile(Utf8(second.fs_path() / "MANIFEST"));
  ISF_CHECK(!manifest_a.empty());
  ISF_CHECK(manifest_a == manifest_b);
}

ISF_TEST(Persistence, OnCheckpointPolicyStillRecoversExactly) {
  Fixture fixture("persist-checkpoint", isf::StateDigestPolicy::OnCheckpoint);
  for (int index = 0; index < 20; ++index) {
    ReportIncident(fixture, "checkpoint incident " + std::to_string(index),
                   "rack-t" + std::to_string(index));
  }
  const Snapshot before = Capture(fixture.fabric());
  ISF_CHECK_EQ(before.incidents.size(), std::size_t{20});

  fixture.Restart(isf::StateDigestPolicy::OnCheckpoint);
  const Snapshot after = Capture(fixture.fabric());
  ISF_CHECK_EQ(after.incidents.size(), before.incidents.size());
  for (std::size_t index = 0; index < before.incidents.size(); ++index) {
    ISF_CHECK_EQ(after.incidents[index].id, before.incidents[index].id);
    ISF_CHECK_EQ(after.incidents[index].revision, before.incidents[index].revision);
    ISF_CHECK_EQ(after.incidents[index].state, before.incidents[index].state);
    ISF_CHECK_EQ(after.incidents[index].severity, before.incidents[index].severity);
  }

  // An explicit checkpoint takes a fresh whole-state digest, and the next
  // recovery verifies it.
  ISF_REQUIRE(fixture.fabric().Checkpoint().ok());
  fixture.Restart(isf::StateDigestPolicy::OnCheckpoint);
  ISF_CHECK_EQ(Capture(fixture.fabric()).incidents.size(), before.incidents.size());
}

ISF_TEST(Persistence, SegmentsRotateAndTheChainSpansThem) {
  // Records carry up to roughly five kilobytes, so a few hundred commits push
  // past the four megabyte segment target and force a rotation.
  Fixture fixture("persist-rotate", isf::StateDigestPolicy::OnCheckpoint);
  const std::string filler(4000, 'x');
  for (int index = 0; index < 1100; ++index) {
    isf::ReportIncidentRequest report;
    report.header = fixture.Header(fixture.operator_role);
    report.cls = isf::IncidentClass::Cooling;
    report.reported_severity = isf::Severity::Minor;
    report.summary = "rotation incident " + std::to_string(index);
    report.scope = isftest::RackScope("rack-u" + std::to_string(index % 32));
    report.source_system = "synthetic";
    report.source_event_id = "rot-" + std::to_string(index);
    report.detail = filler;
    ISF_REQUIRE(fixture.fabric().ReportIncident(report).ok());
  }
  const auto status = fixture.fabric().GetStatus();
  ISF_REQUIRE(status.ok());
  ISF_CHECK(status.value().segment_count >= 2);
  ISF_CHECK_EQ(status.value().incident_count, std::uint64_t{1100});

  const Snapshot before = Capture(fixture.fabric());
  const std::uint64_t before_audit = status.value().audit_count;
  fixture.Restart(isf::StateDigestPolicy::OnCheckpoint);

  const auto after_status = fixture.fabric().GetStatus();
  ISF_REQUIRE(after_status.ok());
  ISF_CHECK_EQ(after_status.value().incident_count, std::uint64_t{1100});
  ISF_CHECK_EQ(after_status.value().audit_count, before_audit + 2);
  ISF_CHECK_EQ(after_status.value().record_count, after_status.value().generation.value());
  ISF_CHECK_EQ(after_status.value().segment_count, status.value().segment_count);

  // The listing page caps at a thousand, so the boundary is checked explicitly.
  const Snapshot after = Capture(fixture.fabric());
  ISF_CHECK_EQ(after.incidents.size(), std::size_t{1000});
  for (std::size_t index = 0; index < after.incidents.size(); ++index) {
    ISF_CHECK_EQ(after.incidents[index].id, before.incidents[index].id);
    ISF_CHECK_EQ(after.incidents[index].revision, before.incidents[index].revision);
    ISF_CHECK_EQ(after.incidents[index].summary, before.incidents[index].summary);
  }
  const auto tail = fixture.fabric().ListIncidents(isf::ListQuery{1000, 1000});
  ISF_REQUIRE(tail.ok());
  ISF_CHECK_EQ(tail.value().size(), std::size_t{100});
  ISF_CHECK_EQ(tail.value().back().id.value(), std::uint64_t{1100});
}

ISF_TEST(Persistence, CleanRestartKeepsTheEpochAndUncleanRestartAdvancesIt) {
  Fixture fixture("persist-epoch", isf::StateDigestPolicy::EveryCommit);
  const std::uint64_t epoch = fixture.Epoch().value;
  fixture.Restart();
  ISF_CHECK_EQ(fixture.Epoch().value, epoch);

  // A store whose last session never closed is what a crash leaves behind.
  ScratchDir crashed("persist-unclean");
  ISF_REQUIRE(isftest::WriteStore(crashed.path(), 1, [](const isf::detail::State& state,
                                                        std::size_t) {
    return isftest::SessionOpenEffect(state, 7, 3);
  }));

  auto reopened = isf::IncidentFabric::Open(StoreOptions(crashed.path()));
  ISF_REQUIRE(reopened.ok());
  const auto status = reopened.value()->GetStatus();
  ISF_REQUIRE(status.ok());
  ISF_CHECK_EQ(status.value().control_epoch.value, std::uint64_t{4});
  ISF_CHECK_EQ(status.value().incarnation, std::uint64_t{8});
  ISF_CHECK_EQ(status.value().generation.value(), std::uint64_t{2});
}

ISF_TEST(Persistence, StaleEpochFromBeforeACrashIsFenced) {
  ScratchDir crashed("persist-fence");
  ISF_REQUIRE(isftest::WriteStore(crashed.path(), 1, [](const isf::detail::State& state,
                                                        std::size_t) {
    return isftest::SessionOpenEffect(state, 1, 5);
  }));

  auto fabric = isf::IncidentFabric::Open(StoreOptions(crashed.path()));
  ISF_REQUIRE(fabric.ok());
  ISF_REQUIRE(fabric.value()->RegisterAuthority([&] {
                isf::RegisterAuthorityRequest bootstrap;
                bootstrap.header.actor.authority = isf::AuthorityId{};
                bootstrap.header.actor.epoch = isftest::CurrentEpoch(*fabric.value());
                bootstrap.header.key = Key(1);
                bootstrap.name = "director";
                bootstrap.role = isf::AuthorityRole::FacilityDirector;
                bootstrap.rationale = "bootstrap";
                return bootstrap;
              }())
                  .ok());

  isf::ForceFenceRequest stale;
  stale.header.actor.authority = isf::AuthorityId{1};
  stale.header.actor.epoch = isf::ControlEpoch{5};
  stale.header.key = Key(2);
  stale.rationale = "actor from before the crash";
  ISF_EXPECT_ERROR(fabric.value()->ForceFence(stale), isf::ErrorCode::StaleControlEpoch);
}

ISF_TEST(Persistence, RepeatedOpenAndCloseCyclesAreStable) {
  Fixture fixture("persist-cycles", isf::StateDigestPolicy::EveryCommit);
  ReportIncident(fixture, "cycle incident", "rack-v1");
  const std::uint64_t incidents = 1;
  for (int cycle = 0; cycle < 12; ++cycle) {
    fixture.Restart();
    const auto status = fixture.fabric().GetStatus();
    ISF_REQUIRE(status.ok());
    ISF_CHECK_EQ(status.value().incident_count, incidents);
    ISF_CHECK_EQ(status.value().incarnation, static_cast<std::uint64_t>(cycle + 2));
  }
  const auto final_status = fixture.fabric().GetStatus();
  ISF_REQUIRE(final_status.ok());
  ISF_CHECK(!final_status.value().state_digest_hex.empty());
}

ISF_TEST(Persistence, CloseIsIdempotentAndReadsFailAfterwards) {
  Fixture fixture("persist-close", isf::StateDigestPolicy::EveryCommit);
  const isf::IncidentId incident = ReportIncident(fixture, "closing", "rack-w1");
  ISF_REQUIRE(fixture.fabric().Close().ok());
  ISF_REQUIRE(fixture.fabric().Close().ok());
  ISF_CHECK(fixture.fabric().closed());
  ISF_EXPECT_ERROR(fixture.fabric().GetIncident(incident), isf::ErrorCode::StoreClosed);
  ISF_EXPECT_ERROR(fixture.fabric().ListIncidents(isf::ListQuery{0, 10}),
                   isf::ErrorCode::StoreClosed);
  isf::ForceFenceRequest fence;
  fence.header = fixture.Header(fixture.director);
  fence.rationale = "after close";
  ISF_EXPECT_ERROR(fixture.fabric().ForceFence(fence), isf::ErrorCode::StoreClosed);
  const auto status = fixture.fabric().GetStatus();
  ISF_CHECK(status.ok());
}
