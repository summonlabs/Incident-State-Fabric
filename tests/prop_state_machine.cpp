// Incident State Fabric - DCCP boundary 50
// Copyright 2026 Summon Software Labs.
// Licensed under the Apache License, Version 2.0.
//
// A deterministic seeded state machine. It drives long random incident
// lifecycles (including deliberately stale actors and duplicate requests),
// checks invariants after every mutation, and finally compares the live state
// against the state rebuilt by replaying the log from scratch.

#include <cstdint>
#include <cstdio>
#include <map>
#include <string>
#include <vector>

#include "isf/isf.h"
#include "support/store_builder.h"
#include "test_framework.h"
#include "test_support.h"

namespace {

using isftest::ReportFailure;

class Random {
 public:
  explicit Random(std::uint64_t seed) : state_(seed == 0 ? 0x9e3779b97f4a7c15ull : seed) {}

  [[nodiscard]] std::uint64_t Next() {
    state_ ^= state_ << 13;
    state_ ^= state_ >> 7;
    state_ ^= state_ << 17;
    return state_;
  }

  [[nodiscard]] std::uint32_t Below(std::uint32_t bound) {
    return bound == 0 ? 0 : static_cast<std::uint32_t>(Next() % bound);
  }

  [[nodiscard]] bool Chance(std::uint32_t percent) { return Below(100) < percent; }

 private:
  std::uint64_t state_;
};

struct Shadow {
  std::map<std::uint64_t, std::uint64_t> observation_generation;
  std::map<std::uint64_t, std::uint64_t> attestation_generation;
  std::map<std::uint64_t, std::uint64_t> revision;
  std::uint64_t next_incident_id_floor = 1;
  std::uint64_t committed = 0;
  std::uint64_t denied = 0;
  std::uint64_t replayed = 0;
};

[[nodiscard]] std::string Failure(const std::string& seed_text, const std::string& detail) {
  return seed_text + ": " + detail;
}

void CheckInvariants(isf::IncidentFabric& fabric, Shadow& shadow, std::uint64_t seed) {
  const std::string seed_text = "seed=" + std::to_string(seed);
  const auto status = fabric.GetStatus();
  ISF_MUST(status);
  if (status.value().audit_count != status.value().generation.value()) {
    ReportFailure(__FILE__, __LINE__,
                  Failure(seed_text, "audit length does not equal the durable generation"));
  }
  if (status.value().record_count != status.value().generation.value()) {
    ReportFailure(__FILE__, __LINE__,
                  Failure(seed_text, "record count does not equal the durable generation"));
  }

  const auto incidents = fabric.ListIncidents(isf::ListQuery{0, 1000});
  ISF_REQUIRE(incidents.ok());
  std::uint64_t highest_id = 0;
  for (const isf::IncidentSummary& summary : incidents.value()) {
    const isf::IncidentView view = isftest::IncidentOf(fabric, summary.id);
    if (view.revision < 1) {
      ReportFailure(__FILE__, __LINE__, Failure(seed_text, "incident revision is below one"));
    }
    if (summary.id.value() > highest_id) highest_id = summary.id.value();
    if (view.state != isf::LifecycleState::Reported &&
        view.cls == isf::IncidentClass::Unclassified) {
      ReportFailure(__FILE__, __LINE__,
                    Failure(seed_text, "an incident past reporting has no concrete class"));
    }
    if (view.state != isf::LifecycleState::Reported &&
        view.severity == isf::Severity::Unclassified) {
      ReportFailure(__FILE__, __LINE__,
                    Failure(seed_text, "an incident past reporting has no concrete severity"));
    }
    if (view.scope.empty()) {
      ReportFailure(__FILE__, __LINE__, Failure(seed_text, "an incident has an empty scope"));
    }

    const auto previous_observation = shadow.observation_generation.find(summary.id.value());
    if (previous_observation != shadow.observation_generation.end() &&
        view.observation_generation < previous_observation->second) {
      ReportFailure(__FILE__, __LINE__,
                    Failure(seed_text, "observation generation went backwards"));
    }
    shadow.observation_generation[summary.id.value()] = view.observation_generation;

    const auto previous_attestation = shadow.attestation_generation.find(summary.id.value());
    if (previous_attestation != shadow.attestation_generation.end() &&
        view.attestation_generation < previous_attestation->second) {
      ReportFailure(__FILE__, __LINE__,
                    Failure(seed_text, "attestation generation went backwards"));
    }
    shadow.attestation_generation[summary.id.value()] = view.attestation_generation;

    const auto previous_revision = shadow.revision.find(summary.id.value());
    if (previous_revision != shadow.revision.end() && view.revision < previous_revision->second) {
      ReportFailure(__FILE__, __LINE__, Failure(seed_text, "incident revision went backwards"));
    }
    shadow.revision[summary.id.value()] = view.revision;

    for (const isf::LifecycleEvent& event : view.history) {
      if (event.at.value() > status.value().generation.value()) {
        ReportFailure(__FILE__, __LINE__,
                      Failure(seed_text, "history references a future generation"));
      }
    }
  }

  if (status.value().incident_count != incidents.value().size()) {
    ReportFailure(__FILE__, __LINE__,
                  Failure(seed_text, "the reported incident count does not match the listed "
                                     "incidents"));
  }
  if (highest_id >= shadow.next_incident_id_floor) {
    shadow.next_incident_id_floor = highest_id + 1;
  }
}

/// Compares every field of the live views against the views produced by a fresh
/// replay of the same log.
void CheckReplayEquivalence(isf::IncidentFabric& fabric, std::uint64_t seed) {
  const auto incidents = fabric.ListIncidents(isf::ListQuery{0, 1000});
  ISF_REQUIRE(incidents.ok());
  std::vector<isf::IncidentView> live;
  std::vector<std::vector<isf::EvidenceView>> live_evidence;
  for (const isf::IncidentSummary& summary : incidents.value()) {
    live.push_back(isftest::IncidentOf(fabric, summary.id));
    const auto evidence = fabric.ListEvidence(summary.id, isf::ListQuery{0, 1000});
    ISF_REQUIRE(evidence.ok());
    live_evidence.push_back(evidence.value());
  }

  const std::string path = fabric.GetStatus().value().store_path;
  ISF_REQUIRE(fabric.Close().ok());

  auto reopened = isf::IncidentFabric::Open(isftest::StoreOptions(path));
  ISF_REQUIRE(reopened.ok());

  const auto replay_incidents = reopened.value()->ListIncidents(isf::ListQuery{0, 1000});
  ISF_REQUIRE(replay_incidents.ok());
  if (replay_incidents.value().size() != live.size()) {
    ReportFailure(__FILE__, __LINE__, "replay produced a different number of incidents");
    return;
  }
  for (std::size_t index = 0; index < live.size(); ++index) {
    const isf::IncidentView replayed =
        isftest::IncidentOf(*reopened.value(), replay_incidents.value()[index].id);
    const isf::IncidentView& expected = live[index];
    ISF_CHECK_EQ(replayed.id, expected.id);
    ISF_CHECK_EQ(replayed.cls, expected.cls);
    ISF_CHECK_EQ(replayed.severity, expected.severity);
    ISF_CHECK_EQ(replayed.state, expected.state);
    ISF_CHECK_EQ(replayed.revision, expected.revision);
    ISF_CHECK_EQ(replayed.observation_generation, expected.observation_generation);
    ISF_CHECK_EQ(replayed.attestation_generation, expected.attestation_generation);
    ISF_CHECK_EQ(replayed.reopen_count, expected.reopen_count);
    ISF_CHECK_EQ(replayed.recovery_started, expected.recovery_started);
    ISF_CHECK_EQ(replayed.containment_declared, expected.containment_declared);
    ISF_CHECK_EQ(replayed.owner, expected.owner);
    ISF_CHECK_EQ(replayed.accepting_authority, expected.accepting_authority);
    ISF_CHECK_EQ(replayed.scope, expected.scope);
    ISF_CHECK_EQ(replayed.summary, expected.summary);
    ISF_CHECK_EQ(replayed.parent, expected.parent);
    ISF_CHECK_EQ(replayed.predecessor, expected.predecessor);
    ISF_CHECK_EQ(replayed.created_at, expected.created_at);
    ISF_CHECK_EQ(replayed.updated_at, expected.updated_at);
    ISF_CHECK_EQ(replayed.escalation_count, expected.escalation_count);
    ISF_CHECK_EQ(replayed.history.size(), expected.history.size());

    const auto replayed_evidence =
        reopened.value()->ListEvidence(replayed.id, isf::ListQuery{0, 1000});
    ISF_REQUIRE(replayed_evidence.ok());
    ISF_CHECK_EQ(replayed_evidence.value().size(), live_evidence[index].size());
    for (std::size_t item = 0; item < live_evidence[index].size() &&
                               item < replayed_evidence.value().size();
         ++item) {
      const isf::EvidenceView& a = live_evidence[index][item];
      const isf::EvidenceView& b = replayed_evidence.value()[item];
      ISF_CHECK_EQ(a.id, b.id);
      ISF_CHECK_EQ(a.kind, b.kind);
      ISF_CHECK_EQ(a.cls, b.cls);
      ISF_CHECK_EQ(a.source, b.source);
      ISF_CHECK_EQ(a.recorded_at, b.recorded_at);
      ISF_CHECK_EQ(a.observation_generation, b.observation_generation);
      ISF_CHECK_EQ(a.attestation_generation, b.attestation_generation);
      ISF_CHECK_EQ(a.withdrawn, b.withdrawn);
      ISF_CHECK_EQ(a.asserted_severity, b.asserted_severity);
      ISF_CHECK_EQ(a.effect_present, b.effect_present);
      ISF_CHECK_EQ(a.current, b.current);
      ISF_CHECK_EQ(a.rationale, b.rationale);
      ISF_CHECK_EQ(a.detail, b.detail);
    }
  }
  ISF_CHECK_EQ(reopened.value()->GetStatus().value().incident_count,
               static_cast<std::uint64_t>(live.size()));
  ISF_REQUIRE(reopened.value()->Close().ok());
  (void)seed;
}

/// Runs one deterministic random walk and returns the store path.
[[nodiscard]] bool RunWalk(std::uint64_t seed, std::size_t steps, const std::string& path,
                           Shadow& shadow) {
  auto opened = isf::IncidentFabric::Open(isftest::StoreOptions(path));
  if (!opened.ok()) return false;
  isf::IncidentFabric& fabric = *opened.value();

  isf::RegisterAuthorityRequest bootstrap;
  bootstrap.header.actor.authority = isf::AuthorityId{};
  bootstrap.header.actor.epoch = isftest::CurrentEpoch(fabric);
  bootstrap.header.key = isftest::Key(1);
  bootstrap.name = "director";
  bootstrap.role = isf::AuthorityRole::FacilityDirector;
  bootstrap.rationale = "walk bootstrap";
  if (!fabric.RegisterAuthority(bootstrap).ok()) return false;

  std::vector<isf::AuthorityId> roles{isf::AuthorityId{1}};
  const isf::AuthorityRole role_table[] = {isf::AuthorityRole::IncidentCommander,
                                           isf::AuthorityRole::DutyManager,
                                           isf::AuthorityRole::Operator,
                                           isf::AuthorityRole::Observer};
  for (std::size_t index = 0; index < 4; ++index) {
    isf::RegisterAuthorityRequest request;
    request.header = isftest::Header(fabric, isf::AuthorityId{1},
                                     static_cast<std::uint64_t>(2 + index));
    request.name = "role-" + std::to_string(index);
    request.role = role_table[index];
    request.rationale = "walk role";
    const auto receipt = fabric.RegisterAuthority(request);
    if (!receipt.ok()) return false;
    roles.push_back(receipt.value().authority);
  }
  const isf::AuthorityId director = roles[0];
  const isf::AuthorityId commander = roles[1];
  const isf::AuthorityId manager = roles[2];
  const isf::AuthorityId operator_role = roles[3];
  const isf::AuthorityId observer = roles[4];

  Random random(seed);
  std::vector<isf::IncidentId> incidents;
  std::uint64_t key_counter = 1000;
  const std::string seed_text = "seed=" + std::to_string(seed);
  std::map<std::pair<std::uint64_t, std::uint64_t>, bool> executed;

  for (std::size_t step = 0; step < steps; ++step) {
    const std::uint32_t choice = random.Below(15);
    isf::MutationHeader header;
    header.key = isftest::Key(key_counter);
    header.actor.epoch = isftest::CurrentEpoch(fabric);

    isf::AnyRequest request;
    switch (choice) {
      case 0:
      case 1:
      case 2: {
        isf::ReportIncidentRequest report;
        report.header = header;
        report.header.actor.authority = random.Chance(90) ? operator_role : observer;
        report.cls = static_cast<isf::IncidentClass>(1 + random.Below(10));
        report.reported_severity = static_cast<isf::Severity>(1 + random.Below(5));
        report.summary = "walk report " + std::to_string(step);
        report.scope.objects.push_back(isf::ObjectRef{
            isf::ObjectKind::Rack, "rack-" + std::to_string(random.Below(8))});
        report.source_system = "synthetic-walk";
        report.source_event_id = "walk-" + std::to_string(step);
        request = report;
        break;
      }
      case 3:
      case 4: {
        isf::RecordEvidenceRequest evidence;
        evidence.header = header;
        evidence.header.actor.authority = random.Chance(80) ? operator_role : manager;
        if (incidents.empty()) {
          ++key_counter;
          continue;
        }
        evidence.incident = incidents[random.Below(static_cast<std::uint32_t>(incidents.size()))];
        evidence.expected_revision = isftest::RevisionOf(fabric, evidence.incident);
        if (random.Chance(10)) evidence.expected_revision += 1;  // deliberately stale
        evidence.kind = static_cast<isf::EvidenceKind>(1 + random.Below(12));
        if (evidence.kind == isf::EvidenceKind::SeverityAssessment) {
          evidence.asserted_severity = static_cast<isf::Severity>(1 + random.Below(5));
        }
        evidence.effect_present = random.Chance(30);
        evidence.rationale = random.Chance(90) ? "walk evidence" : "";
        request = evidence;
        break;
      }
      case 5: {
        isf::AcceptIncidentRequest accept;
        accept.header = header;
        accept.header.actor.authority = commander;
        if (incidents.empty()) {
          ++key_counter;
          continue;
        }
        accept.incident = incidents[random.Below(static_cast<std::uint32_t>(incidents.size()))];
        accept.expected_revision = isftest::RevisionOf(fabric, accept.incident);
        accept.cls = static_cast<isf::IncidentClass>(1 + random.Below(10));
        accept.severity = static_cast<isf::Severity>(1 + random.Below(5));
        accept.owner = commander;
        // Reference the most recent severity assessment on the incident.
        const auto evidence = fabric.ListEvidence(accept.incident, isf::ListQuery{0, 1000});
        if (evidence.ok()) {
          for (const isf::EvidenceView& view : evidence.value()) {
            if (view.kind == isf::EvidenceKind::SeverityAssessment && view.current) {
              accept.severity_evidence = view.id;
              accept.severity = view.asserted_severity;
            }
          }
        }
        accept.rationale = "walk accept";
        request = accept;
        break;
      }
      case 6: {
        isf::DeclareContainedRequest contained;
        contained.header = header;
        contained.header.actor.authority = commander;
        if (incidents.empty()) {
          ++key_counter;
          continue;
        }
        contained.incident = incidents[random.Below(static_cast<std::uint32_t>(incidents.size()))];
        contained.expected_revision = isftest::RevisionOf(fabric, contained.incident);
        const auto evidence = fabric.ListEvidence(contained.incident, isf::ListQuery{0, 1000});
        if (evidence.ok()) {
          for (const isf::EvidenceView& view : evidence.value()) {
            if (view.kind == isf::EvidenceKind::ContainmentProof && view.current) {
              contained.proof = view.id;
            }
          }
        }
        contained.rationale = "walk containment";
        request = contained;
        break;
      }
      case 7: {
        isf::StartRecoveryRequest recovery;
        recovery.header = header;
        recovery.header.actor.authority = commander;
        if (incidents.empty()) {
          ++key_counter;
          continue;
        }
        recovery.incident = incidents[random.Below(static_cast<std::uint32_t>(incidents.size()))];
        recovery.expected_revision = isftest::RevisionOf(fabric, recovery.incident);
        recovery.rationale = "walk recovery";
        request = recovery;
        break;
      }
      case 8: {
        isf::DeclareRecoveredRequest recovered;
        recovered.header = header;
        recovered.header.actor.authority = commander;
        if (incidents.empty()) {
          ++key_counter;
          continue;
        }
        recovered.incident = incidents[random.Below(static_cast<std::uint32_t>(incidents.size()))];
        recovered.expected_revision = isftest::RevisionOf(fabric, recovered.incident);
        const auto evidence = fabric.ListEvidence(recovered.incident, isf::ListQuery{0, 1000});
        if (evidence.ok()) {
          for (const isf::EvidenceView& view : evidence.value()) {
            if (view.kind == isf::EvidenceKind::RecoveryProof && view.current) {
              recovered.proof = view.id;
            }
          }
        }
        recovered.rationale = "walk recovered";
        request = recovered;
        break;
      }
      case 9: {
        isf::ResolveIncidentRequest resolve;
        resolve.header = header;
        resolve.header.actor.authority = manager;
        if (incidents.empty()) {
          ++key_counter;
          continue;
        }
        resolve.incident = incidents[random.Below(static_cast<std::uint32_t>(incidents.size()))];
        resolve.expected_revision = isftest::RevisionOf(fabric, resolve.incident);
        const auto evidence = fabric.ListEvidence(resolve.incident, isf::ListQuery{0, 1000});
        if (evidence.ok()) {
          for (const isf::EvidenceView& view : evidence.value()) {
            if (view.kind == isf::EvidenceKind::EffectCleared && view.current) {
              resolve.clearance = view.id;
            }
          }
        }
        resolve.rationale = "walk resolve";
        request = resolve;
        break;
      }
      case 10: {
        isf::CloseIncidentRequest close;
        close.header = header;
        close.header.actor.authority = director;
        if (incidents.empty()) {
          ++key_counter;
          continue;
        }
        close.incident = incidents[random.Below(static_cast<std::uint32_t>(incidents.size()))];
        close.expected_revision = isftest::RevisionOf(fabric, close.incident);
        const auto evidence = fabric.ListEvidence(close.incident, isf::ListQuery{0, 1000});
        if (evidence.ok()) {
          for (const isf::EvidenceView& view : evidence.value()) {
            if (view.kind == isf::EvidenceKind::ClosureAttestation && view.current) {
              close.attestation = view.id;
            }
          }
        }
        close.rationale = "walk close";
        request = close;
        break;
      }
      case 11: {
        isf::ReopenIncidentRequest reopen;
        reopen.header = header;
        reopen.header.actor.authority = director;
        if (incidents.empty()) {
          ++key_counter;
          continue;
        }
        reopen.incident = incidents[random.Below(static_cast<std::uint32_t>(incidents.size()))];
        reopen.expected_revision = isftest::RevisionOf(fabric, reopen.incident);
        const auto evidence = fabric.ListEvidence(reopen.incident, isf::ListQuery{0, 1000});
        if (evidence.ok()) {
          for (const isf::EvidenceView& view : evidence.value()) {
            if (view.kind == isf::EvidenceKind::ReopenTrigger && view.current) {
              reopen.trigger = view.id;
            }
          }
        }
        reopen.rationale = "walk reopen";
        request = reopen;
        break;
      }
      case 12: {
        isf::AmendScopeRequest scope;
        scope.header = header;
        scope.header.actor.authority = commander;
        if (incidents.empty()) {
          ++key_counter;
          continue;
        }
        scope.incident = incidents[random.Below(static_cast<std::uint32_t>(incidents.size()))];
        scope.expected_revision = isftest::RevisionOf(fabric, scope.incident);
        scope.scope.objects.push_back(isf::ObjectRef{
            isf::ObjectKind::Rack, "rack-" + std::to_string(random.Below(8))});
        if (random.Chance(50)) {
          scope.scope.failure_domains.push_back(isf::FailureDomainRef{
              isf::FailureDomainKind::Zone, "zone-" + std::to_string(random.Below(4))});
        }
        scope.rationale = "walk scope";
        request = scope;
        break;
      }
      case 13: {
        isf::AssignOwnerRequest assign;
        assign.header = header;
        assign.header.actor.authority = commander;
        if (incidents.empty()) {
          ++key_counter;
          continue;
        }
        assign.incident = incidents[random.Below(static_cast<std::uint32_t>(incidents.size()))];
        assign.expected_revision = isftest::RevisionOf(fabric, assign.incident);
        assign.owner = roles[1 + random.Below(4)];
        assign.rationale = "walk handoff";
        request = assign;
        break;
      }
      default: {
        isf::MergeIncidentRequest merge;
        merge.header = header;
        merge.header.actor.authority = director;
        if (incidents.size() < 2) {
          ++key_counter;
          continue;
        }
        merge.survivor = incidents[random.Below(static_cast<std::uint32_t>(incidents.size()))];
        merge.absorbed = incidents[random.Below(static_cast<std::uint32_t>(incidents.size()))];
        merge.expected_survivor_revision = isftest::RevisionOf(fabric, merge.survivor);
        merge.expected_absorbed_revision = isftest::RevisionOf(fabric, merge.absorbed);
        merge.allow_cross_class = random.Chance(50);
        merge.rationale = "walk merge";
        request = merge;
        break;
      }
    }

    // Preview first: a preview must never change the store, and it must agree
    // with what the commit then does.
    const auto preview = fabric.Preview(request);
    ISF_MUST(preview);
    const auto before_status = fabric.GetStatus();
    ISF_MUST(before_status);

    const auto receipt = fabric.Commit(request);
    const auto after_status = fabric.GetStatus();
    ISF_MUST(after_status);

    if (preview.value().would_commit != receipt.ok()) {
      ReportFailure(__FILE__, __LINE__,
                    Failure(seed_text, "preview and commit disagreed about whether the request "
                                       "would commit"));
    }
    if (receipt.ok()) {
      if (receipt.value().replayed) {
        ++shadow.replayed;
        if (after_status.value().generation.value() !=
            before_status.value().generation.value()) {
          ReportFailure(__FILE__, __LINE__,
                        Failure(seed_text, "a replayed request changed the generation"));
        }
      } else {
        ++shadow.committed;
        if (after_status.value().generation.value() !=
            before_status.value().generation.value() + 1) {
          ReportFailure(__FILE__, __LINE__,
                        Failure(seed_text, "a committed request did not advance exactly one "
                                           "generation"));
        }
      }
    } else {
      ++shadow.denied;
      if (after_status.value().generation.value() != before_status.value().generation.value()) {
        ReportFailure(__FILE__, __LINE__,
                      Failure(seed_text, "a denied request changed the generation"));
      }
      if (receipt.status().code() != preview.value().code) {
        ReportFailure(__FILE__, __LINE__,
                      Failure(seed_text, "preview and commit disagreed about the denial code"));
      }
    }

    if (receipt.ok() && receipt.value().created_incident) {
      incidents.push_back(receipt.value().incident);
    }
    ++key_counter;

    // A duplicate of the previous request must be recognised as a replay.
    if (random.Chance(20)) {
      const auto duplicate = fabric.Commit(request);
      if (duplicate.ok()) {
        if (!duplicate.value().replayed) {
          ReportFailure(__FILE__, __LINE__,
                        Failure(seed_text, "an exact duplicate was not resolved as a replay"));
        }
      } else if (receipt.ok()) {
        ReportFailure(__FILE__, __LINE__,
                      Failure(seed_text, "an exact duplicate of a committed request failed"));
      }
    }

    CheckInvariants(fabric, shadow, seed);
  }

  CheckInvariants(fabric, shadow, seed);
  CheckReplayEquivalence(fabric, seed);
  return true;
}

}  // namespace

ISF_TEST(Property, SeededRandomWalkKeepsEveryInvariant) {
  const std::uint64_t seeds[] = {1, 7, 42, 1337, 90210};
  for (const std::uint64_t seed : seeds) {
    isftest::ScratchDir dir("prop-walk-" + std::to_string(seed));
    Shadow shadow;
    std::printf("    walk seed=%llu\n", static_cast<unsigned long long>(seed));
    ISF_CHECK(RunWalk(seed, 300, dir.path(), shadow));
    ISF_CHECK(shadow.committed > 0);
    ISF_CHECK(shadow.denied > 0);
  }
}

ISF_TEST(Property, IdenticalSeedsProduceIdenticalStores) {
  isftest::ScratchDir first("prop-determinism-a");
  isftest::ScratchDir second("prop-determinism-b");
  Shadow shadow_a;
  Shadow shadow_b;
  ISF_REQUIRE(RunWalk(20260101, 200, first.path(), shadow_a));
  ISF_REQUIRE(RunWalk(20260101, 200, second.path(), shadow_b));
  ISF_CHECK_EQ(shadow_a.committed, shadow_b.committed);
  ISF_CHECK_EQ(shadow_a.denied, shadow_b.denied);

  const auto segments_a = isftest::ReadWholeFile(isftest::Utf8(first.fs_path() / "segments" /
                                                               "seg-00000000000000000000.isf"));
  const auto segments_b = isftest::ReadWholeFile(isftest::Utf8(second.fs_path() / "segments" /
                                                               "seg-00000000000000000000.isf"));
  ISF_CHECK(!segments_a.empty());
  ISF_CHECK(segments_a == segments_b);
}

ISF_TEST(Property, FailedRequestsLeaveNoTraceInTheLog) {
  isftest::ScratchDir dir("prop-denials");
  Shadow shadow;
  ISF_REQUIRE(RunWalk(555, 150, dir.path(), shadow));

  auto fabric = isf::IncidentFabric::Open(isftest::StoreOptions(dir.path()));
  ISF_REQUIRE(fabric.ok());
  const auto audit = fabric.value()->ReadAudit(isf::AuditQuery{isf::Generation{}, 100000});
  ISF_REQUIRE(audit.ok());

  // Every durable record must be a session record, an authority registration, or
  // one of the walk's successful commits. A denied request leaves nothing.
  std::uint64_t domain_commits = 0;
  std::uint64_t session_records = 0;
  std::uint64_t registrations = 0;
  for (const isf::AuditEntry& entry : audit.value()) {
    switch (entry.op) {
      case isf::OpKind::SessionOpen:
      case isf::OpKind::SessionClose:
        ++session_records;
        break;
      case isf::OpKind::RegisterAuthority:
        ++registrations;
        break;
      default:
        ++domain_commits;
        break;
    }
  }
  ISF_CHECK_EQ(domain_commits, shadow.committed);
  ISF_CHECK_EQ(registrations, std::uint64_t{5});
  ISF_CHECK(session_records >= 2);
  ISF_CHECK_EQ(static_cast<std::uint64_t>(audit.value().size()),
               session_records + registrations + domain_commits);
  ISF_REQUIRE(fabric.value()->Close().ok());
}
