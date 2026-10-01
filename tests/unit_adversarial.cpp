// Incident State Fabric - DCCP boundary 50
// Copyright 2026 Summon Software Labs.
// Licensed under the Apache License, Version 2.0.

#include <filesystem>
#include <string>
#include <system_error>
#include <vector>

#include "detail/platform.h"
#include "isf/isf.h"
#include "support/process_util.h"
#include "support/store_builder.h"
#include "test_framework.h"
#include "test_support.h"

using isftest::Fixture;
using isftest::Key;
using isftest::RackScope;
using isftest::ReportIncident;
using isftest::ScratchDir;
using isftest::StoreOptions;
using isftest::Utf8;

namespace {

/// A session plus a single FacilityDirector, so the crafted store can accept
/// requests without bootstrapping anything.
[[nodiscard]] isf::detail::Effect DirectorEffect(const isf::detail::State& state) {
  isf::detail::Effect effect;
  effect.op = isf::OpKind::RegisterAuthority;
  effect.actor = isf::AuthorityId{1};
  effect.key = Key(2);
  effect.authority = isf::AuthorityId{1};
  effect.authority_name = "director";
  effect.authority_role = isf::AuthorityRole::FacilityDirector;
  effect.authority_active = true;
  effect.next_authority_id = 2;
  effect.next_incident_id = state.next_incident_id;
  effect.next_evidence_id = state.next_evidence_id;
  return effect;
}

[[nodiscard]] isf::ErrorCode OpenCode(const isf::OpenOptions& options) {
  auto fabric = isf::IncidentFabric::Open(options);
  if (fabric.ok()) {
    (void)fabric.value()->Close();
    return isf::ErrorCode::Ok;
  }
  return fabric.status().code();
}

}  // namespace

ISF_TEST(Adversarial, CapacityLimitsAreEnforced) {
  ScratchDir dir("adv-limits");
  isf::OpenOptions options = StoreOptions(dir.path());
  options.limits.max_incidents = 2;
  options.limits.max_authorities = 2;
  options.limits.max_evidence_per_incident = 2;
  auto fabric = isf::IncidentFabric::Open(options);
  ISF_REQUIRE(fabric.ok());

  isf::RegisterAuthorityRequest bootstrap;
  bootstrap.header.actor.authority = isf::AuthorityId{};
  bootstrap.header.actor.epoch = isftest::CurrentEpoch(*fabric.value());
  bootstrap.header.key = Key(1);
  bootstrap.name = "director";
  bootstrap.role = isf::AuthorityRole::FacilityDirector;
  bootstrap.rationale = "bootstrap";
  ISF_REQUIRE(fabric.value()->RegisterAuthority(bootstrap).ok());

  isf::RegisterAuthorityRequest third;
  third.header = isftest::Header(*fabric.value(), isf::AuthorityId{1}, 2);
  third.name = "operator";
  third.role = isf::AuthorityRole::Operator;
  third.rationale = "third authority";
  ISF_REQUIRE(fabric.value()->RegisterAuthority(third).ok());

  isf::RegisterAuthorityRequest fourth;
  fourth.header = isftest::Header(*fabric.value(), isf::AuthorityId{1}, 3);
  fourth.name = "spare";
  fourth.role = isf::AuthorityRole::Operator;
  fourth.rationale = "beyond the authority limit";
  ISF_EXPECT_ERROR(fabric.value()->RegisterAuthority(fourth), isf::ErrorCode::ResourceExhausted);

  isf::ReportIncidentRequest report;
  report.header = isftest::Header(*fabric.value(), isf::AuthorityId{2}, 10);
  report.cls = isf::IncidentClass::Power;
  report.reported_severity = isf::Severity::Major;
  report.summary = "first";
  report.scope = RackScope("rack-z1");
  report.source_system = "synthetic";
  report.source_event_id = "adv-1";
  const auto first = fabric.value()->ReportIncident(report);
  ISF_REQUIRE(first.ok());

  report.header = isftest::Header(*fabric.value(), isf::AuthorityId{2}, 11);
  report.source_event_id = "adv-2";
  report.summary = "second";
  ISF_REQUIRE(fabric.value()->ReportIncident(report).ok());

  report.header = isftest::Header(*fabric.value(), isf::AuthorityId{2}, 12);
  report.source_event_id = "adv-3";
  report.summary = "third";
  ISF_EXPECT_ERROR(fabric.value()->ReportIncident(report), isf::ErrorCode::ResourceExhausted);

  // The report itself already occupies one evidence slot, so exactly one more
  // record fits before the configured limit of two is reached.
  const isf::IncidentId incident = first.value().incident;
  isf::RecordEvidenceRequest evidence;
  evidence.header = isftest::Header(*fabric.value(), isf::AuthorityId{2}, 20);
  evidence.incident = incident;
  evidence.expected_revision = isftest::RevisionOf(*fabric.value(), incident);
  evidence.kind = isf::EvidenceKind::Acknowledgement;
  evidence.rationale = "fills the second slot";
  ISF_REQUIRE(fabric.value()->RecordEvidence(evidence).ok());

  isf::RecordEvidenceRequest overflow;
  overflow.header = isftest::Header(*fabric.value(), isf::AuthorityId{2}, 30);
  overflow.incident = incident;
  overflow.expected_revision = isftest::RevisionOf(*fabric.value(), incident);
  overflow.kind = isf::EvidenceKind::Acknowledgement;
  overflow.rationale = "one too many";
  ISF_EXPECT_ERROR(fabric.value()->RecordEvidence(overflow), isf::ErrorCode::ResourceExhausted);

  ISF_REQUIRE(fabric.value()->Close().ok());
}

ISF_TEST(Adversarial, AllocatorExhaustionIsRefusedRatherThanWrapped) {
  {
    ScratchDir dir("adv-overflow-incident");
    ISF_REQUIRE(isftest::WriteStore(dir.path(), 2, [](const isf::detail::State& state,
                                                      std::size_t index) {
      if (index == 1) return DirectorEffect(state);
      isf::detail::Effect effect = isftest::SessionOpenEffect(state, 1, 1);
      effect.next_incident_id = UINT64_MAX;
      return effect;
    }));
    auto fabric = isf::IncidentFabric::Open(StoreOptions(dir.path()));
    ISF_REQUIRE(fabric.ok());
    isf::ReportIncidentRequest report;
    report.header = isftest::Header(*fabric.value(), isf::AuthorityId{1}, 1);
    report.cls = isf::IncidentClass::Power;
    report.reported_severity = isf::Severity::Major;
    report.summary = "beyond the allocator";
    report.scope = RackScope("rack-z2");
    ISF_EXPECT_ERROR(fabric.value()->ReportIncident(report), isf::ErrorCode::Overflow);
    ISF_REQUIRE(fabric.value()->Close().ok());
  }
  {
    ScratchDir dir("adv-overflow-evidence");
    ISF_REQUIRE(isftest::WriteStore(dir.path(), 2, [](const isf::detail::State& state,
                                                      std::size_t index) {
      if (index == 1) return DirectorEffect(state);
      isf::detail::Effect effect = isftest::SessionOpenEffect(state, 1, 1);
      effect.next_evidence_id = UINT64_MAX;
      return effect;
    }));
    auto fabric = isf::IncidentFabric::Open(StoreOptions(dir.path()));
    ISF_REQUIRE(fabric.ok());
    isf::ReportIncidentRequest report;
    report.header = isftest::Header(*fabric.value(), isf::AuthorityId{1}, 1);
    report.cls = isf::IncidentClass::Power;
    report.reported_severity = isf::Severity::Major;
    report.summary = "beyond the evidence allocator";
    report.scope = RackScope("rack-z3");
    ISF_EXPECT_ERROR(fabric.value()->ReportIncident(report), isf::ErrorCode::Overflow);
    ISF_REQUIRE(fabric.value()->Close().ok());
  }
  {
    ScratchDir dir("adv-overflow-epoch");
    ISF_REQUIRE(isftest::WriteStore(dir.path(), 1, [](const isf::detail::State& state,
                                                      std::size_t) {
      return isftest::SessionOpenEffect(state, 1, UINT64_MAX);
    }));
    // Open advances the epoch only for an unclean session, which this is, so the
    // increment itself must refuse rather than wrap.
    auto fabric = isf::IncidentFabric::Open(StoreOptions(dir.path()));
    ISF_REQUIRE(!fabric.ok());
    ISF_CHECK_EQ(fabric.status().code(), isf::ErrorCode::Overflow);
  }
  {
    // A store whose control epoch already sits at its maximum, left cleanly
    // closed, so that opening it succeeds and the next fence must refuse.
    ScratchDir dir("adv-overflow-fence");
    ISF_REQUIRE(isftest::WriteStore(dir.path(), 4, [](const isf::detail::State& state,
                                                      std::size_t index) {
      if (index == 0) {
        isf::detail::Effect effect = isftest::SessionOpenEffect(state, 1, 1);
        effect.next_authority_id = 1;
        return effect;
      }
      if (index == 1) {
        isf::detail::Effect effect;
        effect.op = isf::OpKind::RegisterAuthority;
        effect.actor = isf::AuthorityId{1};
        effect.key = Key(2);
        effect.authority = isf::AuthorityId{1};
        effect.authority_name = "director";
        effect.authority_role = isf::AuthorityRole::FacilityDirector;
        effect.authority_active = true;
        effect.next_authority_id = 2;
        effect.next_incident_id = state.next_incident_id;
        effect.next_evidence_id = state.next_evidence_id;
        return effect;
      }
      if (index == 2) {
        isf::detail::Effect effect;
        effect.op = isf::OpKind::ForceFence;
        effect.actor = isf::AuthorityId{1};
        effect.key = Key(3);
        effect.control_epoch_after = UINT64_MAX;
        effect.next_authority_id = state.next_authority_id;
        effect.next_incident_id = state.next_incident_id;
        effect.next_evidence_id = state.next_evidence_id;
        return effect;
      }
      isf::detail::Effect effect;
      effect.op = isf::OpKind::SessionClose;
      effect.actor = isf::AuthorityId{1};
      effect.session_open = false;
      effect.clean_close = true;
      effect.control_epoch_after = state.control_epoch.value;
      effect.next_authority_id = state.next_authority_id;
      effect.next_incident_id = state.next_incident_id;
      effect.next_evidence_id = state.next_evidence_id;
      return effect;
    }));
    auto fenced = isf::IncidentFabric::Open(StoreOptions(dir.path()));
    ISF_REQUIRE(fenced.ok());
    const auto status = fenced.value()->GetStatus();
    ISF_REQUIRE(status.ok());
    ISF_CHECK_EQ(status.value().control_epoch.value, UINT64_MAX);
    isf::ForceFenceRequest fence;
    fence.header = isftest::Header(*fenced.value(), isf::AuthorityId{1}, 5);
    fence.rationale = "epoch is exhausted";
    ISF_EXPECT_ERROR(fenced.value()->ForceFence(fence), isf::ErrorCode::Overflow);
    ISF_REQUIRE(fenced.value()->Close().ok());
  }
}

ISF_TEST(Adversarial, MalformedTextIsRefusedBeforeAnyDurableWork) {
  Fixture fixture("adv-text", isf::StateDigestPolicy::EveryCommit);

  isf::ReportIncidentRequest report;
  report.header = fixture.Header(fixture.operator_role);
  report.cls = isf::IncidentClass::Power;
  report.reported_severity = isf::Severity::Major;
  report.summary = "invalid utf8 in scope";
  report.scope.objects.push_back(
      isf::ObjectRef{isf::ObjectKind::Rack, std::string("rack-\xc3")});
  report.source_system = "synthetic";
  report.source_event_id = "bad-1";
  ISF_EXPECT_ERROR(fixture.fabric().ReportIncident(report), isf::ErrorCode::InvalidArgument);

  report.scope.objects.clear();
  report.scope = RackScope("rack-ok");
  report.summary = "control character";
  report.summary.push_back('\x07');
  ISF_EXPECT_ERROR(fixture.fabric().ReportIncident(report), isf::ErrorCode::InvalidArgument);

  report.summary = "too long";
  report.detail = std::string(isf::FieldLimits::kDetail + 1, 'd');
  ISF_EXPECT_ERROR(fixture.fabric().ReportIncident(report), isf::ErrorCode::InvalidArgument);

  report.detail.clear();
  report.source_system = "";
  report.source_event_id = "orphan";
  ISF_EXPECT_ERROR(fixture.fabric().ReportIncident(report), isf::ErrorCode::InvalidArgument);

  report.source_system = "synthetic";
  report.source_event_id = "";
  report.scope = isf::AffectedScope{};
  ISF_EXPECT_ERROR(fixture.fabric().ReportIncident(report), isf::ErrorCode::InvalidArgument);

  const auto status = fixture.fabric().GetStatus();
  ISF_REQUIRE(status.ok());
  ISF_CHECK_EQ(status.value().incident_count, std::uint64_t{0});
}

ISF_TEST(Adversarial, PathShapesAreValidatedBeforeTheFilesystemIsTouched) {
  // Relative paths resolve against the working directory.
  ScratchDir scratch("adv-path");
  const std::filesystem::path relative =
      std::filesystem::path(scratch.path()).lexically_relative(std::filesystem::current_path());
  if (!relative.empty() && !relative.native().empty()) {
    auto fabric = isf::IncidentFabric::Open(StoreOptions(isftest::Utf8(relative / "relative-store")));
    ISF_REQUIRE(fabric.ok());
    ISF_CHECK(!fabric.value()->GetStatus().value().store_path.empty());
    ISF_REQUIRE(fabric.value()->Close().ok());
  }

  const char* rejected[] = {"",
                            "   ",
                            "C:\\..\\escape",
                            "C:\\temp\\trailing. ",
                            "C:\\temp\\trailing.",
                            "\\\\server\\share\\store",
                            "\\\\?\\C:\\temp\\store",
                            "C:\\temp\\NUL",
                            "C:\\temp\\con",
                            "C:\\temp\\LPT1\\store"};
  for (const char* path : rejected) {
    isf::OpenOptions options;
    options.path = path;
    const isf::ErrorCode code = OpenCode(options);
    ISF_CHECK(code == isf::ErrorCode::UnsafePath || code == isf::ErrorCode::InvalidArgument);
  }
}

ISF_TEST(Adversarial, InvalidUnicodePathsAreRefused) {
  isf::OpenOptions options;
  // A lone high surrogate encoded as CESU-8 style bytes is not legal UTF-8 and
  // must not reach the filesystem layer.
  options.path = std::string("C:\\temp\\") + "\xed\xa0\x80";
  const isf::ErrorCode code = OpenCode(options);
  ISF_CHECK(code == isf::ErrorCode::InvalidArgument || code == isf::ErrorCode::UnsafePath);

  options.path = std::string("C:\\temp\\embedded") + '\0' + "nul";
  ISF_CHECK_EQ(OpenCode(options), isf::ErrorCode::InvalidArgument);
}

ISF_TEST(Adversarial, LongPathsAreSupported) {
  ScratchDir scratch("adv-longpath");
  std::filesystem::path deep = scratch.fs_path();
  for (int index = 0; index < 12; ++index) {
    deep /= ("segment-directory-" + std::to_string(index) + "-padding-padding");
  }
  const std::string path = Utf8(deep);
  ISF_CHECK(path.size() > 260);

  auto fabric = isf::IncidentFabric::Open(StoreOptions(path));
  ISF_REQUIRE(fabric.ok());
  isf::RegisterAuthorityRequest bootstrap;
  bootstrap.header.actor.authority = isf::AuthorityId{};
  bootstrap.header.actor.epoch = isftest::CurrentEpoch(*fabric.value());
  bootstrap.header.key = Key(1);
  bootstrap.name = "director";
  bootstrap.role = isf::AuthorityRole::FacilityDirector;
  bootstrap.rationale = "long path";
  ISF_REQUIRE(fabric.value()->RegisterAuthority(bootstrap).ok());
  ISF_REQUIRE(fabric.value()->Close().ok());

  auto reopened = isf::IncidentFabric::Open(StoreOptions(path));
  ISF_REQUIRE(reopened.ok());
  const auto status = reopened.value()->GetStatus();
  ISF_REQUIRE(status.ok());
  ISF_CHECK_EQ(status.value().authority_count, std::uint64_t{1});
  ISF_REQUIRE(reopened.value()->Close().ok());
}

ISF_TEST(Adversarial, ReparsePointRootsAreRefusedUnlessExplicitlyAllowed) {
  ScratchDir scratch("adv-reparse", isftest::TempScratchRoot());
  const std::string target = scratch.child("real-store");
  const std::string link = scratch.child("linked-store");

  auto fabric = isf::IncidentFabric::Open(StoreOptions(target));
  ISF_REQUIRE(fabric.ok());
  ISF_REQUIRE(fabric.value()->Close().ok());

  isftest::ChildProcess child;
  const std::vector<std::string> arguments{"/c", "mklink", "/J", link, target};
  if (!isftest::Spawn("C:\\Windows\\System32\\cmd.exe", arguments, {}, child)) {
    ISF_CHECK(false);
    return;
  }
  unsigned long exit_code = 0;
  isftest::WaitForExit(child, exit_code);
  isftest::CloseProcess(child);
  if (exit_code != 0) {
    // The environment could not create a junction, which is recorded rather
    // than silently treated as a pass.
    std::printf("    note: junction creation unavailable, exit code %lu\n", exit_code);
    return;
  }

  isf::OpenOptions strict = StoreOptions(link);
  ISF_CHECK_EQ(OpenCode(strict), isf::ErrorCode::UnsafePath);

  isf::OpenOptions relaxed = StoreOptions(link);
  relaxed.allow_reparse_root = true;
  auto linked = isf::IncidentFabric::Open(relaxed);
  ISF_REQUIRE(linked.ok());
  const auto status = linked.value()->GetStatus();
  ISF_REQUIRE(status.ok());
  ISF_REQUIRE(linked.value()->Close().ok());

  // The junction is removed with the scratch tree, so nothing is left in the
  // temporary directory by this proof.
  std::error_code error;
  std::filesystem::remove_all(isftest::TempScratchRoot(), error);
}

ISF_TEST(Adversarial, ASingleStoreCannotBeOpenedTwiceByOneProcess) {
  ScratchDir dir("adv-double-open");
  auto first = isf::IncidentFabric::Open(StoreOptions(dir.path()));
  ISF_REQUIRE(first.ok());
  ISF_EXPECT_ERROR(isf::IncidentFabric::Open(StoreOptions(dir.path())),
                   isf::ErrorCode::StoreLocked);
  ISF_REQUIRE(first.value()->Close().ok());
  auto second = isf::IncidentFabric::Open(StoreOptions(dir.path()));
  ISF_REQUIRE(second.ok());
  ISF_REQUIRE(second.value()->Close().ok());
}

ISF_TEST(Adversarial, ReadQueriesAreBoundedAndStable) {
  Fixture fixture("adv-queries", isf::StateDigestPolicy::EveryCommit);
  for (int index = 0; index < 5; ++index) {
    ReportIncident(fixture, "query incident " + std::to_string(index),
                   "rack-y" + std::to_string(index));
  }

  const auto all = fixture.fabric().ListIncidents(isf::ListQuery{0, 1000});
  ISF_REQUIRE(all.ok());
  ISF_CHECK_EQ(all.value().size(), std::size_t{5});
  for (std::size_t index = 1; index < all.value().size(); ++index) {
    ISF_CHECK(all.value()[index - 1].id < all.value()[index].id);
  }

  const auto page = fixture.fabric().ListIncidents(isf::ListQuery{2, 2});
  ISF_REQUIRE(page.ok());
  ISF_CHECK_EQ(page.value().size(), std::size_t{2});
  ISF_CHECK_EQ(page.value()[0].id, all.value()[2].id);

  const auto beyond = fixture.fabric().ListIncidents(isf::ListQuery{99, 10});
  ISF_REQUIRE(beyond.ok());
  ISF_CHECK(beyond.value().empty());

  // Limits above the documented page maximum are clamped rather than honoured.
  const auto clamped = fixture.fabric().ListIncidents(isf::ListQuery{0, 0xffffffffu});
  ISF_REQUIRE(clamped.ok());
  ISF_CHECK_EQ(clamped.value().size(), std::size_t{5});

  const auto rejected = fixture.fabric().ListIncidentsInState(isf::LifecycleState::Closed,
                                                              isf::ListQuery{0, 10});
  ISF_REQUIRE(rejected.ok());
  ISF_CHECK(rejected.value().empty());

  const auto missing = fixture.fabric().GetIncident(isf::IncidentId{999});
  ISF_EXPECT_ERROR(missing, isf::ErrorCode::NotFound);
  ISF_EXPECT_ERROR(fixture.fabric().GetEvidence(isf::EvidenceId{999}), isf::ErrorCode::NotFound);
  ISF_EXPECT_ERROR(fixture.fabric().GetAuthority(isf::AuthorityId{999}), isf::ErrorCode::NotFound);
  ISF_EXPECT_ERROR(fixture.fabric().GetLineage(isf::IncidentId{999}), isf::ErrorCode::NotFound);
}

ISF_TEST(Adversarial, OperationsOnTerminalIncidentsAreRefused) {
  Fixture fixture("adv-terminal", isf::StateDigestPolicy::EveryCommit);
  const isf::IncidentId incident = ReportIncident(fixture, "terminal", "rack-y9");

  isf::RejectReportRequest reject;
  reject.header = fixture.Header(fixture.manager);
  reject.incident = incident;
  reject.expected_revision = isftest::RevisionOf(fixture.fabric(), incident);
  reject.rationale = "not an incident";
  ISF_REQUIRE(fixture.fabric().RejectReport(reject).ok());

  isf::RecordEvidenceRequest evidence;
  evidence.header = fixture.Header(fixture.operator_role);
  evidence.incident = incident;
  evidence.expected_revision = isftest::RevisionOf(fixture.fabric(), incident);
  evidence.kind = isf::EvidenceKind::Acknowledgement;
  evidence.rationale = "after terminal";
  ISF_EXPECT_ERROR(fixture.fabric().RecordEvidence(evidence), isf::ErrorCode::IllegalTransition);

  isf::AmendScopeRequest scope;
  scope.header = fixture.Header(fixture.commander);
  scope.incident = incident;
  scope.expected_revision = isftest::RevisionOf(fixture.fabric(), incident);
  scope.scope = RackScope("rack-y8");
  scope.rationale = "after terminal";
  ISF_EXPECT_ERROR(fixture.fabric().AmendScope(scope), isf::ErrorCode::IllegalTransition);
}
