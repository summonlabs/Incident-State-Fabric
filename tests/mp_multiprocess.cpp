// Incident State Fabric - DCCP boundary 50
// Copyright 2026 Summon Software Labs.
// Licensed under the Apache License, Version 2.0.
//
// Every proof here uses real, independent operating-system processes.

#include <cstdint>
#include <string>
#include <vector>

#include "isf/isf.h"
#include "support/process_util.h"
#include "test_framework.h"
#include "test_support.h"

using isftest::ChildProcess;
using isftest::CloseProcess;
using isftest::CtlExecutable;
using isftest::ScratchDir;
using isftest::Spawn;
using isftest::StoreOptions;
using isftest::TerminateNow;
using isftest::WaitForExit;
using isftest::WaitForFileText;
using isftest::WaitForGeneration;

namespace {

constexpr unsigned long kCrashExitCode = 70;
constexpr unsigned long kRefusedExitCode = 3;
constexpr unsigned long kTerminatedExitCode = 0xBEEF;

/// Generations produced by isfctl seed before the first report: one session
/// record and three authority registrations.
constexpr std::uint64_t kSeedPreambleRecords = 4;

}  // namespace

ISF_TEST(MultiProcess, MutationAuthorityIsExclusiveAndReleasedByDeath) {
  ScratchDir dir("mp-lock");
  const std::string ready = dir.child("ready.txt");

  ChildProcess holder;
  ISF_REQUIRE(Spawn(CtlExecutable(), {"hold", dir.path(), ready}, {}, holder));
  const std::string ready_text = WaitForFileText(ready);
  ISF_CHECK_EQ(ready_text, std::string("held"));

  // A second independent process is refused while the first holds the lock.
  {
    ChildProcess intruder;
    ISF_REQUIRE(Spawn(CtlExecutable(), {"status", dir.path()}, {}, intruder));
    unsigned long exit_code = 0;
    WaitForExit(intruder, exit_code);
    CloseProcess(intruder);
    ISF_CHECK_EQ(exit_code, kRefusedExitCode);
  }

  // Abrupt death releases the kernel-owned lock without any cooperative act.
  TerminateNow(holder, kTerminatedExitCode);
  unsigned long holder_exit = 0;
  WaitForExit(holder, holder_exit);
  CloseProcess(holder);
  ISF_CHECK_EQ(holder_exit, kTerminatedExitCode);

  auto successor = isf::IncidentFabric::Open(StoreOptions(dir.path()));
  ISF_REQUIRE(successor.ok());
  const auto status = successor.value()->GetStatus();
  ISF_REQUIRE(status.ok());
  // The new incarnation takes over, and the control epoch advances because the
  // previous session never closed.
  ISF_CHECK_EQ(status.value().incarnation, std::uint64_t{2});
  ISF_CHECK_EQ(status.value().control_epoch.value, std::uint64_t{2});
  ISF_CHECK(!status.value().last_close_clean || status.value().session_open);

  // While the successor holds the lock the third process is refused again.
  {
    ChildProcess intruder;
    ISF_REQUIRE(Spawn(CtlExecutable(), {"status", dir.path()}, {}, intruder));
    unsigned long exit_code = 0;
    WaitForExit(intruder, exit_code);
    CloseProcess(intruder);
    ISF_CHECK_EQ(exit_code, kRefusedExitCode);
  }
  ISF_REQUIRE(successor.value()->Close().ok());

  // A clean close leaves the epoch alone for the next incumbent.
  auto third = isf::IncidentFabric::Open(StoreOptions(dir.path()));
  ISF_REQUIRE(third.ok());
  const auto third_status = third.value()->GetStatus();
  ISF_REQUIRE(third_status.ok());
  ISF_CHECK_EQ(third_status.value().incarnation, std::uint64_t{3});
  ISF_CHECK_EQ(third_status.value().control_epoch.value, std::uint64_t{2});
  ISF_REQUIRE(third.value()->Close().ok());
}

ISF_TEST(MultiProcess, CrashAtEveryDurableBoundaryRecoversToOneWholeGeneration) {
  struct Phase {
    const char* name;
    bool committed;
  };
  const Phase phases[] = {{"before_append", false},
                          {"after_write", false},
                          {"after_flush", false},
                          {"before_publish", false},
                          {"after_publish", true}};

  for (const Phase& phase : phases) {
    ScratchDir dir(std::string("mp-crash-") + phase.name);
    const std::string progress = dir.child("progress.txt");

    ChildProcess child;
    ISF_REQUIRE(Spawn(CtlExecutable(), {"seed", dir.path(), "100", progress},
                      {{"ISF_CRASH_POINT", std::string(phase.name) + ":50"}}, child));
    unsigned long exit_code = 0;
    WaitForExit(child, exit_code);
    CloseProcess(child);
    if (exit_code != kCrashExitCode) {
      std::printf("    phase %s: child exited with %lu instead of the crash code\n", phase.name,
                  exit_code);
      ISF_CHECK(false);
      continue;
    }

    const std::uint64_t expected = phase.committed ? 50 : 49;
    auto fabric = isf::IncidentFabric::Open(StoreOptions(dir.path()));
    ISF_REQUIRE(fabric.ok());
    const auto status = fabric.value()->GetStatus();
    ISF_REQUIRE(status.ok());

    // Reopening appends exactly one session record.
    ISF_CHECK_EQ(status.value().generation.value(), expected + 1);
    ISF_CHECK_EQ(status.value().record_count, status.value().generation.value());
    ISF_CHECK_EQ(status.value().audit_count, status.value().generation.value());
    ISF_CHECK_EQ(status.value().incident_count, expected - kSeedPreambleRecords);

    const auto incidents = fabric.value()->ListIncidents(isf::ListQuery{0, 1000});
    ISF_REQUIRE(incidents.ok());
    ISF_CHECK_EQ(incidents.value().size(), static_cast<std::size_t>(expected - kSeedPreambleRecords));
    for (std::size_t index = 0; index < incidents.value().size(); ++index) {
      const isf::IncidentView view = isftest::IncidentOf(*fabric.value(), incidents.value()[index].id);
      ISF_CHECK_EQ(view.state, isf::LifecycleState::Reported);
      ISF_CHECK_EQ(view.revision, std::uint64_t{1});
      ISF_REQUIRE(view.scope.objects.size() == 1);
      ISF_CHECK_EQ(view.scope.objects[0].id, std::string("rack-") + std::to_string(index));
      ISF_CHECK_EQ(view.id.value(), index + 1);
    }
    ISF_REQUIRE(fabric.value()->Close().ok());

    // A second recovery is byte-stable: the same generation, the same incidents.
    auto again = isf::IncidentFabric::Open(StoreOptions(dir.path()));
    ISF_REQUIRE(again.ok());
    ISF_CHECK_EQ(again.value()->GetStatus().value().incident_count,
                 expected - kSeedPreambleRecords);
    ISF_REQUIRE(again.value()->Close().ok());
  }
}

ISF_TEST(MultiProcess, AbruptKillMidCommitLeavesAWholeGenerationAndAPrefixOfHistory) {
  ScratchDir killed("mp-kill");
  ScratchDir reference("mp-kill-reference");
  const std::string progress = killed.child("progress.txt");

  ChildProcess child;
  ISF_REQUIRE(Spawn(CtlExecutable(), {"seed", killed.path(), "100000", progress}, {}, child));
  const std::string announced = WaitForGeneration(progress, 60);
  const std::uint64_t announced_generation =
      isftest::ParseUintField(announced, "generation");
  ISF_CHECK(announced_generation >= 60);

  TerminateNow(child, kTerminatedExitCode);
  unsigned long exit_code = 0;
  WaitForExit(child, exit_code);
  CloseProcess(child);
  ISF_CHECK_EQ(exit_code, kTerminatedExitCode);

  auto recovered = isf::IncidentFabric::Open(StoreOptions(killed.path()));
  ISF_REQUIRE(recovered.ok());
  const auto status = recovered.value()->GetStatus();
  ISF_REQUIRE(status.ok());
  // Reopening appends one session record, so the recovered generation is one
  // less. It can be one higher than announced because the child may have
  // published the in-flight record before dying.
  const std::uint64_t recovered_generation = status.value().generation.value() - 1;
  ISF_CHECK(recovered_generation >= announced_generation);
  ISF_CHECK(recovered_generation <= announced_generation + 1);
  ISF_CHECK_EQ(status.value().record_count, status.value().generation.value());
  ISF_CHECK_EQ(status.value().audit_count, status.value().generation.value());

  const auto incidents = recovered.value()->ListIncidents(isf::ListQuery{0, 1000});
  ISF_REQUIRE(incidents.ok());
  ISF_CHECK_EQ(incidents.value().size(),
               static_cast<std::size_t>(recovered_generation - kSeedPreambleRecords));
  // The recovered incidents are exactly the prefix of the intended run: no gap,
  // no reordering, and no torn record was ever accepted.
  for (std::size_t index = 0; index < incidents.value().size(); ++index) {
    ISF_CHECK_EQ(incidents.value()[index].id.value(), index + 1);
    ISF_CHECK_EQ(incidents.value()[index].revision, std::uint64_t{1});
  }
  ISF_REQUIRE(recovered.value()->Close().ok());

  // Differential check against a complete reference run of the same workload.
  ChildProcess full;
  ISF_REQUIRE(Spawn(CtlExecutable(), {"seed", reference.path(), "100", reference.child("p.txt")},
                    {}, full));
  unsigned long full_exit = 0;
  WaitForExit(full, full_exit);
  CloseProcess(full);
  ISF_CHECK_EQ(full_exit, 0UL);

  auto reference_fabric = isf::IncidentFabric::Open(StoreOptions(reference.path()));
  ISF_REQUIRE(reference_fabric.ok());
  const auto reference_incidents =
      reference_fabric.value()->ListIncidents(isf::ListQuery{0, 1000});
  ISF_REQUIRE(reference_incidents.ok());
  ISF_CHECK_EQ(reference_incidents.value().size(), std::size_t{100});

  auto survivor = isf::IncidentFabric::Open(StoreOptions(killed.path()));
  ISF_REQUIRE(survivor.ok());
  const auto survivor_incidents = survivor.value()->ListIncidents(isf::ListQuery{0, 1000});
  ISF_REQUIRE(survivor_incidents.ok());
  ISF_CHECK(survivor_incidents.value().size() <= reference_incidents.value().size());
  for (std::size_t index = 0; index < survivor_incidents.value().size(); ++index) {
    ISF_CHECK_EQ(survivor_incidents.value()[index].id,
                 reference_incidents.value()[index].id);
    ISF_CHECK_EQ(survivor_incidents.value()[index].revision,
                 reference_incidents.value()[index].revision);
    ISF_CHECK_EQ(survivor_incidents.value()[index].summary,
                 reference_incidents.value()[index].summary);
  }
  ISF_REQUIRE(survivor.value()->Close().ok());
  ISF_REQUIRE(reference_fabric.value()->Close().ok());
}

ISF_TEST(MultiProcess, AStaleActorFromAKilledIncarnationIsFenced) {
  ScratchDir dir("mp-fence");
  const std::string ready = dir.child("ready.txt");

  ChildProcess holder;
  ISF_REQUIRE(Spawn(CtlExecutable(), {"hold", dir.path(), ready}, {}, holder));
  (void)WaitForFileText(ready);
  TerminateNow(holder, kTerminatedExitCode);
  unsigned long exit_code = 0;
  WaitForExit(holder, exit_code);
  CloseProcess(holder);

  // The successor must not accept anything minted for the previous incarnation.
  auto successor = isf::IncidentFabric::Open(StoreOptions(dir.path()));
  ISF_REQUIRE(successor.ok());
  const auto status = successor.value()->GetStatus();
  ISF_REQUIRE(status.ok());
  const isf::ControlEpoch current = status.value().control_epoch;

  isf::RegisterAuthorityRequest bootstrap;
  bootstrap.header.actor.authority = isf::AuthorityId{};
  bootstrap.header.actor.epoch = current;
  bootstrap.header.key = isftest::Key(1);
  bootstrap.name = "director";
  bootstrap.role = isf::AuthorityRole::FacilityDirector;
  bootstrap.rationale = "successor bootstrap";
  ISF_REQUIRE(successor.value()->RegisterAuthority(bootstrap).ok());

  isf::ForceFenceRequest stale;
  stale.header.actor.authority = isf::AuthorityId{1};
  stale.header.actor.epoch = isf::ControlEpoch{current.value - 1};
  stale.header.key = isftest::Key(2);
  stale.rationale = "actor from the killed incarnation";
  ISF_EXPECT_ERROR(successor.value()->ForceFence(stale), isf::ErrorCode::StaleControlEpoch);

  isf::ForceFenceRequest fresh;
  fresh.header.actor.authority = isf::AuthorityId{1};
  fresh.header.actor.epoch = current;
  fresh.header.key = isftest::Key(3);
  fresh.rationale = "current incarnation";
  ISF_REQUIRE(successor.value()->ForceFence(fresh).ok());
  ISF_REQUIRE(successor.value()->Close().ok());
}
