// Incident State Fabric - DCCP boundary 50
// Copyright 2026 Summon Software Labs.
// Licensed under the Apache License, Version 2.0.
//
// Benchmarks measure completed durable operations, not submission latency.
// Every reported commit is a commit whose bytes were flushed to the segment and
// whose manifest was staged, flushed, read back, verified, and atomically
// renamed. Provenance: REAL filesystem durability on the volume hosting the
// scratch directory, exercised through the Win32 API.

#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <string>

#include "isf/isf.h"

namespace {

using Clock = std::chrono::steady_clock;

[[nodiscard]] double SecondsSince(Clock::time_point start) {
  return std::chrono::duration<double>(Clock::now() - start).count();
}

[[nodiscard]] isf::MutationHeader Header(const isf::IncidentFabric& fabric,
                                         isf::AuthorityId authority, std::uint64_t counter,
                                         std::uint64_t salt) {
  const auto status = fabric.GetStatus();
  isf::MutationHeader header;
  header.actor.authority = authority;
  header.actor.epoch = status.ok() ? status.value().control_epoch : isf::ControlEpoch{};
  header.key = isf::IdempotencyKey{0xabcdef0123456789ull ^ salt, counter};
  return header;
}

struct Setup {
  isf::IncidentFabricPtr fabric;
  isf::AuthorityId director;
  isf::AuthorityId operator_role;
};

[[nodiscard]] bool Bootstrap(Setup& setup) {
  isf::RegisterAuthorityRequest bootstrap;
  bootstrap.header.actor.authority = isf::AuthorityId{};
  const auto status = setup.fabric->GetStatus();
  bootstrap.header.actor.epoch = status.ok() ? status.value().control_epoch : isf::ControlEpoch{};
  bootstrap.header.key = isf::IdempotencyKey{0xabcdef0123456789ull ^ 0xfull, 1};
  bootstrap.name = "bench-director";
  bootstrap.role = isf::AuthorityRole::FacilityDirector;
  bootstrap.rationale = "benchmark bootstrap";
  auto receipt = setup.fabric->RegisterAuthority(bootstrap);
  if (!receipt.ok()) return false;
  setup.director = receipt.value().authority;

  isf::RegisterAuthorityRequest create;
  create.header = Header(*setup.fabric, setup.director, 2, 0xfull);
  create.name = "bench-operator";
  create.role = isf::AuthorityRole::Operator;
  create.rationale = "benchmark bootstrap";
  receipt = setup.fabric->RegisterAuthority(create);
  if (!receipt.ok()) return false;
  setup.operator_role = receipt.value().authority;
  return true;
}

struct CommitResult {
  double seconds = 0.0;
  std::uint64_t commits = 0;
  std::uint64_t generation = 0;
  std::uint64_t incidents = 0;
};

[[nodiscard]] bool RunCommitWorkload(const std::string& path, const char* label,
                                     std::uint64_t commits, isf::StateDigestPolicy policy,
                                     CommitResult& result) {
  isf::OpenOptions options;
  options.path = path;
  options.create_if_missing = true;
  options.state_digest = policy;
  auto fabric = isf::IncidentFabric::Open(options);
  if (!fabric.ok()) {
    std::printf("  %s: open failed: %s\n", label, fabric.status().ToString().c_str());
    return false;
  }
  Setup setup;
  setup.fabric = std::move(fabric).value();
  if (!Bootstrap(setup)) {
    std::printf("  %s: bootstrap failed\n", label);
    return false;
  }

  const Clock::time_point start = Clock::now();
  for (std::uint64_t index = 0; index < commits; ++index) {
    isf::ReportIncidentRequest request;
    request.header = Header(*setup.fabric, setup.operator_role, index + 10, 0xfull);
    request.cls = isf::IncidentClass::Power;
    request.reported_severity = isf::Severity::Major;
    request.summary = "benchmark incident " + std::to_string(index);
    request.scope.objects.push_back(
        isf::ObjectRef{isf::ObjectKind::Rack, "rack-" + std::to_string(index % 256)});
    request.source_system = "isfbench";
    request.source_event_id = "bench-" + std::to_string(index);
    request.detail = "synthetic benchmark report";
    const auto receipt = setup.fabric->ReportIncident(request);
    if (!receipt.ok()) {
      std::printf("  %s: commit %llu failed: %s\n", label,
                  static_cast<unsigned long long>(index), receipt.status().ToString().c_str());
      return false;
    }
  }
  result.seconds = SecondsSince(start);
  result.commits = commits;
  const auto status = setup.fabric->GetStatus();
  if (!status.ok()) return false;
  result.generation = status.value().generation.value();
  result.incidents = status.value().incident_count;
  const auto closed = setup.fabric->Close();
  return closed.ok();
}

[[nodiscard]] bool MeasureReplay(const std::string& path, double& seconds, std::uint64_t& records) {
  isf::OpenOptions options;
  options.path = path;
  options.create_if_missing = false;
  const Clock::time_point start = Clock::now();
  auto fabric = isf::IncidentFabric::Open(options);
  seconds = SecondsSince(start);
  if (!fabric.ok()) {
    std::printf("  reopen failed: %s\n", fabric.status().ToString().c_str());
    return false;
  }
  const auto status = fabric.value()->GetStatus();
  records = status.ok() ? status.value().record_count : 0;
  const auto closed = fabric.value()->Close();
  return closed.ok();
}

[[nodiscard]] bool MeasureReads(const std::string& path, std::uint64_t reads, double& seconds_get,
                                double& seconds_list) {
  isf::OpenOptions options;
  options.path = path;
  options.create_if_missing = false;
  auto fabric = isf::IncidentFabric::Open(options);
  if (!fabric.ok()) return false;

  const auto listed = fabric.value()->ListIncidents(isf::ListQuery{0, 1000});
  if (!listed.ok() || listed.value().empty()) return false;
  const std::size_t count = listed.value().size();

  std::uint64_t checksum = 0;
  Clock::time_point start = Clock::now();
  for (std::uint64_t index = 0; index < reads; ++index) {
    const isf::IncidentId id = listed.value()[static_cast<std::size_t>(index % count)].id;
    const auto view = fabric.value()->GetIncident(id);
    if (!view.ok()) return false;
    checksum += view.value().revision;
  }
  seconds_get = SecondsSince(start);

  start = Clock::now();
  for (std::uint64_t index = 0; index < reads; ++index) {
    const auto page = fabric.value()->ListIncidents(isf::ListQuery{0, 1000});
    if (!page.ok()) return false;
    checksum += page.value().size();
  }
  seconds_list = SecondsSince(start);

  const auto closed = fabric.value()->Close();
  if (checksum == 0xffffffffffffffffull) std::printf(" ");
  return closed.ok();
}

}  // namespace

int main(int argc, char** argv) {
  std::uint64_t commits = 2000;
  if (argc > 1) {
    commits = std::strtoull(argv[1], nullptr, 10);
    if (commits == 0 || commits > 200000) commits = 2000;
  }

  std::printf("Incident State Fabric %s benchmark\n", isf::VersionString());
  std::printf("provenance: REAL durability on the local filesystem; SYNTHETIC facility workload\n");
  std::printf("durability per commit: segment write + FlushFileBuffers + staged manifest write +\n");
  std::printf("  FlushFileBuffers + read-back verification + atomic MoveFileExW publish\n");
  std::printf("workload: %llu reported incidents, single writer, one rack per incident\n\n",
              static_cast<unsigned long long>(commits));

  const std::string scratch = "isfbench-scratch";
  const std::string every = scratch + "-every";
  const std::string checkpoint = scratch + "-checkpoint";

  CommitResult full;
  CommitResult lazy;
  if (!RunCommitWorkload(every, "digest=EveryCommit", commits, isf::StateDigestPolicy::EveryCommit,
                         full)) {
    return 1;
  }
  if (!RunCommitWorkload(checkpoint, "digest=OnCheckpoint", commits,
                         isf::StateDigestPolicy::OnCheckpoint, lazy)) {
    return 1;
  }

  std::printf("durable commit throughput\n");
  std::printf("  EveryCommit   %8.3f s  %10.1f commits/s  %8.3f ms/commit  incidents=%llu\n",
              full.seconds, static_cast<double>(full.commits) / full.seconds,
              1000.0 * full.seconds / static_cast<double>(full.commits),
              static_cast<unsigned long long>(full.incidents));
  std::printf("  OnCheckpoint  %8.3f s  %10.1f commits/s  %8.3f ms/commit  incidents=%llu\n",
              lazy.seconds, static_cast<double>(lazy.commits) / lazy.seconds,
              1000.0 * lazy.seconds / static_cast<double>(lazy.commits),
              static_cast<unsigned long long>(lazy.incidents));

  double replay_every = 0.0;
  double replay_checkpoint = 0.0;
  std::uint64_t records_every = 0;
  std::uint64_t records_checkpoint = 0;
  std::printf("\nrecovery: decode, verify the digest chain, reapply the log, verify the checkpoint\n");
  if (!MeasureReplay(every, replay_every, records_every)) return 1;
  std::printf("  EveryCommit   %8.3f s  records=%llu  %10.1f records/s\n", replay_every,
              static_cast<unsigned long long>(records_every),
              static_cast<double>(records_every) / replay_every);
  if (!MeasureReplay(checkpoint, replay_checkpoint, records_checkpoint)) return 1;
  std::printf("  OnCheckpoint  %8.3f s  records=%llu  %10.1f records/s\n", replay_checkpoint,
              static_cast<unsigned long long>(records_checkpoint),
              static_cast<double>(records_checkpoint) / replay_checkpoint);

  double seconds_get = 0.0;
  double seconds_list = 0.0;
  constexpr std::uint64_t kReads = 20000;
  if (!MeasureReads(every, kReads, seconds_get, seconds_list)) return 1;
  std::printf("\nreads over %llu iterations\n", static_cast<unsigned long long>(kReads));
  std::printf("  GetIncident   %8.3f s  %10.1f reads/s\n", seconds_get,
              static_cast<double>(kReads) / seconds_get);
  std::printf("  ListIncidents %8.3f s  %10.1f reads/s (page of 1000)\n", seconds_list,
              static_cast<double>(kReads) / seconds_list);

  std::printf("\nscratch stores written under the working directory: %s, %s\n", every.c_str(),
              checkpoint.c_str());
  return 0;
}
