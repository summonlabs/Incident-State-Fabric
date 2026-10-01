// Incident State Fabric - DCCP boundary 50
// Copyright 2026 Summon Software Labs.
// Licensed under the Apache License, Version 2.0.
//
// A small command line driver. It is used by the documentation examples and as
// the independent second process in the multiprocess and crash proofs.

#include <cstdio>
#include <cstring>
#include <fstream>
#include <string>
#include <vector>

#include <windows.h>

#include "isf/isf.h"

namespace {

void Print(const std::string& text) {
  std::fputs(text.c_str(), stdout);
  std::fputc('\n', stdout);
  std::fflush(stdout);
}

[[nodiscard]] std::string StatusLine(const isf::IncidentFabric& fabric) {
  const auto status = fabric.GetStatus();
  if (!status.ok()) return "error=" + std::string(isf::ToString(status.status().code()));
  const isf::FabricStatus& value = status.value();
  std::string line = "ok generation=" + std::to_string(value.generation.value());
  line += " epoch=" + std::to_string(value.control_epoch.value);
  line += " incarnation=" + std::to_string(value.incarnation);
  line += " incidents=" + std::to_string(value.incident_count);
  line += " evidence=" + std::to_string(value.evidence_count);
  line += " authorities=" + std::to_string(value.authority_count);
  line += " audit=" + std::to_string(value.audit_count);
  line += " records=" + std::to_string(value.record_count);
  line += " segments=" + std::to_string(value.segment_count);
  line += " session_open=" + std::string(value.session_open ? "1" : "0");
  line += " digest=" + value.state_digest_hex;
  return line;
}

[[nodiscard]] isf::OpenOptions Options(const std::string& path) {
  isf::OpenOptions options;
  options.path = path;
  options.create_if_missing = true;
  return options;
}

[[nodiscard]] int Fail(const std::string& message, int code) {
  Print(message);
  return code;
}

// ---------------------------------------------------------------------------
// Authorities
// ---------------------------------------------------------------------------

struct Roles {
  isf::AuthorityId director;
  isf::AuthorityId commander;
  isf::AuthorityId operator_role;
  std::uint64_t counter = 1;
};

[[nodiscard]] isf::MutationHeader Header(const isf::IncidentFabric& fabric,
                                         isf::AuthorityId authority, std::uint64_t counter) {
  isf::MutationHeader header;
  header.actor.authority = authority;
  const auto status = fabric.GetStatus();
  header.actor.epoch = status.ok() ? status.value().control_epoch : isf::ControlEpoch{};
  header.key = isf::IdempotencyKey{0x1111222233334444ull, counter};
  return header;
}

[[nodiscard]] bool EnsureRoles(isf::IncidentFabric& fabric, Roles& roles) {
  std::vector<isf::AuthorityView> existing;
  const auto listed = fabric.ListAuthorities(isf::ListQuery{0, 1000});
  if (!listed.ok()) return false;
  for (const isf::AuthorityView& view : listed.value()) {
    if (!view.active) continue;
    if (view.role == isf::AuthorityRole::FacilityDirector && !roles.director.valid()) {
      roles.director = view.id;
    } else if (view.role == isf::AuthorityRole::Operator && !roles.operator_role.valid()) {
      roles.operator_role = view.id;
    } else if (view.role == isf::AuthorityRole::IncidentCommander && !roles.commander.valid()) {
      roles.commander = view.id;
    }
  }

  if (!roles.director.valid()) {
    isf::RegisterAuthorityRequest bootstrap;
    bootstrap.header.actor.authority = isf::AuthorityId{};
    const auto status = fabric.GetStatus();
    bootstrap.header.actor.epoch = status.ok() ? status.value().control_epoch : isf::ControlEpoch{};
    bootstrap.header.key = isf::IdempotencyKey{0x1111222233334444ull, roles.counter++};
    bootstrap.name = "isfctl-director";
    bootstrap.role = isf::AuthorityRole::FacilityDirector;
    bootstrap.rationale = "isfctl bootstrap";
    const auto receipt = fabric.RegisterAuthority(bootstrap);
    if (!receipt.ok()) {
      Print("error=" + std::string(isf::ToString(receipt.status().code())) + " " +
            receipt.status().message());
      return false;
    }
    roles.director = receipt.value().authority;
  }

  const struct {
    isf::AuthorityId* slot;
    const char* name;
    isf::AuthorityRole role;
  } kNeeded[] = {{&roles.commander, "isfctl-commander", isf::AuthorityRole::IncidentCommander},
                 {&roles.operator_role, "isfctl-operator", isf::AuthorityRole::Operator}};
  for (const auto& need : kNeeded) {
    if (need.slot->valid()) continue;
    isf::RegisterAuthorityRequest request;
    request.header = Header(fabric, roles.director, roles.counter++);
    request.name = need.name;
    request.role = need.role;
    request.rationale = "isfctl bootstrap";
    const auto receipt = fabric.RegisterAuthority(request);
    if (!receipt.ok()) {
      Print("error=" + std::string(isf::ToString(receipt.status().code())) + " " +
            receipt.status().message());
      return false;
    }
    *need.slot = receipt.value().authority;
  }
  return true;
}

// ---------------------------------------------------------------------------
// Commands
// ---------------------------------------------------------------------------

[[nodiscard]] int CommandStatus(const std::string& path) {
  auto fabric = isf::IncidentFabric::Open(Options(path));
  if (!fabric.ok()) return Fail("error=" + std::string(isf::ToString(fabric.status().code())), 3);
  Print(StatusLine(*fabric.value()));
  const auto closed = fabric.value()->Close();
  return closed.ok() ? 0 : 3;
}

[[nodiscard]] int CommandHold(const std::string& path, const std::string& ready_file) {
  auto fabric = isf::IncidentFabric::Open(Options(path));
  if (!fabric.ok()) return Fail("error=" + std::string(isf::ToString(fabric.status().code())), 3);
  {
    std::ofstream ready(ready_file, std::ios::binary | std::ios::trunc);
    if (!ready) return Fail("error=ready_file", 3);
    ready << "held";
    ready.flush();
  }
  Print(StatusLine(*fabric.value()));
  for (;;) ::Sleep(20);
}

[[nodiscard]] int CommandSeed(const std::string& path, std::uint64_t count,
                              const std::string& progress_file) {
  auto fabric = isf::IncidentFabric::Open(Options(path));
  if (!fabric.ok()) return Fail("error=" + std::string(isf::ToString(fabric.status().code())), 3);
  Roles roles;
  if (!EnsureRoles(*fabric.value(), roles)) return 3;

  // Report keys live in a disjoint range from the bootstrap keys, so a seeded
  // store never reuses a key for a different operation.
  for (std::uint64_t index = 0; index < count; ++index) {
    isf::ReportIncidentRequest request;
    request.header = Header(*fabric.value(), roles.operator_role, 0x50000000ull + index + 1);
    request.cls = isf::IncidentClass::Power;
    request.reported_severity = isf::Severity::Major;
    request.summary = "seeded incident " + std::to_string(index);
    request.scope.objects.push_back(
        isf::ObjectRef{isf::ObjectKind::Rack, "rack-" + std::to_string(index)});
    request.source_system = "isfctl";
    request.source_event_id = "seed-" + std::to_string(index);
    request.detail = "synthetic seeded report";
    const auto receipt = fabric.value()->ReportIncident(request);
    if (!receipt.ok()) {
      return Fail("error=" + std::string(isf::ToString(receipt.status().code())) + " " +
                      receipt.status().message(),
                  3);
    }
    if (!progress_file.empty()) {
      const auto status = fabric.value()->GetStatus();
      if (status.ok()) {
        std::string line = "generation=" + std::to_string(status.value().generation.value());
        line += " incidents=" + std::to_string(status.value().incident_count);
        std::ofstream progress(progress_file, std::ios::binary | std::ios::trunc);
        if (progress) {
          progress << line;
          progress.flush();
        }
      }
    }
  }

  Print(StatusLine(*fabric.value()));
  const auto closed = fabric.value()->Close();
  return closed.ok() ? 0 : 3;
}

}  // namespace

int main(int argc, char** argv) {
  if (argc < 3) {
    Print("usage: isfctl <status|hold|seed> <store> [args]");
    return 2;
  }
  const std::string command(argv[1]);
  const std::string store(argv[2]);
  if (command == "status" || command == "open") return CommandStatus(store);
  if (command == "hold" && argc >= 4) return CommandHold(store, argv[3]);
  if (command == "seed" && argc >= 5) {
    return CommandSeed(store, std::strtoull(argv[3], nullptr, 10), argv[4]);
  }
  Print("usage: isfctl <status|hold|seed> <store> [args]");
  return 2;
}
