// Incident State Fabric - DCCP boundary 50
// Copyright 2026 Summon Software Labs.
// Licensed under the Apache License, Version 2.0.

#include "test_support.h"

#include <atomic>
#include <stdexcept>
#include <system_error>
#include <utility>

namespace isftest {
namespace {

std::atomic<std::uint64_t> g_scratch_counter{0};

[[nodiscard]] std::filesystem::path MakeScratchRoot() {
  const std::filesystem::path base = std::filesystem::current_path() / "scratch";
  std::error_code error;
  std::filesystem::create_directories(base, error);
  return base;
}

void RemoveTreeQuietly(const std::filesystem::path& path) {
  std::error_code error;
  std::filesystem::remove_all(path, error);
}

[[nodiscard]] isf::IncidentFabricPtr OpenOrThrow(const std::string& path,
                                                 isf::StateDigestPolicy policy) {
  auto fabric = isf::IncidentFabric::Open(StoreOptions(path, policy));
  if (!fabric.ok()) {
    throw std::runtime_error("could not open the scratch store: " + fabric.status().ToString());
  }
  return std::move(fabric).value();
}

[[nodiscard]] isf::AuthorityId RegisterRole(isf::IncidentFabric& fabric,
                                            isf::AuthorityId registrar, const char* name,
                                            isf::AuthorityRole role, std::uint64_t counter) {
  isf::RegisterAuthorityRequest request;
  request.header = Header(fabric, registrar, counter);
  request.name = name;
  request.role = role;
  request.rationale = "fixture role";
  const auto receipt = fabric.RegisterAuthority(request);
  if (!receipt.ok()) {
    throw std::runtime_error(std::string("could not register fixture role ") + name + ": " +
                             receipt.status().ToString());
  }
  return receipt.value().authority;
}

}  // namespace

const std::filesystem::path& ScratchRoot() {
  static const std::filesystem::path root = MakeScratchRoot();
  return root;
}

std::string Utf8(const std::filesystem::path& path) {
  const std::u8string text = path.u8string();
  return std::string(reinterpret_cast<const char*>(text.data()), text.size());
}

const std::filesystem::path& TempScratchRoot() {
  static const std::filesystem::path root = [] {
    std::error_code error;
    const std::filesystem::path base = std::filesystem::temp_directory_path(error) / "isf-tests";
    if (error) return std::filesystem::path();
    std::filesystem::create_directories(base, error);
    return error ? std::filesystem::path() : base;
  }();
  return root.empty() ? ScratchRoot() : root;
}

ScratchDir::ScratchDir(const std::string& tag) : ScratchDir(tag, ScratchRoot()) {}

ScratchDir::ScratchDir(const std::string& tag, const std::filesystem::path& base) {
  const std::uint64_t counter = ++g_scratch_counter;
  fs_path_ = base / (tag + "-" + std::to_string(counter));
  RemoveTreeQuietly(fs_path_);
  std::error_code error;
  std::filesystem::create_directories(fs_path_, error);
  path_ = Utf8(fs_path_);
}

ScratchDir::~ScratchDir() { RemoveTreeQuietly(fs_path_); }

std::string ScratchDir::child(const std::string& name) const { return Utf8(fs_path_ / name); }

isf::IdempotencyKey Key(std::uint64_t counter) {
  return isf::IdempotencyKey{0x9e3779b97f4a7c15ull, counter};
}

isf::ControlEpoch CurrentEpoch(const isf::IncidentFabric& fabric) {
  const auto status = fabric.GetStatus();
  return status.ok() ? status.value().control_epoch : isf::ControlEpoch{};
}

isf::MutationHeader Header(const isf::IncidentFabric& fabric, isf::AuthorityId authority,
                           std::uint64_t counter) {
  isf::MutationHeader header;
  header.actor.authority = authority;
  header.actor.epoch = CurrentEpoch(fabric);
  header.key = Key(counter);
  return header;
}

isf::AffectedScope RackScope(const std::string& rack) {
  isf::AffectedScope scope;
  scope.objects.push_back(isf::ObjectRef{isf::ObjectKind::Rack, rack});
  scope.failure_domains.push_back(isf::FailureDomainRef{isf::FailureDomainKind::Row, "row-a"});
  return scope;
}

isf::AffectedScope TwoRackScope(const std::string& first, const std::string& second) {
  isf::AffectedScope scope;
  scope.objects.push_back(isf::ObjectRef{isf::ObjectKind::Rack, first});
  scope.objects.push_back(isf::ObjectRef{isf::ObjectKind::Rack, second});
  return scope;
}

isf::AffectedScope PowerFeedScope(const std::string& feed) {
  isf::AffectedScope scope;
  scope.failure_domains.push_back(isf::FailureDomainRef{isf::FailureDomainKind::PowerFeed, feed});
  return scope;
}

isf::OpenOptions StoreOptions(const std::string& path) {
  return StoreOptions(path, isf::StateDigestPolicy::EveryCommit);
}

isf::OpenOptions StoreOptions(const std::string& path, isf::StateDigestPolicy policy) {
  isf::OpenOptions options;
  options.path = path;
  options.create_if_missing = true;
  options.state_digest = policy;
  return options;
}

struct Fixture::Impl {
  ScratchDir scratch;
  isf::IncidentFabricPtr fabric;
  isf::StateDigestPolicy policy = isf::StateDigestPolicy::EveryCommit;
  Impl(const std::string& tag, isf::StateDigestPolicy chosen)
      : scratch(tag), policy(chosen), fabric(OpenOrThrow(scratch.path(), chosen)) {}
};

Fixture::Fixture(const std::string& tag, isf::StateDigestPolicy policy)
    : impl(new Impl(tag, policy)) {
  isf::IncidentFabric& fab = fabric();
  isf::RegisterAuthorityRequest bootstrap;
  bootstrap.header.actor.authority = isf::AuthorityId{};
  bootstrap.header.actor.epoch = CurrentEpoch(fab);
  bootstrap.header.key = Key(NextKey());
  bootstrap.name = "director";
  bootstrap.role = isf::AuthorityRole::FacilityDirector;
  bootstrap.rationale = "bootstrap";
  const auto receipt = fab.RegisterAuthority(bootstrap);
  if (!receipt.ok()) {
    throw std::runtime_error("could not bootstrap the fixture director: " +
                             receipt.status().ToString());
  }
  director = receipt.value().authority;
  commander = RegisterRole(fab, director, "commander", isf::AuthorityRole::IncidentCommander,
                           NextKey());
  manager = RegisterRole(fab, director, "manager", isf::AuthorityRole::DutyManager, NextKey());
  operator_role = RegisterRole(fab, director, "operator", isf::AuthorityRole::Operator, NextKey());
  observer = RegisterRole(fab, director, "observer", isf::AuthorityRole::Observer, NextKey());
}

Fixture::~Fixture() { delete impl; }

isf::IncidentFabric& Fixture::fabric() const { return *impl->fabric; }

const std::string& Fixture::path() const { return impl->scratch.path(); }

void Fixture::Restart() { Restart(impl->policy); }

void Fixture::Restart(isf::StateDigestPolicy policy) {
  if (impl->fabric) {
    (void)impl->fabric->Close();
    impl->fabric.reset();
  }
  impl->policy = policy;
  impl->fabric = OpenOrThrow(impl->scratch.path(), policy);
}

void Fixture::Close() {
  if (impl->fabric) {
    (void)impl->fabric->Close();
  }
}

isf::IncidentId ReportIncident(Fixture& fixture, const std::string& summary,
                               const std::string& rack) {
  isf::ReportIncidentRequest request;
  request.header = fixture.Header(fixture.operator_role);
  request.cls = isf::IncidentClass::Power;
  request.reported_severity = isf::Severity::Major;
  request.summary = summary;
  request.scope = RackScope(rack);
  request.source_system = "synthetic-bms";
  request.source_event_id = "evt-" + std::to_string(fixture.NextKey());
  request.detail = "synthetic report";
  const auto receipt = fixture.fabric().ReportIncident(request);
  if (!receipt.ok()) {
    throw std::runtime_error("scratch report failed: " + receipt.status().ToString());
  }
  return receipt.value().incident;
}

AcceptedIncident AcceptFreshIncident(Fixture& fixture, isf::IncidentClass cls,
                                     isf::Severity severity, const std::string& summary,
                                     const std::string& rack) {
  AcceptedIncident accepted;
  accepted.id = ReportIncident(fixture, summary, rack);
  const isf::EvidenceId assessment =
      RecordEvidence(fixture, accepted.id, RevisionOf(fixture.fabric(), accepted.id),
                     isf::EvidenceKind::SeverityAssessment, severity,
                     "severity assessment from the severity authority");

  isf::AcceptIncidentRequest accept;
  accept.header = fixture.Header(fixture.commander);
  accept.incident = accepted.id;
  accept.expected_revision = RevisionOf(fixture.fabric(), accepted.id);
  accept.cls = cls;
  accept.severity = severity;
  accept.severity_evidence = assessment;
  accept.owner = fixture.commander;
  accept.rationale = "triaged";
  const auto receipt = fixture.fabric().AcceptIncident(accept);
  if (!receipt.ok()) {
    throw std::runtime_error("scratch acceptance failed: " + receipt.status().ToString());
  }
  accepted.revision = receipt.value().incident_revision;
  return accepted;
}

isf::EvidenceId RecordEvidence(Fixture& fixture, isf::IncidentId incident, std::uint64_t revision,
                               isf::EvidenceKind kind, isf::Severity asserted_severity,
                               const std::string& rationale) {
  return RecordEvidenceWith(fixture, fixture.operator_role, incident, revision, kind,
                            asserted_severity, false, rationale);
}

isf::EvidenceId RecordEvidenceWith(Fixture& fixture, isf::AuthorityId actor,
                                   isf::IncidentId incident, std::uint64_t revision,
                                   isf::EvidenceKind kind, isf::Severity asserted_severity,
                                   bool effect_present, const std::string& rationale) {
  isf::RecordEvidenceRequest request;
  request.header = fixture.Header(actor);
  request.incident = incident;
  request.expected_revision = revision;
  request.kind = kind;
  request.effect_present = effect_present;
  request.asserted_severity = asserted_severity;
  request.rationale = rationale;
  request.source_system = "synthetic-bms";
  request.source_event_id = "ev-" + std::to_string(fixture.NextKey());
  request.detail = rationale;
  const auto receipt = fixture.fabric().RecordEvidence(request);
  if (!receipt.ok()) {
    throw std::runtime_error("scratch evidence recording failed: " +
                             receipt.status().ToString());
  }
  return receipt.value().evidence;
}

bool DenialSays(const isf::Status& status, const std::string& phrase) {
  return status.message().find(phrase) != std::string::npos;
}

std::uint64_t RevisionOf(const isf::IncidentFabric& fabric, isf::IncidentId id) {
  const auto view = fabric.GetIncident(id);
  return view.ok() ? view.value().revision : 0;
}

isf::IncidentView IncidentOf(const isf::IncidentFabric& fabric, isf::IncidentId id) {
  const auto view = fabric.GetIncident(id);
  if (!view.ok()) throw std::runtime_error("incident lookup failed: " + view.status().ToString());
  return view.value();
}

}  // namespace isftest
