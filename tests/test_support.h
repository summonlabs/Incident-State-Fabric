// Incident State Fabric - DCCP boundary 50
// Copyright 2026 Summon Software Labs.
// Licensed under the Apache License, Version 2.0.
//
// Shared fixtures for the proof suite.

#ifndef ISF_TEST_SUPPORT_H
#define ISF_TEST_SUPPORT_H

#include <cstdint>
#include <filesystem>
#include <string>

#include "isf/isf.h"

namespace isftest {

/// A scratch directory removed on destruction, including after a killed child
/// process left an orphaned store behind.
class ScratchDir {
 public:
  explicit ScratchDir(const std::string& tag);

  /// Roots the directory somewhere else. The reparse-point proofs need a volume
  /// that can host a junction, which the repository volume may not be able to.
  ScratchDir(const std::string& tag, const std::filesystem::path& base);
  ~ScratchDir();
  ScratchDir(const ScratchDir&) = delete;
  ScratchDir& operator=(const ScratchDir&) = delete;

  [[nodiscard]] const std::string& path() const noexcept { return path_; }
  [[nodiscard]] std::string child(const std::string& name) const;
  [[nodiscard]] const std::filesystem::path& fs_path() const noexcept { return fs_path_; }

 private:
  std::filesystem::path fs_path_;
  std::string path_;
};

[[nodiscard]] const std::filesystem::path& ScratchRoot();

/// A scratch root under the operating system temporary directory.
[[nodiscard]] const std::filesystem::path& TempScratchRoot();
[[nodiscard]] std::string Utf8(const std::filesystem::path& path);

/// Deterministic idempotency key. Keys are never derived from time or thread
/// identifiers, so a failure reproduces exactly.
[[nodiscard]] isf::IdempotencyKey Key(std::uint64_t counter);

[[nodiscard]] isf::ControlEpoch CurrentEpoch(const isf::IncidentFabric& fabric);

/// A mutation header bound to the fabric's current control epoch.
[[nodiscard]] isf::MutationHeader Header(const isf::IncidentFabric& fabric,
                                         isf::AuthorityId authority, std::uint64_t counter);

[[nodiscard]] isf::AffectedScope RackScope(const std::string& rack);
[[nodiscard]] isf::AffectedScope TwoRackScope(const std::string& first, const std::string& second);
[[nodiscard]] isf::AffectedScope PowerFeedScope(const std::string& feed);

[[nodiscard]] isf::OpenOptions StoreOptions(const std::string& path);
[[nodiscard]] isf::OpenOptions StoreOptions(const std::string& path,
                                            isf::StateDigestPolicy policy);

/// A store plus the roles most suites need, ready for lifecycle work.
struct Fixture {
  struct Impl;

  Fixture(const std::string& tag, isf::StateDigestPolicy policy);
  ~Fixture();
  Fixture(const Fixture&) = delete;
  Fixture& operator=(const Fixture&) = delete;

  [[nodiscard]] isf::IncidentFabric& fabric() const;
  [[nodiscard]] const std::string& path() const;
  [[nodiscard]] std::uint64_t NextKey() noexcept { return ++counter; }
  [[nodiscard]] isf::MutationHeader Header(isf::AuthorityId authority) {
    return isftest::Header(fabric(), authority, NextKey());
  }
  [[nodiscard]] isf::ControlEpoch Epoch() const { return CurrentEpoch(fabric()); }

  /// Clean restart: closes the current session and opens the same directory
  /// again. An unclean restart is modelled by the crash and multiprocess
  /// suites, which use real processes.
  void Restart();
  void Restart(isf::StateDigestPolicy policy);

  /// Releases mutation authority without reopening.
  void Close();

  isf::AuthorityId director;       // first FacilityDirector
  isf::AuthorityId commander;      // IncidentCommander
  isf::AuthorityId manager;        // DutyManager
  isf::AuthorityId operator_role;  // Operator
  isf::AuthorityId observer;       // Observer

  Impl* impl;
  std::uint64_t counter = 1000;
};

/// Reports an incident and returns its identifier.
isf::IncidentId ReportIncident(Fixture& fixture, const std::string& summary,
                               const std::string& rack);

struct AcceptedIncident {
  isf::IncidentId id;
  std::uint64_t revision = 0;
};
[[nodiscard]] AcceptedIncident AcceptFreshIncident(Fixture& fixture, isf::IncidentClass cls,
                                                   isf::Severity severity,
                                                   const std::string& summary,
                                                   const std::string& rack);

isf::EvidenceId RecordEvidence(Fixture& fixture, isf::IncidentId incident,
                               std::uint64_t revision, isf::EvidenceKind kind,
                               isf::Severity asserted_severity, const std::string& rationale);

isf::EvidenceId RecordEvidenceWith(Fixture& fixture, isf::AuthorityId actor, isf::IncidentId incident,
                                   std::uint64_t revision, isf::EvidenceKind kind,
                                   isf::Severity asserted_severity, bool effect_present,
                                   const std::string& rationale);

[[nodiscard]] std::uint64_t RevisionOf(const isf::IncidentFabric& fabric, isf::IncidentId id);

/// True when a denial message contains a phrase. Denial messages are
/// deterministic, so asserting on them is a stable proof that the right rule
/// fired rather than merely that something failed.
[[nodiscard]] bool DenialSays(const isf::Status& status, const std::string& phrase);

[[nodiscard]] isf::IncidentView IncidentOf(const isf::IncidentFabric& fabric, isf::IncidentId id);

}  // namespace isftest

#endif  // ISF_TEST_SUPPORT_H
