// Incident State Fabric - DCCP boundary 50
// Copyright 2026 Summon Software Labs.
// Licensed under the Apache License, Version 2.0.

#ifndef ISF_FABRIC_H
#define ISF_FABRIC_H

#include <functional>
#include <memory>
#include <vector>

#include "isf/model.h"
#include "isf/requests.h"
#include "isf/result.h"
#include "isf/types.h"

namespace isf {

class IncidentFabric;
using IncidentFabricPtr = std::unique_ptr<IncidentFabric>;

/// The authoritative incident lifecycle for one facility domain.
///
/// One process owns mutation authority for a store; a second process that tries
/// to open the same store is refused with ErrorCode::StoreLocked. Reads may run
/// concurrently with each other; every mutation is serialised behind a single
/// writer and becomes visible only after it is durable.
///
/// Every method acquires its internal lock exactly once and never re-enters the
/// fabric, so no call path can deadlock against itself.
class IncidentFabric {
 public:
  /// Invoked after a commit has become durable and after the internal lock has
  /// been released. Observers are not serialised with each other and may call
  /// back into the fabric, including performing further commits.
  using CommitObserver = std::function<void(const CommitReceipt&)>;

  /// Opens or creates the store described by \p options and takes the
  /// single-writer lock. Opening is itself a durable commit: a session record is
  /// appended so that an unclean shutdown is detectable by the next open.
  [[nodiscard]] static Result<IncidentFabricPtr> Open(const OpenOptions& options);

  ~IncidentFabric();

  IncidentFabric(const IncidentFabric&) = delete;
  IncidentFabric& operator=(const IncidentFabric&) = delete;
  IncidentFabric(IncidentFabric&&) = delete;
  IncidentFabric& operator=(IncidentFabric&&) = delete;

  // -------------------------------------------------------------------------
  // Session
  // -------------------------------------------------------------------------

  /// Appends a clean-shutdown record and releases the single-writer lock.
  /// Idempotent. Called automatically by the destructor when it has not run.
  [[nodiscard]] Status Close();

  [[nodiscard]] bool closed() const noexcept;

  /// Publishes the current whole-state digest into the manifest without adding a
  /// record. Recovery verifies whatever checkpoint the manifest names.
  [[nodiscard]] Status Checkpoint();

  void SetCommitObserver(CommitObserver observer);

  // -------------------------------------------------------------------------
  // Reads. These never mutate authoritative state.
  // -------------------------------------------------------------------------

  [[nodiscard]] Result<FabricStatus> GetStatus() const;
  [[nodiscard]] Result<IncidentView> GetIncident(IncidentId id) const;
  [[nodiscard]] Result<EvidenceView> GetEvidence(EvidenceId id) const;
  [[nodiscard]] Result<AuthorityView> GetAuthority(AuthorityId id) const;
  [[nodiscard]] Result<LineageView> GetLineage(IncidentId id) const;

  /// Incidents in ascending identifier order.
  [[nodiscard]] Result<std::vector<IncidentSummary>> ListIncidents(const ListQuery& query) const;
  [[nodiscard]] Result<std::vector<IncidentSummary>> ListIncidentsInState(LifecycleState state,
                                                                          const ListQuery& query) const;
  /// A single incident's evidence in ascending evidence identifier order.
  [[nodiscard]] Result<std::vector<EvidenceView>> ListEvidence(IncidentId incident,
                                                               const ListQuery& query) const;
  [[nodiscard]] Result<std::vector<AuthorityView>> ListAuthorities(const ListQuery& query) const;

  /// Durable audit trail, ascending by generation starting at AuditQuery::from.
  [[nodiscard]] Result<std::vector<AuditEntry>> ReadAudit(const AuditQuery& query) const;

  // -------------------------------------------------------------------------
  // Decisions
  // -------------------------------------------------------------------------

  /// Reports exactly what Commit would do, without mutating anything. Preview
  /// and Commit share one decision function, so they cannot disagree.
  [[nodiscard]] Result<TransitionPreview> Preview(const AnyRequest& request) const;

  /// The single durable entry point. Typed wrappers below forward here.
  [[nodiscard]] Result<CommitReceipt> Commit(const AnyRequest& request);

  // -------------------------------------------------------------------------
  // Typed mutations
  // -------------------------------------------------------------------------

  [[nodiscard]] Result<CommitReceipt> RegisterAuthority(const RegisterAuthorityRequest& request);
  [[nodiscard]] Result<CommitReceipt> RevokeAuthority(const RevokeAuthorityRequest& request);
  [[nodiscard]] Result<CommitReceipt> ForceFence(const ForceFenceRequest& request);
  [[nodiscard]] Result<CommitReceipt> ReportIncident(const ReportIncidentRequest& request);
  [[nodiscard]] Result<CommitReceipt> AcceptIncident(const AcceptIncidentRequest& request);
  [[nodiscard]] Result<CommitReceipt> RejectReport(const RejectReportRequest& request);
  [[nodiscard]] Result<CommitReceipt> RecordEvidence(const RecordEvidenceRequest& request);
  [[nodiscard]] Result<CommitReceipt> WithdrawEvidence(const WithdrawEvidenceRequest& request);
  [[nodiscard]] Result<CommitReceipt> ReestablishEvidence(const ReestablishEvidenceRequest& request);
  [[nodiscard]] Result<CommitReceipt> AmendSeverity(const AmendSeverityRequest& request);
  [[nodiscard]] Result<CommitReceipt> AmendScope(const AmendScopeRequest& request);
  [[nodiscard]] Result<CommitReceipt> AssignOwner(const AssignOwnerRequest& request);
  [[nodiscard]] Result<CommitReceipt> DeclareContained(const DeclareContainedRequest& request);
  [[nodiscard]] Result<CommitReceipt> StartRecovery(const StartRecoveryRequest& request);
  [[nodiscard]] Result<CommitReceipt> DeclareRecovered(const DeclareRecoveredRequest& request);
  [[nodiscard]] Result<CommitReceipt> ResolveIncident(const ResolveIncidentRequest& request);
  [[nodiscard]] Result<CommitReceipt> CloseIncident(const CloseIncidentRequest& request);
  [[nodiscard]] Result<CommitReceipt> ReopenIncident(const ReopenIncidentRequest& request);
  [[nodiscard]] Result<CommitReceipt> CreateSuccessor(const CreateSuccessorRequest& request);
  [[nodiscard]] Result<CommitReceipt> MergeIncident(const MergeIncidentRequest& request);

 private:
  IncidentFabric();

  struct Impl;
  std::unique_ptr<Impl> impl_;
};

}  // namespace isf

#endif  // ISF_FABRIC_H
