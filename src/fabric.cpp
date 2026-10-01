// Incident State Fabric - DCCP boundary 50
// Copyright 2026 Summon Software Labs.
// Licensed under the Apache License, Version 2.0.

#include "isf/fabric.h"

#include <algorithm>
#include <mutex>
#include <shared_mutex>
#include <utility>

#include "detail/evaluate.h"
#include "detail/request_codec.h"
#include "detail/state.h"
#include "detail/store.h"
#include "isf/version.h"

namespace isf {
namespace {

/// Every public entry point calls this exactly once, while holding the internal
/// lock, and no public entry point calls another. That is the whole reason the
/// fabric cannot deadlock against itself.
[[nodiscard]] Status CheckUsable(bool opened, bool closed, bool poisoned) {
  if (!opened) {
    return Status::Error(ErrorCode::StoreClosed, "the fabric was never opened successfully");
  }
  if (closed) {
    return Status::Error(ErrorCode::StoreClosed, "the fabric has been closed");
  }
  if (poisoned) {
    return Status::Error(ErrorCode::StoreIoError,
                         "a durable commit failed part way through; the in-memory view may be "
                         "ahead of the log, so reopen the store before continuing");
  }
  return Status::Ok();
}

[[nodiscard]] Status CheckedIncrement(std::uint64_t value, const char* field,
                                      std::uint64_t& out) {
  if (value == UINT64_MAX) {
    return Status::Error(ErrorCode::Overflow, std::string(field) + " would overflow");
  }
  out = value + 1;
  return Status::Ok();
}

[[nodiscard]] std::uint32_t ClampLimit(std::uint32_t requested) {
  if (requested == 0 || requested > PolicyConstants::kMaxListPage) {
    return PolicyConstants::kMaxListPage;
  }
  return requested;
}

}  // namespace

struct IncidentFabric::Impl {
  mutable std::shared_mutex mutex;
  std::unique_ptr<detail::Store> store;
  detail::State state;
  OpenOptions options;
  /// True only once Open has published the session record. A fabric that never
  /// finished opening owns no store and must not try to close one.
  bool opened = false;
  bool closed = false;
  bool poisoned = false;
  mutable std::mutex observer_mutex;
  CommitObserver observer;

  /// Applies an effect to the in-memory state and then commits it. The manifest
  /// rename inside Store::Commit is the single point after which the operation
  /// is authoritative.
  [[nodiscard]] Status ApplyAndCommit(const detail::Effect& effect, bool force_digest);

  /// Observers run after the internal lock has been released. The observer is
  /// copied under its own mutex, which is never held while the observer runs.
  void Notify(const CommitReceipt& receipt);
};

Status IncidentFabric::Impl::ApplyAndCommit(const detail::Effect& effect, bool force_digest) {
  const Status applied = detail::ApplyEffect(state, effect);
  if (!applied.ok()) return applied;

  const bool write_digest =
      force_digest || options.state_digest == StateDigestPolicy::EveryCommit;
  detail::Digest256 digest;
  if (write_digest) digest = detail::ComputeStateDigest(state);

  const std::vector<std::byte> payload = detail::EncodeEffect(effect);
  const Status committed = store->Commit(effect, payload, state.Counters(), write_digest, digest);
  if (!committed.ok()) poisoned = true;
  return committed;
}

void IncidentFabric::Impl::Notify(const CommitReceipt& receipt) {
  CommitObserver callback;
  {
    std::lock_guard<std::mutex> guard(observer_mutex);
    callback = observer;
  }
  if (callback) callback(receipt);
}

IncidentFabric::IncidentFabric() : impl_(std::make_unique<Impl>()) {}

IncidentFabric::~IncidentFabric() {
  if (impl_ != nullptr && impl_->opened && !impl_->closed) {
    (void)Close();
  }
}

Result<IncidentFabricPtr> IncidentFabric::Open(const OpenOptions& options) {
  IncidentFabricPtr fabric(new IncidentFabric());
  Impl& impl = *fabric->impl_;
  impl.options = options;

  detail::Store::RecoveryReport report;
  auto store = detail::Store::Open(options, report);
  if (!store.ok()) return store.status();
  impl.store = std::move(store).value();

  std::vector<detail::Effect> effects;
  Status status = impl.store->Replay(effects);
  if (!status.ok()) return status;

  impl.state = detail::State{};
  impl.state.next_incident_id = 1;
  impl.state.next_evidence_id = 1;
  impl.state.next_authority_id = 1;
  impl.state.last_close_clean = true;

  const detail::Manifest& manifest = impl.store->manifest();
  bool checkpoint_verified = false;
  for (const detail::Effect& effect : effects) {
    status = detail::ApplyEffect(impl.state, effect);
    if (!status.ok()) return status;
    if (manifest.digest_current && manifest.state_digest_generation == effect.generation) {
      const detail::Digest256 actual = detail::ComputeStateDigest(impl.state);
      if (!(actual == manifest.state_digest)) {
        return Status::Error(
            ErrorCode::IntegrityFailure,
            "the replayed state does not match the checkpoint digest recorded at generation " +
                std::to_string(effect.generation.value()));
      }
      checkpoint_verified = true;
    }
  }
  if (manifest.digest_current && !checkpoint_verified &&
      manifest.state_digest_generation == impl.state.generation) {
    const detail::Digest256 actual = detail::ComputeStateDigest(impl.state);
    if (!(actual == manifest.state_digest)) {
      return Status::Error(ErrorCode::IntegrityFailure,
                           "the replayed state does not match the checkpoint digest");
    }
  }

  // The manifest commits to the allocators and session flags directly, so replay
  // divergence is caught even when no whole-state checkpoint has been taken.
  const detail::StateCounters counters = impl.state.Counters();
  if (manifest.generation != counters.generation ||
      manifest.control_epoch != counters.control_epoch ||
      manifest.incarnation != counters.incarnation ||
      manifest.next_incident_id != counters.next_incident_id ||
      manifest.next_evidence_id != counters.next_evidence_id ||
      manifest.next_authority_id != counters.next_authority_id ||
      manifest.session_open != counters.session_open ||
      manifest.last_close_clean != counters.last_close_clean) {
    return Status::Error(ErrorCode::IntegrityFailure,
                         "the replayed state does not match the state the manifest committed to");
  }

  std::uint64_t incarnation = 0;
  status = CheckedIncrement(impl.state.incarnation, "store incarnation", incarnation);
  if (!status.ok()) return status;

  // A successor never inherits the previous incarnation's authority by
  // accident: an unclean shutdown, or a store that has never been opened,
  // advances the control epoch and fences every actor that held the old one.
  std::uint64_t epoch = impl.state.control_epoch.value;
  if (impl.state.session_open || impl.state.generation.value() == 0) {
    status = CheckedIncrement(epoch, "control epoch", epoch);
    if (!status.ok()) return status;
  }

  detail::Effect session;
  session.op = OpKind::SessionOpen;
  session.actor = AuthorityId{};
  session.incarnation = incarnation;
  session.control_epoch_after = epoch;
  session.session_open = true;
  session.clean_close = false;
  session.next_incident_id = impl.state.next_incident_id;
  session.next_evidence_id = impl.state.next_evidence_id;
  session.next_authority_id = impl.state.next_authority_id;
  std::uint64_t next_generation = 0;
  status = CheckedIncrement(impl.state.generation.value(), "generation", next_generation);
  if (!status.ok()) return status;
  session.generation = Generation{next_generation};

  status = impl.ApplyAndCommit(session, false);
  if (!status.ok()) return status;
  impl.opened = true;

  return fabric;
}

Status IncidentFabric::Close() {
  Impl& impl = *impl_;
  std::unique_lock<std::shared_mutex> lock(impl.mutex);
  if (impl.closed) return Status::Ok();
  if (!impl.opened) {
    impl.closed = true;
    return Status::Ok();
  }

  if (!impl.poisoned) {
    detail::Effect session;
    session.op = OpKind::SessionClose;
    session.actor = AuthorityId{};
    session.incarnation = impl.state.incarnation;
    session.control_epoch_after = impl.state.control_epoch.value;
    session.session_open = false;
    session.clean_close = true;
    session.next_incident_id = impl.state.next_incident_id;
    session.next_evidence_id = impl.state.next_evidence_id;
    session.next_authority_id = impl.state.next_authority_id;
    std::uint64_t next_generation = 0;
    const Status status =
        CheckedIncrement(impl.state.generation.value(), "generation", next_generation);
    if (!status.ok()) return status;
    session.generation = Generation{next_generation};

    const Status committed = impl.ApplyAndCommit(session, true);
    if (!committed.ok()) {
      impl.store->Close();
      impl.closed = true;
      return committed;
    }
  }

  impl.store->Close();
  impl.closed = true;
  return Status::Ok();
}

bool IncidentFabric::closed() const noexcept { return impl_->closed; }

Status IncidentFabric::Checkpoint() {
  Impl& impl = *impl_;
  std::unique_lock<std::shared_mutex> lock(impl.mutex);
  const Status usable = CheckUsable(impl.opened, impl.closed, impl.poisoned);
  if (!usable.ok()) return usable;
  const detail::Digest256 digest = detail::ComputeStateDigest(impl.state);
  return impl.store->Checkpoint(impl.state.Counters(), digest);
}

void IncidentFabric::SetCommitObserver(CommitObserver observer) {
  Impl& impl = *impl_;
  std::lock_guard<std::mutex> guard(impl.observer_mutex);
  impl.observer = std::move(observer);
}

Result<TransitionPreview> IncidentFabric::Preview(const AnyRequest& request) const {
  const Impl& impl = *impl_;
  std::shared_lock<std::shared_mutex> lock(impl.mutex);
  const Status usable = CheckUsable(impl.opened, impl.closed, impl.poisoned);
  if (!usable.ok()) return usable;

  const detail::Digest256 intent = detail::ComputeIntentDigest(request);
  const detail::Evaluation evaluation =
      detail::EvaluateRequest(impl.state, request, impl.options.limits, intent);

  TransitionPreview preview;
  preview.failures = evaluation.failures;
  preview.from_state = evaluation.from_state;
  preview.to_state = evaluation.to_state;
  preview.from_severity = evaluation.from_severity;
  preview.to_severity = evaluation.to_severity;
  preview.from_revision = evaluation.from_revision;
  preview.to_revision = evaluation.to_revision;
  preview.incident = evaluation.incident;
  switch (evaluation.kind) {
    case detail::DecisionKind::Commit:
      preview.would_commit = true;
      preview.code = ErrorCode::Ok;
      preview.detail = "the request would commit a new durable operation";
      break;
    case detail::DecisionKind::Replay:
      preview.would_commit = true;
      preview.replayed = true;
      preview.code = ErrorCode::Ok;
      preview.detail = "the request would replay an already committed operation";
      break;
    case detail::DecisionKind::Denied:
      preview.would_commit = false;
      preview.code = evaluation.denial.code();
      preview.detail = evaluation.denial.message();
      break;
    case detail::DecisionKind::Undecided:
      preview.would_commit = false;
      preview.code = ErrorCode::InternalError;
      preview.detail = "the decision function returned without reaching a decision";
      break;
  }
  return preview;
}

Result<CommitReceipt> IncidentFabric::Commit(const AnyRequest& request) {
  Impl& impl = *impl_;
  CommitReceipt receipt;
  {
    std::unique_lock<std::shared_mutex> lock(impl.mutex);
    const Status usable = CheckUsable(impl.opened, impl.closed, impl.poisoned);
    if (!usable.ok()) return usable;

    const detail::Digest256 intent = detail::ComputeIntentDigest(request);
    const detail::Evaluation evaluation =
        detail::EvaluateRequest(impl.state, request, impl.options.limits, intent);
    if (evaluation.kind == detail::DecisionKind::Denied) return evaluation.denial;
    if (evaluation.kind == detail::DecisionKind::Undecided) {
      return Status::Error(ErrorCode::InternalError,
                           "the decision function returned without reaching a decision");
    }
    if (evaluation.kind == detail::DecisionKind::Replay) return evaluation.receipt;

    const Status status = impl.ApplyAndCommit(evaluation.effect, false);
    if (!status.ok()) return status;
    receipt = evaluation.receipt;
  }
  impl.Notify(receipt);
  return receipt;
}

// ---------------------------------------------------------------------------
// Reads
// ---------------------------------------------------------------------------

Result<FabricStatus> IncidentFabric::GetStatus() const {
  const Impl& impl = *impl_;
  std::shared_lock<std::shared_mutex> lock(impl.mutex);
  FabricStatus status;
  if (impl.store == nullptr) {
    // Only reachable for a fabric that never finished opening, which the public
    // API never hands out; reporting it here keeps the read path total.
    status.format_id = StoreFormatIdentifier();
    status.format_version = StoreFormatVersion();
    status.write_failed = true;
    return status;
  }
  status.store_path = impl.store->root_utf8();
  status.format_id = StoreFormatIdentifier();
  status.format_version = StoreFormatVersion();
  status.generation = impl.state.generation;
  status.control_epoch = impl.state.control_epoch;
  status.incarnation = impl.state.incarnation;
  status.session_open = impl.state.session_open;
  status.last_close_clean = impl.state.last_close_clean;
  status.incident_count = impl.state.incidents.size();
  status.evidence_count = impl.state.evidence.size();
  status.authority_count = impl.state.authorities.size();
  status.idempotency_count = impl.state.idempotency.size();
  status.audit_count = impl.state.audit.size();
  status.write_failed = impl.poisoned;
  status.state_digest_policy =
      impl.options.state_digest == StateDigestPolicy::EveryCommit ? "EveryCommit" : "OnCheckpoint";

  std::uint64_t records = 0;
  for (const detail::SegmentDescriptor& segment : impl.store->manifest().segments) {
    records += segment.record_count;
  }
  status.record_count = records;
  status.segment_count = static_cast<std::uint32_t>(impl.store->manifest().segments.size());
  if (impl.store->manifest().digest_current) {
    status.state_digest_hex = impl.store->manifest().state_digest.Hex();
  }
  status.recovered_tail_bytes = impl.store->report().recovered_tail_bytes;
  status.removed_orphan_segments = impl.store->report().removed_orphan_segments;
  return status;
}

Result<IncidentView> IncidentFabric::GetIncident(IncidentId id) const {
  const Impl& impl = *impl_;
  std::shared_lock<std::shared_mutex> lock(impl.mutex);
  const Status usable = CheckUsable(impl.opened, impl.closed, impl.poisoned);
  if (!usable.ok()) return usable;
  const detail::IncidentRecord* record = impl.state.FindIncident(id);
  if (record == nullptr) {
    return Status::Error(ErrorCode::NotFound,
                         "incident " + std::to_string(id.value()) + " does not exist");
  }
  return detail::ToView(*record);
}

Result<EvidenceView> IncidentFabric::GetEvidence(EvidenceId id) const {
  const Impl& impl = *impl_;
  std::shared_lock<std::shared_mutex> lock(impl.mutex);
  const Status usable = CheckUsable(impl.opened, impl.closed, impl.poisoned);
  if (!usable.ok()) return usable;
  const detail::EvidenceRecord* record = impl.state.FindEvidence(id);
  if (record == nullptr) {
    return Status::Error(ErrorCode::NotFound,
                         "evidence " + std::to_string(id.value()) + " does not exist");
  }
  const detail::IncidentRecord* incident = impl.state.FindIncident(record->incident);
  if (incident == nullptr) {
    return Status::Error(ErrorCode::StoreCorrupt, "evidence references a missing incident");
  }
  return detail::ToView(*record, *incident);
}

Result<AuthorityView> IncidentFabric::GetAuthority(AuthorityId id) const {
  const Impl& impl = *impl_;
  std::shared_lock<std::shared_mutex> lock(impl.mutex);
  const Status usable = CheckUsable(impl.opened, impl.closed, impl.poisoned);
  if (!usable.ok()) return usable;
  const detail::AuthorityRecord* record = impl.state.FindAuthority(id);
  if (record == nullptr) {
    return Status::Error(ErrorCode::NotFound,
                         "authority " + std::to_string(id.value()) + " does not exist");
  }
  return detail::ToView(*record);
}

Result<LineageView> IncidentFabric::GetLineage(IncidentId id) const {
  const Impl& impl = *impl_;
  std::shared_lock<std::shared_mutex> lock(impl.mutex);
  const Status usable = CheckUsable(impl.opened, impl.closed, impl.poisoned);
  if (!usable.ok()) return usable;
  const detail::IncidentRecord* record = impl.state.FindIncident(id);
  if (record == nullptr) {
    return Status::Error(ErrorCode::NotFound,
                         "incident " + std::to_string(id.value()) + " does not exist");
  }
  LineageView view;
  view.subject = id;

  std::vector<IncidentSummary> chain;
  IncidentId cursor = record->predecessor;
  while (cursor.valid() && chain.size() < 64) {
    const detail::IncidentRecord* predecessor = impl.state.FindIncident(cursor);
    if (predecessor == nullptr) break;
    chain.push_back(detail::ToSummary(*predecessor));
    cursor = predecessor->predecessor;
  }
  std::reverse(chain.begin(), chain.end());
  view.predecessors = std::move(chain);

  for (const auto& entry : impl.state.incidents) {
    const detail::IncidentRecord& candidate = entry.second;
    if (candidate.predecessor == id) view.successors.push_back(detail::ToSummary(candidate));
    if (candidate.parent == id) view.merged_children.push_back(detail::ToSummary(candidate));
  }
  return view;
}

Result<std::vector<IncidentSummary>> IncidentFabric::ListIncidents(const ListQuery& query) const {
  const Impl& impl = *impl_;
  std::shared_lock<std::shared_mutex> lock(impl.mutex);
  const Status usable = CheckUsable(impl.opened, impl.closed, impl.poisoned);
  if (!usable.ok()) return usable;
  std::vector<IncidentSummary> out;
  const std::uint32_t limit = ClampLimit(query.limit);
  std::uint32_t seen = 0;
  for (const auto& entry : impl.state.incidents) {
    if (seen++ < query.offset) continue;
    if (out.size() >= limit) break;
    out.push_back(detail::ToSummary(entry.second));
  }
  return out;
}

Result<std::vector<IncidentSummary>> IncidentFabric::ListIncidentsInState(
    LifecycleState state, const ListQuery& query) const {
  const Impl& impl = *impl_;
  std::shared_lock<std::shared_mutex> lock(impl.mutex);
  const Status usable = CheckUsable(impl.opened, impl.closed, impl.poisoned);
  if (!usable.ok()) return usable;
  std::vector<IncidentSummary> out;
  const std::uint32_t limit = ClampLimit(query.limit);
  std::uint32_t seen = 0;
  for (const auto& entry : impl.state.incidents) {
    if (entry.second.state != state) continue;
    if (seen++ < query.offset) continue;
    if (out.size() >= limit) break;
    out.push_back(detail::ToSummary(entry.second));
  }
  return out;
}

Result<std::vector<EvidenceView>> IncidentFabric::ListEvidence(IncidentId incident,
                                                               const ListQuery& query) const {
  const Impl& impl = *impl_;
  std::shared_lock<std::shared_mutex> lock(impl.mutex);
  const Status usable = CheckUsable(impl.opened, impl.closed, impl.poisoned);
  if (!usable.ok()) return usable;
  const detail::IncidentRecord* record = impl.state.FindIncident(incident);
  if (record == nullptr) {
    return Status::Error(ErrorCode::NotFound,
                         "incident " + std::to_string(incident.value()) + " does not exist");
  }
  std::vector<EvidenceView> out;
  const std::uint32_t limit = ClampLimit(query.limit);
  std::uint32_t seen = 0;
  for (const EvidenceId id : record->evidence_ids) {
    if (seen++ < query.offset) continue;
    if (out.size() >= limit) break;
    const detail::EvidenceRecord* evidence = impl.state.FindEvidence(id);
    if (evidence == nullptr) continue;
    out.push_back(detail::ToView(*evidence, *record));
  }
  return out;
}

Result<std::vector<AuthorityView>> IncidentFabric::ListAuthorities(const ListQuery& query) const {
  const Impl& impl = *impl_;
  std::shared_lock<std::shared_mutex> lock(impl.mutex);
  const Status usable = CheckUsable(impl.opened, impl.closed, impl.poisoned);
  if (!usable.ok()) return usable;
  std::vector<AuthorityView> out;
  const std::uint32_t limit = ClampLimit(query.limit);
  std::uint32_t seen = 0;
  for (const auto& entry : impl.state.authorities) {
    if (seen++ < query.offset) continue;
    if (out.size() >= limit) break;
    out.push_back(detail::ToView(entry.second));
  }
  return out;
}

Result<std::vector<AuditEntry>> IncidentFabric::ReadAudit(const AuditQuery& query) const {
  const Impl& impl = *impl_;
  std::shared_lock<std::shared_mutex> lock(impl.mutex);
  const Status usable = CheckUsable(impl.opened, impl.closed, impl.poisoned);
  if (!usable.ok()) return usable;
  const auto begin = std::lower_bound(
      impl.state.audit.begin(), impl.state.audit.end(), query.from,
      [](const AuditEntry& entry, Generation generation) { return entry.generation < generation; });
  std::vector<AuditEntry> out;
  const std::uint32_t limit = ClampLimit(query.limit);
  for (auto it = begin; it != impl.state.audit.end(); ++it) {
    if (out.size() >= limit) break;
    out.push_back(*it);
  }
  return out;
}

// ---------------------------------------------------------------------------
// Typed mutations
// ---------------------------------------------------------------------------

#define ISF_FORWARD_MUTATION(Name, Type)                            \
  Result<CommitReceipt> IncidentFabric::Name(const Type& request) { \
    return Commit(AnyRequest{request});                             \
  }

ISF_FORWARD_MUTATION(RegisterAuthority, RegisterAuthorityRequest)
ISF_FORWARD_MUTATION(RevokeAuthority, RevokeAuthorityRequest)
ISF_FORWARD_MUTATION(ForceFence, ForceFenceRequest)
ISF_FORWARD_MUTATION(ReportIncident, ReportIncidentRequest)
ISF_FORWARD_MUTATION(AcceptIncident, AcceptIncidentRequest)
ISF_FORWARD_MUTATION(RejectReport, RejectReportRequest)
ISF_FORWARD_MUTATION(RecordEvidence, RecordEvidenceRequest)
ISF_FORWARD_MUTATION(WithdrawEvidence, WithdrawEvidenceRequest)
ISF_FORWARD_MUTATION(ReestablishEvidence, ReestablishEvidenceRequest)
ISF_FORWARD_MUTATION(AmendSeverity, AmendSeverityRequest)
ISF_FORWARD_MUTATION(AmendScope, AmendScopeRequest)
ISF_FORWARD_MUTATION(AssignOwner, AssignOwnerRequest)
ISF_FORWARD_MUTATION(DeclareContained, DeclareContainedRequest)
ISF_FORWARD_MUTATION(StartRecovery, StartRecoveryRequest)
ISF_FORWARD_MUTATION(DeclareRecovered, DeclareRecoveredRequest)
ISF_FORWARD_MUTATION(ResolveIncident, ResolveIncidentRequest)
ISF_FORWARD_MUTATION(CloseIncident, CloseIncidentRequest)
ISF_FORWARD_MUTATION(ReopenIncident, ReopenIncidentRequest)
ISF_FORWARD_MUTATION(CreateSuccessor, CreateSuccessorRequest)
ISF_FORWARD_MUTATION(MergeIncident, MergeIncidentRequest)

#undef ISF_FORWARD_MUTATION

}  // namespace isf
