// Incident State Fabric - DCCP boundary 50
// Copyright 2026 Summon Software Labs.
// Licensed under the Apache License, Version 2.0.

#include "detail/state.h"

#include <algorithm>
#include <array>

#include "detail/canonical.h"

namespace isf::detail {
namespace {

Status Corrupt(const std::string& detail) {
  return Status::Error(ErrorCode::StoreCorrupt, detail);
}

void EncodeScope(Encoder& encoder, const AffectedScope& scope) {
  encoder.U32(static_cast<std::uint32_t>(scope.objects.size()));
  for (const ObjectRef& object : scope.objects) {
    encoder.U8(static_cast<std::uint8_t>(object.kind));
    encoder.Text(object.id);
  }
  encoder.U32(static_cast<std::uint32_t>(scope.failure_domains.size()));
  for (const FailureDomainRef& domain : scope.failure_domains) {
    encoder.U8(static_cast<std::uint8_t>(domain.kind));
    encoder.Text(domain.id);
  }
}

bool DecodeScope(Decoder& decoder, AffectedScope& scope) {
  std::uint32_t object_count = 0;
  if (!decoder.U32(object_count)) return false;
  if (object_count > FieldLimits::kScopeObjects) {
    decoder.Poison();
    return false;
  }
  scope.objects.reserve(object_count);
  for (std::uint32_t i = 0; i < object_count; ++i) {
    std::uint8_t kind = 0;
    ObjectRef object;
    if (!decoder.U8(kind) || !decoder.Text(object.id, FieldLimits::kToken)) return false;
    object.kind = static_cast<ObjectKind>(kind);
    scope.objects.push_back(std::move(object));
  }
  std::uint32_t domain_count = 0;
  if (!decoder.U32(domain_count)) return false;
  if (domain_count > FieldLimits::kScopeDomains) {
    decoder.Poison();
    return false;
  }
  scope.failure_domains.reserve(domain_count);
  for (std::uint32_t i = 0; i < domain_count; ++i) {
    std::uint8_t kind = 0;
    FailureDomainRef domain;
    if (!decoder.U8(kind) || !decoder.Text(domain.id, FieldLimits::kToken)) return false;
    domain.kind = static_cast<FailureDomainKind>(kind);
    scope.failure_domains.push_back(std::move(domain));
  }
  return true;
}

void EncodeEvent(Encoder& encoder, const LifecycleEvent& event) {
  encoder.U32(static_cast<std::uint32_t>(event.op));
  encoder.U64(event.at.value());
  encoder.U8(static_cast<std::uint8_t>(event.from));
  encoder.U8(static_cast<std::uint8_t>(event.to));
  encoder.U8(static_cast<std::uint8_t>(event.from_severity));
  encoder.U8(static_cast<std::uint8_t>(event.to_severity));
  encoder.U64(event.actor.value());
  encoder.U64(event.revision);
  encoder.Text(event.rationale);
}

bool DecodeEvent(Decoder& decoder, LifecycleEvent& event) {
  std::uint32_t op = 0;
  std::uint64_t at = 0;
  std::uint8_t from = 0;
  std::uint8_t to = 0;
  std::uint8_t from_severity = 0;
  std::uint8_t to_severity = 0;
  std::uint64_t actor = 0;
  std::uint64_t revision = 0;
  if (!decoder.U32(op) || !decoder.U64(at) || !decoder.U8(from) || !decoder.U8(to) ||
      !decoder.U8(from_severity) || !decoder.U8(to_severity) || !decoder.U64(actor) ||
      !decoder.U64(revision) || !decoder.Text(event.rationale, FieldLimits::kRationale)) {
    return false;
  }
  if (!IsKnownOpKind(op) || !IsKnownLifecycleState(from) || !IsKnownLifecycleState(to) ||
      !IsKnownSeverity(from_severity) || !IsKnownSeverity(to_severity)) {
    decoder.Poison();
    return false;
  }
  event.op = static_cast<OpKind>(op);
  event.at = Generation{at};
  event.from = static_cast<LifecycleState>(from);
  event.to = static_cast<LifecycleState>(to);
  event.from_severity = static_cast<Severity>(from_severity);
  event.to_severity = static_cast<Severity>(to_severity);
  event.actor = AuthorityId{actor};
  event.revision = revision;
  return true;
}

void PushHistory(IncidentRecord& incident, const Effect& effect, LifecycleState to_state,
                 Severity to_severity) {
  LifecycleEvent event;
  event.op = effect.op;
  event.at = effect.generation;
  event.from = incident.state;
  event.to = to_state;
  event.from_severity = incident.severity;
  event.to_severity = to_severity;
  event.actor = effect.actor;
  event.revision = effect.incident_revision;
  event.rationale = effect.rationale;
  incident.history.push_back(std::move(event));
}

void InsertEvidence(State& state, const Effect& effect) {
  EvidenceRecord record;
  record.id = effect.evidence;
  record.incident = effect.incident;
  record.kind = effect.evidence_kind;
  record.source = effect.actor;
  record.recorded_at = effect.generation;
  record.subject = effect.evidence_subject;
  record.asserted_severity = effect.evidence_asserted_severity;
  record.effect_present = effect.evidence_effect_present;
  record.rationale = effect.evidence_rationale;
  record.source_system = effect.evidence_source_system;
  record.source_event_id = effect.evidence_source_event_id;
  record.detail = effect.evidence_detail;
  if (IncidentRecord* incident = state.MutableIncident(effect.incident)) {
    record.observation_generation = incident->observation_generation;
    record.attestation_generation = incident->attestation_generation;
  }
  state.evidence.emplace(record.id, std::move(record));
  if (IncidentRecord* incident = state.MutableIncident(effect.incident)) {
    incident->evidence_ids.push_back(effect.evidence);
  }
}

}  // namespace

const AuthorityRecord* State::FindAuthority(AuthorityId id) const {
  const auto it = authorities.find(id);
  return it == authorities.end() ? nullptr : &it->second;
}

const IncidentRecord* State::FindIncident(IncidentId id) const {
  const auto it = incidents.find(id);
  return it == incidents.end() ? nullptr : &it->second;
}

const EvidenceRecord* State::FindEvidence(EvidenceId id) const {
  const auto it = evidence.find(id);
  return it == evidence.end() ? nullptr : &it->second;
}

IncidentRecord* State::MutableIncident(IncidentId id) {
  const auto it = incidents.find(id);
  return it == incidents.end() ? nullptr : &it->second;
}

EvidenceRecord* State::MutableEvidence(EvidenceId id) {
  const auto it = evidence.find(id);
  return it == evidence.end() ? nullptr : &it->second;
}

StateCounters State::Counters() const {
  StateCounters counters;
  counters.generation = generation;
  counters.control_epoch = control_epoch;
  counters.incarnation = incarnation;
  counters.next_incident_id = next_incident_id;
  counters.next_evidence_id = next_evidence_id;
  counters.next_authority_id = next_authority_id;
  counters.session_open = session_open;
  counters.last_close_clean = last_close_clean;
  return counters;
}

std::string ReportDedupToken(const std::string& source_system, const std::string& source_event_id) {
  if (source_system.empty() || source_event_id.empty()) return std::string();
  std::string token = source_system;
  token.push_back('\x1f');
  token += source_event_id;
  return token;
}

bool IsEvidenceCurrent(const EvidenceRecord& evidence, const IncidentRecord& incident) {
  if (evidence.withdrawn) return false;
  if (ClassifyEvidence(evidence.kind) == EvidenceClass::DynamicObservation) {
    return evidence.observation_generation == incident.observation_generation;
  }
  return evidence.attestation_generation == incident.attestation_generation;
}

AuthorityView ToView(const AuthorityRecord& record) {
  AuthorityView view;
  view.id = record.id;
  view.name = record.name;
  view.role = record.role;
  view.active = record.active;
  view.registered_at = record.registered_at;
  view.revoked_at = record.revoked_at;
  view.rationale = record.rationale;
  return view;
}

IncidentSummary ToSummary(const IncidentRecord& record) {
  IncidentSummary summary;
  summary.id = record.id;
  summary.cls = record.cls;
  summary.severity = record.severity;
  summary.state = record.state;
  summary.revision = record.revision;
  summary.owner = record.owner;
  summary.created_at = record.created_at;
  summary.updated_at = record.updated_at;
  summary.evidence_count = record.evidence_ids.size();
  summary.summary = record.summary;
  return summary;
}

IncidentView ToView(const IncidentRecord& record) {
  IncidentView view;
  view.id = record.id;
  view.cls = record.cls;
  view.severity = record.severity;
  view.state = record.state;
  view.revision = record.revision;
  view.observation_generation = record.observation_generation;
  view.attestation_generation = record.attestation_generation;
  view.reopen_count = record.reopen_count;
  view.recovery_started = record.recovery_started;
  view.containment_declared = record.containment_declared;
  view.owner = record.owner;
  view.reported_by = record.reported_by;
  view.accepting_authority = record.accepting_authority;
  view.scope = record.scope;
  view.summary = record.summary;
  view.source_system = record.source_system;
  view.source_event_id = record.source_event_id;
  view.parent = record.parent;
  view.predecessor = record.predecessor;
  view.created_at = record.created_at;
  view.updated_at = record.updated_at;
  view.last_escalation_at = record.last_escalation_at;
  view.escalation_count = record.escalation_count;
  view.history = record.history;
  return view;
}

EvidenceView ToView(const EvidenceRecord& record, const IncidentRecord& incident) {
  EvidenceView view;
  view.id = record.id;
  view.incident = record.incident;
  view.kind = record.kind;
  view.cls = ClassifyEvidence(record.kind);
  view.source = record.source;
  view.recorded_at = record.recorded_at;
  view.observation_generation = record.observation_generation;
  view.attestation_generation = record.attestation_generation;
  view.withdrawn = record.withdrawn;
  view.withdrawn_at = record.withdrawn_at;
  view.withdrawn_by = record.withdrawn_by;
  view.subject = record.subject;
  view.asserted_severity = record.asserted_severity;
  view.effect_present = record.effect_present;
  view.rationale = record.rationale;
  view.source_system = record.source_system;
  view.source_event_id = record.source_event_id;
  view.detail = record.detail;
  view.current = IsEvidenceCurrent(record, incident);
  return view;
}

// ---------------------------------------------------------------------------
// Effect encoding
// ---------------------------------------------------------------------------

std::vector<std::byte> EncodeEffect(const Effect& effect) {
  Encoder encoder;
  encoder.U32(static_cast<std::uint32_t>(effect.op));
  encoder.U64(effect.generation.value());
  encoder.U64(effect.actor.value());
  encoder.U64(effect.key.hi);
  encoder.U64(effect.key.lo);
  encoder.Digest(effect.intent);
  encoder.U64(effect.request_epoch);

  encoder.U64(effect.incarnation);
  encoder.U64(effect.control_epoch_after);
  encoder.Bool(effect.session_open);
  encoder.Bool(effect.clean_close);

  encoder.U64(effect.authority.value());
  encoder.Text(effect.authority_name);
  encoder.U8(static_cast<std::uint8_t>(effect.authority_role));
  encoder.Bool(effect.authority_active);

  encoder.U64(effect.incident.value());
  encoder.U64(effect.incident_revision);
  encoder.U8(static_cast<std::uint8_t>(effect.cls));
  encoder.U8(static_cast<std::uint8_t>(effect.severity));
  encoder.U8(static_cast<std::uint8_t>(effect.state));
  EncodeScope(encoder, effect.scope);
  encoder.U64(effect.owner.value());
  encoder.Bool(effect.recovery_started);
  encoder.Bool(effect.containment_declared);
  encoder.U64(effect.observation_generation);
  encoder.U64(effect.attestation_generation);
  encoder.U64(effect.reopen_count);
  encoder.U64(effect.escalation_count);
  encoder.U64(effect.last_escalation_at.value());
  encoder.Text(effect.summary);
  encoder.Text(effect.source_system);
  encoder.Text(effect.source_event_id);

  encoder.U64(effect.secondary_incident.value());
  encoder.U64(effect.secondary_revision);
  encoder.U8(static_cast<std::uint8_t>(effect.secondary_state));
  encoder.Bool(effect.cross_class);

  encoder.U64(effect.evidence.value());
  encoder.U8(static_cast<std::uint8_t>(effect.evidence_kind));
  encoder.Bool(effect.evidence_withdrawn);
  encoder.Bool(effect.evidence_reestablished);
  EncodeScope(encoder, effect.evidence_subject);
  encoder.U8(static_cast<std::uint8_t>(effect.evidence_asserted_severity));
  encoder.Bool(effect.evidence_effect_present);
  encoder.Text(effect.evidence_rationale);
  encoder.Text(effect.evidence_source_system);
  encoder.Text(effect.evidence_source_event_id);
  encoder.Text(effect.evidence_detail);

  encoder.U64(effect.next_incident_id);
  encoder.U64(effect.next_evidence_id);
  encoder.U64(effect.next_authority_id);

  encoder.Bool(effect.created_incident);
  encoder.Bool(effect.duplicate_report);
  encoder.Text(effect.rationale);
  return encoder.Take();
}

Result<Effect> DecodeEffect(OpKind op, const std::byte* data, std::size_t length) {
  Decoder decoder(data, length);
  Effect effect;
  effect.op = op;
  std::uint32_t op_raw = 0;
  std::uint64_t generation = 0;
  std::uint64_t actor = 0;
  std::uint64_t epoch = 0;
  std::uint8_t role = 0;
  std::uint8_t cls = 0;
  std::uint8_t severity = 0;
  std::uint8_t state = 0;
  std::uint8_t secondary_state = 0;
  std::uint8_t evidence_kind = 0;
  std::uint8_t evidence_severity = 0;

  std::uint64_t authority_id = 0;
  std::uint64_t incident_id = 0;
  std::uint64_t owner_id = 0;
  std::uint64_t last_escalation = 0;
  std::uint64_t secondary_incident_id = 0;
  std::uint64_t evidence_id = 0;

  if (!decoder.U32(op_raw) || !decoder.U64(generation) || !decoder.U64(actor) ||
      !decoder.U64(effect.key.hi) || !decoder.U64(effect.key.lo) ||
      !decoder.Digest(effect.intent) || !decoder.U64(epoch) ||
      !decoder.U64(effect.incarnation) || !decoder.U64(effect.control_epoch_after) ||
      !decoder.Bool(effect.session_open) || !decoder.Bool(effect.clean_close) ||
      !decoder.U64(authority_id) || !decoder.Text(effect.authority_name, FieldLimits::kName) ||
      !decoder.U8(role) || !decoder.Bool(effect.authority_active) ||
      !decoder.U64(incident_id) || !decoder.U64(effect.incident_revision) ||
      !decoder.U8(cls) || !decoder.U8(severity) || !decoder.U8(state) ||
      !DecodeScope(decoder, effect.scope) || !decoder.U64(owner_id) ||
      !decoder.Bool(effect.recovery_started) || !decoder.Bool(effect.containment_declared) ||
      !decoder.U64(effect.observation_generation) || !decoder.U64(effect.attestation_generation) ||
      !decoder.U64(effect.reopen_count) || !decoder.U64(effect.escalation_count) ||
      !decoder.U64(last_escalation) ||
      !decoder.Text(effect.summary, FieldLimits::kSummary) ||
      !decoder.Text(effect.source_system, FieldLimits::kToken) ||
      !decoder.Text(effect.source_event_id, FieldLimits::kToken) ||
      !decoder.U64(secondary_incident_id) || !decoder.U64(effect.secondary_revision) ||
      !decoder.U8(secondary_state) || !decoder.Bool(effect.cross_class) ||
      !decoder.U64(evidence_id) ||
      !decoder.U8(evidence_kind) || !decoder.Bool(effect.evidence_withdrawn) ||
      !decoder.Bool(effect.evidence_reestablished) || !DecodeScope(decoder, effect.evidence_subject) ||
      !decoder.U8(evidence_severity) || !decoder.Bool(effect.evidence_effect_present) ||
      !decoder.Text(effect.evidence_rationale, FieldLimits::kRationale) ||
      !decoder.Text(effect.evidence_source_system, FieldLimits::kToken) ||
      !decoder.Text(effect.evidence_source_event_id, FieldLimits::kToken) ||
      !decoder.Text(effect.evidence_detail, FieldLimits::kDetail) ||
      !decoder.U64(effect.next_incident_id) || !decoder.U64(effect.next_evidence_id) ||
      !decoder.U64(effect.next_authority_id) || !decoder.Bool(effect.created_incident) ||
      !decoder.Bool(effect.duplicate_report) ||
      !decoder.Text(effect.rationale, FieldLimits::kRationale)) {
    return Corrupt("effect record body is truncated or exceeds a field limit");
  }
  if (!decoder.done()) return Corrupt("effect record has trailing bytes");
  if (op_raw != static_cast<std::uint32_t>(op)) {
    return Corrupt("effect operation kind does not match the record header");
  }
  if (!IsKnownAuthorityRole(role) || !IsKnownIncidentClass(cls) || !IsKnownSeverity(severity) ||
      !IsKnownLifecycleState(state) || !IsKnownLifecycleState(secondary_state) ||
      !IsKnownEvidenceKind(evidence_kind) || !IsKnownSeverity(evidence_severity)) {
    return Corrupt("effect record carries an out-of-range enumerator");
  }
  for (const ObjectRef& object : effect.scope.objects) {
    if (!IsValidToken(object.id, FieldLimits::kToken)) {
      return Corrupt("effect scope object identifier is not a valid token");
    }
  }
  for (const FailureDomainRef& domain : effect.scope.failure_domains) {
    if (!IsValidToken(domain.id, FieldLimits::kToken)) {
      return Corrupt("effect scope failure domain identifier is not a valid token");
    }
  }

  effect.generation = Generation{generation};
  effect.actor = AuthorityId{actor};
  effect.request_epoch = epoch;
  effect.authority = AuthorityId{authority_id};
  effect.incident = IncidentId{incident_id};
  effect.owner = AuthorityId{owner_id};
  effect.last_escalation_at = Generation{last_escalation};
  effect.secondary_incident = IncidentId{secondary_incident_id};
  effect.evidence = EvidenceId{evidence_id};
  effect.authority_role = static_cast<AuthorityRole>(role);
  effect.cls = static_cast<IncidentClass>(cls);
  effect.severity = static_cast<Severity>(severity);
  effect.state = static_cast<LifecycleState>(state);
  effect.secondary_state = static_cast<LifecycleState>(secondary_state);
  effect.evidence_kind = static_cast<EvidenceKind>(evidence_kind);
  effect.evidence_asserted_severity = static_cast<Severity>(evidence_severity);
  return effect;
}

// ---------------------------------------------------------------------------
// Replay
// ---------------------------------------------------------------------------

CommitReceipt ReceiptFor(const Effect& effect) {
  CommitReceipt receipt;
  receipt.generation = effect.generation;
  receipt.key = effect.key;
  receipt.op = effect.op;
  receipt.replayed = false;
  receipt.created_incident = effect.created_incident;
  receipt.duplicate_report = effect.duplicate_report;
  receipt.incident = effect.incident;
  receipt.incident_revision = effect.incident_revision;
  receipt.evidence = effect.evidence;
  receipt.authority = effect.authority.valid() ? effect.authority : effect.actor;
  return receipt;
}

Status ApplyEffect(State& state, const Effect& effect) {
  if (effect.generation.value() != state.generation.value() + 1) {
    return Corrupt("effect generation is not the next durable generation");
  }
  state.generation = effect.generation;

  switch (effect.op) {
    case OpKind::SessionOpen: {
      state.incarnation = effect.incarnation;
      state.control_epoch = ControlEpoch{effect.control_epoch_after};
      state.next_incident_id = effect.next_incident_id;
      state.next_evidence_id = effect.next_evidence_id;
      state.next_authority_id = effect.next_authority_id;
      state.session_open = effect.session_open;
      state.last_close_clean = effect.clean_close;
      break;
    }
    case OpKind::SessionClose: {
      state.session_open = effect.session_open;
      state.last_close_clean = effect.clean_close;
      break;
    }
    case OpKind::RegisterAuthority: {
      if (state.authorities.find(effect.authority) != state.authorities.end()) {
        return Corrupt("a registration effect reused an existing authority identifier");
      }
      AuthorityRecord record;
      record.id = effect.authority;
      record.name = effect.authority_name;
      record.role = effect.authority_role;
      record.active = effect.authority_active;
      record.registered_at = effect.generation;
      record.rationale = effect.rationale;
      state.authorities.emplace(record.id, std::move(record));
      state.authority_names.emplace(effect.authority_name, effect.authority);
      state.next_authority_id = effect.next_authority_id;
      break;
    }
    case OpKind::RevokeAuthority: {
      AuthorityRecord* record = nullptr;
      const auto it = state.authorities.find(effect.authority);
      if (it != state.authorities.end()) record = &it->second;
      if (record == nullptr) return Corrupt("revocation targets an unknown authority");
      record->active = false;
      record->revoked_at = effect.generation;
      break;
    }
    case OpKind::ForceFence: {
      state.control_epoch = ControlEpoch{effect.control_epoch_after};
      break;
    }
    case OpKind::ReportIncident:
    case OpKind::CreateSuccessor: {
      if (effect.created_incident) {
        if (state.incidents.find(effect.incident) != state.incidents.end()) {
          return Corrupt("a creation effect reused an existing incident identifier");
        }
        IncidentRecord record;
        record.id = effect.incident;
        record.cls = effect.cls;
        record.severity = effect.severity;
        record.state = effect.state;
        record.revision = effect.incident_revision;
        record.owner = effect.owner;
        record.reported_by = effect.actor;
        record.scope = effect.scope;
        record.summary = effect.summary;
        record.source_system = effect.source_system;
        record.source_event_id = effect.source_event_id;
        record.predecessor = effect.secondary_incident;
        record.created_at = effect.generation;
        record.updated_at = effect.generation;
        PushHistory(record, effect, record.state, record.severity);
        state.incidents.emplace(record.id, std::move(record));
        state.next_incident_id = effect.next_incident_id;
        const std::string token = ReportDedupToken(effect.source_system, effect.source_event_id);
        // The index always names the most recent incident for a source event, so
        // a recurrence after a terminal incident opens a fresh incident rather
        // than reviving the old one.
        if (!token.empty()) state.report_dedup.insert_or_assign(token, effect.incident);
      } else {
        IncidentRecord* incident = state.MutableIncident(effect.incident);
        if (incident == nullptr) return Corrupt("duplicate report targets an unknown incident");
        incident->revision = effect.incident_revision;
        incident->updated_at = effect.generation;
      }
      InsertEvidence(state, effect);
      state.next_evidence_id = effect.next_evidence_id;
      break;
    }
    case OpKind::AcceptIncident: {
      IncidentRecord* incident = state.MutableIncident(effect.incident);
      if (incident == nullptr) return Corrupt("accept targets an unknown incident");
      PushHistory(*incident, effect, LifecycleState::Accepted, effect.severity);
      incident->state = LifecycleState::Accepted;
      incident->cls = effect.cls;
      incident->severity = effect.severity;
      incident->accepting_authority = effect.actor;
      incident->owner = effect.owner;
      incident->revision = effect.incident_revision;
      incident->updated_at = effect.generation;
      break;
    }
    case OpKind::RejectReport: {
      IncidentRecord* incident = state.MutableIncident(effect.incident);
      if (incident == nullptr) return Corrupt("rejection targets an unknown incident");
      PushHistory(*incident, effect, LifecycleState::Rejected, incident->severity);
      incident->state = LifecycleState::Rejected;
      incident->revision = effect.incident_revision;
      incident->updated_at = effect.generation;
      break;
    }
    case OpKind::RecordEvidence: {
      InsertEvidence(state, effect);
      state.next_evidence_id = effect.next_evidence_id;
      IncidentRecord* incident = state.MutableIncident(effect.incident);
      if (incident == nullptr) return Corrupt("evidence targets an unknown incident");
      incident->revision = effect.incident_revision;
      incident->updated_at = effect.generation;
      break;
    }
    case OpKind::WithdrawEvidence: {
      EvidenceRecord* record = state.MutableEvidence(effect.evidence);
      if (record == nullptr) return Corrupt("withdrawal targets unknown evidence");
      record->withdrawn = true;
      record->withdrawn_at = effect.generation;
      record->withdrawn_by = effect.actor;
      IncidentRecord* incident = state.MutableIncident(effect.incident);
      if (incident == nullptr) return Corrupt("withdrawal targets an unknown incident");
      incident->revision = effect.incident_revision;
      incident->updated_at = effect.generation;
      break;
    }
    case OpKind::ReestablishEvidence: {
      if (!effect.evidence_reestablished) {
        return Corrupt("re-establishment effect is missing its marker flag");
      }
      EvidenceRecord* record = state.MutableEvidence(effect.evidence);
      if (record == nullptr) return Corrupt("re-establishment targets unknown evidence");
      IncidentRecord* incident = state.MutableIncident(effect.incident);
      if (incident == nullptr) return Corrupt("re-establishment targets an unknown incident");
      if (ClassifyEvidence(record->kind) == EvidenceClass::DynamicObservation) {
        record->observation_generation = incident->observation_generation;
      } else {
        record->attestation_generation = incident->attestation_generation;
      }
      incident->revision = effect.incident_revision;
      incident->updated_at = effect.generation;
      break;
    }
    case OpKind::AmendSeverity: {
      IncidentRecord* incident = state.MutableIncident(effect.incident);
      if (incident == nullptr) return Corrupt("severity amendment targets an unknown incident");
      PushHistory(*incident, effect, incident->state, effect.severity);
      incident->severity = effect.severity;
      incident->escalation_count = effect.escalation_count;
      incident->last_escalation_at = effect.last_escalation_at;
      incident->revision = effect.incident_revision;
      incident->updated_at = effect.generation;
      break;
    }
    case OpKind::AmendScope: {
      IncidentRecord* incident = state.MutableIncident(effect.incident);
      if (incident == nullptr) return Corrupt("scope amendment targets an unknown incident");
      PushHistory(*incident, effect, incident->state, incident->severity);
      incident->scope = effect.scope;
      incident->revision = effect.incident_revision;
      incident->updated_at = effect.generation;
      break;
    }
    case OpKind::AssignOwner: {
      IncidentRecord* incident = state.MutableIncident(effect.incident);
      if (incident == nullptr) return Corrupt("assignment targets an unknown incident");
      PushHistory(*incident, effect, incident->state, incident->severity);
      incident->owner = effect.owner;
      incident->revision = effect.incident_revision;
      incident->updated_at = effect.generation;
      break;
    }
    case OpKind::DeclareContained: {
      IncidentRecord* incident = state.MutableIncident(effect.incident);
      if (incident == nullptr) return Corrupt("containment targets an unknown incident");
      PushHistory(*incident, effect, LifecycleState::Contained, incident->severity);
      incident->state = LifecycleState::Contained;
      incident->containment_declared = true;
      incident->revision = effect.incident_revision;
      incident->updated_at = effect.generation;
      break;
    }
    case OpKind::StartRecovery: {
      IncidentRecord* incident = state.MutableIncident(effect.incident);
      if (incident == nullptr) return Corrupt("recovery start targets an unknown incident");
      PushHistory(*incident, effect, LifecycleState::Recovering, incident->severity);
      incident->state = LifecycleState::Recovering;
      incident->recovery_started = true;
      incident->revision = effect.incident_revision;
      incident->updated_at = effect.generation;
      break;
    }
    case OpKind::DeclareRecovered: {
      IncidentRecord* incident = state.MutableIncident(effect.incident);
      if (incident == nullptr) return Corrupt("recovery proof targets an unknown incident");
      PushHistory(*incident, effect, LifecycleState::Recovered, incident->severity);
      incident->state = LifecycleState::Recovered;
      incident->recovery_started = effect.recovery_started;
      incident->observation_generation = effect.observation_generation;
      incident->revision = effect.incident_revision;
      incident->updated_at = effect.generation;
      break;
    }
    case OpKind::ResolveIncident: {
      IncidentRecord* incident = state.MutableIncident(effect.incident);
      if (incident == nullptr) return Corrupt("resolution targets an unknown incident");
      PushHistory(*incident, effect, LifecycleState::Resolved, incident->severity);
      incident->state = LifecycleState::Resolved;
      incident->revision = effect.incident_revision;
      incident->updated_at = effect.generation;
      break;
    }
    case OpKind::CloseIncident: {
      IncidentRecord* incident = state.MutableIncident(effect.incident);
      if (incident == nullptr) return Corrupt("closure targets an unknown incident");
      PushHistory(*incident, effect, LifecycleState::Closed, incident->severity);
      incident->state = LifecycleState::Closed;
      incident->revision = effect.incident_revision;
      incident->updated_at = effect.generation;
      break;
    }
    case OpKind::ReopenIncident: {
      IncidentRecord* incident = state.MutableIncident(effect.incident);
      if (incident == nullptr) return Corrupt("reopen targets an unknown incident");
      PushHistory(*incident, effect, LifecycleState::Reopened, incident->severity);
      incident->state = LifecycleState::Reopened;
      incident->reopen_count = effect.reopen_count;
      incident->observation_generation = effect.observation_generation;
      incident->attestation_generation = effect.attestation_generation;
      incident->revision = effect.incident_revision;
      incident->updated_at = effect.generation;
      break;
    }
    case OpKind::MergeIncident: {
      IncidentRecord* survivor = state.MutableIncident(effect.incident);
      IncidentRecord* absorbed = state.MutableIncident(effect.secondary_incident);
      if (survivor == nullptr || absorbed == nullptr) {
        return Corrupt("merge references an unknown incident");
      }
      PushHistory(*survivor, effect, survivor->state, survivor->severity);
      survivor->scope = effect.scope;
      survivor->revision = effect.incident_revision;
      survivor->updated_at = effect.generation;

      PushHistory(*absorbed, effect, LifecycleState::Superseded, absorbed->severity);
      absorbed->state = LifecycleState::Superseded;
      absorbed->parent = effect.incident;
      absorbed->revision = effect.secondary_revision;
      absorbed->updated_at = effect.generation;
      break;
    }
    default:
      return Corrupt("effect carries an operation this build cannot apply");
  }

  if (effect.key.valid() && effect.op != OpKind::SessionOpen && effect.op != OpKind::SessionClose) {
    IdemRecord record;
    record.key = effect.key;
    record.intent = effect.intent;
    record.generation = effect.generation;
    record.receipt = ReceiptFor(effect);
    state.idempotency.emplace(record.key, std::move(record));
  }

  AuditEntry entry;
  entry.generation = effect.generation;
  entry.op = effect.op;
  entry.actor = effect.actor;
  entry.incident = effect.incident;
  entry.incident_revision = effect.incident_revision;
  entry.summary = DescribeEffect(effect);
  state.audit.push_back(std::move(entry));
  return Status::Ok();
}

// ---------------------------------------------------------------------------
// Deterministic description
// ---------------------------------------------------------------------------

std::string DescribeEffect(const Effect& effect) {
  std::string out = ToString(effect.op);
  out += " req_epoch=" + std::to_string(effect.request_epoch);
  switch (effect.op) {
    case OpKind::SessionOpen:
      out += " incarnation=" + std::to_string(effect.incarnation);
      out += " epoch=" + std::to_string(effect.control_epoch_after);
      break;
    case OpKind::SessionClose:
      break;
    case OpKind::RegisterAuthority:
      out += " authority=" + std::to_string(effect.authority.value());
      out += " role=" + std::string(ToString(effect.authority_role));
      break;
    case OpKind::RevokeAuthority:
      out += " authority=" + std::to_string(effect.authority.value());
      break;
    case OpKind::ForceFence:
      out += " epoch=" + std::to_string(effect.control_epoch_after);
      break;
    case OpKind::ReportIncident:
      out += " incident=" + std::to_string(effect.incident.value());
      out += effect.created_incident ? " created" : " duplicate";
      break;
    case OpKind::CreateSuccessor:
      out += " incident=" + std::to_string(effect.incident.value());
      out += " predecessor=" + std::to_string(effect.secondary_incident.value());
      break;
    case OpKind::MergeIncident:
      out += " survivor=" + std::to_string(effect.incident.value());
      out += " absorbed=" + std::to_string(effect.secondary_incident.value());
      if (effect.cross_class) out += " cross_class";
      break;
    default:
      out += " incident=" + std::to_string(effect.incident.value());
      out += " revision=" + std::to_string(effect.incident_revision);
      break;
  }
  if (effect.evidence.valid()) {
    out += " evidence=" + std::to_string(effect.evidence.value());
  }
  return out;
}

// ---------------------------------------------------------------------------
// Whole-state digest
// ---------------------------------------------------------------------------

Digest256 ComputeStateDigest(const State& state) {
  Encoder encoder;
  encoder.U32(1);  // digest schema version
  encoder.U64(state.generation.value());
  encoder.U64(state.control_epoch.value);
  encoder.U64(state.incarnation);
  encoder.U64(state.next_incident_id);
  encoder.U64(state.next_evidence_id);
  encoder.U64(state.next_authority_id);
  encoder.Bool(state.session_open);
  encoder.Bool(state.last_close_clean);

  encoder.U32(static_cast<std::uint32_t>(state.authorities.size()));
  for (const auto& entry : state.authorities) {
    const AuthorityRecord& record = entry.second;
    encoder.U64(record.id.value());
    encoder.Text(record.name);
    encoder.U8(static_cast<std::uint8_t>(record.role));
    encoder.Bool(record.active);
    encoder.U64(record.registered_at.value());
    encoder.U64(record.revoked_at.value());
    encoder.Text(record.rationale);
  }

  encoder.U32(static_cast<std::uint32_t>(state.incidents.size()));
  for (const auto& entry : state.incidents) {
    const IncidentRecord& record = entry.second;
    encoder.U64(record.id.value());
    encoder.U8(static_cast<std::uint8_t>(record.cls));
    encoder.U8(static_cast<std::uint8_t>(record.severity));
    encoder.U8(static_cast<std::uint8_t>(record.state));
    encoder.U64(record.revision);
    encoder.U64(record.observation_generation);
    encoder.U64(record.attestation_generation);
    encoder.U64(record.reopen_count);
    encoder.Bool(record.recovery_started);
    encoder.Bool(record.containment_declared);
    encoder.U64(record.owner.value());
    encoder.U64(record.reported_by.value());
    encoder.U64(record.accepting_authority.value());
    EncodeScope(encoder, record.scope);
    encoder.Text(record.summary);
    encoder.Text(record.source_system);
    encoder.Text(record.source_event_id);
    encoder.U64(record.parent.value());
    encoder.U64(record.predecessor.value());
    encoder.U64(record.created_at.value());
    encoder.U64(record.updated_at.value());
    encoder.U64(record.last_escalation_at.value());
    encoder.U64(record.escalation_count);
    encoder.U32(static_cast<std::uint32_t>(record.history.size()));
    for (const LifecycleEvent& event : record.history) EncodeEvent(encoder, event);
    encoder.U32(static_cast<std::uint32_t>(record.evidence_ids.size()));
    for (const EvidenceId id : record.evidence_ids) encoder.U64(id.value());
  }

  encoder.U32(static_cast<std::uint32_t>(state.evidence.size()));
  for (const auto& entry : state.evidence) {
    const EvidenceRecord& record = entry.second;
    encoder.U64(record.id.value());
    encoder.U64(record.incident.value());
    encoder.U8(static_cast<std::uint8_t>(record.kind));
    encoder.U64(record.source.value());
    encoder.U64(record.recorded_at.value());
    encoder.U64(record.observation_generation);
    encoder.U64(record.attestation_generation);
    encoder.Bool(record.withdrawn);
    encoder.U64(record.withdrawn_at.value());
    encoder.U64(record.withdrawn_by.value());
    EncodeScope(encoder, record.subject);
    encoder.U8(static_cast<std::uint8_t>(record.asserted_severity));
    encoder.Bool(record.effect_present);
    encoder.Text(record.rationale);
    encoder.Text(record.source_system);
    encoder.Text(record.source_event_id);
    encoder.Text(record.detail);
  }

  encoder.U32(static_cast<std::uint32_t>(state.idempotency.size()));
  for (const auto& entry : state.idempotency) {
    const IdemRecord& record = entry.second;
    encoder.U64(record.key.hi);
    encoder.U64(record.key.lo);
    encoder.Digest(record.intent);
    encoder.U64(record.generation.value());
  }

  encoder.U32(static_cast<std::uint32_t>(state.audit.size()));
  for (const AuditEntry& entry : state.audit) {
    encoder.U64(entry.generation.value());
    encoder.U32(static_cast<std::uint32_t>(entry.op));
    encoder.U64(entry.actor.value());
    encoder.U64(entry.incident.value());
    encoder.U64(entry.incident_revision);
    encoder.Text(entry.summary);
  }

  encoder.U32(static_cast<std::uint32_t>(state.report_dedup.size()));
  for (const auto& entry : state.report_dedup) {
    encoder.Text(entry.first);
    encoder.U64(entry.second.value());
  }

  return ComputeSha256(encoder.data().data(), encoder.size());
}

}  // namespace isf::detail
