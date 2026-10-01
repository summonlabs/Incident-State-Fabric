// Incident State Fabric - DCCP boundary 50
// Copyright 2026 Summon Software Labs.
// Licensed under the Apache License, Version 2.0.
//
// The single decision function of the fabric. Both the durable commit path and
// the read-only Preview path call EvaluateRequest, so a preview can never
// disagree with what a commit would do.

#ifndef ISF_DETAIL_EVALUATE_H
#define ISF_DETAIL_EVALUATE_H

#include <cstdint>
#include <string>
#include <vector>

#include "detail/crypto.h"
#include "detail/state.h"
#include "isf/model.h"
#include "isf/requests.h"
#include "isf/result.h"

namespace isf::detail {

enum class DecisionKind : std::uint8_t {
  /// No decision has been reached yet. The default must never mean "denied",
  /// because a successful dispatch leaves the decision untouched.
  Undecided = 0,
  Commit = 1,
  Replay = 2,
  Denied = 3,
};

struct Evaluation {
  DecisionKind kind = DecisionKind::Undecided;

  Effect effect;               // valid when kind == Commit
  CommitReceipt receipt;       // valid when kind == Commit or Replay
  Status denial;               // valid when kind == Denied
  std::vector<GateFailure> failures;

  IncidentId incident;
  LifecycleState from_state = LifecycleState::Reported;
  LifecycleState to_state = LifecycleState::Reported;
  Severity from_severity = Severity::Unclassified;
  Severity to_severity = Severity::Unclassified;
  std::uint64_t from_revision = 0;
  std::uint64_t to_revision = 0;
};

/// Decide what a request does against \p state. Pure: never mutates state.
///
/// Order of resolution is fixed and observable:
///   1. request shape;
///   2. idempotent replay of an already-committed operation (a lost response
///      must not become a second mutation, even across a restart);
///   3. control-epoch fencing;
///   4. authority resolution and role;
///   5. runtime capacity limits;
///   6. operation semantics and evidence gates.
[[nodiscard]] Evaluation EvaluateRequest(const State& state, const AnyRequest& request,
                                         const StoreLimits& limits, const Digest256& intent);

}  // namespace isf::detail

#endif  // ISF_DETAIL_EVALUATE_H
