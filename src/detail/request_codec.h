// Incident State Fabric - DCCP boundary 50
// Copyright 2026 Summon Software Labs.
// Licensed under the Apache License, Version 2.0.

#ifndef ISF_DETAIL_REQUEST_CODEC_H
#define ISF_DETAIL_REQUEST_CODEC_H

#include <string>

#include "detail/crypto.h"
#include "detail/state.h"
#include "isf/model.h"
#include "isf/requests.h"
#include "isf/result.h"

namespace isf::detail {

/// Canonical encoding of everything that defines the intent of a request. The
/// control epoch is deliberately excluded: a lost-response retry issued after a
/// restart carries the successor's epoch but is still the same operation, so
/// replay must be recognised before any fencing check is applied.
[[nodiscard]] Digest256 ComputeIntentDigest(const AnyRequest& request);

/// Field-level validation that does not depend on store state.
[[nodiscard]] Status ValidateRequestShape(const AnyRequest& request);

/// Runtime capacity limits, checked before allocating a new identity.
[[nodiscard]] Status CheckCapacity(const State& state, const StoreLimits& limits, OpKind op);

/// Canonicalises a scope and validates every identifier. Duplicates are
/// removed and ordering is fixed, so canonical bytes never depend on caller
/// order.
[[nodiscard]] Status ValidateAndCanonicalizeScope(AffectedScope& scope, const char* field);

}  // namespace isf::detail

#endif  // ISF_DETAIL_REQUEST_CODEC_H
