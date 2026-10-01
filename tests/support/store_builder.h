// Incident State Fabric - DCCP boundary 50
// Copyright 2026 Summon Software Labs.
// Licensed under the Apache License, Version 2.0.
//
// Writes stores directly through the internal commit path. The public API
// deliberately cannot produce an allocator one step below exhaustion, a session
// that never closed, or a record carrying an unimplemented operation; the
// adversarial and recovery proofs need exactly those stores.

#ifndef ISF_TEST_STORE_BUILDER_H
#define ISF_TEST_STORE_BUILDER_H

#include <cstdint>
#include <functional>
#include <string>
#include <vector>

#include "detail/state.h"
#include "detail/store.h"
#include "isf/model.h"

namespace isftest {

/// Builds a store at \p path whose log is exactly the effects produced by
/// \p build. The callback receives the state as it stands before the effect and
/// the zero-based index, and must return the effect to commit next.
[[nodiscard]] bool WriteStore(
    const std::string& path, std::size_t effect_count,
    const std::function<isf::detail::Effect(const isf::detail::State&, std::size_t)>& build);

/// An effect that opens a session. Session effects are the fabric's own.
[[nodiscard]] isf::detail::Effect SessionOpenEffect(const isf::detail::State& state,
                                                    std::uint64_t incarnation,
                                                    std::uint64_t control_epoch);

[[nodiscard]] std::vector<std::uint8_t> ReadWholeFile(const std::string& path);
[[nodiscard]] bool WriteWholeFile(const std::string& path, const std::vector<std::uint8_t>& bytes);
[[nodiscard]] bool TruncateFileTo(const std::string& path, std::uint64_t length);
[[nodiscard]] bool FlipByte(const std::string& path, std::uint64_t offset);
[[nodiscard]] std::uint64_t FileSize(const std::string& path);

/// Appends raw bytes to the end of a file, which is how a torn or extra tail is
/// simulated without going through the store.
[[nodiscard]] bool AppendBytes(const std::string& path, const std::vector<std::uint8_t>& bytes);

}  // namespace isftest

#endif  // ISF_TEST_STORE_BUILDER_H
