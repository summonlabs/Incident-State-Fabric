// Incident State Fabric - DCCP boundary 50
// Copyright 2026 Summon Software Labs.
// Licensed under the Apache License, Version 2.0.
//
// Library version. Kept in lock-step with the CMake project version by
// tests/release/test_version_consistency.cpp.

#ifndef ISF_VERSION_H
#define ISF_VERSION_H

#include <cstdint>

#define ISF_VERSION_MAJOR 1
#define ISF_VERSION_MINOR 0
#define ISF_VERSION_PATCH 0
#define ISF_VERSION_STRING "1.0.0"

namespace isf {

struct Version {
  std::uint32_t major = ISF_VERSION_MAJOR;
  std::uint32_t minor = ISF_VERSION_MINOR;
  std::uint32_t patch = ISF_VERSION_PATCH;

  friend constexpr bool operator==(const Version& a, const Version& b) noexcept {
    return a.major == b.major && a.minor == b.minor && a.patch == b.patch;
  }
  friend constexpr bool operator!=(const Version& a, const Version& b) noexcept { return !(a == b); }
};

/// Compile-time version of the headers that were included.
[[nodiscard]] constexpr Version HeaderVersion() noexcept { return Version{}; }

/// Runtime version of the linked library. Always equals HeaderVersion() for a
/// correctly packaged install; a mismatch indicates a mixed-version install.
[[nodiscard]] const char* VersionString() noexcept;
[[nodiscard]] Version LibraryVersion() noexcept;

/// Stable identifier of the persistence format this build reads and writes.
[[nodiscard]] const char* StoreFormatIdentifier() noexcept;
[[nodiscard]] std::uint16_t StoreFormatVersion() noexcept;

}  // namespace isf

#endif  // ISF_VERSION_H
