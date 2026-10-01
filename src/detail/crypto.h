// Incident State Fabric - DCCP boundary 50
// Copyright 2026 Summon Software Labs.
// Licensed under the Apache License, Version 2.0.

#ifndef ISF_DETAIL_CRYPTO_H
#define ISF_DETAIL_CRYPTO_H

#include <array>
#include <cstddef>
#include <cstdint>
#include <string>

namespace isf::detail {

/// A 256-bit SHA-256 digest. Used for record chaining, payload integrity, and
/// whole-state checkpoints. This is an integrity mechanism, not a signature:
/// it detects corruption and accidental divergence, it does not authenticate a
/// hostile writer.
struct Digest256 {
  std::array<std::uint8_t, 32> bytes{};

  friend bool operator==(const Digest256& a, const Digest256& b) noexcept { return a.bytes == b.bytes; }
  friend bool operator!=(const Digest256& a, const Digest256& b) noexcept { return !(a == b); }
  friend bool operator<(const Digest256& a, const Digest256& b) noexcept { return a.bytes < b.bytes; }

  [[nodiscard]] bool IsZero() const noexcept;
  [[nodiscard]] std::string Hex() const;
};

inline constexpr std::size_t kDigestBytes = 32;

/// Streaming SHA-256 (FIPS 180-4).
class Sha256 {
 public:
  Sha256() noexcept;

  void Update(const void* data, std::size_t length) noexcept;
  [[nodiscard]] Digest256 Finish() noexcept;

  Sha256(const Sha256&) = delete;
  Sha256& operator=(const Sha256&) = delete;

 private:
  void Compress(const std::uint8_t* block) noexcept;

  std::array<std::uint32_t, 8> state_{};
  std::array<std::uint8_t, 64> buffer_{};
  std::uint64_t total_{0};
  std::size_t buffered_{0};
};

[[nodiscard]] Digest256 ComputeSha256(const void* data, std::size_t length) noexcept;

}  // namespace isf::detail

#endif  // ISF_DETAIL_CRYPTO_H
