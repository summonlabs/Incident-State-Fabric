// Incident State Fabric - DCCP boundary 50
// Copyright 2026 Summon Software Labs.
// Licensed under the Apache License, Version 2.0.
//
// Canonical byte encoding. Every durable byte in a store is produced here, so
// two stores that observe the same operation sequence produce byte-identical
// files regardless of insertion order, container choice, or thread timing.

#ifndef ISF_DETAIL_CANONICAL_H
#define ISF_DETAIL_CANONICAL_H

#include <cstddef>
#include <cstdint>
#include <string>
#include <string_view>
#include <vector>

#include "detail/crypto.h"

namespace isf::detail {

/// Little-endian, fixed width, length-prefixed writer.
class Encoder {
 public:
  void U8(std::uint8_t value);
  void U16(std::uint16_t value);
  void U32(std::uint32_t value);
  void U64(std::uint64_t value);
  void I64AsU64(std::int64_t value);  // two's complement, explicit
  void Bool(bool value);
  void Raw(const void* data, std::size_t length);
  void Bytes(const std::vector<std::byte>& value);
  void Digest(const Digest256& value);

  /// Length-prefixed UTF-8 text. The caller is responsible for having validated
  /// the text against the field limits first; the encoder never truncates, so a
  /// length bug shows up as a decoder rejection rather than as silent data loss.
  void Text(std::string_view value);

  [[nodiscard]] const std::vector<std::byte>& data() const noexcept { return buffer_; }
  [[nodiscard]] std::size_t size() const noexcept { return buffer_.size(); }
  [[nodiscard]] std::vector<std::byte> Take() noexcept { return std::move(buffer_); }

 private:
  std::vector<std::byte> buffer_;
};

/// Bounds-checked reader. Every accessor returns false instead of reading out of
/// range; a decoder that has returned false must not be used further.
class Decoder {
 public:
  Decoder(const std::byte* data, std::size_t length) noexcept;

  bool U8(std::uint8_t& out);
  bool U16(std::uint16_t& out);
  bool U32(std::uint32_t& out);
  bool U64(std::uint64_t& out);
  bool I64FromU64(std::int64_t& out);
  bool Bool(bool& out);
  bool Raw(void* out, std::size_t length);
  bool Bytes(std::vector<std::byte>& out, std::size_t maximum);
  bool Digest(Digest256& out);
  bool Text(std::string& out, std::size_t maximum);

  [[nodiscard]] bool failed() const noexcept { return failed_; }
  [[nodiscard]] bool done() const noexcept { return !failed_ && position_ == length_; }
  [[nodiscard]] std::size_t remaining() const noexcept {
    return failed_ ? 0 : (length_ - position_);
  }
  [[nodiscard]] std::size_t position() const noexcept { return position_; }

  /// Fail the decoder deliberately, for semantic checks performed by the caller.
  void Poison() noexcept { failed_ = true; }

 private:
  bool Require(std::size_t count) noexcept;

  const std::byte* data_;
  std::size_t length_;
  std::size_t position_{0};
  bool failed_{false};
};

// ---------------------------------------------------------------------------
// Text validation
// ---------------------------------------------------------------------------

/// Strict UTF-8 well-formedness: rejects overlong encodings, surrogate code
/// points, values above U+10FFFF, and truncated sequences.
[[nodiscard]] bool IsValidUtf8(std::string_view text) noexcept;

/// True when the text is valid UTF-8, non-empty, within \p maximum bytes, and
/// contains no C0/C1 control characters other than nothing at all.
[[nodiscard]] bool IsValidToken(std::string_view text, std::size_t maximum) noexcept;

/// True when the text is valid UTF-8 and within \p maximum bytes; may be empty
/// and may contain newlines and tabs.
[[nodiscard]] bool IsValidFreeText(std::string_view text, std::size_t maximum) noexcept;

/// Number of Unicode code points, used for human-facing length policy.
[[nodiscard]] std::size_t Utf8CodePointCount(std::string_view text) noexcept;

}  // namespace isf::detail

#endif  // ISF_DETAIL_CANONICAL_H
