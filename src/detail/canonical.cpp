// Incident State Fabric - DCCP boundary 50
// Copyright 2026 Summon Software Labs.
// Licensed under the Apache License, Version 2.0.

#include "detail/canonical.h"

#include <cstring>

namespace isf::detail {

void Encoder::U8(std::uint8_t value) { buffer_.push_back(static_cast<std::byte>(value)); }

void Encoder::U16(std::uint16_t value) {
  buffer_.push_back(static_cast<std::byte>(value & 0xffu));
  buffer_.push_back(static_cast<std::byte>((value >> 8u) & 0xffu));
}

void Encoder::U32(std::uint32_t value) {
  for (unsigned shift = 0; shift < 32; shift += 8) {
    buffer_.push_back(static_cast<std::byte>((value >> shift) & 0xffu));
  }
}

void Encoder::U64(std::uint64_t value) {
  for (unsigned shift = 0; shift < 64; shift += 8) {
    buffer_.push_back(static_cast<std::byte>((value >> shift) & 0xffu));
  }
}

void Encoder::I64AsU64(std::int64_t value) { U64(static_cast<std::uint64_t>(value)); }

void Encoder::Bool(bool value) { U8(value ? 1u : 0u); }

void Encoder::Raw(const void* data, std::size_t length) {
  if (length == 0) return;
  const auto* bytes = static_cast<const std::byte*>(data);
  buffer_.insert(buffer_.end(), bytes, bytes + length);
}

void Encoder::Bytes(const std::vector<std::byte>& value) {
  const std::uint64_t length = static_cast<std::uint64_t>(value.size());
  U64(length);
  Raw(value.data(), value.size());
}

void Encoder::Digest(const Digest256& value) { Raw(value.bytes.data(), value.bytes.size()); }

void Encoder::Text(std::string_view value) {
  U32(static_cast<std::uint32_t>(value.size()));
  Raw(value.data(), value.size());
}

Decoder::Decoder(const std::byte* data, std::size_t length) noexcept
    : data_(data), length_(length) {}

bool Decoder::Require(std::size_t count) noexcept {
  if (failed_) return false;
  if (count > length_ - position_) {
    failed_ = true;
    return false;
  }
  return true;
}

bool Decoder::U8(std::uint8_t& out) {
  if (!Require(1)) return false;
  out = std::to_integer<std::uint8_t>(data_[position_]);
  position_ += 1;
  return true;
}

bool Decoder::U16(std::uint16_t& out) {
  if (!Require(2)) return false;
  out = static_cast<std::uint16_t>(std::to_integer<std::uint8_t>(data_[position_])) |
        static_cast<std::uint16_t>(static_cast<std::uint16_t>(
            std::to_integer<std::uint8_t>(data_[position_ + 1])) << 8u);
  position_ += 2;
  return true;
}

bool Decoder::U32(std::uint32_t& out) {
  if (!Require(4)) return false;
  std::uint32_t value = 0;
  for (std::size_t i = 0; i < 4; ++i) {
    value |= static_cast<std::uint32_t>(std::to_integer<std::uint8_t>(data_[position_ + i]))
             << (8u * static_cast<unsigned>(i));
  }
  out = value;
  position_ += 4;
  return true;
}

bool Decoder::U64(std::uint64_t& out) {
  if (!Require(8)) return false;
  std::uint64_t value = 0;
  for (std::size_t i = 0; i < 8; ++i) {
    value |= static_cast<std::uint64_t>(std::to_integer<std::uint8_t>(data_[position_ + i]))
             << (8u * static_cast<unsigned>(i));
  }
  out = value;
  position_ += 8;
  return true;
}

bool Decoder::I64FromU64(std::int64_t& out) {
  std::uint64_t raw = 0;
  if (!U64(raw)) return false;
  out = static_cast<std::int64_t>(raw);
  return true;
}

bool Decoder::Bool(bool& out) {
  std::uint8_t raw = 0;
  if (!U8(raw)) return false;
  if (raw > 1) {
    failed_ = true;
    return false;
  }
  out = raw == 1;
  return true;
}

bool Decoder::Raw(void* out, std::size_t length) {
  if (!Require(length)) return false;
  if (length > 0) std::memcpy(out, data_ + position_, length);
  position_ += length;
  return true;
}

bool Decoder::Bytes(std::vector<std::byte>& out, std::size_t maximum) {
  std::uint64_t length = 0;
  if (!U64(length)) return false;
  if (length > static_cast<std::uint64_t>(maximum)) {
    failed_ = true;
    return false;
  }
  const auto count = static_cast<std::size_t>(length);
  if (!Require(count)) return false;
  out.assign(data_ + position_, data_ + position_ + count);
  position_ += count;
  return true;
}

bool Decoder::Digest(Digest256& out) { return Raw(out.bytes.data(), out.bytes.size()); }

bool Decoder::Text(std::string& out, std::size_t maximum) {
  std::uint32_t length = 0;
  if (!U32(length)) return false;
  if (length > maximum) {
    failed_ = true;
    return false;
  }
  if (!Require(length)) return false;
  out.assign(reinterpret_cast<const char*>(data_ + position_), length);
  position_ += length;
  return true;
}

// ---------------------------------------------------------------------------
// Text validation
// ---------------------------------------------------------------------------

bool IsValidUtf8(std::string_view text) noexcept {
  std::size_t i = 0;
  const std::size_t n = text.size();
  while (i < n) {
    const auto byte = static_cast<unsigned char>(text[i]);
    if (byte < 0x80u) {
      ++i;
      continue;
    }
    std::size_t extra = 0;
    std::uint32_t code_point = 0;
    if (byte >= 0xc2u && byte <= 0xdfu) {
      extra = 1;
      code_point = byte & 0x1fu;
    } else if (byte >= 0xe0u && byte <= 0xefu) {
      extra = 2;
      code_point = byte & 0x0fu;
    } else if (byte >= 0xf0u && byte <= 0xf4u) {
      extra = 3;
      code_point = byte & 0x07u;
    } else {
      return false;  // continuation byte or invalid lead (0x80-0xC1, 0xF5-0xFF)
    }
    if (i + extra >= n) return false;
    for (std::size_t k = 1; k <= extra; ++k) {
      const auto continuation = static_cast<unsigned char>(text[i + k]);
      if ((continuation & 0xc0u) != 0x80u) return false;
      code_point = (code_point << 6u) | (continuation & 0x3fu);
    }
    // Reject overlong encodings, UTF-16 surrogates, and out-of-range values.
    if (extra == 2 && code_point < 0x800u) return false;
    if (extra == 3 && code_point < 0x10000u) return false;
    if (code_point >= 0xd800u && code_point <= 0xdfffu) return false;
    if (code_point > 0x10ffffu) return false;
    i += extra + 1;
  }
  return true;
}

std::size_t Utf8CodePointCount(std::string_view text) noexcept {
  std::size_t count = 0;
  for (const char raw : text) {
    if ((static_cast<unsigned char>(raw) & 0xc0u) != 0x80u) ++count;
  }
  return count;
}

bool IsValidToken(std::string_view text, std::size_t maximum) noexcept {
  if (text.empty() || text.size() > maximum) return false;
  if (!IsValidUtf8(text)) return false;
  for (const char raw : text) {
    const auto byte = static_cast<unsigned char>(raw);
    if (byte < 0x20u || byte == 0x7fu) return false;
  }
  return true;
}

bool IsValidFreeText(std::string_view text, std::size_t maximum) noexcept {
  if (text.size() > maximum) return false;
  if (!IsValidUtf8(text)) return false;
  for (const char raw : text) {
    const auto byte = static_cast<unsigned char>(raw);
    if (byte == 0x00u) return false;
    if (byte < 0x20u && byte != 0x09u && byte != 0x0au && byte != 0x0du) return false;
    if (byte == 0x7fu) return false;
  }
  return true;
}

}  // namespace isf::detail
