// Incident State Fabric - DCCP boundary 50
// Copyright 2026 Summon Software Labs.
// Licensed under the Apache License, Version 2.0.

#include "detail/format.h"

#include <algorithm>
#include <array>
#include <cstdio>

#include "detail/canonical.h"

namespace isf::detail {
namespace {

[[nodiscard]] Status Corrupt(const char* detail) {
  return Status::Error(ErrorCode::StoreCorrupt, detail);
}

}  // namespace

std::vector<std::byte> EncodeManifest(const Manifest& manifest) {
  Encoder encoder;
  encoder.Raw(kManifestMagic, sizeof(kManifestMagic));
  encoder.U16(manifest.version);
  encoder.U16(0);
  encoder.U32(0);  // total_bytes placeholder
  encoder.U64(manifest.manifest_seq);
  encoder.U64(manifest.generation.value());
  encoder.U64(manifest.control_epoch.value);
  encoder.U64(manifest.incarnation);
  encoder.U64(manifest.next_incident_id);
  encoder.U64(manifest.next_evidence_id);
  encoder.U64(manifest.next_authority_id);
  encoder.Bool(manifest.session_open);
  encoder.Bool(manifest.last_close_clean);
  encoder.Bool(manifest.digest_current);
  encoder.U8(0);
  encoder.U32(static_cast<std::uint32_t>(manifest.segments.size()));
  for (const SegmentDescriptor& segment : manifest.segments) {
    encoder.U32(segment.index);
    encoder.U64(segment.byte_length);
    encoder.U64(segment.record_count);
    encoder.Digest(segment.chain_head);
  }
  encoder.Digest(manifest.state_digest);
  encoder.U64(manifest.state_digest_generation.value());

  std::vector<std::byte> body = encoder.Take();
  const std::uint32_t total = static_cast<std::uint32_t>(body.size() + kDigestBytes);
  // Patch the total length at its fixed offset: magic(8) + version(2) + reserved(2).
  const std::size_t offset = sizeof(kManifestMagic) + 2 + 2;
  for (std::size_t i = 0; i < 4; ++i) {
    body[offset + i] = static_cast<std::byte>((total >> (8u * static_cast<unsigned>(i))) & 0xffu);
  }

  const Digest256 checksum = ComputeSha256(body.data(), body.size());
  Encoder trailer;
  trailer.Digest(checksum);
  std::vector<std::byte> trailer_bytes = trailer.Take();
  body.insert(body.end(), trailer_bytes.begin(), trailer_bytes.end());
  return body;
}

Result<Manifest> DecodeManifest(const std::byte* data, std::size_t length) {
  if (data == nullptr) return Corrupt("manifest pointer is null");
  if (length < sizeof(kManifestMagic) + 2 + 2 + 4 + kDigestBytes) {
    return Corrupt("manifest is smaller than its fixed header");
  }
  if (length > FormatLimits::kMaxManifestBytes) return Corrupt("manifest exceeds the format maximum");
  for (std::size_t i = 0; i < sizeof(kManifestMagic); ++i) {
    if (std::to_integer<char>(data[i]) != kManifestMagic[i]) {
      return Corrupt("manifest magic does not match this store format");
    }
  }

  const Digest256 stored = ComputeSha256(data, length - kDigestBytes);
  Digest256 recorded;
  for (std::size_t i = 0; i < kDigestBytes; ++i) {
    recorded.bytes[i] = std::to_integer<std::uint8_t>(data[length - kDigestBytes + i]);
  }
  if (!(stored == recorded)) {
    return Status::Error(ErrorCode::IntegrityFailure, "manifest checksum does not match its contents");
  }

  // The trailing digest is verified above; the decodable body ends before it.
  Decoder decoder(data, length - kDigestBytes);
  std::array<char, 8> magic{};
  if (!decoder.Raw(magic.data(), magic.size())) return Corrupt("manifest header is truncated");

  Manifest manifest;
  std::uint16_t version = 0;
  std::uint16_t reserved16 = 0;
  std::uint32_t total_bytes = 0;
  std::uint8_t reserved8 = 0;
  if (!decoder.U16(version) || !decoder.U16(reserved16) || !decoder.U32(total_bytes)) {
    return Corrupt("manifest header is truncated");
  }
  if (version != kFormatVersion) {
    return Status::Error(ErrorCode::StoreIncompatible,
                         "manifest format version " + std::to_string(version) +
                             " is not supported by this build (expected " +
                             std::to_string(kFormatVersion) + ")");
  }
  if (static_cast<std::size_t>(total_bytes) != length) {
    return Corrupt("manifest length field does not match the file size");
  }
  manifest.version = version;
  std::uint64_t generation = 0;
  std::uint64_t epoch = 0;
  if (!decoder.U64(manifest.manifest_seq) || !decoder.U64(generation) || !decoder.U64(epoch) ||
      !decoder.U64(manifest.incarnation) || !decoder.U64(manifest.next_incident_id) ||
      !decoder.U64(manifest.next_evidence_id) || !decoder.U64(manifest.next_authority_id) ||
      !decoder.Bool(manifest.session_open) || !decoder.Bool(manifest.last_close_clean) ||
      !decoder.Bool(manifest.digest_current) || !decoder.U8(reserved8)) {
    return Corrupt("manifest body is truncated");
  }
  manifest.generation = Generation{generation};
  manifest.control_epoch = ControlEpoch{epoch};

  std::uint32_t segment_count = 0;
  if (!decoder.U32(segment_count)) return Corrupt("manifest segment count is truncated");
  if (segment_count > FormatLimits::kMaxSegments) {
    return Status::Error(ErrorCode::ResourceExhausted,
                         "manifest declares " + std::to_string(segment_count) +
                             " segments, above the format maximum of " +
                             std::to_string(FormatLimits::kMaxSegments));
  }
  // Bounded pre-allocation: refuse absurd counts before reserving memory.
  if (static_cast<std::uint64_t>(segment_count) * (4 + 8 + 8 + kDigestBytes) >
      FormatLimits::kMaxManifestBytes) {
    return Corrupt("manifest segment table cannot fit in the format maximum");
  }
  manifest.segments.reserve(segment_count);
  for (std::uint32_t i = 0; i < segment_count; ++i) {
    SegmentDescriptor descriptor;
    std::uint64_t record_count = 0;
    if (!decoder.U32(descriptor.index) || !decoder.U64(descriptor.byte_length) ||
        !decoder.U64(record_count) || !decoder.Digest(descriptor.chain_head)) {
      return Corrupt("manifest segment table is truncated");
    }
    descriptor.record_count = record_count;
    if (descriptor.index != i) {
      return Corrupt("manifest segment indices are not contiguous from zero");
    }
    if (descriptor.byte_length > FormatLimits::kMaxSegmentBytes) {
      return Corrupt("manifest segment length is implausible");
    }
    manifest.segments.push_back(descriptor);
  }

  std::uint64_t digest_generation = 0;
  if (!decoder.Digest(manifest.state_digest) || !decoder.U64(digest_generation)) {
    return Corrupt("manifest digest block is truncated");
  }
  manifest.state_digest_generation = Generation{digest_generation};
  if (!decoder.done()) return Corrupt("manifest has trailing bytes");

  std::uint64_t expected_records = 0;
  for (const SegmentDescriptor& segment : manifest.segments) expected_records += segment.record_count;
  if (expected_records != manifest.generation.value()) {
    return Corrupt("manifest record count does not match its generation");
  }
  if (manifest.state_digest_generation.value() > manifest.generation.value()) {
    return Corrupt("manifest checkpoint generation is ahead of the committed generation");
  }
  return manifest;
}

void EncodeRecord(std::uint64_t generation, OpKind op, const std::vector<std::byte>& payload,
                  const Digest256& prev_chain, std::vector<std::byte>& out, Digest256& chain_out) {
  Encoder header;
  header.U32(kRecordMagic);
  header.U16(kFormatVersion);
  header.U16(0);
  header.U32(static_cast<std::uint32_t>(payload.size()));
  header.U64(generation);
  header.U32(static_cast<std::uint32_t>(op));
  header.U32(0);
  header.Digest(prev_chain);
  const Digest256 payload_digest = ComputeSha256(payload.data(), payload.size());
  header.Digest(payload_digest);
  const std::vector<std::byte> header_bytes = header.Take();

  Sha256 hasher;
  hasher.Update(header_bytes.data(), header_bytes.size());
  hasher.Update(payload.data(), payload.size());
  chain_out = hasher.Finish();

  out.clear();
  out.reserve(header_bytes.size() + payload.size() + kRecordTrailerBytes);
  out.insert(out.end(), header_bytes.begin(), header_bytes.end());
  out.insert(out.end(), payload.begin(), payload.end());
  const auto* chain_bytes = reinterpret_cast<const std::byte*>(chain_out.bytes.data());
  out.insert(out.end(), chain_bytes, chain_bytes + chain_out.bytes.size());
}

Digest256 ChainDigestOfRecord(const std::byte* record, std::size_t total_bytes) {
  return ComputeSha256(record, total_bytes - kRecordTrailerBytes);
}

Result<RecordFrame> DecodeRecord(const std::byte* data, std::size_t available) {
  if (available < kRecordHeaderBytes + kRecordTrailerBytes) {
    return Corrupt("record header is truncated");
  }
  Decoder decoder(data, available);
  std::uint32_t magic = 0;
  std::uint16_t version = 0;
  std::uint16_t reserved16 = 0;
  std::uint32_t payload_length = 0;
  std::uint64_t generation = 0;
  std::uint32_t op_raw = 0;
  std::uint32_t reserved32 = 0;
  RecordFrame frame;
  if (!decoder.U32(magic) || !decoder.U16(version) || !decoder.U16(reserved16) ||
      !decoder.U32(payload_length) || !decoder.U64(generation) || !decoder.U32(op_raw) ||
      !decoder.U32(reserved32) || !decoder.Digest(frame.prev_chain) ||
      !decoder.Digest(frame.payload_digest)) {
    return Corrupt("record header is truncated");
  }
  if (magic != kRecordMagic) return Corrupt("record magic does not match this store format");
  if (version != kFormatVersion) {
    return Status::Error(ErrorCode::StoreIncompatible,
                         "record format version " + std::to_string(version) + " is not supported");
  }
  if (payload_length > FormatLimits::kMaxRecordBytes) {
    return Status::Error(ErrorCode::ResourceExhausted,
                         "record payload length " + std::to_string(payload_length) +
                             " exceeds the format maximum");
  }
  if (!IsKnownOpKind(op_raw)) {
    return Status::Error(ErrorCode::StoreIncompatible,
                         "record carries operation kind " + std::to_string(op_raw) +
                             " which this build does not implement");
  }
  const std::size_t total = kRecordHeaderBytes + static_cast<std::size_t>(payload_length) +
                            kRecordTrailerBytes;
  if (total > available) return Corrupt("record payload is truncated");
  if (total > FormatLimits::kMaxRecordBytes + kRecordHeaderBytes + kRecordTrailerBytes) {
    return Status::Error(ErrorCode::ResourceExhausted, "record exceeds the format maximum");
  }

  frame.payload_length = payload_length;
  frame.generation = generation;
  frame.op = static_cast<OpKind>(op_raw);
  frame.payload = data + kRecordHeaderBytes;
  frame.total_bytes = total;

  const Digest256 payload_digest = ComputeSha256(frame.payload, payload_length);
  if (!(payload_digest == frame.payload_digest)) {
    return Status::Error(ErrorCode::IntegrityFailure, "record payload digest does not match");
  }
  const Digest256 chain = ChainDigestOfRecord(data, total);
  Digest256 recorded_chain;
  for (std::size_t i = 0; i < kRecordTrailerBytes; ++i) {
    recorded_chain.bytes[i] = std::to_integer<std::uint8_t>(data[total - kRecordTrailerBytes + i]);
  }
  if (!(chain == recorded_chain)) {
    return Status::Error(ErrorCode::IntegrityFailure, "record chain digest does not match");
  }
  frame.chain_digest = chain;
  return frame;
}

std::string SegmentFileName(std::uint32_t index) {
  char buffer[64];
  std::snprintf(buffer, sizeof(buffer), "seg-%020u.isf", static_cast<unsigned>(index));
  return std::string(buffer);
}

bool ParseSegmentFileName(const std::string& name, std::uint32_t& index) {
  const std::string prefix = "seg-";
  const std::string suffix = ".isf";
  if (name.size() != prefix.size() + FormatLimits::kSegmentSuffixDigits + suffix.size()) return false;
  if (name.compare(0, prefix.size(), prefix) != 0) return false;
  if (name.compare(name.size() - suffix.size(), suffix.size(), suffix) != 0) return false;
  std::uint64_t value = 0;
  for (std::size_t i = 0; i < FormatLimits::kSegmentSuffixDigits; ++i) {
    const char raw = name[prefix.size() + i];
    if (raw < '0' || raw > '9') return false;
    const std::uint64_t digit = static_cast<std::uint64_t>(raw - '0');
    // Refuse an index that would wrap or exceed the supported range rather than
    // silently accepting a different segment number.
    if (value > (0xffffffffull - digit) / 10ull) return false;
    value = value * 10ull + digit;
  }
  index = static_cast<std::uint32_t>(value);
  return true;
}

bool IsReservedDeviceName(const std::string& name) noexcept {
  if (name.empty()) return false;
  std::string stem;
  for (const char raw : name) {
    if (raw == '.') break;
    stem.push_back(raw);
  }
  if (stem.empty()) return false;
  std::string upper;
  upper.reserve(stem.size());
  for (const char raw : stem) {
    upper.push_back(static_cast<char>((raw >= 'a' && raw <= 'z') ? (raw - 'a' + 'A') : raw));
  }
  if (upper == "CON" || upper == "PRN" || upper == "AUX" || upper == "NUL") return true;
  if (upper.size() == 4) {
    const bool com = upper.compare(0, 3, "COM") == 0;
    const bool lpt = upper.compare(0, 3, "LPT") == 0;
    if ((com || lpt) && upper[3] >= '1' && upper[3] <= '9') return true;
  }
  return false;
}

}  // namespace isf::detail
