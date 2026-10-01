// Incident State Fabric - DCCP boundary 50
// Copyright 2026 Summon Software Labs.
// Licensed under the Apache License, Version 2.0.
//
// On-disk framing. Two structures exist:
//
//   * a record, which is one durably committed operation inside a segment file;
//   * a manifest, which names the exact committed byte range of every segment
//     and is published atomically. The manifest rename is the single commit
//     point of the store: bytes appended past the manifest's declared length
//     are never authoritative.

#ifndef ISF_DETAIL_FORMAT_H
#define ISF_DETAIL_FORMAT_H

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

#include "detail/crypto.h"
#include "isf/model.h"
#include "isf/result.h"
#include "isf/types.h"

namespace isf::detail {

/// Little-endian u32 whose on-disk bytes read "ISFR".
inline constexpr std::uint32_t kRecordMagic = 0x52465349u;
inline constexpr char kManifestMagic[8] = {'I', 'S', 'F', 'M', 'A', 'N', 'I', 'F'};
inline constexpr std::uint16_t kFormatVersion = 1;

inline constexpr std::size_t kRecordHeaderBytes =
    4 + 2 + 2 + 4 + 8 + 4 + 4 + kDigestBytes + kDigestBytes;  // 92
inline constexpr std::size_t kRecordTrailerBytes = kDigestBytes;

struct SegmentDescriptor {
  std::uint32_t index = 0;
  std::uint64_t byte_length = 0;
  std::uint64_t record_count = 0;
  Digest256 chain_head;

  friend bool operator==(const SegmentDescriptor& a, const SegmentDescriptor& b) noexcept {
    return a.index == b.index && a.byte_length == b.byte_length &&
           a.record_count == b.record_count && a.chain_head == b.chain_head;
  }
};

struct Manifest {
  std::uint16_t version = kFormatVersion;
  std::uint64_t manifest_seq = 0;
  Generation generation;
  ControlEpoch control_epoch;
  std::uint64_t incarnation = 0;
  std::uint64_t next_incident_id = 0;
  std::uint64_t next_evidence_id = 0;
  std::uint64_t next_authority_id = 0;
  bool session_open = false;
  bool last_close_clean = true;
  bool digest_current = false;
  Generation state_digest_generation;
  Digest256 state_digest;
  std::vector<SegmentDescriptor> segments;
};

/// The parts of authoritative state that the manifest commits to directly.
/// Recovery replays the log and requires these to match exactly.
struct StateCounters {
  Generation generation;
  ControlEpoch control_epoch;
  std::uint64_t incarnation = 0;
  std::uint64_t next_incident_id = 0;
  std::uint64_t next_evidence_id = 0;
  std::uint64_t next_authority_id = 0;
  bool session_open = false;
  bool last_close_clean = true;
};

[[nodiscard]] std::vector<std::byte> EncodeManifest(const Manifest& manifest);
[[nodiscard]] Result<Manifest> DecodeManifest(const std::byte* data, std::size_t length);

/// A decoded record header plus the payload bytes that follow it.
struct RecordFrame {
  std::uint32_t payload_length = 0;
  std::uint64_t generation = 0;
  OpKind op = OpKind::SessionOpen;
  Digest256 prev_chain;
  Digest256 payload_digest;
  const std::byte* payload = nullptr;
  std::size_t total_bytes = 0;
  Digest256 chain_digest;
};

/// Frame and checksum one record. \p out receives header + payload + trailer.
/// \p chain_out receives the chain digest that the next record in the segment
/// must reference.
void EncodeRecord(std::uint64_t generation, OpKind op, const std::vector<std::byte>& payload,
                  const Digest256& prev_chain, std::vector<std::byte>& out, Digest256& chain_out);

/// Decode one record starting at \p data with \p available bytes remaining.
/// Fails when the magic, version, payload length, or either digest is invalid.
[[nodiscard]] Result<RecordFrame> DecodeRecord(const std::byte* data, std::size_t available);

/// Chain digest of a record given its raw bytes, as written on disk.
[[nodiscard]] Digest256 ChainDigestOfRecord(const std::byte* record, std::size_t total_bytes);

/// Canonical segment file name for an index, e.g. seg-00000000000000000007.isf.
[[nodiscard]] std::string SegmentFileName(std::uint32_t index);

/// Parse a segment file name. Returns false when the name is not exactly the
/// canonical form, which is how stray and hostile names are rejected.
[[nodiscard]] bool ParseSegmentFileName(const std::string& name, std::uint32_t& index);

/// Windows reserved device names are refused outright rather than silently
/// creating an aliased file.
[[nodiscard]] bool IsReservedDeviceName(const std::string& name) noexcept;

}  // namespace isf::detail

#endif  // ISF_DETAIL_FORMAT_H
