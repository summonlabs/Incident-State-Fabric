// Incident State Fabric - DCCP boundary 50
// Copyright 2026 Summon Software Labs.
// Licensed under the Apache License, Version 2.0.

#include "detail/store.h"

#include <algorithm>
#include <utility>

#include "detail/canonical.h"

namespace isf::detail {
namespace {

[[nodiscard]] std::wstring Join(const std::wstring& base, const std::wstring& leaf) {
  std::wstring out = base;
  if (!out.empty() && out.back() != L'\\') out.push_back(L'\\');
  out += leaf;
  return out;
}

/// Segment file names are generated from an index and are always ASCII, so this
/// conversion cannot fail and never needs to consult the locale.
[[nodiscard]] std::wstring AsciiToWide(const std::string& text) {
  std::wstring out;
  out.reserve(text.size());
  for (const char raw : text) {
    out.push_back(static_cast<wchar_t>(static_cast<unsigned char>(raw)));
  }
  return out;
}

}  // namespace

Store::~Store() { Close(); }

Result<std::unique_ptr<Store>> Store::Open(const OpenOptions& options, RecoveryReport& report) {
  auto resolved = platform::ResolveStorePath(options.path);
  if (!resolved.ok()) return resolved.status();
  const std::wstring root = std::move(resolved).value();

  auto reparse = platform::ExistsReparsePoint(root);
  if (!reparse.ok()) return reparse.status();
  if (reparse.value() && !options.allow_reparse_root) {
    return Status::Error(ErrorCode::UnsafePath,
                         "store root is a reparse point (symbolic link or junction); "
                         "set allow_reparse_root to accept this explicitly");
  }
  if (platform::PathExists(root) && !platform::IsDirectory(root)) {
    return Status::Error(ErrorCode::UnsafePath, "store root exists and is not a directory");
  }
  if (!platform::PathExists(root) && !options.create_if_missing) {
    return Status::Error(ErrorCode::NotFound, "store root does not exist");
  }

  auto store = std::unique_ptr<Store>(new Store());
  store->root_ = root;
  store->segments_dir_ = Join(root, L"segments");
  store->tmp_dir_ = Join(root, L"tmp");
  store->manifest_path_ = Join(root, L"MANIFEST");
  store->staging_path_ = Join(store->tmp_dir_, L"MANIFEST.staged");

  Status status = platform::CreateDirectories(store->root_);
  if (!status.ok()) return status;
  status = platform::CreateDirectories(store->segments_dir_);
  if (!status.ok()) return status;
  status = platform::CreateDirectories(store->tmp_dir_);
  if (!status.ok()) return status;

  status = store->lock_.Acquire(Join(root, L"LOCK"));
  if (!status.ok()) return status;

  auto narrow_root = platform::WideToUtf8(platform::StripExtendedPrefix(root));
  if (narrow_root.ok()) store->root_utf8_ = std::move(narrow_root).value();

  const bool manifest_exists = platform::PathExists(store->manifest_path_);
  if (!manifest_exists) {
    if (!options.create_if_missing) {
      return Status::Error(ErrorCode::NotFound, "store manifest does not exist");
    }
    store->report_.created = true;
    store->manifest_ = Manifest{};
    store->manifest_.next_incident_id = 1;
    store->manifest_.next_evidence_id = 1;
    store->manifest_.next_authority_id = 1;
    store->manifest_.last_close_clean = true;
    // The store becomes durable at the first commit; nothing is published yet.
  } else {
    auto bytes = platform::ReadFileBounded(store->manifest_path_, FormatLimits::kMaxManifestBytes);
    if (!bytes.ok()) return bytes.status();
    auto decoded = DecodeManifest(bytes.value().data(), bytes.value().size());
    if (!decoded.ok()) return decoded.status();
    store->manifest_ = std::move(decoded).value();
  }

  if (store->manifest_.next_incident_id == 0 || store->manifest_.next_evidence_id == 0 ||
      store->manifest_.next_authority_id == 0) {
    return Status::Error(ErrorCode::IntegrityFailure,
                         "manifest allocators must start at one");
  }

  // Remove segment files that the manifest does not declare. A crash between
  // creating a segment and publishing the manifest leaves exactly this residue.
  auto present = platform::ListSegmentFileNames(store->segments_dir_);
  if (!present.ok()) return present.status();
  for (const std::string& name : present.value()) {
    std::uint32_t index = 0;
    if (!ParseSegmentFileName(name, index)) continue;
    if (index < store->manifest_.segments.size()) continue;
    status = platform::DeleteFileQuietly(Join(store->segments_dir_, AsciiToWide(name)));
    if (!status.ok()) return status;
    store->report_.removed_orphan_segments += 1;
  }

  // Validate declared segment lengths against what is actually on disk and drop
  // any bytes beyond the committed length: those were never published.
  for (const SegmentDescriptor& descriptor : store->manifest_.segments) {
    const std::wstring path = Join(store->segments_dir_, AsciiToWide(SegmentFileName(descriptor.index)));
    platform::FileHandle handle;
    status = handle.Open(path, false);
    if (!status.ok()) {
      return Status::Error(ErrorCode::StoreCorrupt,
                           "segment " + std::to_string(descriptor.index) +
                               " declared by the manifest is missing");
    }
    auto size = handle.Size();
    if (!size.ok()) return size.status();
    if (size.value() < descriptor.byte_length) {
      return Status::Error(ErrorCode::StoreCorrupt,
                           "segment " + std::to_string(descriptor.index) +
                               " is shorter than the manifest declares");
    }
    if (size.value() > descriptor.byte_length) {
      status = handle.Truncate(descriptor.byte_length);
      if (!status.ok()) return status;
      status = handle.Flush();
      if (!status.ok()) return status;
      store->report_.recovered_tail_bytes += size.value() - descriptor.byte_length;
    }
    handle.Close();
  }

  store->report_.segment_count = static_cast<std::uint32_t>(store->manifest_.segments.size());
  report = store->report_;
  return store;
}

Status Store::OpenSegment(std::uint32_t index) {
  if (has_open_segment_ && open_segment_ == index && segment_.valid()) return Status::Ok();
  segment_.Close();
  const std::wstring path = Join(segments_dir_, AsciiToWide(SegmentFileName(index)));
  Status status = segment_.Open(path, true);
  if (!status.ok()) return status;
  open_segment_ = index;
  has_open_segment_ = true;
  return Status::Ok();
}

Status Store::Replay(std::vector<Effect>& effects) const {
  effects.clear();
  std::uint64_t expected_generation = 1;
  Digest256 previous_chain;

  for (const SegmentDescriptor& descriptor : manifest_.segments) {
    const std::wstring path = Join(segments_dir_, AsciiToWide(SegmentFileName(descriptor.index)));
    auto bytes = platform::ReadFileRange(path, 0, descriptor.byte_length);
    if (!bytes.ok()) return bytes.status();

    const std::byte* cursor = bytes.value().data();
    std::size_t remaining = bytes.value().size();
    std::uint64_t records = 0;
    Digest256 chain = previous_chain;
    while (remaining > 0) {
      auto frame = DecodeRecord(cursor, remaining);
      if (!frame.ok()) return frame.status();
      if (!(frame.value().prev_chain == chain)) {
        return Status::Error(ErrorCode::IntegrityFailure,
                             "segment " + std::to_string(descriptor.index) +
                                 " record chain does not continue the previous record");
      }
      if (frame.value().generation != expected_generation) {
        return Status::Error(ErrorCode::IntegrityFailure,
                             "record generation is not the next expected generation");
      }
      auto effect = DecodeEffect(frame.value().op, frame.value().payload,
                                 static_cast<std::size_t>(frame.value().payload_length));
      if (!effect.ok()) return effect.status();
      effects.push_back(std::move(effect).value());
      chain = frame.value().chain_digest;
      ++expected_generation;
      ++records;
      cursor += frame.value().total_bytes;
      remaining -= frame.value().total_bytes;
    }
    if (records != descriptor.record_count) {
      return Status::Error(ErrorCode::IntegrityFailure,
                           "segment " + std::to_string(descriptor.index) +
                               " record count does not match the manifest");
    }
    if (!(chain == descriptor.chain_head)) {
      return Status::Error(ErrorCode::IntegrityFailure,
                           "segment " + std::to_string(descriptor.index) +
                               " chain head does not match the manifest");
    }
    previous_chain = chain;
  }

  if (expected_generation - 1 != manifest_.generation.value()) {
    return Status::Error(ErrorCode::IntegrityFailure,
                         "committed record count does not match the manifest generation");
  }
  return Status::Ok();
}

Status Store::Commit(const Effect& effect, const std::vector<std::byte>& payload,
                     const StateCounters& counters, bool write_state_digest,
                     const Digest256& state_digest) {
  const std::size_t record_size =
      kRecordHeaderBytes + payload.size() + kRecordTrailerBytes;
  if (record_size > FormatLimits::kMaxRecordBytes + kRecordHeaderBytes + kRecordTrailerBytes) {
    return Status::Error(ErrorCode::ResourceExhausted, "encoded record exceeds the format maximum");
  }

  Manifest next = manifest_;
  std::uint32_t segment_index = 0;
  if (next.segments.empty()) {
    SegmentDescriptor descriptor;
    descriptor.index = 0;
    next.segments.push_back(descriptor);
    segment_index = 0;
  } else {
    segment_index = static_cast<std::uint32_t>(next.segments.size() - 1);
    const std::uint64_t current_length = next.segments[segment_index].byte_length;
    if (current_length > 0 &&
        current_length + static_cast<std::uint64_t>(record_size) >
            FormatLimits::kSegmentTargetBytes) {
      if (next.segments.size() >= FormatLimits::kMaxSegments) {
        return Status::Error(ErrorCode::ResourceExhausted,
                             "store has reached the maximum number of segments");
      }
      SegmentDescriptor descriptor;
      descriptor.index = static_cast<std::uint32_t>(next.segments.size());
      // The new segment continues the digest chain, so its first record binds
      // the previous segment's head rather than restarting from zero.
      descriptor.chain_head = next.segments.back().chain_head;
      next.segments.push_back(descriptor);
      segment_index = descriptor.index;
    }
  }

  Status status = OpenSegment(segment_index);
  if (!status.ok()) return status;

  const SegmentDescriptor& current = next.segments[segment_index];
  std::vector<std::byte> encoded;
  Digest256 chain;
  EncodeRecord(effect.generation.value(), effect.op, payload, current.chain_head, encoded, chain);
  if (encoded.size() != record_size) {
    return Status::Error(ErrorCode::InternalError, "record size changed during encoding");
  }

  platform::CrashPoint("before_append", effect.generation.value());
  status = segment_.WriteAt(current.byte_length, encoded.data(), encoded.size());
  if (!status.ok()) return status;
  platform::CrashPoint("after_write", effect.generation.value());
  status = segment_.Flush();
  if (!status.ok()) return status;
  platform::CrashPoint("after_flush", effect.generation.value());

  next.segments[segment_index].byte_length =
      current.byte_length + static_cast<std::uint64_t>(encoded.size());
  if (next.segments[segment_index].record_count == UINT64_MAX) {
    return Status::Error(ErrorCode::Overflow, "segment record count would overflow");
  }
  next.segments[segment_index].record_count = current.record_count + 1;
  next.segments[segment_index].chain_head = chain;

  std::uint64_t next_manifest_seq = 0;
  if (next.manifest_seq == UINT64_MAX) {
    return Status::Error(ErrorCode::Overflow, "manifest sequence would overflow");
  }
  next_manifest_seq = next.manifest_seq + 1;
  next.manifest_seq = next_manifest_seq;
  next.generation = effect.generation;
  next.control_epoch = counters.control_epoch;
  next.incarnation = counters.incarnation;
  next.next_incident_id = counters.next_incident_id;
  next.next_evidence_id = counters.next_evidence_id;
  next.next_authority_id = counters.next_authority_id;
  next.session_open = counters.session_open;
  next.last_close_clean = counters.last_close_clean;
  if (write_state_digest) {
    next.digest_current = true;
    next.state_digest = state_digest;
    next.state_digest_generation = effect.generation;
  }

  const std::vector<std::byte> manifest_bytes = EncodeManifest(next);
  if (manifest_bytes.size() > FormatLimits::kMaxManifestBytes) {
    return Status::Error(ErrorCode::ResourceExhausted,
                         "manifest exceeds the format maximum; the store must be rotated");
  }

  platform::CrashPoint("before_publish", effect.generation.value());
  status = platform::PublishAtomically(staging_path_, manifest_path_, manifest_bytes);
  if (!status.ok()) return status;
  manifest_ = std::move(next);
  platform::CrashPoint("after_publish", effect.generation.value());
  return Status::Ok();
}

Status Store::Checkpoint(const StateCounters& counters, const Digest256& state_digest) {
  Manifest next = manifest_;
  if (next.manifest_seq == UINT64_MAX) {
    return Status::Error(ErrorCode::Overflow, "manifest sequence would overflow");
  }
  next.manifest_seq += 1;
  next.control_epoch = counters.control_epoch;
  next.incarnation = counters.incarnation;
  next.next_incident_id = counters.next_incident_id;
  next.next_evidence_id = counters.next_evidence_id;
  next.next_authority_id = counters.next_authority_id;
  next.session_open = counters.session_open;
  next.last_close_clean = counters.last_close_clean;
  next.digest_current = true;
  next.state_digest = state_digest;
  next.state_digest_generation = next.generation;

  const std::vector<std::byte> manifest_bytes = EncodeManifest(next);
  if (manifest_bytes.size() > FormatLimits::kMaxManifestBytes) {
    return Status::Error(ErrorCode::ResourceExhausted, "manifest exceeds the format maximum");
  }
  const Status status = platform::PublishAtomically(staging_path_, manifest_path_, manifest_bytes);
  if (!status.ok()) return status;
  manifest_ = std::move(next);
  return Status::Ok();
}

void Store::Close() {
  segment_.Close();
  lock_.Release();
}

}  // namespace isf::detail
