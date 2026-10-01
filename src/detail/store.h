// Incident State Fabric - DCCP boundary 50
// Copyright 2026 Summon Software Labs.
// Licensed under the Apache License, Version 2.0.

#ifndef ISF_DETAIL_STORE_H
#define ISF_DETAIL_STORE_H

#include <cstdint>
#include <memory>
#include <string>
#include <vector>

#include "detail/format.h"
#include "detail/platform.h"
#include "detail/state.h"
#include "isf/model.h"
#include "isf/result.h"

namespace isf::detail {

/// Owns the store directory, the single-writer lock, the segment files, and the
/// manifest. It knows nothing about incident semantics.
class Store {
 public:
  struct RecoveryReport {
    std::uint64_t recovered_tail_bytes = 0;
    std::uint64_t removed_orphan_segments = 0;
    std::uint32_t segment_count = 0;
    bool created = false;
  };

  ~Store();
  Store(const Store&) = delete;
  Store& operator=(const Store&) = delete;
  Store(Store&&) = delete;
  Store& operator=(Store&&) = delete;

  /// Opens or creates a store, takes the single-writer lock, validates the
  /// manifest, removes uncommitted tails and orphan segments, and leaves the
  /// store ready for Replay.
  [[nodiscard]] static Result<std::unique_ptr<Store>> Open(const OpenOptions& options,
                                                           RecoveryReport& report);

  /// Decodes every record declared committed by the manifest, in order,
  /// verifying the digest chain across the whole log.
  [[nodiscard]] Status Replay(std::vector<Effect>& effects) const;

  /// Appends one record and republishes the manifest. Everything before the
  /// manifest rename may be lost; everything after it is durable.
  [[nodiscard]] Status Commit(const Effect& effect, const std::vector<std::byte>& payload,
                              const StateCounters& counters, bool write_state_digest,
                              const Digest256& state_digest);

  /// Republishes the manifest with a fresh whole-state digest but no new record.
  [[nodiscard]] Status Checkpoint(const StateCounters& counters, const Digest256& state_digest);

  void Close();

  [[nodiscard]] const Manifest& manifest() const noexcept { return manifest_; }
  [[nodiscard]] const std::string& root_utf8() const noexcept { return root_utf8_; }
  [[nodiscard]] const RecoveryReport& report() const noexcept { return report_; }

 private:
  Store() = default;

  [[nodiscard]] Status OpenSegment(std::uint32_t index);

  std::wstring root_;
  std::wstring segments_dir_;
  std::wstring tmp_dir_;
  std::wstring manifest_path_;
  std::wstring staging_path_;
  std::string root_utf8_;
  platform::FileLock lock_;
  platform::FileHandle segment_;
  std::uint32_t open_segment_ = 0;
  bool has_open_segment_ = false;
  Manifest manifest_;
  RecoveryReport report_;
};

}  // namespace isf::detail

#endif  // ISF_DETAIL_STORE_H
