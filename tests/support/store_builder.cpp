// Incident State Fabric - DCCP boundary 50
// Copyright 2026 Summon Software Labs.
// Licensed under the Apache License, Version 2.0.

#include "support/store_builder.h"

#include <cstdio>
#include <filesystem>
#include <fstream>
#include <system_error>
#include <utility>

#include "detail/platform.h"

namespace isftest {
namespace {

[[nodiscard]] isf::detail::Effect MakeSessionBase(const isf::detail::State& state) {
  isf::detail::Effect effect;
  effect.op = isf::OpKind::SessionOpen;
  effect.session_open = true;
  effect.clean_close = false;
  effect.next_incident_id = state.next_incident_id;
  effect.next_evidence_id = state.next_evidence_id;
  effect.next_authority_id = state.next_authority_id;
  return effect;
}

}  // namespace

isf::detail::Effect SessionOpenEffect(const isf::detail::State& state, std::uint64_t incarnation,
                                      std::uint64_t control_epoch) {
  isf::detail::Effect effect = MakeSessionBase(state);
  effect.incarnation = incarnation;
  effect.control_epoch_after = control_epoch;
  return effect;
}

bool WriteStore(
    const std::string& path, std::size_t effect_count,
    const std::function<isf::detail::Effect(const isf::detail::State&, std::size_t)>& build) {
  isf::OpenOptions options;
  options.path = path;
  options.create_if_missing = true;

  isf::detail::Store::RecoveryReport report;
  auto store = isf::detail::Store::Open(options, report);
  if (!store.ok()) {
    std::printf("    store builder: open failed: %s\n", store.status().ToString().c_str());
    return false;
  }

  isf::detail::State state;
  for (std::size_t index = 0; index < effect_count; ++index) {
    isf::detail::Effect effect = build(state, index);
    effect.generation = isf::Generation{state.generation.value() + 1};
    const isf::Status applied = isf::detail::ApplyEffect(state, effect);
    if (!applied.ok()) {
      std::printf("    store builder: apply failed: %s\n", applied.ToString().c_str());
      return false;
    }
    const std::vector<std::byte> payload = isf::detail::EncodeEffect(effect);
    const isf::Status committed =
        store.value()->Commit(effect, payload, state.Counters(), false, isf::detail::Digest256{});
    if (!committed.ok()) {
      std::printf("    store builder: commit failed: %s\n", committed.ToString().c_str());
      return false;
    }
  }

  const isf::Status checkpoint = store.value()->Checkpoint(
      state.Counters(), isf::detail::ComputeStateDigest(state));
  if (!checkpoint.ok()) {
    std::printf("    store builder: checkpoint failed: %s\n", checkpoint.ToString().c_str());
    return false;
  }
  store.value()->Close();
  return true;
}

namespace {

[[nodiscard]] std::wstring Extended(const std::string& path) {
  auto resolved = isf::detail::platform::ResolveStorePath(path);
  return resolved.ok() ? std::move(resolved).value() : std::wstring();
}

}  // namespace

std::vector<std::uint8_t> ReadWholeFile(const std::string& path) {
  std::vector<std::uint8_t> bytes;
  std::ifstream stream(path, std::ios::binary);
  if (!stream) return bytes;
  stream.seekg(0, std::ios::end);
  const std::streamoff size = stream.tellg();
  stream.seekg(0, std::ios::beg);
  if (size > 0) {
    bytes.resize(static_cast<std::size_t>(size));
    stream.read(reinterpret_cast<char*>(bytes.data()), size);
  }
  return bytes;
}

bool WriteWholeFile(const std::string& path, const std::vector<std::uint8_t>& bytes) {
  std::ofstream stream(path, std::ios::binary | std::ios::trunc);
  if (!stream) return false;
  if (!bytes.empty()) {
    stream.write(reinterpret_cast<const char*>(bytes.data()),
                 static_cast<std::streamsize>(bytes.size()));
  }
  stream.flush();
  return stream.good();
}

bool AppendBytes(const std::string& path, const std::vector<std::uint8_t>& bytes) {
  std::ofstream stream(path, std::ios::binary | std::ios::app);
  if (!stream) return false;
  if (!bytes.empty()) {
    stream.write(reinterpret_cast<const char*>(bytes.data()),
                 static_cast<std::streamsize>(bytes.size()));
  }
  stream.flush();
  return stream.good();
}

bool TruncateFileTo(const std::string& path, std::uint64_t length) {
  std::error_code error;
  std::filesystem::resize_file(path, length, error);
  return !error;
}

std::uint64_t FileSize(const std::string& path) {
  std::error_code error;
  const auto size = std::filesystem::file_size(path, error);
  return error ? 0 : static_cast<std::uint64_t>(size);
}

bool FlipByte(const std::string& path, std::uint64_t offset) {
  std::vector<std::uint8_t> bytes = ReadWholeFile(path);
  if (offset >= bytes.size()) return false;
  bytes[static_cast<std::size_t>(offset)] ^= 0x5au;
  return WriteWholeFile(path, bytes);
}

}  // namespace isftest
