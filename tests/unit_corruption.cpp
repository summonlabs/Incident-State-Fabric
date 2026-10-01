// Incident State Fabric - DCCP boundary 50
// Copyright 2026 Summon Software Labs.
// Licensed under the Apache License, Version 2.0.

#include <filesystem>
#include <functional>
#include <string>
#include <utility>
#include <vector>

#include "detail/canonical.h"
#include "detail/format.h"
#include "detail/platform.h"
#include "isf/isf.h"
#include "support/store_builder.h"
#include "test_framework.h"
#include "test_support.h"

using isftest::Fixture;
using isftest::Key;
using isftest::ReportIncident;
using isftest::ScratchDir;
using isftest::StoreOptions;
using isftest::Utf8;

namespace {

[[nodiscard]] std::string ManifestPath(const ScratchDir& dir) {
  return Utf8(dir.fs_path() / "MANIFEST");
}

[[nodiscard]] std::string SegmentPath(const ScratchDir& dir, std::uint32_t index) {
  return Utf8(dir.fs_path() / "segments" / isf::detail::SegmentFileName(index));
}

[[nodiscard]] bool BuildSeed(const std::string& path, std::size_t reports) {
  return isftest::WriteStore(path, reports + 1, [reports](const isf::detail::State& state,
                                                          std::size_t index) {
    if (index == 0) return isftest::SessionOpenEffect(state, 1, 1);
    isf::detail::Effect effect;
    effect.op = isf::OpKind::ReportIncident;
    effect.actor = isf::AuthorityId{1};
    effect.key = Key(100 + index);
    effect.created_incident = true;
    effect.incident = isf::IncidentId{state.next_incident_id};
    effect.incident_revision = 1;
    effect.cls = isf::IncidentClass::Power;
    effect.severity = isf::Severity::Major;
    effect.state = isf::LifecycleState::Reported;
    effect.scope = isftest::RackScope("rack-x" + std::to_string(index));
    effect.summary = "seeded " + std::to_string(index);
    effect.evidence = isf::EvidenceId{state.next_evidence_id};
    effect.evidence_kind = isf::EvidenceKind::Report;
    effect.evidence_subject = effect.scope;
    effect.evidence_rationale = effect.summary;
    effect.next_incident_id = state.next_incident_id + 1;
    effect.next_evidence_id = state.next_evidence_id + 1;
    effect.next_authority_id = state.next_authority_id;
    return effect;
  });
}

[[nodiscard]] isf::ErrorCode OpenError(const std::string& path) {
  auto fabric = isf::IncidentFabric::Open(StoreOptions(path));
  if (fabric.ok()) {
    (void)fabric.value()->Close();
    return isf::ErrorCode::Ok;
  }
  return fabric.status().code();
}

}  // namespace

ISF_TEST(Corruption, MissingManifestIsRecreatedOnlyWhenAsked) {
  ScratchDir dir("corrupt-missing");
  ISF_REQUIRE(BuildSeed(dir.path(), 3));
  std::error_code error;
  std::filesystem::remove(ManifestPath(dir), error);
  ISF_REQUIRE(!error);

  isf::OpenOptions options = StoreOptions(dir.path());
  options.create_if_missing = false;
  auto fabric = isf::IncidentFabric::Open(options);
  ISF_REQUIRE(!fabric.ok());
  ISF_CHECK_EQ(fabric.status().code(), isf::ErrorCode::NotFound);

  // Segment files without a manifest are not silently adopted.
  options.create_if_missing = true;
  auto fresh = isf::IncidentFabric::Open(options);
  ISF_REQUIRE(fresh.ok());
  const auto status = fresh.value()->GetStatus();
  ISF_REQUIRE(status.ok());
  ISF_CHECK_EQ(status.value().incident_count, std::uint64_t{0});
  ISF_CHECK_EQ(status.value().generation.value(), std::uint64_t{1});
  ISF_CHECK_EQ(status.value().removed_orphan_segments, std::uint64_t{1});
  ISF_REQUIRE(fresh.value()->Close().ok());
}

ISF_TEST(Corruption, TruncatedManifestIsRefused) {
  ScratchDir dir("corrupt-truncate-manifest");
  ISF_REQUIRE(BuildSeed(dir.path(), 3));
  const std::uint64_t size = isftest::FileSize(ManifestPath(dir));
  ISF_REQUIRE(size > 8);
  ISF_REQUIRE(isftest::TruncateFileTo(ManifestPath(dir), size / 2));
  ISF_CHECK_EQ(OpenError(dir.path()), isf::ErrorCode::IntegrityFailure);

  // Truncated below the fixed header the manifest is not even recognisable.
  ISF_REQUIRE(isftest::TruncateFileTo(ManifestPath(dir), 12));
  ISF_CHECK_EQ(OpenError(dir.path()), isf::ErrorCode::StoreCorrupt);
}

ISF_TEST(Corruption, ManifestChecksumDetectsASingleFlippedBit) {
  ScratchDir dir("corrupt-manifest-bit");
  ISF_REQUIRE(BuildSeed(dir.path(), 3));
  ISF_REQUIRE(isftest::FlipByte(ManifestPath(dir), 40));
  ISF_CHECK_EQ(OpenError(dir.path()), isf::ErrorCode::IntegrityFailure);
}

ISF_TEST(Corruption, ManifestMagicAndVersionAreEnforced) {
  ScratchDir magic("corrupt-manifest-magic");
  ISF_REQUIRE(BuildSeed(magic.path(), 2));
  std::vector<std::uint8_t> bytes = isftest::ReadWholeFile(ManifestPath(magic));
  ISF_REQUIRE(bytes.size() > 8);
  bytes[0] = 'X';
  ISF_REQUIRE(isftest::WriteWholeFile(ManifestPath(magic), bytes));
  ISF_CHECK_EQ(OpenError(magic.path()), isf::ErrorCode::StoreCorrupt);

  ScratchDir version("corrupt-manifest-version");
  ISF_REQUIRE(BuildSeed(version.path(), 2));
  auto store_manifest = [&]() {
    const auto raw = isftest::ReadWholeFile(ManifestPath(version));
    return isf::detail::DecodeManifest(reinterpret_cast<const std::byte*>(raw.data()), raw.size());
  }();
  ISF_REQUIRE(store_manifest.ok());
  isf::detail::Manifest manifest = std::move(store_manifest).value();
  manifest.version = 99;
  const std::vector<std::byte> encoded = isf::detail::EncodeManifest(manifest);
  std::vector<std::uint8_t> raw(encoded.size());
  for (std::size_t index = 0; index < encoded.size(); ++index) {
    raw[index] = std::to_integer<std::uint8_t>(encoded[index]);
  }
  ISF_REQUIRE(isftest::WriteWholeFile(ManifestPath(version), raw));
  ISF_CHECK_EQ(OpenError(version.path()), isf::ErrorCode::StoreIncompatible);
}

ISF_TEST(Corruption, SemanticallyInconsistentManifestsAreRefused) {
  const auto rewrite = [](const ScratchDir& dir, const std::function<void(isf::detail::Manifest&)>& edit) {
    const auto raw = isftest::ReadWholeFile(ManifestPath(dir));
    auto decoded =
        isf::detail::DecodeManifest(reinterpret_cast<const std::byte*>(raw.data()), raw.size());
    if (!decoded.ok()) return false;
    isf::detail::Manifest manifest = std::move(decoded).value();
    edit(manifest);
    const std::vector<std::byte> encoded = isf::detail::EncodeManifest(manifest);
    std::vector<std::uint8_t> bytes(encoded.size());
    for (std::size_t index = 0; index < encoded.size(); ++index) {
      bytes[index] = std::to_integer<std::uint8_t>(encoded[index]);
    }
    return isftest::WriteWholeFile(ManifestPath(dir), bytes);
  };

  {
    ScratchDir dir("corrupt-count-mismatch");
    ISF_REQUIRE(BuildSeed(dir.path(), 3));
    ISF_REQUIRE(rewrite(dir, [](isf::detail::Manifest& manifest) {
      manifest.segments.back().record_count += 1;
      manifest.generation = isf::Generation{manifest.generation.value() + 1};
    }));
    ISF_CHECK_EQ(OpenError(dir.path()), isf::ErrorCode::IntegrityFailure);
  }
  {
    ScratchDir dir("corrupt-length");
    ISF_REQUIRE(BuildSeed(dir.path(), 3));
    ISF_REQUIRE(rewrite(dir, [](isf::detail::Manifest& manifest) {
      manifest.segments.back().byte_length += 4096;
    }));
    ISF_CHECK_EQ(OpenError(dir.path()), isf::ErrorCode::StoreCorrupt);
  }
  {
    ScratchDir dir("corrupt-allocator");
    ISF_REQUIRE(BuildSeed(dir.path(), 3));
    ISF_REQUIRE(rewrite(dir, [](isf::detail::Manifest& manifest) {
      manifest.next_incident_id = 0;
    }));
    ISF_CHECK_EQ(OpenError(dir.path()), isf::ErrorCode::IntegrityFailure);
  }
  {
    ScratchDir dir("corrupt-digest-ahead");
    ISF_REQUIRE(BuildSeed(dir.path(), 3));
    ISF_REQUIRE(rewrite(dir, [](isf::detail::Manifest& manifest) {
      manifest.state_digest_generation = isf::Generation{manifest.generation.value() + 5};
    }));
    ISF_CHECK_EQ(OpenError(dir.path()), isf::ErrorCode::StoreCorrupt);
  }
  {
    ScratchDir dir("corrupt-index-order");
    ISF_REQUIRE(BuildSeed(dir.path(), 3));
    ISF_REQUIRE(rewrite(dir, [](isf::detail::Manifest& manifest) {
      manifest.segments.front().index = 7;
    }));
    ISF_CHECK_EQ(OpenError(dir.path()), isf::ErrorCode::StoreCorrupt);
  }
  {
    ScratchDir dir("corrupt-segment-count");
    ISF_REQUIRE(BuildSeed(dir.path(), 3));
    ISF_REQUIRE(rewrite(dir, [](isf::detail::Manifest& manifest) {
      manifest.segments.clear();
    }));
    ISF_CHECK_EQ(OpenError(dir.path()), isf::ErrorCode::StoreCorrupt);
  }
}

ISF_TEST(Corruption, SegmentDamageIsDetected) {
  {
    ScratchDir dir("corrupt-segment-bit");
    ISF_REQUIRE(BuildSeed(dir.path(), 4));
    ISF_REQUIRE(isftest::FlipByte(SegmentPath(dir, 0), 60));
    ISF_CHECK_EQ(OpenError(dir.path()), isf::ErrorCode::IntegrityFailure);
  }
  {
    ScratchDir dir("corrupt-segment-short");
    ISF_REQUIRE(BuildSeed(dir.path(), 4));
    const std::uint64_t size = isftest::FileSize(SegmentPath(dir, 0));
    ISF_REQUIRE(size > 100);
    ISF_REQUIRE(isftest::TruncateFileTo(SegmentPath(dir, 0), size - 10));
    ISF_CHECK_EQ(OpenError(dir.path()), isf::ErrorCode::StoreCorrupt);
  }
  {
    ScratchDir dir("corrupt-segment-missing");
    ISF_REQUIRE(BuildSeed(dir.path(), 4));
    std::error_code error;
    std::filesystem::remove(SegmentPath(dir, 0), error);
    ISF_REQUIRE(!error);
    ISF_CHECK_EQ(OpenError(dir.path()), isf::ErrorCode::StoreCorrupt);
  }
  {
    ScratchDir dir("corrupt-segment-payload");
    ISF_REQUIRE(BuildSeed(dir.path(), 4));
    // Flip a byte inside the second record's payload rather than its header.
    ISF_REQUIRE(isftest::FlipByte(SegmentPath(dir, 0), 130));
    ISF_CHECK_EQ(OpenError(dir.path()), isf::ErrorCode::IntegrityFailure);
  }
}

ISF_TEST(Corruption, UncommittedTailIsDiscardedRatherThanAccepted) {
  ScratchDir dir("corrupt-tail");
  ISF_REQUIRE(BuildSeed(dir.path(), 3));

  // Settle the store: one open and one clean close, so the manifest on disk is
  // the single source of truth for the committed generation.
  {
    auto fabric = isf::IncidentFabric::Open(StoreOptions(dir.path()));
    ISF_REQUIRE(fabric.ok());
    ISF_REQUIRE(fabric.value()->Close().ok());
  }
  std::uint64_t before_incidents = 0;
  {
    auto fabric = isf::IncidentFabric::Open(StoreOptions(dir.path()));
    ISF_REQUIRE(fabric.ok());
    const auto status = fabric.value()->GetStatus();
    ISF_REQUIRE(status.ok());
    before_incidents = status.value().incident_count;
    ISF_REQUIRE(fabric.value()->Close().ok());
  }
  std::uint64_t before_generation = 0;
  {
    const auto raw = isftest::ReadWholeFile(ManifestPath(dir));
    auto decoded =
        isf::detail::DecodeManifest(reinterpret_cast<const std::byte*>(raw.data()), raw.size());
    ISF_REQUIRE(decoded.ok());
    before_generation = decoded.value().generation.value();
  }
  ISF_REQUIRE(before_generation > 0);

  // Append bytes that a crash between the segment flush and the manifest publish
  // would have left behind.
  std::vector<std::uint8_t> garbage(200, 0x7f);
  ISF_REQUIRE(isftest::AppendBytes(SegmentPath(dir, 0), garbage));

  auto fabric = isf::IncidentFabric::Open(StoreOptions(dir.path()));
  ISF_REQUIRE(fabric.ok());
  const auto status = fabric.value()->GetStatus();
  ISF_REQUIRE(status.ok());
  ISF_CHECK_EQ(status.value().incident_count, before_incidents);
  ISF_CHECK_EQ(status.value().generation.value(), before_generation + 1);
  ISF_CHECK_EQ(status.value().recovered_tail_bytes, std::uint64_t{200});
  ISF_REQUIRE(fabric.value()->Close().ok());

  // A second reopen sees the tidied file and recovers nothing extra.
  auto second = isf::IncidentFabric::Open(StoreOptions(dir.path()));
  ISF_REQUIRE(second.ok());
  ISF_CHECK_EQ(second.value()->GetStatus().value().recovered_tail_bytes, std::uint64_t{0});
  ISF_REQUIRE(second.value()->Close().ok());
}

ISF_TEST(Corruption, UnknownOperationKindsAreRefused) {
  ScratchDir dir("corrupt-opcode");
  ISF_REQUIRE(BuildSeed(dir.path(), 1));

  // Rewrite segment zero so its only record carries an operation this build does
  // not implement, keeping every checksum internally consistent.
  const std::vector<std::uint8_t> payload_bytes{1, 2, 3, 4};
  const std::vector<std::byte> payload(payload_bytes.size());
  std::vector<std::byte> record;
  isf::detail::Digest256 chain;
  isf::detail::EncodeRecord(1, static_cast<isf::OpKind>(99), payload, isf::detail::Digest256{},
                            record, chain);

  isf::detail::Manifest manifest;
  manifest.manifest_seq = 2;
  manifest.generation = isf::Generation{1};
  manifest.control_epoch = isf::ControlEpoch{1};
  manifest.incarnation = 1;
  manifest.next_incident_id = 1;
  manifest.next_evidence_id = 1;
  manifest.next_authority_id = 1;
  manifest.session_open = true;
  manifest.last_close_clean = false;
  isf::detail::SegmentDescriptor descriptor;
  descriptor.index = 0;
  descriptor.byte_length = record.size();
  descriptor.record_count = 1;
  descriptor.chain_head = chain;
  manifest.segments.push_back(descriptor);

  std::vector<std::uint8_t> record_bytes(record.size());
  for (std::size_t index = 0; index < record.size(); ++index) {
    record_bytes[index] = std::to_integer<std::uint8_t>(record[index]);
  }
  ISF_REQUIRE(isftest::WriteWholeFile(SegmentPath(dir, 0), record_bytes));
  const std::vector<std::byte> encoded = isf::detail::EncodeManifest(manifest);
  std::vector<std::uint8_t> manifest_bytes(encoded.size());
  for (std::size_t index = 0; index < encoded.size(); ++index) {
    manifest_bytes[index] = std::to_integer<std::uint8_t>(encoded[index]);
  }
  ISF_REQUIRE(isftest::WriteWholeFile(ManifestPath(dir), manifest_bytes));
  ISF_CHECK_EQ(OpenError(dir.path()), isf::ErrorCode::StoreIncompatible);
}

ISF_TEST(Corruption, SegmentFileNamesAreStrictlyParsed) {
  std::uint32_t index = 123;
  ISF_CHECK(isf::detail::ParseSegmentFileName("seg-00000000000000000000.isf", index));
  ISF_CHECK_EQ(index, 0u);
  ISF_CHECK(isf::detail::ParseSegmentFileName("seg-00000000000000000007.isf", index));
  ISF_CHECK_EQ(index, 7u);

  const char* hostile[] = {"../evil.isf",
                           "seg-00000000000000000000.isf.bak",
                           "SEG-00000000000000000000.isf",
                           "seg-0000000000000000000a.isf",
                           "seg-0000000000000000000.isf",
                           "seg-000000000000000000000.isf",
                           "seg-99999999999999999999.isf",
                           "seg-18446744073709551616.isf",
                           ".isf",
                           "seg-00000000000000000000.isf/..",
                           "seg-00000000000000000000.isf "};
  for (const char* name : hostile) {
    std::uint32_t parsed = 0;
    ISF_CHECK(!isf::detail::ParseSegmentFileName(std::string(name), parsed));
  }
  std::uint32_t parsed = 0;
  ISF_CHECK(!isf::detail::ParseSegmentFileName(std::string("seg-00000000000000000000.isf") + '\0',
                                               parsed));
  ISF_CHECK(!isf::detail::ParseSegmentFileName(std::string("seg-00000000000000000000.isf", 20),
                                               parsed));
}

ISF_TEST(Corruption, GeneratedSegmentNamesAreCanonical) {
  ISF_CHECK_EQ(isf::detail::SegmentFileName(0), std::string("seg-00000000000000000000.isf"));
  ISF_CHECK_EQ(isf::detail::SegmentFileName(42), std::string("seg-00000000000000000042.isf"));
  const std::string highest = isf::detail::SegmentFileName(4294967295u);
  ISF_CHECK_EQ(highest.size(), std::size_t{28});
  ISF_CHECK_EQ(highest, std::string("seg-00000000004294967295.isf"));
  std::uint32_t highest_parsed = 0;
  ISF_CHECK(isf::detail::ParseSegmentFileName(highest, highest_parsed));
  ISF_CHECK_EQ(highest_parsed, 4294967295u);
  for (std::uint32_t index = 0; index < 64; ++index) {
    std::uint32_t parsed = 999;
    ISF_CHECK(isf::detail::ParseSegmentFileName(isf::detail::SegmentFileName(index), parsed));
    ISF_CHECK_EQ(parsed, index);
  }
}

ISF_TEST(Corruption, ReservedDeviceNamesAreRecognised) {
  ISF_CHECK(isf::detail::IsReservedDeviceName("NUL"));
  ISF_CHECK(isf::detail::IsReservedDeviceName("con"));
  ISF_CHECK(isf::detail::IsReservedDeviceName("Com1"));
  ISF_CHECK(isf::detail::IsReservedDeviceName("LPT9.txt"));
  ISF_CHECK(!isf::detail::IsReservedDeviceName("COM0"));
  ISF_CHECK(!isf::detail::IsReservedDeviceName("console"));
  ISF_CHECK(!isf::detail::IsReservedDeviceName(""));
}

ISF_TEST(Corruption, StoresThatFailToOpenDoNotFabricateAuthority) {
  ScratchDir dir("corrupt-no-authority");
  ISF_REQUIRE(BuildSeed(dir.path(), 2));
  ISF_REQUIRE(isftest::FlipByte(ManifestPath(dir), 30));
  ISF_EXPECT_ERROR(isf::IncidentFabric::Open(StoreOptions(dir.path())),
                   isf::ErrorCode::IntegrityFailure);
}
