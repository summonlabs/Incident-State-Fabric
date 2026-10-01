// Incident State Fabric - DCCP boundary 50
// Copyright 2026 Summon Software Labs.
// Licensed under the Apache License, Version 2.0.

#include <array>
#include <string>
#include <vector>

#include "detail/canonical.h"
#include "detail/crypto.h"
#include "test_framework.h"

namespace {

using isf::detail::Decoder;
using isf::detail::Digest256;
using isf::detail::Encoder;
using isf::detail::Sha256;

[[nodiscard]] std::string Hex(const Digest256& digest) { return digest.Hex(); }

[[nodiscard]] std::string Sha256Hex(const std::string& text) {
  return isf::detail::ComputeSha256(text.data(), text.size()).Hex();
}

}  // namespace

ISF_TEST(Crypto, KnownVectors) {
  ISF_CHECK_EQ(Sha256Hex(""),
               std::string("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"));
  ISF_CHECK_EQ(Sha256Hex("abc"),
               std::string("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"));
  ISF_CHECK_EQ(
      Sha256Hex("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"),
      std::string("248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1"));
  ISF_CHECK_EQ(Sha256Hex("The quick brown fox jumps over the lazy dog"),
               std::string("d7a8fbb307d7809469ca9abcb0082e4f8d5651e46d3cdb762d02d0bf37c9e592"));
}

ISF_TEST(Crypto, StreamingMatchesOneShot) {
  std::string material;
  for (int index = 0; index < 5000; ++index) material += "incident-state-fabric";

  const Digest256 one_shot = isf::detail::ComputeSha256(material.data(), material.size());
  for (const std::size_t chunk : {std::size_t{1}, std::size_t{7}, std::size_t{63}, std::size_t{64},
                                  std::size_t{65}, std::size_t{4096}}) {
    Sha256 hasher;
    std::size_t offset = 0;
    while (offset < material.size()) {
      const std::size_t take = std::min(chunk, material.size() - offset);
      hasher.Update(material.data() + offset, take);
      offset += take;
    }
    ISF_CHECK_EQ(hasher.Finish(), one_shot);
  }
}

ISF_TEST(Crypto, DigestHexAndZero) {
  Digest256 zero;
  ISF_CHECK(zero.IsZero());
  zero.bytes[31] = 1;
  ISF_CHECK(!zero.IsZero());
  ISF_CHECK_EQ(zero.Hex().size(), std::size_t{64});
}

// ---------------------------------------------------------------------------
// Canonical encoding
// ---------------------------------------------------------------------------

ISF_TEST(Canonical, RoundTripIsLossless) {
  Encoder encoder;
  encoder.U8(0xab);
  encoder.U16(0xbeef);
  encoder.U32(0xdeadbeefu);
  encoder.U64(0x0123456789abcdefull);
  encoder.I64AsU64(-42);
  encoder.Bool(true);
  encoder.Bool(false);
  encoder.Text("rack-a1");
  encoder.Bytes(std::vector<std::byte>{std::byte{1}, std::byte{2}, std::byte{3}});
  Digest256 digest;
  digest.bytes[0] = 0x5a;
  encoder.Digest(digest);

  const std::vector<std::byte> bytes = encoder.Take();
  Decoder decoder(bytes.data(), bytes.size());

  std::uint8_t u8 = 0;
  std::uint16_t u16 = 0;
  std::uint32_t u32 = 0;
  std::uint64_t u64 = 0;
  std::int64_t i64 = 0;
  bool first = false;
  bool second = true;
  std::string text;
  std::vector<std::byte> blob;
  Digest256 restored;

  ISF_CHECK(decoder.U8(u8));
  ISF_CHECK(decoder.U16(u16));
  ISF_CHECK(decoder.U32(u32));
  ISF_CHECK(decoder.U64(u64));
  ISF_CHECK(decoder.I64FromU64(i64));
  ISF_CHECK(decoder.Bool(first));
  ISF_CHECK(decoder.Bool(second));
  ISF_CHECK(decoder.Text(text, 64));
  ISF_CHECK(decoder.Bytes(blob, 64));
  ISF_CHECK(decoder.Digest(restored));
  ISF_CHECK(decoder.done());

  ISF_CHECK_EQ(u8, std::uint8_t{0xab});
  ISF_CHECK_EQ(u16, std::uint16_t{0xbeef});
  ISF_CHECK_EQ(u32, 0xdeadbeefu);
  ISF_CHECK_EQ(u64, 0x0123456789abcdefull);
  ISF_CHECK_EQ(i64, std::int64_t{-42});
  ISF_CHECK(first);
  ISF_CHECK(!second);
  ISF_CHECK_EQ(text, std::string("rack-a1"));
  ISF_CHECK_EQ(blob.size(), std::size_t{3});
  ISF_CHECK(restored == digest);
}

ISF_TEST(Canonical, LittleEndianLayoutIsFixed) {
  Encoder encoder;
  encoder.U32(0x01020304u);
  encoder.U64(0x0102030405060708ull);
  const std::vector<std::byte> bytes = encoder.Take();
  const std::array<std::uint8_t, 12> expected{0x04, 0x03, 0x02, 0x01, 0x08, 0x07,
                                              0x06, 0x05, 0x04, 0x03, 0x02, 0x01};
  ISF_REQUIRE(bytes.size() == expected.size());
  for (std::size_t index = 0; index < expected.size(); ++index) {
    ISF_CHECK_EQ(std::to_integer<std::uint8_t>(bytes[index]), expected[index]);
  }
}

ISF_TEST(Canonical, DecoderRejectsShortReads) {
  Encoder encoder;
  encoder.U64(1);
  const std::vector<std::byte> bytes = encoder.Take();

  Decoder decoder(bytes.data(), 4);
  std::uint64_t value = 0;
  ISF_CHECK(!decoder.U64(value));
  ISF_CHECK(decoder.failed());

  Decoder empty(nullptr, 0);
  ISF_CHECK(!empty.U8(*reinterpret_cast<std::uint8_t*>(&value)));
  ISF_CHECK(empty.failed());
}

ISF_TEST(Canonical, DecoderRejectsOversizedAndTrailingData) {
  Encoder encoder;
  encoder.Text(std::string(100, 'x'));
  const std::vector<std::byte> bytes = encoder.Take();

  Decoder too_small(bytes.data(), bytes.size());
  std::string text;
  ISF_CHECK(!too_small.Text(text, 10));
  ISF_CHECK(too_small.failed());

  Encoder trailing;
  trailing.U32(7);
  trailing.U32(9);
  Decoder decoder(trailing.data().data(), trailing.size());
  std::uint32_t value = 0;
  ISF_CHECK(decoder.U32(value));
  ISF_CHECK(!decoder.done());
  ISF_CHECK_EQ(decoder.remaining(), std::size_t{4});
}

ISF_TEST(Canonical, BoolRejectsOutOfRangeBytes) {
  const std::byte raw{2};
  Decoder decoder(&raw, 1);
  bool value = false;
  ISF_CHECK(!decoder.Bool(value));
  ISF_CHECK(decoder.failed());
}

// ---------------------------------------------------------------------------
// Text validation
// ---------------------------------------------------------------------------

ISF_TEST(Text, Utf8WellFormedness) {
  ISF_CHECK(isf::detail::IsValidUtf8("plain ascii"));
  ISF_CHECK(isf::detail::IsValidUtf8("caf\xc3\xa9"));
  ISF_CHECK(isf::detail::IsValidUtf8("\xe6\x9c\xba\xe6\x88\xbf"));
  ISF_CHECK(isf::detail::IsValidUtf8("\xf0\x9f\x9b\xb0"));

  ISF_CHECK(!isf::detail::IsValidUtf8("\x80"));
  ISF_CHECK(!isf::detail::IsValidUtf8("\xc0\xaf"));            // overlong
  ISF_CHECK(!isf::detail::IsValidUtf8("\xed\xa0\x80"));       // surrogate
  ISF_CHECK(!isf::detail::IsValidUtf8("\xf5\x80\x80\x80"));  // beyond U+10FFFF
  ISF_CHECK(!isf::detail::IsValidUtf8("\xe2\x82"));            // truncated
  ISF_CHECK(!isf::detail::IsValidUtf8("caf\xc3"));
}

ISF_TEST(Text, TokenAndFreeTextPolicy) {
  ISF_CHECK(isf::detail::IsValidToken("rack-a1", 128));
  ISF_CHECK(!isf::detail::IsValidToken("", 128));
  ISF_CHECK(!isf::detail::IsValidToken("has\nnewline", 128));
  ISF_CHECK(!isf::detail::IsValidToken(std::string(129, 'a'), 128));

  ISF_CHECK(isf::detail::IsValidFreeText("line one\nline two\t", 128));
  ISF_CHECK(!isf::detail::IsValidFreeText(std::string("nul\0byte", 8), 128));
  ISF_CHECK(!isf::detail::IsValidFreeText("bell\x07", 128));
  ISF_CHECK_EQ(isf::detail::Utf8CodePointCount("\xe6\x9c\xba\xe6\x88\xbf" "a"),
               std::size_t{3});
}
