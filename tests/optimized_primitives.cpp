/* SPDX-License-Identifier: MIT */

extern "C" {
#include "aes.h"
#include "fields.h"
#include "instances.h"
#include "vole.h"
}

#include <boost/test/unit_test.hpp>

#include <algorithm>
#include <array>
#include <cstdint>
#include <span>
#include <stdexcept>
#include <string_view>
#include <vector>

namespace {

void check(bool condition, const char* message) {
  if (!condition) throw std::runtime_error(message);
}

void run_bf64_kat() {
  struct Vector {
    bf64_t lhs;
    bf64_t rhs;
    bf64_t expected;
  };
  constexpr std::array<Vector, 5> vectors{{
      {0, 0, 0},
      {1, UINT64_C(0x0123456789abcdef), UINT64_C(0x0123456789abcdef)},
      {UINT64_C(0x0123456789abcdef), UINT64_C(0xfedcba9876543210),
       UINT64_C(0x48827ab55d976fa0)},
      {UINT64_C(0xffffffffffffffff), UINT64_C(0xffffffffffffffff),
       UINT64_C(0x5555555555555513)},
      {UINT64_C(0x8000000000000000), UINT64_C(0x8000000000000000),
       UINT64_C(0xc00000000000005a)},
  }};
  for (const auto& vector : vectors) {
    check(bf64_mul(vector.lhs, vector.rhs) == vector.expected,
          "bf64 PCLMUL KAT mismatch");
  }
}

template<std::size_t Size>
std::array<std::uint8_t, Size> field_bytes(std::string_view hex) {
  check(hex.size() == 2 * Size, "invalid finite-field KAT encoding");
  const auto nibble = [](char digit) -> std::uint8_t {
    if (digit >= '0' && digit <= '9')
      return static_cast<std::uint8_t>(digit - '0');
    if (digit >= 'a' && digit <= 'f')
      return static_cast<std::uint8_t>(digit - 'a' + 10);
    throw std::runtime_error("invalid GF(2^128) KAT digit");
  };
  std::array<std::uint8_t, Size> output{};
  for (std::size_t i = 0; i != output.size(); ++i)
    output[i] = static_cast<std::uint8_t>((nibble(hex[2 * i]) << 4) |
                                          nibble(hex[2 * i + 1]));
  return output;
}

std::array<std::uint8_t, 16> bytes128(std::string_view hex) {
  return field_bytes<16>(hex);
}

template<std::size_t Size>
std::array<std::uint8_t, Size> reference_field_mul(
    std::array<std::uint8_t, Size> lhs,
    const std::array<std::uint8_t, Size>& rhs, std::uint64_t modulus) {
  std::array<std::uint8_t, Size> result{};
  for (std::size_t bit = 0; bit != 8 * Size; ++bit) {
    const auto mask = static_cast<std::uint8_t>(
        0U - ((rhs[bit / 8] >> (bit % 8)) & 1U));
    for (std::size_t byte = 0; byte != Size; ++byte)
      result[byte] ^= lhs[byte] & mask;
    const auto carry = static_cast<std::uint8_t>(lhs.back() >> 7);
    for (std::size_t byte = Size - 1; byte != 0; --byte)
      lhs[byte] = static_cast<std::uint8_t>(
          (lhs[byte] << 1) | (lhs[byte - 1] >> 7));
    lhs[0] = static_cast<std::uint8_t>(lhs[0] << 1);
    for (std::size_t byte = 0; byte != sizeof(modulus); ++byte) {
      lhs[byte] ^= static_cast<std::uint8_t>(modulus >> (8 * byte)) &
                   static_cast<std::uint8_t>(0U - carry);
    }
  }
  return result;
}

std::array<std::uint8_t, 16> reference_bf128_mul(
    std::array<std::uint8_t, 16> lhs,
    const std::array<std::uint8_t, 16>& rhs) {
  return reference_field_mul(lhs, rhs, UINT64_C(0x87));
}

void check_bf128_mul(const std::array<std::uint8_t, 16>& lhs_bytes,
                     const std::array<std::uint8_t, 16>& rhs_bytes,
                     const std::array<std::uint8_t, 16>& expected) {
  check(reference_bf128_mul(lhs_bytes, rhs_bytes) == expected,
        "GF(2^128) reference KAT mismatch");
  bf128_t lhs, rhs, product;
  bf128_load(&lhs, lhs_bytes.data());
  bf128_load(&rhs, rhs_bytes.data());
  bf128_mul(&product, &lhs, &rhs);
  std::array<std::uint8_t, 16> output{};
  bf128_store(output.data(), &product);
  check(output == expected, "bf128 PCLMUL KAT mismatch");

  auto inplace = lhs;
  bf128_mul_inplace(&inplace, &rhs);
  bf128_store(output.data(), &inplace);
  check(output == expected, "bf128 PCLMUL in-place KAT mismatch");
}

void run_bf128_kat() {
  check_bf128_mul(
      bytes128("00000000000000000000000000000000"),
      bytes128("00112233445566778899aabbccddeeff"),
      bytes128("00000000000000000000000000000000"));
  check_bf128_mul(
      bytes128("01000000000000000000000000000000"),
      bytes128("00112233445566778899aabbccddeeff"),
      bytes128("00112233445566778899aabbccddeeff"));
  check_bf128_mul(
      bytes128("0123456789abcdeffedcba9876543210"),
      bytes128("00112233445566778899aabbccddeeff"),
      bytes128("fdb07b41fca4d756a0e6108f04c68baf"));
  check_bf128_mul(
      bytes128("00000000000000000000000000000080"),
      bytes128("00000000000000000000000000000080"),
      bytes128("671000000000000000000000000000c0"));
  check_bf128_mul(
      bytes128("ffffffffffffffffffffffffffffffff"),
      bytes128("ffffffffffffffffffffffffffffffff"),
      bytes128("2f405555555555555555555555555555"));

  for (std::size_t vector = 0; vector != 64; ++vector) {
    std::array<std::uint8_t, 16> lhs{}, rhs{};
    for (std::size_t byte = 0; byte != lhs.size(); ++byte) {
      lhs[byte] = static_cast<std::uint8_t>(0x35 + 17 * vector + 29 * byte);
      rhs[byte] = static_cast<std::uint8_t>(0xa7 + 31 * vector + 13 * byte);
    }
    check_bf128_mul(lhs, rhs, reference_bf128_mul(lhs, rhs));
  }
  constexpr auto rhs64 = UINT64_C(0xfedcba9876543210);
  const auto lhs_bytes = bytes128("0123456789abcdeffedcba9876543210");
  std::array<std::uint8_t, 16> rhs_bytes{};
  for (std::size_t i = 0; i != 8; ++i)
    rhs_bytes[i] = static_cast<std::uint8_t>(rhs64 >> (8 * i));
  bf128_t lhs;
  bf128_load(&lhs, lhs_bytes.data());
  bf128_mul_64_inplace(&lhs, rhs64);
  std::array<std::uint8_t, 16> output{};
  bf128_store(output.data(), &lhs);
  check(output == reference_field_mul(lhs_bytes, rhs_bytes, UINT64_C(0x87)),
        "bf128 mixed-width PCLMUL KAT mismatch");
}

void check_bf192_mul(const std::array<std::uint8_t, 24>& lhs_bytes,
                     const std::array<std::uint8_t, 24>& rhs_bytes,
                     const std::array<std::uint8_t, 24>& expected) {
  check(reference_field_mul(lhs_bytes, rhs_bytes, UINT64_C(0x87)) == expected,
        "GF(2^192) reference KAT mismatch");
  bf192_t lhs, rhs, product;
  bf192_load(&lhs, lhs_bytes.data());
  bf192_load(&rhs, rhs_bytes.data());
  bf192_mul(&product, &lhs, &rhs);
  std::array<std::uint8_t, 24> output{};
  bf192_store(output.data(), &product);
  check(output == expected, "bf192 Karatsuba PCLMUL KAT mismatch");
  bf192_mul_inplace(&lhs, &rhs);
  bf192_store(output.data(), &lhs);
  check(output == expected, "bf192 Karatsuba PCLMUL in-place KAT mismatch");
}

void run_bf192_kat() {
  check_bf192_mul(
      field_bytes<24>("35526f8ca9c6e3001d3a577491aecbe805223f5c7996b3d0"),
      field_bytes<24>("a7b4c1cedbe8f5020f1c293643505d6a7784919eabb8c5d2"),
      field_bytes<24>("871b82caf5a12442a72a79ac84d30f72c8185b445ecbffcd"));
  for (std::size_t vector = 0; vector != 64; ++vector) {
    std::array<std::uint8_t, 24> lhs{}, rhs{};
    for (std::size_t byte = 0; byte != lhs.size(); ++byte) {
      lhs[byte] = static_cast<std::uint8_t>(0x29 + 19 * vector + 23 * byte);
      rhs[byte] = static_cast<std::uint8_t>(0xd3 + 11 * vector + 31 * byte);
    }
    check_bf192_mul(lhs, rhs,
                    reference_field_mul(lhs, rhs, UINT64_C(0x87)));
  }
  constexpr auto rhs64 = UINT64_C(0x0123456789abcdef);
  const auto lhs_bytes =
      field_bytes<24>("35526f8ca9c6e3001d3a577491aecbe805223f5c7996b3d0");
  std::array<std::uint8_t, 24> rhs_bytes{};
  for (std::size_t i = 0; i != 8; ++i)
    rhs_bytes[i] = static_cast<std::uint8_t>(rhs64 >> (8 * i));
  bf192_t lhs;
  bf192_load(&lhs, lhs_bytes.data());
  bf192_mul_64_inplace(&lhs, rhs64);
  std::array<std::uint8_t, 24> output{};
  bf192_store(output.data(), &lhs);
  check(output == reference_field_mul(lhs_bytes, rhs_bytes, UINT64_C(0x87)),
        "bf192 mixed-width PCLMUL KAT mismatch");
}

void check_bf256_mul(const std::array<std::uint8_t, 32>& lhs_bytes,
                     const std::array<std::uint8_t, 32>& rhs_bytes,
                     const std::array<std::uint8_t, 32>& expected) {
  check(reference_field_mul(lhs_bytes, rhs_bytes, UINT64_C(0x425)) == expected,
        "GF(2^256) reference KAT mismatch");
  bf256_t lhs, rhs, product;
  bf256_load(&lhs, lhs_bytes.data());
  bf256_load(&rhs, rhs_bytes.data());
  bf256_mul(&product, &lhs, &rhs);
  std::array<std::uint8_t, 32> output{};
  bf256_store(output.data(), &product);
  check(output == expected, "bf256 Karatsuba PCLMUL KAT mismatch");
  bf256_mul_inplace(&lhs, &rhs);
  bf256_store(output.data(), &lhs);
  check(output == expected, "bf256 Karatsuba PCLMUL in-place KAT mismatch");
}

void run_bf256_kat() {
  check_bf256_mul(
      field_bytes<32>(
          "35526f8ca9c6e3001d3a577491aecbe805223f5c7996b3d0ed0a2744617e9bb8"),
      field_bytes<32>(
          "a7b4c1cedbe8f5020f1c293643505d6a7784919eabb8c5d2dfecf90613202d3a"),
      field_bytes<32>(
          "9435de282a539de4735d77dc6fcedeb1fa09e990d6d43f0ce95a86f03f1b48a3"));
  for (std::size_t vector = 0; vector != 64; ++vector) {
    std::array<std::uint8_t, 32> lhs{}, rhs{};
    for (std::size_t byte = 0; byte != lhs.size(); ++byte) {
      lhs[byte] = static_cast<std::uint8_t>(0x51 + 13 * vector + 37 * byte);
      rhs[byte] = static_cast<std::uint8_t>(0x9b + 29 * vector + 17 * byte);
    }
    check_bf256_mul(lhs, rhs,
                    reference_field_mul(lhs, rhs, UINT64_C(0x425)));
  }
  constexpr auto rhs64 = UINT64_C(0xa55aa55a01234567);
  const auto lhs_bytes = field_bytes<32>(
      "35526f8ca9c6e3001d3a577491aecbe805223f5c7996b3d0ed0a2744617e9bb8");
  std::array<std::uint8_t, 32> rhs_bytes{};
  for (std::size_t i = 0; i != 8; ++i)
    rhs_bytes[i] = static_cast<std::uint8_t>(rhs64 >> (8 * i));
  bf256_t lhs;
  bf256_load(&lhs, lhs_bytes.data());
  bf256_mul_64_inplace(&lhs, rhs64);
  std::array<std::uint8_t, 32> output{};
  bf256_store(output.data(), &lhs);
  check(output == reference_field_mul(lhs_bytes, rhs_bytes, UINT64_C(0x425)),
        "bf256 mixed-width PCLMUL KAT mismatch");
}

void run_field_batch_kat() {
  constexpr auto rhs64 = UINT64_C(0x9e3779b97f4a7c15);
  {
    std::array<std::uint8_t, 16> rhs_bytes{};
    std::array<bf128_t, 3> full{}, mixed{};
    const auto rhs = field_bytes<16>("a7b4c1cedbe8f5020f1c293643505d6a");
    bf128_t rhs_field;
    bf128_load(&rhs_field, rhs.data());
    for (std::size_t byte = 0; byte != 8; ++byte)
      rhs_bytes[byte] = static_cast<std::uint8_t>(rhs64 >> (8 * byte));
    for (std::size_t lane = 0; lane != 3; ++lane) {
      std::array<std::uint8_t, 16> input{};
      for (std::size_t byte = 0; byte != input.size(); ++byte)
        input[byte] = static_cast<std::uint8_t>(0x21 + 41 * lane + 17 * byte);
      bf128_load(&full[lane], input.data());
      mixed[lane] = full[lane];
    }
    const auto original_full = full;
    bf128_mul_3_inplace(full.data(), &rhs_field);
    bf128_mul_64_3_inplace(mixed.data(), rhs64);
    for (std::size_t lane = 0; lane != 3; ++lane) {
      std::array<std::uint8_t, 16> input{}, output{};
      bf128_store(input.data(), &original_full[lane]);
      bf128_store(output.data(), &full[lane]);
      check(output == reference_field_mul(input, rhs, UINT64_C(0x87)),
            "bf128 batch full-width KAT mismatch");
      bf128_store(output.data(), &mixed[lane]);
      check(output == reference_field_mul(input, rhs_bytes, UINT64_C(0x87)),
            "bf128 batch mixed-width KAT mismatch");
    }
  }
  {
    std::array<std::uint8_t, 24> rhs_bytes{};
    std::array<bf192_t, 3> full{}, mixed{};
    const auto rhs =
        field_bytes<24>("a7b4c1cedbe8f5020f1c293643505d6a7784919eabb8c5d2");
    bf192_t rhs_field;
    bf192_load(&rhs_field, rhs.data());
    for (std::size_t byte = 0; byte != 8; ++byte)
      rhs_bytes[byte] = static_cast<std::uint8_t>(rhs64 >> (8 * byte));
    for (std::size_t lane = 0; lane != 3; ++lane) {
      std::array<std::uint8_t, 24> input{};
      for (std::size_t byte = 0; byte != input.size(); ++byte)
        input[byte] = static_cast<std::uint8_t>(0x43 + 37 * lane + 11 * byte);
      bf192_load(&full[lane], input.data());
      mixed[lane] = full[lane];
    }
    const auto original_full = full;
    bf192_mul_3_inplace(full.data(), &rhs_field);
    bf192_mul_64_3_inplace(mixed.data(), rhs64);
    for (std::size_t lane = 0; lane != 3; ++lane) {
      std::array<std::uint8_t, 24> input{}, output{};
      bf192_store(input.data(), &original_full[lane]);
      bf192_store(output.data(), &full[lane]);
      check(output == reference_field_mul(input, rhs, UINT64_C(0x87)),
            "bf192 batch full-width KAT mismatch");
      bf192_store(output.data(), &mixed[lane]);
      check(output == reference_field_mul(input, rhs_bytes, UINT64_C(0x87)),
            "bf192 batch mixed-width KAT mismatch");
    }
  }
  {
    std::array<std::uint8_t, 32> rhs_bytes{};
    std::array<bf256_t, 3> full{}, mixed{};
    const auto rhs = field_bytes<32>(
        "a7b4c1cedbe8f5020f1c293643505d6a7784919eabb8c5d2dfecf90613202d3a");
    bf256_t rhs_field;
    bf256_load(&rhs_field, rhs.data());
    for (std::size_t byte = 0; byte != 8; ++byte)
      rhs_bytes[byte] = static_cast<std::uint8_t>(rhs64 >> (8 * byte));
    for (std::size_t lane = 0; lane != 3; ++lane) {
      std::array<std::uint8_t, 32> input{};
      for (std::size_t byte = 0; byte != input.size(); ++byte)
        input[byte] = static_cast<std::uint8_t>(0x67 + 31 * lane + 19 * byte);
      bf256_load(&full[lane], input.data());
      mixed[lane] = full[lane];
    }
    const auto original_full = full;
    bf256_mul_3_inplace(full.data(), &rhs_field);
    bf256_mul_64_3_inplace(mixed.data(), rhs64);
    for (std::size_t lane = 0; lane != 3; ++lane) {
      std::array<std::uint8_t, 32> input{}, output{};
      bf256_store(input.data(), &original_full[lane]);
      bf256_store(output.data(), &full[lane]);
      check(output == reference_field_mul(input, rhs, UINT64_C(0x425)),
            "bf256 batch full-width KAT mismatch");
      bf256_store(output.data(), &mixed[lane]);
      check(output == reference_field_mul(input, rhs_bytes, UINT64_C(0x425)),
            "bf256 batch mixed-width KAT mismatch");
    }
  }
}

std::vector<std::uint8_t> reference_prg(
    std::span<const std::uint8_t> key,
    const std::array<std::uint8_t, 16>& iv, std::uint32_t tweak,
    unsigned int security_bits, std::size_t output_bytes) {
  auto counter = iv;
  std::uint32_t upper = static_cast<std::uint32_t>(counter[12]) |
                        (static_cast<std::uint32_t>(counter[13]) << 8) |
                        (static_cast<std::uint32_t>(counter[14]) << 16) |
                        (static_cast<std::uint32_t>(counter[15]) << 24);
  upper += tweak;
  for (unsigned int i = 0; i != 4; ++i)
    counter[12 + i] = static_cast<std::uint8_t>(upper >> (8 * i));

  generic_aes_ecb_t cipher{};
  check(generic_aes_ecb_new(&cipher, key.data(), security_bits) == 0,
        "reference AES setup failed");
  std::vector<std::uint8_t> output(output_bytes);
  std::size_t offset = 0;
  while (output_bytes - offset >= 16) {
    check(generic_aes_ecb_encrypt(&cipher, output.data() + offset,
                                  counter.data(), 1) == 0,
          "reference AES encryption failed");
    aes_increment_iv(counter.data());
    offset += 16;
  }
  if (offset != output_bytes) {
    std::array<std::uint8_t, 16> last{};
    check(generic_aes_ecb_encrypt(&cipher, last.data(), counter.data(), 1) ==
              0,
          "reference AES tail encryption failed");
    std::copy_n(last.begin(), output_bytes - offset, output.begin() + offset);
  }
  generic_aes_ecb_free(&cipher);
  return output;
}

void run_prg_kat() {
  const std::array<std::size_t, 2> lengths{128, 137};
  for (const auto security_bits : {128U, 192U, 256U}) {
    std::vector<std::uint8_t> key(security_bits / 8);
    for (std::size_t i = 0; i != key.size(); ++i)
      key[i] = static_cast<std::uint8_t>(0x31 + 7 * i);
    std::array<std::uint8_t, 16> iv{};
    for (std::size_t i = 0; i != iv.size(); ++i)
      iv[i] = static_cast<std::uint8_t>(0xa0 - 3 * i);
    for (const auto length : lengths) {
      const auto expected =
          reference_prg(key, iv, UINT32_C(0x81234567), security_bits, length);
      std::vector<std::uint8_t> actual(length);
      prg(key.data(), iv.data(), UINT32_C(0x81234567), actual.data(),
          security_bits, actual.size());
      check(actual == expected, "batched AES-CTR PRG differs from reference");
    }
  }
}

unsigned int reference_convert_to_vole(
    const std::uint8_t* iv, const std::uint8_t* seeds, bool seed_zero_bottom,
    unsigned int tree_index, unsigned int output_bytes, std::uint8_t* u,
    std::uint8_t* v, const faest_paramset_t* parameters) {
  const auto depth =
      bavc_max_node_depth(tree_index, parameters->tau1, parameters->k);
  const auto leaves =
      bavc_max_node_index(tree_index, parameters->tau1, parameters->k);
  const auto lambda_bytes = parameters->lambda / 8;
  std::vector<std::uint8_t> rows(2 * leaves * output_bytes);
  const auto row = [&](unsigned int level, unsigned int node) {
    return rows.data() + ((level % 2) * leaves + node) * output_bytes;
  };
  const auto tweak = tree_index ^ UINT32_C(0x80000000);
  if (!seed_zero_bottom)
    prg(seeds, iv, tweak, row(0, 0), parameters->lambda, output_bytes);
  for (unsigned int leaf = 1; leaf != leaves; ++leaf)
    prg(seeds + lambda_bytes * leaf, iv, tweak, row(0, leaf),
        parameters->lambda, output_bytes);

  std::fill_n(v, depth * output_bytes, UINT8_C(0));
  for (unsigned int level = 0; level != depth; ++level) {
    const auto nodes = leaves >> (level + 1);
    for (unsigned int node = 0; node != nodes; ++node) {
      for (unsigned int byte = 0; byte != output_bytes; ++byte) {
        const auto right = row(level, 2 * node + 1)[byte];
        v[level * output_bytes + byte] ^= right;
        row(level + 1, node)[byte] =
            row(level, 2 * node)[byte] ^ right;
      }
    }
  }
  if (!seed_zero_bottom && u != nullptr)
    std::copy_n(row(depth, 0), output_bytes, u);
  return depth;
}

void run_convert_to_vole_kat() {
  for (const auto parameter_id :
       {FAEST_128S, FAEST_128F, FAEST_192S, FAEST_192F, FAEST_256S,
        FAEST_256F}) {
    const auto* parameters = faest_get_paramset(parameter_id);
    check(parameters != nullptr, "missing FAEST parameter set");
    for (const auto tree_index : {0U,
                                  static_cast<unsigned int>(parameters->tau - 1)}) {
      const auto depth =
          bavc_max_node_depth(tree_index, parameters->tau1, parameters->k);
      const auto leaves =
          bavc_max_node_index(tree_index, parameters->tau1, parameters->k);
      constexpr unsigned int output_bytes = 137;
      std::array<std::uint8_t, 16> iv{};
      std::vector<std::uint8_t> seeds(
          leaves * static_cast<unsigned int>(parameters->lambda / 8));
      for (std::size_t i = 0; i != seeds.size(); ++i)
        seeds[i] = static_cast<std::uint8_t>(0x59 + 11 * i);
      std::vector<std::uint8_t> expected_u(output_bytes), actual_u(output_bytes);
      std::vector<std::uint8_t> expected_v(depth * output_bytes);
      std::vector<std::uint8_t> actual_v(depth * output_bytes);
      for (const auto seed_zero_bottom : {false, true}) {
        const auto expected_depth = reference_convert_to_vole(
            iv.data(), seeds.data(), seed_zero_bottom, tree_index,
            output_bytes, seed_zero_bottom ? nullptr : expected_u.data(),
            expected_v.data(), parameters);
        const auto actual_depth = convert_to_vole(
            iv.data(), seeds.data(), seed_zero_bottom, tree_index,
            output_bytes, seed_zero_bottom ? nullptr : actual_u.data(),
            actual_v.data(), parameters);
        check(actual_depth == expected_depth && actual_v == expected_v,
              "streaming ConvertToVOLE differs from reference");
        if (!seed_zero_bottom)
          check(actual_u == expected_u,
                "streaming ConvertToVOLE root differs from reference");
      }
    }
  }
}

} // namespace

BOOST_AUTO_TEST_SUITE(optimized_faest_primitives)

BOOST_AUTO_TEST_CASE(kats_match_portable_references) {
  run_bf64_kat();
  run_bf128_kat();
  run_bf192_kat();
  run_bf256_kat();
  run_field_batch_kat();
  run_prg_kat();
  run_convert_to_vole_kat();
}

BOOST_AUTO_TEST_SUITE_END()
