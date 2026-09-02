/* SPDX-License-Identifier: MIT */

extern "C" {
#include "fields.h"
}

#include <boost/test/unit_test.hpp>

#include <array>
#include <cstddef>
#include <cstdint>

namespace {

template<std::size_t Words, std::size_t RhsWords>
std::array<std::uint8_t, Words * 8> reference_multiply(
    const std::array<std::uint8_t, Words * 8>& lhs,
    const std::array<std::uint8_t, RhsWords * 8>& rhs,
    std::uint64_t modulus) {
  std::array<std::uint64_t, Words> value{}, result{};
  for (std::size_t i = 0; i != Words; ++i)
    for (std::size_t j = 0; j != 8; ++j)
      value[i] |= std::uint64_t{lhs[8 * i + j]} << (8 * j);

  for (std::size_t bit = 0; bit != RhsWords * 64; ++bit) {
    const auto selected = -static_cast<std::uint64_t>(
        (rhs[bit / 8] >> (bit % 8)) & std::uint8_t{1});
    for (std::size_t i = 0; i != Words; ++i)
      result[i] ^= value[i] & selected;
    const auto reduction = -std::uint64_t{value[Words - 1] >> 63};
    for (std::size_t i = Words - 1; i != 0; --i)
      value[i] = (value[i] << 1) | (value[i - 1] >> 63);
    value[0] <<= 1;
    value[0] ^= modulus & reduction;
  }

  std::array<std::uint8_t, Words * 8> output{};
  for (std::size_t i = 0; i != Words; ++i)
    for (std::size_t j = 0; j != 8; ++j)
      output[8 * i + j] = static_cast<std::uint8_t>(result[i] >> (8 * j));
  return output;
}

template<std::size_t Bytes>
std::array<std::uint8_t, Bytes> random_bytes(std::uint64_t& state) {
  std::array<std::uint8_t, Bytes> output{};
  for (auto& byte : output) {
    state ^= state << 13;
    state ^= state >> 7;
    state ^= state << 17;
    byte = static_cast<std::uint8_t>(state);
  }
  return output;
}

} // namespace

BOOST_AUTO_TEST_SUITE(carryless_field_multiplication)

BOOST_AUTO_TEST_CASE(matches_bit_serial_reference) {
  constexpr std::uint64_t modulus192 = (UINT64_C(1) << 7) |
      (UINT64_C(1) << 2) | (UINT64_C(1) << 1) | 1;
  constexpr std::uint64_t modulus256 = (UINT64_C(1) << 10) |
      (UINT64_C(1) << 5) | (UINT64_C(1) << 2) | 1;
  constexpr std::uint64_t modulus576 = (UINT64_C(1) << 13) |
      (UINT64_C(1) << 4) | (UINT64_C(1) << 3) | 1;
  constexpr std::uint64_t modulus768 = (UINT64_C(1) << 19) |
      (UINT64_C(1) << 17) | (UINT64_C(1) << 4) | 1;
  std::uint64_t state = UINT64_C(0xbb67ae8584caa73b);

  for (unsigned int sample = 0; sample != 24; ++sample) {
    const auto a192 = random_bytes<24>(state);
    const auto b192 = random_bytes<24>(state);
    bf192_t x192, y192, z192;
    bf192_load(&x192, a192.data());
    bf192_load(&y192, b192.data());
    bf192_mul(&z192, &x192, &y192);
    std::array<std::uint8_t, 24> actual192{};
    bf192_store(actual192.data(), &z192);
    const auto expected192 = reference_multiply<3, 3>(a192, b192, modulus192);
    BOOST_TEST(actual192 == expected192);

    auto inplace192 = x192;
    bf192_mul_inplace(&inplace192, &y192);
    bf192_store(actual192.data(), &inplace192);
    BOOST_TEST(actual192 == expected192);

    const auto a256 = random_bytes<32>(state);
    const auto b256 = random_bytes<32>(state);
    bf256_t x256, y256, z256;
    bf256_load(&x256, a256.data());
    bf256_load(&y256, b256.data());
    bf256_mul(&z256, &x256, &y256);
    std::array<std::uint8_t, 32> actual256{};
    bf256_store(actual256.data(), &z256);
    const auto expected256 = reference_multiply<4, 4>(a256, b256, modulus256);
    BOOST_TEST(actual256 == expected256);

    auto inplace256 = x256;
    bf256_mul_inplace(&inplace256, &y256);
    bf256_store(actual256.data(), &inplace256);
    BOOST_TEST(actual256 == expected256);

    const auto a576 = random_bytes<72>(state);
    bf576_t x576;
    bf576_load(&x576, a576.data());
    bf576_mul_192_inplace(&x576, &y192);
    std::array<std::uint8_t, 72> actual576{};
    bf576_store(actual576.data(), &x576);
    const auto expected576 = reference_multiply<9, 3>(a576, b192, modulus576);
    BOOST_TEST(actual576 == expected576);

    const auto a768 = random_bytes<96>(state);
    bf768_t x768;
    bf768_load(&x768, a768.data());
    bf768_mul_256_inplace(&x768, &y256);
    std::array<std::uint8_t, 96> actual768{};
    bf768_store(actual768.data(), &x768);
    const auto expected768 = reference_multiply<12, 4>(a768, b256, modulus768);
    BOOST_TEST(actual768 == expected768);
  }
}

BOOST_AUTO_TEST_SUITE_END()
