/* SPDX-License-Identifier: MIT */
#ifndef VOLE_BACKEND_QUICKSILVER_TYPES_HPP
#define VOLE_BACKEND_QUICKSILVER_TYPES_HPP

#include <array>
#include <cstddef>
#include <cstdint>

namespace vole_backend {

constexpr std::size_t lambda_bits = 128;
constexpr std::size_t lambda_bytes = lambda_bits / 8;
constexpr std::size_t quicksilver_challenge_bytes = 3 * lambda_bytes + 8;
using QuicksilverChallenge = std::array<std::uint8_t, quicksilver_challenge_bytes>;

struct QuicksilverProof {
  std::array<std::uint8_t, lambda_bytes> a0{};
  std::array<std::uint8_t, lambda_bytes> a1{};
  std::array<std::uint8_t, lambda_bytes> a2{};
};

} // namespace vole_backend

#endif
