/* SPDX-License-Identifier: MIT */
#ifndef VOLE_BACKEND_QUICKSILVER_TYPES_HPP
#define VOLE_BACKEND_QUICKSILVER_TYPES_HPP

#include <array>
#include <cstddef>
#include <cstdint>
#include <vector>

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

// Runtime-sized counterparts used by the parameterized binary-circuit
// backend.  The legacy fixed-size aliases above remain the ABI used by the
// SHA-256 compatibility frontend and the FAEST AES-128 relation.
using ParameterizedQuicksilverChallenge = std::vector<std::uint8_t>;

struct ParameterizedQuicksilverProof {
  std::vector<std::uint8_t> a0;
  std::vector<std::uint8_t> a1;
  std::vector<std::uint8_t> a2;
};

} // namespace vole_backend

#endif
