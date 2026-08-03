/* SPDX-License-Identifier: MIT */
#ifndef VOLE_SHA256_FAEST_QUICKSILVER_HPP
#define VOLE_SHA256_FAEST_QUICKSILVER_HPP

#include "sha256_circuit.hpp"
#include "witness.hpp"

#include <array>
#include <cstdint>
#include <vector>

extern "C" {
#include "fields.h"
}

namespace vole_sha256 {

constexpr std::size_t lambda_bits = 128;
constexpr std::size_t lambda_bytes = lambda_bits / 8;
constexpr std::size_t quicksilver_challenge_bytes = 3 * lambda_bytes + 8;

using QuicksilverChallenge = std::array<std::uint8_t, quicksilver_challenge_bytes>;

struct QuicksilverProof {
  std::array<std::uint8_t, lambda_bytes> a0{};
  std::array<std::uint8_t, lambda_bytes> a1{};
  std::array<std::uint8_t, lambda_bytes> a2{};
};

// V/Q are lambda column pointers, each containing ell_hat bits.  These entry
// points mirror FAEST's AES prover/verifier wrappers but traverse SHA-256 IR.
QuicksilverProof sha256_quicksilver_prove(
    const faest::sha256_circuit::Circuit& circuit, const PackedWitness& witness,
    const std::vector<std::uint8_t*>& v_columns, const std::uint8_t* u_after_witness,
    const faest::sha256_circuit::Digest& public_digest,
    const QuicksilverChallenge& challenge_2);

std::array<std::uint8_t, lambda_bytes> sha256_quicksilver_verify(
    const faest::sha256_circuit::Circuit& circuit, const PackedWitness& masked_witness_d,
    const std::vector<std::uint8_t*>& q_columns, const std::array<std::uint8_t, lambda_bytes>& delta,
    const faest::sha256_circuit::Digest& public_digest,
    const QuicksilverChallenge& challenge_2, const QuicksilverProof& proof);

} // namespace vole_sha256

#endif
