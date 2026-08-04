/* SPDX-License-Identifier: MIT */
#ifndef VOLE_SHA256_NIZK_HPP
#define VOLE_SHA256_NIZK_HPP

#include "sha256_circuit.hpp"

#include <array>
#include <cstddef>
#include <cstdint>
#include <span>
#include <vector>

namespace vole_sha256 {

using ProverRandomness = std::array<std::uint8_t, 32>;

std::size_t serialized_proof_bytes(const faest::sha256_circuit::Circuit& circuit);

std::vector<std::uint8_t> prove(
    const faest::sha256_circuit::Circuit& circuit,
    const faest::sha256_circuit::Message& secret_message,
    const faest::sha256_circuit::Digest& public_digest,
    std::span<const std::uint8_t> context,
    const ProverRandomness& randomness);

bool verify(const faest::sha256_circuit::Circuit& circuit,
            const faest::sha256_circuit::Digest& public_digest,
            std::span<const std::uint8_t> context,
            std::span<const std::uint8_t> serialized_proof);

} // namespace vole_sha256

#endif
