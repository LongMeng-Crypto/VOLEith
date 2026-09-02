/* SPDX-License-Identifier: MIT */
#ifndef VOLE_BACKEND_GENERIC_NIZK_HPP
#define VOLE_BACKEND_GENERIC_NIZK_HPP

#include "binary_circuit.hpp"
#include "prepared_binary_circuit.hpp"
#include "security_parameters.hpp"

#include <array>
#include <cstddef>
#include <cstdint>
#include <span>
#include <vector>

namespace vole_backend {

struct PublicStatement {
  std::vector<std::uint8_t> public_inputs;
  std::vector<std::uint8_t> expected_outputs;
};

using ProverRandomness = std::array<std::uint8_t, 32>;

std::size_t serialized_proof_bytes(const BinaryCircuit& circuit);
std::size_t serialized_proof_bytes(const BinaryCircuit& circuit,
                                   SecurityLevel security);
std::size_t serialized_proof_bytes(const PreparedBinaryCircuit& circuit,
                                   SecurityLevel security);

std::vector<std::uint8_t> prove(const BinaryCircuit& circuit,
                                std::span<const std::uint8_t> private_inputs,
                                const PublicStatement& statement,
                                std::span<const std::uint8_t> context,
                                const ProverRandomness& randomness);

std::vector<std::uint8_t> prove(const PreparedBinaryCircuit& circuit,
                                SecurityLevel security,
                                std::span<const std::uint8_t> private_inputs,
                                const PublicStatement& statement,
                                std::span<const std::uint8_t> context,
                                const ProverRandomness& randomness);

std::vector<std::uint8_t> prove(const BinaryCircuit& circuit,
                                SecurityLevel security,
                                std::span<const std::uint8_t> private_inputs,
                                const PublicStatement& statement,
                                std::span<const std::uint8_t> context,
                                const ProverRandomness& randomness);

bool verify(const BinaryCircuit& circuit, const PublicStatement& statement,
            std::span<const std::uint8_t> context,
            std::span<const std::uint8_t> serialized_proof);

bool verify(const BinaryCircuit& circuit, SecurityLevel security,
            const PublicStatement& statement,
            std::span<const std::uint8_t> context,
            std::span<const std::uint8_t> serialized_proof);

bool verify(const PreparedBinaryCircuit& circuit, SecurityLevel security,
            const PublicStatement& statement,
            std::span<const std::uint8_t> context,
            std::span<const std::uint8_t> serialized_proof);

} // namespace vole_backend

#endif
