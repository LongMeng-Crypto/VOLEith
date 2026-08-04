/* SPDX-License-Identifier: MIT */
#ifndef VOLE_BACKEND_CIRCUIT_FORMAT_HPP
#define VOLE_BACKEND_CIRCUIT_FORMAT_HPP

#include "binary_circuit.hpp"

#include <array>
#include <cstdint>
#include <span>
#include <vector>

namespace vole_backend {

using CircuitHash = std::array<std::uint8_t, 32>;

std::vector<std::uint8_t> serialize_vbc(const BinaryCircuit& circuit);
BinaryCircuit deserialize_vbc(std::span<const std::uint8_t> bytes);
CircuitHash circuit_hash(const BinaryCircuit& circuit);
CircuitHash circuit_hash(std::span<const std::uint8_t> canonical_vbc);

} // namespace vole_backend

#endif
