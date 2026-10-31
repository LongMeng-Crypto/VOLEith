/* SPDX-License-Identifier: MIT */
#pragma once
#include "backend/binary_circuit.hpp"
#include <span>

namespace vole_circuits::shake {
// FIPS 202 bit order: bit i is byte[i/8] >> (i%8).
// SHAKE256's rate is 1088 bits. A single padded input block fits 0..1082 bits.
constexpr std::size_t rate_bits = 1088;
std::vector<vole_backend::Wire> append_shake256(
    vole_backend::BinaryCircuit& circuit,
    std::span<const vole_backend::Wire> input, std::size_t output_bits);
vole_backend::BinaryCircuit prune_unused(const vole_backend::BinaryCircuit&);
vole_backend::BinaryCircuit make_shake256(std::size_t input_bits,
                                          std::size_t output_bits,
                                          bool prune = true);
}
