/* SPDX-License-Identifier: MIT */
#ifndef VOLE_BACKEND_WITNESS_HPP
#define VOLE_BACKEND_WITNESS_HPP

#include "binary_circuit.hpp"

#include <cstddef>
#include <cstdint>
#include <span>
#include <vector>

namespace vole_backend {

struct WitnessLayout {
  std::size_t private_input_bits;
  std::size_t multiplication_bits;
  std::size_t logical_bits;
  std::size_t vole_bits;
  std::size_t vole_bytes;
  std::size_t transport_padding_bits;
};

struct UnpackedWitness {
  std::vector<std::uint8_t> private_inputs;
  std::vector<std::uint8_t> multiplication_outputs;
};

using PackedWitness = std::vector<std::uint8_t>;

WitnessLayout witness_layout(const BinaryCircuit& circuit);
PackedWitness build_witness(const BinaryCircuit& circuit,
                            std::span<const std::uint8_t> private_inputs,
                            std::span<const std::uint8_t> public_inputs);
UnpackedWitness unpack_witness(const BinaryCircuit& circuit, const PackedWitness& packed);
bool verify_witness(const BinaryCircuit& circuit, const PackedWitness& packed,
                    std::span<const std::uint8_t> public_inputs,
                    std::span<const std::uint8_t> expected_outputs);

} // namespace vole_backend

#endif
