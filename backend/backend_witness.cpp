/* SPDX-License-Identifier: MIT */

#include "backend_witness.hpp"

#include <algorithm>
#include <stdexcept>

namespace vole_backend {
namespace {

bool get_bit(const PackedWitness& packed, std::size_t bit) {
  return ((packed[bit / 8] >> (bit % 8)) & 1U) != 0;
}

void set_bit(PackedWitness& packed, std::size_t bit, bool value) {
  if (value) packed[bit / 8] |= static_cast<std::uint8_t>(1U << (bit % 8));
}

} // namespace

WitnessLayout witness_layout(const BinaryCircuit& circuit) {
  const auto stats = circuit.statistics();
  const auto logical = stats.private_inputs + stats.multiplication_gates;
  const auto vole = (logical + 7) & ~std::size_t{7};
  return {stats.private_inputs, stats.multiplication_gates, logical, vole, vole / 8,
          vole - logical};
}

PackedWitness build_witness(const BinaryCircuit& circuit,
                            std::span<const std::uint8_t> private_inputs,
                            std::span<const std::uint8_t> public_inputs) {
  const auto layout = witness_layout(circuit);
  const auto evaluation = circuit.evaluate(private_inputs, public_inputs);
  PackedWitness packed(layout.vole_bytes, 0);
  for (std::size_t i = 0; i != private_inputs.size(); ++i) set_bit(packed, i, private_inputs[i]);
  for (std::size_t i = 0; i != evaluation.multiplication_outputs.size(); ++i) {
    set_bit(packed, layout.private_input_bits + i, evaluation.multiplication_outputs[i]);
  }
  return packed;
}

UnpackedWitness unpack_witness(const BinaryCircuit& circuit, const PackedWitness& packed) {
  const auto layout = witness_layout(circuit);
  if (packed.size() != layout.vole_bytes) throw std::invalid_argument("wrong generic witness size");
  UnpackedWitness result;
  result.private_inputs.resize(layout.private_input_bits);
  result.multiplication_outputs.resize(layout.multiplication_bits);
  for (std::size_t i = 0; i != result.private_inputs.size(); ++i) result.private_inputs[i] = get_bit(packed, i);
  for (std::size_t i = 0; i != result.multiplication_outputs.size(); ++i) {
    result.multiplication_outputs[i] = get_bit(packed, layout.private_input_bits + i);
  }
  for (std::size_t i = layout.logical_bits; i != layout.vole_bits; ++i) {
    if (get_bit(packed, i)) throw std::invalid_argument("nonzero witness transport padding");
  }
  return result;
}

bool verify_witness(const BinaryCircuit& circuit, const PackedWitness& packed,
                    std::span<const std::uint8_t> public_inputs,
                    std::span<const std::uint8_t> expected_outputs) {
  try {
    const auto witness = unpack_witness(circuit, packed);
    const auto evaluation = circuit.evaluate(witness.private_inputs, public_inputs);
    return evaluation.multiplication_outputs == witness.multiplication_outputs &&
           evaluation.outputs.size() == expected_outputs.size() &&
           std::equal(evaluation.outputs.begin(), evaluation.outputs.end(), expected_outputs.begin());
  } catch (const std::exception&) {
    return false;
  }
}

} // namespace vole_backend
