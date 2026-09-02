/* SPDX-License-Identifier: MIT */

#include "prepared_binary_circuit.hpp"

extern "C" {
#include "random_oracle.h"
}

#include <algorithm>
#include <limits>
#include <stdexcept>
#include <string>

namespace vole_backend {
namespace {

constexpr char circuit_id_domain[] = "VOLE-BINARY-CIRCUIT-ID-v2";

std::size_t security_index(SecurityLevel security) {
  switch (security) {
  case SecurityLevel::Bits128: return 0;
  case SecurityLevel::Bits192: return 1;
  case SecurityLevel::Bits256: return 2;
  }
  throw std::invalid_argument("unsupported VOLEith security level");
}

std::vector<std::uint8_t> make_identifier(
    std::span<const std::uint8_t> encoded, SecurityLevel security) {
  if (encoded.size() > std::numeric_limits<std::uint32_t>::max())
    throw std::invalid_argument("circuit encoding too large");
  const auto& parameters = security_parameters(security);
  H2_context_t hash;
  H2_init(&hash, parameters.lambda_bits);
  H2_update(&hash, reinterpret_cast<const std::uint8_t*>(circuit_id_domain),
            sizeof(circuit_id_domain) - 1);
  const auto code = security_level_code(security);
  H2_update(&hash, &code, 1);
  H2_update_u32_le(&hash, static_cast<std::uint32_t>(encoded.size()));
  H2_update(&hash, encoded.data(), encoded.size());
  std::vector<std::uint8_t> result(2 * parameters.lambda_bytes);
  H2_0_final(&hash, result.data(), result.size());
  return result;
}

bool get_bit(const PackedWitness& packed, std::size_t bit) {
  return ((packed[bit / 8] >> (bit % 8)) & 1U) != 0;
}

void set_bit(PackedWitness& packed, std::size_t bit, bool value) {
  if (value)
    packed[bit / 8] |= static_cast<std::uint8_t>(1U << (bit % 8));
}

} // namespace

PreparedBinaryCircuit::PreparedBinaryCircuit(const BinaryCircuit& circuit)
    : circuit_(&circuit), statistics_(circuit.statistics()),
      layout_(witness_layout(circuit)) {
  std::string error;
  if (!circuit.validate(&error))
    throw std::invalid_argument("cannot prepare invalid binary circuit: " + error);

  const auto encoded = serialize_vbc(circuit);
  canonical_hash_ = circuit_hash(encoded);
  identifiers_[0] = make_identifier(encoded, SecurityLevel::Bits128);
  identifiers_[1] = make_identifier(encoded, SecurityLevel::Bits192);
  identifiers_[2] = make_identifier(encoded, SecurityLevel::Bits256);

  traversal_.reserve(circuit.nodes().size());
  std::size_t private_index = 0;
  std::size_t public_index = 0;
  std::size_t multiplication_index = 0;
  for (const auto& node : circuit.nodes()) {
    auto index = PreparedTraversalNode::no_index;
    switch (node.op) {
    case Op::PrivateInput: index = private_index++; break;
    case Op::PublicInput: index = public_index++; break;
    case Op::And: index = multiplication_index++; break;
    case Op::Constant:
    case Op::Xor: break;
    }
    traversal_.push_back({node.op, node.lhs, node.rhs, node.constant, index});
  }
}

std::span<const std::uint8_t> PreparedBinaryCircuit::identifier(
    SecurityLevel security) const {
  return identifiers_[security_index(security)];
}

Evaluation PreparedBinaryCircuit::evaluate(
    std::span<const std::uint8_t> private_bits,
    std::span<const std::uint8_t> public_bits) const {
  if (private_bits.size() != statistics_.private_inputs ||
      public_bits.size() != statistics_.public_inputs)
    throw std::invalid_argument("binary circuit input size mismatch");
  const auto invalid = [](std::uint8_t bit) { return bit > 1; };
  if (std::any_of(private_bits.begin(), private_bits.end(), invalid) ||
      std::any_of(public_bits.begin(), public_bits.end(), invalid))
    throw std::invalid_argument("binary circuit inputs must be bits");

  Evaluation result;
  result.wires.resize(traversal_.size());
  result.multiplication_outputs.resize(statistics_.multiplication_gates);
  for (std::size_t i = 0; i != traversal_.size(); ++i) {
    const auto& node = traversal_[i];
    switch (node.op) {
    case Op::Constant:
      result.wires[i] = static_cast<std::uint8_t>(node.constant);
      break;
    case Op::PrivateInput:
      result.wires[i] = private_bits[node.value_index];
      break;
    case Op::PublicInput:
      result.wires[i] = public_bits[node.value_index];
      break;
    case Op::Xor:
      result.wires[i] = result.wires[node.lhs] ^ result.wires[node.rhs];
      break;
    case Op::And:
      result.wires[i] = result.wires[node.lhs] & result.wires[node.rhs];
      result.multiplication_outputs[node.value_index] = result.wires[i];
      break;
    }
  }
  result.outputs.reserve(circuit_->outputs().size());
  for (const auto wire : circuit_->outputs())
    result.outputs.push_back(result.wires[wire]);
  return result;
}

PackedWitness PreparedBinaryCircuit::build_witness(
    std::span<const std::uint8_t> private_bits,
    const Evaluation& evaluation) const {
  if (private_bits.size() != layout_.private_input_bits ||
      evaluation.multiplication_outputs.size() != layout_.multiplication_bits)
    throw std::invalid_argument("evaluation does not match prepared circuit");
  PackedWitness packed(layout_.vole_bytes, 0);
  for (std::size_t i = 0; i != private_bits.size(); ++i)
    set_bit(packed, i, private_bits[i] != 0);
  for (std::size_t i = 0; i != evaluation.multiplication_outputs.size(); ++i)
    set_bit(packed, layout_.private_input_bits + i,
            evaluation.multiplication_outputs[i] != 0);
  return packed;
}

UnpackedWitness PreparedBinaryCircuit::unpack_witness(
    const PackedWitness& packed) const {
  if (packed.size() != layout_.vole_bytes)
    throw std::invalid_argument("wrong generic witness size");
  UnpackedWitness result;
  result.private_inputs.resize(layout_.private_input_bits);
  result.multiplication_outputs.resize(layout_.multiplication_bits);
  for (std::size_t i = 0; i != result.private_inputs.size(); ++i)
    result.private_inputs[i] = get_bit(packed, i);
  for (std::size_t i = 0; i != result.multiplication_outputs.size(); ++i)
    result.multiplication_outputs[i] =
        get_bit(packed, layout_.private_input_bits + i);
  for (std::size_t i = layout_.logical_bits; i != layout_.vole_bits; ++i) {
    if (get_bit(packed, i))
      throw std::invalid_argument("nonzero witness transport padding");
  }
  return result;
}

} // namespace vole_backend
