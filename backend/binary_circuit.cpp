/* SPDX-License-Identifier: MIT */

#include "binary_circuit.hpp"

#include <algorithm>
#include <limits>
#include <stdexcept>

namespace vole_backend {

BinaryCircuit::BinaryCircuit() {
  nodes_.push_back({Op::Constant, 0, 0, false});
  nodes_.push_back({Op::Constant, 0, 0, true});
}

Wire BinaryCircuit::private_input() {
  if (nodes_.size() >= std::numeric_limits<Wire>::max()) throw std::length_error("too many wires");
  nodes_.push_back({Op::PrivateInput, 0, 0, false});
  return static_cast<Wire>(nodes_.size() - 1);
}

Wire BinaryCircuit::public_input() {
  if (nodes_.size() >= std::numeric_limits<Wire>::max()) throw std::length_error("too many wires");
  nodes_.push_back({Op::PublicInput, 0, 0, false});
  return static_cast<Wire>(nodes_.size() - 1);
}

Wire BinaryCircuit::xor_wire(Wire lhs, Wire rhs) {
  if (lhs >= nodes_.size() || rhs >= nodes_.size()) throw std::out_of_range("XOR wire index");
  if (lhs == zero()) return rhs;
  if (rhs == zero()) return lhs;
  if (lhs == rhs) return zero();
  if (nodes_.size() >= std::numeric_limits<Wire>::max()) throw std::length_error("too many wires");
  nodes_.push_back({Op::Xor, lhs, rhs, false});
  return static_cast<Wire>(nodes_.size() - 1);
}

Wire BinaryCircuit::and_wire(Wire lhs, Wire rhs) {
  if (lhs >= nodes_.size() || rhs >= nodes_.size()) throw std::out_of_range("AND wire index");
  if (lhs == zero() || rhs == zero()) return zero();
  if (lhs == one()) return rhs;
  if (rhs == one()) return lhs;
  if (lhs == rhs) return lhs;
  if (nodes_.size() >= std::numeric_limits<Wire>::max()) throw std::length_error("too many wires");
  nodes_.push_back({Op::And, lhs, rhs, false});
  return static_cast<Wire>(nodes_.size() - 1);
}

void BinaryCircuit::add_output(Wire wire) {
  if (wire >= nodes_.size()) throw std::out_of_range("output wire index");
  outputs_.push_back(wire);
}

Evaluation BinaryCircuit::evaluate(std::span<const std::uint8_t> private_bits,
                                   std::span<const std::uint8_t> public_bits) const {
  const auto stats = statistics();
  if (private_bits.size() != stats.private_inputs || public_bits.size() != stats.public_inputs) {
    throw std::invalid_argument("binary circuit input size mismatch");
  }
  if (std::any_of(private_bits.begin(), private_bits.end(), [](std::uint8_t bit) { return bit > 1; }) ||
      std::any_of(public_bits.begin(), public_bits.end(), [](std::uint8_t bit) { return bit > 1; })) {
    throw std::invalid_argument("binary circuit inputs must be bits");
  }
  Evaluation result;
  result.wires.resize(nodes_.size());
  result.multiplication_outputs.reserve(stats.multiplication_gates);
  std::size_t private_index = 0;
  std::size_t public_index = 0;
  for (std::size_t i = 0; i != nodes_.size(); ++i) {
    const auto& node = nodes_[i];
    switch (node.op) {
    case Op::Constant:
      result.wires[i] = static_cast<std::uint8_t>(node.constant);
      break;
    case Op::PrivateInput:
      result.wires[i] = private_bits[private_index++];
      break;
    case Op::PublicInput:
      result.wires[i] = public_bits[public_index++];
      break;
    case Op::Xor:
      result.wires[i] = result.wires[node.lhs] ^ result.wires[node.rhs];
      break;
    case Op::And:
      result.wires[i] = result.wires[node.lhs] & result.wires[node.rhs];
      result.multiplication_outputs.push_back(result.wires[i]);
      break;
    }
  }
  result.outputs.reserve(outputs_.size());
  for (const auto wire : outputs_) result.outputs.push_back(result.wires[wire]);
  return result;
}

CircuitStatistics BinaryCircuit::statistics() const {
  CircuitStatistics result;
  result.total_nodes = nodes_.size();
  for (const auto& node : nodes_) {
    switch (node.op) {
    case Op::PrivateInput: ++result.private_inputs; break;
    case Op::PublicInput: ++result.public_inputs; break;
    case Op::Xor: ++result.xor_gates; break;
    case Op::And: ++result.multiplication_gates; break;
    case Op::Constant: break;
    }
  }
  return result;
}

bool BinaryCircuit::validate(std::string* error) const {
  const auto fail = [error](const char* message) {
    if (error) *error = message;
    return false;
  };
  if (nodes_.size() < 2 || nodes_[0].op != Op::Constant || nodes_[0].constant ||
      nodes_[0].lhs != 0 || nodes_[0].rhs != 0 ||
      nodes_[1].op != Op::Constant || !nodes_[1].constant ||
      nodes_[1].lhs != 0 || nodes_[1].rhs != 0) {
    return fail("missing canonical constant wires");
  }
  for (std::size_t i = 2; i != nodes_.size(); ++i) {
    const auto& node = nodes_[i];
    if (node.op == Op::Constant) return fail("non-canonical extra constant node");
    if ((node.op == Op::PrivateInput || node.op == Op::PublicInput) &&
        (node.lhs != 0 || node.rhs != 0 || node.constant)) {
      return fail("non-canonical input node");
    }
    if ((node.op == Op::Xor || node.op == Op::And) && node.constant) {
      return fail("non-canonical gate flags");
    }
    if ((node.op == Op::Xor || node.op == Op::And) && (node.lhs >= i || node.rhs >= i)) {
      return fail("gate does not reference earlier wires");
    }
  }
  if (std::any_of(outputs_.begin(), outputs_.end(),
                  [this](Wire wire) { return wire >= nodes_.size(); })) {
    return fail("output wire is out of range");
  }
  return true;
}

BinaryCircuit BinaryCircuit::from_canonical(std::vector<Node> nodes,
                                            std::vector<Wire> outputs) {
  BinaryCircuit result;
  result.nodes_ = std::move(nodes);
  result.outputs_ = std::move(outputs);
  std::string error;
  if (!result.validate(&error)) throw std::invalid_argument("invalid binary circuit: " + error);
  return result;
}

} // namespace vole_backend
