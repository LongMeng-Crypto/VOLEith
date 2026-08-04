/* SPDX-License-Identifier: MIT */
#ifndef VOLE_BACKEND_BINARY_CIRCUIT_HPP
#define VOLE_BACKEND_BINARY_CIRCUIT_HPP

#include <cstddef>
#include <cstdint>
#include <span>
#include <string>
#include <vector>

namespace vole_backend {

using Wire = std::uint32_t;

enum class Op : std::uint8_t {
  Constant,
  PrivateInput,
  PublicInput,
  Xor,
  And,
};

struct Node {
  Op op;
  Wire lhs;
  Wire rhs;
  bool constant;
};

struct CircuitStatistics {
  std::size_t private_inputs = 0;
  std::size_t public_inputs = 0;
  std::size_t xor_gates = 0;
  std::size_t multiplication_gates = 0;
  std::size_t total_nodes = 0;
};

struct Evaluation {
  std::vector<std::uint8_t> wires;
  std::vector<std::uint8_t> outputs;
  std::vector<std::uint8_t> multiplication_outputs;
};

class BinaryCircuit {
public:
  BinaryCircuit();

  Wire private_input();
  Wire public_input();
  Wire xor_wire(Wire lhs, Wire rhs);
  Wire and_wire(Wire lhs, Wire rhs);
  void add_output(Wire wire);

  Evaluation evaluate(std::span<const std::uint8_t> private_bits,
                      std::span<const std::uint8_t> public_bits = {}) const;

  bool validate(std::string* error = nullptr) const;

  const std::vector<Node>& nodes() const { return nodes_; }
  const std::vector<Wire>& outputs() const { return outputs_; }
  CircuitStatistics statistics() const;

  static constexpr Wire zero() { return 0; }
  static constexpr Wire one() { return 1; }

  // Used by canonical circuit decoders; rejects malformed/non-canonical IR.
  static BinaryCircuit from_canonical(std::vector<Node> nodes, std::vector<Wire> outputs);

private:
  std::vector<Node> nodes_;
  std::vector<Wire> outputs_;
};

class CircuitBuilder {
public:
  explicit CircuitBuilder(BinaryCircuit& circuit) : circuit_(circuit) {}

  Wire zero() const { return BinaryCircuit::zero(); }
  Wire one() const { return BinaryCircuit::one(); }
  Wire private_input() { return circuit_.private_input(); }
  Wire public_input() { return circuit_.public_input(); }
  Wire xor_wire(Wire lhs, Wire rhs) { return circuit_.xor_wire(lhs, rhs); }
  Wire and_wire(Wire lhs, Wire rhs) { return circuit_.and_wire(lhs, rhs); }
  void output(Wire wire) { circuit_.add_output(wire); }

private:
  BinaryCircuit& circuit_;
};

} // namespace vole_backend

#endif
