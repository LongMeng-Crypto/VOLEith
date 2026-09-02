/*
 * SPDX-License-Identifier: MIT
 *
 * A Boolean (XOR/AND) circuit for bounded multi-block SHA-256. XOR, NOT, shifts and
 * rotations are linear over F_2; only AND nodes are multiplication gates.
 */
#ifndef SHA256_CIRCUIT_HPP
#define SHA256_CIRCUIT_HPP

#include "binary_circuit.hpp"
#include "input_visibility.hpp"

#include <array>
#include <cstddef>
#include <cstdint>
#include <vector>

namespace faest::sha256_circuit {

class CircuitBuilder;

constexpr std::size_t max_message_bytes    = 550;
constexpr std::size_t secret_message_bytes = max_message_bytes;
constexpr std::size_t digest_bytes         = 32;

using Message = std::array<std::uint8_t, secret_message_bytes>;
using Digest  = std::array<std::uint8_t, digest_bytes>;

using Op = vole_backend::Op;
using Node = vole_backend::Node;

struct Statistics {
  std::size_t secret_inputs;
  std::size_t public_inputs;
  std::size_t xor_gates;
  std::size_t multiplication_gates;
  std::size_t schedule_multiplications;
  std::size_t round_multiplications;
  std::size_t feed_forward_multiplications;
  std::size_t total_nodes;
};

class Circuit {
public:
  explicit Circuit(std::size_t message_length = 55);
  Circuit(std::size_t message_length, InputVisibilityLayout input_visibility);

  // Evaluate all 256 public output wires for the public message_length prefix.
  Digest evaluate(const Message& message) const;

  // Values of the AND outputs, in circuit order. Together with the inputs
  // marked secret by input_visibility, this is the VOLE extended witness.
  std::vector<std::uint8_t> multiplication_witness(const Message& message) const;

  // Checks SHA256(message) == claimed_digest for a complete local message.
  bool verify_statement(const Message& message, const Digest& claimed_digest) const;

  const Statistics& statistics() const { return statistics_; }
  std::size_t message_length() const { return message_length_; }
  std::size_t secret_input_bits() const { return input_visibility_.private_bits(); }
  std::size_t public_input_bits() const { return input_visibility_.public_bits(); }
  std::size_t block_count() const { return block_count_; }
  const std::vector<Node>& nodes() const { return circuit_.nodes(); }
  const vole_backend::BinaryCircuit& binary_circuit() const { return circuit_; }
  const std::array<std::uint32_t, 256>& output_wires() const { return outputs_; }
  const std::vector<std::uint32_t>& input_wires() const { return inputs_; }
  const InputVisibilityLayout& input_visibility() const { return input_visibility_; }
  PartitionedInput partition_input(const Message& message) const;

private:
  friend class CircuitBuilder;
  vole_backend::BinaryCircuit circuit_;
  std::array<std::uint32_t, 256> outputs_{};
  std::vector<std::uint32_t> inputs_;
  Statistics statistics_{};
  std::size_t message_length_ = 0;
  std::size_t block_count_ = 0;
  InputVisibilityLayout input_visibility_;

  std::uint32_t input(InputVisibility visibility);
  std::uint32_t xor_wire(std::uint32_t lhs, std::uint32_t rhs);
  std::uint32_t and_wire(std::uint32_t lhs, std::uint32_t rhs);
  vole_backend::Evaluation evaluate_ir(const Message& message) const;
};

} // namespace faest::sha256_circuit

#endif
