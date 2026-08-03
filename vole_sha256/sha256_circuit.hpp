/*
 * SPDX-License-Identifier: MIT
 *
 * A Boolean (XOR/AND) circuit for one-block SHA-256.  XOR, NOT, shifts and
 * rotations are linear over F_2; only AND nodes are multiplication gates.
 */
#ifndef SHA256_CIRCUIT_HPP
#define SHA256_CIRCUIT_HPP

#include <array>
#include <cstddef>
#include <cstdint>
#include <vector>

namespace faest::sha256_circuit {

class CircuitBuilder;

constexpr std::size_t secret_message_bytes = 55;
constexpr std::size_t secret_message_bits  = secret_message_bytes * 8;
constexpr std::size_t digest_bytes         = 32;

using Message = std::array<std::uint8_t, secret_message_bytes>;
using Digest  = std::array<std::uint8_t, digest_bytes>;

enum class Op : std::uint8_t { Constant, SecretInput, Xor, And };

struct Node {
  Op op;
  std::uint32_t lhs;
  std::uint32_t rhs;
  bool constant;
};

struct Statistics {
  std::size_t secret_inputs;
  std::size_t xor_gates;
  std::size_t multiplication_gates;
  std::size_t schedule_multiplications;
  std::size_t round_multiplications;
  std::size_t feed_forward_multiplications;
  std::size_t total_nodes;
};

class Circuit {
public:
  Circuit();

  // Evaluate all 256 public output wires for a 55-byte secret message.
  Digest evaluate(const Message& message) const;

  // Values of the AND outputs, in circuit order.  Together with the 440
  // secret input bits, this is the extended witness committed by VOLE.
  std::vector<std::uint8_t> multiplication_witness(const Message& message) const;

  // The public statement is SHA256(message) == claimed_digest.
  bool verify_statement(const Message& message, const Digest& claimed_digest) const;

  const Statistics& statistics() const { return statistics_; }
  const std::vector<Node>& nodes() const { return nodes_; }
  const std::array<std::uint32_t, 256>& output_wires() const { return outputs_; }

private:
  friend class CircuitBuilder;
  std::vector<Node> nodes_;
  std::array<std::uint32_t, 256> outputs_{};
  Statistics statistics_{};

  std::uint32_t secret_input();
  std::uint32_t xor_wire(std::uint32_t lhs, std::uint32_t rhs);
  std::uint32_t and_wire(std::uint32_t lhs, std::uint32_t rhs);
  std::vector<std::uint8_t> evaluate_wires(const Message& message) const;
};

} // namespace faest::sha256_circuit

#endif
