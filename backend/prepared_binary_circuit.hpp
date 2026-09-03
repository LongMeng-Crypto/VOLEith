/* SPDX-License-Identifier: MIT */
#ifndef VOLE_BACKEND_PREPARED_BINARY_CIRCUIT_HPP
#define VOLE_BACKEND_PREPARED_BINARY_CIRCUIT_HPP

#include "backend_witness.hpp"
#include "circuit_format.hpp"
#include "security_parameters.hpp"

#include <array>
#include <cstddef>
#include <cstdint>
#include <limits>
#include <span>
#include <vector>

namespace vole_backend {

struct PreparedTraversalNode {
  Op op;
  Wire lhs;
  Wire rhs;
  bool constant;
  // Private/public input position or multiplication-witness position,
  // according to op. Constants and XOR nodes use no_index.
  std::size_t value_index;

  static constexpr std::size_t no_index = std::numeric_limits<std::size_t>::max();
};

// Immutable metadata prepared from one canonical BinaryCircuit. The source
// circuit must not be mutated during this object's lifetime.
class PreparedBinaryCircuit {
public:
  explicit PreparedBinaryCircuit(const BinaryCircuit& circuit);

  const BinaryCircuit& circuit() const { return *circuit_; }
  const CircuitStatistics& statistics() const { return statistics_; }
  const WitnessLayout& layout() const { return layout_; }
  const CircuitHash& canonical_hash() const { return canonical_hash_; }
  std::span<const PreparedTraversalNode> traversal() const { return traversal_; }
  std::span<const std::uint8_t> identifier(SecurityLevel security) const;
  std::span<const std::uint8_t> identifier(SecurityLevel security,
                                           VoleProfile profile) const;

  Evaluation evaluate(std::span<const std::uint8_t> private_bits,
                      std::span<const std::uint8_t> public_bits = {}) const;
  PackedWitness build_witness(std::span<const std::uint8_t> private_bits,
                              const Evaluation& evaluation) const;
  UnpackedWitness unpack_witness(const PackedWitness& packed) const;

private:
  const BinaryCircuit* circuit_;
  CircuitStatistics statistics_;
  WitnessLayout layout_;
  CircuitHash canonical_hash_{};
  std::vector<PreparedTraversalNode> traversal_;
  std::array<std::vector<std::uint8_t>, 6> identifiers_;
};

} // namespace vole_backend

#endif
