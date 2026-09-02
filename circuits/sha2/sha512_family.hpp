/*
 * SPDX-License-Identifier: MIT
 *
 * Composable SHA-384/SHA-512 Boolean circuits. The core consumes existing
 * message wires in SHA/FIPS order and returns digest wires in the same order;
 * it does not allocate inputs or register public outputs.
 */
#ifndef VOLE_CIRCUITS_SHA2_SHA512_FAMILY_HPP
#define VOLE_CIRCUITS_SHA2_SHA512_FAMILY_HPP

#include "backend/binary_circuit.hpp"
#include "circuits/common/input_visibility.hpp"

#include <cstddef>
#include <cstdint>
#include <span>
#include <vector>

namespace vole_circuits::sha2 {

constexpr std::size_t sha512_family_max_message_bytes = 1100;

enum class Sha512Variant : std::uint8_t { Sha384, Sha512 };

struct CoreStatistics {
  std::size_t schedule_multiplications = 0;
  std::size_t round_multiplications = 0;
  std::size_t feed_forward_multiplications = 0;
};

struct Statistics {
  std::size_t secret_inputs = 0;
  std::size_t public_inputs = 0;
  std::size_t xor_gates = 0;
  std::size_t multiplication_gates = 0;
  std::size_t schedule_multiplications = 0;
  std::size_t round_multiplications = 0;
  std::size_t feed_forward_multiplications = 0;
  std::size_t total_nodes = 0;
};

struct DigestWires {
  // SHA/FIPS order: bits of each digest byte are most-significant first.
  // These wires can be passed directly as part of another SHA message.
  std::vector<vole_backend::Wire> fips_bits;
};

// Build a complete, padded SHA-384 or SHA-512 hash over existing message
// wires. message_fips_bits[0] is the most-significant bit of the first byte.
// Arbitrary bit lengths are supported by the core, although the standalone
// wrappers intentionally expose byte-string messages.
DigestWires build_sha512_family(
    vole_backend::BinaryCircuit& circuit,
    std::span<const vole_backend::Wire> message_fips_bits,
    Sha512Variant variant, CoreStatistics* statistics = nullptr);

// Register a digest as packed public BinaryCircuit outputs. Keeping this
// separate lets callers leave an intermediate digest (such as et) private and
// wire it directly into a later hash.
void add_sha2_digest_outputs(vole_backend::BinaryCircuit& circuit,
                             const DigestWires& digest);

class Sha512FamilyCircuit {
public:
  std::vector<std::uint8_t> evaluate(
      std::span<const std::uint8_t> message) const;
  std::vector<std::uint8_t> multiplication_witness(
      std::span<const std::uint8_t> message) const;
  bool verify_statement(std::span<const std::uint8_t> message,
                        std::span<const std::uint8_t> claimed_digest) const;

  const Statistics& statistics() const { return statistics_; }
  std::size_t message_length() const { return message_length_; }
  std::size_t secret_input_bits() const {
    return input_visibility_.private_bits();
  }
  std::size_t public_input_bits() const {
    return input_visibility_.public_bits();
  }
  std::size_t block_count() const { return block_count_; }
  std::size_t digest_bytes() const;
  Sha512Variant variant() const { return variant_; }
  const vole_backend::BinaryCircuit& binary_circuit() const { return circuit_; }
  const std::vector<vole_backend::Wire>& output_wires() const {
    return output_wires_;
  }
  const InputVisibilityLayout& input_visibility() const {
    return input_visibility_;
  }
  PartitionedInput partition_input(
      std::span<const std::uint8_t> message) const;

protected:
  Sha512FamilyCircuit(Sha512Variant variant, std::size_t message_length,
                      InputVisibilityLayout input_visibility);

private:
  vole_backend::Evaluation evaluate_ir(
      std::span<const std::uint8_t> message) const;

  vole_backend::BinaryCircuit circuit_;
  std::vector<vole_backend::Wire> output_wires_;
  Statistics statistics_{};
  std::size_t message_length_ = 0;
  std::size_t block_count_ = 0;
  Sha512Variant variant_ = Sha512Variant::Sha512;
  InputVisibilityLayout input_visibility_;
};

} // namespace vole_circuits::sha2

#endif
