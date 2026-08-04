/* SPDX-License-Identifier: MIT */
#ifndef VOLE_SHA256_WITNESS_HPP
#define VOLE_SHA256_WITNESS_HPP

#include "sha256_circuit.hpp"

#include <array>
#include <cstddef>
#include <cstdint>
#include <vector>

namespace vole_sha256 {

struct WitnessLayout {
  std::size_t secret_input_bits;
  std::size_t multiplication_bits;
  std::size_t logical_bits;
  std::size_t vole_bits;
  std::size_t vole_bytes;
  std::size_t transport_padding_bits;
};

WitnessLayout witness_layout(const faest::sha256_circuit::Circuit& circuit);

using PackedWitness = std::vector<std::uint8_t>;

struct UnpackedWitness {
  faest::sha256_circuit::Message secret_message{};
  std::vector<std::uint8_t> multiplication_outputs;
};

PackedWitness build_witness(const faest::sha256_circuit::Circuit& circuit,
                            const faest::sha256_circuit::Message& secret_message);

UnpackedWitness unpack_witness(const faest::sha256_circuit::Circuit& circuit,
                               const PackedWitness& packed);

bool transport_padding_is_zero(const faest::sha256_circuit::Circuit& circuit,
                               const PackedWitness& packed);

// Checks packing, every committed multiplication output, and the public digest.
bool verify_witness(const faest::sha256_circuit::Circuit& circuit, const PackedWitness& packed,
                    const faest::sha256_circuit::Digest& public_digest);

} // namespace vole_sha256

#endif
