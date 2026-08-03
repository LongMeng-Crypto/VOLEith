/* SPDX-License-Identifier: MIT */
#ifndef VOLE_SHA256_WITNESS_HPP
#define VOLE_SHA256_WITNESS_HPP

#include "sha256_circuit.hpp"

#include <array>
#include <cstddef>
#include <cstdint>
#include <vector>

namespace vole_sha256 {

constexpr std::size_t multiplication_bits = 39201;
constexpr std::size_t logical_witness_bits =
    faest::sha256_circuit::secret_message_bits + multiplication_bits;
constexpr std::size_t vole_witness_bits = 39648;
constexpr std::size_t vole_witness_bytes = vole_witness_bits / 8;
constexpr std::size_t transport_padding_bits = vole_witness_bits - logical_witness_bits;

using PackedWitness = std::array<std::uint8_t, vole_witness_bytes>;

struct UnpackedWitness {
  faest::sha256_circuit::Message secret_message{};
  std::vector<std::uint8_t> multiplication_outputs;
};

PackedWitness build_witness(const faest::sha256_circuit::Circuit& circuit,
                            const faest::sha256_circuit::Message& secret_message);

UnpackedWitness unpack_witness(const PackedWitness& packed);

bool transport_padding_is_zero(const PackedWitness& packed);

// Checks packing, every committed multiplication output, and the public digest.
bool verify_witness(const faest::sha256_circuit::Circuit& circuit, const PackedWitness& packed,
                    const faest::sha256_circuit::Digest& public_digest);

} // namespace vole_sha256

#endif
