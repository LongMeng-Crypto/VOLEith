/* SPDX-License-Identifier: MIT */

#include "witness.hpp"

#include <algorithm>
#include <cassert>
#include <cstring>

namespace vole_sha256 {
namespace {

bool get_bit(const PackedWitness& packed, std::size_t bit) {
  return ((packed[bit / 8] >> (bit % 8)) & 1U) != 0;
}

void set_bit(PackedWitness& packed, std::size_t bit, bool value) {
  const auto mask = static_cast<std::uint8_t>(1U << (bit % 8));
  if (value) packed[bit / 8] |= mask;
}

} // namespace

PackedWitness build_witness(const faest::sha256_circuit::Circuit& circuit,
                            const faest::sha256_circuit::Message& secret_message) {
  PackedWitness packed{};
  std::copy(secret_message.begin(), secret_message.end(), packed.begin());

  const auto products = circuit.multiplication_witness(secret_message);
  assert(products.size() == multiplication_bits);
  for (std::size_t i = 0; i != products.size(); ++i) {
    set_bit(packed, faest::sha256_circuit::secret_message_bits + i, products[i] != 0);
  }
  return packed;
}

UnpackedWitness unpack_witness(const PackedWitness& packed) {
  UnpackedWitness unpacked;
  std::copy_n(packed.begin(), unpacked.secret_message.size(), unpacked.secret_message.begin());
  unpacked.multiplication_outputs.resize(multiplication_bits);
  for (std::size_t i = 0; i != multiplication_bits; ++i) {
    unpacked.multiplication_outputs[i] = static_cast<std::uint8_t>(
        get_bit(packed, faest::sha256_circuit::secret_message_bits + i));
  }
  return unpacked;
}

bool transport_padding_is_zero(const PackedWitness& packed) {
  for (std::size_t i = logical_witness_bits; i != vole_witness_bits; ++i) {
    if (get_bit(packed, i)) return false;
  }
  return true;
}

bool verify_witness(const faest::sha256_circuit::Circuit& circuit, const PackedWitness& packed,
                    const faest::sha256_circuit::Digest& public_digest) {
  if (!transport_padding_is_zero(packed)) return false;
  const auto unpacked = unpack_witness(packed);
  if (!circuit.verify_statement(unpacked.secret_message, public_digest)) return false;
  return circuit.multiplication_witness(unpacked.secret_message) == unpacked.multiplication_outputs;
}

} // namespace vole_sha256
