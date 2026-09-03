/* SPDX-License-Identifier: MIT */

#include "witness.hpp"

#include <algorithm>
#include <cassert>
#include <cstring>
#include <stdexcept>

namespace vole_sha256 {
namespace {

void require_all_secret(const faest::sha256_circuit::Circuit& circuit) {
  if (circuit.public_input_bits() != 0)
    throw std::invalid_argument(
        "legacy SHA-256 witness API only supports all-secret input; use the generic backend");
}

bool get_bit(const PackedWitness& packed, std::size_t bit) {
  return ((packed[bit / 8] >> (bit % 8)) & 1U) != 0;
}

void set_bit(PackedWitness& packed, std::size_t bit, bool value) {
  const auto mask = static_cast<std::uint8_t>(1U << (bit % 8));
  if (value) packed[bit / 8] |= mask;
}

} // namespace

WitnessLayout witness_layout(const faest::sha256_circuit::Circuit& circuit) {
  require_all_secret(circuit);
  const std::size_t inputs = circuit.secret_input_bits();
  const std::size_t products = circuit.statistics().multiplication_gates;
  const std::size_t logical = inputs + products;
  const std::size_t vole = (logical + 7) & ~std::size_t{7};
  return {inputs, products, logical, vole, vole / 8, vole - logical};
}

PackedWitness build_witness(const faest::sha256_circuit::Circuit& circuit,
                            const faest::sha256_circuit::Message& secret_message) {
  require_all_secret(circuit);
  const auto layout = witness_layout(circuit);
  PackedWitness packed(layout.vole_bytes, 0);
  std::copy_n(secret_message.begin(), circuit.message_length(), packed.begin());

  const auto products = circuit.multiplication_witness(secret_message);
  assert(products.size() == layout.multiplication_bits);
  for (std::size_t i = 0; i != products.size(); ++i) {
    set_bit(packed, layout.secret_input_bits + i, products[i] != 0);
  }
  return packed;
}

UnpackedWitness unpack_witness(const faest::sha256_circuit::Circuit& circuit,
                               const PackedWitness& packed) {
  require_all_secret(circuit);
  const auto layout = witness_layout(circuit);
  if (packed.size() != layout.vole_bytes) throw std::invalid_argument("wrong witness size");
  UnpackedWitness unpacked;
  std::copy_n(packed.begin(), circuit.message_length(), unpacked.secret_message.begin());
  unpacked.multiplication_outputs.resize(layout.multiplication_bits);
  for (std::size_t i = 0; i != layout.multiplication_bits; ++i) {
    unpacked.multiplication_outputs[i] = static_cast<std::uint8_t>(
        get_bit(packed, layout.secret_input_bits + i));
  }
  return unpacked;
}

bool transport_padding_is_zero(const faest::sha256_circuit::Circuit& circuit,
                               const PackedWitness& packed) {
  require_all_secret(circuit);
  const auto layout = witness_layout(circuit);
  if (packed.size() != layout.vole_bytes) return false;
  for (std::size_t i = layout.logical_bits; i != layout.vole_bits; ++i) {
    if (get_bit(packed, i)) return false;
  }
  return true;
}

bool verify_witness(const faest::sha256_circuit::Circuit& circuit, const PackedWitness& packed,
                    const faest::sha256_circuit::Digest& public_digest) {
  if (!transport_padding_is_zero(circuit, packed)) return false;
  const auto unpacked = unpack_witness(circuit, packed);
  if (!circuit.verify_statement(unpacked.secret_message, public_digest)) return false;
  const auto expected = circuit.multiplication_witness(unpacked.secret_message);
  return expected == unpacked.multiplication_outputs;
}

} // namespace vole_sha256
