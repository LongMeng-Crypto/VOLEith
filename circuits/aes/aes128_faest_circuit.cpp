/* SPDX-License-Identifier: MIT */

#include "aes128_faest_circuit.hpp"
#include "vole/faest_vole.hpp"

extern "C" {
#include "aes.h"
#include "faest_aes.h"
}

#include <stdexcept>

namespace vole_circuits::aes {
namespace {

std::array<std::uint8_t, 16> pack128(std::span<const std::uint8_t> bits) {
  if (bits.size() != 128) throw std::invalid_argument("AES value must contain 128 bits");
  std::array<std::uint8_t, 16> out{};
  for (std::size_t i = 0; i != bits.size(); ++i) {
    if (bits[i] > 1) throw std::invalid_argument("AES input is not binary");
    out[i / 8] |= bits[i] << (i % 8);
  }
  return out;
}

void check_statement(const vole_backend::PublicStatement& statement) {
  if (statement.public_inputs.size() != 128 || statement.expected_outputs.size() != 128)
    throw std::invalid_argument("AES-128 statement has wrong size");
}

} // namespace

Aes128FaestRelation::Aes128FaestRelation() {
  ir_.private_input_bits = key_bits;
  ir_.public_input_bits = plaintext_bits;
  ir_.output_bits = ciphertext_bits;
  ir_.auxiliary_witness_bits = auxiliary_bits;
  ir_.multiplication_constraints = sbox_constraints;
}

std::array<std::uint8_t, 32> Aes128FaestRelation::id() const {
  return vole_backend::relation_hash(ir_);
}

std::vector<std::uint8_t> Aes128FaestRelation::build_witness(
    std::span<const std::uint8_t> private_inputs,
    const vole_backend::PublicStatement& statement) const {
  check_statement(statement);
  const auto key = pack128(private_inputs);
  const auto plaintext = pack128(statement.public_inputs);
  const auto claimed = pack128(statement.expected_outputs);
  aes_round_keys_t round_keys;
  aes128_init_round_keys(&round_keys, key.data());
  std::array<std::uint8_t, 16> actual{};
  aes128_encrypt_block(&round_keys, plaintext.data(), actual.data());
  if (actual != claimed) throw std::invalid_argument("AES private key does not satisfy statement");
  auto params = vole_backend::faest_vole_parameters();
  std::vector<std::uint8_t> witness(extended_witness_bits / 8);
  aes_extend_witness(witness.data(), key.data(), plaintext.data(), &params);
  return witness;
}

vole_backend::QuicksilverProof Aes128FaestRelation::prove_constraints(
    std::span<const std::uint8_t> witness,
    const vole_backend::PublicStatement& statement,
    const std::vector<std::uint8_t*>& v_columns,
    const std::uint8_t* u_after_witness,
    const vole_backend::QuicksilverChallenge& challenge) const {
  check_statement(statement);
  if (witness.size() != extended_witness_bits / 8) throw std::invalid_argument("wrong AES witness size");
  const auto plaintext = pack128(statement.public_inputs);
  const auto ciphertext = pack128(statement.expected_outputs);
  auto params = vole_backend::faest_vole_parameters();
  auto v = v_columns;
  vole_backend::QuicksilverProof proof;
  aes_128_prover(proof.a0.data(), proof.a1.data(), proof.a2.data(), witness.data(),
                 u_after_witness, v.data(), plaintext.data(), ciphertext.data(),
                 challenge.data(), &params);
  return proof;
}

std::array<std::uint8_t, vole_backend::lambda_bytes>
Aes128FaestRelation::verify_constraints(
    std::span<const std::uint8_t> d,
    const vole_backend::PublicStatement& statement,
    const std::vector<std::uint8_t*>& q_columns,
    const std::array<std::uint8_t, vole_backend::lambda_bytes>& delta,
    const vole_backend::QuicksilverChallenge& challenge,
    const vole_backend::QuicksilverProof& proof) const {
  check_statement(statement);
  if (d.size() != extended_witness_bits / 8) throw std::invalid_argument("wrong masked AES witness size");
  const auto plaintext = pack128(statement.public_inputs);
  const auto ciphertext = pack128(statement.expected_outputs);
  auto params = vole_backend::faest_vole_parameters();
  auto q = q_columns;
  std::array<std::uint8_t, vole_backend::lambda_bytes> a0{};
  aes_128_verifier(a0.data(), d.data(), q.data(), plaintext.data(), ciphertext.data(),
                   challenge.data(), delta.data(), proof.a1.data(), proof.a2.data(), &params);
  return a0;
}

} // namespace vole_circuits::aes
