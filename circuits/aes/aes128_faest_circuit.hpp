/* SPDX-License-Identifier: MIT */
#ifndef VOLE_CIRCUITS_AES128_FAEST_CIRCUIT_HPP
#define VOLE_CIRCUITS_AES128_FAEST_CIRCUIT_HPP

#include "quadratic_relation.hpp"

namespace vole_circuits::aes {

class Aes128FaestRelation final : public vole_backend::QuicksilverRelation {
public:
  static constexpr std::size_t key_bits = 128;
  static constexpr std::size_t plaintext_bits = 128;
  static constexpr std::size_t ciphertext_bits = 128;
  static constexpr std::size_t extended_witness_bits = 1280;
  static constexpr std::size_t auxiliary_bits = extended_witness_bits - key_bits;
  static constexpr std::size_t sbox_constraints = 200;

  Aes128FaestRelation();
  const vole_backend::QuadraticRelationIR& ir() const { return ir_; }
  std::array<std::uint8_t, 32> id() const override;
  std::size_t private_input_bits() const override { return key_bits; }
  std::size_t public_input_bits() const override { return plaintext_bits; }
  std::size_t output_bits() const override { return ciphertext_bits; }
  std::size_t witness_bits() const override { return extended_witness_bits; }
  std::vector<std::uint8_t> build_witness(
      std::span<const std::uint8_t> private_inputs,
      const vole_backend::PublicStatement& statement) const override;
  vole_backend::QuicksilverProof prove_constraints(
      std::span<const std::uint8_t> witness,
      const vole_backend::PublicStatement& statement,
      const std::vector<std::uint8_t*>& v_columns,
      const std::uint8_t* u_after_witness,
      const vole_backend::QuicksilverChallenge& challenge) const override;
  std::array<std::uint8_t, vole_backend::lambda_bytes> verify_constraints(
      std::span<const std::uint8_t> masked_witness,
      const vole_backend::PublicStatement& statement,
      const std::vector<std::uint8_t*>& q_columns,
      const std::array<std::uint8_t, vole_backend::lambda_bytes>& delta,
      const vole_backend::QuicksilverChallenge& challenge,
      const vole_backend::QuicksilverProof& proof) const override;

private:
  vole_backend::QuadraticRelationIR ir_;
};

} // namespace vole_circuits::aes

#endif
