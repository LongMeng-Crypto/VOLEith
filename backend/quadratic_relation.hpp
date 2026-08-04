/* SPDX-License-Identifier: MIT */
#ifndef VOLE_BACKEND_QUADRATIC_RELATION_HPP
#define VOLE_BACKEND_QUADRATIC_RELATION_HPP

#include "generic_nizk.hpp"
#include "vole/quicksilver_types.hpp"

#include <array>
#include <cstdint>
#include <span>
#include <vector>

namespace vole_backend {

enum class ExtensionField : std::uint8_t { Gf256Aes = 1 };
enum class QuadraticConstraint : std::uint8_t { AesInverseNorm = 1 };

struct QuadraticRelationIR {
  ExtensionField field = ExtensionField::Gf256Aes;
  QuadraticConstraint constraint = QuadraticConstraint::AesInverseNorm;
  std::uint32_t private_input_bits = 0;
  std::uint32_t public_input_bits = 0;
  std::uint32_t output_bits = 0;
  std::uint32_t auxiliary_witness_bits = 0;
  std::uint32_t multiplication_constraints = 0;
};

std::vector<std::uint8_t> serialize_vqir(const QuadraticRelationIR& relation);
QuadraticRelationIR deserialize_vqir(std::span<const std::uint8_t> encoded);
std::array<std::uint8_t, 32> relation_hash(const QuadraticRelationIR& relation);

class QuicksilverRelation {
public:
  virtual ~QuicksilverRelation() = default;
  virtual std::array<std::uint8_t, 32> id() const = 0;
  virtual std::size_t private_input_bits() const = 0;
  virtual std::size_t public_input_bits() const = 0;
  virtual std::size_t output_bits() const = 0;
  virtual std::size_t witness_bits() const = 0;
  virtual std::vector<std::uint8_t> build_witness(
      std::span<const std::uint8_t> private_inputs,
      const PublicStatement& statement) const = 0;
  virtual QuicksilverProof prove_constraints(
      std::span<const std::uint8_t> witness,
      const PublicStatement& statement,
      const std::vector<std::uint8_t*>& v_columns,
      const std::uint8_t* u_after_witness,
      const QuicksilverChallenge& challenge) const = 0;
  virtual std::array<std::uint8_t, lambda_bytes> verify_constraints(
      std::span<const std::uint8_t> masked_witness,
      const PublicStatement& statement,
      const std::vector<std::uint8_t*>& q_columns,
      const std::array<std::uint8_t, lambda_bytes>& delta,
      const QuicksilverChallenge& challenge,
      const QuicksilverProof& proof) const = 0;
};

std::size_t serialized_proof_bytes(const QuicksilverRelation& relation);
std::vector<std::uint8_t> prove(const QuicksilverRelation& relation,
                                std::span<const std::uint8_t> private_inputs,
                                const PublicStatement& statement,
                                std::span<const std::uint8_t> context,
                                const ProverRandomness& randomness);
bool verify(const QuicksilverRelation& relation, const PublicStatement& statement,
            std::span<const std::uint8_t> context,
            std::span<const std::uint8_t> proof);

} // namespace vole_backend

#endif
