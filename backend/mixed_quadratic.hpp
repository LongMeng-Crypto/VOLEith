/* SPDX-License-Identifier: MIT */
#pragma once
#include "quadratic_relation.hpp"
#include "vole/gf128.hpp"

namespace vole_backend {
// Public, topologically ordered F_(2^128)-linear forms over authenticated
// Boolean wires and earlier linear forms. No form allocates VOLE rows.
// Constant table entries 0 and 1 must be the field zero and one.
struct FieldLinearTerm { Wire source; std::uint16_t coefficient; };
struct FieldLinearForm {
  std::vector<FieldLinearTerm> terms;
  bool cache_scaled = false; // cache public scalar multiples of reused forms
};
struct FieldQuadraticEquation {
  std::vector<std::pair<Wire,Wire>> products;
  Wire linear = 0;
  // Empty means coefficient 1. Otherwise one public scalar per product.
  std::vector<std::uint16_t> coefficients;
};
Gf128 field_multiply(Gf128,Gf128);

class MixedQuadraticRelation final : public QuicksilverRelation {
public:
  MixedQuadraticRelation(BinaryCircuit, std::vector<Gf128> constants,
      std::vector<FieldLinearForm>, std::vector<FieldQuadraticEquation>,
      std::vector<std::uint8_t> public_binding);
  std::array<std::uint8_t,32> id() const override { return id_; }
  std::size_t private_input_bits() const override;
  std::size_t public_input_bits() const override;
  // Binary outputs are internal wires, NOT publicly disclosed outputs.
  std::size_t output_bits() const override { return 0; }
  std::size_t witness_bits() const override;
  const BinaryCircuit& circuit() const { return circuit_; }
  std::size_t equation_count() const { return equations_.size(); }
  std::size_t product_count() const;
  std::size_t linear_term_count() const;
  std::vector<std::uint8_t> build_witness(std::span<const std::uint8_t>,
      const PublicStatement&) const override;
  QuicksilverProof prove_constraints(std::span<const std::uint8_t>,
      const PublicStatement&, const std::vector<std::uint8_t*>&,
      const std::uint8_t*,const QuicksilverChallenge&) const override;
  std::array<std::uint8_t,lambda_bytes> verify_constraints(
      std::span<const std::uint8_t>,const PublicStatement&,
      const std::vector<std::uint8_t*>&,
      const std::array<std::uint8_t,lambda_bytes>&,
      const QuicksilverChallenge&,const QuicksilverProof&) const override;
private:
  BinaryCircuit circuit_;
  std::vector<Gf128> constants_;
  std::vector<FieldLinearForm> forms_;
  std::vector<FieldQuadraticEquation> equations_;
  std::array<std::uint8_t,32> id_{};
};
}
