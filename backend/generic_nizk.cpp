/* SPDX-License-Identifier: MIT */

#include "generic_nizk.hpp"
#include "quadratic_relation.hpp"

#include "backend_witness.hpp"
#include "circuit_format.hpp"
#include "faest_vole.hpp"
#include "generic_quicksilver.hpp"

extern "C" {
#include "random_oracle.h"
#include "universal_hashing.h"
#include "utils.h"
}

#include <algorithm>
#include <limits>
#include <stdexcept>

namespace vole_backend {
namespace {


constexpr std::array<std::uint8_t, 8> proof_magic = {'V', 'B', 'C', 'Z', 'K', 1, 0, 0};
constexpr char domain[] = "VOLE-BINARY-CIRCUIT-NIZK-v1";
constexpr std::size_t utilde_bytes = lambda_bytes + 2;
constexpr std::size_t challenge_1_bytes = 5 * lambda_bytes + 8;

struct Fields {
  std::vector<std::uint8_t> corrections;
  std::array<std::uint8_t, utilde_bytes> u_tilde{};
  PackedWitness d;
  std::array<std::uint8_t, lambda_bytes> a1{};
  std::array<std::uint8_t, lambda_bytes> a2{};
  std::vector<std::uint8_t> opening;
  std::array<std::uint8_t, lambda_bytes> challenge_3{};
  std::array<std::uint8_t, 16> iv_pre{};
  std::uint32_t counter = 0;
};

// Compatibility adapter for verification of generic binary-circuit proofs
// emitted before the runtime security-level API introduced proof format v2.
class LegacyBinaryRelation final : public QuicksilverRelation {
public:
  explicit LegacyBinaryRelation(const BinaryCircuit& circuit) : circuit_(circuit) {}
  std::array<std::uint8_t, 32> id() const override { return circuit_hash(circuit_); }
  std::size_t private_input_bits() const override { return circuit_.statistics().private_inputs; }
  std::size_t public_input_bits() const override { return circuit_.statistics().public_inputs; }
  std::size_t output_bits() const override { return circuit_.outputs().size(); }
  std::size_t witness_bits() const override { return witness_layout(circuit_).vole_bits; }
  std::vector<std::uint8_t> build_witness(
      std::span<const std::uint8_t> private_inputs,
      const PublicStatement& statement) const override {
    const auto evaluation = circuit_.evaluate(private_inputs, statement.public_inputs);
    if (evaluation.outputs != statement.expected_outputs)
      throw std::invalid_argument("private input does not satisfy outputs");
    return vole_backend::build_witness(circuit_, private_inputs, statement.public_inputs);
  }
  QuicksilverProof prove_constraints(
      std::span<const std::uint8_t> witness, const PublicStatement& statement,
      const std::vector<std::uint8_t*>& v, const std::uint8_t* u_extra,
      const QuicksilverChallenge& challenge) const override {
    const PackedWitness packed(witness.begin(), witness.end());
    return quicksilver_prove(circuit_, packed, statement.public_inputs,
                             statement.expected_outputs, v, u_extra, challenge);
  }
  std::array<std::uint8_t, lambda_bytes> verify_constraints(
      std::span<const std::uint8_t> d, const PublicStatement& statement,
      const std::vector<std::uint8_t*>& q,
      const std::array<std::uint8_t, lambda_bytes>& delta,
      const QuicksilverChallenge& challenge,
      const QuicksilverProof& proof) const override {
    const PackedWitness packed(d.begin(), d.end());
    return quicksilver_verify(circuit_, packed, statement.public_inputs,
                              statement.expected_outputs, q, delta, challenge, proof);
  }

private:
  const BinaryCircuit& circuit_;
};

bool valid_statement(const QuicksilverRelation& relation, const PublicStatement& statement) {
  const auto valid_bit = [](std::uint8_t bit) { return bit <= 1; };
  return statement.public_inputs.size() == relation.public_input_bits() &&
         statement.expected_outputs.size() == relation.output_bits() &&
         std::all_of(statement.public_inputs.begin(), statement.public_inputs.end(), valid_bit) &&
         std::all_of(statement.expected_outputs.begin(), statement.expected_outputs.end(), valid_bit);
}

void domain_update(H2_context_t* hash) {
  H2_update(hash, reinterpret_cast<const std::uint8_t*>(domain), sizeof(domain) - 1);
}

std::array<std::uint8_t, 2 * lambda_bytes> statement_hash(
    const QuicksilverRelation& relation, const PublicStatement& statement,
    std::span<const std::uint8_t> context) {
  if (!valid_statement(relation, statement)) throw std::invalid_argument("invalid public statement");
  if (context.size() > std::numeric_limits<std::uint32_t>::max()) throw std::invalid_argument("context too long");
  const auto id = relation.id();
  H2_context_t hash;
  H2_init(&hash, lambda_bits);
  domain_update(&hash);
  H2_update(&hash, id.data(), id.size());
  H2_update_u32_le(&hash, static_cast<std::uint32_t>(statement.public_inputs.size()));
  if (!statement.public_inputs.empty()) H2_update(&hash, statement.public_inputs.data(), statement.public_inputs.size());
  H2_update_u32_le(&hash, static_cast<std::uint32_t>(statement.expected_outputs.size()));
  if (!statement.expected_outputs.empty()) H2_update(&hash, statement.expected_outputs.data(), statement.expected_outputs.size());
  H2_update_u32_le(&hash, static_cast<std::uint32_t>(context.size()));
  if (!context.empty()) H2_update(&hash, context.data(), context.size());
  std::array<std::uint8_t, 2 * lambda_bytes> mu{};
  H2_0_final(&hash, mu.data(), mu.size());
  return mu;
}

void derive_seed(const PackedWitness& witness,
                 const std::array<std::uint8_t, 2 * lambda_bytes>& mu,
                 const ProverRandomness& randomness,
                 std::array<std::uint8_t, lambda_bytes>& root,
                 std::array<std::uint8_t, 16>& iv_pre,
                 std::array<std::uint8_t, 16>& iv) {
  H3_context_t hash;
  H3_init(&hash, lambda_bits);
  H3_update(&hash, reinterpret_cast<const std::uint8_t*>(domain), sizeof(domain) - 1);
  if (!witness.empty()) H3_update(&hash, witness.data(), witness.size());
  H3_update(&hash, mu.data(), mu.size());
  H3_update(&hash, randomness.data(), randomness.size());
  H3_final(&hash, root.data(), root.size(), iv_pre.data());
  H4(iv.data(), iv_pre.data(), lambda_bits);
}

std::array<std::uint8_t, challenge_1_bytes> challenge_1(
    const std::array<std::uint8_t, 2 * lambda_bytes>& mu,
    const std::array<std::uint8_t, 2 * lambda_bytes>& hcom,
    const std::vector<std::uint8_t>& corrections, const std::array<std::uint8_t, 16>& iv) {
  H2_context_t hash;
  H2_init(&hash, lambda_bits);
  H2_update(&hash, mu.data(), mu.size());
  H2_update(&hash, hcom.data(), hcom.size());
  H2_update(&hash, corrections.data(), corrections.size());
  H2_update(&hash, iv.data(), iv.size());
  std::array<std::uint8_t, challenge_1_bytes> out{};
  H2_1_final(&hash, out.data(), out.size());
  return out;
}

H2_context_t challenge_2_prefix(const std::array<std::uint8_t, challenge_1_bytes>& c1,
                                const std::array<std::uint8_t, utilde_bytes>& u_tilde) {
  H2_context_t hash;
  H2_init(&hash, lambda_bits);
  H2_update(&hash, c1.data(), c1.size());
  H2_update(&hash, u_tilde.data(), u_tilde.size());
  return hash;
}

QuicksilverChallenge finish_challenge_2(H2_context_t* hash, const PackedWitness& d) {
  if (!d.empty()) H2_update(hash, d.data(), d.size());
  QuicksilverChallenge out{};
  H2_2_final(hash, out.data(), out.size());
  return out;
}

H2_context_t challenge_3_prefix(const QuicksilverChallenge& c2,
                                const std::array<std::uint8_t, lambda_bytes>& a0,
                                const std::array<std::uint8_t, lambda_bytes>& a1,
                                const std::array<std::uint8_t, lambda_bytes>& a2) {
  H2_context_t hash;
  H2_init(&hash, lambda_bits);
  H2_update(&hash, c2.data(), c2.size());
  H2_update(&hash, a0.data(), a0.size());
  H2_update(&hash, a1.data(), a1.size());
  H2_update(&hash, a2.data(), a2.size());
  return hash;
}

std::array<std::uint8_t, lambda_bytes> finish_challenge_3(const H2_context_t& prefix,
                                                         std::uint32_t counter) {
  H2_context_t hash;
  H2_copy(&hash, &prefix);
  H2_update_u32_le(&hash, counter);
  std::array<std::uint8_t, lambda_bytes> out{};
  H2_3_final(&hash, out.data(), out.size());
  return out;
}

bool grinding(const std::array<std::uint8_t, lambda_bytes>& challenge) {
  const auto parameters = faest_vole_parameters();
  for (std::size_t bit = lambda_bits - parameters.w_grind; bit != lambda_bits; ++bit) {
    if (ptr_get_bit(challenge.data(), bit)) return false;
  }
  return true;
}

std::vector<std::uint8_t> serialize(const QuicksilverRelation& relation, const Fields& f) {
  std::vector<std::uint8_t> out;
  out.reserve(serialized_proof_bytes(relation));
  const auto append = [&out](const auto& value) { out.insert(out.end(), value.begin(), value.end()); };
  append(proof_magic); append(f.corrections); append(f.u_tilde); append(f.d);
  append(f.a1); append(f.a2); append(f.opening); append(f.challenge_3); append(f.iv_pre);
  for (unsigned int shift = 0; shift != 32; shift += 8) out.push_back(static_cast<std::uint8_t>(f.counter >> shift));
  if (out.size() != serialized_proof_bytes(relation)) throw std::logic_error("generic proof size mismatch");
  return out;
}

bool deserialize(const QuicksilverRelation& relation, std::span<const std::uint8_t> input, Fields& f) {
  const auto witness_bits = relation.witness_bits();
  const auto witness_bytes = (witness_bits + 7) / 8;
  const auto vole = vole_layout(witness_bits);
  if (input.size() != serialized_proof_bytes(relation) ||
      !std::equal(proof_magic.begin(), proof_magic.end(), input.begin())) return false;
  f.corrections.resize(vole.correction_bytes);
  f.d.resize(witness_bytes);
  f.opening.resize(vole_opening_bytes);
  std::size_t offset = proof_magic.size();
  const auto take = [&input, &offset](auto& value) {
    std::copy_n(input.begin() + static_cast<std::ptrdiff_t>(offset), value.size(), value.begin());
    offset += value.size();
  };
  take(f.corrections); take(f.u_tilde); take(f.d); take(f.a1); take(f.a2);
  take(f.opening); take(f.challenge_3); take(f.iv_pre);
  f.counter = 0;
  for (unsigned int shift = 0; shift != 32; shift += 8) f.counter |= std::uint32_t(input[offset++]) << shift;
  return offset == input.size();
}

} // namespace

std::size_t serialized_proof_bytes(const QuicksilverRelation& relation) {
  const auto witness_bits = relation.witness_bits();
  const auto vole = vole_layout(witness_bits);
  return proof_magic.size() + vole.correction_bytes + utilde_bytes + (witness_bits + 7) / 8 +
         2 * lambda_bytes + vole_opening_bytes + lambda_bytes + 16 + 4;
}

std::vector<std::uint8_t> prove(const QuicksilverRelation& relation,
                                std::span<const std::uint8_t> private_inputs,
                                const PublicStatement& statement,
                                std::span<const std::uint8_t> context,
                                const ProverRandomness& randomness) {
  if (!valid_statement(relation, statement)) throw std::invalid_argument("invalid public statement");
  const auto witness = relation.build_witness(private_inputs, statement);
  if (witness.size() != (relation.witness_bits() + 7) / 8)
    throw std::logic_error("relation returned wrong witness size");
  const auto mu = statement_hash(relation, statement, context);
  std::array<std::uint8_t, lambda_bytes> root{};
  std::array<std::uint8_t, 16> iv_pre{}, iv{};
  derive_seed(witness, mu, randomness, root, iv_pre, iv);
  FaestVoleCommitment commitment(root, iv, relation.witness_bits());
  auto v = commitment.v_columns();
  const auto c1 = challenge_1(mu, commitment.commitment_hash(), commitment.corrections(), iv);
  Fields f;
  f.corrections = commitment.corrections();
  f.iv_pre = iv_pre;
  vole_hash(f.u_tilde.data(), c1.data(), commitment.u().data(), relation.witness_bits(), lambda_bits);
  auto c2_hash = challenge_2_prefix(c1, f.u_tilde);
  std::array<std::uint8_t, utilde_bytes> v_tilde{};
  for (std::size_t column = 0; column != lambda_bits; ++column) {
    vole_hash(v_tilde.data(), c1.data(), v[column], relation.witness_bits(), lambda_bits);
    H2_update(&c2_hash, v_tilde.data(), v_tilde.size());
  }
  f.d = mask_witness(witness, commitment.u());
  const auto c2 = finish_challenge_2(&c2_hash, f.d);
  const auto qs = relation.prove_constraints(witness, statement, v,
      commitment.u().data() + witness.size(), c2);
  f.a1 = qs.a1; f.a2 = qs.a2;
  auto c3_hash = challenge_3_prefix(c2, qs.a0, qs.a1, qs.a2);
  for (std::uint32_t counter = 0;; ++counter) {
    f.challenge_3 = finish_challenge_3(c3_hash, counter);
    if (!grinding(f.challenge_3) || !commitment.open(f.challenge_3, f.opening)) continue;
    f.counter = counter;
    break;
  }
  hash_clear(&c3_hash);
  return serialize(relation, f);
}

bool verify(const QuicksilverRelation& relation, const PublicStatement& statement,
            std::span<const std::uint8_t> context,
            std::span<const std::uint8_t> proof) {
  try {
    if (!valid_statement(relation, statement)) return false;
    Fields f;
    if (!deserialize(relation, proof, f) || !grinding(f.challenge_3)) return false;
    std::array<std::uint8_t, 16> iv{};
    H4(iv.data(), f.iv_pre.data(), lambda_bits);
    ReconstructedVole reconstructed;
    if (!reconstruct_vole(iv, f.challenge_3, f.opening, f.corrections, relation.witness_bits(), reconstructed)) return false;
    const auto mu = statement_hash(relation, statement, context);
    const auto c1 = challenge_1(mu, reconstructed.commitment_hash, f.corrections, iv);
    auto c2_hash = challenge_2_prefix(c1, f.u_tilde);
    auto q = reconstructed.columns();
    std::array<std::uint8_t, utilde_bytes> q_tilde{};
    for (std::size_t column = 0; column != lambda_bits; ++column) {
      vole_hash(q_tilde.data(), c1.data(), q[column], relation.witness_bits(), lambda_bits);
      if (ptr_get_bit(f.challenge_3.data(), column)) {
        for (std::size_t i = 0; i != q_tilde.size(); ++i) q_tilde[i] ^= f.u_tilde[i];
      }
      H2_update(&c2_hash, q_tilde.data(), q_tilde.size());
    }
    const auto c2 = finish_challenge_2(&c2_hash, f.d);
    QuicksilverProof qs;
    qs.a1 = f.a1; qs.a2 = f.a2;
    qs.a0 = relation.verify_constraints(f.d, statement, q, f.challenge_3, c2, qs);
    auto c3_hash = challenge_3_prefix(c2, qs.a0, qs.a1, qs.a2);
    return finish_challenge_3(c3_hash, f.counter) == f.challenge_3;
  } catch (const std::exception&) {
    return false;
  }
}

namespace parameterized_nizk {
namespace {

constexpr char parameterized_domain[] = "VOLE-BINARY-CIRCUIT-NIZK-v2";

struct Fields {
  std::vector<std::uint8_t> corrections;
  std::vector<std::uint8_t> u_tilde;
  PackedWitness d;
  std::vector<std::uint8_t> a1;
  std::vector<std::uint8_t> a2;
  std::vector<std::uint8_t> opening;
  std::vector<std::uint8_t> challenge_3;
  std::array<std::uint8_t, 16> iv_pre{};
  std::uint32_t counter = 0;
};

std::array<std::uint8_t, 8> magic(SecurityLevel security) {
  return {'V', 'B', 'C', 'Z', 'K', 2, security_level_code(security), 0};
}

bool valid_statement(const PreparedBinaryCircuit& circuit, const PublicStatement& statement) {
  const auto& stats = circuit.statistics();
  const auto valid_bit = [](std::uint8_t bit) { return bit <= 1; };
  return statement.public_inputs.size() == stats.public_inputs &&
         statement.expected_outputs.size() == circuit.circuit().outputs().size() &&
         std::all_of(statement.public_inputs.begin(), statement.public_inputs.end(), valid_bit) &&
         std::all_of(statement.expected_outputs.begin(), statement.expected_outputs.end(), valid_bit);
}

void domain_update(H2_context_t* hash, SecurityLevel security) {
  H2_update(hash, reinterpret_cast<const std::uint8_t*>(parameterized_domain),
            sizeof(parameterized_domain) - 1);
  const auto code = security_level_code(security);
  H2_update(hash, &code, 1);
}

std::vector<std::uint8_t> statement_hash(
    const PreparedBinaryCircuit& circuit, SecurityLevel security,
    const PublicStatement& statement, std::span<const std::uint8_t> context) {
  if (!valid_statement(circuit, statement)) throw std::invalid_argument("invalid public statement");
  if (context.size() > std::numeric_limits<std::uint32_t>::max())
    throw std::invalid_argument("context too long");
  const auto& parameters = security_parameters(security);
  const auto id = circuit.identifier(security);
  H2_context_t hash;
  H2_init(&hash, parameters.lambda_bits);
  domain_update(&hash, security);
  H2_update(&hash, id.data(), id.size());
  H2_update_u32_le(&hash, static_cast<std::uint32_t>(statement.public_inputs.size()));
  if (!statement.public_inputs.empty())
    H2_update(&hash, statement.public_inputs.data(), statement.public_inputs.size());
  H2_update_u32_le(&hash, static_cast<std::uint32_t>(statement.expected_outputs.size()));
  if (!statement.expected_outputs.empty())
    H2_update(&hash, statement.expected_outputs.data(), statement.expected_outputs.size());
  H2_update_u32_le(&hash, static_cast<std::uint32_t>(context.size()));
  if (!context.empty()) H2_update(&hash, context.data(), context.size());
  std::vector<std::uint8_t> mu(2 * parameters.lambda_bytes);
  H2_0_final(&hash, mu.data(), mu.size());
  return mu;
}

void derive_seed(std::span<const std::uint8_t> witness,
                 std::span<const std::uint8_t> mu,
                 const ProverRandomness& randomness,
                 SecurityLevel security,
                 std::vector<std::uint8_t>& root,
                 std::array<std::uint8_t, 16>& iv_pre,
                 std::array<std::uint8_t, 16>& iv) {
  const auto& parameters = security_parameters(security);
  H3_context_t hash;
  H3_init(&hash, parameters.lambda_bits);
  H3_update(&hash, reinterpret_cast<const std::uint8_t*>(parameterized_domain),
            sizeof(parameterized_domain) - 1);
  const auto code = security_level_code(security);
  H3_update(&hash, &code, 1);
  if (!witness.empty()) H3_update(&hash, witness.data(), witness.size());
  H3_update(&hash, mu.data(), mu.size());
  H3_update(&hash, randomness.data(), randomness.size());
  root.resize(parameters.lambda_bytes);
  H3_final(&hash, root.data(), root.size(), iv_pre.data());
  H4(iv.data(), iv_pre.data(), parameters.lambda_bits);
}

std::vector<std::uint8_t> challenge_1(
    SecurityLevel security, std::span<const std::uint8_t> mu,
    std::span<const std::uint8_t> hcom,
    std::span<const std::uint8_t> corrections,
    const std::array<std::uint8_t, 16>& iv) {
  const auto& parameters = security_parameters(security);
  H2_context_t hash;
  H2_init(&hash, parameters.lambda_bits);
  H2_update(&hash, mu.data(), mu.size());
  H2_update(&hash, hcom.data(), hcom.size());
  H2_update(&hash, corrections.data(), corrections.size());
  H2_update(&hash, iv.data(), iv.size());
  std::vector<std::uint8_t> out(parameters.challenge_1_bytes());
  H2_1_final(&hash, out.data(), out.size());
  return out;
}

H2_context_t challenge_2_prefix(SecurityLevel security,
                                std::span<const std::uint8_t> c1,
                                std::span<const std::uint8_t> u_tilde) {
  H2_context_t hash;
  H2_init(&hash, security_parameters(security).lambda_bits);
  H2_update(&hash, c1.data(), c1.size());
  H2_update(&hash, u_tilde.data(), u_tilde.size());
  return hash;
}

std::vector<std::uint8_t> finish_challenge_2(SecurityLevel security,
                                             H2_context_t* hash,
                                             std::span<const std::uint8_t> d) {
  if (!d.empty()) H2_update(hash, d.data(), d.size());
  std::vector<std::uint8_t> out(
      security_parameters(security).quicksilver_challenge_bytes());
  H2_2_final(hash, out.data(), out.size());
  return out;
}

H2_context_t challenge_3_prefix(SecurityLevel security,
                                std::span<const std::uint8_t> c2,
                                std::span<const std::uint8_t> a0,
                                std::span<const std::uint8_t> a1,
                                std::span<const std::uint8_t> a2) {
  H2_context_t hash;
  H2_init(&hash, security_parameters(security).lambda_bits);
  H2_update(&hash, c2.data(), c2.size());
  H2_update(&hash, a0.data(), a0.size());
  H2_update(&hash, a1.data(), a1.size());
  H2_update(&hash, a2.data(), a2.size());
  return hash;
}

std::vector<std::uint8_t> finish_challenge_3(SecurityLevel security,
                                             const H2_context_t& prefix,
                                             std::uint32_t counter) {
  H2_context_t hash;
  H2_copy(&hash, &prefix);
  H2_update_u32_le(&hash, counter);
  std::vector<std::uint8_t> out(security_parameters(security).lambda_bytes);
  H2_3_final(&hash, out.data(), out.size());
  return out;
}

bool grinding(SecurityLevel security, std::span<const std::uint8_t> challenge) {
  const auto& level = security_parameters(security);
  const auto parameters = faest_vole_parameters(security);
  if (challenge.size() != level.lambda_bytes) return false;
  for (std::size_t bit = level.lambda_bits - parameters.w_grind;
       bit != level.lambda_bits; ++bit) {
    if (ptr_get_bit(challenge.data(), bit)) return false;
  }
  return true;
}

std::size_t proof_bytes(const PreparedBinaryCircuit& circuit, SecurityLevel security) {
  const auto& parameters = security_parameters(security);
  const auto witness_bits = circuit.layout().vole_bits;
  const auto vole = vole_layout(witness_bits, security);
  return magic(security).size() + vole.correction_bytes + parameters.utilde_bytes() +
         (witness_bits + 7) / 8 + 2 * parameters.lambda_bytes +
         vole_opening_size(security) + parameters.lambda_bytes + 16 + 4;
}

std::vector<std::uint8_t> serialize(const PreparedBinaryCircuit& circuit,
                                    SecurityLevel security, const Fields& fields) {
  std::vector<std::uint8_t> out;
  out.reserve(proof_bytes(circuit, security));
  const auto append = [&out](const auto& value) {
    out.insert(out.end(), value.begin(), value.end());
  };
  append(magic(security));
  append(fields.corrections);
  append(fields.u_tilde);
  append(fields.d);
  append(fields.a1);
  append(fields.a2);
  append(fields.opening);
  append(fields.challenge_3);
  append(fields.iv_pre);
  for (unsigned int shift = 0; shift != 32; shift += 8)
    out.push_back(static_cast<std::uint8_t>(fields.counter >> shift));
  if (out.size() != proof_bytes(circuit, security))
    throw std::logic_error("parameterized proof size mismatch");
  return out;
}

bool deserialize(const PreparedBinaryCircuit& circuit, SecurityLevel security,
                 std::span<const std::uint8_t> input, Fields& fields) {
  const auto& parameters = security_parameters(security);
  const auto witness_bits = circuit.layout().vole_bits;
  const auto vole = vole_layout(witness_bits, security);
  const auto expected_magic = magic(security);
  if (input.size() != proof_bytes(circuit, security) ||
      !std::equal(expected_magic.begin(), expected_magic.end(), input.begin()))
    return false;
  fields.corrections.resize(vole.correction_bytes);
  fields.u_tilde.resize(parameters.utilde_bytes());
  fields.d.resize((witness_bits + 7) / 8);
  fields.a1.resize(parameters.lambda_bytes);
  fields.a2.resize(parameters.lambda_bytes);
  fields.opening.resize(vole_opening_size(security));
  fields.challenge_3.resize(parameters.lambda_bytes);
  std::size_t offset = expected_magic.size();
  const auto take = [&input, &offset](auto& value) {
    std::copy_n(input.begin() + static_cast<std::ptrdiff_t>(offset), value.size(), value.begin());
    offset += value.size();
  };
  take(fields.corrections);
  take(fields.u_tilde);
  take(fields.d);
  take(fields.a1);
  take(fields.a2);
  take(fields.opening);
  take(fields.challenge_3);
  take(fields.iv_pre);
  fields.counter = 0;
  for (unsigned int shift = 0; shift != 32; shift += 8)
    fields.counter |= std::uint32_t(input[offset++]) << shift;
  return offset == input.size();
}

} // namespace

std::size_t serialized_proof_bytes(const PreparedBinaryCircuit& circuit,
                                   SecurityLevel security) {
  return proof_bytes(circuit, security);
}

std::vector<std::uint8_t> prove(const PreparedBinaryCircuit& circuit,
                                SecurityLevel security,
                                std::span<const std::uint8_t> private_inputs,
                                const PublicStatement& statement,
                                std::span<const std::uint8_t> context,
                                const ProverRandomness& randomness) {
  if (!valid_statement(circuit, statement)) throw std::invalid_argument("invalid public statement");
  const auto evaluation = circuit.evaluate(private_inputs, statement.public_inputs);
  if (evaluation.outputs != statement.expected_outputs)
    throw std::invalid_argument("private input does not satisfy outputs");
  const auto witness = circuit.build_witness(private_inputs, evaluation);
  const auto witness_bits = circuit.layout().vole_bits;
  if (witness.size() != (witness_bits + 7) / 8)
    throw std::logic_error("binary relation returned wrong witness size");
  const auto& parameters = security_parameters(security);
  const auto mu = statement_hash(circuit, security, statement, context);
  std::vector<std::uint8_t> root;
  std::array<std::uint8_t, 16> iv_pre{}, iv{};
  derive_seed(witness, mu, randomness, security, root, iv_pre, iv);
  ParameterizedFaestVoleCommitment commitment(security, root, iv, witness_bits);
  auto v = commitment.v_columns();
  const auto c1 = challenge_1(security, mu, commitment.commitment_hash(),
                              commitment.corrections(), iv);
  Fields fields;
  fields.corrections = commitment.corrections();
  fields.iv_pre = iv_pre;
  fields.u_tilde.resize(parameters.utilde_bytes());
  vole_hash(fields.u_tilde.data(), c1.data(), commitment.u().data(), witness_bits,
            parameters.lambda_bits);
  auto c2_hash = challenge_2_prefix(security, c1, fields.u_tilde);
  std::vector<std::uint8_t> v_tilde(parameters.utilde_bytes());
  for (std::size_t column = 0; column != parameters.lambda_bits; ++column) {
    vole_hash(v_tilde.data(), c1.data(), v[column], witness_bits,
              parameters.lambda_bits);
    H2_update(&c2_hash, v_tilde.data(), v_tilde.size());
  }
  fields.d = mask_witness(witness, commitment.u());
  const auto c2 = finish_challenge_2(security, &c2_hash, fields.d);
  const auto qs = quicksilver_prove(
      security, circuit, witness, statement.public_inputs,
      statement.expected_outputs, v, commitment.u().data() + witness.size(), c2);
  fields.a1 = qs.a1;
  fields.a2 = qs.a2;
  auto c3_hash = challenge_3_prefix(security, c2, qs.a0, qs.a1, qs.a2);
  for (std::uint32_t counter = 0;; ++counter) {
    fields.challenge_3 = finish_challenge_3(security, c3_hash, counter);
    if (!grinding(security, fields.challenge_3) ||
        !commitment.open(fields.challenge_3, fields.opening))
      continue;
    fields.counter = counter;
    break;
  }
  hash_clear(&c3_hash);
  return serialize(circuit, security, fields);
}

bool verify(const PreparedBinaryCircuit& circuit, SecurityLevel security,
            const PublicStatement& statement,
            std::span<const std::uint8_t> context,
            std::span<const std::uint8_t> proof) {
  try {
    if (!valid_statement(circuit, statement)) return false;
    const auto& parameters = security_parameters(security);
    const auto witness_bits = circuit.layout().vole_bits;
    Fields fields;
    if (!deserialize(circuit, security, proof, fields) ||
        !grinding(security, fields.challenge_3))
      return false;
    std::array<std::uint8_t, 16> iv{};
    H4(iv.data(), fields.iv_pre.data(), parameters.lambda_bits);
    ParameterizedReconstructedVole reconstructed;
    if (!reconstruct_vole(security, iv, fields.challenge_3, fields.opening,
                          fields.corrections, witness_bits, reconstructed))
      return false;
    const auto mu = statement_hash(circuit, security, statement, context);
    const auto c1 = challenge_1(security, mu, reconstructed.commitment_hash,
                                fields.corrections, iv);
    auto c2_hash = challenge_2_prefix(security, c1, fields.u_tilde);
    auto q = reconstructed.columns();
    std::vector<std::uint8_t> q_tilde(parameters.utilde_bytes());
    for (std::size_t column = 0; column != parameters.lambda_bits; ++column) {
      vole_hash(q_tilde.data(), c1.data(), q[column], witness_bits,
                parameters.lambda_bits);
      if (ptr_get_bit(fields.challenge_3.data(), column)) {
        for (std::size_t i = 0; i != q_tilde.size(); ++i)
          q_tilde[i] ^= fields.u_tilde[i];
      }
      H2_update(&c2_hash, q_tilde.data(), q_tilde.size());
    }
    const auto c2 = finish_challenge_2(security, &c2_hash, fields.d);
    ParameterizedQuicksilverProof qs{
        std::vector<std::uint8_t>(parameters.lambda_bytes), fields.a1, fields.a2};
    qs.a0 = quicksilver_verify(
        security, circuit, fields.d, statement.public_inputs,
        statement.expected_outputs, q, fields.challenge_3, c2, qs);
    auto c3_hash = challenge_3_prefix(security, c2, qs.a0, qs.a1, qs.a2);
    const auto expected = finish_challenge_3(security, c3_hash, fields.counter);
    hash_clear(&c3_hash);
    return expected == fields.challenge_3;
  } catch (const std::exception&) {
    return false;
  }
}

} // namespace parameterized_nizk

std::size_t serialized_proof_bytes(const BinaryCircuit& circuit,
                                   SecurityLevel security) {
  const PreparedBinaryCircuit prepared(circuit);
  return serialized_proof_bytes(prepared, security);
}

std::size_t serialized_proof_bytes(const PreparedBinaryCircuit& circuit,
                                   SecurityLevel security) {
  return parameterized_nizk::serialized_proof_bytes(circuit, security);
}

std::size_t serialized_proof_bytes(const BinaryCircuit& circuit) {
  return serialized_proof_bytes(circuit, SecurityLevel::Bits128);
}

std::vector<std::uint8_t> prove(const BinaryCircuit& circuit,
                                SecurityLevel security,
                                std::span<const std::uint8_t> private_inputs,
                                const PublicStatement& statement,
                                std::span<const std::uint8_t> context,
                                const ProverRandomness& randomness) {
  const PreparedBinaryCircuit prepared(circuit);
  return prove(prepared, security, private_inputs, statement, context,
               randomness);
}

std::vector<std::uint8_t> prove(const PreparedBinaryCircuit& circuit,
                                SecurityLevel security,
                                std::span<const std::uint8_t> private_inputs,
                                const PublicStatement& statement,
                                std::span<const std::uint8_t> context,
                                const ProverRandomness& randomness) {
  return parameterized_nizk::prove(circuit, security, private_inputs,
                                   statement, context, randomness);
}

std::vector<std::uint8_t> prove(const BinaryCircuit& circuit,
                                std::span<const std::uint8_t> private_inputs,
                                const PublicStatement& statement,
                                std::span<const std::uint8_t> context,
                                const ProverRandomness& randomness) {
  return prove(circuit, SecurityLevel::Bits128, private_inputs, statement,
               context, randomness);
}

bool verify(const BinaryCircuit& circuit, SecurityLevel security,
            const PublicStatement& statement,
            std::span<const std::uint8_t> context,
            std::span<const std::uint8_t> proof) {
  const PreparedBinaryCircuit prepared(circuit);
  return verify(prepared, security, statement, context, proof);
}

bool verify(const PreparedBinaryCircuit& circuit, SecurityLevel security,
            const PublicStatement& statement,
            std::span<const std::uint8_t> context,
            std::span<const std::uint8_t> proof) {
  if (parameterized_nizk::verify(circuit, security, statement, context, proof))
    return true;
  if (security != SecurityLevel::Bits128) return false;
  const LegacyBinaryRelation legacy(circuit.circuit());
  return verify(static_cast<const QuicksilverRelation&>(legacy), statement,
                context, proof);
}

bool verify(const BinaryCircuit& circuit, const PublicStatement& statement,
            std::span<const std::uint8_t> context,
            std::span<const std::uint8_t> proof) {
  return verify(circuit, SecurityLevel::Bits128, statement, context, proof);
}

} // namespace vole_backend
