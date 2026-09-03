/* SPDX-License-Identifier: MIT */

#include "generic_quicksilver.hpp"
#include "vole/bit_matrix_transpose.hpp"

extern "C" {
#include "universal_hashing.h"
#include "utils.h"
}

#include <cassert>
#include <algorithm>
#include <stdexcept>

namespace vole_backend {
namespace {


std::vector<bf128_t> columns_to_rows(const std::vector<std::uint8_t*>& columns,
                                    std::size_t rows_count) {
  if (columns.size() != lambda_bits) throw std::invalid_argument("wrong VOLE column count");
  std::vector<bf128_t> rows(rows_count);
  std::vector<std::uint8_t> packed(64 * lambda_bytes);
  for (std::size_t row_base = 0; row_base < rows_count; row_base += 64) {
    const auto block_rows = std::min<std::size_t>(64, rows_count - row_base);
    transpose_column_block(
        columns, row_base, block_rows,
        std::span<std::uint8_t>(packed.data(), block_rows * lambda_bytes),
        lambda_bytes);
    for (std::size_t row = 0; row != block_rows; ++row)
      bf128_load(&rows[row_base + row], packed.data() + row * lambda_bytes);
  }
  return rows;
}

bf128_t add(const bf128_t& lhs, const bf128_t& rhs) {
  bf128_t result;
  bf128_add(&result, &lhs, &rhs);
  return result;
}

bf128_t multiply(const bf128_t& lhs, const bf128_t& rhs) {
  bf128_t result;
  bf128_mul(&result, &lhs, &rhs);
  return result;
}

struct ProverWire { bool value = false; bf128_t tag = bf128_zero(); };
struct VerifierWire { bf128_t key = bf128_zero(); };

void check_statement_sizes(const BinaryCircuit& circuit,
                           std::span<const std::uint8_t> public_inputs,
                           std::span<const std::uint8_t> expected_outputs) {
  const auto stats = circuit.statistics();
  if (public_inputs.size() != stats.public_inputs ||
      expected_outputs.size() != circuit.outputs().size()) {
    throw std::invalid_argument("generic public statement size mismatch");
  }
  const auto invalid = [](std::uint8_t bit) { return bit > 1; };
  if (std::any_of(public_inputs.begin(), public_inputs.end(), invalid) ||
      std::any_of(expected_outputs.begin(), expected_outputs.end(), invalid)) {
    throw std::invalid_argument("generic public statement must contain bits");
  }
}

void check_statement_sizes(const PreparedBinaryCircuit& circuit,
                           std::span<const std::uint8_t> public_inputs,
                           std::span<const std::uint8_t> expected_outputs) {
  if (public_inputs.size() != circuit.statistics().public_inputs ||
      expected_outputs.size() != circuit.circuit().outputs().size()) {
    throw std::invalid_argument("generic public statement size mismatch");
  }
  const auto invalid = [](std::uint8_t bit) { return bit > 1; };
  if (std::any_of(public_inputs.begin(), public_inputs.end(), invalid) ||
      std::any_of(expected_outputs.begin(), expected_outputs.end(), invalid)) {
    throw std::invalid_argument("generic public statement must contain bits");
  }
}

void prover_constraints(const BinaryCircuit& circuit, const UnpackedWitness& witness,
                        std::span<const std::uint8_t> public_inputs,
                        const std::vector<bf128_t>& tags, zk_hash_128_3_ctx* hasher) {
  const auto layout = witness_layout(circuit);
  std::vector<ProverWire> wires(circuit.nodes().size());
  std::size_t private_index = 0, public_index = 0, product_index = 0;
  const auto zero = bf128_zero();
  for (std::size_t i = 0; i != circuit.nodes().size(); ++i) {
    const auto& node = circuit.nodes()[i];
    switch (node.op) {
    case Op::Constant: wires[i].value = node.constant; break;
    case Op::PrivateInput:
      wires[i].value = witness.private_inputs[private_index];
      wires[i].tag = tags[private_index++];
      break;
    case Op::PublicInput: wires[i].value = public_inputs[public_index++]; break;
    case Op::Xor:
      wires[i].value = wires[node.lhs].value != wires[node.rhs].value;
      wires[i].tag = add(wires[node.lhs].tag, wires[node.rhs].tag);
      break;
    case Op::And: {
      wires[i].value = witness.multiplication_outputs[product_index];
      wires[i].tag = tags[layout.private_input_bits + product_index++];
      const auto degree0 = multiply(wires[node.lhs].tag, wires[node.rhs].tag);
      auto degree1 = wires[i].tag;
      if (wires[node.lhs].value) bf128_add_inplace(&degree1, &wires[node.rhs].tag);
      if (wires[node.rhs].value) bf128_add_inplace(&degree1, &wires[node.lhs].tag);
      zk_hash_128_3_update(hasher, &degree0, &degree1, &zero);
      break;
    }
    }
  }
  for (std::size_t bit = layout.logical_bits; bit != layout.vole_bits; ++bit) {
    zk_hash_128_3_update(hasher, &zero, &tags[bit], &zero);
  }
  for (const auto output : circuit.outputs()) {
    zk_hash_128_3_update(hasher, &zero, &wires[output].tag, &zero);
  }
}

void verifier_constraints(const BinaryCircuit& circuit, std::span<const std::uint8_t> public_inputs,
                          std::span<const std::uint8_t> expected_outputs,
                          const std::vector<bf128_t>& keys, const bf128_t& delta,
                          const bf128_t& delta_squared, zk_hash_128_ctx* hasher) {
  const auto layout = witness_layout(circuit);
  std::vector<VerifierWire> wires(circuit.nodes().size());
  std::size_t private_index = 0, public_index = 0, product_index = 0;
  for (std::size_t i = 0; i != circuit.nodes().size(); ++i) {
    const auto& node = circuit.nodes()[i];
    switch (node.op) {
    case Op::Constant: wires[i].key = node.constant ? delta : bf128_zero(); break;
    case Op::PrivateInput: wires[i].key = keys[private_index++]; break;
    case Op::PublicInput: wires[i].key = public_inputs[public_index++] ? delta : bf128_zero(); break;
    case Op::Xor: wires[i].key = add(wires[node.lhs].key, wires[node.rhs].key); break;
    case Op::And: {
      wires[i].key = keys[layout.private_input_bits + product_index++];
      auto evaluation = multiply(wires[node.lhs].key, wires[node.rhs].key);
      const auto delta_z = multiply(delta, wires[i].key);
      bf128_add_inplace(&evaluation, &delta_z);
      zk_hash_128_update(hasher, &evaluation);
      break;
    }
    }
  }
  for (std::size_t bit = layout.logical_bits; bit != layout.vole_bits; ++bit) {
    auto evaluation = multiply(delta, keys[bit]);
    zk_hash_128_update(hasher, &evaluation);
  }
  for (std::size_t i = 0; i != circuit.outputs().size(); ++i) {
    auto evaluation = multiply(delta, wires[circuit.outputs()[i]].key);
    if (expected_outputs[i]) bf128_add_inplace(&evaluation, &delta_squared);
    zk_hash_128_update(hasher, &evaluation);
  }
}

} // namespace

QuicksilverProof quicksilver_prove(
    const BinaryCircuit& circuit, const PackedWitness& packed,
    std::span<const std::uint8_t> public_inputs,
    std::span<const std::uint8_t> expected_outputs,
    const std::vector<std::uint8_t*>& v_columns, const std::uint8_t* u_after_witness,
    const QuicksilverChallenge& challenge_2) {
  check_statement_sizes(circuit, public_inputs, expected_outputs);
  const auto layout = witness_layout(circuit);
  const auto witness = unpack_witness(circuit, packed);
  auto tags = columns_to_rows(v_columns, layout.vole_bits + 2 * lambda_bits);
  bf128_t u0, u1, v0, v1;
  bf128_sum_poly_bits(&u0, u_after_witness);
  bf128_sum_poly_bits(&u1, u_after_witness + lambda_bytes);
  bf128_sum_poly(&v0, tags.data() + layout.vole_bits);
  bf128_sum_poly(&v1, tags.data() + layout.vole_bits + lambda_bits);
  zk_hash_128_3_ctx hasher;
  zk_hash_128_3_init(&hasher, challenge_2.data());
  prover_constraints(circuit, witness, public_inputs, tags, &hasher);
  bf128_add_inplace(&u0, &v1);
  QuicksilverProof proof;
  zk_hash_128_3_finalize(proof.a0.data(), proof.a1.data(), proof.a2.data(), &hasher, &v0, &u0, &u1);
  return proof;
}

std::array<std::uint8_t, lambda_bytes> quicksilver_verify(
    const BinaryCircuit& circuit, const PackedWitness& masked,
    std::span<const std::uint8_t> public_inputs,
    std::span<const std::uint8_t> expected_outputs,
    const std::vector<std::uint8_t*>& q_columns,
    const std::array<std::uint8_t, lambda_bytes>& delta_bytes,
    const QuicksilverChallenge& challenge_2,
    const QuicksilverProof& proof) {
  check_statement_sizes(circuit, public_inputs, expected_outputs);
  const auto layout = witness_layout(circuit);
  if (masked.size() != layout.vole_bytes) throw std::invalid_argument("wrong masked witness size");
  bf128_t delta;
  bf128_load(&delta, delta_bytes.data());
  const auto delta_squared = multiply(delta, delta);
  auto keys = columns_to_rows(q_columns, layout.vole_bits + 2 * lambda_bits);
  bf128_t q_star, tmp;
  bf128_sum_poly(&q_star, keys.data() + layout.vole_bits);
  bf128_sum_poly(&tmp, keys.data() + layout.vole_bits + lambda_bits);
  tmp = multiply(tmp, delta);
  bf128_add_inplace(&q_star, &tmp);
  for (std::size_t i = 0; i != layout.vole_bits; ++i) {
    if (ptr_get_bit(masked.data(), i)) bf128_add_inplace(&keys[i], &delta);
  }
  zk_hash_128_ctx hasher;
  zk_hash_128_init(&hasher, challenge_2.data());
  verifier_constraints(circuit, public_inputs, expected_outputs, keys, delta, delta_squared, &hasher);
  std::array<std::uint8_t, lambda_bytes> q_tilde{};
  zk_hash_128_finalize(q_tilde.data(), &hasher, &q_star);
  bf128_t result, a2;
  bf128_load(&result, proof.a1.data());
  result = multiply(result, delta);
  bf128_load(&a2, proof.a2.data());
  a2 = multiply(a2, delta_squared);
  bf128_add_inplace(&result, &a2);
  bf128_load(&tmp, q_tilde.data());
  bf128_add_inplace(&result, &tmp);
  std::array<std::uint8_t, lambda_bytes> a0{};
  bf128_store(a0.data(), &result);
  return a0;
}

namespace {

template<SecurityLevel Level> struct FieldOps;

#define VOLE_DEFINE_FIELD_OPS(level_value, bits_value, bytes_value, field_type, field_prefix, hash_prefix) \
  template<> struct FieldOps<level_value> {                                                         \
    using Field = field_type;                                                                        \
    using ProverHash = hash_prefix##_3_ctx;                                                          \
    using VerifierHash = hash_prefix##_ctx;                                                          \
    static constexpr std::size_t bits = bits_value;                                                  \
    static constexpr std::size_t bytes = bytes_value;                                                \
    static Field zero() { return field_prefix##_zero(); }                                            \
    static void load(Field* out, const std::uint8_t* in) { field_prefix##_load(out, in); }           \
    static void store(std::uint8_t* out, const Field* in) { field_prefix##_store(out, in); }         \
    static void add(Field* out, const Field* a, const Field* b) { field_prefix##_add(out, a, b); }    \
    static void add_inplace(Field* out, const Field* a) { field_prefix##_add_inplace(out, a); }       \
    static void mul(Field* out, const Field* a, const Field* b) { field_prefix##_mul(out, a, b); }    \
    static void mul_bit(Field* out, const Field* a, std::uint8_t bit) {                               \
      field_prefix##_mul_bit(out, a, bit);                                                           \
    }                                                                                                \
    static void sum_poly(Field* out, const Field* values) { field_prefix##_sum_poly(out, values); }  \
    static void sum_poly_bits(Field* out, const std::uint8_t* values) {                               \
      field_prefix##_sum_poly_bits(out, values);                                                     \
    }                                                                                                \
    static void prover_init(ProverHash* hash, const std::uint8_t* seed) { hash_prefix##_3_init(hash, seed); } \
    static void prover_update(ProverHash* hash, const Field* a, const Field* b, const Field* c) {     \
      hash_prefix##_3_update(hash, a, b, c);                                                        \
    }                                                                                                \
    static void prover_finalize(std::uint8_t* a0, std::uint8_t* a1, std::uint8_t* a2,                \
                                ProverHash* hash, const Field* x0, const Field* x1,                   \
                                const Field* x2) { hash_prefix##_3_finalize(a0, a1, a2, hash, x0, x1, x2); } \
    static void verifier_init(VerifierHash* hash, const std::uint8_t* seed) { hash_prefix##_init(hash, seed); } \
    static void verifier_update(VerifierHash* hash, const Field* value) { hash_prefix##_update(hash, value); } \
    static void verifier_finalize(std::uint8_t* out, VerifierHash* hash, const Field* x) {           \
      hash_prefix##_finalize(out, hash, x);                                                         \
    }                                                                                                \
  }

VOLE_DEFINE_FIELD_OPS(SecurityLevel::Bits128, 128, 16, bf128_t, bf128, zk_hash_128);
VOLE_DEFINE_FIELD_OPS(SecurityLevel::Bits192, 192, 24, bf192_t, bf192, zk_hash_192);
VOLE_DEFINE_FIELD_OPS(SecurityLevel::Bits256, 256, 32, bf256_t, bf256, zk_hash_256);

#undef VOLE_DEFINE_FIELD_OPS

template<class Ops>
typename Ops::Field field_add(const typename Ops::Field& lhs,
                              const typename Ops::Field& rhs) {
  typename Ops::Field result;
  Ops::add(&result, &lhs, &rhs);
  return result;
}

template<class Ops>
typename Ops::Field field_multiply(const typename Ops::Field& lhs,
                                   const typename Ops::Field& rhs) {
  typename Ops::Field result;
  Ops::mul(&result, &lhs, &rhs);
  return result;
}

template<class Ops>
std::vector<typename Ops::Field> parameterized_columns_to_rows(
    const std::vector<std::uint8_t*>& columns, std::size_t rows_count) {
  if (columns.size() != Ops::bits) throw std::invalid_argument("wrong VOLE column count");
  std::vector<typename Ops::Field> rows(rows_count);
  std::vector<std::uint8_t> packed(64 * Ops::bytes);
  for (std::size_t row_base = 0; row_base < rows_count; row_base += 64) {
    const auto block_rows = std::min<std::size_t>(64, rows_count - row_base);
    transpose_column_block(
        columns, row_base, block_rows,
        std::span<std::uint8_t>(packed.data(), block_rows * Ops::bytes),
        Ops::bytes);
    for (std::size_t row = 0; row != block_rows; ++row)
      Ops::load(&rows[row_base + row], packed.data() + row * Ops::bytes);
  }
  return rows;
}

template<class Ops> struct ParameterizedProverWire {
  bool value = false;
  typename Ops::Field tag = Ops::zero();
};

template<class Ops> struct ParameterizedVerifierWire {
  typename Ops::Field key = Ops::zero();
};

template<class Ops>
void parameterized_prover_constraints(
    const PreparedBinaryCircuit& prepared, const UnpackedWitness& witness,
    std::span<const std::uint8_t> public_inputs,
    const std::vector<typename Ops::Field>& tags,
    typename Ops::ProverHash* hasher) {
  const auto& circuit = prepared.circuit();
  const auto& layout = prepared.layout();
  std::vector<ParameterizedProverWire<Ops>> wires(prepared.traversal().size());
  const auto zero = Ops::zero();
  for (std::size_t i = 0; i != prepared.traversal().size(); ++i) {
    const auto& node = prepared.traversal()[i];
    switch (node.op) {
    case Op::Constant: wires[i].value = node.constant; break;
    case Op::PrivateInput:
      wires[i].value = witness.private_inputs[node.value_index];
      wires[i].tag = tags[node.value_index];
      break;
    case Op::PublicInput: wires[i].value = public_inputs[node.value_index]; break;
    case Op::Xor:
      wires[i].value = wires[node.lhs].value != wires[node.rhs].value;
      wires[i].tag = field_add<Ops>(wires[node.lhs].tag, wires[node.rhs].tag);
      break;
    case Op::And: {
      wires[i].value = witness.multiplication_outputs[node.value_index];
      wires[i].tag = tags[layout.private_input_bits + node.value_index];
      const auto degree0 = field_multiply<Ops>(wires[node.lhs].tag, wires[node.rhs].tag);
      auto degree1 = wires[i].tag;
      typename Ops::Field term;
      Ops::mul_bit(&term, &wires[node.rhs].tag, wires[node.lhs].value);
      Ops::add_inplace(&degree1, &term);
      Ops::mul_bit(&term, &wires[node.lhs].tag, wires[node.rhs].value);
      Ops::add_inplace(&degree1, &term);
      Ops::prover_update(hasher, &degree0, &degree1, &zero);
      break;
    }
    }
  }
  for (std::size_t bit = layout.logical_bits; bit != layout.vole_bits; ++bit)
    Ops::prover_update(hasher, &zero, &tags[bit], &zero);
  for (const auto output : circuit.outputs())
    Ops::prover_update(hasher, &zero, &wires[output].tag, &zero);
}

template<class Ops>
void parameterized_verifier_constraints(
    const PreparedBinaryCircuit& prepared, std::span<const std::uint8_t> public_inputs,
    std::span<const std::uint8_t> expected_outputs,
    const std::vector<typename Ops::Field>& keys,
    const typename Ops::Field& delta, const typename Ops::Field& delta_squared,
    typename Ops::VerifierHash* hasher) {
  const auto& circuit = prepared.circuit();
  const auto& layout = prepared.layout();
  std::vector<ParameterizedVerifierWire<Ops>> wires(prepared.traversal().size());
  for (std::size_t i = 0; i != prepared.traversal().size(); ++i) {
    const auto& node = prepared.traversal()[i];
    switch (node.op) {
    case Op::Constant: wires[i].key = node.constant ? delta : Ops::zero(); break;
    case Op::PrivateInput: wires[i].key = keys[node.value_index]; break;
    case Op::PublicInput:
      wires[i].key = public_inputs[node.value_index] ? delta : Ops::zero();
      break;
    case Op::Xor:
      wires[i].key = field_add<Ops>(wires[node.lhs].key, wires[node.rhs].key);
      break;
    case Op::And: {
      wires[i].key = keys[layout.private_input_bits + node.value_index];
      auto evaluation = field_multiply<Ops>(wires[node.lhs].key, wires[node.rhs].key);
      const auto delta_z = field_multiply<Ops>(delta, wires[i].key);
      Ops::add_inplace(&evaluation, &delta_z);
      Ops::verifier_update(hasher, &evaluation);
      break;
    }
    }
  }
  for (std::size_t bit = layout.logical_bits; bit != layout.vole_bits; ++bit) {
    auto evaluation = field_multiply<Ops>(delta, keys[bit]);
    Ops::verifier_update(hasher, &evaluation);
  }
  for (std::size_t i = 0; i != circuit.outputs().size(); ++i) {
    auto evaluation = field_multiply<Ops>(delta, wires[circuit.outputs()[i]].key);
    if (expected_outputs[i]) Ops::add_inplace(&evaluation, &delta_squared);
    Ops::verifier_update(hasher, &evaluation);
  }
}

template<class Ops>
ParameterizedQuicksilverProof parameterized_quicksilver_prove_impl(
    const PreparedBinaryCircuit& circuit, const PackedWitness& packed,
    std::span<const std::uint8_t> public_inputs,
    std::span<const std::uint8_t> expected_outputs,
    const std::vector<std::uint8_t*>& v_columns,
    const std::uint8_t* u_after_witness,
    std::span<const std::uint8_t> challenge_2) {
  if (challenge_2.size() != 3 * Ops::bytes + 8)
    throw std::invalid_argument("wrong QuickSilver challenge size");
  check_statement_sizes(circuit, public_inputs, expected_outputs);
  const auto& layout = circuit.layout();
  const auto witness = circuit.unpack_witness(packed);
  auto tags = parameterized_columns_to_rows<Ops>(v_columns, layout.vole_bits + 2 * Ops::bits);
  typename Ops::Field u0, u1, v0, v1;
  Ops::sum_poly_bits(&u0, u_after_witness);
  Ops::sum_poly_bits(&u1, u_after_witness + Ops::bytes);
  Ops::sum_poly(&v0, tags.data() + layout.vole_bits);
  Ops::sum_poly(&v1, tags.data() + layout.vole_bits + Ops::bits);
  typename Ops::ProverHash hasher;
  Ops::prover_init(&hasher, challenge_2.data());
  parameterized_prover_constraints<Ops>(circuit, witness, public_inputs, tags, &hasher);
  Ops::add_inplace(&u0, &v1);
  ParameterizedQuicksilverProof proof{
      std::vector<std::uint8_t>(Ops::bytes),
      std::vector<std::uint8_t>(Ops::bytes),
      std::vector<std::uint8_t>(Ops::bytes)};
  Ops::prover_finalize(proof.a0.data(), proof.a1.data(), proof.a2.data(),
                       &hasher, &v0, &u0, &u1);
  return proof;
}

template<class Ops>
std::vector<std::uint8_t> parameterized_quicksilver_verify_impl(
    const PreparedBinaryCircuit& circuit, const PackedWitness& masked,
    std::span<const std::uint8_t> public_inputs,
    std::span<const std::uint8_t> expected_outputs,
    const std::vector<std::uint8_t*>& q_columns,
    std::span<const std::uint8_t> delta_bytes,
    std::span<const std::uint8_t> challenge_2,
    const ParameterizedQuicksilverProof& proof) {
  if (delta_bytes.size() != Ops::bytes || challenge_2.size() != 3 * Ops::bytes + 8 ||
      proof.a0.size() != Ops::bytes || proof.a1.size() != Ops::bytes ||
      proof.a2.size() != Ops::bytes)
    throw std::invalid_argument("wrong parameterized QuickSilver field size");
  check_statement_sizes(circuit, public_inputs, expected_outputs);
  const auto& layout = circuit.layout();
  if (masked.size() != layout.vole_bytes) throw std::invalid_argument("wrong masked witness size");
  typename Ops::Field delta;
  Ops::load(&delta, delta_bytes.data());
  const auto delta_squared = field_multiply<Ops>(delta, delta);
  auto keys = parameterized_columns_to_rows<Ops>(q_columns, layout.vole_bits + 2 * Ops::bits);
  typename Ops::Field q_star, tmp;
  Ops::sum_poly(&q_star, keys.data() + layout.vole_bits);
  Ops::sum_poly(&tmp, keys.data() + layout.vole_bits + Ops::bits);
  tmp = field_multiply<Ops>(tmp, delta);
  Ops::add_inplace(&q_star, &tmp);
  for (std::size_t i = 0; i != layout.vole_bits; ++i) {
    /* The masked witness is public proof data at verification time. Skipping
     * zero bits avoids constructing and XORing an all-zero field element. */
    if (ptr_get_bit(masked.data(), i)) Ops::add_inplace(&keys[i], &delta);
  }
  typename Ops::VerifierHash hasher;
  Ops::verifier_init(&hasher, challenge_2.data());
  parameterized_verifier_constraints<Ops>(circuit, public_inputs, expected_outputs,
                                           keys, delta, delta_squared, &hasher);
  std::vector<std::uint8_t> q_tilde(Ops::bytes);
  Ops::verifier_finalize(q_tilde.data(), &hasher, &q_star);
  typename Ops::Field result, a2;
  Ops::load(&result, proof.a1.data());
  result = field_multiply<Ops>(result, delta);
  Ops::load(&a2, proof.a2.data());
  a2 = field_multiply<Ops>(a2, delta_squared);
  Ops::add_inplace(&result, &a2);
  Ops::load(&tmp, q_tilde.data());
  Ops::add_inplace(&result, &tmp);
  std::vector<std::uint8_t> a0(Ops::bytes);
  Ops::store(a0.data(), &result);
  return a0;
}

} // namespace

ParameterizedQuicksilverProof quicksilver_prove(
    SecurityLevel security, const PreparedBinaryCircuit& circuit,
    const PackedWitness& witness, std::span<const std::uint8_t> public_inputs,
    std::span<const std::uint8_t> expected_outputs,
    const std::vector<std::uint8_t*>& v_columns,
    const std::uint8_t* u_after_witness,
    std::span<const std::uint8_t> challenge_2) {
  switch (security) {
  case SecurityLevel::Bits128:
    return parameterized_quicksilver_prove_impl<FieldOps<SecurityLevel::Bits128>>(
        circuit, witness, public_inputs, expected_outputs, v_columns,
        u_after_witness, challenge_2);
  case SecurityLevel::Bits192:
    return parameterized_quicksilver_prove_impl<FieldOps<SecurityLevel::Bits192>>(
        circuit, witness, public_inputs, expected_outputs, v_columns,
        u_after_witness, challenge_2);
  case SecurityLevel::Bits256:
    return parameterized_quicksilver_prove_impl<FieldOps<SecurityLevel::Bits256>>(
        circuit, witness, public_inputs, expected_outputs, v_columns,
        u_after_witness, challenge_2);
  }
  throw std::invalid_argument("unsupported QuickSilver security level");
}

ParameterizedQuicksilverProof quicksilver_prove(
    SecurityLevel security, const BinaryCircuit& circuit,
    const PackedWitness& witness, std::span<const std::uint8_t> public_inputs,
    std::span<const std::uint8_t> expected_outputs,
    const std::vector<std::uint8_t*>& v_columns,
    const std::uint8_t* u_after_witness,
    std::span<const std::uint8_t> challenge_2) {
  const PreparedBinaryCircuit prepared(circuit);
  return quicksilver_prove(security, prepared, witness, public_inputs,
                           expected_outputs, v_columns, u_after_witness,
                           challenge_2);
}

std::vector<std::uint8_t> quicksilver_verify(
    SecurityLevel security, const PreparedBinaryCircuit& circuit,
    const PackedWitness& masked_witness,
    std::span<const std::uint8_t> public_inputs,
    std::span<const std::uint8_t> expected_outputs,
    const std::vector<std::uint8_t*>& q_columns,
    std::span<const std::uint8_t> delta,
    std::span<const std::uint8_t> challenge_2,
    const ParameterizedQuicksilverProof& proof) {
  switch (security) {
  case SecurityLevel::Bits128:
    return parameterized_quicksilver_verify_impl<FieldOps<SecurityLevel::Bits128>>(
        circuit, masked_witness, public_inputs, expected_outputs, q_columns,
        delta, challenge_2, proof);
  case SecurityLevel::Bits192:
    return parameterized_quicksilver_verify_impl<FieldOps<SecurityLevel::Bits192>>(
        circuit, masked_witness, public_inputs, expected_outputs, q_columns,
        delta, challenge_2, proof);
  case SecurityLevel::Bits256:
    return parameterized_quicksilver_verify_impl<FieldOps<SecurityLevel::Bits256>>(
        circuit, masked_witness, public_inputs, expected_outputs, q_columns,
        delta, challenge_2, proof);
  }
  throw std::invalid_argument("unsupported QuickSilver security level");
}

std::vector<std::uint8_t> quicksilver_verify(
    SecurityLevel security, const BinaryCircuit& circuit,
    const PackedWitness& masked_witness,
    std::span<const std::uint8_t> public_inputs,
    std::span<const std::uint8_t> expected_outputs,
    const std::vector<std::uint8_t*>& q_columns,
    std::span<const std::uint8_t> delta,
    std::span<const std::uint8_t> challenge_2,
    const ParameterizedQuicksilverProof& proof) {
  const PreparedBinaryCircuit prepared(circuit);
  return quicksilver_verify(security, prepared, masked_witness, public_inputs,
                            expected_outputs, q_columns, delta, challenge_2,
                            proof);
}

} // namespace vole_backend
