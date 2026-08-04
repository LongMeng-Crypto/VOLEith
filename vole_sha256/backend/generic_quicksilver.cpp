/* SPDX-License-Identifier: MIT */

#include "generic_quicksilver.hpp"

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
  for (std::size_t row = 0; row != rows.size(); ++row) {
    std::array<std::uint8_t, lambda_bytes> buffer{};
    for (std::size_t column = 0; column != lambda_bits; ++column) {
      if (ptr_get_bit(columns[column], row)) ptr_set_bit(buffer.data(), column, 1);
    }
    bf128_load(&rows[row], buffer.data());
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

} // namespace vole_backend
