/* SPDX-License-Identifier: MIT */

#include "faest_quicksilver.hpp"

extern "C" {
#include "universal_hashing.h"
#include "utils.h"
}

#include <cassert>
#include <stdexcept>

namespace vole_sha256 {
namespace {

std::vector<bf128_t> columns_to_rows(const std::vector<std::uint8_t*>& columns,
                                    std::size_t committed_tag_rows) {
  assert(columns.size() == lambda_bits);
  std::vector<bf128_t> rows(committed_tag_rows);
  for (std::size_t row = 0; row != rows.size(); ++row) {
    std::array<std::uint8_t, lambda_bytes> buffer{};
    for (std::size_t column = 0; column != lambda_bits; ++column) {
      if (ptr_get_bit(columns[column], row)) ptr_set_bit(buffer.data(), column, 1);
    }
    bf128_load(&rows[row], buffer.data());
  }
  return rows;
}

bool digest_bit(const faest::sha256_circuit::Digest& digest, std::size_t bit) {
  return ((digest[bit / 8] >> (bit % 8)) & 1U) != 0;
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

struct ProverWire {
  bool value = false;
  bf128_t tag = bf128_zero();
};

struct VerifierWire {
  bf128_t key = bf128_zero();
};

void hash_prover_constraints(const faest::sha256_circuit::Circuit& circuit,
                             const UnpackedWitness& witness, const std::vector<bf128_t>& witness_tags,
                             const faest::sha256_circuit::Digest& digest,
                             zk_hash_128_3_ctx* hasher) {
  std::vector<ProverWire> wires(circuit.nodes().size());
  std::size_t input_index = 0;
  std::size_t multiplication_index = 0;
  const bf128_t zero = bf128_zero();

  for (std::size_t i = 0; i != circuit.nodes().size(); ++i) {
    const auto& node = circuit.nodes()[i];
    switch (node.op) {
    case faest::sha256_circuit::Op::Constant:
      wires[i].value = node.constant;
      break;
    case faest::sha256_circuit::Op::PrivateInput: {
      const auto byte = input_index / 8;
      const auto bit = input_index % 8;
      wires[i].value = ((witness.secret_message[byte] >> bit) & 1U) != 0;
      wires[i].tag = witness_tags[input_index];
      ++input_index;
      break;
    }
    case faest::sha256_circuit::Op::PublicInput:
      throw std::logic_error("SHA-256 adapter does not use BinaryCircuit public-input nodes");
    case faest::sha256_circuit::Op::Xor:
      wires[i].value = wires[node.lhs].value != wires[node.rhs].value;
      wires[i].tag = add(wires[node.lhs].tag, wires[node.rhs].tag);
      break;
    case faest::sha256_circuit::Op::And: {
      wires[i].value = witness.multiplication_outputs[multiplication_index] != 0;
      wires[i].tag = witness_tags[circuit.secret_input_bits() + multiplication_index];

      const auto& x = wires[node.lhs];
      const auto& y = wires[node.rhs];
      const auto& z = wires[i];
      const bf128_t degree0 = multiply(x.tag, y.tag);
      bf128_t degree1 = z.tag;
      if (x.value) bf128_add_inplace(&degree1, &y.tag);
      if (y.value) bf128_add_inplace(&degree1, &x.tag);
      // The omitted degree-2 coefficient is x*y+z.
      zk_hash_128_3_update(hasher, &degree0, &degree1, &zero);
      ++multiplication_index;
      break;
    }
    }
  }

  assert(input_index == circuit.secret_input_bits());
  assert(multiplication_index == circuit.statistics().multiplication_gates);

  const auto layout = witness_layout(circuit);
  for (std::size_t bit = layout.logical_bits; bit != layout.vole_bits; ++bit) {
    zk_hash_128_3_update(hasher, &zero, &witness_tags[bit], &zero);
  }

  // Lift output+public_bit=0 by X: coefficients (0, tag, residual).
  for (std::size_t bit = 0; bit != circuit.output_wires().size(); ++bit) {
    const auto& output = wires[circuit.output_wires()[bit]];
    (void)digest; // residual is deliberately omitted from the proof.
    zk_hash_128_3_update(hasher, &zero, &output.tag, &zero);
  }

}

void hash_verifier_constraints(const faest::sha256_circuit::Circuit& circuit,
                               const std::vector<bf128_t>& witness_keys, const bf128_t& delta,
                               const bf128_t& delta_squared,
                               const faest::sha256_circuit::Digest& digest,
                               zk_hash_128_ctx* hasher) {
  std::vector<VerifierWire> wires(circuit.nodes().size());
  std::size_t input_index = 0;
  std::size_t multiplication_index = 0;

  for (std::size_t i = 0; i != circuit.nodes().size(); ++i) {
    const auto& node = circuit.nodes()[i];
    switch (node.op) {
    case faest::sha256_circuit::Op::Constant:
      wires[i].key = node.constant ? delta : bf128_zero();
      break;
    case faest::sha256_circuit::Op::PrivateInput:
      wires[i].key = witness_keys[input_index++];
      break;
    case faest::sha256_circuit::Op::PublicInput:
      throw std::logic_error("SHA-256 adapter does not use BinaryCircuit public-input nodes");
    case faest::sha256_circuit::Op::Xor:
      wires[i].key = add(wires[node.lhs].key, wires[node.rhs].key);
      break;
    case faest::sha256_circuit::Op::And: {
      wires[i].key = witness_keys[circuit.secret_input_bits() + multiplication_index];
      bf128_t evaluation = multiply(wires[node.lhs].key, wires[node.rhs].key);
      bf128_t delta_z = multiply(delta, wires[i].key);
      bf128_add_inplace(&evaluation, &delta_z);
      zk_hash_128_update(hasher, &evaluation);
      ++multiplication_index;
      break;
    }
    }
  }

  const auto layout = witness_layout(circuit);
  for (std::size_t bit = layout.logical_bits; bit != layout.vole_bits; ++bit) {
    auto evaluation = multiply(delta, witness_keys[bit]);
    zk_hash_128_update(hasher, &evaluation);
  }

  for (std::size_t bit = 0; bit != circuit.output_wires().size(); ++bit) {
    bf128_t evaluation = multiply(delta, wires[circuit.output_wires()[bit]].key);
    if (digest_bit(digest, bit)) bf128_add_inplace(&evaluation, &delta_squared);
    zk_hash_128_update(hasher, &evaluation);
  }
}

} // namespace

QuicksilverProof sha256_quicksilver_prove(
    const faest::sha256_circuit::Circuit& circuit, const PackedWitness& packed_witness,
    const std::vector<std::uint8_t*>& v_columns, const std::uint8_t* u_after_witness,
    const faest::sha256_circuit::Digest& public_digest,
    const QuicksilverChallenge& challenge_2) {
  const auto layout = witness_layout(circuit);
  const auto witness = unpack_witness(circuit, packed_witness);
  auto witness_tags = columns_to_rows(v_columns, layout.vole_bits + 2 * lambda_bits);

  bf128_t u_star_0;
  bf128_sum_poly_bits(&u_star_0, u_after_witness);
  bf128_t u_star_1;
  bf128_sum_poly_bits(&u_star_1, u_after_witness + lambda_bytes);
  bf128_t v_star_0;
  bf128_sum_poly(&v_star_0, witness_tags.data() + layout.vole_bits);
  bf128_t v_star_1;
  bf128_sum_poly(&v_star_1, witness_tags.data() + layout.vole_bits + lambda_bits);

  zk_hash_128_3_ctx hasher;
  zk_hash_128_3_init(&hasher, challenge_2.data());
  hash_prover_constraints(circuit, witness, witness_tags, public_digest, &hasher);

  bf128_add_inplace(&u_star_0, &v_star_1);
  QuicksilverProof proof;
  zk_hash_128_3_finalize(proof.a0.data(), proof.a1.data(), proof.a2.data(), &hasher, &v_star_0,
                         &u_star_0, &u_star_1);
  return proof;
}

std::array<std::uint8_t, lambda_bytes> sha256_quicksilver_verify(
    const faest::sha256_circuit::Circuit& circuit, const PackedWitness& masked_witness_d,
    const std::vector<std::uint8_t*>& q_columns,
    const std::array<std::uint8_t, lambda_bytes>& delta_bytes,
    const faest::sha256_circuit::Digest& public_digest,
    const QuicksilverChallenge& challenge_2, const QuicksilverProof& proof) {
  bf128_t delta;
  bf128_load(&delta, delta_bytes.data());
  const bf128_t delta_squared = multiply(delta, delta);
  const auto layout = witness_layout(circuit);
  auto witness_keys = columns_to_rows(q_columns, layout.vole_bits + 2 * lambda_bits);

  bf128_t q_star;
  bf128_sum_poly(&q_star, witness_keys.data() + layout.vole_bits);
  bf128_t tmp;
  bf128_sum_poly(&tmp, witness_keys.data() + layout.vole_bits + lambda_bits);
  tmp = multiply(tmp, delta);
  bf128_add_inplace(&q_star, &tmp);

  for (std::size_t i = 0; i != layout.vole_bits; ++i) {
    if (ptr_get_bit(masked_witness_d.data(), i)) bf128_add_inplace(&witness_keys[i], &delta);
  }

  zk_hash_128_ctx hasher;
  zk_hash_128_init(&hasher, challenge_2.data());
  hash_verifier_constraints(circuit, witness_keys, delta, delta_squared, public_digest, &hasher);

  std::array<std::uint8_t, lambda_bytes> q_tilde{};
  zk_hash_128_finalize(q_tilde.data(), &hasher, &q_star);

  bf128_t result;
  bf128_load(&result, proof.a1.data());
  result = multiply(result, delta);
  bf128_t a2;
  bf128_load(&a2, proof.a2.data());
  a2 = multiply(a2, delta_squared);
  bf128_add_inplace(&result, &a2);
  bf128_load(&tmp, q_tilde.data());
  bf128_add_inplace(&result, &tmp);

  std::array<std::uint8_t, lambda_bytes> a0{};
  bf128_store(a0.data(), &result);
  return a0;
}

} // namespace vole_sha256
