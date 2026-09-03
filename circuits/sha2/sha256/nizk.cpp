/* SPDX-License-Identifier: MIT */

#include "nizk.hpp"

#include "faest_quicksilver.hpp"
#include "faest_vole.hpp"
#include "witness.hpp"

extern "C" {
#include "random_oracle.h"
#include "universal_hashing.h"
#include "utils.h"
}

#include <algorithm>
#include <cstring>
#include <limits>
#include <stdexcept>

namespace vole_sha256 {

using namespace vole_backend;
namespace {

constexpr std::array<std::uint8_t, 8> proof_magic = {'V', 'S', 'H', '2', '5', '6', 2, 0};
constexpr char protocol_domain[] = "VOLE-SHA256-GENERIC-NIZK-v2";
constexpr std::size_t utilde_bytes = lambda_bytes + 2;
constexpr std::size_t challenge_1_bytes = 5 * lambda_bytes + 8;

struct ProofFields {
  std::vector<std::uint8_t> corrections;
  std::array<std::uint8_t, utilde_bytes> u_tilde{};
  PackedWitness d{};
  std::array<std::uint8_t, lambda_bytes> a1{};
  std::array<std::uint8_t, lambda_bytes> a2{};
  std::vector<std::uint8_t> opening;
  std::array<std::uint8_t, lambda_bytes> challenge_3{};
  std::array<std::uint8_t, 16> iv_pre{};
  std::uint32_t counter = 0;
};

void update_domain(H2_context_t* context) {
  H2_update(context, reinterpret_cast<const std::uint8_t*>(protocol_domain),
            sizeof(protocol_domain) - 1);
}

std::array<std::uint8_t, 2 * lambda_bytes> hash_statement(
    std::size_t message_length, const faest::sha256_circuit::Digest& digest,
    std::span<const std::uint8_t> context) {
  if (context.size() > std::numeric_limits<std::uint32_t>::max()) {
    throw std::invalid_argument("context is too long");
  }
  H2_context_t hash;
  H2_init(&hash, lambda_bits);
  update_domain(&hash);
  H2_update_u32_le(&hash, static_cast<std::uint32_t>(faest::sha256_circuit::max_message_bytes));
  H2_update_u32_le(&hash, static_cast<std::uint32_t>(message_length));
  H2_update(&hash, digest.data(), digest.size());
  H2_update_u32_le(&hash, static_cast<std::uint32_t>(context.size()));
  if (!context.empty()) H2_update(&hash, context.data(), context.size());
  std::array<std::uint8_t, 2 * lambda_bytes> mu{};
  H2_0_final(&hash, mu.data(), mu.size());
  return mu;
}

void derive_commitment_seed(const PackedWitness& witness,
                            const std::array<std::uint8_t, 2 * lambda_bytes>& mu,
                            const ProverRandomness& randomness,
                            std::array<std::uint8_t, lambda_bytes>& root_key,
                            std::array<std::uint8_t, 16>& iv_pre,
                            std::array<std::uint8_t, 16>& iv) {
  H3_context_t hash;
  H3_init(&hash, lambda_bits);
  H3_update(&hash, reinterpret_cast<const std::uint8_t*>(protocol_domain),
            sizeof(protocol_domain) - 1);
  H3_update(&hash, witness.data(), witness.size());
  H3_update(&hash, mu.data(), mu.size());
  H3_update(&hash, randomness.data(), randomness.size());
  H3_final(&hash, root_key.data(), root_key.size(), iv_pre.data());
  H4(iv.data(), iv_pre.data(), lambda_bits);
}

std::array<std::uint8_t, challenge_1_bytes> challenge_1(
    const std::array<std::uint8_t, 2 * lambda_bytes>& mu,
    const std::array<std::uint8_t, 2 * lambda_bytes>& commitment_hash,
    const std::vector<std::uint8_t>& corrections, const std::array<std::uint8_t, 16>& iv) {
  H2_context_t hash;
  H2_init(&hash, lambda_bits);
  H2_update(&hash, mu.data(), mu.size());
  H2_update(&hash, commitment_hash.data(), commitment_hash.size());
  H2_update(&hash, corrections.data(), corrections.size());
  H2_update(&hash, iv.data(), iv.size());
  std::array<std::uint8_t, challenge_1_bytes> result{};
  H2_1_final(&hash, result.data(), result.size());
  return result;
}

H2_context_t challenge_2_prefix(const std::array<std::uint8_t, challenge_1_bytes>& chall_1,
                                const std::array<std::uint8_t, utilde_bytes>& u_tilde) {
  H2_context_t hash;
  H2_init(&hash, lambda_bits);
  H2_update(&hash, chall_1.data(), chall_1.size());
  H2_update(&hash, u_tilde.data(), u_tilde.size());
  return hash;
}

QuicksilverChallenge finish_challenge_2(H2_context_t* hash, const PackedWitness& d) {
  H2_update(hash, d.data(), d.size());
  QuicksilverChallenge result{};
  H2_2_final(hash, result.data(), result.size());
  return result;
}

H2_context_t challenge_3_prefix(const QuicksilverChallenge& chall_2,
                                const std::array<std::uint8_t, lambda_bytes>& a0,
                                const std::array<std::uint8_t, lambda_bytes>& a1,
                                const std::array<std::uint8_t, lambda_bytes>& a2) {
  H2_context_t hash;
  H2_init(&hash, lambda_bits);
  H2_update(&hash, chall_2.data(), chall_2.size());
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
  std::array<std::uint8_t, lambda_bytes> result{};
  H2_3_final(&hash, result.data(), result.size());
  return result;
}

bool grinding_condition(const std::array<std::uint8_t, lambda_bytes>& challenge) {
  const auto parameters = faest_vole_parameters();
  for (std::size_t bit = lambda_bits - parameters.w_grind; bit != lambda_bits; ++bit) {
    if (ptr_get_bit(challenge.data(), bit)) return false;
  }
  return true;
}

std::vector<std::uint8_t> serialize(const faest::sha256_circuit::Circuit& circuit,
                                    const ProofFields& fields) {
  const auto expected_size = serialized_proof_bytes(circuit);
  std::vector<std::uint8_t> output;
  output.reserve(expected_size);
  const auto append = [&output](const auto& value) {
    output.insert(output.end(), value.begin(), value.end());
  };
  append(proof_magic);
  append(fields.corrections);
  append(fields.u_tilde);
  append(fields.d);
  append(fields.a1);
  append(fields.a2);
  append(fields.opening);
  append(fields.challenge_3);
  append(fields.iv_pre);
  output.push_back(static_cast<std::uint8_t>(fields.counter));
  output.push_back(static_cast<std::uint8_t>(fields.counter >> 8));
  output.push_back(static_cast<std::uint8_t>(fields.counter >> 16));
  output.push_back(static_cast<std::uint8_t>(fields.counter >> 24));
  if (output.size() != expected_size) {
    throw std::logic_error("internal proof-size mismatch");
  }
  return output;
}

bool deserialize(const faest::sha256_circuit::Circuit& circuit,
                 std::span<const std::uint8_t> input, ProofFields& fields) {
  const auto witness = witness_layout(circuit);
  const auto vole = vole_layout(witness.vole_bits);
  if (input.size() != serialized_proof_bytes(circuit) ||
      !std::equal(proof_magic.begin(), proof_magic.end(), input.begin())) {
    return false;
  }
  std::size_t offset = proof_magic.size();
  const auto take = [&input, &offset](auto& value) {
    std::copy_n(input.begin() + static_cast<std::ptrdiff_t>(offset), value.size(), value.begin());
    offset += value.size();
  };
  fields.corrections.resize(vole.correction_bytes);
  fields.d.resize(witness.vole_bytes);
  fields.opening.resize(vole_opening_bytes);
  take(fields.corrections);
  take(fields.u_tilde);
  take(fields.d);
  take(fields.a1);
  take(fields.a2);
  take(fields.opening);
  take(fields.challenge_3);
  take(fields.iv_pre);
  fields.counter = static_cast<std::uint32_t>(input[offset]) |
                   (static_cast<std::uint32_t>(input[offset + 1]) << 8) |
                   (static_cast<std::uint32_t>(input[offset + 2]) << 16) |
                   (static_cast<std::uint32_t>(input[offset + 3]) << 24);
  return offset + 4 == input.size();
}

} // namespace

std::size_t serialized_proof_bytes(const faest::sha256_circuit::Circuit& circuit) {
  const auto witness = witness_layout(circuit);
  const auto vole = vole_layout(witness.vole_bits);
  return proof_magic.size() + vole.correction_bytes + utilde_bytes + witness.vole_bytes +
         2 * lambda_bytes + vole_opening_bytes + lambda_bytes + 16 + 4;
}

std::vector<std::uint8_t> prove(
    const faest::sha256_circuit::Circuit& circuit,
    const faest::sha256_circuit::Message& secret_message,
    const faest::sha256_circuit::Digest& public_digest, std::span<const std::uint8_t> context,
    const ProverRandomness& randomness) {
  if (!circuit.verify_statement(secret_message, public_digest)) {
    throw std::invalid_argument("secret message does not match public digest");
  }

  const auto witness = build_witness(circuit, secret_message);
  const auto layout = witness_layout(circuit);
  const auto mu = hash_statement(circuit.message_length(), public_digest, context);
  std::array<std::uint8_t, lambda_bytes> root_key{};
  std::array<std::uint8_t, 16> iv_pre{};
  std::array<std::uint8_t, 16> iv{};
  derive_commitment_seed(witness, mu, randomness, root_key, iv_pre, iv);

  FaestVoleCommitment commitment(root_key, iv, layout.vole_bits);
  auto v = commitment.v_columns();
  const auto chall_1 = challenge_1(mu, commitment.commitment_hash(), commitment.corrections(), iv);

  ProofFields fields;
  fields.corrections = commitment.corrections();
  fields.iv_pre = iv_pre;
  vole_hash(fields.u_tilde.data(), chall_1.data(), commitment.u().data(), layout.vole_bits,
            lambda_bits);

  H2_context_t chall_2_hash = challenge_2_prefix(chall_1, fields.u_tilde);
  std::array<std::uint8_t, utilde_bytes> v_tilde{};
  for (std::size_t column = 0; column != lambda_bits; ++column) {
    vole_hash(v_tilde.data(), chall_1.data(), v[column], layout.vole_bits, lambda_bits);
    H2_update(&chall_2_hash, v_tilde.data(), v_tilde.size());
  }

  fields.d = mask_witness(witness, commitment.u());
  const auto chall_2 = finish_challenge_2(&chall_2_hash, fields.d);
  const auto qs_proof = sha256_quicksilver_prove(
      circuit, witness, v, commitment.u().data() + layout.vole_bytes, public_digest, chall_2);
  fields.a1 = qs_proof.a1;
  fields.a2 = qs_proof.a2;

  H2_context_t chall_3_hash = challenge_3_prefix(chall_2, qs_proof.a0, fields.a1, fields.a2);
  bool opened = false;
  for (std::uint32_t counter = 0;; ++counter) {
    fields.challenge_3 = finish_challenge_3(chall_3_hash, counter);
    if (!grinding_condition(fields.challenge_3)) continue;
    if (!commitment.open(fields.challenge_3, fields.opening)) continue;
    fields.counter = counter;
    opened = true;
    break;
  }
  hash_clear(&chall_3_hash);
  if (!opened) throw std::runtime_error("Fiat-Shamir challenge search failed");
  return serialize(circuit, fields);
}

bool verify(const faest::sha256_circuit::Circuit& circuit,
            const faest::sha256_circuit::Digest& public_digest,
            std::span<const std::uint8_t> context,
            std::span<const std::uint8_t> serialized_proof) {
  ProofFields fields;
  if (!deserialize(circuit, serialized_proof, fields) || !grinding_condition(fields.challenge_3)) return false;

  std::array<std::uint8_t, 16> iv{};
  H4(iv.data(), fields.iv_pre.data(), lambda_bits);
  ReconstructedVole reconstructed;
  const auto layout = witness_layout(circuit);
  if (!reconstruct_vole(iv, fields.challenge_3, fields.opening, fields.corrections,
                        layout.vole_bits,
                        reconstructed)) {
    return false;
  }

  const auto mu = hash_statement(circuit.message_length(), public_digest, context);
  const auto chall_1 = challenge_1(mu, reconstructed.commitment_hash, fields.corrections, iv);
  H2_context_t chall_2_hash = challenge_2_prefix(chall_1, fields.u_tilde);
  auto q = reconstructed.columns();
  std::array<std::uint8_t, utilde_bytes> q_tilde{};
  for (std::size_t column = 0; column != lambda_bits; ++column) {
    vole_hash(q_tilde.data(), chall_1.data(), q[column], layout.vole_bits, lambda_bits);
    if (ptr_get_bit(fields.challenge_3.data(), column)) {
      for (std::size_t i = 0; i != q_tilde.size(); ++i) q_tilde[i] ^= fields.u_tilde[i];
    }
    H2_update(&chall_2_hash, q_tilde.data(), q_tilde.size());
  }
  const auto chall_2 = finish_challenge_2(&chall_2_hash, fields.d);

  QuicksilverProof qs_proof;
  qs_proof.a1 = fields.a1;
  qs_proof.a2 = fields.a2;
  qs_proof.a0 = sha256_quicksilver_verify(circuit, fields.d, q, fields.challenge_3, public_digest,
                                          chall_2, qs_proof);

  H2_context_t chall_3_hash = challenge_3_prefix(chall_2, qs_proof.a0, fields.a1, fields.a2);
  const auto expected_challenge = finish_challenge_3(chall_3_hash, fields.counter);
  return expected_challenge == fields.challenge_3;
}

} // namespace vole_sha256
