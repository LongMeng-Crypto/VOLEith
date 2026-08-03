/* SPDX-License-Identifier: MIT */

#include "faest_vole.hpp"

extern "C" {
#include "utils.h"
#include "vole.h"
}

#include <algorithm>
#include <stdexcept>

namespace vole_sha256 {
namespace {

std::vector<std::uint8_t*> make_columns(std::vector<std::uint8_t>& storage) {
  std::vector<std::uint8_t*> columns(lambda_bits);
  for (std::size_t i = 0; i != lambda_bits; ++i) {
    columns[i] = storage.data() + i * vole_ell_hat_bytes;
  }
  return columns;
}

std::array<std::uint8_t, lambda_bytes> candidate_challenge(std::uint64_t counter) {
  std::array<std::uint8_t, lambda_bytes> challenge{};
  std::uint64_t state = counter + 0x9e3779b97f4a7c15ULL;
  for (auto& byte : challenge) {
    state ^= state >> 12;
    state ^= state << 25;
    state ^= state >> 27;
    state *= 0x2545f4914f6cdd1dULL;
    byte = static_cast<std::uint8_t>(state >> 56);
  }
  return challenge;
}

} // namespace

faest_paramset_t sha256_vole_parameters() {
  auto parameters = *faest_get_paramset(FAEST_128S);
  parameters.l = static_cast<std::uint16_t>(vole_witness_bits);
  return parameters;
}

std::vector<std::uint8_t*> ReconstructedVole::columns() { return make_columns(q_storage); }

FaestVoleCommitment::FaestVoleCommitment(
    const std::array<std::uint8_t, lambda_bytes>& root_key,
    const std::array<std::uint8_t, 16>& iv)
    : iv_(iv) {
  parameters_ = sha256_vole_parameters();

  corrections_.resize((parameters_.tau - 1) * vole_ell_hat_bytes);
  u_.resize(vole_ell_hat_bytes);
  v_storage_.resize(lambda_bits * vole_ell_hat_bytes);
  auto columns = v_columns();
  vole_commit(root_key.data(), iv_.data(), vole_ell_hat_bits, &parameters_, &bavc_,
              corrections_.data(), u_.data(), columns.data());
  bavc_live_ = true;
}

FaestVoleCommitment::~FaestVoleCommitment() {
  if (bavc_live_) bavc_clear(&bavc_);
}

std::vector<std::uint8_t*> FaestVoleCommitment::v_columns() {
  return make_columns(v_storage_);
}

std::array<std::uint8_t, 2 * lambda_bytes> FaestVoleCommitment::commitment_hash() const {
  std::array<std::uint8_t, 2 * lambda_bytes> result{};
  std::copy_n(bavc_.h, result.size(), result.begin());
  return result;
}

bool FaestVoleCommitment::open(
    const std::array<std::uint8_t, lambda_bytes>& challenge,
    std::vector<std::uint8_t>& decomposition) {
  std::vector<std::uint16_t> decoded(parameters_.tau);
  if (!decode_all_chall_3(decoded.data(), challenge.data(), &parameters_)) return false;
  decomposition.resize(vole_opening_bytes);
  return bavc_open(decomposition.data(), &bavc_, decoded.data(), &parameters_);
}

ReconstructedVole FaestVoleCommitment::open_and_reconstruct() {
  std::vector<std::uint8_t> decomposition;

  for (std::uint64_t counter = 1; counter != 100000; ++counter) {
    auto challenge = candidate_challenge(counter);
    for (std::size_t bit = lambda_bits - parameters_.w_grind; bit != lambda_bits; ++bit) {
      ptr_set_bit(challenge.data(), bit, 0);
    }
    if (!open(challenge, decomposition)) continue;

    ReconstructedVole reconstructed;
    reconstructed.challenge = challenge;
    std::copy_n(bavc_.h, reconstructed.commitment_hash.size(),
                reconstructed.commitment_hash.begin());
    reconstructed.q_storage.resize(lambda_bits * vole_ell_hat_bytes);
    auto q_columns = reconstructed.columns();
    std::array<std::uint8_t, 2 * lambda_bytes> reconstructed_hash{};
    if (!vole_reconstruct(reconstructed_hash.data(), q_columns.data(), iv_.data(), challenge.data(),
                          decomposition.data(), corrections_.data(), vole_ell_hat_bits,
                          &parameters_)) {
      continue;
    }
    if (reconstructed_hash != reconstructed.commitment_hash) continue;
    return reconstructed;
  }
  throw std::runtime_error("could not find an openable FAEST VOLE challenge");
}

bool reconstruct_vole(const std::array<std::uint8_t, 16>& iv,
                      const std::array<std::uint8_t, lambda_bytes>& challenge,
                      const std::vector<std::uint8_t>& decomposition,
                      const std::vector<std::uint8_t>& corrections,
                      ReconstructedVole& reconstructed) {
  if (decomposition.size() != vole_opening_bytes ||
      corrections.size() != vole_correction_bytes) {
    return false;
  }
  auto parameters = sha256_vole_parameters();
  reconstructed.challenge = challenge;
  reconstructed.q_storage.assign(lambda_bits * vole_ell_hat_bytes, 0);
  auto q = reconstructed.columns();
  return vole_reconstruct(reconstructed.commitment_hash.data(), q.data(), iv.data(),
                          challenge.data(), decomposition.data(), corrections.data(),
                          vole_ell_hat_bits, &parameters);
}

PackedWitness mask_witness(const PackedWitness& witness, const std::vector<std::uint8_t>& u) {
  if (u.size() < witness.size()) throw std::invalid_argument("VOLE u is shorter than witness");
  PackedWitness masked{};
  for (std::size_t i = 0; i != masked.size(); ++i) masked[i] = witness[i] ^ u[i];
  return masked;
}

bool check_vole_correlation(FaestVoleCommitment& commitment,
                            ReconstructedVole& reconstructed) {
  auto v = commitment.v_columns();
  auto q = reconstructed.columns();
  for (std::size_t column = 0; column != lambda_bits; ++column) {
    const bool delta = ptr_get_bit(reconstructed.challenge.data(), column) != 0;
    for (std::size_t byte = 0; byte != vole_ell_hat_bytes; ++byte) {
      const auto expected = static_cast<std::uint8_t>(v[column][byte] ^
                                                      (delta ? commitment.u()[byte] : 0));
      if (q[column][byte] != expected) return false;
    }
  }
  return true;
}

} // namespace vole_sha256
