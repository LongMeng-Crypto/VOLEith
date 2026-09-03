/* SPDX-License-Identifier: MIT */

#include "faest_vole.hpp"

extern "C" {
#include "utils.h"
#include "vole.h"
}

#include <algorithm>
#include <stdexcept>

namespace vole_backend {
namespace {

std::vector<std::uint8_t*> make_columns(std::vector<std::uint8_t>& storage,
                                       std::size_t ell_hat_bytes,
                                       std::size_t column_count = lambda_bits) {
  std::vector<std::uint8_t*> columns(column_count);
  for (std::size_t i = 0; i != column_count; ++i) {
    columns[i] = storage.data() + i * ell_hat_bytes;
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

VoleLayout vole_layout(std::size_t witness_bits) {
  const auto ell_hat_bits = witness_bits + vole_extra_bits;
  const auto ell_hat_bytes = (ell_hat_bits + 7) / 8;
  return {witness_bits, ell_hat_bits, ell_hat_bytes, 10 * ell_hat_bytes};
}

VoleLayout vole_layout(std::size_t witness_bits, SecurityLevel level) {
  return vole_layout(witness_bits, level, VoleProfile::Small);
}

VoleLayout vole_layout(std::size_t witness_bits, SecurityLevel level,
                       VoleProfile profile) {
  const auto& security = security_parameters(level, profile);
  const auto ell_hat_bits = witness_bits + security.vole_extra_bits();
  const auto ell_hat_bytes = (ell_hat_bits + 7) / 8;
  const auto parameters = faest_vole_parameters(level, profile);
  return {witness_bits, ell_hat_bits, ell_hat_bytes,
          static_cast<std::size_t>(parameters.tau - 1) * ell_hat_bytes};
}

std::size_t vole_opening_size(SecurityLevel level) {
  return vole_opening_size(level, VoleProfile::Small);
}

std::size_t vole_opening_size(SecurityLevel level, VoleProfile profile) {
  const auto& security = security_parameters(level, profile);
  const auto parameters = faest_vole_parameters(level, profile);
  return security.lambda_bytes *
         (3 * static_cast<std::size_t>(parameters.tau) + parameters.T_open);
}

faest_paramset_t faest_vole_parameters() {
  return faest_vole_parameters(SecurityLevel::Bits128);
}

faest_paramset_t faest_vole_parameters(SecurityLevel level) {
  return faest_vole_parameters(level, VoleProfile::Small);
}

faest_paramset_t faest_vole_parameters(SecurityLevel level,
                                      VoleProfile profile) {
  const auto& security = security_parameters(level, profile);
  const auto* source = faest_get_paramset(security.faest_parameter);
  if (source == nullptr || source->lambda != security.lambda_bits)
    throw std::logic_error("invalid FAEST VOLE parameter mapping");
  auto parameters = *source;
  // `l` is uint16_t in the FAEST parameter ABI.  The VOLE routines used by
  // this adapter take ell_hat explicitly and do not consult `l`; keep the
  // base parameter value instead of truncating the larger generic witness.
  return parameters;
}

std::vector<std::uint8_t*> ReconstructedVole::columns() {
  return make_columns(q_storage, ell_hat_bytes);
}

FaestVoleCommitment::FaestVoleCommitment(
    const std::array<std::uint8_t, lambda_bytes>& root_key,
    const std::array<std::uint8_t, 16>& iv, std::size_t witness_bits)
    : iv_(iv), layout_(vole_layout(witness_bits)) {
  parameters_ = faest_vole_parameters();

  corrections_.resize((parameters_.tau - 1) * layout_.ell_hat_bytes);
  u_.resize(layout_.ell_hat_bytes);
  v_storage_.resize(lambda_bits * layout_.ell_hat_bytes);
  auto columns = v_columns();
  vole_commit(root_key.data(), iv_.data(), layout_.ell_hat_bits, &parameters_, &bavc_,
              corrections_.data(), u_.data(), columns.data());
  bavc_live_ = true;
}

FaestVoleCommitment::~FaestVoleCommitment() {
  if (bavc_live_) bavc_clear(&bavc_);
}

std::vector<std::uint8_t*> FaestVoleCommitment::v_columns() {
  return make_columns(v_storage_, layout_.ell_hat_bytes);
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
    reconstructed.ell_hat_bytes = layout_.ell_hat_bytes;
    std::copy_n(bavc_.h, reconstructed.commitment_hash.size(),
                reconstructed.commitment_hash.begin());
    reconstructed.q_storage.resize(lambda_bits * layout_.ell_hat_bytes);
    auto q_columns = reconstructed.columns();
    std::array<std::uint8_t, 2 * lambda_bytes> reconstructed_hash{};
    if (!vole_reconstruct(reconstructed_hash.data(), q_columns.data(), iv_.data(), challenge.data(),
                          decomposition.data(), corrections_.data(), layout_.ell_hat_bits,
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
                      std::size_t witness_bits,
                      ReconstructedVole& reconstructed) {
  const auto layout = vole_layout(witness_bits);
  if (decomposition.size() != vole_opening_bytes || corrections.size() != layout.correction_bytes) {
    return false;
  }
  auto parameters = faest_vole_parameters();
  reconstructed.challenge = challenge;
  reconstructed.ell_hat_bytes = layout.ell_hat_bytes;
  reconstructed.q_storage.assign(lambda_bits * layout.ell_hat_bytes, 0);
  auto q = reconstructed.columns();
  return vole_reconstruct(reconstructed.commitment_hash.data(), q.data(), iv.data(),
                          challenge.data(), decomposition.data(), corrections.data(),
                          layout.ell_hat_bits, &parameters);
}

std::vector<std::uint8_t> mask_witness(const std::vector<std::uint8_t>& witness,
                                       const std::vector<std::uint8_t>& u) {
  if (u.size() < witness.size()) throw std::invalid_argument("VOLE u is shorter than witness");
  std::vector<std::uint8_t> masked(witness.size(), 0);
  for (std::size_t i = 0; i != masked.size(); ++i) masked[i] = witness[i] ^ u[i];
  return masked;
}

bool check_vole_correlation(FaestVoleCommitment& commitment,
                            ReconstructedVole& reconstructed) {
  auto v = commitment.v_columns();
  auto q = reconstructed.columns();
  for (std::size_t column = 0; column != lambda_bits; ++column) {
    const bool delta = ptr_get_bit(reconstructed.challenge.data(), column) != 0;
    for (std::size_t byte = 0; byte != reconstructed.ell_hat_bytes; ++byte) {
      const auto expected = static_cast<std::uint8_t>(v[column][byte] ^
                                                      (delta ? commitment.u()[byte] : 0));
      if (q[column][byte] != expected) return false;
    }
  }
  return true;
}

std::vector<std::uint8_t*> ParameterizedReconstructedVole::columns() {
  const auto& parameters = security_parameters(security);
  return make_columns(q_storage, ell_hat_bytes, parameters.lambda_bits);
}

ParameterizedFaestVoleCommitment::ParameterizedFaestVoleCommitment(
    SecurityLevel security, VoleProfile profile,
    std::span<const std::uint8_t> root_key,
    const std::array<std::uint8_t, 16>& iv, std::size_t witness_bits)
    : security_(security), profile_(profile),
      parameters_(faest_vole_parameters(security, profile)), iv_(iv),
      layout_(vole_layout(witness_bits, security, profile)) {
  const auto& security_params = security_parameters(security, profile);
  if (root_key.size() != security_params.lambda_bytes)
    throw std::invalid_argument("VOLE root key has wrong size for security level");
  corrections_.resize(layout_.correction_bytes);
  u_.resize(layout_.ell_hat_bytes);
  v_storage_.resize(security_params.lambda_bits * layout_.ell_hat_bytes);
  auto columns = v_columns();
  vole_commit(root_key.data(), iv_.data(), layout_.ell_hat_bits, &parameters_, &bavc_,
              corrections_.data(), u_.data(), columns.data());
  bavc_live_ = true;
}

ParameterizedFaestVoleCommitment::~ParameterizedFaestVoleCommitment() {
  if (bavc_live_) bavc_clear(&bavc_);
}

std::vector<std::uint8_t*> ParameterizedFaestVoleCommitment::v_columns() {
  return make_columns(v_storage_, layout_.ell_hat_bytes,
                      security_parameters(security_, profile_).lambda_bits);
}

std::vector<std::uint8_t> ParameterizedFaestVoleCommitment::commitment_hash() const {
  std::vector<std::uint8_t> result(
      2 * security_parameters(security_, profile_).lambda_bytes);
  std::copy_n(bavc_.h, result.size(), result.begin());
  return result;
}

bool ParameterizedFaestVoleCommitment::open(
    std::span<const std::uint8_t> challenge,
    std::vector<std::uint8_t>& decomposition) {
  const auto& security = security_parameters(security_, profile_);
  if (challenge.size() != security.lambda_bytes) return false;
  std::vector<std::uint16_t> decoded(parameters_.tau);
  if (!decode_all_chall_3(decoded.data(), challenge.data(), &parameters_)) return false;
  decomposition.resize(vole_opening_size(security_, profile_));
  return bavc_open(decomposition.data(), &bavc_, decoded.data(), &parameters_);
}

bool reconstruct_vole(SecurityLevel security_level,
                      VoleProfile profile,
                      const std::array<std::uint8_t, 16>& iv,
                      std::span<const std::uint8_t> challenge,
                      std::span<const std::uint8_t> decomposition,
                      std::span<const std::uint8_t> corrections,
                      std::size_t witness_bits,
                      ParameterizedReconstructedVole& reconstructed) {
  const auto& security = security_parameters(security_level, profile);
  const auto layout = vole_layout(witness_bits, security_level, profile);
  if (challenge.size() != security.lambda_bytes ||
      decomposition.size() != vole_opening_size(security_level, profile) ||
      corrections.size() != layout.correction_bytes) {
    return false;
  }
  auto parameters = faest_vole_parameters(security_level, profile);
  reconstructed.security = security_level;
  reconstructed.profile = profile;
  reconstructed.challenge.assign(challenge.begin(), challenge.end());
  reconstructed.commitment_hash.assign(2 * security.lambda_bytes, 0);
  reconstructed.ell_hat_bytes = layout.ell_hat_bytes;
  reconstructed.q_storage.assign(security.lambda_bits * layout.ell_hat_bytes, 0);
  auto q = reconstructed.columns();
  return vole_reconstruct(reconstructed.commitment_hash.data(), q.data(), iv.data(),
                          challenge.data(), decomposition.data(), corrections.data(),
                          layout.ell_hat_bits, &parameters);
}

bool check_vole_correlation(ParameterizedFaestVoleCommitment& commitment,
                            ParameterizedReconstructedVole& reconstructed) {
  if (commitment.security() != reconstructed.security ||
      commitment.profile() != reconstructed.profile)
    return false;
  const auto& security =
      security_parameters(commitment.security(), commitment.profile());
  auto v = commitment.v_columns();
  auto q = reconstructed.columns();
  for (std::size_t column = 0; column != security.lambda_bits; ++column) {
    const bool delta = ptr_get_bit(reconstructed.challenge.data(), column) != 0;
    for (std::size_t byte = 0; byte != reconstructed.ell_hat_bytes; ++byte) {
      const auto expected = static_cast<std::uint8_t>(
          v[column][byte] ^ (delta ? commitment.u()[byte] : 0));
      if (q[column][byte] != expected) return false;
    }
  }
  return true;
}

} // namespace vole_backend
