/* SPDX-License-Identifier: MIT */
#ifndef VOLE_SHA256_FAEST_VOLE_HPP
#define VOLE_SHA256_FAEST_VOLE_HPP

#include "faest_quicksilver.hpp"

#include <array>
#include <cstddef>
#include <cstdint>
#include <vector>

extern "C" {
#include "bavc.h"
#include "instances.h"
}

namespace vole_sha256 {

constexpr std::size_t vole_extra_bits = 3 * lambda_bits + 16;
constexpr std::size_t vole_ell_hat_bits = vole_witness_bits + vole_extra_bits;
constexpr std::size_t vole_ell_hat_bytes = vole_ell_hat_bits / 8;
constexpr std::size_t vole_correction_bytes = 10 * vole_ell_hat_bytes;
constexpr std::size_t vole_opening_bytes = 3 * lambda_bytes * 11 + 102 * lambda_bytes;

faest_paramset_t sha256_vole_parameters();

struct ReconstructedVole {
  std::array<std::uint8_t, lambda_bytes> challenge{};
  std::array<std::uint8_t, 2 * lambda_bytes> commitment_hash{};
  std::vector<std::uint8_t> q_storage;

  std::vector<std::uint8_t*> columns();
};

class FaestVoleCommitment {
public:
  FaestVoleCommitment(const std::array<std::uint8_t, lambda_bytes>& root_key,
                      const std::array<std::uint8_t, 16>& iv);
  ~FaestVoleCommitment();

  FaestVoleCommitment(const FaestVoleCommitment&) = delete;
  FaestVoleCommitment& operator=(const FaestVoleCommitment&) = delete;

  const faest_paramset_t& parameters() const { return parameters_; }
  const std::vector<std::uint8_t>& u() const { return u_; }
  const std::vector<std::uint8_t>& corrections() const { return corrections_; }
  std::array<std::uint8_t, 2 * lambda_bytes> commitment_hash() const;
  std::vector<std::uint8_t*> v_columns();

  bool open(const std::array<std::uint8_t, lambda_bytes>& challenge,
            std::vector<std::uint8_t>& decomposition);

  // Deterministically searches for a decodable/openable challenge for tests
  // and the next transcript-integration stage.
  ReconstructedVole open_and_reconstruct();

private:
  faest_paramset_t parameters_{};
  std::array<std::uint8_t, 16> iv_{};
  bavc_t bavc_{};
  bool bavc_live_ = false;
  std::vector<std::uint8_t> corrections_;
  std::vector<std::uint8_t> u_;
  std::vector<std::uint8_t> v_storage_;
};

PackedWitness mask_witness(const PackedWitness& witness, const std::vector<std::uint8_t>& u);

bool check_vole_correlation(FaestVoleCommitment& commitment,
                            ReconstructedVole& reconstructed);

bool reconstruct_vole(const std::array<std::uint8_t, 16>& iv,
                      const std::array<std::uint8_t, lambda_bytes>& challenge,
                      const std::vector<std::uint8_t>& decomposition,
                      const std::vector<std::uint8_t>& corrections,
                      ReconstructedVole& reconstructed);

} // namespace vole_sha256

#endif
