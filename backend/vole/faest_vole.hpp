/* SPDX-License-Identifier: MIT */
#ifndef VOLE_BACKEND_FAEST_VOLE_HPP
#define VOLE_BACKEND_FAEST_VOLE_HPP

#include "quicksilver_types.hpp"
#include "security_parameters.hpp"

#include <array>
#include <cstddef>
#include <cstdint>
#include <span>
#include <vector>

extern "C" {
#include "bavc.h"
#include "instances.h"
}

namespace vole_backend {

constexpr std::size_t vole_extra_bits = 3 * lambda_bits + 16;
constexpr std::size_t vole_opening_bytes = 3 * lambda_bytes * 11 + 102 * lambda_bytes;

struct VoleLayout {
  std::size_t witness_bits;
  std::size_t ell_hat_bits;
  std::size_t ell_hat_bytes;
  std::size_t correction_bytes;
};

VoleLayout vole_layout(std::size_t witness_bits);

faest_paramset_t faest_vole_parameters();
faest_paramset_t faest_vole_parameters(SecurityLevel level);
faest_paramset_t faest_vole_parameters(SecurityLevel level, VoleProfile profile);

VoleLayout vole_layout(std::size_t witness_bits, SecurityLevel level);
VoleLayout vole_layout(std::size_t witness_bits, SecurityLevel level,
                       VoleProfile profile);
std::size_t vole_opening_size(SecurityLevel level);
std::size_t vole_opening_size(SecurityLevel level, VoleProfile profile);

struct ReconstructedVole {
  std::array<std::uint8_t, lambda_bytes> challenge{};
  std::array<std::uint8_t, 2 * lambda_bytes> commitment_hash{};
  std::vector<std::uint8_t> q_storage;
  std::size_t ell_hat_bytes = 0;

  std::vector<std::uint8_t*> columns();
};

class FaestVoleCommitment {
public:
  FaestVoleCommitment(const std::array<std::uint8_t, lambda_bytes>& root_key,
                      const std::array<std::uint8_t, 16>& iv,
                      std::size_t witness_bits);
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
  VoleLayout layout_{};
};

std::vector<std::uint8_t> mask_witness(const std::vector<std::uint8_t>& witness,
                                       const std::vector<std::uint8_t>& u);

bool check_vole_correlation(FaestVoleCommitment& commitment,
                            ReconstructedVole& reconstructed);

bool reconstruct_vole(const std::array<std::uint8_t, 16>& iv,
                      const std::array<std::uint8_t, lambda_bytes>& challenge,
                      const std::vector<std::uint8_t>& decomposition,
                      const std::vector<std::uint8_t>& corrections,
                      std::size_t witness_bits,
                      ReconstructedVole& reconstructed);

struct ParameterizedReconstructedVole {
  SecurityLevel security = SecurityLevel::Bits128;
  VoleProfile profile = VoleProfile::Small;
  std::vector<std::uint8_t> challenge;
  std::vector<std::uint8_t> commitment_hash;
  std::vector<std::uint8_t> q_storage;
  std::size_t ell_hat_bytes = 0;

  std::vector<std::uint8_t*> columns();
};

class ParameterizedFaestVoleCommitment {
public:
  ParameterizedFaestVoleCommitment(SecurityLevel security,
                                   VoleProfile profile,
                                   std::span<const std::uint8_t> root_key,
                                   const std::array<std::uint8_t, 16>& iv,
                                   std::size_t witness_bits);
  ~ParameterizedFaestVoleCommitment();

  ParameterizedFaestVoleCommitment(const ParameterizedFaestVoleCommitment&) = delete;
  ParameterizedFaestVoleCommitment& operator=(const ParameterizedFaestVoleCommitment&) = delete;

  SecurityLevel security() const { return security_; }
  VoleProfile profile() const { return profile_; }
  const faest_paramset_t& parameters() const { return parameters_; }
  const std::vector<std::uint8_t>& u() const { return u_; }
  const std::vector<std::uint8_t>& corrections() const { return corrections_; }
  std::vector<std::uint8_t> commitment_hash() const;
  std::vector<std::uint8_t*> v_columns();
  bool open(std::span<const std::uint8_t> challenge,
            std::vector<std::uint8_t>& decomposition);

private:
  SecurityLevel security_;
  VoleProfile profile_;
  faest_paramset_t parameters_{};
  std::array<std::uint8_t, 16> iv_{};
  bavc_t bavc_{};
  bool bavc_live_ = false;
  std::vector<std::uint8_t> corrections_;
  std::vector<std::uint8_t> u_;
  std::vector<std::uint8_t> v_storage_;
  VoleLayout layout_{};
};

bool reconstruct_vole(SecurityLevel security,
                      VoleProfile profile,
                      const std::array<std::uint8_t, 16>& iv,
                      std::span<const std::uint8_t> challenge,
                      std::span<const std::uint8_t> decomposition,
                      std::span<const std::uint8_t> corrections,
                      std::size_t witness_bits,
                      ParameterizedReconstructedVole& reconstructed);

bool check_vole_correlation(ParameterizedFaestVoleCommitment& commitment,
                            ParameterizedReconstructedVole& reconstructed);

} // namespace vole_backend

#endif
