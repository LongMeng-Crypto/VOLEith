/* SPDX-License-Identifier: MIT */
#ifndef VOLE_BACKEND_SECURITY_PARAMETERS_HPP
#define VOLE_BACKEND_SECURITY_PARAMETERS_HPP

#include <cstddef>
#include <cstdint>
#include <string_view>

extern "C" {
#include "instances.h"
}

namespace vole_backend {

enum class SecurityLevel : std::uint8_t {
  Bits128 = 1,
  Bits192 = 2,
  Bits256 = 3,
};

struct SecurityParameters {
  SecurityLevel level;
  std::size_t lambda_bits;
  std::size_t lambda_bytes;
  faest_paramid_t faest_parameter;

  std::size_t quicksilver_challenge_bytes() const { return 3 * lambda_bytes + 8; }
  std::size_t challenge_1_bytes() const { return 5 * lambda_bytes + 8; }
  std::size_t utilde_bytes() const { return lambda_bytes + 2; }
  std::size_t vole_extra_bits() const { return 3 * lambda_bits + 16; }
};

const SecurityParameters& security_parameters(SecurityLevel level);
SecurityLevel parse_security_level(std::string_view text);
std::string_view security_level_name(SecurityLevel level);
std::uint8_t security_level_code(SecurityLevel level);

} // namespace vole_backend

#endif
