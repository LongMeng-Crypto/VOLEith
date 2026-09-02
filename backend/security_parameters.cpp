/* SPDX-License-Identifier: MIT */

#include "security_parameters.hpp"

#include <stdexcept>

namespace vole_backend {

const SecurityParameters& security_parameters(SecurityLevel level) {
  static constexpr SecurityParameters p128{SecurityLevel::Bits128, 128, 16, FAEST_128S};
  static constexpr SecurityParameters p192{SecurityLevel::Bits192, 192, 24, FAEST_192S};
  static constexpr SecurityParameters p256{SecurityLevel::Bits256, 256, 32, FAEST_256S};
  switch (level) {
  case SecurityLevel::Bits128: return p128;
  case SecurityLevel::Bits192: return p192;
  case SecurityLevel::Bits256: return p256;
  }
  throw std::invalid_argument("unsupported VOLEith security level");
}

SecurityLevel parse_security_level(std::string_view text) {
  if (text == "128") return SecurityLevel::Bits128;
  if (text == "192") return SecurityLevel::Bits192;
  if (text == "256") return SecurityLevel::Bits256;
  throw std::invalid_argument("security level must be 128, 192, or 256");
}

std::string_view security_level_name(SecurityLevel level) {
  switch (level) {
  case SecurityLevel::Bits128: return "128";
  case SecurityLevel::Bits192: return "192";
  case SecurityLevel::Bits256: return "256";
  }
  throw std::invalid_argument("unsupported VOLEith security level");
}

std::uint8_t security_level_code(SecurityLevel level) {
  return static_cast<std::uint8_t>(level);
}

} // namespace vole_backend
