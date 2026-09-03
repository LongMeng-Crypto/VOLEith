/* SPDX-License-Identifier: MIT */

#include "security_parameters.hpp"

#include <stdexcept>

namespace vole_backend {

const SecurityParameters& security_parameters(SecurityLevel level) {
  return security_parameters(level, VoleProfile::Small);
}

const SecurityParameters& security_parameters(SecurityLevel level,
                                              VoleProfile profile) {
  static constexpr SecurityParameters p128s{
      SecurityLevel::Bits128, VoleProfile::Small, 128, 16, FAEST_128S};
  static constexpr SecurityParameters p128f{
      SecurityLevel::Bits128, VoleProfile::Fast, 128, 16, FAEST_128F};
  static constexpr SecurityParameters p192s{
      SecurityLevel::Bits192, VoleProfile::Small, 192, 24, FAEST_192S};
  static constexpr SecurityParameters p192f{
      SecurityLevel::Bits192, VoleProfile::Fast, 192, 24, FAEST_192F};
  static constexpr SecurityParameters p256s{
      SecurityLevel::Bits256, VoleProfile::Small, 256, 32, FAEST_256S};
  static constexpr SecurityParameters p256f{
      SecurityLevel::Bits256, VoleProfile::Fast, 256, 32, FAEST_256F};
  if (profile != VoleProfile::Small && profile != VoleProfile::Fast)
    throw std::invalid_argument("unsupported VOLEith profile");
  switch (level) {
  case SecurityLevel::Bits128:
    return profile == VoleProfile::Small ? p128s : p128f;
  case SecurityLevel::Bits192:
    return profile == VoleProfile::Small ? p192s : p192f;
  case SecurityLevel::Bits256:
    return profile == VoleProfile::Small ? p256s : p256f;
  }
  throw std::invalid_argument("unsupported VOLEith security level");
}

SecurityLevel parse_security_level(std::string_view text) {
  if (text == "128") return SecurityLevel::Bits128;
  if (text == "192") return SecurityLevel::Bits192;
  if (text == "256") return SecurityLevel::Bits256;
  throw std::invalid_argument("security level must be 128, 192, or 256");
}

VoleProfile parse_vole_profile(std::string_view text) {
  if (text == "s" || text == "small") return VoleProfile::Small;
  if (text == "f" || text == "fast") return VoleProfile::Fast;
  throw std::invalid_argument("VOLE profile must be s/small or f/fast");
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

std::string_view vole_profile_name(VoleProfile profile) {
  switch (profile) {
  case VoleProfile::Small: return "s";
  case VoleProfile::Fast: return "f";
  }
  throw std::invalid_argument("unsupported VOLEith profile");
}

std::uint8_t vole_profile_code(VoleProfile profile) {
  switch (profile) {
  case VoleProfile::Small: return 1;
  case VoleProfile::Fast: return 2;
  }
  throw std::invalid_argument("unsupported VOLEith profile");
}

} // namespace vole_backend
