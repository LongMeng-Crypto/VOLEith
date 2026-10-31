/* SPDX-License-Identifier: MIT */
#pragma once
#include <cstdint>
namespace vole_backend {
// v1 research baseline: per-AND degree-2 relations, raised before FAEST masking.
inline constexpr std::uint8_t constraint_encoding_version = 4;
inline constexpr unsigned quadratic_authentication_check_degree = 3;
}
