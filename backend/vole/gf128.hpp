/* SPDX-License-Identifier: MIT */
#ifndef VOLE_BACKEND_GF128_HPP
#define VOLE_BACKEND_GF128_HPP

#include <cstdint>
#include <iosfwd>

namespace vole_backend {

// GF(2^128) in the polynomial basis used by FAEST:
// X^128 + X^7 + X^2 + X + 1.
struct Gf128 {
  std::uint64_t lo = 0;
  std::uint64_t hi = 0;

  static Gf128 from_bit(bool bit) { return {static_cast<std::uint64_t>(bit), 0}; }

  friend bool operator==(const Gf128&, const Gf128&) = default;
  friend Gf128 operator+(Gf128 lhs, const Gf128& rhs) {
    lhs.lo ^= rhs.lo;
    lhs.hi ^= rhs.hi;
    return lhs;
  }
  Gf128& operator+=(const Gf128& rhs) {
    lo ^= rhs.lo;
    hi ^= rhs.hi;
    return *this;
  }
};

Gf128 operator*(Gf128 lhs, Gf128 rhs);
std::ostream& operator<<(std::ostream& stream, const Gf128& value);

} // namespace vole_backend

#endif
