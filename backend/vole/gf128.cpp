/* SPDX-License-Identifier: MIT */

#include "gf128.hpp"

#include <iomanip>
#include <ostream>

namespace vole_backend {

Gf128 operator*(Gf128 lhs, Gf128 rhs) {
  Gf128 result{};
  for (unsigned int i = 0; i != 128; ++i) {
    if (rhs.lo & 1U) result += lhs;

    rhs.lo = (rhs.lo >> 1) | (rhs.hi << 63);
    rhs.hi >>= 1;

    const bool carry = (lhs.hi >> 63) != 0;
    lhs.hi = (lhs.hi << 1) | (lhs.lo >> 63);
    lhs.lo <<= 1;
    if (carry) lhs.lo ^= 0x87U;
  }
  return result;
}

std::ostream& operator<<(std::ostream& stream, const Gf128& value) {
  const auto flags = stream.flags();
  const auto fill = stream.fill();
  stream << "0x" << std::hex << std::setfill('0') << std::setw(16) << value.hi << std::setw(16)
         << value.lo;
  stream.flags(flags);
  stream.fill(fill);
  return stream;
}

} // namespace vole_backend
