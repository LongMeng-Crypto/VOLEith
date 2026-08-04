/* SPDX-License-Identifier: MIT */
#ifndef VOLE_CIRCUITS_AES128_CIRCUIT_HPP
#define VOLE_CIRCUITS_AES128_CIRCUIT_HPP

#include "binary_circuit.hpp"

#include <array>
#include <cstdint>

namespace vole_circuits::aes {

using Block = std::array<std::uint8_t, 16>;

class Aes128Circuit {
public:
  Aes128Circuit();
  const vole_backend::BinaryCircuit& binary_circuit() const { return circuit_; }
  Block evaluate(const Block& key, const Block& plaintext) const;

private:
  vole_backend::BinaryCircuit circuit_;
};

} // namespace vole_circuits::aes

#endif
