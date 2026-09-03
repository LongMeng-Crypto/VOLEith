/* SPDX-License-Identifier: MIT */
#ifndef VOLE_CIRCUITS_SHA2_SHA512_CIRCUIT_HPP
#define VOLE_CIRCUITS_SHA2_SHA512_CIRCUIT_HPP

#include "sha512_family.hpp"

namespace vole_circuits::sha2 {

class Sha512Circuit final : public Sha512FamilyCircuit {
public:
  explicit Sha512Circuit(std::size_t message_length = 96);
  Sha512Circuit(std::size_t message_length,
                InputVisibilityLayout input_visibility);
};

} // namespace vole_circuits::sha2

#endif
