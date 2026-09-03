/* SPDX-License-Identifier: MIT */

#include "sha512_circuit.hpp"

#include <utility>

namespace vole_circuits::sha2 {

Sha512Circuit::Sha512Circuit(std::size_t message_length)
    : Sha512Circuit(message_length,
                    InputVisibilityLayout::all_secret(message_length * 8)) {}

Sha512Circuit::Sha512Circuit(std::size_t message_length,
                             InputVisibilityLayout input_visibility)
    : Sha512FamilyCircuit(Sha512Variant::Sha512, message_length,
                          std::move(input_visibility)) {}

} // namespace vole_circuits::sha2
