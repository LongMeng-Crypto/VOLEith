/* SPDX-License-Identifier: MIT */

#include "sha384_circuit.hpp"

#include <utility>

namespace vole_circuits::sha2 {

Sha384Circuit::Sha384Circuit(std::size_t message_length)
    : Sha384Circuit(message_length,
                    InputVisibilityLayout::all_secret(message_length * 8)) {}

Sha384Circuit::Sha384Circuit(std::size_t message_length,
                             InputVisibilityLayout input_visibility)
    : Sha512FamilyCircuit(Sha512Variant::Sha384, message_length,
                          std::move(input_visibility)) {}

} // namespace vole_circuits::sha2
