/* SPDX-License-Identifier: MIT */
#ifndef VOLE_BACKEND_JSON_CIRCUIT_HPP
#define VOLE_BACKEND_JSON_CIRCUIT_HPP

#include "binary_circuit.hpp"

#include <string_view>

namespace vole_backend {

// Compile the strict, versioned JSON circuit representation documented in
// doc/JSON_CIRCUIT_FORMAT.md into the canonical in-memory IR.
BinaryCircuit compile_json_circuit(std::string_view json);

} // namespace vole_backend

#endif
