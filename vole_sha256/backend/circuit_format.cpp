/* SPDX-License-Identifier: MIT */

#include "circuit_format.hpp"

#include <openssl/evp.h>

#include <algorithm>
#include <limits>
#include <stdexcept>

namespace vole_backend {
namespace {

constexpr std::array<std::uint8_t, 8> magic = {'V', 'O', 'L', 'E', 'V', 'B', 'C', 1};
constexpr std::size_t node_record_bytes = 10;

void append_u32(std::vector<std::uint8_t>& out, std::uint32_t value) {
  for (unsigned int shift = 0; shift != 32; shift += 8) {
    out.push_back(static_cast<std::uint8_t>(value >> shift));
  }
}

std::uint32_t read_u32(std::span<const std::uint8_t> bytes, std::size_t& offset) {
  if (offset + 4 > bytes.size()) throw std::invalid_argument("truncated VBC integer");
  std::uint32_t value = 0;
  for (unsigned int shift = 0; shift != 32; shift += 8) value |= std::uint32_t(bytes[offset++]) << shift;
  return value;
}

std::uint8_t opcode(Op op) {
  switch (op) {
  case Op::Constant: return 0;
  case Op::PrivateInput: return 1;
  case Op::PublicInput: return 2;
  case Op::Xor: return 3;
  case Op::And: return 4;
  }
  throw std::invalid_argument("unknown circuit operation");
}

Op decode_opcode(std::uint8_t value) {
  switch (value) {
  case 0: return Op::Constant;
  case 1: return Op::PrivateInput;
  case 2: return Op::PublicInput;
  case 3: return Op::Xor;
  case 4: return Op::And;
  default: throw std::invalid_argument("unknown VBC opcode");
  }
}

} // namespace

std::vector<std::uint8_t> serialize_vbc(const BinaryCircuit& circuit) {
  std::string error;
  if (!circuit.validate(&error)) throw std::invalid_argument("cannot serialize circuit: " + error);
  if (circuit.nodes().size() > std::numeric_limits<std::uint32_t>::max() ||
      circuit.outputs().size() > std::numeric_limits<std::uint32_t>::max()) {
    throw std::length_error("circuit is too large for VBC v1");
  }
  std::vector<std::uint8_t> out;
  out.reserve(magic.size() + 8 + node_record_bytes * circuit.nodes().size() +
              4 * circuit.outputs().size());
  out.insert(out.end(), magic.begin(), magic.end());
  append_u32(out, static_cast<std::uint32_t>(circuit.nodes().size()));
  append_u32(out, static_cast<std::uint32_t>(circuit.outputs().size()));
  for (const auto& node : circuit.nodes()) {
    out.push_back(opcode(node.op));
    append_u32(out, node.lhs);
    append_u32(out, node.rhs);
    out.push_back(static_cast<std::uint8_t>(node.constant));
  }
  for (const auto output : circuit.outputs()) append_u32(out, output);
  return out;
}

BinaryCircuit deserialize_vbc(std::span<const std::uint8_t> bytes) {
  if (bytes.size() < magic.size() + 8 || !std::equal(magic.begin(), magic.end(), bytes.begin())) {
    throw std::invalid_argument("invalid VBC magic/version");
  }
  std::size_t offset = magic.size();
  const auto node_count = read_u32(bytes, offset);
  const auto output_count = read_u32(bytes, offset);
  const std::uint64_t expected = magic.size() + 8ULL +
                                 std::uint64_t(node_count) * node_record_bytes +
                                 std::uint64_t(output_count) * 4;
  if (expected != bytes.size()) throw std::invalid_argument("non-canonical VBC size");
  std::vector<Node> nodes;
  nodes.reserve(node_count);
  for (std::uint32_t i = 0; i != node_count; ++i) {
    const auto op = decode_opcode(bytes[offset++]);
    const auto lhs = read_u32(bytes, offset);
    const auto rhs = read_u32(bytes, offset);
    const auto flags = bytes[offset++];
    if (flags > 1) throw std::invalid_argument("non-canonical VBC flags");
    nodes.push_back({op, lhs, rhs, flags != 0});
  }
  std::vector<Wire> outputs;
  outputs.reserve(output_count);
  for (std::uint32_t i = 0; i != output_count; ++i) outputs.push_back(read_u32(bytes, offset));
  auto circuit = BinaryCircuit::from_canonical(std::move(nodes), std::move(outputs));
  if (serialize_vbc(circuit) != std::vector<std::uint8_t>(bytes.begin(), bytes.end())) {
    throw std::invalid_argument("non-canonical VBC encoding");
  }
  return circuit;
}

CircuitHash circuit_hash(std::span<const std::uint8_t> canonical_vbc) {
  CircuitHash digest{};
  unsigned int size = 0;
  if (EVP_Digest(canonical_vbc.data(), canonical_vbc.size(), digest.data(), &size,
                 EVP_sha256(), nullptr) != 1 || size != digest.size()) {
    throw std::runtime_error("SHA-256 circuit hash failed");
  }
  return digest;
}

CircuitHash circuit_hash(const BinaryCircuit& circuit) { return circuit_hash(serialize_vbc(circuit)); }

} // namespace vole_backend
