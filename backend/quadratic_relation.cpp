/* SPDX-License-Identifier: MIT */

#include "quadratic_relation.hpp"

#include <openssl/evp.h>

#include <stdexcept>

namespace vole_backend {
namespace {
constexpr std::array<std::uint8_t, 8> magic{'V','Q','I','R',1,0,0,0};
void append_u32(std::vector<std::uint8_t>& out, std::uint32_t x) {
  for (unsigned s = 0; s != 32; s += 8) out.push_back(x >> s);
}
std::uint32_t read_u32(std::span<const std::uint8_t> in, std::size_t& p) {
  std::uint32_t x = 0;
  for (unsigned s = 0; s != 32; s += 8) x |= std::uint32_t(in[p++]) << s;
  return x;
}
} // namespace

std::vector<std::uint8_t> serialize_vqir(const QuadraticRelationIR& r) {
  std::vector<std::uint8_t> out(magic.begin(), magic.end());
  out.push_back(static_cast<std::uint8_t>(r.field));
  out.push_back(static_cast<std::uint8_t>(r.constraint));
  out.push_back(0); out.push_back(0);
  append_u32(out, r.private_input_bits); append_u32(out, r.public_input_bits);
  append_u32(out, r.output_bits); append_u32(out, r.auxiliary_witness_bits);
  append_u32(out, r.multiplication_constraints);
  return out;
}

QuadraticRelationIR deserialize_vqir(std::span<const std::uint8_t> in) {
  if (in.size() != 32 || !std::equal(magic.begin(), magic.end(), in.begin()) ||
      in[8] != 1 || in[9] != 1 || in[10] != 0 || in[11] != 0)
    throw std::invalid_argument("invalid VQIR encoding");
  std::size_t p = 12;
  QuadraticRelationIR r;
  r.private_input_bits = read_u32(in,p); r.public_input_bits = read_u32(in,p);
  r.output_bits = read_u32(in,p); r.auxiliary_witness_bits = read_u32(in,p);
  r.multiplication_constraints = read_u32(in,p);
  return r;
}

std::array<std::uint8_t, 32> relation_hash(const QuadraticRelationIR& r) {
  const auto encoded = serialize_vqir(r);
  std::array<std::uint8_t, 32> out{}; unsigned int n = 0;
  if (EVP_Digest(encoded.data(), encoded.size(), out.data(), &n, EVP_sha256(), nullptr) != 1 || n != out.size())
    throw std::runtime_error("relation hash failed");
  return out;
}

} // namespace vole_backend
