/* SPDX-License-Identifier: MIT */

#include "aes128_circuit.hpp"

#include <algorithm>
#include <vector>

namespace vole_circuits::aes {
namespace {

using Wire = vole_backend::Wire;
using Byte = std::array<Wire, 8>;
using State = std::array<Byte, 16>;

Byte xor_byte(vole_backend::CircuitBuilder& b, const Byte& x, const Byte& y) {
  Byte z{};
  for (unsigned i = 0; i != 8; ++i) z[i] = b.xor_wire(x[i], y[i]);
  return z;
}

Byte constant_byte(vole_backend::CircuitBuilder& b, std::uint8_t value) {
  Byte x{};
  for (unsigned i = 0; i != 8; ++i) x[i] = ((value >> i) & 1U) ? b.one() : b.zero();
  return x;
}

Byte square(vole_backend::CircuitBuilder& b, const Byte& x) {
  std::array<Wire, 15> p{};
  p.fill(b.zero());
  for (unsigned i = 0; i != 8; ++i) p[2 * i] = x[i];
  for (int d = 14; d >= 8; --d) {
    const auto t = p[d];
    p[d - 8] = b.xor_wire(p[d - 8], t);
    p[d - 7] = b.xor_wire(p[d - 7], t);
    p[d - 5] = b.xor_wire(p[d - 5], t);
    p[d - 4] = b.xor_wire(p[d - 4], t);
  }
  Byte z{};
  std::copy_n(p.begin(), 8, z.begin());
  return z;
}

Byte multiply(vole_backend::CircuitBuilder& b, const Byte& x, const Byte& y) {
  std::array<Wire, 15> p{};
  p.fill(b.zero());
  for (unsigned i = 0; i != 8; ++i)
    for (unsigned j = 0; j != 8; ++j)
      p[i + j] = b.xor_wire(p[i + j], b.and_wire(x[i], y[j]));
  for (int d = 14; d >= 8; --d) {
    const auto t = p[d];
    p[d - 8] = b.xor_wire(p[d - 8], t);
    p[d - 7] = b.xor_wire(p[d - 7], t);
    p[d - 5] = b.xor_wire(p[d - 5], t);
    p[d - 4] = b.xor_wire(p[d - 4], t);
  }
  Byte z{};
  std::copy_n(p.begin(), 8, z.begin());
  return z;
}

Byte sbox(vole_backend::CircuitBuilder& b, const Byte& x) {
  const auto x2 = square(b, x);
  const auto x4 = square(b, x2);
  const auto x8 = square(b, x4);
  const auto x16 = square(b, x8);
  const auto x32 = square(b, x16);
  const auto x64 = square(b, x32);
  const auto x128 = square(b, x64);
  auto inverse = multiply(b, x2, x4);
  inverse = multiply(b, inverse, x8);
  inverse = multiply(b, inverse, x16);
  inverse = multiply(b, inverse, x32);
  inverse = multiply(b, inverse, x64);
  inverse = multiply(b, inverse, x128);
  constexpr std::uint8_t affine = 0x63;
  Byte out{};
  for (unsigned i = 0; i != 8; ++i) {
    auto bit = inverse[i];
    for (unsigned offset : {4U, 5U, 6U, 7U})
      bit = b.xor_wire(bit, inverse[(i + offset) & 7U]);
    out[i] = b.xor_wire(bit, ((affine >> i) & 1U) ? b.one() : b.zero());
  }
  return out;
}

Byte xtime(vole_backend::CircuitBuilder& b, const Byte& x) {
  Byte y{};
  y[0] = x[7]; y[1] = b.xor_wire(x[0], x[7]); y[2] = x[1];
  y[3] = b.xor_wire(x[2], x[7]); y[4] = b.xor_wire(x[3], x[7]);
  y[5] = x[4]; y[6] = x[5]; y[7] = x[6];
  return y;
}

State add_round_key(vole_backend::CircuitBuilder& b, State s,
                    const std::array<Byte, 176>& keys, unsigned round) {
  for (unsigned i = 0; i != 16; ++i) s[i] = xor_byte(b, s[i], keys[16 * round + i]);
  return s;
}

State round_state(vole_backend::CircuitBuilder& b, const State& input, bool final) {
  State sub{}, shifted{}, out{};
  for (unsigned i = 0; i != 16; ++i) sub[i] = sbox(b, input[i]);
  for (unsigned c = 0; c != 4; ++c)
    for (unsigned r = 0; r != 4; ++r) shifted[4 * c + r] = sub[4 * ((c + r) & 3U) + r];
  if (final) return shifted;
  for (unsigned c = 0; c != 4; ++c) {
    const auto& a0 = shifted[4*c]; const auto& a1 = shifted[4*c+1];
    const auto& a2 = shifted[4*c+2]; const auto& a3 = shifted[4*c+3];
    const auto x0 = xtime(b, a0), x1 = xtime(b, a1), x2 = xtime(b, a2), x3 = xtime(b, a3);
    out[4*c]   = xor_byte(b, xor_byte(b, xor_byte(b, x0, xor_byte(b, x1, a1)), a2), a3);
    out[4*c+1] = xor_byte(b, xor_byte(b, xor_byte(b, a0, x1), xor_byte(b, x2, a2)), a3);
    out[4*c+2] = xor_byte(b, xor_byte(b, xor_byte(b, a0, a1), x2), xor_byte(b, x3, a3));
    out[4*c+3] = xor_byte(b, xor_byte(b, xor_byte(b, xor_byte(b, x0, a0), a1), a2), x3);
  }
  return out;
}

} // namespace

Aes128Circuit::Aes128Circuit() {
  vole_backend::CircuitBuilder b(circuit_);
  std::array<Byte, 176> keys{};
  State state{};
  for (unsigned i = 0; i != 16; ++i)
    for (auto& bit : keys[i]) bit = b.private_input();
  for (auto& byte : state)
    for (auto& bit : byte) bit = b.public_input();
  constexpr std::array<std::uint8_t, 10> rcon{1,2,4,8,16,32,64,128,27,54};
  for (unsigned i = 16; i != 176;) {
    std::array<Byte, 4> temp{keys[i-4], keys[i-3], keys[i-2], keys[i-1]};
    if (i % 16 == 0) {
      std::rotate(temp.begin(), temp.begin() + 1, temp.end());
      for (auto& byte : temp) byte = sbox(b, byte);
      temp[0] = xor_byte(b, temp[0], constant_byte(b, rcon[i / 16 - 1]));
    }
    for (unsigned j = 0; j != 4; ++j, ++i) keys[i] = xor_byte(b, keys[i - 16], temp[j]);
  }
  state = add_round_key(b, state, keys, 0);
  for (unsigned round = 1; round != 11; ++round)
    state = add_round_key(b, round_state(b, state, round == 10), keys, round);
  for (const auto& byte : state) for (const auto bit : byte) b.output(bit);
}

Block Aes128Circuit::evaluate(const Block& key, const Block& plaintext) const {
  std::vector<std::uint8_t> private_bits(128), public_bits(128);
  for (unsigned i = 0; i != 128; ++i) {
    private_bits[i] = (key[i / 8] >> (i & 7U)) & 1U;
    public_bits[i] = (plaintext[i / 8] >> (i & 7U)) & 1U;
  }
  const auto result = circuit_.evaluate(private_bits, public_bits);
  Block out{};
  for (unsigned i = 0; i != 128; ++i) out[i / 8] |= result.outputs[i] << (i & 7U);
  return out;
}

} // namespace vole_circuits::aes
