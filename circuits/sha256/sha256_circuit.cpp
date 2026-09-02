/* SPDX-License-Identifier: MIT */

#include "sha256_circuit.hpp"

#include <algorithm>
#include <stdexcept>
#include <utility>

namespace faest::sha256_circuit {
namespace {

using Wire = std::uint32_t;
using Word = std::array<Wire, 32>; // little-endian bits: bit 0 is the LSB

constexpr std::array<std::uint32_t, 8> initial_state = {
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
    0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
};

constexpr std::array<std::uint32_t, 64> round_constants = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1,
    0x923f82a4, 0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
    0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786,
    0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147,
    0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
    0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
    0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a,
    0x5b9cca4f, 0x682e6ff3, 0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
    0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
};

InputVisibilityLayout default_input_visibility(std::size_t message_length) {
  if (message_length > max_message_bytes)
    throw std::invalid_argument("SHA-256 message exceeds the 550-byte circuit limit");
  return InputVisibilityLayout::all_secret(message_length * 8);
}

} // namespace

class CircuitBuilder {
public:
  explicit CircuitBuilder(Circuit& circuit) : circuit_(circuit) {}

  Wire zero() { return 0; }
  Wire one() { return 1; }
  Wire input(InputVisibility visibility) { return circuit_.input(visibility); }
  Wire xor_(Wire a, Wire b) { return circuit_.xor_wire(a, b); }
  Wire and_(Wire a, Wire b) { return circuit_.and_wire(a, b); }

  Word constant_word(std::uint32_t value) {
    Word out{};
    for (std::size_t i = 0; i != 32; ++i) {
      out[i] = (value >> i) & 1U ? one() : zero();
    }
    return out;
  }

  Word xor_word(const Word& a, const Word& b) {
    Word out{};
    for (std::size_t i = 0; i != 32; ++i) out[i] = xor_(a[i], b[i]);
    return out;
  }

  Word xor_word(const Word& a, const Word& b, const Word& c) {
    return xor_word(xor_word(a, b), c);
  }

  Word rotr(const Word& x, std::size_t amount) {
    Word out{};
    for (std::size_t i = 0; i != 32; ++i) out[i] = x[(i + amount) % 32];
    return out;
  }

  Word shr(const Word& x, std::size_t amount) {
    Word out{};
    for (std::size_t i = 0; i != 32; ++i) {
      out[i] = i + amount < 32 ? x[i + amount] : zero();
    }
    return out;
  }

  Word add(const Word& a, const Word& b) {
    Word sum{};
    Wire carry = zero();
    for (std::size_t i = 0; i != 32; ++i) {
      const Wire propagate = xor_(a[i], b[i]);
      sum[i] = xor_(propagate, carry);
      if (i != 31) {
        // maj(a,b,carry) = a XOR ((a XOR b) AND (a XOR carry)).
        // This is the same full-adder carry as generate/propagate, but has
        // multiplicative complexity one instead of two AND gates per bit.
        carry = xor_(a[i], and_(propagate, xor_(a[i], carry)));
      }
    }
    return sum;
  }

  Word choice(const Word& x, const Word& y, const Word& z) {
    Word out{};
    for (std::size_t i = 0; i != 32; ++i) {
      out[i] = xor_(z[i], and_(x[i], xor_(y[i], z[i])));
    }
    return out;
  }

  Word majority(const Word& x, const Word& y, const Word& z) {
    Word out{};
    for (std::size_t i = 0; i != 32; ++i) {
      // maj(x,y,z) = x XOR ((x XOR y) AND (x XOR z)).
      out[i] = xor_(x[i], and_(xor_(x[i], y[i]), xor_(x[i], z[i])));
    }
    return out;
  }

  Word big_sigma0(const Word& x) { return xor_word(rotr(x, 2), rotr(x, 13), rotr(x, 22)); }
  Word big_sigma1(const Word& x) { return xor_word(rotr(x, 6), rotr(x, 11), rotr(x, 25)); }
  Word small_sigma0(const Word& x) { return xor_word(rotr(x, 7), rotr(x, 18), shr(x, 3)); }
  Word small_sigma1(const Word& x) { return xor_word(rotr(x, 17), rotr(x, 19), shr(x, 10)); }

private:
  Circuit& circuit_;
};

Circuit::Circuit(std::size_t message_length)
    : Circuit(message_length, default_input_visibility(message_length)) {}

Circuit::Circuit(std::size_t message_length,
                 InputVisibilityLayout input_visibility)
    : message_length_(message_length),
      input_visibility_(std::move(input_visibility)) {
  if (message_length > max_message_bytes) {
    throw std::invalid_argument("SHA-256 message exceeds the 550-byte circuit limit");
  }
  if (input_visibility_.message_bits() != message_length * 8)
    throw std::invalid_argument(
        "SHA-256 visibility layout length does not match message length");
  block_count_ = (message_length * 8 + 1 + 64 + 511) / 512;
  CircuitBuilder b(*this);
  const auto multiplication_count = [this]() {
    return static_cast<std::size_t>(std::count_if(
        nodes().begin(), nodes().end(), [](const Node& node) { return node.op == Op::And; }));
  };

  // Secret bytes are supplied in ordinary byte order.  SHA-256 parses each
  // group of four bytes as a big-endian word; Word itself stores LSB first.
  std::vector<std::array<Wire, 8>> message(message_length);
  inputs_.reserve(message_length * 8);
  for (std::size_t byte = 0; byte != message.size(); ++byte) {
    for (std::size_t bit = 0; bit != 8; ++bit) {
      const auto fips_bit = 8 * byte + (7 - bit);
      message[byte][bit] = b.input(input_visibility_.visibility_at(fips_bit));
      inputs_.push_back(message[byte][bit]);
    }
  }

  std::array<Word, 8> chaining{};
  for (std::size_t i = 0; i != 8; ++i) chaining[i] = b.constant_word(initial_state[i]);
  const std::uint64_t bit_length = static_cast<std::uint64_t>(message_length) * 8;

  for (std::size_t block_index = 0; block_index != block_count_; ++block_index) {
    std::array<std::array<Wire, 8>, 64> block{};
    for (std::size_t offset = 0; offset != 64; ++offset) {
      const std::size_t absolute = block_index * 64 + offset;
      if (absolute < message_length) {
        block[offset] = message[absolute];
      } else if (absolute == message_length) {
        block[offset][7] = b.one();
      } else if (absolute >= block_count_ * 64 - 8) {
        const std::size_t length_byte = absolute - (block_count_ * 64 - 8);
        const auto value = static_cast<std::uint8_t>(bit_length >> (8 * (7 - length_byte)));
        for (std::size_t bit = 0; bit != 8; ++bit) {
          block[offset][bit] = ((value >> bit) & 1U) ? b.one() : b.zero();
        }
      }
    }

    const auto schedule_before = multiplication_count();
    std::array<Word, 64> schedule{};
    for (std::size_t word = 0; word != 16; ++word) {
      for (std::size_t byte = 0; byte != 4; ++byte) {
        for (std::size_t bit = 0; bit != 8; ++bit) {
          schedule[word][24 - 8 * byte + bit] = block[4 * word + byte][bit];
        }
      }
    }
    for (std::size_t t = 16; t != 64; ++t) {
      auto value = b.add(b.small_sigma1(schedule[t - 2]), schedule[t - 7]);
      value = b.add(value, b.small_sigma0(schedule[t - 15]));
      schedule[t] = b.add(value, schedule[t - 16]);
    }
    statistics_.schedule_multiplications += multiplication_count() - schedule_before;

    const auto round_before = multiplication_count();
    auto state = chaining;
    for (std::size_t t = 0; t != 64; ++t) {
      auto t1 = b.add(state[7], b.big_sigma1(state[4]));
      t1 = b.add(t1, b.choice(state[4], state[5], state[6]));
      t1 = b.add(t1, schedule[t]);
      t1 = b.add(t1, b.constant_word(round_constants[t]));
      const auto t2 = b.add(b.big_sigma0(state[0]), b.majority(state[0], state[1], state[2]));
      const auto new_a = b.add(t1, t2);
      const auto new_e = b.add(state[3], t1);
      state = {new_a, state[0], state[1], state[2], new_e, state[4], state[5], state[6]};
    }
    statistics_.round_multiplications += multiplication_count() - round_before;

    const auto feed_before = multiplication_count();
    for (std::size_t i = 0; i != 8; ++i) state[i] = b.add(state[i], chaining[i]);
    statistics_.feed_forward_multiplications += multiplication_count() - feed_before;
    chaining = state;
  }

  // Public SHA-256 digest bytes are big-endian.
  for (std::size_t word = 0; word != 8; ++word) {
    for (std::size_t byte = 0; byte != 4; ++byte) {
      for (std::size_t bit = 0; bit != 8; ++bit) {
        outputs_[(4 * word + byte) * 8 + bit] = chaining[word][24 - 8 * byte + bit];
        circuit_.add_output(outputs_[(4 * word + byte) * 8 + bit]);
      }
    }
  }

  statistics_.secret_inputs = secret_input_bits();
  statistics_.public_inputs = public_input_bits();
  statistics_.total_nodes = nodes().size();
  statistics_.xor_gates = std::count_if(nodes().begin(), nodes().end(),
                                        [](const Node& n) { return n.op == Op::Xor; });
  statistics_.multiplication_gates = std::count_if(
      nodes().begin(), nodes().end(), [](const Node& n) { return n.op == Op::And; });

  std::string validation_error;
  if (!circuit_.validate(&validation_error)) {
    throw std::logic_error("generated invalid binary circuit: " + validation_error);
  }
}

std::uint32_t Circuit::input(InputVisibility visibility) {
  return visibility == InputVisibility::Secret
             ? circuit_.private_input()
             : circuit_.public_input();
}

std::uint32_t Circuit::xor_wire(std::uint32_t lhs, std::uint32_t rhs) {
  return circuit_.xor_wire(lhs, rhs);
}

std::uint32_t Circuit::and_wire(std::uint32_t lhs, std::uint32_t rhs) {
  return circuit_.and_wire(lhs, rhs);
}

vole_backend::Evaluation Circuit::evaluate_ir(const Message& message) const {
  const auto inputs = partition_input(message);
  return circuit_.evaluate(inputs.private_bits, inputs.public_bits);
}

PartitionedInput Circuit::partition_input(const Message& message) const {
  return input_visibility_.partition(
      std::span(message.data(), message_length_));
}

Digest Circuit::evaluate(const Message& message) const {
  const auto evaluation = evaluate_ir(message);
  Digest digest{};
  for (std::size_t i = 0; i != outputs_.size(); ++i) {
    if (evaluation.outputs[i]) digest[i / 8] |= static_cast<std::uint8_t>(1U << (i % 8));
  }
  return digest;
}

std::vector<std::uint8_t> Circuit::multiplication_witness(const Message& message) const {
  return evaluate_ir(message).multiplication_outputs;
}

bool Circuit::verify_statement(const Message& message, const Digest& claimed_digest) const {
  if (std::any_of(message.begin() + static_cast<std::ptrdiff_t>(message_length_), message.end(),
                  [](std::uint8_t byte) { return byte != 0; })) return false;
  return evaluate(message) == claimed_digest;
}

} // namespace faest::sha256_circuit
