/* SPDX-License-Identifier: MIT */

#include "sha512_family.hpp"

#include <algorithm>
#include <array>
#include <stdexcept>
#include <unordered_map>
#include <utility>

namespace vole_circuits::sha2 {
namespace {

using Wire = vole_backend::Wire;
using Word = std::array<Wire, 64>;

constexpr std::array<std::uint64_t, 8> sha384_initial_state = {
    0xcbbb9d5dc1059ed8ULL, 0x629a292a367cd507ULL,
    0x9159015a3070dd17ULL, 0x152fecd8f70e5939ULL,
    0x67332667ffc00b31ULL, 0x8eb44a8768581511ULL,
    0xdb0c2e0d64f98fa7ULL, 0x47b5481dbefa4fa4ULL,
};

constexpr std::array<std::uint64_t, 8> sha512_initial_state = {
    0x6a09e667f3bcc908ULL, 0xbb67ae8584caa73bULL,
    0x3c6ef372fe94f82bULL, 0xa54ff53a5f1d36f1ULL,
    0x510e527fade682d1ULL, 0x9b05688c2b3e6c1fULL,
    0x1f83d9abfb41bd6bULL, 0x5be0cd19137e2179ULL,
};

constexpr std::array<std::uint64_t, 80> round_constants = {
    0x428a2f98d728ae22ULL, 0x7137449123ef65cdULL,
    0xb5c0fbcfec4d3b2fULL, 0xe9b5dba58189dbbcULL,
    0x3956c25bf348b538ULL, 0x59f111f1b605d019ULL,
    0x923f82a4af194f9bULL, 0xab1c5ed5da6d8118ULL,
    0xd807aa98a3030242ULL, 0x12835b0145706fbeULL,
    0x243185be4ee4b28cULL, 0x550c7dc3d5ffb4e2ULL,
    0x72be5d74f27b896fULL, 0x80deb1fe3b1696b1ULL,
    0x9bdc06a725c71235ULL, 0xc19bf174cf692694ULL,
    0xe49b69c19ef14ad2ULL, 0xefbe4786384f25e3ULL,
    0x0fc19dc68b8cd5b5ULL, 0x240ca1cc77ac9c65ULL,
    0x2de92c6f592b0275ULL, 0x4a7484aa6ea6e483ULL,
    0x5cb0a9dcbd41fbd4ULL, 0x76f988da831153b5ULL,
    0x983e5152ee66dfabULL, 0xa831c66d2db43210ULL,
    0xb00327c898fb213fULL, 0xbf597fc7beef0ee4ULL,
    0xc6e00bf33da88fc2ULL, 0xd5a79147930aa725ULL,
    0x06ca6351e003826fULL, 0x142929670a0e6e70ULL,
    0x27b70a8546d22ffcULL, 0x2e1b21385c26c926ULL,
    0x4d2c6dfc5ac42aedULL, 0x53380d139d95b3dfULL,
    0x650a73548baf63deULL, 0x766a0abb3c77b2a8ULL,
    0x81c2c92e47edaee6ULL, 0x92722c851482353bULL,
    0xa2bfe8a14cf10364ULL, 0xa81a664bbc423001ULL,
    0xc24b8b70d0f89791ULL, 0xc76c51a30654be30ULL,
    0xd192e819d6ef5218ULL, 0xd69906245565a910ULL,
    0xf40e35855771202aULL, 0x106aa07032bbd1b8ULL,
    0x19a4c116b8d2d0c8ULL, 0x1e376c085141ab53ULL,
    0x2748774cdf8eeb99ULL, 0x34b0bcb5e19b48a8ULL,
    0x391c0cb3c5c95a63ULL, 0x4ed8aa4ae3418acbULL,
    0x5b9cca4f7763e373ULL, 0x682e6ff3d6b2b8a3ULL,
    0x748f82ee5defb2fcULL, 0x78a5636f43172f60ULL,
    0x84c87814a1f0ab72ULL, 0x8cc702081a6439ecULL,
    0x90befffa23631e28ULL, 0xa4506cebde82bde9ULL,
    0xbef9a3f7b2c67915ULL, 0xc67178f2e372532bULL,
    0xca273eceea26619cULL, 0xd186b8c721c0c207ULL,
    0xeada7dd6cde0eb1eULL, 0xf57d4f7fee6ed178ULL,
    0x06f067aa72176fbaULL, 0x0a637dc5a2c898a6ULL,
    0x113f9804bef90daeULL, 0x1b710b35131c471bULL,
    0x28db77f523047d84ULL, 0x32caab7b40c72493ULL,
    0x3c9ebe0a15c9bebcULL, 0x431d67c49c100d4cULL,
    0x4cc5d4becb3e42b6ULL, 0x597f299cfc657e2aULL,
    0x5fcb6fab3ad6faecULL, 0x6c44198c4a475817ULL,
};

const std::array<std::uint64_t, 8>& initial_state(Sha512Variant variant) {
  return variant == Sha512Variant::Sha384 ? sha384_initial_state
                                          : sha512_initial_state;
}

std::size_t output_words(Sha512Variant variant) {
  return variant == Sha512Variant::Sha384 ? 6 : 8;
}

class CoreBuilder {
public:
  explicit CoreBuilder(vole_backend::BinaryCircuit& circuit)
      : circuit_(circuit) {}

  Wire zero() const { return vole_backend::BinaryCircuit::zero(); }
  Wire one() const { return vole_backend::BinaryCircuit::one(); }

  Wire xor_(Wire lhs, Wire rhs) {
    if (lhs > rhs) std::swap(lhs, rhs);
    const auto key = key_for(lhs, rhs);
    if (const auto found = xor_cache_.find(key); found != xor_cache_.end())
      return found->second;
    const auto result = circuit_.xor_wire(lhs, rhs);
    xor_cache_.emplace(key, result);
    return result;
  }

  Wire and_(Wire lhs, Wire rhs) {
    if (lhs > rhs) std::swap(lhs, rhs);
    const auto key = key_for(lhs, rhs);
    if (const auto found = and_cache_.find(key); found != and_cache_.end())
      return found->second;
    const auto before = circuit_.nodes().size();
    const auto result = circuit_.and_wire(lhs, rhs);
    if (circuit_.nodes().size() != before) ++multiplications_;
    and_cache_.emplace(key, result);
    return result;
  }

  std::size_t multiplications() const { return multiplications_; }

  Word constant_word(std::uint64_t value) const {
    Word out{};
    for (std::size_t bit = 0; bit != out.size(); ++bit)
      out[bit] = ((value >> bit) & 1ULL) != 0 ? one() : zero();
    return out;
  }

  Word xor_word(const Word& lhs, const Word& rhs) {
    Word out{};
    for (std::size_t bit = 0; bit != out.size(); ++bit)
      out[bit] = xor_(lhs[bit], rhs[bit]);
    return out;
  }

  Word xor_word(const Word& a, const Word& b, const Word& c) {
    return xor_word(xor_word(a, b), c);
  }

  Word rotr(const Word& value, std::size_t amount) const {
    Word out{};
    for (std::size_t bit = 0; bit != out.size(); ++bit)
      out[bit] = value[(bit + amount) % value.size()];
    return out;
  }

  Word shr(const Word& value, std::size_t amount) const {
    Word out{};
    for (std::size_t bit = 0; bit != out.size(); ++bit)
      out[bit] = bit + amount < value.size() ? value[bit + amount]
                                             : zero();
    return out;
  }

  Word add(const Word& lhs, const Word& rhs) {
    Word sum{};
    Wire carry = zero();
    for (std::size_t bit = 0; bit != sum.size(); ++bit) {
      const auto propagate = xor_(lhs[bit], rhs[bit]);
      sum[bit] = xor_(propagate, carry);
      if (bit + 1 != sum.size()) {
        // maj(lhs,rhs,carry) with multiplicative complexity one.
        carry = xor_(lhs[bit],
                     and_(propagate, xor_(lhs[bit], carry)));
      }
    }
    return sum;
  }

  Word choice(const Word& x, const Word& y, const Word& z) {
    Word out{};
    for (std::size_t bit = 0; bit != out.size(); ++bit)
      out[bit] = xor_(z[bit], and_(x[bit], xor_(y[bit], z[bit])));
    return out;
  }

  Word majority(const Word& x, const Word& y, const Word& z) {
    Word out{};
    for (std::size_t bit = 0; bit != out.size(); ++bit) {
      out[bit] = xor_(x[bit],
                      and_(xor_(x[bit], y[bit]), xor_(x[bit], z[bit])));
    }
    return out;
  }

  Word big_sigma0(const Word& x) {
    return xor_word(rotr(x, 28), rotr(x, 34), rotr(x, 39));
  }
  Word big_sigma1(const Word& x) {
    return xor_word(rotr(x, 14), rotr(x, 18), rotr(x, 41));
  }
  Word small_sigma0(const Word& x) {
    return xor_word(rotr(x, 1), rotr(x, 8), shr(x, 7));
  }
  Word small_sigma1(const Word& x) {
    return xor_word(rotr(x, 19), rotr(x, 61), shr(x, 6));
  }

private:
  static std::uint64_t key_for(Wire lhs, Wire rhs) {
    return (static_cast<std::uint64_t>(lhs) << 32) | rhs;
  }

  vole_backend::BinaryCircuit& circuit_;
  std::unordered_map<std::uint64_t, Wire> xor_cache_;
  std::unordered_map<std::uint64_t, Wire> and_cache_;
  std::size_t multiplications_ = 0;
};

} // namespace

DigestWires build_sha512_family(
    vole_backend::BinaryCircuit& circuit,
    std::span<const vole_backend::Wire> message_fips_bits,
    Sha512Variant variant, CoreStatistics* statistics) {
  if (message_fips_bits.size() > sha512_family_max_message_bytes * 8)
    throw std::invalid_argument("SHA-512-family message exceeds circuit limit");
  if (std::any_of(message_fips_bits.begin(), message_fips_bits.end(),
                  [&circuit](Wire wire) {
                    return wire >= circuit.nodes().size();
                  }))
    throw std::invalid_argument("SHA-512-family message wire is out of range");

  CoreBuilder b(circuit);
  CoreStatistics local_statistics{};
  const auto block_count =
      (message_fips_bits.size() + 1 + 128 + 1023) / 1024;
  std::vector<Wire> padded(block_count * 1024, b.zero());
  std::copy(message_fips_bits.begin(), message_fips_bits.end(),
            padded.begin());
  padded[message_fips_bits.size()] = b.one();

  // Practical circuit sizes fit in size_t, so the high 64 bits of SHA-512's
  // 128-bit length field are zero. Encode the low half in big-endian bit order.
  const auto bit_length = static_cast<std::uint64_t>(message_fips_bits.size());
  for (std::size_t bit = 0; bit != 64; ++bit) {
    padded[padded.size() - 1 - bit] =
        ((bit_length >> bit) & 1ULL) != 0 ? b.one() : b.zero();
  }

  std::array<Word, 8> chaining{};
  const auto& iv = initial_state(variant);
  for (std::size_t word = 0; word != chaining.size(); ++word)
    chaining[word] = b.constant_word(iv[word]);

  for (std::size_t block = 0; block != block_count; ++block) {
    const auto schedule_before = b.multiplications();
    std::array<Word, 80> schedule{};
    for (std::size_t word = 0; word != 16; ++word) {
      for (std::size_t fips_bit = 0; fips_bit != 64; ++fips_bit) {
        schedule[word][63 - fips_bit] =
            padded[block * 1024 + word * 64 + fips_bit];
      }
    }
    for (std::size_t round = 16; round != schedule.size(); ++round) {
      auto value = b.add(b.small_sigma1(schedule[round - 2]),
                         schedule[round - 7]);
      value = b.add(value, b.small_sigma0(schedule[round - 15]));
      schedule[round] = b.add(value, schedule[round - 16]);
    }
    local_statistics.schedule_multiplications +=
        b.multiplications() - schedule_before;

    const auto rounds_before = b.multiplications();
    auto state = chaining;
    for (std::size_t round = 0; round != schedule.size(); ++round) {
      auto t1 = b.add(state[7], b.big_sigma1(state[4]));
      t1 = b.add(t1, b.choice(state[4], state[5], state[6]));
      t1 = b.add(t1, schedule[round]);
      t1 = b.add(t1, b.constant_word(round_constants[round]));
      const auto t2 =
          b.add(b.big_sigma0(state[0]),
                b.majority(state[0], state[1], state[2]));
      const auto new_a = b.add(t1, t2);
      const auto new_e = b.add(state[3], t1);
      state = {new_a, state[0], state[1], state[2],
               new_e, state[4], state[5], state[6]};
    }
    local_statistics.round_multiplications +=
        b.multiplications() - rounds_before;

    const auto feed_before = b.multiplications();
    const bool final_block = block + 1 == block_count;
    const auto feed_words =
        final_block ? output_words(variant) : chaining.size();
    for (std::size_t word = 0; word != feed_words; ++word)
      state[word] = b.add(state[word], chaining[word]);
    local_statistics.feed_forward_multiplications +=
        b.multiplications() - feed_before;
    chaining = state;
  }

  DigestWires result;
  result.fips_bits.reserve(output_words(variant) * 64);
  for (std::size_t word = 0; word != output_words(variant); ++word) {
    for (std::size_t fips_bit = 0; fips_bit != 64; ++fips_bit)
      result.fips_bits.push_back(chaining[word][63 - fips_bit]);
  }
  if (statistics != nullptr) *statistics = local_statistics;
  return result;
}

void add_sha2_digest_outputs(vole_backend::BinaryCircuit& circuit,
                             const DigestWires& digest) {
  if (digest.fips_bits.size() % 8 != 0)
    throw std::invalid_argument("SHA-2 digest wire count is not byte aligned");
  for (std::size_t byte = 0; byte != digest.fips_bits.size() / 8; ++byte) {
    for (std::size_t storage_bit = 0; storage_bit != 8; ++storage_bit)
      circuit.add_output(digest.fips_bits[8 * byte + (7 - storage_bit)]);
  }
}

Sha512FamilyCircuit::Sha512FamilyCircuit(
    Sha512Variant variant, std::size_t message_length,
    InputVisibilityLayout input_visibility)
    : message_length_(message_length), variant_(variant),
      input_visibility_(std::move(input_visibility)) {
  if (message_length > sha512_family_max_message_bytes)
    throw std::invalid_argument(
        "SHA-512-family message exceeds 1100-byte circuit limit");
  if (input_visibility_.message_bits() != message_length * 8)
    throw std::invalid_argument(
        "SHA-512-family visibility layout length does not match message length");
  block_count_ = (message_length * 8 + 1 + 128 + 1023) / 1024;

  std::vector<Wire> message_fips_bits(message_length * 8);
  for (std::size_t byte = 0; byte != message_length; ++byte) {
    // Preserve the generic backend's packed input convention: input nodes are
    // allocated least-significant bit first within each byte.
    for (std::size_t storage_bit = 0; storage_bit != 8; ++storage_bit) {
      const auto fips_bit = 8 * byte + (7 - storage_bit);
      const auto visibility = input_visibility_.visibility_at(fips_bit);
      message_fips_bits[fips_bit] =
          visibility == InputVisibility::Secret ? circuit_.private_input()
                                                : circuit_.public_input();
    }
  }

  CoreStatistics core_statistics{};
  const auto digest = build_sha512_family(
      circuit_, message_fips_bits, variant_, &core_statistics);
  add_sha2_digest_outputs(circuit_, digest);
  output_wires_ = circuit_.outputs();

  const auto circuit_statistics = circuit_.statistics();
  statistics_.secret_inputs = circuit_statistics.private_inputs;
  statistics_.public_inputs = circuit_statistics.public_inputs;
  statistics_.xor_gates = circuit_statistics.xor_gates;
  statistics_.multiplication_gates =
      circuit_statistics.multiplication_gates;
  statistics_.schedule_multiplications =
      core_statistics.schedule_multiplications;
  statistics_.round_multiplications =
      core_statistics.round_multiplications;
  statistics_.feed_forward_multiplications =
      core_statistics.feed_forward_multiplications;
  statistics_.total_nodes = circuit_statistics.total_nodes;

  std::string validation_error;
  if (!circuit_.validate(&validation_error))
    throw std::logic_error("generated invalid SHA-512-family circuit: " +
                           validation_error);
}

std::size_t Sha512FamilyCircuit::digest_bytes() const {
  return variant_ == Sha512Variant::Sha384 ? 48 : 64;
}

PartitionedInput Sha512FamilyCircuit::partition_input(
    std::span<const std::uint8_t> message) const {
  if (message.size() != message_length_)
    throw std::invalid_argument("SHA-512-family message length mismatch");
  return input_visibility_.partition(message);
}

vole_backend::Evaluation Sha512FamilyCircuit::evaluate_ir(
    std::span<const std::uint8_t> message) const {
  const auto inputs = partition_input(message);
  return circuit_.evaluate(inputs.private_bits, inputs.public_bits);
}

std::vector<std::uint8_t> Sha512FamilyCircuit::evaluate(
    std::span<const std::uint8_t> message) const {
  const auto evaluation = evaluate_ir(message);
  std::vector<std::uint8_t> digest(digest_bytes(), 0);
  for (std::size_t bit = 0; bit != evaluation.outputs.size(); ++bit) {
    if (evaluation.outputs[bit])
      digest[bit / 8] |= static_cast<std::uint8_t>(1U << (bit % 8));
  }
  return digest;
}

std::vector<std::uint8_t> Sha512FamilyCircuit::multiplication_witness(
    std::span<const std::uint8_t> message) const {
  return evaluate_ir(message).multiplication_outputs;
}

bool Sha512FamilyCircuit::verify_statement(
    std::span<const std::uint8_t> message,
    std::span<const std::uint8_t> claimed_digest) const {
  return claimed_digest.size() == digest_bytes() &&
         evaluate(message) ==
             std::vector<std::uint8_t>(claimed_digest.begin(),
                                       claimed_digest.end());
}

} // namespace vole_circuits::sha2
