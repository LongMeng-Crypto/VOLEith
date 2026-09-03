/* SPDX-License-Identifier: MIT */

#include "../backend/circuit_format.hpp"
#include "../backend/generic_nizk.hpp"
#include "../circuits/sha2/sha384_circuit.hpp"
#include "../circuits/sha2/sha512_circuit.hpp"

#include <boost/test/unit_test.hpp>
#include <openssl/evp.h>

#include <algorithm>
#include <array>
#include <cstdint>
#include <span>
#include <stdexcept>
#include <string>
#include <string_view>
#include <vector>

namespace {

std::vector<std::uint8_t> from_hex(std::string_view text) {
  const auto nibble = [](char value) -> std::uint8_t {
    if (value >= '0' && value <= '9')
      return static_cast<std::uint8_t>(value - '0');
    if (value >= 'a' && value <= 'f')
      return static_cast<std::uint8_t>(value - 'a' + 10);
    throw std::invalid_argument("invalid test hex");
  };
  if (text.size() % 2 != 0) throw std::invalid_argument("odd test hex");
  std::vector<std::uint8_t> result(text.size() / 2);
  for (std::size_t i = 0; i != result.size(); ++i)
    result[i] = static_cast<std::uint8_t>(
        (nibble(text[2 * i]) << 4) | nibble(text[2 * i + 1]));
  return result;
}

std::vector<std::uint8_t> openssl_digest(
    std::span<const std::uint8_t> message, const EVP_MD* algorithm,
    std::size_t digest_bytes) {
  std::vector<std::uint8_t> digest(digest_bytes);
  unsigned int output_size = 0;
  if (EVP_Digest(message.data(), message.size(), digest.data(), &output_size,
                 algorithm, nullptr) != 1 || output_size != digest.size())
    throw std::runtime_error("OpenSSL digest failed in test");
  return digest;
}

std::vector<std::uint8_t> unpack_bytes(
    std::span<const std::uint8_t> bytes) {
  std::vector<std::uint8_t> bits(bytes.size() * 8);
  for (std::size_t i = 0; i != bits.size(); ++i)
    bits[i] = static_cast<std::uint8_t>((bytes[i / 8] >> (i % 8)) & 1U);
  return bits;
}

template<class Circuit>
void check_against_openssl(std::size_t length, const EVP_MD* algorithm,
                           std::size_t digest_bytes) {
  std::vector<std::uint8_t> message(length);
  for (std::size_t i = 0; i != length; ++i)
    message[i] = static_cast<std::uint8_t>(17 * i + length);
  const Circuit circuit(length);
  const auto expected = openssl_digest(message, algorithm, digest_bytes);
  BOOST_TEST(circuit.evaluate(message) == expected,
             "message_length=" << length);
  BOOST_TEST(circuit.verify_statement(message, expected));
  BOOST_TEST(circuit.block_count() ==
             (length * 8 + 1 + 128 + 1023) / 1024);
}

template<class Circuit>
void check_mixed_visibility_proof(
    std::size_t message_length, std::size_t secret_bits,
    std::size_t digest_bytes, const EVP_MD* algorithm,
    vole_backend::SecurityLevel security) {
  const auto layout = vole_circuits::InputVisibilityLayout::parse(
      message_length * 8,
      "secret:0:" + std::to_string(secret_bits) + ",public:" +
          std::to_string(secret_bits) + ":" +
          std::to_string(message_length * 8));
  const Circuit circuit(message_length, layout);
  std::vector<std::uint8_t> message(message_length);
  for (std::size_t i = 0; i != message.size(); ++i)
    message[i] = static_cast<std::uint8_t>(9 * i + 5);
  const auto expected = openssl_digest(message, algorithm, digest_bytes);
  const auto partitioned = circuit.partition_input(message);
  BOOST_TEST(partitioned.private_bits.size() == secret_bits);
  BOOST_TEST(partitioned.public_bits.size() ==
             message_length * 8 - secret_bits);

  const vole_backend::PublicStatement statement{
      partitioned.public_bits, unpack_bytes(expected)};
  const std::array<std::uint8_t, 21> context = {
      's','h','a','5','1','2','-','f','a','m','i','l','y','-','e','2','e','-','v','1','!'};
  vole_backend::ProverRandomness randomness{};
  for (std::size_t i = 0; i != randomness.size(); ++i)
    randomness[i] = static_cast<std::uint8_t>(0x31 + i);
  const vole_backend::PreparedBinaryCircuit prepared(circuit.binary_circuit());
  for (const auto profile : {vole_backend::VoleProfile::Small,
                             vole_backend::VoleProfile::Fast}) {
    const auto proof = vole_backend::prove(
        prepared, security, profile, partitioned.private_bits, statement,
        context, randomness);
    BOOST_TEST(vole_backend::verify(prepared, security, profile, statement,
                                    context, proof));

    auto wrong_public = statement;
    wrong_public.public_inputs.back() ^= 1;
    BOOST_TEST(!vole_backend::verify(prepared, security, profile,
                                     wrong_public, context, proof));
    auto wrong_digest = statement;
    wrong_digest.expected_outputs.front() ^= 1;
    BOOST_TEST(!vole_backend::verify(prepared, security, profile,
                                     wrong_digest, context, proof));
  }
}

} // namespace

BOOST_AUTO_TEST_SUITE(sha512_family_binary_circuit)

BOOST_AUTO_TEST_CASE(sha384_known_answer_tests) {
  const std::vector<std::uint8_t> empty;
  const vole_circuits::sha2::Sha384Circuit empty_circuit(0);
  BOOST_TEST(empty_circuit.evaluate(empty) == from_hex(
      "38b060a751ac96384cd9327eb1b1e36a21fdb71114be07434c0cc7bf63f6e1da"
      "274edebfe76f65fbd51ad2f14898b95b"));

  const std::vector<std::uint8_t> abc{'a', 'b', 'c'};
  const vole_circuits::sha2::Sha384Circuit abc_circuit(abc.size());
  BOOST_TEST(abc_circuit.evaluate(abc) == from_hex(
      "cb00753f45a35e8bb5a03d699ac65007272c32ab0eded1631a8b605a43ff5bed"
      "8086072ba1e7cc2358baeca134c825a7"));
}

BOOST_AUTO_TEST_CASE(sha512_known_answer_tests) {
  const std::vector<std::uint8_t> empty;
  const vole_circuits::sha2::Sha512Circuit empty_circuit(0);
  BOOST_TEST(empty_circuit.evaluate(empty) == from_hex(
      "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce"
      "47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e"));

  const std::vector<std::uint8_t> abc{'a', 'b', 'c'};
  const vole_circuits::sha2::Sha512Circuit abc_circuit(abc.size());
  BOOST_TEST(abc_circuit.evaluate(abc) == from_hex(
      "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2"
      "192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f"));
}

BOOST_AUTO_TEST_CASE(padding_boundaries_and_multiblock_match_openssl) {
  constexpr std::array<std::size_t, 7> lengths = {
      0, 1, 111, 112, 128, 239, 240};
  for (const auto length : lengths) {
    check_against_openssl<vole_circuits::sha2::Sha384Circuit>(
        length, EVP_sha384(), 48);
    check_against_openssl<vole_circuits::sha2::Sha512Circuit>(
        length, EVP_sha512(), 64);
  }
}

BOOST_AUTO_TEST_CASE(structure_and_canonical_vbc_round_trip) {
  const vole_circuits::sha2::Sha384Circuit sha384(72);
  const vole_circuits::sha2::Sha512Circuit sha512(96);
  for (const auto* circuit :
       {&sha384.binary_circuit(), &sha512.binary_circuit()}) {
    const auto encoded = vole_backend::serialize_vbc(*circuit);
    const auto decoded = vole_backend::deserialize_vbc(encoded);
    BOOST_TEST(vole_backend::serialize_vbc(decoded) == encoded);
    BOOST_TEST(vole_backend::circuit_hash(decoded) ==
               vole_backend::circuit_hash(*circuit));
  }
  BOOST_TEST(sha384.binary_circuit().outputs().size() == 384U);
  BOOST_TEST(sha512.binary_circuit().outputs().size() == 512U);
  BOOST_TEST(sha384.statistics().multiplication_gates == 55890U);
  BOOST_TEST(sha384.statistics().xor_gates == 236354U);
  BOOST_TEST(sha384.statistics().schedule_multiplications == 10893U);
  BOOST_TEST(sha384.statistics().round_multiplications == 44622U);
  BOOST_TEST(sha384.statistics().feed_forward_multiplications == 375U);
  BOOST_TEST(sha512.statistics().multiplication_gates == 56764U);
  BOOST_TEST(sha512.statistics().xor_gates == 240250U);
  BOOST_TEST(sha512.statistics().schedule_multiplications == 11455U);
  BOOST_TEST(sha512.statistics().round_multiplications == 44808U);
  BOOST_TEST(sha512.statistics().feed_forward_multiplications == 501U);
  BOOST_TEST(sha384.statistics().schedule_multiplications +
                 sha384.statistics().round_multiplications +
                 sha384.statistics().feed_forward_multiplications ==
             sha384.statistics().multiplication_gates);
  BOOST_TEST(sha512.statistics().schedule_multiplications +
                 sha512.statistics().round_multiplications +
                 sha512.statistics().feed_forward_multiplications ==
             sha512.statistics().multiplication_gates);
  BOOST_TEST_MESSAGE(
      "SHA-384/72 bytes: " << sha384.statistics().multiplication_gates
                            << " AND, " << sha384.statistics().xor_gates
                            << " XOR; SHA-512/96 bytes: "
                            << sha512.statistics().multiplication_gates
                            << " AND, " << sha512.statistics().xor_gates
                            << " XOR");
}

BOOST_AUTO_TEST_CASE(core_accepts_existing_wires_without_registering_outputs) {
  vole_backend::BinaryCircuit circuit;
  const std::array<std::uint8_t, 3> message{'a', 'b', 'c'};
  std::vector<vole_backend::Wire> message_fips_bits(message.size() * 8);
  std::vector<std::uint8_t> private_bits;
  for (std::size_t byte = 0; byte != message.size(); ++byte) {
    for (std::size_t storage_bit = 0; storage_bit != 8; ++storage_bit) {
      message_fips_bits[8 * byte + (7 - storage_bit)] =
          circuit.private_input();
      private_bits.push_back(
          static_cast<std::uint8_t>((message[byte] >> storage_bit) & 1U));
    }
  }
  const auto digest = vole_circuits::sha2::build_sha512_family(
      circuit, message_fips_bits,
      vole_circuits::sha2::Sha512Variant::Sha512);
  BOOST_TEST(circuit.statistics().private_inputs == 24U);
  BOOST_TEST(circuit.outputs().empty());
  BOOST_TEST(digest.fips_bits.size() == 512U);
  vole_circuits::sha2::add_sha2_digest_outputs(circuit, digest);
  const auto evaluation = circuit.evaluate(private_bits);
  std::vector<std::uint8_t> actual(64, 0);
  for (std::size_t bit = 0; bit != evaluation.outputs.size(); ++bit)
    actual[bit / 8] |= static_cast<std::uint8_t>(evaluation.outputs[bit]
                                                 << (bit % 8));
  BOOST_TEST(actual == openssl_digest(message, EVP_sha512(), 64));
}

BOOST_AUTO_TEST_CASE(non_byte_aligned_visibility_uses_shared_layout) {
  const auto layout = vole_circuits::InputVisibilityLayout::parse(
      16, "public:0:1,secret:1:9,public:9:16");
  const vole_circuits::sha2::Sha512Circuit circuit(2, layout);
  const std::array<std::uint8_t, 2> message{0xa5, 0x3c};
  const auto partitioned = circuit.partition_input(message);
  BOOST_TEST(vole_circuits::pack_input_bits(partitioned.private_bits) ==
             std::vector<std::uint8_t>{0x25});
  BOOST_TEST(vole_circuits::pack_input_bits(partitioned.public_bits) ==
             std::vector<std::uint8_t>{0x79});
  BOOST_TEST(circuit.evaluate(message) ==
             openssl_digest(message, EVP_sha512(), 64));
}

BOOST_AUTO_TEST_CASE(mixed_visibility_end_to_end_proofs) {
  check_mixed_visibility_proof<vole_circuits::sha2::Sha384Circuit>(
      72, 192, 48, EVP_sha384(), vole_backend::SecurityLevel::Bits192);
  check_mixed_visibility_proof<vole_circuits::sha2::Sha512Circuit>(
      96, 256, 64, EVP_sha512(), vole_backend::SecurityLevel::Bits256);
}

BOOST_AUTO_TEST_SUITE_END()
