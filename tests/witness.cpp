/* SPDX-License-Identifier: MIT */

#include "../circuits/sha2/sha256/witness.hpp"

#include <boost/test/unit_test.hpp>
#include <algorithm>

using faest::sha256_circuit::Circuit;
using faest::sha256_circuit::Digest;
using faest::sha256_circuit::Message;

BOOST_AUTO_TEST_SUITE(vole_sha256_witness)

BOOST_AUTO_TEST_CASE(pack_unpack_and_verify) {
  const Circuit circuit;
  Message message{};
  std::fill_n(message.begin(), 55, static_cast<std::uint8_t>('a'));
  const Digest digest = {
      0x9f, 0x43, 0x90, 0xf8, 0xd3, 0x0c, 0x2d, 0xd9,
      0x2e, 0xc9, 0xf0, 0x95, 0xb6, 0x5e, 0x2b, 0x9a,
      0xe9, 0xb0, 0xa9, 0x25, 0xa5, 0x25, 0x8e, 0x24,
      0x1c, 0x9f, 0x1e, 0x91, 0x0f, 0x73, 0x43, 0x18,
  };

  const auto packed = vole_sha256::build_witness(circuit, message);
  const auto layout = vole_sha256::witness_layout(circuit);
  const auto unpacked = vole_sha256::unpack_witness(circuit, packed);
  BOOST_TEST(packed.size() == 2833U);
  BOOST_TEST(layout.logical_bits == 22657U);
  BOOST_TEST(layout.transport_padding_bits == 7U);
  BOOST_TEST(unpacked.secret_message == message);
  BOOST_TEST(unpacked.multiplication_outputs.size() == 22217U);
  BOOST_TEST(vole_sha256::transport_padding_is_zero(circuit, packed));
  BOOST_TEST(vole_sha256::verify_witness(circuit, packed, digest));
}

BOOST_AUTO_TEST_CASE(tampering_is_rejected) {
  const Circuit circuit;
  Message message{};
  const auto digest = circuit.evaluate(message);

  auto bad_product = vole_sha256::build_witness(circuit, message);
  const std::size_t product_bit = circuit.secret_input_bits() + 12345;
  bad_product[product_bit / 8] ^= static_cast<std::uint8_t>(1U << (product_bit % 8));
  BOOST_TEST(!vole_sha256::verify_witness(circuit, bad_product, digest));

  auto bad_padding = vole_sha256::build_witness(circuit, message);
  const auto layout = vole_sha256::witness_layout(circuit);
  bad_padding[layout.logical_bits / 8] ^=
      static_cast<std::uint8_t>(1U << (layout.logical_bits % 8));
  BOOST_TEST(!vole_sha256::transport_padding_is_zero(circuit, bad_padding));
  BOOST_TEST(!vole_sha256::verify_witness(circuit, bad_padding, digest));

  auto wrong_digest = digest;
  wrong_digest[9] ^= 0x20;
  const auto valid = vole_sha256::build_witness(circuit, message);
  BOOST_TEST(!vole_sha256::verify_witness(circuit, valid, wrong_digest));
}

BOOST_AUTO_TEST_SUITE_END()
