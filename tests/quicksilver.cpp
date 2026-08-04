/* SPDX-License-Identifier: MIT */

#include "../backend/vole/quicksilver.hpp"

#include <boost/test/unit_test.hpp>

namespace qs = vole_backend::quicksilver;
using vole_backend::Gf128;

namespace {

qs::ProverWire wire(bool value, std::uint64_t lo, std::uint64_t hi) {
  return {value, {lo, hi}};
}

} // namespace

BOOST_AUTO_TEST_SUITE(vole_sha256_quicksilver)

BOOST_AUTO_TEST_CASE(field_sanity) {
  const Gf128 zero{};
  const Gf128 one = Gf128::from_bit(true);
  const Gf128 x{0x0123456789abcdefULL, 0xfedcba9876543210ULL};
  BOOST_TEST(x * zero == zero);
  BOOST_TEST(x * one == x);
  BOOST_TEST(x * x + x * x == zero);

  // X^128 = X^7+X^2+X+1 in the FAEST polynomial basis.
  const Gf128 x127{0, 0x8000000000000000ULL};
  const Gf128 polynomial_x{2, 0};
  const Gf128 reduced{0x87, 0};
  BOOST_TEST(x127 * polynomial_x == reduced);
}

BOOST_AUTO_TEST_CASE(all_multiplication_truth_table_rows) {
  const Gf128 delta{0x1020304050607081ULL, 0x8877665544332211ULL};
  for (unsigned int xb = 0; xb != 2; ++xb) {
    for (unsigned int yb = 0; yb != 2; ++yb) {
      const auto x = wire(xb, 0x1111 + xb, 0xaaaa);
      const auto y = wire(yb, 0x2222 + yb, 0xbbbb);
      const auto z = wire(xb & yb, 0x3333 + xb + yb, 0xcccc);
      const auto polynomial = qs::multiplication_constraint(x, y, z);
      const auto verifier = qs::multiplication_constraint(
          qs::authenticate(x, delta), qs::authenticate(y, delta), qs::authenticate(z, delta),
          delta);

      BOOST_TEST(polynomial.degree2 == Gf128{});
      BOOST_TEST(qs::evaluate_proof(polynomial, delta) == verifier);
      BOOST_TEST(qs::evaluate_full(polynomial, delta) == verifier);
    }
  }
}

BOOST_AUTO_TEST_CASE(invalid_multiplication_is_rejected) {
  const Gf128 delta{0xabcdef1234567891ULL, 0x13579bdf2468ace0ULL};
  const auto x = wire(true, 0x111, 0x222);
  const auto y = wire(true, 0x333, 0x444);
  const auto bad_z = wire(false, 0x555, 0x666);
  const auto polynomial = qs::multiplication_constraint(x, y, bad_z);
  const auto verifier = qs::multiplication_constraint(
      qs::authenticate(x, delta), qs::authenticate(y, delta),
      qs::authenticate(bad_z, delta), delta);

  BOOST_TEST(polynomial.degree2 == Gf128::from_bit(true));
  BOOST_TEST(qs::evaluate_full(polynomial, delta) == verifier);
  BOOST_TEST(qs::evaluate_proof(polynomial, delta) != verifier);
}

BOOST_AUTO_TEST_CASE(linear_public_statement_constraint) {
  const Gf128 delta{0x7777777777777777ULL, 0x123456789abcdef0ULL};
  const auto x = wire(true, 0x1234, 0x5678);
  const auto key = qs::authenticate(x, delta);

  const auto valid = qs::linear_constraint(x, true);
  BOOST_TEST(valid.degree2 == Gf128{});
  BOOST_TEST(qs::evaluate_proof(valid, delta) == qs::linear_constraint(key, true, delta));

  const auto invalid = qs::linear_constraint(x, false);
  BOOST_TEST(invalid.degree2 == Gf128::from_bit(true));
  BOOST_TEST(qs::evaluate_proof(invalid, delta) != qs::linear_constraint(key, false, delta));
}

BOOST_AUTO_TEST_CASE(random_linear_aggregation) {
  const Gf128 delta{0xdeadbeef01234567ULL, 0x89abcdef76543210ULL};
  const Gf128 challenge{0x3141592653589793ULL, 0x2384626433832795ULL};
  qs::ProverAccumulator prover(challenge);
  qs::VerifierAccumulator verifier(challenge);

  for (unsigned int i = 0; i != 64; ++i) {
    const bool xb = (i & 1U) != 0;
    const bool yb = (i & 2U) != 0;
    const auto x = wire(xb, 0x1000 + i, 0x2000 + 3 * i);
    const auto y = wire(yb, 0x3000 + i, 0x4000 + 5 * i);
    const auto z = wire(xb && yb, 0x5000 + i, 0x6000 + 7 * i);
    prover.update(qs::multiplication_constraint(x, y, z));
    verifier.update(qs::multiplication_constraint(qs::authenticate(x, delta),
                                                  qs::authenticate(y, delta),
                                                  qs::authenticate(z, delta), delta));
  }

  BOOST_TEST(prover.constraints() == 64U);
  BOOST_TEST(verifier.constraints() == 64U);
  BOOST_TEST(prover.polynomial().degree2 == Gf128{});
  BOOST_TEST(qs::evaluate_proof(prover.polynomial(), delta) == verifier.evaluation());
}

BOOST_AUTO_TEST_SUITE_END()
