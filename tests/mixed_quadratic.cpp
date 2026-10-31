/* SPDX-License-Identifier: MIT */
#include "backend/mixed_quadratic.hpp"
#include "backend/backend_witness.hpp"
#include <boost/test/unit_test.hpp>
using namespace vole_backend;
namespace {
// A malicious prover bypassing honest witness validation must still fail the
// actual authenticated polynomial check and Fiat-Shamir verification.
class Dishonest final:public QuicksilverRelation {
  const MixedQuadraticRelation& r;
public:
  explicit Dishonest(const MixedQuadraticRelation& relation):r(relation){}
  auto id()const->std::array<std::uint8_t,32> override{return r.id();}
  std::size_t private_input_bits()const override{return r.private_input_bits();}
  std::size_t public_input_bits()const override{return 0;}
  std::size_t output_bits()const override{return 0;}
  std::size_t witness_bits()const override{return r.witness_bits();}
  std::vector<std::uint8_t> build_witness(std::span<const std::uint8_t> in,const PublicStatement&)const override{
    auto packed=vole_backend::build_witness(r.circuit(),in,{});
    return packed;
  }
  QuicksilverProof prove_constraints(std::span<const std::uint8_t>w,const PublicStatement&s,
      const std::vector<std::uint8_t*>&v,const std::uint8_t*u,const QuicksilverChallenge&c)const override{return r.prove_constraints(w,s,v,u,c);}
  std::array<std::uint8_t,16> verify_constraints(std::span<const std::uint8_t>d,const PublicStatement&s,
      const std::vector<std::uint8_t*>&q,const std::array<std::uint8_t,16>&delta,const QuicksilverChallenge&c,const QuicksilverProof&p)const override{return r.verify_constraints(d,s,q,delta,c,p);}
};
}
BOOST_AUTO_TEST_SUITE(mixed_quadratic)
BOOST_AUTO_TEST_CASE(direct_products_are_checked_without_output_witness) {
  BinaryCircuit c;auto x=c.private_input(),y=c.private_input(),z=c.private_input();
  // (a*x)*(a*y) + a^2*z = 0, with an arbitrary nontrivial check-field a.
  Gf128 a{0x9a712bb6c5d3e2f1ULL,0x13579bdf2468ace0ULL};
  std::vector<Gf128> constants{Gf128{},Gf128::from_bit(1),a,field_multiply(a,a)};
  std::vector<FieldLinearForm> forms{{{{x,2}},true},{{{y,2}},true},{{{z,3}},false}};
  FieldQuadraticEquation equation{{{5,6}},7,{}};
  MixedQuadraticRelation r(c,constants,forms,{equation},{'t','e','s','t',1});
  BOOST_CHECK_EQUAL(r.witness_bits(),8U);BOOST_CHECK_EQUAL(r.product_count(),1U);
  const PublicStatement st{};ProverRandomness randomness{};randomness[0]=79;
  const std::array<std::uint8_t,3> valid{1,1,1},invalid{1,1,0};
  for(auto profile:{VoleProfile::Small,VoleProfile::Fast}){
    auto proof=prove(r,profile,valid,st,{},randomness);BOOST_REQUIRE(verify(r,profile,st,{},proof));
    BOOST_CHECK_THROW(r.build_witness(invalid,st),std::invalid_argument);
    auto forged=prove(Dishonest(r),profile,invalid,st,{},randomness);
    BOOST_CHECK(!verify(r,profile,st,{},forged));
    // A product's public coefficient is included in both arithmetic and ID.
    auto weighted=equation;weighted.coefficients={2};
    MixedQuadraticRelation weighted_relation(c,constants,forms,{weighted},{'t','e','s','t',1});
    BOOST_CHECK(weighted_relation.id()!=r.id());
    BOOST_CHECK_THROW(weighted_relation.build_witness(valid,st),std::invalid_argument);
    const std::array<std::uint8_t,3> zero{0,0,0};
    auto weighted_proof=prove(weighted_relation,profile,zero,st,{},randomness);
    BOOST_CHECK(verify(weighted_relation,profile,st,{},weighted_proof));
    MixedQuadraticRelation other(c,constants,forms,{equation},{'t','e','s','t',2});
    BOOST_CHECK(!verify(other,profile,st,{},proof));
  }
}
BOOST_AUTO_TEST_CASE(malformed_linear_wires_rejected) {
  BinaryCircuit c;
  BOOST_CHECK_THROW(MixedQuadraticRelation(c,{Gf128{}},{{{{2,0}},false}},{},{1}),std::invalid_argument);
  BOOST_CHECK_THROW(MixedQuadraticRelation(c,{Gf128{}},{{{{0,1}},false}},{},{1}),std::invalid_argument);
}
BOOST_AUTO_TEST_SUITE_END()
