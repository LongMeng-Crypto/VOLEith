/* SPDX-License-Identifier: MIT */
#include "circuits/shake/shake256_circuit.hpp"
#include "backend/generic_nizk.hpp"
#include <boost/test/unit_test.hpp>
#include <openssl/evp.h>
#include <random>
extern "C" {
#include "KeccakP-1600-SnP.h"
}
using namespace vole_backend;
BOOST_AUTO_TEST_SUITE(shake256_circuit)
BOOST_AUTO_TEST_CASE(outputs_and_bit_boundaries) {
  std::mt19937 rng(4781);
  for(auto input_bits:{0U,1U,7U,8U,255U,384U,1080U,1082U}) {
    std::vector<std::uint8_t> bits(input_bits),bytes((input_bits+7)/8);
    for(unsigned i=0;i<input_bits;++i) { bits[i]=rng()&1; bytes[i/8]|=bits[i]<<(i%8); }
    alignas(32) std::array<std::uint8_t,200> state{};
    std::copy(bytes.begin(),bytes.end(),state.begin());
    for(unsigned i=input_bits;i<input_bits+5;++i) state[i/8]^=1U<<(i%8);
    state[135]^=0x80;
    KeccakP1600_Permute_24rounds(state.data());
    for(auto outbits:{1U,7U,8U,256U,360U,1087U,1088U}) {
      auto c=vole_circuits::shake::make_shake256(input_bits,outbits);
      const auto ev=c.evaluate(bits);
      for(unsigned i=0;i<outbits;++i) BOOST_REQUIRE_EQUAL(ev.outputs[i],(state[i/8]>>(i%8))&1U);
      BOOST_REQUIRE(c.statistics().multiplication_gates<=23*1600+outbits);
      if(input_bits%8==0) {
        std::vector<std::uint8_t> ref((outbits+7)/8);
        EVP_MD_CTX* ctx=EVP_MD_CTX_new();
        BOOST_REQUIRE(EVP_DigestInit_ex(ctx,EVP_shake256(),nullptr)==1);
        BOOST_REQUIRE(EVP_DigestUpdate(ctx,bytes.data(),bytes.size())==1);
        BOOST_REQUIRE(EVP_DigestFinalXOF(ctx,ref.data(),ref.size())==1);
        EVP_MD_CTX_free(ctx);
        for(unsigned i=0;i<outbits;++i) BOOST_REQUIRE_EQUAL(ev.outputs[i],(ref[i/8]>>(i%8))&1U);
      }
    }
  }
  BOOST_CHECK_THROW(vole_circuits::shake::make_shake256(1083,256),std::invalid_argument);
  BOOST_CHECK_THROW(vole_circuits::shake::make_shake256(384,1089),std::invalid_argument);
  BOOST_CHECK_THROW(vole_circuits::shake::make_shake256(384,0),std::invalid_argument);
}
BOOST_AUTO_TEST_CASE(empty_known_answer_and_random_48_byte_inputs) {
  const auto empty=vole_circuits::shake::make_shake256(0,256).evaluate({}).outputs;
  const std::string expected="46b9dd2b0ba88d13233b3feb743eeb243fcd52ea62b81b82b50c27646ed5762f";
  const char* alphabet="0123456789abcdef";std::string actual;
  for(unsigned i=0;i<32;++i){unsigned b=0;for(unsigned j=0;j<8;++j)b|=empty[i*8+j]<<j;actual+=alphabet[b>>4];actual+=alphabet[b&15];}
  BOOST_CHECK_EQUAL(actual,expected);
  const auto c=vole_circuits::shake::make_shake256(384,360);
  std::mt19937 rng(3921);
  for(unsigned trial=0;trial<24;++trial){
    std::array<std::uint8_t,48> bytes{};std::vector<std::uint8_t> bits;
    for(auto&b:bytes){b=rng();for(unsigned j=0;j<8;++j)bits.push_back((b>>j)&1);}
    std::array<std::uint8_t,45> ref{};auto* ctx=EVP_MD_CTX_new();
    BOOST_REQUIRE(EVP_DigestInit_ex(ctx,EVP_shake256(),nullptr)==1);
    BOOST_REQUIRE(EVP_DigestUpdate(ctx,bytes.data(),bytes.size())==1);
    BOOST_REQUIRE(EVP_DigestFinalXOF(ctx,ref.data(),ref.size())==1);EVP_MD_CTX_free(ctx);
    const auto out=c.evaluate(bits).outputs;
    for(unsigned i=0;i<360;++i)BOOST_REQUIRE_EQUAL(out[i],(ref[i/8]>>(i%8))&1);
  }
}
BOOST_AUTO_TEST_CASE(all_security_profiles_and_negative_cases) {
  const auto c=vole_circuits::shake::make_shake256(384,360);
  const PreparedBinaryCircuit prepared(c);
  std::vector<std::uint8_t> input(384); for(unsigned i=0;i<384;++i) input[i]=(i*13+i/7)&1;
  PublicStatement st{{},c.evaluate(input).outputs};
  ProverRandomness rnd{}; rnd[0]=91;
  const std::array<std::uint8_t,3> context{'x','o','f'};
  for(auto level:{SecurityLevel::Bits128,SecurityLevel::Bits192,SecurityLevel::Bits256})
    for(auto profile:{VoleProfile::Small,VoleProfile::Fast}) {
      auto proof=prove(prepared,level,profile,input,st,context,rnd);
      BOOST_REQUIRE(verify(prepared,level,profile,st,context,proof));
      auto wrong=st; wrong.expected_outputs[359]^=1;
      BOOST_CHECK(!verify(prepared,level,profile,wrong,context,proof));
      BOOST_CHECK(!verify(prepared,level,profile,st,{},proof));
      const auto other=profile==VoleProfile::Small ? VoleProfile::Fast : VoleProfile::Small;
      BOOST_CHECK(!verify(prepared,level,other,st,context,proof));
      proof[proof.size()/2]^=1;
      BOOST_CHECK(!verify(prepared,level,profile,st,context,proof));
    }
}
BOOST_AUTO_TEST_SUITE_END()
