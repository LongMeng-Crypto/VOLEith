/* SPDX-License-Identifier: MIT */
// Malicious-prover tests: local witness checks are deliberately bypassed.
#include "backend/backend_witness.hpp"
#include "backend/circuit_format.hpp"
#include "backend/generic_nizk.hpp"
#include "backend/generic_quicksilver.hpp"
#include "backend/vole/faest_vole.hpp"
#ifdef VOLE_SOUNDNESS_FRONTENDS
#include "backend/mixed_quadratic.hpp"
#include "circuits/aes/aes128_faest_circuit.hpp"
#include "circuits/sha2/sha256/faest_quicksilver.hpp"
#endif
extern "C" {
#include "universal_hashing.h"
}
#ifdef VOLE_SOUNDNESS_DAA
#include "tpm_sha_relation.hpp"
#include "issuer_anchor_relation.hpp"
#include "issuer_anchor_nizk.h"
#endif
#include <algorithm>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <stdexcept>
using namespace vole_backend;
using Bytes=std::vector<std::uint8_t>;
namespace {
std::size_t checks=0;
void check(bool ok,const char* message){++checks;if(!ok)throw std::runtime_error(message);}
// Real bit-VOLE correlations, generated directly to isolate constraint soundness
// from the seed-tree and Fiat--Shamir layers. Delta is independent of the prover.
struct Correlations {
 Bytes u,v,q,delta,challenge;std::size_t stride,columns;
 Correlations(std::size_t witness,SecurityLevel level,VoleProfile profile){
  const auto& p=security_parameters(level,profile);auto layout=vole_layout(witness,level,profile);
  stride=layout.ell_hat_bytes;columns=p.lambda_bits;
  u.resize(stride);v.resize(columns*stride);delta.resize(p.lambda_bytes);challenge.resize(p.quicksilver_challenge_bytes());
  std::uint64_t state=0xb8a93102a72c4e15ULL;
  auto fill=[&](Bytes& a){for(auto& x:a){state^=state<<13;state^=state>>7;state^=state<<17;x=state;}};
  fill(u);fill(v);fill(delta);fill(challenge);q=v;
  for(std::size_t j=0;j<columns;++j)if((delta[j/8]>>(j%8))&1)for(std::size_t i=0;i<stride;++i)q[j*stride+i]^=u[i];
 }
 std::vector<std::uint8_t*> cols(Bytes& data){std::vector<std::uint8_t*> out;for(std::size_t j=0;j<columns;++j)out.push_back(data.data()+j*stride);return out;}
};
Bytes residual_hash(SecurityLevel level,const Bytes& challenge,const Bytes& residuals){
 Bytes out(security_parameters(level).lambda_bytes);
#define HASH_CASE(LEVEL,BITS) case SecurityLevel::LEVEL:{ \
 zk_hash_##BITS##_ctx h;zk_hash_##BITS##_init(&h,challenge.data()); \
 for(auto bit:residuals){auto value=bf##BITS##_from_bit(bit);zk_hash_##BITS##_update(&h,&value);} \
 auto zero=bf##BITS##_zero();zk_hash_##BITS##_finalize(out.data(),&h,&zero);break;}
 switch(level){HASH_CASE(Bits128,128) HASH_CASE(Bits192,192) HASH_CASE(Bits256,256)}
#undef HASH_CASE
 return out;
}
void malicious_generic(const BinaryCircuit& c,const Bytes& witness,const PublicStatement& st,const Bytes& residuals,SecurityLevel level,VoleProfile profile){
 PreparedBinaryCircuit prepared(c);Correlations f(prepared.layout().vole_bits,level,profile);auto v=f.cols(f.v),q=f.cols(f.q);
 auto prover_witness=witness;
 // The public helper rejects nonzero padding locally. A malicious prover can
 // bypass that check; its lower polynomial coefficients do not depend on the
 // padding values, so obtain those coefficients with the padding cleared.
 for(std::size_t i=prepared.layout().logical_bits;i<prepared.layout().vole_bits;++i)prover_witness[i/8]&=static_cast<std::uint8_t>(~(1U<<(i%8)));
 auto p=quicksilver_prove(level,prepared,prover_witness,st.public_inputs,st.expected_outputs,v,f.u.data()+witness.size(),f.challenge);
 auto masked=mask_witness(witness,f.u);
 check(quicksilver_verify(level,prepared,masked,st.public_inputs,st.expected_outputs,q,f.delta,f.challenge,p)!=p.a0,"false generic constraint accepted");
 auto correction=residual_hash(level,f.challenge,residuals);
 for(std::size_t i=0;i<p.a2.size();++i)p.a2[i]^=correction[i];
 check(quicksilver_verify(level,prepared,masked,st.public_inputs,st.expected_outputs,q,f.delta,f.challenge,p)!=p.a0,"a2 residual-absorption attack accepted");
}
void generic_tests(){
 for(auto level:{SecurityLevel::Bits128,SecurityLevel::Bits192,SecurityLevel::Bits256})for(auto profile:{VoleProfile::Small,VoleProfile::Fast}){
  BinaryCircuit c;c.private_input();c.add_output(c.one());Bytes input{0};PublicStatement false_st{{},{0}};
  auto w=build_witness(c,input,{});Bytes residuals(8);residuals.back()=1;
  malicious_generic(c,w,false_st,residuals,level,profile);
  BinaryCircuit gate;auto x=gate.private_input(),y=gate.private_input();gate.add_output(gate.and_wire(x,y));
  auto bad_gate=build_witness(gate,Bytes{1,1},{});bad_gate[0]^=4;
  Bytes gate_residuals(7);gate_residuals[0]=1;
  malicious_generic(gate,bad_gate,false_st,gate_residuals,level,profile);
  BinaryCircuit padding;auto bit=padding.private_input();padding.add_output(bit);
  auto bad_padding=build_witness(padding,input,{});bad_padding[0]^=8;
  Bytes padding_residuals(8);padding_residuals[2]=1;
  malicious_generic(padding,bad_padding,false_st,padding_residuals,level,profile);
  const PreparedBinaryCircuit prepared_c(c);
  const PublicStatement true_st{{},{1}};ProverRandomness random{};random[0]=19;
  auto proof=prove(prepared_c,level,profile,input,true_st,{},random);
  check(verify(prepared_c,level,profile,true_st,{},proof),"valid generic NIZK rejected");
  for(auto version:{1,2,3}){
   auto old=proof;old[5]=version;
   check(!verify(prepared_c,level,profile,true_st,{},old),"old generic version accepted");
   if(profile==VoleProfile::Small)check(!verify(prepared_c,level,true_st,{},old),"legacy fallback accepted old proof");
  }
  auto fixture=std::filesystem::path(VOLE_SOUNDNESS_DATA_DIR)/(std::string(security_level_name(level))+std::string(vole_profile_name(profile))+".bin");
  std::ifstream in(fixture,std::ios::binary);check(bool(in),"missing historical forgery fixture");
  Bytes historical{std::istreambuf_iterator<char>(in),{}};
  check(!verify(prepared_c,level,profile,false_st,{},historical),"historical forgery accepted");
  historical[5]=4;
  check(!verify(prepared_c,level,profile,false_st,{},historical),"relabelled historical forgery accepted");
 }
}
#ifdef VOLE_SOUNDNESS_FRONTENDS
class MaliciousMixed final:public QuicksilverRelation {
 const MixedQuadraticRelation& r;
public:
 explicit MaliciousMixed(const MixedQuadraticRelation& relation):r(relation){}
 auto id()const->std::array<std::uint8_t,32>override{return r.id();}
 std::size_t private_input_bits()const override{return r.private_input_bits();}
 std::size_t public_input_bits()const override{return 0;}
 std::size_t output_bits()const override{return 0;}
 std::size_t witness_bits()const override{return r.witness_bits();}
 Bytes build_witness(std::span<const std::uint8_t> in,const PublicStatement&)const override{return vole_backend::build_witness(r.circuit(),in,{});}
 QuicksilverProof prove_constraints(std::span<const std::uint8_t>w,const PublicStatement&s,const std::vector<std::uint8_t*>&v,const std::uint8_t*u,const QuicksilverChallenge&c)const override{
  auto p=r.prove_constraints(w,s,v,u,c);
  for(std::size_t i=0;i<16;++i)p.a2[i]^=c[i]^c[16+i];
  return p;
 }
 auto verify_constraints(std::span<const std::uint8_t>d,const PublicStatement&s,const std::vector<std::uint8_t*>&q,const std::array<std::uint8_t,16>&delta,const QuicksilverChallenge&c,const QuicksilverProof&p)const->std::array<std::uint8_t,16>override{return r.verify_constraints(d,s,q,delta,c,p);}
};
void mixed_tests(){
 BinaryCircuit c;c.private_input();FieldQuadraticEquation equation;equation.linear=c.one();
 MixedQuadraticRelation r(c,{Gf128{},Gf128::from_bit(1)},{},{equation},{'1','=','0'});
 ProverRandomness random{};random[0]=7;
 for(auto profile:{VoleProfile::Small,VoleProfile::Fast}){
  auto proof=prove(MaliciousMixed(r),profile,Bytes{0},{},{},random);
  check(!verify(r,profile,{},{},proof),"unsatisfiable mixed relation accepted");
 }
}
void legacy_sha_test(){
 faest::sha256_circuit::Circuit c(0);faest::sha256_circuit::Message input{};auto digest=c.evaluate(input);
 auto w=vole_sha256::build_witness(c,input);auto witness_bits=vole_sha256::witness_layout(c).vole_bits;
 Correlations f(witness_bits,SecurityLevel::Bits128,VoleProfile::Small);auto v=f.cols(f.v),q=f.cols(f.q);
 QuicksilverChallenge challenge{};std::copy(f.challenge.begin(),f.challenge.end(),challenge.begin());std::array<std::uint8_t,16> delta{};std::copy(f.delta.begin(),f.delta.end(),delta.begin());
 auto good=vole_sha256::sha256_quicksilver_prove(c,w,v,f.u.data()+w.size(),digest,challenge);auto masked=mask_witness(w,f.u);
 check(vole_sha256::sha256_quicksilver_verify(c,masked,q,delta,digest,challenge,good)==good.a0,"legacy SHA valid proof rejected");
 digest[31]^=0x80;auto forged=vole_sha256::sha256_quicksilver_prove(c,w,v,f.u.data()+w.size(),digest,challenge);
 for(std::size_t i=0;i<16;++i)forged.a2[i]^=challenge[i]^challenge[16+i];
 check(vole_sha256::sha256_quicksilver_verify(c,masked,q,delta,digest,challenge,forged)!=forged.a0,"legacy SHA a2 absorption accepted");
}
void aes_test(){
 vole_circuits::aes::Aes128FaestRelation r;
 const Bytes key{0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15},pt{0,0x11,0x22,0x33,0x44,0x55,0x66,0x77,0x88,0x99,0xaa,0xbb,0xcc,0xdd,0xee,0xff},ct{0x69,0xc4,0xe0,0xd8,0x6a,0x7b,0x04,0x30,0xd8,0xcd,0xb7,0x80,0x70,0xb4,0xc5,0x5a};
 auto bits=[](const Bytes&a){Bytes b;for(auto x:a)for(unsigned i=0;i<8;++i)b.push_back((x>>i)&1);return b;};
 PublicStatement st{bits(pt),bits(ct)};auto w=r.build_witness(bits(key),st);
 for(auto profile:{VoleProfile::Small,VoleProfile::Fast}){
  Correlations f(r.witness_bits(),SecurityLevel::Bits128,profile);auto v=f.cols(f.v),q=f.cols(f.q);auto masked=mask_witness(w,f.u);
  QuicksilverChallenge challenge{};std::copy(f.challenge.begin(),f.challenge.end(),challenge.begin());std::array<std::uint8_t,16> delta{};std::copy(f.delta.begin(),f.delta.end(),delta.begin());
  auto p=r.prove_constraints(w,st,v,f.u.data()+w.size(),challenge);
  check(r.verify_constraints(masked,st,q,delta,challenge,p)==p.a0,"native AES valid constraint rejected");
  auto wrong=st;wrong.expected_outputs[0]^=1;
  p=r.prove_constraints(w,wrong,v,f.u.data()+w.size(),challenge);
  check(r.verify_constraints(masked,wrong,q,delta,challenge,p)!=p.a0,"native AES wrong ciphertext accepted");
  for(std::size_t i=0;i<16;++i)p.a2[i]^=challenge[i]^challenge[16+i];
  check(r.verify_constraints(masked,wrong,q,delta,challenge,p)!=p.a0,"native AES coefficient modification accepted");
 }
}
#endif

#ifdef VOLE_SOUNDNESS_DAA
void daa_tests(){
 for(auto level:{SecurityLevel::Bits128,SecurityLevel::Bits192,SecurityLevel::Bits256}){
  for(auto kind:{daa::tpm_sha::RelationKind::Join,daa::tpm_sha::RelationKind::OursSign,daa::tpm_sha::RelationKind::Chen23Sign}){
   daa::tpm_sha::Relation relation(level,kind);const auto& c=relation.binary_circuit();const auto stats=c.statistics();
   Bytes input(stats.private_inputs),public_input(stats.public_inputs);auto output=c.evaluate(input,public_input).outputs;output.back()^=1;
   auto w=build_witness(c,input,public_input);auto layout=witness_layout(c);Bytes residuals(stats.multiplication_gates+layout.transport_padding_bits+output.size());residuals.back()=1;
   for(auto profile:{VoleProfile::Small,VoleProfile::Fast})malicious_generic(c,w,{public_input,output},residuals,level,profile);
  }
  for(auto kind:{daa::issuer_anchor::Kind::Sphincs,daa::issuer_anchor::Kind::FSphincs}){
   daa::issuer_anchor::Relation relation(level,kind);const auto& c=relation.binary_circuit();
   Bytes seed(relation.seed_bytes()),a(relation.public_a_bytes()),b(relation.public_b_bytes());for(std::size_t i=0;i<b.size();++i)b[i]=i+1;
   auto input=relation.private_bits(seed),pub=relation.public_bits(a,b);auto output=c.evaluate(input,pub).outputs;
   Bytes endpoint((output.size()+7)/8);for(std::size_t i=0;i<output.size();++i)endpoint[i/8]|=output[i]<<(i%8);
   auto w=build_witness(c,input,pub);auto layout=witness_layout(c);Bytes residuals(c.statistics().multiplication_gates+layout.transport_padding_bits+output.size());residuals.back()=1;
   auto bad_output=output;bad_output.back()^=1;
   for(auto profile:{VoleProfile::Small,VoleProfile::Fast}){
    malicious_generic(c,w,{pub,bad_output},residuals,level,profile);
    auto cl=static_cast<daa_tpm_sha_level>(security_parameters(level).lambda_bits);
    auto cp=profile==VoleProfile::Small?DAA_TPM_SHA_SMALL:DAA_TPM_SHA_FAST;
    auto ck=kind==daa::issuer_anchor::Kind::Sphincs?DAA_ISSUER_ANCHOR_SPHINCS:DAA_ISSUER_ANCHOR_FSPHINCS;
    Bytes proof(daa_issuer_anchor_proof_bytes(cl,cp,ck));std::size_t length=proof.size();ProverRandomness random{};random[0]=89;
    auto status=daa_issuer_anchor_prove(cl,cp,ck,seed.data(),seed.size(),a.data(),a.size(),b.data(),b.size(),endpoint.data(),endpoint.size(),nullptr,0,random.data(),random.size(),proof.data(),&length);
    check(status==DAA_TPM_SHA_OK,daa_issuer_anchor_last_error());
    auto accepts=[&](const Bytes& bytes){return daa_issuer_anchor_verify(cl,cp,ck,a.data(),a.size(),b.data(),b.size(),endpoint.data(),endpoint.size(),nullptr,0,bytes.data(),bytes.size())==DAA_TPM_SHA_OK;};
    check(accepts(proof),"issuer setup C API rejected a valid proof");
    auto old=proof;old[5]=3;check(!accepts(old),"issuer setup accepted old protocol");
    auto wrong=endpoint;wrong[0]^=1;
    check(daa_issuer_anchor_verify(cl,cp,ck,a.data(),a.size(),b.data(),b.size(),wrong.data(),wrong.size(),nullptr,0,proof.data(),proof.size())!=DAA_TPM_SHA_OK,"issuer setup accepted wrong public endpoint");
   }
  }
 }
}
#endif
}
int main(){try{generic_tests();
#ifdef VOLE_SOUNDNESS_FRONTENDS
 mixed_tests();legacy_sha_test();aes_test();
#endif
#ifdef VOLE_SOUNDNESS_DAA
 daa_tests();
#endif
 std::cout<<"soundness regression: "<<checks<<" checks passed\n";return 0;
}catch(const std::exception&e){std::cerr<<"soundness regression failed: "<<e.what()<<'\n';return 1;}}
