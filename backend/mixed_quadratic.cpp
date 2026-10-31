/* SPDX-License-Identifier: MIT */
#include "mixed_quadratic.hpp"
#include "backend_witness.hpp"
#include "circuit_format.hpp"
#include "vole/bit_matrix_transpose.hpp"
#include <openssl/evp.h>
#include <algorithm>
#include <cstring>
#include <limits>
#include <stdexcept>
#include <unordered_map>
extern "C" {
#include "universal_hashing.h"
#include "utils.h"
}
namespace vole_backend {
namespace {
using F=Gf128;
bf128_t native(F f) { bf128_t r; bf128_load(&r,reinterpret_cast<const std::uint8_t*>(&f)); return r; }
F plain(const bf128_t& f) { F r; bf128_store(reinterpret_cast<std::uint8_t*>(&r),&f); return r; }
F load(const std::uint8_t* p) { bf128_t f; bf128_load(&f,p); return plain(f); }
void store(std::uint8_t* p,F f) { auto n=native(f); bf128_store(p,&n); }
struct Auth { F value{}, tag{}; };
Auth plus(Auth a,const Auth& b) { a.value+=b.value; a.tag+=b.tag; return a; }
std::vector<F> rows(const std::vector<std::uint8_t*>& cols,std::size_t count) {
  if(cols.size()!=128) throw std::invalid_argument("mixed relation requires 128 VOLE columns");
  std::vector<F> out(count); std::vector<std::uint8_t> packed(64*16);
  for(std::size_t base=0;base<count;base+=64) {
    auto n=std::min<std::size_t>(64,count-base);
    transpose_column_block(cols,base,n,std::span<std::uint8_t>(packed.data(),n*16),16);
    for(std::size_t j=0;j<n;++j) out[base+j]=load(packed.data()+j*16);
  }
  return out;
}
void update(zk_hash_128_3_ctx* h,F a,F b) {
  auto na=native(a),nb=native(b),zero=bf128_zero();
  zk_hash_128_3_update(h,&na,&nb,&zero);
}
void update(zk_hash_128_ctx* h,F a) { auto na=native(a); zk_hash_128_update(h,&na); }
template<bool Prover> std::vector<Auth> linear_wires(
    const BinaryCircuit& circuit,const std::vector<FieldLinearForm>& forms,
    const std::vector<F>& constants,std::vector<Auth> wires) {
  const auto total=circuit.nodes().size()+forms.size();
  wires.reserve(total);
  std::vector<std::size_t> cache_slot(total,std::numeric_limits<std::size_t>::max());
  std::vector<std::vector<Auth>> cache;
  for(const auto& form:forms) {
    Auth a{};
    for(auto term:form.terms) {
      const auto slot=cache_slot[term.source];
      if(slot!=std::numeric_limits<std::size_t>::max()) a=plus(a,cache[slot][term.coefficient]);
      else {
        const auto src=wires[term.source]; const auto c=constants[term.coefficient];
        a.tag+=field_multiply(src.tag,c);
        if constexpr(Prover) a.value+=field_multiply(src.value,c);
      }
    }
    const auto index=wires.size(); wires.push_back(a);
    if(form.cache_scaled) {
      cache_slot[index]=cache.size();
      std::vector<Auth> scaled(constants.size());
      for(std::size_t i=0;i<constants.size();++i) {
        scaled[i].tag=field_multiply(a.tag,constants[i]);
        if constexpr(Prover) scaled[i].value=field_multiply(a.value,constants[i]);
      }
      cache.push_back(std::move(scaled));
    }
  }
  return wires;
}
}
Gf128 field_multiply(Gf128 a,Gf128 b) {
  auto na=native(a),nb=native(b); bf128_t r; bf128_mul(&r,&na,&nb); return plain(r);
}
MixedQuadraticRelation::MixedQuadraticRelation(BinaryCircuit c,std::vector<F> constants,
    std::vector<FieldLinearForm> forms,std::vector<FieldQuadraticEquation> eq,
    std::vector<std::uint8_t> binding):circuit_(std::move(c)),constants_(std::move(constants)),
    forms_(std::move(forms)),equations_(std::move(eq)) {
  if(!circuit_.validate() || constants_.size()<2 || constants_.size()>65536 ||
      constants_[0]!=F{} || constants_[1]!=F::from_bit(true))
    throw std::invalid_argument("invalid mixed quadratic IR");
  std::size_t total=circuit_.nodes().size();
  for(const auto& form:forms_) {
    for(auto t:form.terms) if(t.source>=total || t.coefficient>=constants_.size())
      throw std::invalid_argument("invalid mixed linear term");
    ++total;
  }
  for(const auto& q:equations_) {
    if(!q.coefficients.empty() && q.coefficients.size()!=q.products.size()) throw std::invalid_argument("quadratic coefficient count");
    for(auto coefficient:q.coefficients) if(coefficient>=constants_.size()) throw std::invalid_argument("quadratic coefficient index");
    if(q.linear>=total) throw std::invalid_argument("invalid mixed equation");
    for(auto [a,b]:q.products) if(a>=total || b>=total)
      throw std::invalid_argument("invalid mixed quadratic term");
  }
  // Canonical, endian-independent relation ID binds every coefficient, wire,
  // constraint, embedding, application version and exact public key.
  auto* h=EVP_MD_CTX_new(); if(!h) throw std::bad_alloc();
  EVP_DigestInit_ex(h,EVP_sha256(),nullptr);
  auto bytes=[&](auto* p,std::size_t n){ if(EVP_DigestUpdate(h,p,n)!=1) throw std::runtime_error("relation hash"); };
  auto u64=[&](std::uint64_t x){ std::uint8_t b[8]; for(unsigned i=0;i<8;++i)b[i]=x>>(8*i); bytes(b,8); };
  constexpr char domain[]="VOLEith-MixedQuadratic-v1-GF128-0x87";
  bytes(domain,sizeof(domain)-1); u64(binding.size()); bytes(binding.data(),binding.size());
  const auto bh=circuit_hash(circuit_); bytes(bh.data(),bh.size());
  u64(constants_.size()); for(auto f:constants_) {u64(f.lo);u64(f.hi);}
  u64(forms_.size()); for(const auto& f:forms_) {
    u64(f.terms.size()); for(auto t:f.terms){u64(t.source);u64(t.coefficient);}
  }
  u64(equations_.size()); for(const auto& q:equations_) {
    u64(q.linear);u64(q.products.size());for(std::size_t i=0;i<q.products.size();++i){auto [a,b]=q.products[i];u64(a);u64(b);u64(q.coefficients.empty()?1:q.coefficients[i]);}
  }
  unsigned len=0; EVP_DigestFinal_ex(h,id_.data(),&len); EVP_MD_CTX_free(h);
  if(len!=32) throw std::runtime_error("relation hash size");
}
std::size_t MixedQuadraticRelation::private_input_bits() const {return circuit_.statistics().private_inputs;}
std::size_t MixedQuadraticRelation::public_input_bits() const {return circuit_.statistics().public_inputs;}
std::size_t MixedQuadraticRelation::witness_bits() const {return witness_layout(circuit_).vole_bits;}
std::size_t MixedQuadraticRelation::product_count() const {std::size_t n=0;for(const auto&q:equations_)n+=q.products.size();return n;}
std::size_t MixedQuadraticRelation::linear_term_count() const {std::size_t n=0;for(const auto&f:forms_)n+=f.terms.size();return n;}
std::vector<std::uint8_t> MixedQuadraticRelation::build_witness(
    std::span<const std::uint8_t> in,const PublicStatement& st) const {
  if(!st.expected_outputs.empty()) throw std::invalid_argument("mixed binary outputs are internal");
  auto ev=circuit_.evaluate(in,st.public_inputs);
  std::vector<Auth> wires(ev.wires.size());
  for(std::size_t i=0;i<wires.size();++i) wires[i].value=F::from_bit(ev.wires[i]);
  wires=linear_wires<true>(circuit_,forms_,constants_,std::move(wires));
  for(const auto& q:equations_) {
    F a=wires[q.linear].value;
    for(std::size_t i=0;i<q.products.size();++i) {
      auto [l,r]=q.products[i];auto value=field_multiply(wires[l].value,wires[r].value);
      if(!q.coefficients.empty())value=field_multiply(value,constants_[q.coefficients[i]]);
      a+=value;
    }
    if(a!=F{}) throw std::invalid_argument("witness does not satisfy mixed quadratic equation");
  }
  return vole_backend::build_witness(circuit_,in,st.public_inputs);
}
QuicksilverProof MixedQuadraticRelation::prove_constraints(
    std::span<const std::uint8_t> witness,const PublicStatement& st,
    const std::vector<std::uint8_t*>& columns,const std::uint8_t* u,
    const QuicksilverChallenge& challenge) const {
  const auto layout=witness_layout(circuit_);
  if(witness.size()!=layout.vole_bytes) throw std::invalid_argument("mixed witness length");
  const auto tags=rows(columns,layout.vole_bits+256);
  zk_hash_128_3_ctx hasher; zk_hash_128_3_init(&hasher,challenge.data());
  std::vector<Auth> wires(circuit_.nodes().size());
  std::size_t pi=0,pu=0,ai=layout.private_input_bits;
  for(std::size_t i=0;i<wires.size();++i) {
    const auto n=circuit_.nodes()[i]; auto& a=wires[i];
    switch(n.op) {
    case Op::Constant:a.value=F::from_bit(n.constant);break;
    case Op::PublicInput:a.value=F::from_bit(st.public_inputs[pu++]);break;
    case Op::PrivateInput:a={F::from_bit(ptr_get_bit(witness.data(),pi)),tags[pi]};++pi;break;
    case Op::Xor:a=plus(wires[n.lhs],wires[n.rhs]);break;
    case Op::And: {
      a={F::from_bit(ptr_get_bit(witness.data(),ai)),tags[ai]};++ai;
      const auto l=wires[n.lhs],r=wires[n.rhs];
      update(&hasher,field_multiply(l.tag,r.tag),
          field_multiply(l.value,r.tag)+field_multiply(r.value,l.tag)+a.tag);break;
    }
    }
  }
  for(std::size_t i=layout.logical_bits;i<layout.vole_bits;++i) update(&hasher,F{},tags[i]);
  wires=linear_wires<true>(circuit_,forms_,constants_,std::move(wires));
  std::unordered_map<std::uint64_t,Auth> products;
  for(const auto& q:equations_) {
    F a0{},a1=wires[q.linear].tag;
    for(std::size_t i=0;i<q.products.size();++i) {
      auto [l,r]=q.products[i];Auth value;
      if(q.coefficients.empty()) {
        value={field_multiply(wires[l].tag,wires[r].tag),
          field_multiply(wires[l].value,wires[r].tag)+field_multiply(wires[r].value,wires[l].tag)};
      } else {
        auto key=(std::uint64_t(std::min(l,r))<<32)|std::max(l,r);
        auto it=products.find(key);
        if(it==products.end())it=products.emplace(key,Auth{field_multiply(wires[l].tag,wires[r].tag),
          field_multiply(wires[l].value,wires[r].tag)+field_multiply(wires[r].value,wires[l].tag)}).first;
        const auto scalar=constants_[q.coefficients[i]];
        value={field_multiply(it->second.value,scalar),field_multiply(it->second.tag,scalar)};
      }
      a0+=value.value;a1+=value.tag;
    }
    update(&hasher,a0,a1);
  }
  std::vector<bf128_t> extra(256);for(unsigned i=0;i<256;++i)extra[i]=native(tags[layout.vole_bits+i]);
  bf128_t u0,u1,v0,v1; bf128_sum_poly_bits(&u0,u);bf128_sum_poly_bits(&u1,u+16);
  bf128_sum_poly(&v0,extra.data());bf128_sum_poly(&v1,extra.data()+128);
  bf128_add_inplace(&u0,&v1);
  QuicksilverProof proof;
  zk_hash_128_3_finalize(proof.a0.data(),proof.a1.data(),proof.a2.data(),&hasher,&v0,&u0,&u1);
  return proof;
}
std::array<std::uint8_t,lambda_bytes> MixedQuadraticRelation::verify_constraints(
    std::span<const std::uint8_t> d,const PublicStatement& st,
    const std::vector<std::uint8_t*>& columns,const std::array<std::uint8_t,16>& delta_bytes,
    const QuicksilverChallenge& challenge,const QuicksilverProof& proof) const {
  const auto layout=witness_layout(circuit_);
  if(d.size()!=layout.vole_bytes) throw std::invalid_argument("mixed masked witness length");
  auto keys=rows(columns,layout.vole_bits+256);const auto delta=load(delta_bytes.data());
  for(std::size_t i=0;i<layout.vole_bits;++i) if(ptr_get_bit(d.data(),i))keys[i]+=delta;
  zk_hash_128_ctx hasher;zk_hash_128_init(&hasher,challenge.data());
  std::vector<Auth> wires(circuit_.nodes().size());
  std::size_t pi=0,pu=0,ai=layout.private_input_bits;
  for(std::size_t i=0;i<wires.size();++i) {
    const auto n=circuit_.nodes()[i];auto& a=wires[i];
    switch(n.op) {
    case Op::Constant:a.tag=n.constant?delta:F{};break;
    case Op::PublicInput:a.tag=st.public_inputs[pu++]?delta:F{};break;
    case Op::PrivateInput:a.tag=keys[pi++];break;
    case Op::Xor:a.tag=wires[n.lhs].tag+wires[n.rhs].tag;break;
    case Op::And:a.tag=keys[ai++];update(&hasher,field_multiply(wires[n.lhs].tag,wires[n.rhs].tag)+field_multiply(delta,a.tag));break;
    }
  }
  for(std::size_t i=layout.logical_bits;i<layout.vole_bits;++i)update(&hasher,field_multiply(delta,keys[i]));
  wires=linear_wires<false>(circuit_,forms_,constants_,std::move(wires));
  std::unordered_map<std::uint64_t,F> products;
  for(const auto& q:equations_) {
    auto a=field_multiply(delta,wires[q.linear].tag);
    for(std::size_t i=0;i<q.products.size();++i) {
      auto [l,r]=q.products[i];F value;
      if(q.coefficients.empty())value=field_multiply(wires[l].tag,wires[r].tag);
      else {
        auto key=(std::uint64_t(std::min(l,r))<<32)|std::max(l,r);
        auto it=products.find(key);
        if(it==products.end())it=products.emplace(key,field_multiply(wires[l].tag,wires[r].tag)).first;
        value=field_multiply(it->second,constants_[q.coefficients[i]]);
      }
      a+=value;
    }
    update(&hasher,a);
  }
  std::vector<bf128_t> extra(256);for(unsigned i=0;i<256;++i)extra[i]=native(keys[layout.vole_bits+i]);
  bf128_t q0,q1;bf128_sum_poly(&q0,extra.data());bf128_sum_poly(&q1,extra.data()+128);
  auto qstar=plain(q0)+field_multiply(plain(q1),delta);auto nq=native(qstar);
  std::array<std::uint8_t,16> out{};zk_hash_128_finalize(out.data(),&hasher,&nq);
  const auto a0=load(out.data())+field_multiply(load(proof.a1.data()),delta)+
      field_multiply(load(proof.a2.data()),field_multiply(delta,delta));
  store(out.data(),a0);return out;
}
}
