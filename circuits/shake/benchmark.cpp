/* SPDX-License-Identifier: MIT */
#include "shake256_circuit.hpp"
#include "backend/generic_nizk.hpp"
#include "backend/vole/faest_vole.hpp"
#include <openssl/rand.h>
#include <algorithm>
#include <chrono>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <map>
#include <sys/resource.h>
using namespace vole_backend;
int main(int argc,char**argv){try{
  std::map<std::string,std::string> opts;
  for(int i=1;i<argc;i+=2){if(i+1==argc)throw std::invalid_argument("option value missing");opts[argv[i]]=argv[i+1];}
  auto get=[&](const std::string&k,const std::string&d){return opts.count(k)?opts[k]:d;};
  const auto input_bits=std::stoul(get("--input-bits","384"));
  const auto output_bits=std::stoul(get("--output-bits","256"));
  const auto iterations=std::stoul(get("--iterations","10"));
  if(!iterations || iterations>100000)throw std::invalid_argument("iterations range");
  const auto level=std::stoul(get("--security","128"));
  if(level!=128 && level!=192 && level!=256)throw std::invalid_argument("security must be 128, 192, or 256");
  const auto profile_name=get("--profile","s");
  if(profile_name!="s" && profile_name!="f")throw std::invalid_argument("profile must be s or f");
  const auto security=level==128?SecurityLevel::Bits128:level==192?SecurityLevel::Bits192:SecurityLevel::Bits256;
  const auto profile=profile_name=="s"?VoleProfile::Small:VoleProfile::Fast;
  const auto c=vole_circuits::shake::make_shake256(input_bits,output_bits);
  const PreparedBinaryCircuit prepared(c);
  std::vector<std::uint8_t> input(input_bits);
  if(RAND_bytes(input.data(),input.size())!=1)throw std::runtime_error("RAND_bytes failed");
  for(auto&b:input)b&=1;
  const PublicStatement statement{{},c.evaluate(input).outputs};
  const std::string label="SHAKE256-XOF-baseline-v1";const std::vector<std::uint8_t> context(label.begin(),label.end());
  auto random=[](){ProverRandomness r{};if(RAND_bytes(r.data(),r.size())!=1)throw std::runtime_error("RAND_bytes failed");return r;};
  auto warm=prove(prepared,security,profile,input,statement,context,random());
  if(!verify(prepared,security,profile,statement,context,warm))throw std::runtime_error("warm-up rejected");
  std::vector<double> proving,verifying;std::size_t proof_bytes=0;
  for(unsigned i=0;i<iterations;++i){
    const auto r=random();auto start=std::chrono::steady_clock::now();
    auto proof=prove(prepared,security,profile,input,statement,context,r);
    auto end=std::chrono::steady_clock::now();proving.push_back(std::chrono::duration<double,std::milli>(end-start).count());
    start=std::chrono::steady_clock::now();const auto ok=verify(prepared,security,profile,statement,context,proof);
    end=std::chrono::steady_clock::now();verifying.push_back(std::chrono::duration<double,std::milli>(end-start).count());
    if(!ok)throw std::runtime_error("benchmark rejected");
    proof_bytes=proof.size();
  }
  auto quantile=[](std::vector<double> v,double p){std::sort(v.begin(),v.end());double pos=(v.size()-1)*p;auto i=std::size_t(pos);return v[i]+(v[std::min(i+1,v.size()-1)]-v[i])*(pos-i);};
  auto stats=c.statistics();const auto layout=prepared.layout();
  const auto vole=vole_layout(layout.vole_bits,security,profile);
  struct rusage usage{};getrusage(RUSAGE_SELF,&usage);
  std::ostringstream out;out<<std::setprecision(10)<<"{\n  \"scheme\":\"SHAKE256\",\n";
  auto n=[&](std::string k,auto v){out<<"  \""<<k<<"\":"<<v<<",\n";};
  n("input_bits",input_bits);n("output_bits",output_bits);n("security_bits",level);
  out<<"  \"profile\":\""<<profile_name<<"\",\n";n("iterations",iterations);n("sha_permutations",1);
  n("and_gates",stats.multiplication_gates);n("xor_gates",stats.xor_gates);n("circuit_nodes",stats.total_nodes);
  n("witness_bits_logical",layout.logical_bits);n("witness_bits_vole",layout.vole_bits);n("vole_correlation_rows",vole.ell_hat_bits);n("committed_witness_rows",layout.vole_bits);n("vole_ell_hat",vole.ell_hat_bits);n("vole_correction_bytes",vole.correction_bytes);n("proof_bytes",proof_bytes);n("peak_rss_mb",usage.ru_maxrss/1024.0);
  auto samples=[&](std::string name,const std::vector<double>&v){n(name+"_median_ms",quantile(v,.5));n(name+"_p25_ms",quantile(v,.25));n(name+"_p75_ms",quantile(v,.75));out<<"  \""<<name<<"_samples_ms\":[";for(std::size_t i=0;i<v.size();++i)out<<(i?",":"")<<v[i];out<<"],\n";};
  samples("prover",proving);samples("verifier",verifying);out<<"  \"verify_success\":true\n}\n";
  if(opts.count("--json")){std::ofstream f(opts["--json"]);if(!f)throw std::runtime_error("JSON output file");f<<out.str();}
  std::cout<<out.str();return 0;
}catch(const std::exception&e){std::cerr<<e.what()<<'\n';return 1;}}
