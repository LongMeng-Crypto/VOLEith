/* SPDX-License-Identifier: MIT */
#include "shake256_circuit.hpp"
#include <array>
#include <stdexcept>

namespace vole_circuits::shake {
using namespace vole_backend;
namespace {
using Lane = std::array<Wire,64>;
using State = std::array<Lane,25>;
constexpr unsigned rotations[25] = {
  0,1,62,28,27,36,44,6,55,20,3,10,43,25,39,41,45,15,21,8,18,2,61,56,14};
constexpr std::uint64_t rc[24] = {
  0x0000000000000001ULL,0x0000000000008082ULL,0x800000000000808aULL,
  0x8000000080008000ULL,0x000000000000808bULL,0x0000000080000001ULL,
  0x8000000080008081ULL,0x8000000000008009ULL,0x000000000000008aULL,
  0x0000000000000088ULL,0x0000000080008009ULL,0x000000008000000aULL,
  0x000000008000808bULL,0x800000000000008bULL,0x8000000000008089ULL,
  0x8000000000008003ULL,0x8000000000008002ULL,0x8000000000000080ULL,
  0x000000000000800aULL,0x800000008000000aULL,0x8000000080008081ULL,
  0x8000000000008080ULL,0x0000000080000001ULL,0x8000000080008008ULL};
}
std::vector<Wire> append_shake256(BinaryCircuit& c, std::span<const Wire> input,
                                 std::size_t output_bits) {
  if (input.size()>1082 || output_bits==0 || output_bits>rate_bits)
    throw std::invalid_argument("single-block SHAKE256: input 0..1082, output 1..1088 bits");
  State a{};
  for (std::size_t i=0;i<input.size();++i) a[i/64][i%64]=input[i];
  // SHAKE suffix 1111, followed by pad10*1. These positions are disjoint.
  for (std::size_t i=input.size();i<input.size()+5;++i) a[i/64][i%64]=c.one();
  a[1087/64][1087%64]=c.one();
  for (unsigned round=0;round<24;++round) {
    std::array<Lane,5> col{},d{};
    for (unsigned x=0;x<5;++x) for (unsigned z=0;z<64;++z) {
      auto v=a[x][z];
      for (unsigned y=1;y<5;++y) v=c.xor_wire(v,a[x+5*y][z]);
      col[x][z]=v;
    }
    for (unsigned x=0;x<5;++x) for (unsigned z=0;z<64;++z)
      d[x][z]=c.xor_wire(col[(x+4)%5][z],col[(x+1)%5][(z+63)%64]);
    State b{};
    for (unsigned x=0;x<5;++x) for (unsigned y=0;y<5;++y)
      for (unsigned z=0;z<64;++z)
        b[y+5*((2*x+3*y)%5)][(z+rotations[x+5*y])%64]=c.xor_wire(a[x+5*y][z],d[x][z]);
    for (unsigned x=0;x<5;++x) for (unsigned y=0;y<5;++y)
      for (unsigned z=0;z<64;++z) {
        auto u=b[(x+1)%5+5*y][z],v=b[(x+2)%5+5*y][z];
        a[x+5*y][z]=c.xor_wire(b[x+5*y][z],c.xor_wire(v,c.and_wire(u,v)));
      }
    for (unsigned z=0;z<64;++z) if ((rc[round]>>z)&1)
      a[0][z]=c.xor_wire(a[0][z],c.one());
  }
  std::vector<Wire> out;
  for (std::size_t i=0;i<output_bits;++i) out.push_back(a[i/64][i%64]);
  return out;
}
BinaryCircuit prune_unused(const BinaryCircuit& c) {
  std::vector<bool> used(c.nodes().size(),false);
  used[0]=used[1]=true;
  for (auto w:c.outputs()) used[w]=true;
  // Keep the API's complete input layout, including inputs unused by outputs.
  for (std::size_t i=c.nodes().size();i-->2;) {
    auto n=c.nodes()[i];
    if(n.op==Op::PrivateInput || n.op==Op::PublicInput) used[i]=true;
    if(used[i] && (n.op==Op::Xor || n.op==Op::And)) used[n.lhs]=used[n.rhs]=true;
  }
  std::vector<Wire> map(c.nodes().size());
  std::vector<Node> nodes;
  for(std::size_t i=0;i<c.nodes().size();++i) if(used[i]) {
    auto n=c.nodes()[i];
    if(n.op==Op::Xor || n.op==Op::And) { n.lhs=map[n.lhs]; n.rhs=map[n.rhs]; }
    map[i]=nodes.size(); nodes.push_back(n);
  }
  std::vector<Wire> out; for(auto w:c.outputs()) out.push_back(map[w]);
  return BinaryCircuit::from_canonical(std::move(nodes),std::move(out));
}
BinaryCircuit make_shake256(std::size_t input_bits,std::size_t output_bits,bool prune) {
  if(input_bits>1082) throw std::invalid_argument("SHAKE256 single absorb block exceeded");
  BinaryCircuit c; std::vector<Wire> in;
  for(std::size_t i=0;i<input_bits;++i) in.push_back(c.private_input());
  for(auto w:append_shake256(c,in,output_bits)) c.add_output(w);
  return prune ? prune_unused(c) : c;
}
}
