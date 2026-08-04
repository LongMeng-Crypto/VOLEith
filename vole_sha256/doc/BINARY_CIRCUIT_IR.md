# In-memory BinaryCircuit IR

`vole_backend::BinaryCircuit` is the algorithm-independent Boolean circuit
representation used by circuit frontends. Its canonical primitive operations
are:

```text
Constant(0 or 1)
PrivateInput
PublicInput
Xor(lhs, rhs)
And(lhs, rhs)
Output(wire)
```

Wire identifiers are node indices. Constants are always wires 0 and 1, and a
gate may reference only earlier wires, making the IR a topologically ordered
DAG. `CircuitBuilder` performs constant propagation for XOR and AND while the
circuit owns nodes, output wires, validation, statistics and evaluation.

```cpp
vole_backend::BinaryCircuit circuit;
vole_backend::CircuitBuilder builder(circuit);
auto a = builder.private_input();
auto b = builder.private_input();
auto c = builder.public_input();
auto z = builder.and_wire(builder.xor_wire(a, b), c);
builder.output(z);
```

`evaluate` consumes bit vectors in declaration order and returns every wire,
the declared outputs, and AND outputs in circuit order. The latter is the
multiplication portion of a VOLE extended witness.

## SHA-256 frontend migration

The SHA-256 generator now owns a `BinaryCircuit` and emits all private inputs,
XOR gates, AND gates and 256 digest outputs into it. The existing SHA wrapper
retains message padding, compression construction and byte-oriented APIs, but
node storage, constant propagation, validation, statistics and evaluation are
provided by the generic IR.

The migration is protected by tests comparing SHA wrapper and IR statistics,
all padding boundaries against OpenSSL, and the complete deterministic NIZK
KAT. Thus it changes representation, not the generated relation or proof.

## Generic backend

The generic backend now consumes this IR directly. It supports private and
public input nodes, constrains every declared output to a public expected bit,
derives the dynamic VOLE witness from private inputs plus AND outputs, and
binds the canonical VBC circuit hash into Fiat-Shamir. See `VBC_FORMAT.md`.
