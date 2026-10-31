# Authenticated Boolean and extension-field quadratic relations

MixedQuadraticRelation adds a relation frontend to the existing 128s/128f
QuicksilverRelation interface. It uses the existing VQRZK v3 proof envelope,
transcript, challenges, VOLE layout and universal hashing. It does not change
the existing AES relation, Boolean circuit protocol, or their proof formats.

All witness inputs remain authenticated bits. A BinaryCircuit allocates its
private input bits and AND-output bits exactly as before. Its listed output
wires are internal expressions: this relation does not expose them as public
outputs. Public application data must be bound through public_binding and/or
the public Boolean input statement.

The frontend then derives topologically ordered GF(2^128)-linear forms from
these authenticated wires. A public constant table starts with zero and one.
Each quadratic equation is sum_j c_j L_j R_j + H = 0. Linear forms and product
terms allocate no VOLE witness rows. The sum is one check-field equation, while
all product evaluations still incur computation. Reused public scalar multiples
and naive shared monomials can be cached without affecting the relation ID.

For an authenticated value x, write its prover tag as T_x and verifier key as
Q_x = T_x + delta*x. For C(x) = sum_j c_j L_j R_j + H, the prover accumulates:

```text
A0 = sum_j c_j T_Lj T_Rj
A1 = sum_j c_j (L_j T_Rj + R_j T_Lj) + T_H
```

The verifier accumulates E = sum_j c_j Q_Lj Q_Rj + delta*Q_H. Expanding gives
E = A0 + delta*A1 + delta^2*C(x). This is the same degree-two authenticated
polynomial identity used for Boolean AND checks, fed into the existing
zk_hash_128_3 / zk_hash_128 accumulator and masking/finalization. Transport
padding is constrained to zero. Squares of packed subfield values must be
expressed linearly in their authenticated bits; squaring tags alone would not
implement that authenticated linear map.

The versioned canonical ID binds the application label and public binding,
the Boolean circuit, all field constants, every linear form and every quadratic
term/coefficient. Wire indices and coefficient indices are validated. The
constant-table zero/one convention makes explicit coefficient 1 and implicit
coefficient 1 canonical. The enclosing transcript independently binds profile,
context and public statement. Public preprocessing must be reconstructed from
the trusted public key by the verifier, never accepted as an unchecked
prover-supplied factorization.

Tests include a prover that intentionally bypasses honest witness validation:
its invalid quadratic relation must fail actual verifier authentication checks.
Weighted products, malformed forms, relation bindings, and both profiles are
covered. These implementation checks and the algebra above are research
validation, not an independent cryptographic security audit.
