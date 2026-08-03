# FAEST QuickSilver and VOLE integration

## Parameters

The prototype uses the FAEST-128s VOLE/BAVC parameters with a SHA-256-specific
witness length:

```text
lambda            128 bits
ell             39,648 bits
ell_hat         40,048 bits
ell_hat bytes    5,006 bytes
tau                 11
w_grind               7
```

The parent FAEST source is not modified.  `faest_vole.cpp` copies the public
FAEST-128s parameter structure and changes only `ell` before calling the
official VOLE and BAVC functions.

## Prover

`sha256_quicksilver_prove` converts the column-major FAEST `V` matrix into
one GF(2^128) tag per committed witness bit.  Circuit wires are evaluated as:

```text
secret input tag = V row [input index]
AND output tag   = V row [440 + AND index]
XOR tag          = XOR of input tags
constant tag     = zero
```

For every `z=x AND y`, the prover sends the degree-zero and degree-one
constraint coefficients into `zk_hash_128_3_update`; the residual degree-two
coefficient is omitted.  Public digest equalities are lifted to degree two and
processed by the same hasher.  Finalization uses FAEST's two extra lambda-bit
VOLE rows and mask polynomials exactly as the AES wrapper does.

## Verifier

The verifier converts reconstructed `Q` to row keys and applies

```text
key[i] = Q[i] + Delta*d[i]
```

for all 39,648 committed bits.  It evaluates each multiplication constraint
as

```text
k_x*k_y + Delta*k_z
```

and each public output equality as

```text
Delta*(k_output + Delta*public_bit).
```

`zk_hash_128_finalize` and the standard FAEST `a1/a2` reconstruction then
produce the expected `a0` exactly when all constraints hold.

## VOLE correlation

The stage-four adapter calls the unmodified functions:

```text
vole_commit
decode_all_chall_3
bavc_open
vole_reconstruct
```

The integration test checks every correlation bit:

```text
Q[column] = V[column] XOR challenge[column]*u.
```

The Fiat-Shamir transcript and serialized non-interactive proof layer built on
this adapter are documented in `NIZK_PROOF_FORMAT.md`.
