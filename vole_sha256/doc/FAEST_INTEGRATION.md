# FAEST QuickSilver and VOLE integration

## Parameters

The prototype uses FAEST-128s VOLE/BAVC parameters with a public-length-derived
SHA-256 witness length:

```text
lambda            128 bits
ell             round_up_8(message_bits + actual AND gates)
ell_hat         ell + 400 bits
ell_hat bytes   ceil(ell_hat / 8)
tau                 11
w_grind               7
```

The parent FAEST source is not modified.  `faest_vole.cpp` copies the public
FAEST-128s parameter structure and passes the extended length explicitly to
the official VOLE functions. The upstream ABI stores `l` in 16 bits, but the
VOLE entry points used here accept `ell_hat` as an independent unsigned value
and do not consult that field; the parent source remains unchanged.

## Prover

`sha256_quicksilver_prove` converts the column-major FAEST `V` matrix into
one GF(2^128) tag per committed witness bit.  Circuit wires are evaluated as:

```text
secret input tag = V row [input index]
AND output tag   = V row [message_bits + AND index]
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

for all dynamically committed bits. It constrains only byte-rounding transport
padding to zero, then evaluates each multiplication constraint
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
