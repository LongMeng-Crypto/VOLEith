# FAEST QuickSilver and VOLE integration

## Parameters

The legacy SHA-256 convenience frontend and optimized AES relation use
FAEST-128s. The generic binary-circuit backend additionally supports
FAEST-192s and FAEST-256s:

| Level | lambda | ell_hat - ell | tau | w_grind | opening bytes |
| ---: | ---: | ---: | ---: | ---: | ---: |
| 128 | 128 | 400 bits | 11 | 7 | 2,160 |
| 192 | 192 | 592 bits | 16 | 12 | 5,040 |
| 256 | 256 | 784 bits | 22 | 6 | 9,952 |

For a binary circuit, `ell` is the byte-rounded sum of private-input bits and
actual AND outputs. `ell_hat = ell + 3*lambda + 16`.

The required upstream FAEST VOLE, BAVC, field, universal-hash and SHAKE
primitives are vendored under `third_party/faest` with their MIT license.
`faest_vole.cpp` passes the extended length explicitly to those primitives.
The upstream ABI stores `l` in 16 bits, but the VOLE entry points used here
accept `ell_hat` independently and do not consult that field.

## Prover

The traversal converts the column-major FAEST `V` matrix into one
GF(2^lambda) tag per committed witness bit. Circuit wires are evaluated as:

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

The matching `zk_hash_128`, `zk_hash_192`, or `zk_hash_256` accumulator and
the standard FAEST `a1/a2` reconstruction then produce the expected `a0`
exactly when all constraints hold.

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
this adapter are documented in `NIZK_PROOF_FORMAT.md`; the full parameter table
and generic v2 header are in `SECURITY_PARAMETERS.md`.
