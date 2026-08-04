# Fiat-Shamir transcript and proof format

## Transcript

The statement digest is

```text
mu = H2_0("VOLE-SHA256-GENERIC-NIZK-v2" || max_bytes || message_length ||
          digest || len(context) || context).
```

The prover derives the VOLE root key and IV preimage from the complete witness,
`mu`, and 32 bytes of caller-supplied randomness using `H3`.  The remaining
challenges follow the FAEST ordering:

```text
chall_1 = H2_1(mu || hcom || corrections || iv)
u_tilde = vole_hash(chall_1, u)
V_tilde[j] = vole_hash(chall_1, V[j])
chall_2 = H2_2(chall_1 || u_tilde || all V_tilde || d)
(a0,a1,a2) = SHA256-QuickSilver(chall_2)
chall_3 = H2_3(chall_2 || a0 || a1 || a2 || counter)
```

The prover grinds `counter` until the FAEST-128s grinding condition holds and
the BAVC challenge can be decoded and opened.  The verifier reconstructs `Q`
and `hcom`, recomputes `chall_1`, derives `Q_tilde`, reconstructs `a0`, and
finally recomputes `chall_3`.

## Serialization

The public message length determines the circuit, witness layout and expected
proof size. Integers are little-endian.

```text
field                    bytes
magic/version                8
VOLE corrections       10 * ell_hat_bytes
u_tilde                     18
masked witness d         ceil(ell/8)
a1                          16
a2                          16
BAVC opening             2,160
chall_3                     16
IV preimage                 16
grinding counter             4
--------------------------------
total                    derived from public length
```

Examples are 2,754 bytes for an empty message, 57,270 bytes for 55 bytes,
97,519 bytes for 56 bytes, and 509,029 bytes for the 550-byte maximum.

`a0` is intentionally absent: as in FAEST, the verifier reconstructs it from
`Q`, `d`, `a1`, `a2`, and the public SHA-256 statement.

The magic bytes contain both the protocol identifier and serialization
version. The verifier derives the expected size from the public length and
rejects an incorrect size or version before cryptographic processing.
