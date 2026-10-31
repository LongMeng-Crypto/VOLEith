# Corrected NIZK proof formats

See [the constraint-encoding fix](SOUNDNESS_FIX_V1.md) for the degree argument.
The current generic circuit format is `VBCZK`, version **4**, security-level
code 1/2/3 and profile code 1/2. Its circuit-ID domain and transcript domain
are `VOLE-BINARY-CIRCUIT-ID-v4` and `VOLE-BINARY-CIRCUIT-NIZK-v4`.
Profiled AES/mixed relations use `VQRZK`, version **4**, with level code 1 and
profile code 1/2, and domain `VOLE-QUADRATIC-RELATION-NIZK-v4`.
The fixed-128 relation API uses `VQRZK` v4, level/profile bytes 0/0 and domain
`VOLE-RELATION-NIZK-v4`. The separate legacy SHA-256 API uses `VSH256`,
version **3**, reserved byte zero and domain `VOLE-SHA256-GENERIC-NIZK-v3`.
These APIs reject the previous wire versions; there is no old-version fallback.
The VBC/VQIR circuit-file formats themselves have not changed.

For byte-rounded committed witness ell and security lambda:

```text
header                          8 bytes
VOLE corrections                (tau-1) * (ell + 3*lambda + 16)/8
u_tilde                         lambda/8 + 2
masked witness d                ell/8
a1, a2                          2*lambda/8
BAVC opening                    (3*tau + T_open)*lambda/8
challenge_3                     lambda/8
IV preimage                     16
grinding counter                4 (little endian)
```

The verifier derives the expected size from the public relation. a0 is not
serialized: the verifier reconstructs it from its authenticated constraint
hash, masks, Delta, a1 and a2, then recomputes the final challenge. The final
challenge/grinding condition and BAVC opening must both verify.
The statement hash binds the relation/circuit identifier, security and profile,
public inputs, public outputs and context before VOLE commitment and challenges.
The proof seed derives from the complete witness, statement and caller randomness.
All correction vectors, consistency hashes and masked witness are bound before
the constraint challenge; a0/a1/a2 are bound before the final opening challenge.

For 128s, total bytes are 11*ell/8+2754. For 128f they are 16*ell/8+3372.
These sizes are unchanged by the soundness correction.
