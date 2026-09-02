# VOLEith benchmark reference

The numbers below were measured on the development machine with a Meson
`release` build. Prover and verifier measurements cover only the in-process
`prove()` and `verify()` calls: circuit loading/construction, input parsing,
witness preparation outside `prove()`, process startup, and output formatting
are excluded. Results are implementation baselines, not portable performance
claims.

## Optimized one-block SHA-256

The current 55-byte circuit uses one-AND full-adder carries and a one-AND
SHA-256 `Maj`. Ten iterations measured on 2026-08-04 gave:

```text
private input bits            440
public output bits            256
XOR gates                  94,618
multiplication gates       22,217
logical witness bits       22,657
serialized proof bytes     33,917
prover mean                 87.979 ms
prover min                  78.433 ms
prover max                 101.376 ms
verifier mean               73.376 ms
verifier min                67.958 ms
verifier max                83.118 ms
```

The canonical circuit hash is:

```text
1da15d0c0cc37f9f0fc8245e70d145461d910fecf471fa94fa79f0504d64ad93
```

Reproduce it with a 55-byte message and its SHA-256 digest:

```sh
build-release/vole-sha256 export-sha256-circuit \
  --message-length 55 --circuit sha256-55.vbc

build-release/vole-sha256 circuit-benchmark \
  --circuit sha256-55.vbc \
  --private-input-hex "$MESSAGE_HEX" \
  --expected-output-hex "$DIGEST_HEX" \
  --context sha256-optimized-v1 \
  --iterations 10 \
  --security 128
```

The generic benchmark also accepts `--security 192` and `--security 256`.
For this same circuit, the exact proof sizes are 51,604 and 74,494 bytes,
respectively. Fresh multi-iteration timings should be collected on the target
DAA benchmark machine; the historical timing table above remains the 128-bit
baseline.

## SHA-384 and SHA-512 DAA circuits

The shared SHA-512-family core uses 64-bit one-AND full adders and one-AND
`Ch`/`Maj` identities. The current DAA-shaped, one-block circuit sizes are:

| Relation | Private bits | Public input bits | Output bits | AND gates | XOR gates | Security | Proof bytes |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| SHA-384, `sk(192) || lid(384)` | 192 | 384 | 384 | 55,890 | 236,354 | 192 | 118,452 |
| SHA-512, `sk(256) || lid(512)` | 256 | 512 | 512 | 56,764 | 240,250 | 256 | 168,984 |

These are structural and exact proof-size results, not timing measurements.
Use `circuit-benchmark` on the target machine to obtain in-process
prove/verify mean, minimum, and maximum times. Reproduction commands and
construction details are in
[`SHA512_FAMILY_BINARY_CIRCUIT.md`](SHA512_FAMILY_BINARY_CIRCUIT.md).

Run all three DAA-shaped benchmarks with their matching visibility and
128/192/256-bit soundness profiles using:

```sh
scripts/benchmark_sha2.py --iterations 10
```

Use `--profile all-secret` to reproduce the 55-byte SHA-256, 72-byte SHA-384,
and 96-byte SHA-512 all-witness cases. The driver also accepts arbitrary
single-algorithm layouts and message lengths and prints the resulting exact
compression-block count. See
[`SHA2_BENCHMARK_DRIVER.md`](SHA2_BENCHMARK_DRIVER.md).

## Public-length-derived SHA-256 capacity

The public message length determines the padding, number of compression blocks,
circuit, committed witness, and proof size. The implementation supports 0 to
550 secret bytes. Current structural measurements are:

| Message bytes | SHA-256 blocks | Private bits | AND gates | XOR gates | Proof bytes |
| ---: | ---: | ---: | ---: | ---: | ---: |
| 0 | 1 | 0 | 0 | 0 | 2,754 |
| 1 | 1 | 8 | 20,515 | 85,875 | 30,980 |
| 55 | 1 | 440 | 22,217 | 94,618 | 33,917 |
| 56 | 2 | 448 | 39,680 | 164,857 | 57,930 |
| 64 | 2 | 512 | 39,963 | 166,251 | 58,414 |
| 119 | 2 | 952 | 44,852 | 191,736 | 65,740 |
| 120 | 3 | 960 | 62,310 | 261,940 | 89,753 |
| 550 | 9 | 4,400 | 202,803 | 869,238 | 287,665 |

For an empty message the complete padded SHA-256 computation is constant, so
the generator folds away all gates; 2,754 bytes are the fixed proof framing and
VOLE/BAVC overhead.

## AES-128 comparison

Both AES experiments prove that a private AES-128 key maps a public plaintext
to a public ciphertext. The portable Boolean frontend and the optimized
FAEST-style extension-field relation are checked against the same FIPS-197
known-answer vector.

| AES-128 frontend | Nonlinear constraints | Extended witness | Proof bytes | Prover mean | Verifier mean |
| --- | ---: | ---: | ---: | ---: | ---: |
| Boolean baseline | 76,800 GF(2) AND | 76,928 bits | 108,530 | 309.943 ms | 267.969 ms |
| FAEST-style | 200 GF(2^8) quadratic | 1,280 bits | 4,514 | 18.720 ms | 14.710 ms |

The Boolean benchmark used ten iterations and observed prover min/max
290.320/334.802 ms and verifier min/max 252.114/282.589 ms. The FAEST-style
benchmark observed prover min/max 16.841/22.125 ms and verifier min/max
14.106/15.515 ms.

Commands for regenerating both AES relations and proofs are in
[`../vole_aes/README.md`](../vole_aes/README.md).

## Random-message SHA-256 benchmark

`scripts/benchmark_random.py` asks one C++ benchmark process to generate a new
random printable secret for every sample. It prints each secret in ASCII and
hex, the public digest, proof size, timings, and verification result. The
circuit is constructed once and reused.

```sh
scripts/benchmark_random.py --iterations 10 --message-bytes 55
scripts/benchmark_random.py --iterations 10 --message-bytes 550
```

The script defaults to `build-release/vole-sha256`; use `--binary PATH` to
select another build.

## Historical pre-optimization SHA-256 baseline

Before the one-AND full-adder and `Maj` changes, the same 55-byte circuit used
39,201 AND gates, a 39,641-bit logical witness, and a 57,270-byte proof. A later
ten-iteration in-process run measured 132.825 ms prover time and 110.448 ms
verifier time. These values are retained only to quantify the optimization and
must not be treated as current circuit parameters.
