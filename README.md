# VOLEith-SHA256

An independent VOLE-in-the-head/QuickSilver proof backend with SHA-256 and
AES-128 binary-circuit frontends.

The current implementation contains:

- an algorithm-independent in-memory `BinaryCircuit` IR and builder;
- SHA-256 generation migrated onto that IR without changing proof behavior;
- an AES-128 frontend with private key, public plaintext and public ciphertext;
- generic private/public input QuickSilver and NIZK APIs;
- canonical `.vbc` serialization with circuit-hash transcript binding;
- a public message length from 0 through 550 bytes, with secret message bytes;
- standard SHA-256 padding and chaining over one through nine blocks;
- public-length-derived witness and VOLE capacity: only actual message bits
  and actual circuit AND outputs are committed;
- a generic degree-2 QuickSilver algebra layer for `x*y+z=0` and public linear
  constraints;
- randomized constraint aggregation over the FAEST GF(2^128) polynomial
  basis;
- full SHA-256 constraint traversal through FAEST's native
  `zk_hash_128_3`/`zk_hash_128` QuickSilver accumulators;
- vendored minimal FAEST `vole_commit`, BAVC, field and SHAKE primitives under
  `third_party/faest`, with upstream attribution and no external FAEST build;
- a complete Fiat-Shamir transcript binding length, digest and context, and a dynamically sized serialized
  non-interactive proof with public `prove`/`verify` APIs;
- a command-line prover/verifier, deterministic known-answer test, negative
  tests and release benchmark driver.

Build and test from a clean checkout:

```sh
meson setup build
meson compile -C build
meson test -C build --print-errorlogs
```

Example CLI workflow:

```sh
build/vole-sha256 prove --message-hex <0..1100 hex chars> --proof proof.bin --context app-v2
build/vole-sha256 verify --digest-hex <64 hex chars> --message-length <0..550> --proof proof.bin --context app-v2
build/vole-sha256 inspect --message-length <0..550> --proof proof.bin
build/vole-sha256 benchmark --iterations 10
```

Generic circuit-file workflow:

```sh
build/vole-sha256 export-sha256-circuit --message-length 55 --circuit sha256-55.vbc
build/vole-sha256 export-aes128-circuit --circuit aes128.vbc
build/vole-sha256 export-aes128-faest-relation --relation aes128-faest.vqir
build/vole-sha256 json-to-vbc --json examples/and_xor.json --circuit and_xor.vbc
build/vole-sha256 circuit-inspect --circuit sha256-55.vbc
build/vole-sha256 circuit-prove --circuit sha256-55.vbc \
  --private-input-hex <packed private bits> \
  --expected-output-hex <packed public output bits> \
  --proof proof.bin --context app-v1
build/vole-sha256 circuit-verify --circuit sha256-55.vbc \
  --expected-output-hex <packed public output bits> \
  --proof proof.bin --context app-v1
build/vole-sha256 circuit-benchmark --circuit sha256-55.vbc \
  --private-input-hex <packed private bits> \
  --expected-output-hex <packed public output bits> \
  --context app-v1 --iterations 10
```

`circuit-benchmark` deserializes the circuit and parses all inputs once, then
times only the in-process generic `prove()` and `verify()` calls. It reports
mean/min/max milliseconds, proof bytes, and XOR/AND gate counts.

The optimized AES-128s relation uses extension-field quadratic constraints:

```sh
build/vole-sha256 aes128-faest-prove --relation aes128-faest.vqir \
  --private-input-hex <16-byte-key> --public-input-hex <16-byte-plaintext> \
  --expected-output-hex <16-byte-ciphertext> --proof aes.proof
build/vole-sha256 aes128-faest-verify --relation aes128-faest.vqir \
  --public-input-hex <16-byte-plaintext> \
  --expected-output-hex <16-byte-ciphertext> --proof aes.proof
```

The strict JSON compiler format is documented in
[`doc/JSON_CIRCUIT_FORMAT.md`](doc/JSON_CIRCUIT_FORMAT.md). Generic backend
implementation files live under `backend/`; SHA-256 and AES-128 are independent
frontends under `circuits/sha256/` and `circuits/aes/`.

To benchmark fresh random printable secrets and print every secret,
public digest, prover/verifier time and proof size:

```sh
scripts/benchmark_random.py --iterations 5 --message-bytes 550
```

This script defaults to `build-release/vole-sha256`; use `--binary PATH` for
another build.  It delegates to the in-process C++ benchmark, so the reported
prover and verifier times exclude process startup and one-time circuit
construction.

For meaningful performance results, configure Meson with
`--buildtype=release`; the default developer build is unoptimized.
The measured baseline and reproduction command are in `doc/BENCHMARK.md`.

The integration tests establish `Q = V + Delta*u`, form `d = witness XOR u`,
and check that the verifier reconstructs the prover's `a0`.  They also reject
an incorrect public digest, an incorrect committed AND output, and a tampered
masked witness.

The NIZK API is declared in `nizk.hpp`:

```cpp
auto proof = vole_sha256::prove(circuit, secret_message, public_digest,
                                application_context, randomness);
bool ok = vole_sha256::verify(circuit, public_digest,
                              application_context, proof);
```
