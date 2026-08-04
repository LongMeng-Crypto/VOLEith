# VOLE-SHA256

An independent subproject for proving a bounded generic SHA-256 preimage relation
with FAEST-style VOLE-in-the-head and QuickSilver.  It does not modify or
replace the FAEST AES circuit.

The current implementation contains:

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
- real `vole_commit`, BAVC opening and `vole_reconstruct` integration against
  the unmodified parent FAEST static library;
- a complete Fiat-Shamir transcript binding length, digest and context, and a dynamically sized serialized
  non-interactive proof with public `prove`/`verify` APIs;
- a command-line prover/verifier, deterministic known-answer test, negative
  tests and release benchmark driver.

Build and test independently from the parent FAEST project:

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

The parent FAEST project must be built first because this independent project
links its internal static library without changing the parent source tree.
