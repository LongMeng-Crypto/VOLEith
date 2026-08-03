# Release benchmark baseline

The benchmark was run on 2026-08-04 from a Meson `release` build, linked to an
unmodified FAEST `release` static library.  Ten complete, independently seeded
proof/verification iterations gave:

```text
multiplication gates       39,201
logical witness bits       39,641
VOLE witness bytes          4,956
serialized proof bytes     57,270
circuit construction       3.81 ms
witness generation         1.60 ms
prover mean               158.37 ms
verifier mean             132.32 ms
peak resident memory       29,572 KiB
```

These are an implementation baseline, not constant-time or cross-machine
performance claims.  The CLI reports wall-clock means and process-wide peak
RSS; construction and witness timings are separate from `prove_mean_ms`.

Reproduce with:

```sh
meson setup build-release --buildtype=release \
  -Dfaest_build_dir=/path/to/faest-release-build
meson compile -C build-release
meson test -C build-release --print-errorlogs
build-release/vole-sha256 benchmark --iterations 10 \
  --message-hex 000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f30313233343536 \
  --context benchmark-v1
```

Timings will vary with CPU, compiler, enabled FAEST backend and system load.

## Random-message end-to-end benchmark

`scripts/benchmark_random.py` asks the C++ benchmark process to generate a new
random 55-character ASCII secret for every sample.  It prints the secret in
ASCII and hex, the public SHA-256 digest, the prover/verifier timings and the
serialized proof size.  Every generated proof is required to verify.

```sh
scripts/benchmark_random.py --iterations 10
```

The script is only a launcher: all samples run inside one C++ process and reuse
one constructed circuit.  The prover timer surrounds only `prove()`, and the
verifier timer surrounds only `verify()`, exactly matching the original C++
benchmark timing boundaries.  Digest and witness generation, circuit
construction, process startup and output formatting are excluded.  Circuit
construction and mean witness-generation time are reported separately.
