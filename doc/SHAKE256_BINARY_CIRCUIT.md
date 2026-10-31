# SHAKE256 Boolean proof baseline

This frontend proves knowledge of a secret input whose SHAKE256 output equals
the public output. It has no UOV dependency. It uses the existing VBCZK v3
BinaryCircuit prover, security levels 128/192/256, and profiles s/f.

The input length and output length are public, fixed circuit parameters.
Input lengths 0..1082 bits fit one SHAKE256 absorb block after the four SHAKE
suffix bits and pad10*1. Output lengths 1..1088 bits fit one rate block.
Within each byte, bit 0 is the least significant bit. Unused high bits in a
partial output byte are zero in the generic packed CLI encoding.

The circuit executes all 24 Keccak-f[1600] rounds. Theta, rho, pi and iota
are affine; chi uses a XOR c XOR (b AND c). Constant folding is performed by
BinaryCircuit. A backward dependency pass removes unused nodes while preserving
the complete input layout. There is no reduced-round hash or substituted hash.

For 384 secret input bits:

| Output bits | ANDs | XORs | Logical witness bits |
| ---: | ---: | ---: | ---: |
| 256 | 37056 | 147298 | 37440 |
| 360 | 37160 | 147626 | 37544 |

These are counts from the compiled circuit. Other output lengths have their
own actual counts, bounded above by 38400 ANDs. The last-round pruning bound
is 23*1600 + output_bits, before any additional constant/dependency elimination.

Build and run from the VOLEith root:

```sh
meson setup build-release --buildtype=release   # first configuration only
meson compile -C build-release
meson test -C build-release --print-errorlogs
build-release/vole-shake256 --input-bits 384 --output-bits 360 \
  --security 128 --profile s --iterations 20
python3 scripts/benchmark_shake256.py --iterations 20
```

The benchmark uses one untimed complete prove/verify warm-up, reports medians,
p25/p75 and raw samples in milliseconds, complete proof bytes, witness length,
VOLE correction bytes, expanded VOLE rows and process peak RSS. Circuit
construction and preparation precede the timed calls. Outputs are JSON; the
Python driver also writes CSV. Secret inputs are never printed.

The existing generic proof commands are also available after exporting a circuit:

```sh
build-release/vole-sha256 export-shake256-circuit --input-bits 384 \
  --output-bits 360 --circuit /tmp/shake360.vbc
build-release/vole-sha256 circuit-inspect --circuit /tmp/shake360.vbc \
  --security 128 --profile s
```

Use circuit-prove/circuit-verify with the existing private-input-hex and
expected-output-hex options. The C++ API is make_shake256(input_bits,
output_bits), returning an ordinary BinaryCircuit; append_shake256 reuses
existing input wires in a larger circuit.

Tests cross-check OpenSSL SHAKE256 and the independent native Keccak permutation,
including non-byte-aligned input/output and padding boundaries. Proof tests
cover all six security/profile combinations and corrupted outputs, profiles,
contexts and proof bytes. Existing AES/SHA-2 tests and deterministic KATs remain
part of the same suite.
