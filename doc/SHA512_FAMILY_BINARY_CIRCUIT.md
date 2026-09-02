# SHA-384 and SHA-512 binary circuits

SHA-384 and SHA-512 share the same SHA-512-family compression function. The
frontends therefore use one composable 64-bit core and differ only in their IV
and digest length. Both compile to the generic constant/private-input/
public-input/XOR/AND `BinaryCircuit` IR and canonical `.vbc` format.

For a fixed byte-string length and visibility layout, the standalone relations
are:

```text
SHA384(message) = public_digest[384]
SHA512(message) = public_digest[512]
```

The message length determines the exact number of compression blocks:

```text
blocks = ceil((message_bits + 1 + 128) / 1024)
```

Padding, the 128-bit big-endian length field, the IV, and all 80 round
constants are circuit constants. No maximum-capacity blocks are included in a
proof. The standalone byte-string wrappers accept 0 through 1100 bytes; the
core itself accepts an arbitrary bit-length wire span.

## Composable core

`build_sha512_family()` accepts message wires that already exist in a
`BinaryCircuit`. The wires are in SHA/FIPS order: index zero is the
most-significant bit of the first byte. It returns digest wires in the same
order and deliberately creates neither input nodes nor public outputs.
`add_sha2_digest_outputs()` is the separate opt-in step for digests that form
part of the public statement.

This allows a larger relation to reuse an input wire vector in several hashes
and to pass one digest directly into another hash. In particular, a TPM
relation can share `sk` between `SHA2(sk || lid)` and `SHA2(sk || gid)`, then
pass the second digest wires directly into `SHA2(s || et)` without committing
a duplicate `et` or adding equality constraints.

The `Sha384Circuit` and `Sha512Circuit` wrappers allocate inputs according to
an `InputVisibilityLayout`, invoke the composable core, and expose the digest
as packed public output bits.

## VOLEith-oriented gate construction

Rotations, shifts, NOT, and XOR are linear over GF(2). The nonlinear Boolean
functions use one AND per bit:

```text
Ch(x,y,z)  = z XOR (x AND (y XOR z))
Maj(x,y,z) = x XOR ((x XOR y) AND (x XOR z))
```

Every 64-bit modular addition uses a one-AND full-adder carry:

```text
propagate = a XOR b
sum       = propagate XOR carry
carry'    = a XOR (propagate AND (a XOR carry))
```

The unused carry out of bit 63 is omitted. Exact duplicate local gates are
reused, and the generic IR folds operations involving zero, one, or identical
wires. On the final SHA-384 block, feed-forward additions for the two truncated
state words are omitted. A carry-save representation is not used because with
the one-AND full adder it does not lower the committed AND count and generally
adds XOR nodes; QuickSilver proof size is driven primarily by the AND count,
not multiplicative depth.

## DAA-sized circuits

The intended one-hash DAA layouts are:

| Algorithm | Message layout | Message bytes | Security | AND gates | XOR gates | Proof bytes |
| --- | --- | ---: | ---: | ---: | ---: | ---: |
| SHA-384 | `secret:0:192,public:192:576` | 72 | 192 | 55,890 | 236,354 | 118,452 |
| SHA-512 | `secret:0:256,public:256:768` | 96 | 256 | 56,764 | 240,250 | 168,984 |

The proof sizes are exact for the current canonical circuits and selected
VOLEith security levels. Timings are intentionally left to the in-process
benchmark on the target machine.

SHA-384/72-byte multiplication breakdown:

```text
message schedule    10,893
80 rounds           44,622
final feed-forward     375
total               55,890
```

SHA-512/96-byte multiplication breakdown:

```text
message schedule    11,455
80 rounds           44,808
final feed-forward     501
total               56,764
```

## CLI workflow

```sh
build-release/vole-sha256 export-sha384-circuit \
  --message-length 72 \
  --input-layout-bits "secret:0:192,public:192:576" \
  --circuit sha384-sk-lid.vbc

build-release/vole-sha256 sha384-partition-input \
  --message-hex <24-byte-secret><48-byte-public> \
  --input-layout-bits "secret:0:192,public:192:576"

build-release/vole-sha256 export-sha512-circuit \
  --message-length 96 \
  --input-layout-bits "secret:0:256,public:256:768" \
  --circuit sha512-sk-lid.vbc

build-release/vole-sha256 sha512-partition-input \
  --message-hex <32-byte-secret><64-byte-public> \
  --input-layout-bits "secret:0:256,public:256:768"
```

Use the emitted private input, public input, and digest with the generic
`circuit-prove`, `circuit-verify`, and `circuit-benchmark` commands. Select
`--security 192` for SHA-384 and `--security 256` for SHA-512 in the intended
DAA profiles.
