# SHA-256 input visibility layouts

The SHA-256 frontend can classify every message bit independently as a secret
or public input. This is a frontend feature over the generic `BinaryCircuit`
IR: secret positions generate `PrivateInput` nodes and public positions
generate `PublicInput` nodes. Padding and the 256 digest outputs remain public
and unchanged.

## Range syntax

`--input-layout-bits` is a comma-separated partition of the complete message:

```text
secret:0:128,public:128:384
```

Every interval is half-open `[begin,end)`. Ranges must be ordered, nonempty,
nonoverlapping, and cover exactly `[0,message_length*8)`. Any number of
alternating ranges and non-byte-aligned boundaries are allowed. Adjacent ranges
with the same visibility are normalized into one canonical range.

Bit indices follow the SHA/FIPS bitstream convention: bit zero is the most
significant bit of the first message byte. The frontend translates this to the
existing circuit's least-significant-bit-first wire order. This preserves the
canonical all-secret VBC while presenting conventional SHA bit positions.

## Export and pack inputs

For `SHA256(sk || lid)` with a 128-bit `sk` and 256-bit `lid`:

```sh
build-release/vole-sha256 export-sha256-circuit \
  --message-length 48 \
  --input-layout-bits "secret:0:128,public:128:384" \
  --circuit sha256-sk-lid.vbc

build-release/vole-sha256 sha256-partition-input \
  --message-hex <16-byte-sk><32-byte-lid> \
  --input-layout-bits "secret:0:128,public:128:384"
```

The second command prints:

```text
private_input_bits=128
public_input_bits=256
private_input_hex=<compact private input>
public_input_hex=<compact public input>
public_sha256=<32-byte digest>
```

The compact bit vectors follow input-node declaration order and are packed
LSB-first for the generic CLI. For byte-aligned ranges in message order, the
hex outputs are simply the corresponding concatenated message byte ranges.
For arbitrary bit boundaries, always use the partition helper rather than
manually repacking bits.

Pass the emitted values to the generic backend:

```sh
build-release/vole-sha256 circuit-prove \
  --circuit sha256-sk-lid.vbc \
  --private-input-hex "$PRIVATE_INPUT_HEX" \
  --public-input-hex "$PUBLIC_INPUT_HEX" \
  --expected-output-hex "$DIGEST_HEX" \
  --context sha256-sk-lid-v1 \
  --security 128 \
  --proof sha256-sk-lid.proof

build-release/vole-sha256 circuit-verify \
  --circuit sha256-sk-lid.vbc \
  --public-input-hex "$PUBLIC_INPUT_HEX" \
  --expected-output-hex "$DIGEST_HEX" \
  --context sha256-sk-lid-v1 \
  --security 128 \
  --proof sha256-sk-lid.proof
```

The verifier never receives the private bits. The VBC opcode sequence binds
the visibility policy through the circuit identifier in the Fiat-Shamir
transcript. Changing a position from public to secret or vice versa produces a
different circuit hash and invalidates the proof.

## Witness and constraint size

For a mixed circuit:

```text
logical witness bits = number of secret message bits + AND gate outputs
```

Public message bits are excluded from the VOLE witness. They remain symbolic,
however, so changing visibility alone does not generally reduce the SHA-256
AND count. Compile-time constants are distinct from public inputs and may be
constant-folded.

The older `vole_sha256::prove` convenience API intentionally remains an
all-secret compatibility path. Mixed-visibility circuits use the generic
`vole_backend::prove/verify` API and `circuit-prove/circuit-verify` commands.
