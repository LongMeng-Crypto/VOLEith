# Canonical VBC v1 format

VBC is the canonical little-endian serialization of `BinaryCircuit`. Its
bytes are hashed with SHA-256 to form the `circuit_hash` bound into the generic
Fiat-Shamir transcript.

```text
field                         bytes
magic "VOLEVBC" + version        8
node_count (u32 LE)               4
output_count (u32 LE)             4
node records                10 each
output wire indices          4 each
```

Each node record is:

```text
opcode                           u8
lhs wire index               u32 LE
rhs wire index               u32 LE
constant flag                    u8
```

Opcodes are `0=Constant`, `1=PrivateInput`, `2=PublicInput`, `3=Xor`, and
`4=And`. Wires 0 and 1 must be the unique canonical constants zero and one.
Input nodes have zero operands/flags; gates have a zero constant flag and may
reference only earlier wires. No trailing bytes or alternative encodings are
accepted. A decoder validates the IR and reserializes it to enforce canonical
bytes.

## Generic statement and transcript

The generic relation is:

```text
exists private_inputs:
  evaluate(circuit, private_inputs, public_inputs) == expected_outputs
```

The transcript statement hash binds:

```text
protocol domain and version
SHA256(canonical VBC bytes)
public input bit count and bits
expected output bit count and bits
application context length and bytes
```

Changing a gate, declared output, public input, expected output or context
invalidates the proof. Private inputs and AND outputs form the dynamic VOLE
witness; public inputs are represented with zero prover tags and verifier keys
`Delta * public_bit`.

CLI bit vectors are packed little-endian within each byte, matching the IR's
input declaration order. Unused high bits in the final byte must be zero.
