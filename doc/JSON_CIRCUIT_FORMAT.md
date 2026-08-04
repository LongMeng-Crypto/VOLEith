# JSON circuit input format

`json-to-vbc` accepts a strict, versioned JSON representation and emits the
canonical `.vbc` binary representation. JSON is a compiler input; proofs bind
the resulting VBC bytes and never bind JSON text.

```json
{
  "format": "vole-binary-circuit",
  "version": 1,
  "nodes": [
    { "op": "constant", "value": 0 },
    { "op": "constant", "value": 1 },
    { "op": "private" },
    { "op": "public" },
    { "op": "xor", "lhs": 2, "rhs": 3 },
    { "op": "and", "lhs": 4, "rhs": 3 }
  ],
  "outputs": [4, 5]
}
```

Nodes are wires and their zero-based array positions are wire identifiers.
Canonical circuits must begin with constant-zero wire 0 and constant-one wire
1. `lhs` and `rhs` must refer to earlier wires. Supported operations are
`constant`, `private`, `public`, `xor`, and `and`.

Unknown or duplicate fields, unsupported versions, non-canonical constants,
forward references, invalid wire identifiers, and trailing JSON values are
rejected. Input and output bit ordering at the CLI remains packed LSB-first.

Compile and inspect:

```sh
build-release/vole-sha256 json-to-vbc \
  --json examples/and_xor.json --circuit and_xor.vbc
build-release/vole-sha256 circuit-inspect --circuit and_xor.vbc
```
