# One-block SHA-256 binary circuit

This circuit proves the relation

```text
SHA256(secret_message[55]) == public_digest[32]
```

for an exactly 55-byte secret message.  The unique one-block SHA-256 padding
is public and built into the circuit:

```text
secret_message (440 bits) || 0x80 || 0x00000000000001b8
```

The SHA-256 IV and 64 round constants are public constants.  The 256 output
bits are exposed as public statement wires.

## Gate model

The circuit has constant, secret-input, XOR and AND nodes.  NOT is XOR with
one; rotations and shifts are wire permutations.  Consequently AND nodes are
the only multiplication gates over F2.

The nonlinear SHA-256 functions use the following optimized identities:

```text
Ch(x,y,z)  = z XOR (x AND (y XOR z))
Maj(x,y,z) = (x AND y) XOR (z AND (x XOR y))
```

A 32-bit ripple-carry addition uses

```text
sum_i     = a_i XOR b_i XOR carry_i
carry_i+1 = (a_i AND b_i) XOR (carry_i AND (a_i XOR b_i))
```

The carry into bit zero is public zero and the carry out of bit 31 is omitted.
Constant propagation removes ANDs with zero/one and repeated inputs.

## Exact size

For this fixed 55-byte relation the generated circuit contains exactly
**39,201 AND gates**.  Its VOLE extended witness consists of 440 secret input
bits followed by 39,201 AND-output bits, for 39,641 bits total (4,956 bytes
when packed and rounded up).

```text
message schedule:   8,362 AND gates
64 rounds:         30,603 AND gates
final feed-forward:   236 AND gates
------------------------------------
total:             39,201 AND gates
```

The exact gate count is computed from the generated circuit and protected by
a regression test.  Three independent SHA-256 vectors test the complete
padding, schedule, compression, feed-forward and endian conversion path.
