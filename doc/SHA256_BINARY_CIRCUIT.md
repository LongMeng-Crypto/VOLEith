# Generic bounded SHA-256 binary circuit

This circuit proves the relation

```text
SHA256(secret_message[0:public_length]) == public_digest[32]
```

for a public length between 0 and 550 bytes and a secret message. Standard
padding and the 64-bit length field are built into the circuit. The number of
compression blocks is `ceil((8*length+65)/512)`, hence at most nine.

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
Maj(x,y,z) = x XOR ((x XOR y) AND (x XOR z))
```

A 32-bit ripple-carry addition uses

```text
sum_i     = a_i XOR b_i XOR carry_i
carry_i+1 = a_i XOR ((a_i XOR b_i) AND (a_i XOR carry_i))
```

The carry into bit zero is public zero and the carry out of bit 31 is omitted.
Constant propagation removes ANDs with zero/one and repeated inputs.

## Exact size

The 55-byte compatibility circuit has exactly **22,217 AND gates** and commits
440 input bits, producing 22,657 logical witness bits. The 550-byte maximum
circuit has **202,803 AND gates** and commits 4,400 input bits, producing
207,203 logical witness bits. Each proof rounds only its own logical witness
length to a byte boundary.

```text
message schedule:   4,301 AND gates
64 rounds:         17,672 AND gates
final feed-forward:   244 AND gates
------------------------------------
total:             22,217 AND gates
```

Regression tests compare 0, 1, 55, 56, 64, 119, 120 and 550-byte circuits to
OpenSSL, covering padding boundaries and maximum nine-block chaining.
