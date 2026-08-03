# Degree-2 QuickSilver constraint algebra

For a committed bit `x`, the prover has its value and tag `(x,t_x)`.  The
verifier has a global key `Delta` and the authentication key

```text
k_x = t_x + Delta*x.
```

For the multiplication constraint `x*y+z=0`, define

```text
P(X) = (t_x + X*x)(t_y + X*y) + X(t_z + X*z).
```

Its coefficients are

```text
P_0 = t_x*t_y
P_1 = x*t_y + y*t_x + t_z
P_2 = x*y + z.
```

The prover aggregates and commits only to `P_0,P_1`.  The top coefficient is
the constraint residual and is required to vanish.  The verifier computes

```text
k_x*k_y + Delta*k_z = P(Delta)
```

and compares it with `P_0 + Delta*P_1`.  If the constraint is false, the two
sides differ by `Delta^2*(x*y+z)`.

A public linear constraint `x+c=0` is lifted to degree two:

```text
L(X) = X(t_x + X(x+c)).
```

This gives the same omitted-top-coefficient check.  Multiple constraints are
combined using powers of the challenge derived from `chall_2`.
