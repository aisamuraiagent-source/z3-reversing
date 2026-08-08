# picoCTF 2019 — vault-door-6

- **Category:** Reverse Engineering
- **Difficulty:** Medium
- **Technique:** model the byte check as constraints, solve with **z3**
- **Status:** solved ✅

## The challenge

`VaultDoor6.java` checks a 32-byte password against a hard-coded array. The minion
brags about a "really cool encryption system" from Applied Cryptography — but the
whole check is a single XOR:

```java
byte[] myBytes = { 0x3b, 0x65, 0x21, 0xa, 0x38, 0x0, 0x36, 0x1d, ... };
for (int i=0; i<32; i++) {
    if (((passBytes[i] ^ 0x55) - myBytes[i]) != 0) {
        return false;
    }
}
```

The condition `(password[i] ^ 0x55) - myBytes[i] == 0` is just
`password[i] ^ 0x55 == myBytes[i]`. The "encryption" is XOR with the constant `0x55`.

## The z3 approach

Model each password byte as an 8-bit variable and mirror the check exactly. z3
recovers the input. (A single `myBytes[i] ^ 0x55` would also do it — the point is
the reusable methodology; see [`solve.py`](solve.py).)

```python
p = [BitVec(f"p{i}", 8) for i in range(32)]
s = Solver()
for i in range(32):
    s.add((p[i] ^ 0x55) == myBytes[i], p[i] >= 0x20, p[i] <= 0x7e)
```

## Result

```
$ python solve.py
sat
password: n0t_mUcH_h4rD3r_tH4n_x0r_faae8b4
FLAG: picoCTF{n0t_mUcH_h4rD3r_tH4n_x0r_faae8b4}
```

Submitted and accepted. The password itself admits it: *"not much harder than xor."*
