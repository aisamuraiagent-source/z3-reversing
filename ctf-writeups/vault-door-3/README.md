# picoCTF 2019 — vault-door-3

- **Category:** Reverse Engineering
- **Difficulty:** Medium
- **Technique:** model the check as constraints, solve with **z3** (no brute force)
- **Status:** solved ✅

## The challenge

`VaultDoor3.java` reads a password and runs `checkPassword`. The method takes the
32-char password, scrambles the characters into a `buffer` through four index
loops, and compares the result to a fixed string:

```java
public boolean checkPassword(String password) {
    if (password.length() != 32) return false;
    char[] buffer = new char[32];
    int i;
    for (i=0; i<8; i++)        buffer[i] = password.charAt(i);      // identity
    for (; i<16; i++)          buffer[i] = password.charAt(23-i);   // reversed slice
    for (; i<32; i+=2)         buffer[i] = password.charAt(46-i);   // even indices
    for (i=31; i>=17; i-=2)    buffer[i] = password.charAt(i);      // odd indices
    String s = new String(buffer);
    return s.equals("jU5t_a_sna_3lpm13gf49_u_4_m9r540");
}
```

There is no arithmetic — the four loops are just a **permutation** of the input
characters. The author even hints at it: the recovered password reads
*"just a simple anagram"*.

## The z3 approach

Instead of inverting the permutation by hand, model each password character as a
symbolic variable, apply the **exact same four loops** symbolically, constrain each
`buffer[i]` to equal the target character, and let z3 recover the input. This is the
defensive/offensive duality in miniature: the solver computes the input that
satisfies every constraint at once.

See [`solve.py`](solve.py). Core:

```python
p = [BitVec(f"p{i}", 8) for i in range(32)]
buf = [None]*32
for i in range(0,8):        buf[i] = p[i]
for i in range(8,16):       buf[i] = p[23-i]
for i in range(16,32,2):    buf[i] = p[46-i]
for i in range(31,16,-2):   buf[i] = p[i]
s = Solver()
for i in range(32):
    s.add(buf[i] == ord(target[i]), p[i] >= 0x20, p[i] <= 0x7e)
```

## Result

```
$ python solve.py
sat
password: jU5t_a_s1mpl3_an4gr4m_4_u_99f530
FLAG: picoCTF{jU5t_a_s1mpl3_an4gr4m_4_u_99f530}
```

Submitted and accepted. Solved in milliseconds — a 32-character anagram the
challenge expected you to untangle by hand.
