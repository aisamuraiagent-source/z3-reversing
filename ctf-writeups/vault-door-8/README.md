# picoCTF 2019 — vault-door-8

- **Category:** Reverse Engineering
- **Difficulty:** Hard
- **Technique:** model the bit-transposition as constraints over 8-bit vectors, solve with **z3**
- **Status:** solved ✅

## The challenge

`VaultDoor8.java` runs each password byte through `scramble()`, which applies eight
`switchBits(c, p1, p2)` operations — each **swaps the bit at position `p1` with the
bit at position `p2`** inside the byte — then compares the result to a fixed array:

```java
// swap sequence applied to every byte:
switchBits(c,1,2); switchBits(c,0,3); switchBits(c,5,6); switchBits(c,4,7);
switchBits(c,0,1); switchBits(c,3,4); switchBits(c,2,5); switchBits(c,6,7);
```

Eight bit-swaps per byte, 32 bytes — untangling that by hand is brutal.

## The z3 approach

Model each password byte as an 8-bit vector, implement `switchBits` symbolically,
apply the **same eight swaps in the same order**, and constrain the scrambled result
to equal `expected[i]`. z3 inverts all eight transpositions at once. See
[`solve.py`](solve.py).

```python
def switch_bits(c, p1, p2):
    m1, m2 = BitVecVal(1<<p1,8), BitVecVal(1<<p2,8)
    bit1, bit2 = c & m1, c & m2
    rest = c & ~(m1 | m2)
    shift = p2 - p1
    return (bit1 << shift) | LShR(bit2, shift) | rest
```

## Result

```
$ python solve.py
sat
password: s0m3_m0r3_b1t_sh1fTiNg_987ee52a8
FLAG: picoCTF{s0m3_m0r3_b1t_sh1fTiNg_987ee52a8}
```

Submitted and accepted. Eight bit-swaps, undone in a single solver call — the hard
one in the vault-door series, cut clean.
