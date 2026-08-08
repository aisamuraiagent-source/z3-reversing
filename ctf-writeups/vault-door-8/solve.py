# picoCTF 2019 — vault-door-8 (Reverse Engineering, Hard)
# scramble() transposes pairs of bits inside each byte (8 switchBits in sequence),
# then compares to expected[]. We mirror switchBits on 8-bit vectors and let z3
# recover the password. Bit-transposition by hand is brutal; z3 inverts it exactly.
from z3 import *

expected = [
    0xF4, 0xC0, 0x97, 0xF0, 0x77, 0x97, 0xC0, 0xE4,
    0xF0, 0x77, 0xA4, 0xD0, 0xC5, 0x77, 0xF4, 0x86,
    0xD0, 0xA5, 0x45, 0x96, 0x27, 0xB5, 0x77, 0xD2,
    0xC2, 0xF1, 0x95, 0x95, 0xD1, 0xE0, 0x94, 0xC2,
]

# swaps the bit at position p1 with the bit at position p2 (p1 < p2)
def switch_bits(c, p1, p2):
    mask1 = BitVecVal(1 << p1, 8)
    mask2 = BitVecVal(1 << p2, 8)
    bit1 = c & mask1
    bit2 = c & mask2
    rest = c & ~(mask1 | mask2)
    shift = p2 - p1
    return (bit1 << shift) | LShR(bit2, shift) | rest   # >> is logical (unsigned)

SWAPS = [(1, 2), (0, 3), (5, 6), (4, 7), (0, 1), (3, 4), (2, 5), (6, 7)]

def scramble(c):
    for p1, p2 in SWAPS:
        c = switch_bits(c, p1, p2)
    return c

p = [BitVec(f"p{i}", 8) for i in range(32)]
s = Solver()
for i in range(32):
    s.add(scramble(p[i]) == BitVecVal(expected[i], 8))   # exact mirror
    s.add(p[i] >= 0x20, p[i] <= 0x7e)                    # printable ASCII

print(s.check())
if s.check() == sat:
    m = s.model()
    pw = "".join(chr(m[p[i]].as_long()) for i in range(32))
    print("password:", pw)
    print("FLAG: picoCTF{" + pw + "}")
