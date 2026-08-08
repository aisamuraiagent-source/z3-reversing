# picoCTF 2019 — vault-door-6 (Reverse Engineering, Medium)
# checkPassword() requires, for every byte:  (password[i] ^ 0x55) - myBytes[i] == 0
# i.e.  password[i] ^ 0x55 == myBytes[i].  The minion's "strong encryption" is
# just XOR with 0x55. Mirror the check in z3 and recover the password.
from z3 import *

myBytes = [
    0x3b, 0x65, 0x21, 0x0a, 0x38, 0x00, 0x36, 0x1d,
    0x0a, 0x3d, 0x61, 0x27, 0x11, 0x66, 0x27, 0x0a,
    0x21, 0x1d, 0x61, 0x3b, 0x0a, 0x2d, 0x65, 0x27,
    0x0a, 0x33, 0x34, 0x34, 0x30, 0x6d, 0x37, 0x61,
]

p = [BitVec(f"p{i}", 8) for i in range(32)]
s = Solver()
for i in range(32):
    s.add((p[i] ^ 0x55) == myBytes[i])       # exact mirror of the Java check
    s.add(p[i] >= 0x20, p[i] <= 0x7e)         # printable ASCII

print(s.check())
if s.check() == sat:
    m = s.model()
    pw = "".join(chr(m[p[i]].as_long()) for i in range(32))
    print("password:", pw)
    print("FLAG: picoCTF{" + pw + "}")
