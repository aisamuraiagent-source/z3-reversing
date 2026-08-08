# picoCTF 2019 — vault-door-3 (Reverse Engineering, Medium)
# Solve with z3. checkPassword() scrambles the 32-char password into `buffer`
# via 4 index loops, then compares to a fixed target. We mirror the SAME loops
# symbolically and let z3 recover the password. (No brute force.)
from z3 import *

target = "jU5t_a_sna_3lpm13gf49_u_4_m9r540"   # what buffer must equal

p = [BitVec(f"p{i}", 8) for i in range(32)]    # the 32 unknown password chars
buf = [None] * 32

# --- mirror checkPassword() exactly ---
for i in range(0, 8):        # loop 1:  buffer[i] = password[i]
    buf[i] = p[i]
for i in range(8, 16):       # loop 2:  buffer[i] = password[23-i]
    buf[i] = p[23 - i]
for i in range(16, 32, 2):   # loop 3:  buffer[i] = password[46-i]
    buf[i] = p[46 - i]
for i in range(31, 16, -2):  # loop 4:  buffer[i] = password[i]
    buf[i] = p[i]

s = Solver()
for i in range(32):
    s.add(buf[i] == ord(target[i]))          # buffer must match the target
    s.add(p[i] >= 0x20, p[i] <= 0x7e)        # printable ASCII

print(s.check())
if s.check() == sat:
    m = s.model()
    pw = "".join(chr(m[p[i]].as_long()) for i in range(32))
    print("password:", pw)
    print("FLAG: picoCTF{" + pw + "}")
