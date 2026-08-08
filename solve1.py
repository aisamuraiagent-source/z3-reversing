# SOLVE 1 — recupera o serial do crackme1 usando z3 (SMT), sem força bruta.
# Metodologia red team: traduzir as regras do alvo em restrições e deixar
# o solver calcular a entrada exata que satisfaz TODAS de uma vez.
from z3 import *
from crackme1 import check

# 6 bytes de 8 bits (como um reverser modela dados controlados pelo usuário)
s = [BitVec(f"s{i}", 8) for i in range(6)]
solver = Solver()

# (1) imprimíveis
for c in s:
    solver.add(c >= 0x20, c <= 0x7e)

# (2) mesma cadeia de obfuscação do alvo, agora como restrições
solver.add(s[0] ^ s[1] == 0x13)
solver.add((s[1] + s[2]) & 0xff == 0x9a)
solver.add(s[3] ^ 0x55 == s[0])
solver.add((s[2] * 3) & 0xff == s[4])
solver.add(s[5] ^ s[4] ^ s[3] == 0x21)

# (3) checksum
solver.add((s[0] + s[1] + s[2] + s[3] + s[4] + s[5]) & 0xff == 0xdc)

print("[*] z3.check():", solver.check())
if solver.check() == sat:
    m = solver.model()
    serial = bytes(m[c].as_long() for c in s)
    print("[+] Serial recuperado:", serial, "=>", serial.decode())
    # PROVA: rodar contra o alvo real, sem confiar no solver
    print("[+] check() do alvo diz:", check(serial))
    # Quantas soluções existem? (unicidade)
    solver.add(Or([c != m[c] for c in s]))
    print("[*] Existe outra solução?", solver.check())
