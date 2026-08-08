# CRACKME 1 — "Serial Validator" (o ALVO)
# Simula um license-check compilado. Aceita 6 bytes imprimíveis.
# Objetivo do red team: achar um serial que faça check() == True,
# SEM força bruta — modelando as regras no z3.

def check(serial: bytes) -> bool:
    if len(serial) != 6:
        return False
    s = list(serial)
    # (1) todos imprimíveis (0x20..0x7e)
    for c in s:
        if not (0x20 <= c <= 0x7e):
            return False
    # (2) cadeia de obfuscação (XOR / soma / mul com wrap de 8 bits)
    if (s[0] ^ s[1]) != 0x13:            return False
    if (s[1] + s[2]) & 0xff != 0x9a:     return False
    if (s[3] ^ 0x55) != s[0]:            return False
    if (s[2] * 3) & 0xff != s[4]:        return False
    if (s[5] ^ s[4] ^ s[3]) != 0x21:     return False
    # (3) checksum final
    if sum(s) & 0xff != 0xdc:            return False
    return True


if __name__ == "__main__":
    import sys
    if len(sys.argv) == 2:
        print("VÁLIDO ✔" if check(sys.argv[1].encode()) else "inválido �’")
