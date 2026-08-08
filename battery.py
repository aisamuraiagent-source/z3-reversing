# BATTERY — 1000 desafios z3 de red team, cada um resolvido E verificado
# contra o alvo CONCRETO (sem confiar no solver). 3 famílias:
#   A) serial keygen (bytes + xor/sum/mul, wrap de 8 bits)
#   B) bypass de IAM/RBAC (achar escalada de privilégio numa política falha)
#   C) keygen XOR+rotate (inverter transformação de bits)
# Reprodutível (seed fixa). 1000/1000 => emite CERTIFICATE + SHA-256.
import sys, random, hashlib, functools
from z3 import *

DATE = "2026-08-08"
SEED = 1000

def rol8(v, r):  # rotate-left 8 bits
    r &= 7
    return ((v << r) | (v >> (8 - r))) & 0xff

# ---------- Família A: serial keygen ----------
def fam_serial(rng):
    n = rng.randint(4, 8)
    sol = [rng.randint(0x21, 0x7e) for _ in range(n)]
    cons = []
    for _ in range(max(1, n // 2)):
        i, j = rng.sample(range(n), 2)
        cons.append(('xor', i, j, sol[i] ^ sol[j]))
    cons.append(('sum', sum(sol) & 0xff))
    i, j = rng.sample(range(n), 2)
    cons.append(('mul', i, j, (sol[i] * sol[j]) & 0xff))

    def target(bs):
        if len(bs) != n or any(not (0x21 <= c <= 0x7e) for c in bs):
            return False
        for c in cons:
            if c[0] == 'xor' and (bs[c[1]] ^ bs[c[2]]) != c[3]: return False
            if c[0] == 'sum' and (sum(bs) & 0xff) != c[1]:       return False
            if c[0] == 'mul' and (bs[c[1]] * bs[c[2]]) & 0xff != c[3]: return False
        return True

    S = Solver()
    b = [BitVec(f'b{i}', 8) for i in range(n)]
    for c in b: S.add(c >= 0x21, c <= 0x7e)
    for c in cons:
        if c[0] == 'xor': S.add(b[c[1]] ^ b[c[2]] == c[3])
        if c[0] == 'sum': S.add(functools.reduce(lambda x, y: x + y, b) == c[1])
        if c[0] == 'mul': S.add(b[c[1]] * b[c[2]] == c[3])
    if S.check() != sat:
        return False
    m = S.model()
    return target(bytes(m[x].as_long() for x in b))

# ---------- Família B: bypass de IAM ----------
def fam_iam(rng):
    K = rng.randint(4, 6)          # bônus do break-glass
    T = rng.randint(6, 8)          # limiar de liberação
    max_tier = rng.randint(2, 4)
    sens_min = rng.randint(7, 9)
    # furo garantido: guest(0) + K + max_tier >= T ?
    if 0 + K + max_tier < T:       # se não houver furo, força um
        max_tier = T - K + 1

    def policy(role, action, sens, bg, tier):
        if role == 2: return True
        eff = role + (K if bg else 0) + tier
        if eff >= T: return True
        if role == 1 and action == 2 and sens < sens_min: return True
        return False

    def invariant_bad(role, action, sens):
        return role == 0 and action == 2 and sens >= sens_min

    role = Int('role'); action = Int('action'); sens = Int('sens')
    bg = Bool('bg'); tier = Int('tier')
    S = Solver()
    S.add(role >= 0, role <= 2, action >= 0, action <= 2)
    S.add(sens >= 0, sens <= 10, tier >= 0, tier <= max_tier)
    eff = role + If(bg, K, 0) + tier
    allow = Or(role == 2, eff >= T, And(role == 1, action == 2, sens < sens_min))
    S.add(allow, And(role == 0, action == 2, sens >= sens_min))
    if S.check() != sat:
        return False
    m = S.model()
    r, a, se = m[role].as_long(), m[action].as_long(), m[sens].as_long()
    bgv, tv = is_true(m[bg]), m[tier].as_long()
    return policy(r, a, se, bgv, tv) and invariant_bad(r, a, se)

# ---------- Família C: keygen XOR + rotate ----------
def fam_xor(rng):
    n = rng.randint(4, 8)
    key = [rng.randint(0, 255) for _ in range(n)]
    c1 = rng.randint(1, 255); r = rng.randint(1, 7); c2 = rng.randint(1, 255)
    out = [(rol8(k ^ c1, r) + c2) & 0xff for k in key]

    def target(cand):
        return len(cand) == n and all((rol8(cand[i] ^ c1, r) + c2) & 0xff == out[i] for i in range(n))

    S = Solver()
    k = [BitVec(f'k{i}', 8) for i in range(n)]
    for i in range(n):
        S.add((RotateLeft(k[i] ^ c1, r) + c2) == out[i])
    if S.check() != sat:
        return False
    m = S.model()
    return target([m[x].as_long() for x in k])

# ---------- Família D: quebra de cifra XOR (known-plaintext) ----------
def fam_xorcipher(rng):
    L = rng.randint(3, 6)                     # comprimento da chave repetida
    key = [rng.randint(0, 255) for _ in range(L)]
    n = rng.randint(L * 2, L * 3)
    pt = [rng.randint(0x20, 0x7e) for _ in range(n)]   # plaintext conhecido
    ct = [pt[i] ^ key[i % L] for i in range(n)]        # ciphertext

    def target(cand):
        return len(cand) == L and all((ct[i] ^ cand[i % L]) == pt[i] for i in range(n))

    S = Solver()
    k = [BitVec(f'k{i}', 8) for i in range(L)]
    for i in range(n):
        S.add(k[i % L] ^ ct[i] == pt[i])
    if S.check() != sat:
        return False
    m = S.model()
    return target([m[x].as_long() for x in k])

# ---------- Família E: forja de checksum (colisão em checksum fraco) ----------
def fam_checksum(rng):
    n = rng.randint(6, 10)
    marker = rng.randint(0x21, 0x7e)
    sol = [marker] + [rng.randint(0x20, 0x7e) for _ in range(n - 1)]
    tgt_sum = sum(sol) & 0xff
    tgt_xor = functools.reduce(lambda a, b: a ^ b, sol)

    def target(bs):
        if len(bs) != n or any(not (0x20 <= c <= 0x7e) for c in bs): return False
        if bs[0] != marker: return False
        if (sum(bs) & 0xff) != tgt_sum: return False
        return functools.reduce(lambda a, b: a ^ b, bs) == tgt_xor

    S = Solver()
    b = [BitVec(f'b{i}', 8) for i in range(n)]
    for c in b: S.add(c >= 0x20, c <= 0x7e)
    S.add(b[0] == marker)
    S.add(functools.reduce(lambda x, y: x + y, b) == tgt_sum)
    S.add(functools.reduce(lambda x, y: x ^ y, b) == tgt_xor)
    if S.check() != sat:
        return False
    m = S.model()
    return target([m[x].as_long() for x in b])

FAMILIES = [
    ("serial-keygen", fam_serial),
    ("iam-bypass", fam_iam),
    ("xor-rotate-keygen", fam_xor),
    ("xor-cipher-break", fam_xorcipher),
    ("checksum-forgery", fam_checksum),
]

def main():
    N = int(sys.argv[1]) if len(sys.argv) > 1 else 1000
    rng = random.Random(SEED)
    wins = 0; per = {name: 0 for name, _ in FAMILIES}; fails = []
    for i in range(N):
        name, fn = FAMILIES[i % len(FAMILIES)]
        try:
            ok = fn(rng)
        except Exception as e:
            ok = False; fails.append((i, name, repr(e)))
        if ok:
            wins += 1; per[name] += 1
        else:
            fails.append((i, name, "solution failed concrete target"))
    print(f"[*] Desafios: {N}  |  Vencidos: {wins}  |  Falhas: {len(fails)}")
    for name in per:
        print(f"     {name}: {per[name]}")
    if fails[:5]:
        print("     primeiras falhas:", fails[:5])
    if wins == N and N >= 1000:
        fam_list = ",".join(name for name, _ in FAMILIES)
        summary = (f"z3 red-team battery | date={DATE} seed={SEED} | "
                   f"challenges={N} solved={wins} families={fam_list}")
        digest = hashlib.sha256(summary.encode()).hexdigest()
        fam_lines = "\n".join(f"- {name}: {per[name]}" for name, _ in FAMILIES)
        cert = f"""# CERTIFICATE — z3 (SMT) Red-Team Battery

**Operator:** Renan Torres Raad
**Date:** {DATE}
**Result:** {wins}/{N} challenges solved (100%) — each solution verified against its concrete target.

**Families ({len(FAMILIES)}):**
{fam_lines}

**Method:** for each challenge, the target's rules are modeled as SMT constraints and z3
computes an input satisfying all of them at once (no brute force). The returned input is
then executed against the concrete target function; a win counts only if the target accepts it.

**Reproducible:** `python battery.py {N}` (seed={SEED}, deterministic).
**Integrity:** SHA-256(summary) = `{digest}`
summary = "{summary}"
"""
        with open("CERTIFICATE.md", "w", encoding="utf-8") as f:
            f.write(cert)
        # SHA-256 do arquivo inteiro (para assinatura Ed25519 externa)
        file_hash = hashlib.sha256(cert.encode("utf-8")).hexdigest()
        with open("CERTIFICATE.sha256", "w", encoding="utf-8") as f:
            f.write(f"{file_hash}  CERTIFICATE.md\n")
        print(f"\n[+] {wins}/{N} — CERTIFICATE.md emitido.")
        print(f"    SHA-256(summary): {digest}")
        print(f"    SHA-256(file):    {file_hash}  -> CERTIFICATE.sha256 (para assinar Ed25519)")
    return 0 if wins == N else 1

sys.exit(main())
