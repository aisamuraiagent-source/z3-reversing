# SOLVE 2 — z3 acha a escalada de privilégio na política IAM vulnerável.
# "Lutar sem lutar": em vez de testar milhões de combinações, pedimos ao
# solver o conjunto exato de atributos onde a política diz ALLOW **e** a
# invariante de segurança é violada. Se existir (sat), é o bypass.
from z3 import *
from crackme2_iam import policy, invariant_violated

role          = Int("role")
action        = Int("action")
sensitivity   = Int("sensitivity")
is_owner      = Bool("is_owner")
in_break_glass= Bool("in_break_glass")
delegation    = Int("delegation_tier")

s = Solver()
# domínios realistas dos atributos
s.add(role >= 0, role <= 2)
s.add(action >= 0, action <= 2)
s.add(sensitivity >= 0, sensitivity <= 10)
s.add(delegation >= 0, delegation <= 3)

# --- modelo simbólico da política (idêntico ao alvo) ---
owner_rw   = And(is_owner, Or(action == 0, action == 1))
effective  = role + If(in_break_glass, 5, 0) + delegation
allow = Or(
    role == 2,                                   # A
    owner_rw,                                     # B
    effective >= 7,                              # C+D (o furo)
    And(role == 1, action == 2, sensitivity < 8) # E
)

# --- a invariante que NÃO pode ser violada ---
violated = And(role == 0, action == 2, sensitivity >= 8)

# procuramos: política ALLOW **enquanto** a invariante é violada
s.add(allow)
s.add(violated)

print("[*] z3.check():", s.check())
if s.check() == sat:
    m = s.model()
    r  = m[role].as_long(); a = m[action].as_long(); se = m[sensitivity].as_long()
    ow = is_true(m[is_owner]); bg = is_true(m[in_break_glass]); dt = m[delegation].as_long()
    print("[+] BYPASS ENCONTRADO — escalada de privilégio:")
    print(f"     role={r}(guest) action={a}(delete) sensitivity={se} "
          f"is_owner={ow} break_glass={bg} delegation_tier={dt}")
    # PROVA contra o alvo real (sem confiar no solver):
    print("     policy() do alvo diz ALLOW:", policy(r, a, se, ow, bg, dt))
    print("     invariante violada:", invariant_violated(r, a, se))
    print("[=] Logo: guest deletou recurso sensível. Furo provado.")
else:
    print("[-] Sem bypass — política seria segura (como o GET: UNSAT).")
