# CRACKME 2 — "IAM/RBAC Bypass" (o ALVO: uma política de acesso vulnerável)
# Caso de uso red team #4 (HackTricks): achar a brecha matemática numa
# política complexa que permite escalada de privilégio.
#
# Papéis: 0=guest, 1=user, 2=admin
# Ações:  0=read, 1=write, 2=delete
#
# INVARIANTE PRETENDIDA (a regra de negócio que NÃO pode ser violada):
#   "Um guest NUNCA pode DELETE um recurso sensível (sensitivity >= 8)."
#
# A política abaixo tem um FURO. O red team acha o conjunto de atributos
# que a política ACEITA (ALLOW) violando a invariante.

def policy(role, action, sensitivity, is_owner, in_break_glass, delegation_tier):
    # Regra A: admin pode tudo
    if role == 2:
        return True
    # Regra B: dono do recurso pode ler/escrever
    if is_owner and action in (0, 1):
        return True
    # Regra C: "break glass" emergencial eleva o tier de delegação
    #          (aqui mora o furo: soma sem checar o papel de origem)
    effective = role + (5 if in_break_glass else 0) + delegation_tier
    # Regra D: se o tier efetivo alcança 7, libera qualquer ação
    if effective >= 7:
        return True
    # Regra E: user pode delete se o recurso não for sensível
    if role == 1 and action == 2 and sensitivity < 8:
        return True
    return False


def invariant_violated(role, action, sensitivity):
    # guest (0) fazendo delete (2) em recurso sensível (>=8)
    return role == 0 and action == 2 and sensitivity >= 8
