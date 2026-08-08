# CERTIFICATE — z3 (SMT) Red-Team Battery

**Operator:** Renan Torres Raad
**Date:** 2026-08-08
**Result:** 1000/1000 challenges solved (100%) — each solution verified against its concrete target.

**Families:**
- serial-keygen (byte constraints: XOR / sum / product, 8-bit wrap): 334
- iam-bypass (privilege-escalation search over access policy): 333
- xor-rotate-keygen (invert XOR+rotate transforms): 333

**Method:** for each challenge, the target's rules are modeled as SMT constraints and z3
computes an input satisfying all of them at once (no brute force). The returned input is
then executed against the concrete target function; a win counts only if the target accepts it.

**Reproducible:** `python battery.py 1000` (seed=1000, deterministic).
**Integrity:** SHA-256(summary) = `8f466738b22dcd27494e1538de1848c54b66af5fdb92ef51cfe870d26004a0f8`
summary = "z3 red-team battery | date=2026-08-08 seed=1000 | challenges=1000 solved=1000 families=serial-keygen,iam-bypass,xor-rotate-keygen"
