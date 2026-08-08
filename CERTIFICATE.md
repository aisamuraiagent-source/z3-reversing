# CERTIFICATE — z3 (SMT) Red-Team Battery

**Operator:** Renan Torres Raad
**Date:** 2026-08-08
**Result:** 10000/10000 challenges solved (100%) — each solution verified against its concrete target.

**Families (5):**
- serial-keygen: 2000
- iam-bypass: 2000
- xor-rotate-keygen: 2000
- xor-cipher-break: 2000
- checksum-forgery: 2000

**Method:** for each challenge, the target's rules are modeled as SMT constraints and z3
computes an input satisfying all of them at once (no brute force). The returned input is
then executed against the concrete target function; a win counts only if the target accepts it.

**Reproducible:** `python battery.py 10000` (seed=1000, deterministic).
**Integrity:** SHA-256(summary) = `fd449524f148adf0bfd2e31b5c7f4e8ee789a074f5a2166f6df4953cfcf4aed7`
summary = "z3 red-team battery | date=2026-08-08 seed=1000 | challenges=10000 solved=10000 families=serial-keygen,iam-bypass,xor-rotate-keygen,xor-cipher-break,checksum-forgery"
