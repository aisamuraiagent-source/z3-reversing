# CERTIFICATE — z3 (SMT) Red-Team Battery

**Operator:** Renan Torres Raad
**Date:** 2026-08-08
**Result:** 18000/18000 challenges solved (100%) — each solution verified against its concrete target.

**Families (9):**
- serial-keygen: 2000
- iam-bypass: 2000
- xor-rotate-keygen: 2000
- xor-cipher-break: 2000
- checksum-forgery: 2000
- lcg-prng-predict: 2000
- firewall-acl-bypass: 2000
- affine-cipher-break: 2000
- intoverflow-bypass: 2000

**Method:** for each challenge, the target's rules are modeled as SMT constraints and z3
computes an input satisfying all of them at once (no brute force). The returned input is
then executed against the concrete target function; a win counts only if the target accepts it.

**Reproducible:** `python battery.py 18000` (seed=1000, deterministic).
**Integrity:** SHA-256(summary) = `ab1c87c9e2e1fcc99446e4ca5b5ab377fbf1d9d9637b97741352e3943de8bcf6`
summary = "z3 red-team battery | date=2026-08-08 seed=1000 | challenges=18000 solved=18000 families=serial-keygen,iam-bypass,xor-rotate-keygen,xor-cipher-break,checksum-forgery,lcg-prng-predict,firewall-acl-bypass,affine-cipher-break,intoverflow-bypass"
