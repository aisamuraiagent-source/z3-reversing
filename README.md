# z3-reversing — SMT solving for offensive security

Practical, reproducible demonstrations of using the **Z3 SMT solver** as a red-team /
reverse-engineering tool: recovering serials, inverting bit-level key transforms, and
finding **privilege-escalation bypasses** in access-control policies — all by modeling the
target's rules as constraints and letting the solver compute a satisfying input, **without
brute force**.

Every solution is **verified against the concrete target** (not just the symbolic model):
a challenge only counts as solved if the recovered input is accepted by the real check.

## Contents

| File | What it does |
|------|--------------|
| `crackme1.py` / `solve1.py` | Serial validator (printable bytes, XOR/sum/product, 8-bit wrap). z3 recovers the unique valid serial and proves uniqueness (`unsat` for any other). |
| `crackme2_iam.py` / `solve2_iam.py` | Vulnerable IAM/RBAC policy. z3 finds the attribute combination that grants a **guest** `delete` on a sensitive resource — a privilege-escalation bypass — verified against the real policy. |
| `battery.py` | Generator + solver for **1000 randomized challenges** across three families (serial-keygen, iam-bypass, xor-rotate-keygen). Deterministic (fixed seed); each solution verified against its concrete target. |
| `CERTIFICATE.md` | Result of the battery: **1000/1000 solved**, with a SHA-256 integrity digest of the run summary. |

## Reproduce

```bash
pip install z3-solver
python solve1.py            # recover the serial + prove uniqueness
python solve2_iam.py        # find the IAM privilege-escalation bypass
python battery.py 1000      # 1000/1000, emits CERTIFICATE.md
```

## Why this matters

The same satisfiability search a red-teamer runs to **find** an authority/IAM bypass (`sat`)
is what a defender runs to **prove one cannot exist** (`unsat`). This lab shows the offensive
side: given a flawed policy or a validation routine, z3 returns the exact input that defeats
it. Applied to a *correct* control, the identical query returns `unsat` — a machine-checked
proof that no bypass exists.

## Ethics

All targets here are self-contained crackmes and synthetic policies authored in this
repository. No third-party system is touched. This is authorized, lawful security research.

## License

MIT — see `LICENSE`.
