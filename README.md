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
| `battery.py` | Generator + solver for **N randomized challenges** across **nine families**. Deterministic (fixed seed); each solution verified against its concrete target. |
| `CERTIFICATE.md` / `.sha256` / `.sig.json` | Result of the battery, with SHA-256 integrity digests and an **Ed25519 operator signature** (verified against `laudo_pub.pem`). |

### Challenge families

| Family | Offensive technique |
|--------|---------------------|
| `serial-keygen` | Recover a validating serial (keygenning) |
| `iam-bypass` | Privilege-escalation search over an access policy |
| `xor-rotate-keygen` | Invert XOR + bit-rotation transforms |
| `xor-cipher-break` | Known-plaintext repeating-XOR key recovery |
| `checksum-forgery` | Forge input colliding a weak checksum |
| `lcg-prng-predict` | Recover a weak PRNG (LCG) state from truncated outputs and predict the next token |
| `firewall-acl-bypass` | Find a packet that reaches a protected service through an ACL gap (attack-path) |
| `affine-cipher-break` | Recover an affine cipher's key from known plaintext |
| `intoverflow-bypass` | Defeat a bounds check via 8-bit integer overflow |

## CTF writeups (external targets)

Beyond the self-contained battery, `ctf-writeups/` documents **public CTF challenges I
did not author**, solved with the same z3 methodology — external validation of the technique:

| Challenge | Platform | Category | Technique |
|-----------|----------|----------|-----------|
| [vault-door-3](ctf-writeups/vault-door-3/) | picoCTF 2019 | Reverse Engineering (Medium) | model the char-permutation check as constraints, recover the password |

## Reproduce

```bash
pip install z3-solver
python solve1.py            # recover the serial + prove uniqueness
python solve2_iam.py        # find the IAM privilege-escalation bypass
python battery.py 10000     # 10000/10000, emits CERTIFICATE.md + .sha256
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
