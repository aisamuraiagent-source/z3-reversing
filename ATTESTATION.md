# ATTESTATION — z3 (SMT) offensive security: consolidated record

**Operator:** Renan Torres Raad
**Date:** 2026-08-08

A single, signable record consolidating the offensive-SMT work in this repository.

## 1. Self-authored battery (signed)

Nine-family, 18,000-challenge SMT/z3 battery — 100% solved, each solution verified
against its concrete target. Certificate `CERTIFICATE.md`, SHA-256
`ddd77d31e7aafde6fe1d18ce28ffc8d3533f491360ddecec35a0addae665a5db`, Ed25519-signed
(`CERTIFICATE.sig.json`), verified OK against `laudo_pub.pem`.

## 2. External CTF challenges solved with z3 (picoCTF 2019 — flags accepted)

| Challenge | Difficulty | Technique | Flag |
|-----------|-----------|-----------|------|
| vault-door-3 | Medium | char permutation | `picoCTF{jU5t_a_s1mpl3_an4gr4m_4_u_99f530}` |
| vault-door-6 | Medium | per-byte XOR | `picoCTF{n0t_mUcH_h4rD3r_tH4n_x0r_faae8b4}` |
| vault-door-8 | Hard | 8-swap bit transposition | `picoCTF{s0m3_m0r3_b1t_sh1fTiNg_987ee52a8}` |

All three flags were accepted on picoCTF — external validation (targets I did not author).
Writeups and solvers in `ctf-writeups/`.

## 3. Verifiable timeline (git commit timestamps, this session)

- vault-door-3 writeup committed: 2026-08-08 19:25:28
- vault-door-6 writeup committed: 2026-08-08 19:28:57
- vault-door-8 writeup committed: 2026-08-08 19:34:09

The three reverse-engineering challenges (one rated Hard) were modeled, solved,
submitted, and written up within an approximately **8m41s** span (git-timestamped).

**Honest scope:** this is a verifiable record of *this session's* work — **not** a claim
of a competitive solve-time record. picoCTF practice challenges have no public per-user
solve-time leaderboard, and these challenges have thousands of solves. The value here is
the method and its reproducibility, not a ranking.

## Integrity

The Ed25519 operator signature of this attestation is in `ATTESTATION.sig.json`,
verifiable against `laudo_pub.pem`. All results above are independently reproducible.
