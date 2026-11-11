# Navi Hashlab

A password & hash lab companion that rides inside a single Apex chip.
Four tools for the coursework side of hashing — identify, crack,
strength, and the salt demo — in a proper multi-file package
(`root.py` + `app_hashlab/`), forged into one `.png` cartridge whose
picture *is* the install.

Hashlab is part of Apex's school series: chips built for a student
walking into cybersecurity courses with their own arsenal. Its sibling
**Navi Cryptex** computes hashes and transforms text; hashlab never
does — it identifies hashes, attacks the ones a lab hands you, and
teaches why passwords fall and how real storage stops them falling.

## Using it

In Apex chat, or anywhere the chip runs:

```
hashlab                              the command list
hashlab id <hash>                    identify a hash by shape
hashlab crack <hash> [--algo A]      dictionary attack (lab hashes)
hashlab strength <password>          entropy + patterns + crack times
hashlab salt demo                    unsalted vs salted vs slow KDF
hashlab --test                       self-test against known vectors
```

Worked example:

```
$ hashlab id 5f4dcc3b5aa765d61d8327deb882cf99
  fact: 32 hexadecimal characters = 16 bytes of digest
candidates (most likely first):
  1. MD5 — 128-bit digest, 32 hex chars — the classic
  2. NTLM — MD4 of the password's UTF-16LE; Windows' unsalted hash
confirm: MD5 and NTLM are THE SAME SHAPE — identical length, identical
charset. No inspection of the string can separate them; provenance can…

$ hashlab crack 0d107d09f5bbe40cade3de5c71e9e9b7
CRACKED (md5): letmein
attempts: 465 in 0.00s
```

## The four tools

### `id` — name the hash

Length + charset analysis ranks the candidate algorithms; prefixes are
proof when a format announces itself — bcrypt (`$2b$` + cost), argon2
(PHC string with its parameters inline), `$1$`/`$5$`/`$6$` crypt,
MySQL's `*`-prefixed double-SHA-1, LM:NTLM pairs, and base64-wrapped
digests are all recognized. The honest limit is stated in the output:
a 32-hex string might be MD5 **or** NTLM, and no inspection can tell
them apart — the report explains what would confirm it (provenance,
or trying both in `crack`).

### `crack` — dictionary attack, for lab-provided hashes

Attacks a hash a course hands you to practice on. Algorithms: `md5`,
`sha1`, `sha256`, `ntlm` (a 32-hex target with no `--algo` gets an MD5
pass, then an NTLM pass). The built-in wordlist carries **400 entries**
— authored for this chip from the classic worst-password lists
(SplashData/NordPass-style top passwords), course-lab and CTF staples,
keyboard walks, seasons, names and fandom, and common compounds. Rules
applied to every word: as-is, Capitalized, UPPERCASE, trailing digit
0–9, trailing `!`, Capitalized+`1`, Capitalized+`!` — 15 variants per
word, 6,400 candidates per pass. The report gives the found password,
attempts, elapsed time, and the explainer: these hashes are *fast* and
*unsalted*, which is why this works at all.

NTLM is MD4 of the password's UTF-16LE. `hashlib` usually can't do MD4
on an OpenSSL 3 system, so the chip carries a pure-Python MD4
(`app_hashlab/md4.py`), verified against OpenSSL's own MD4 — see the
build report for the evidence, including one wrong constant in the
RFC's own printed test suite that the build caught.

### `strength` — how strong is it, really?

Entropy from length and charset pool, a dictionary check against the
lab wordlist (leetspeak decoded first), pattern notes (keyboard walks,
embedded years, sequences, repeats), and cracking-time estimates
against two attackers: a fast hash at ~10 billion guesses/sec and a
bcrypt-class slow KDF at ~10/sec. The gap between those two numbers
*is* the lesson. The password is **never echoed back in full** — the
report shows its first character and length only, and even dictionary
matches are reported by first letter and length.

### `salt demo` — the defence, in one table

One password stored three ways: unsalted MD5 (two accounts, identical
hashes — one crack breaks both), salted SHA-256 (different every time —
no precomputed table exists), and PBKDF2-HMAC-SHA256 at 120,000 rounds
(salted *and* slow, with the per-guess time measured on your machine).
Run `crack`, then this, and the defence explains itself.

## Standard library only

Nothing to install. `hashlib` covers the fast hashes and the KDF demo;
MD4 rides along in pure Python (~60 lines) for NTLM. See
`chip-requirements.txt`.

## Install it in Apex

1. Open the **Chips** tab, then **Navi User Repo (NUR)**.
2. **Search NUR** — every public repo tagged `navi-chips` is listed.
3. **Install** — Apex downloads every Python file in the repo at the
   latest release, keeping folder paths, and forges them into a chip:
   `root.py` is the entry, the `app_hashlab/` package rides beside it,
   and the runner's package mode makes its imports resolve exactly as
   authored.

## Files

- `root.py` — the chip entry (`run(args)`); small on purpose.
- `app_hashlab/core.py` — command table, argument parsing, `--test`.
- `app_hashlab/identify.py` — the `id` shape analysis.
- `app_hashlab/crack.py` — the dictionary attack and its explainer.
- `app_hashlab/wordlist.py` — the 400-word built-in list, as data.
- `app_hashlab/strength.py` — entropy, patterns, crack-time contrast.
- `app_hashlab/saltlab.py` — the salt/slow-KDF demo.
- `app_hashlab/md4.py` — pure-Python MD4 (RFC 1320) for NTLM.
- `navi-chip.json` — the `navi-chip/1` manifest.
- `navi-hashlab.png` — the forged cartridge (once forged): the whole
  file set rides inside the picture.

## Publishing an update

Edit the code, bump `version` in `navi-chip.json`, push, and publish a
new release — a newer release tag is what offers everyone who
installed the chip an update. Keep the `navi-chips` topic on the repo;
that is how Apex finds it.

## License

MIT — see `LICENSE`. Copyright (c) SaintsSec.
