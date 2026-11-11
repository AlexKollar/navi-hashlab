"""core.py — Navi Hashlab's command table, parser and self-test.

Commands: id, crack, strength, salt demo, --test, --help.
Computing hashes is cryptex's job; this chip identifies, attacks
provided lab hashes, and teaches password strength.
"""

import hashlib
import shlex
import time

from app_hashlab import crack as crack_mod
from app_hashlab import saltlab
from app_hashlab import strength as strength_mod
from app_hashlab.identify import identify
from app_hashlab.md4 import md4_hex, ntlm_hex
from app_hashlab.wordlist import Words

VERSION = "1.0.0"

HELP_INDEX = """Navi Hashlab 1.0.0 — a password & hash lab companion.

  id <hash>                    identify a hash by shape
  crack <hash> [--algo A]      dictionary attack on a PROVIDED lab hash
  strength <password>          entropy + pattern + crack-time analysis
  salt demo                    unsalted vs salted vs slow-KDF, one table
  --test                       self-test against known vectors
  --help                       this list

Algorithms for crack: md5, sha1, sha256, ntlm (a 32-hex target with
no --algo gets an MD5 pass, then an NTLM pass).

Rules for crack: each of the %d built-in words is tried as-is,
Capitalized, UPPERCASE, +digit 0-9, +'!', Capitalized+'1', and
Capitalized+'!' — 15 variants per word.

cryptex COMPUTES hashes and transforms text. hashlab never hashes for
you — it identifies, attacks, and explains. The crack command is for
lab-provided hashes — the hashes a course hands you to practice on.""" % len(Words)

HELP_ID = """id — identify a hash by shape.

  hashlab id 5f4dcc3b5aa765d61d8327deb882cf99

Length and charset rank the candidates; prefixes are proof when a
format announces itself (bcrypt $2b$, argon2, $6$ crypt). MD5 and
NTLM are the same shape — the report says so plainly and tells you
what actually separates them (provenance, or trying both)."""

HELP_CRACK = """crack — a dictionary attack on a PROVIDED lab hash.

  hashlab crack <hash> [--algo md5|sha1|sha256|ntlm]

The built-in wordlist (%d classic worst-passwords and course-lab
staples) is tried with rules: as-is, Capitalized, UPPERCASE, +digit
0-9, +'!', Capitalized+'1', Capitalized+'!'. The report gives the
found password, the attempts count, the elapsed time, and why fast
unsalted hashes fall — salting and slow KDFs are the fix, and the
salt demo shows both. Lab-provided hashes only: the ones a course
hands you to practice on.""" % len(Words)

HELP_STRENGTH = """strength — how strong is this password, really?

  hashlab strength <password>

Entropy from length and charset pool, a dictionary check against the
lab wordlist (leetspeak decoded), pattern notes (keyboard walks,
years, repeats), and cracking-time estimates against a fast-hash
attacker and a bcrypt-class one. Your password is never echoed back
in full — first character and length only."""

HELP_SALT = """salt demo — why salting and slow KDFs matter.

  hashlab salt demo

One password, three storage columns: unsalted MD5 (the same twice),
salted SHA-256 (different every time), and PBKDF2 (salted AND slow,
timed). Run crack first, then this, and the defence explains itself."""


def _test_vectors():
    # Every expected value here was computed with hashlib (or, for
    # MD4, verified against OpenSSL's own MD4) in the build's proof
    # — see BUILD-REPORT.md. Nothing was typed from memory.
    rows = []

    def check(label, actual, expected):
        rows.append((label, actual == expected))

    check("md4('') is the RFC empty digest",
          md4_hex(b""), "31d6cfe0d16ae931b73c59d7e0c089c0")
    check("md4('abc') matches OpenSSL's MD4",
          md4_hex(b"abc"), "a448017aaf21d8525fc10ae87aa6729d")
    check("ntlm('password') is the textbook NTLM hash",
          ntlm_hex("password"), "8846f7eaee8fb117ad06bdd830b7586c")

    md5_password = hashlib.md5(b"password").hexdigest()
    check("vector: md5('password') is 5f4dcc3b…",
          md5_password, "5f4dcc3b5aa765d61d8327deb882cf99")
    report = identify(md5_password)
    check("id ranks MD5/NTLM shape for that vector",
          "MD5" in report and "NTLM" in report, True)

    hunter2_sha = hashlib.sha256(b"hunter2").hexdigest()
    report = identify(hunter2_sha)
    check("id reads sha256('hunter2') as SHA-256 shape",
          "SHA-256" in report, True)

    letmein_md5 = hashlib.md5(b"letmein").hexdigest()
    out = []
    _run_capture(lambda: crack_mod.explode(letmein_md5, "md5"), out)
    text = "".join(out)
    check("crack finds 'letmein' from its md5",
          "CRACKED (md5): letmein" in text, True)

    report = strength_mod.analyze("password123")
    check("strength flags the dictionary hit on 'password123'",
          "dictionary: HIT" in report, True)
    check("strength masks 'password123' (first char + length only)",
          "p... (11 characters)" in report, True)

    report = strength_mod.analyze("Tr0ub4dor&3")
    check("strength gives a masked label for a mixed password",
          "T... (11 characters)" in report and "Tr0ub4dor" not in report,
          True)
    return rows


def _run_capture(fn, sink):
    import io
    import contextlib
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        fn()
    sink.append(buf.getvalue())


def _self_test():
    rows = _test_vectors()
    passed = 0
    for label, ok in rows:
        print("%s %s" % ("PASS" if ok else "FAIL", label))
        passed += 1 if ok else 0
    print("self-test: %d/%d passed" % (passed, len(rows)))


def _parse_crack(rest):
    """rest -> (hash, algo) or an error line."""
    target = None
    algo = None
    i = 0
    while i < len(rest):
        tok = rest[i]
        if tok == "--algo":
            if i + 1 >= len(rest):
                return None, None, "crack: --algo needs a value (md5|sha1|sha256|ntlm)."
            algo = rest[i + 1]
            i += 2
        elif tok.startswith("--algo="):
            algo = tok.split("=", 1)[1]
            i += 1
        elif tok.startswith("--"):
            return None, None, "crack: unknown flag %s (only --algo)." % tok
        elif target is None:
            target = tok
            i += 1
        else:
            return None, None, "crack takes ONE hash — quote it if it has spaces."
    return target, algo, None


def run_command(argv):
    if not argv or argv[0] in ("--help", "help", "-h"):
        print(HELP_INDEX)
        return
    cmd, rest = argv[0].lower(), argv[1:]

    if cmd == "--test":
        _self_test()
        return
    if cmd == "id":
        if rest and rest[0] in ("--help", "help"):
            print(HELP_ID)
            return
        print(identify(rest[0] if rest else ""))
        return
    if cmd == "crack":
        if rest and rest[0] in ("--help", "help"):
            print(HELP_CRACK)
            return
        target, algo, err = _parse_crack(rest)
        if err:
            print(err)
            return
        crack_mod.explode(target or "", algo)
        return
    if cmd == "strength":
        if rest and rest[0] in ("--help", "help"):
            print(HELP_STRENGTH)
            return
        print(strength_mod.analyze(rest[0] if rest else ""))
        return
    if cmd == "salt":
        if rest and rest[0] in ("--help", "help"):
            print(HELP_SALT)
            return
        if rest and rest[0].lower() == "demo":
            saltlab.demo(rest[1:])
            return
        print("usage: hashlab salt demo")
        return
    print("unknown command %r — run: hashlab --help" % cmd)


def parse_and_run(text):
    """Entry shim for root.py: text is everything after the chip name."""
    if not text or not text.strip():
        run_command([])
        return
    try:
        argv = shlex.split(text)
    except ValueError as exc:
        print("error: could not parse arguments: " + str(exc))
        return
    run_command(argv)
