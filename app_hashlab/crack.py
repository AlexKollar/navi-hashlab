"""crack.py — a dictionary attack against a PROVIDED lab hash.

Rule set (also stated in the help): for every word in the built-in
wordlist, try the word as-is, UPPERCASE, Capitalized, the word plus a
trailing digit 0-9, the word plus '!', the Capitalized word plus a
trailing digit, and the Capitalized word plus '!'. ~400 words x 15
variants ≈ 6,000 candidates per pass, so a pass finishes in seconds
with a fast hash — and takes longer with NTLM because this chip's MD4
is pure Python. That contrast is part of the lesson.
"""

import hashlib
import time

from app_hashlab.md4 import ntlm_hex
from app_hashlab.wordlist import Words

_ALGOS = ("md5", "sha1", "sha256", "ntlm")
_HEX_LENS = {"md5": 32, "ntlm": 32, "sha1": 40, "sha256": 64}
_MAX_CANDIDATES = 500000


def variants(word):
    base = word
    cap = word.capitalize()
    up = word.upper()
    yield base
    yield cap
    yield up
    for digit in "0123456789":
        yield base + digit
    yield base + "!"
    yield cap + "1"
    yield cap + "!"


def _digest(algo, candidate):
    data = candidate.encode("utf-8")
    if algo == "md5":
        return hashlib.md5(data).hexdigest()
    if algo == "sha1":
        return hashlib.sha1(data).hexdigest()
    if algo == "sha256":
        return hashlib.sha256(data).hexdigest()
    if algo == "ntlm":
        return ntlm_hex(candidate)
    raise ValueError("unknown algo " + algo)


def explode(target_hash, algo=None):
    """Run the attack, printing the report as it goes."""
    target = (target_hash or "").strip().lower()
    if not target:
        print("crack needs a hash to attack.")
        print("usage: hashlab crack <hash> [--algo md5|sha1|sha256|ntlm]")
        print("This is for lab-provided hashes — the hashes a course")
        print("hands you to practice on.")
        return
    if len(target) > 256 or any(c.isspace() for c in target):
        print("That does not look like a single hash (%d characters, "
              "or it contains spaces). Paste just the hash itself."
              % len(target))
        return

    if algo is None:
        guessed = {32: None, 40: "sha1", 64: "sha256"}.get(len(target))
        if guessed is None and len(target) == 32:
            algos = ["md5", "ntlm"]
            note = ("32 hex chars: ambiguous shape, so both MD5 and NTLM "
                    "get a pass (MD5 first).")
        elif guessed is None:
            print("A %d-character hash matches no algorithm this chip"
                  % len(target))
            print("attacks (md5/ntlm are 32 hex chars, sha1 40, sha256")
            print("64). Run: hashlab id <hash>")
            return
        else:
            algos = [guessed]
            note = "%d chars reads as %s." % (len(target), guessed)
    else:
        algo = algo.lower()
        if algo not in _ALGOS:
            print("--algo must be one of: md5, sha1, sha256, ntlm "
                  "(got %r)." % algo)
            return
        if len(target) != _HEX_LENS[algo]:
            print("A %s hash is %d hex characters; you gave %d."
                  % (algo.upper(), _HEX_LENS[algo], len(target)))
            print("Run: hashlab id <hash>")
            return
        algos = [algo]
        note = "algorithm pinned to %s." % algo

    if any(c not in "0123456789abcdef" for c in target):
        print("The target is not hexadecimal — these algorithms print")
        print("hex. Run: hashlab id <hash>")
        return

    print("target: %s… (%d chars)" % (target[:16], len(target)))
    print(note)
    print("wordlist: %d words, rules: as-is / Capitalized / UPPERCASE / "
          "+digit 0-9 / +'!' / Capitalized+'1' / Capitalized+'!'" % len(Words))

    attempts = 0
    started = time.time()
    for algo in algos:
        found = None
        for word in Words:
            for candidate in variants(word):
                attempts += 1
                if attempts > _MAX_CANDIDATES:
                    elapsed = time.time() - started
                    print("stopped at the %d-candidate safety cap (%.1fs)."
                          % (_MAX_CANDIDATES, elapsed))
                    print("NOT FOUND before the cap.")
                    _lesson(False)
                    return
                if _digest(algo, candidate) == target:
                    found = candidate
                    break
            if found is not None:
                break
        elapsed = time.time() - started
        if found is not None:
            print("CRACKED (%s): %s" % (algo, found))
            print("attempts: %d in %.2fs (%.0f guesses/sec)"
                  % (attempts, elapsed, attempts / elapsed if elapsed else 0))
            _lesson(True)
            return
        print("%s pass: no hit (%d candidates so far, %.2fs)"
              % (algo, attempts, elapsed))

    print("NOT FOUND in the wordlist — the password is not a classic.")
    _lesson(False)


def _lesson(found):
    print("")
    print("why this works: these hashes are FAST and UNSALTED — a GPU tries")
    print("billions of them a second, and the same password always makes")
    print("the same hash, so one crack serves every breach at once.")
    print("salt kills the precomputation; a slow KDF (bcrypt, argon2)")
    print("kills the speed. Watch both in: hashlab salt demo")
    print("cryptex computes hashes; hashlab never will — different jobs.")
