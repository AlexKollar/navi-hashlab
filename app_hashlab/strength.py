"""strength.py — password strength, the teaching way.

Entropy, dictionary hits, and pattern notes, with the cracking-time
contrast that is the actual lesson: the same password dies in seconds
against a fast hash and lives for years against a slow KDF. The
password itself is never echoed back — only its first character and
its length.
"""

import math
import re
import time

from app_hashlab.wordlist import Words

_LEET = {
    "0": "o", "1": "i", "3": "e", "4": "a", "5": "s", "7": "t",
    "@": "a", "$": "s", "!": "i", "|": "i", "8": "b", "2": "z",
}

_KEYBOARD_ROWS = (
    "qwertyuiop", "asdfghjkl", "zxcvbnm",
    "1234567890", "1qaz2wsx", "qazwsx",
)

_WORDS_LOWER = frozenset(w.lower() for w in Words)

# Offline guesses per second, order-of-magnitude teaching figures:
# fast hash (MD5 on a single GPU) vs a bcrypt-class slow KDF.
_FAST_GPS = 1e10
_SLOW_GPS = 10


def _mask(password):
    return "%s... (%d characters)" % (password[0], len(password))


def _deleet(text):
    return "".join(_LEET.get(ch, ch) for ch in text.lower())


def _pool_size(password):
    pool = 0
    if any(c.islower() for c in password):
        pool += 26
    if any(c.isupper() for c in password):
        pool += 26
    if any(c.isdigit() for c in password):
        pool += 10
    if any(not c.isalnum() for c in password):
        pool += 33
    return pool


def _patterns(password):
    notes = []
    low = password.lower()
    if re.search(r"(19|20)\d{2}", password):
        notes.append("a 4-digit year is embedded — years are a cracker's "
                     "first guess")
    if re.search(r"(123|234|345|456|567|678|789|890|abc|bcd|xyz)", low):
        notes.append("a straight run (123 / abc) — sequences are trivial")
    if re.search(r"(.)\1\1", password):
        notes.append("a character repeated 3+ times — repetition shrinks "
                     "the search space")
    for row in _KEYBOARD_ROWS:
        for i in range(len(row) - 2):
            if row[i:i + 3] in low:
                notes.append("a keyboard walk (%s) — adjacent keys are "
                             "high in every rule set" % row[i:i + 3])
                break
        if notes and "keyboard walk" in notes[-1]:
            break
    return notes


def _fmt_seconds(seconds):
    if seconds < 1:
        return "under a second"
    if seconds < 60:
        return "%d seconds" % round(seconds)
    if seconds < 3600:
        return "%d minutes" % round(seconds / 60)
    if seconds < 86400:
        return "%d hours" % round(seconds / 3600)
    if seconds < 31557600:
        return "%d days" % round(seconds / 86400)
    if seconds < 31557600 * 100:
        return "%d years" % round(seconds / 31557600)
    if seconds < 31557600 * 100000:
        return "%d thousand years" % round(seconds / 31557600 / 1000)
    return "millions of years"


def analyze(password):
    """Analyze a password; returns the report text."""
    if password is None or password == "":
        return ("strength needs a password to look at.\n"
                "usage: hashlab strength <password>")
    if len(password) > 256:
        password = None
        return ("That password is over 256 characters — keep it under "
                "256 for the lab. (It is not echoed here, by design.)")

    start = time.time()

    pool = _pool_size(password)
    entropy = len(password) * math.log2(pool) if pool else 0.0
    guesses = 2 ** entropy if entropy < 1024 else float("inf")

    lines = ["password: " + _mask(password)]
    lines.append("length: %d characters" % len(password))
    if pool:
        kinds = []
        if any(c.islower() for c in password):
            kinds.append("lowercase")
        if any(c.isupper() for c in password):
            kinds.append("uppercase")
        if any(c.isdigit() for c in password):
            kinds.append("digits")
        if any(not c.isalnum() for c in password):
            kinds.append("symbols")
        lines.append("charset: %s (pool of %d)" % (", ".join(kinds), pool))
    lines.append("entropy: %.1f bits (log2 of the full search space)" % entropy)

    # --- dictionary: direct hit, leet-decoded hit, substring hit
    low = password.lower()
    base = _deleet(password)
    hit = None
    if low in _WORDS_LOWER:
        hit = "in the lab wordlist as-is"
    elif base in _WORDS_LOWER and base != low:
        hit = ("in the lab wordlist once leetspeak is decoded (the "
               "base word starts with %r and is %d letters)"
               % (base[0], len(base)))
    else:
        for word in sorted(_WORDS_LOWER, key=len, reverse=True):
            if len(word) >= 4 and word in low:
                hit = "contains a wordlist word (%d letters, starts "\
                      "with %r)" % (len(word), word[0])
                break
    if hit:
        lines.append("dictionary: HIT — %s" % hit)
    else:
        lines.append("dictionary: no hit in the %d-word lab wordlist"
                     % len(Words))

    for note in _patterns(password):
        lines.append("pattern: " + note)

    if guesses == float("inf"):
        lines.append("cracking time (fast hash, ~10 billion guesses/sec): "
                     "effectively never — 2^%.0f is not a number an "
                     "attacker finishes" % entropy)
    else:
        lines.append("cracking time vs a fast hash (MD5, ~10 billion "
                     "guesses/sec): " + _fmt_seconds(guesses / _FAST_GPS))
    if guesses == float("inf"):
        lines.append("cracking time vs a slow KDF (bcrypt-class, ~10 "
                     "guesses/sec): effectively never either")
    else:
        lines.append("cracking time vs a slow KDF (bcrypt-class, ~10 "
                     "guesses/sec): " + _fmt_seconds(guesses / _SLOW_GPS))

    # --- the verdict, by entropy, with the dictionary hit overriding
    if hit:
        verdict = "WEAK — a dictionary hit beats entropy on paper. " \
                  "A cracker tries the wordlist first; this password " \
                  "is gone in the first seconds of any run."
    elif entropy < 28:
        verdict = "WEAK — under 28 bits. A fast-hash attacker walks " \
                  "the whole space quickly."
    elif entropy < 48:
        verdict = "FAIR — fine against a slow KDF, but a stolen fast " \
                  "hash kills it in hours or less. Length is the " \
                  "cheapest upgrade: a few more characters buys more " \
                  "bits than any symbol swap."
    elif entropy < 64:
        verdict = "GOOD — a slow KDF buys years; a fast hash still " \
                  "falls inside a long weekend. Add length."
    else:
        verdict = "STRONG — length + mixed classes. Even a leaked fast " \
                  "hash would take an attacker years at 10 billion " \
                  "guesses a second."
    lines.append("verdict: " + verdict)
    lines.append("the lesson: entropy is a ceiling, not a guarantee — "
                 "the dictionary, the year, and the keyboard walk all "
                 "cut straight through it. That is why the crack "
                 "command tries the wordlist before anything else, "
                 "and why the salt demo matters.")
    lines.append("(checked in %.2fs)" % (time.time() - start))
    return "\n".join(lines)
