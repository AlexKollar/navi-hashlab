"""identify.py — name a hash by its shape.

Length + character-set analysis, plus the structural tells (prefixes,
field separators, encoded forms). Honest about the limits: MD5 and
NTLM are the same shape and no amount of staring at the string can
tell them apart — the chip says so and explains what WOULD confirm it.
"""

import base64
import binascii
import re

_HEX = re.compile(r"^[0-9a-fA-F]+$")
_B64 = re.compile(r"^[A-Za-z0-9+/=_-]+$")
_BCRYPT = re.compile(r"^\$2[aby]\$(\d{2})\$[./A-Za-z0-9]{53}$")
_BCRYPT_LOOSE = re.compile(r"^\$2[aby]\$(\d{2})\$(.*)$")
_CRYPT = re.compile(r"^\$([156])\$")
_SHA512CRYPT_ROUNDS = re.compile(r"^\$6\$rounds=(\d+)\$")


def _is_hex(text):
    return bool(_HEX.match(text))


def _b64_digest(text):
    """If text is base64 wrapping raw digest bytes, return its size."""
    candidate = text.strip()
    if len(candidate) < 16 or not _B64.match(candidate):
        return None
    normalized = candidate.replace("-", "+").replace("_", "/")
    normalized += "=" * (-len(normalized) % 4)
    try:
        raw = base64.b64decode(normalized, validate=True)
    except (binascii.Error, ValueError):
        return None
    # Re-encode and compare: a decoded-then-encoded string must come
    # back identical, otherwise this was ordinary text, not a digest.
    again = base64.b64encode(raw).decode().rstrip("=")
    if again != candidate.rstrip("="):
        return None
    if len(raw) in (16, 20, 28, 32, 48, 64):
        return len(raw)
    return None


def _report(original, candidates, facts, confirm):
    lines = ["input: " + original]
    lines += ["  fact: " + fact for fact in facts]
    if candidates:
        lines.append("candidates (most likely first):")
        for rank, (name, why) in enumerate(candidates, 1):
            lines.append("  %d. %s — %s" % (rank, name, why))
    else:
        lines.append("candidates: none — this does not match a known hash shape.")
    lines.append("confirm: " + confirm)
    return "\n".join(lines)


def identify(raw):
    """Identify a hash string; returns the report text."""
    text = (raw or "").strip()
    if not text:
        return ("identify needs a hash to look at.\n"
                "usage: hashlab id <hash>")
    if len(text) > 512:
        return ("That is %d characters — hashes are short. "
                "Paste just the hash itself." % len(text))

    # ---- encoded / modular formats first: their prefixes are proof
    if text.startswith("$argon2"):
        parts = text.split("$")
        variant = "argon2id" if "argon2id" in text else \
            "argon2i" if "$argon2i$" in text else "argon2d"
        facts = ["the $argon2 prefix and $-separated parameter fields "
                 "are the PHC string format"]
        for part in parts:
            if part.startswith("m="):
                facts.append("parameters ride inside the string: " + part)
        return _report(
            text,
            [(variant + " (encoded PHC string)",
              "salt and cost parameters are stored in the string itself")],
            facts,
            "the parameters are the confirmation — re-run the KDF with "
            "them and compare. There is no shape-only lookalike.")

    m = _BCRYPT.match(text)
    if m:
        return _report(
            text,
            [("bcrypt", "the $2x$ prefix, cost field, and 53 characters "
                        "of bcrypt-base64 after it")],
            ["$2b$ (or $2a$/$2y$) prefix marks the bcrypt family",
             "cost factor %s — each +1 doubles the work" % m.group(1),
             "total length 60: prefix + salt (22 chars) + hash (31 chars)"],
            "re-run bcrypt with the embedded salt and cost and compare; "
            "the shape has no common impostor.")

    m = _BCRYPT_LOOSE.match(text)
    if m:
        # The prefix and cost are right; measure what follows in the
        # bcrypt base64 alphabet (which includes . and /). A body a
        # few characters off 53 is still bcrypt family — truncated
        # pastes and re-encodings are everyday lab accidents.
        body = m.group(2)
        if len(body) >= 20 and all(c in "./ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789" for c in body):
            return _report(
                text,
                [("bcrypt", "the $2b$ prefix and cost field announce it; "
                            "the body is bcrypt-base64")],
                ["$2b$ (or $2a$/$2y$) prefix marks the bcrypt family",
                 "cost factor %s — each +1 doubles the work" % m.group(1),
                 "body after the prefix is %d chars (a textbook bcrypt "
                 "string carries 53: 22 salt + 31 hash)" % len(body)],
                "re-run bcrypt with the embedded salt and cost and "
                "compare; if this came from a database, check the "
                "column width — bcrypt strings are 60 chars and get "
                "truncated by short columns.")

    m = _CRYPT.match(text)
    if m:
        kind = {"1": ("md5crypt", "$1$"),
                "5": ("sha256crypt", "$5$"),
                "6": ("sha512crypt", "$6$")}[m.group(1)]
        facts = ["the %s prefix is the Unix crypt(3) modular format" % kind[1]]
        rounds = _SHA512CRYPT_ROUNDS.match(text)
        if rounds:
            facts.append("explicit rounds=%s in the string" % rounds.group(1))
        fields = text.count("$")
        facts.append("$-separated fields: salt follows the prefix (%d separators)" % fields)
        return _report(
            text,
            [(kind[0], "modular crypt format with the salt carried in the string")],
            facts,
            "crypt(3) with the embedded salt reproduces it exactly.")

    if text.startswith("$7$"):
        return _report(
            text,
            [("scrypt (yescrypt-family crypt format)", "$7$ prefix")],
            ["the $7$ prefix is scrypt in the Unix crypt modular format"],
            "crypt(3) with the embedded parameters reproduces it.")

    if re.match(r"^[0-9a-fA-F]{32}:[0-9a-fA-F]{32}$", text):
        return _report(
            text,
            [("LM:NTLM pair (Windows SAM / pwdump format)",
              "two 32-hex halves joined by a colon")],
            ["left half is the LM hash slot, right half the NTLM hash",
             "an all-aad3b435... left half means LM is disabled/empty"],
            "the right half is an NTLM hash — feed it to: "
            "hashlab crack <hash> --algo ntlm")

    # ---- hex digests: length is the main witness
    if _is_hex(text):
        n = len(text)
        by_len = {
            32: ([("MD5", "128-bit digest, 32 hex chars — the classic"),
                  ("NTLM", "MD4 of the password's UTF-16LE; Windows' "
                           "unsalted password hash"),
                  ("LM (single half)", "a lone half of a Windows LM hash"),
                  ("MD4 / MD2", "same 128-bit shape, rarely seen alone")],
                 "MD5 and NTLM are THE SAME SHAPE — identical length, "
                 "identical charset. No inspection of the string can "
                 "separate them; provenance can: from a Windows SAM or "
                 "NTDS dump it is NTLM, from a web-app database it is "
                 "almost always MD5. Trying both costs nothing: "
                 "hashlab crack <hash> --algo ntlm, then --algo md5."),
            40: ([("SHA-1", "160-bit digest, 40 hex chars"),
                  ("RIPEMD-160", "same 160-bit shape, far rarer"),
                  ("MySQL5 password hash", "SHA1(SHA1(password)), "
                   "usually *-prefixed in the wild")],
                 "hash a known candidate with SHA-1 and compare; "
                 "context (a git object id is SHA-1 by definition) "
                 "usually settles it first."),
            56: ([("SHA-224", "224-bit digest, 56 hex chars"),
                  ("SHA3-224", "same shape, different padding — "
                               "context decides")],
                 "hash a known candidate both ways and compare."),
            64: ([("SHA-256", "256-bit digest, 64 hex chars — the "
                              "modern default"),
                  ("SHA3-256", "same shape; Keccak padding differs"),
                  ("BLAKE2s-256", "same shape again"),
                  ("NTLM relay / HMAC-SHA256 output", "context shapes "
                   "like this appear in protocol captures too")],
                 "hash a known candidate with SHA-256 and compare; "
                 "if it came from a blockchain or a modern API, "
                 "SHA-256 is the working assumption."),
            96: ([("SHA-384", "384-bit digest, 96 hex chars")],
                 "hash a known candidate with SHA-384 and compare."),
            128: ([("SHA-512", "512-bit digest, 128 hex chars"),
                   ("SHA3-512 / BLAKE2b-512", "same shape — context "
                    "and a test hash decide")],
                  "hash a known candidate with SHA-512 and compare."),
        }
        if n in by_len:
            candidates, confirm = by_len[n]
            return _report(
                text, candidates,
                ["%d hexadecimal characters = %d bytes of digest" % (n, n // 2),
                 "charset is purely 0-9a-f — a raw hex-encoded digest"],
                confirm)
        return _report(
            text, [],
            ["%d hexadecimal characters — no standard digest is %d bits "
             "long" % (n, n * 4),
             "it may be truncated, have extra characters pasted in, "
             "or be a token/key rather than a hash"],
            "check the source the string came from; standard lengths "
            "are 32/40/56/64/96/128 hex characters.")

    if re.match(r"^\*[0-9a-fA-F]{40}$", text):
        return _report(
            text,
            [("MySQL 4.1+ password hash", "a *-prefixed double SHA-1")],
            ["the leading * and 40 hex characters are MySQL's signature"],
            "it is SHA1(SHA1(password)) in hex — unsalted and fast; "
            "shape alone is conclusive here.")

    # ---- base64-wrapped digests
    size = _b64_digest(text)
    if size:
        names = {16: "MD5 or NTLM", 20: "SHA-1", 28: "SHA-224",
                 32: "SHA-256", 48: "SHA-384", 64: "SHA-512"}
        return _report(
            text,
            [("base64-wrapped " + names[size] + " digest",
              "the string base64-decodes to exactly %d raw bytes" % size)],
            ["not a raw digest — a digest ENCODED in base64",
             "LDAP/SSHA and many APIs store hashes this way"],
            "base64-decode it, hex the bytes, and run hashlab id on "
            "the result.")

    return _report(
        text, [],
        ["length %d, charset does not match hex or a known encoded "
         "form" % len(text),
         "no $ prefix (bcrypt/argon2/crypt formats all announce "
         "themselves)"],
        "check for stray whitespace or a truncated paste; if it "
        "came from a database column, look at the column's neighbours "
        "for a salt column — a salt beside it changes the story.")
