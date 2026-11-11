"""Pure-Python MD4 (RFC 1320).

hashlib only offers MD4 when the OpenSSL build still ships it; under
OpenSSL 3 the legacy provider is usually off, and hashlib.new("md4")
raises. NTLM needs MD4, so the chip carries its own — about sixty
lines, verified in the chip's self-test against the RFC 1320 vectors
and against the known NTLM hash of "password".
"""

import struct

_MASK = 0xFFFFFFFF


def _lrot(value, count):
    value &= _MASK
    return ((value << count) | (value >> (32 - count))) & _MASK


def _f(x, y, z):
    return (x & y) | (~x & z)


def _g(x, y, z):
    return (x & y) | (x & z) | (y & z)


def _h(x, y, z):
    return x ^ y ^ z


def md4(data):
    """Return the 16-byte MD4 digest of data (bytes)."""
    if isinstance(data, str):
        data = data.encode("utf-8")
    msg = bytearray(data)
    bit_len = (len(msg) * 8) & 0xFFFFFFFFFFFFFFFF
    msg.append(0x80)
    while len(msg) % 64 != 56:
        msg.append(0)
    msg += struct.pack("<Q", bit_len)

    a0, b0, c0, d0 = 0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476

    rounds = (
        # (function, word order, shifts, constant)
        (_f, list(range(16)), (3, 7, 11, 19), 0),
        (_g, [0, 4, 8, 12, 1, 5, 9, 13, 2, 6, 10, 14, 3, 7, 11, 15],
         (3, 5, 9, 13), 0x5A827999),
        (_h, [0, 8, 4, 12, 2, 10, 6, 14, 1, 9, 5, 13, 3, 11, 7, 15],
         (3, 9, 11, 15), 0x6ED9EBA1),
    )

    for block_at in range(0, len(msg), 64):
        words = struct.unpack("<16I", bytes(msg[block_at:block_at + 64]))
        a, b, c, d = a0, b0, c0, d0
        regs = [a, b, c, d]
        for func, order, shifts, const in rounds:
            for i, k in enumerate(order):
                target = (-i) % 4  # steps hit a, d, c, b in turn
                x, y, z = regs[(target + 1) % 4], regs[(target + 2) % 4], regs[(target + 3) % 4]
                regs[target] = _lrot(
                    regs[target] + func(x, y, z) + words[k] + const,
                    shifts[i % 4],
                )
        a, b, c, d = regs
        a0 = (a0 + a) & _MASK
        b0 = (b0 + b) & _MASK
        c0 = (c0 + c) & _MASK
        d0 = (d0 + d) & _MASK

    return struct.pack("<4I", a0, b0, c0, d0)


def md4_hex(data):
    """Hex MD4 digest of data (bytes or str)."""
    return md4(data).hex()


def ntlm_hex(password):
    """The NTLM hash of a password: MD4 of its UTF-16LE encoding."""
    return md4(password.encode("utf-16-le")).hex()
