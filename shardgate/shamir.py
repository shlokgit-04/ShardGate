"""Shamir's Secret Sharing over GF(2^8). Byte-wise, information-theoretically secure."""
import os
from .gf256 import gmul, ginv

def _eval_poly(coeffs, x: int) -> int:
    """Horner evaluation; coeffs[0] is the constant term (the secret byte)."""
    y = 0
    for c in reversed(coeffs):
        y = gmul(y, x) ^ c
    return y

def split(secret: bytes, threshold: int, shares: int):
    """Return list of (index, share_bytes). Any `threshold` shares rebuild `secret`."""
    if not (1 <= threshold <= shares <= 255):
        raise ValueError("need 1 <= threshold <= shares <= 255")
    # One polynomial per secret byte, drawn ONCE; every share i is f(i) on it.
    polys = []
    for b in secret:
        polys.append([b] + [os.urandom(1)[0] for _ in range(threshold - 1)])
    out = []
    for i in range(1, shares + 1):
        y = bytes(_eval_poly(p, i) for p in polys)
        out.append((i, y))
    return out

def combine(shares):
    """Lagrange interpolation at x=0 from `threshold` (or more) shares."""
    if len(shares) < 2:
        raise ValueError("need at least 2 shares")
    secret = bytearray(len(shares[0][1]))
    for j in range(len(shares[0][1])):
        acc = 0
        for i, (xi, yi) in enumerate(shares):
            num, den = 1, 1
            for m, (xm, _ym) in enumerate(shares):
                if m == i:
                    continue
                num = gmul(num, xm)            # (0 - xm) == xm in GF(2^8)
                den = gmul(den, xi ^ xm)       # (xi - xm) == xi ^ xm
            li = gmul(num, ginv(den))
            acc ^= gmul(yi[j], li)
        secret[j] = acc
    return bytes(secret)
