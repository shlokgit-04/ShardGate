"""GF(2^8) arithmetic using the AES polynomial x^8 + x^4 + x^3 + x + 1 (0x11b)."""

def gmul(a: int, b: int) -> int:
    p = 0
    for _ in range(8):
        if b & 1:
            p ^= a
        hi = a & 0x80
        a = (a << 1) & 0xFF
        if hi:
            a ^= 0x1B
        b >>= 1
    return p

_INV = [0] * 256
for _x in range(1, 256):
    for _y in range(1, 256):
        if gmul(_x, _y) == 1:
            _INV[_x] = _y
            break

def ginv(a: int) -> int:
    if a == 0:
        raise ZeroDivisionError("0 has no inverse in GF(2^8)")
    return _INV[a]
