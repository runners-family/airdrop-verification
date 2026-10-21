"""Faster program-derived-address search, equal in result to solana_util.find_pda.

solana_util._on_curve_bytes computes x^2 = u * v^(p-2) and then Euler's criterion on x^2
(three modular exponentiations, one of them recomputing the constant d). Because p-2 is odd,
v^(p-2) has the same quadratic character as v, so Euler's criterion on u*v gives the same
answer with one exponentiation. replay.py checks this module against solana_util.find_pda.
"""
import hashlib

_P = 2 ** 255 - 19
_D = -121665 * pow(121666, _P - 2, _P) % _P
_HALF = (_P - 1) // 2
_MASK = (1 << 255) - 1


def on_curve(raw):
    encoded = int.from_bytes(raw, 'little')
    y = encoded & _MASK
    if y >= _P:
        return False
    yy = y * y
    num, den = (yy - 1) % _P, (_D * yy + 1) % _P
    if den == 0:
        return False
    if num == 0:
        return encoded >> 255 == 0
    return pow(num * den % _P, _HALF, _P) == 1


def find_pda_raw(seeds, program_raw):
    for bump in range(255, -1, -1):
        raw = hashlib.sha256(b''.join(seeds) + bytes([bump]) + program_raw + b'ProgramDerivedAddress').digest()
        if not on_curve(raw):
            return raw, bump
    raise ValueError('No PDA')
