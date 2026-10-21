"""Small shared primitives; never opens a network or reads environment variables."""
import base64
import hashlib
import json
from decimal import Decimal
from functools import lru_cache
from datetime import datetime, timezone
from pathlib import Path, PurePosixPath

ALPHABET = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'


def require(condition, message):
    if not condition:
        raise ValueError(message)


def unique_pairs(pairs):
    result = {}
    for key, value in pairs:
        require(key not in result, 'Duplicate JSON key')
        result[key] = value
    return result


def loads(raw):
    return json.loads(raw, object_pairs_hook=unique_pairs, parse_float=Decimal,
                      parse_constant=lambda _: (_ for _ in ()).throw(ValueError('Nonfinite JSON')))


def utc_epoch(text):
    """Historical collectors record UTC; naive legacy UTC is made explicit.

    Replacing trailing Z also supports Python 3.10. Never use the host timezone.
    """
    require(isinstance(text, str), 'Expected UTC capture timestamp')
    value = datetime.fromisoformat(text.removesuffix('Z') + ('+00:00' if text.endswith('Z') else ''))
    if value.tzinfo is None:
        value = value.replace(tzinfo=timezone.utc)
    require(value.utcoffset().total_seconds() == 0, 'Capture timestamp is not UTC')
    return value.timestamp()


def canonical(value):
    def encode(item):
        if isinstance(item, Decimal):
            require(item.is_finite(), 'Nonfinite number')
            return str(item)
        if isinstance(item, dict):
            return '{' + ','.join(json.dumps(k, ensure_ascii=False) + ':' + encode(v)
                                  for k, v in sorted(item.items())) + '}'
        if isinstance(item, list):
            return '[' + ','.join(encode(v) for v in item) + ']'
        return json.dumps(item, ensure_ascii=False, allow_nan=False, separators=(',', ':'))
    return (encode(value) + '\n').encode()


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def file_hash(path):
    h = hashlib.sha256()
    with Path(path).open('rb') as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b''):
            h.update(chunk)
    return h.hexdigest()


def safe_path(root, relative):
    require(isinstance(relative, str) and relative and '\\' not in relative and ':' not in relative, 'Invalid relative path')
    path = PurePosixPath(relative)
    require(str(path) == relative and not path.is_absolute()
            and all(p not in ('.', '..') for p in path.parts), 'Unsafe relative path')
    root = Path(root).resolve()
    resolved = (root / path).resolve()
    require(resolved.is_relative_to(root), 'Path leaves package')
    return resolved


def decode58(value):
    require(isinstance(value, str) and value, 'Invalid base58')
    n = 0
    for ch in value:
        require(ch in ALPHABET, 'Invalid base58')
        n = n * 58 + ALPHABET.index(ch)
    return b'\0' * (len(value) - len(value.lstrip('1'))) + n.to_bytes((n.bit_length() + 7) // 8, 'big')


def encode58(raw):
    n, text = int.from_bytes(raw, 'big'), ''
    while n:
        n, remainder = divmod(n, 58)
        text = ALPHABET[remainder] + text
    return '1' * (len(raw) - len(raw.lstrip(b'\0'))) + text



@lru_cache(maxsize=131072)
def address(value):
    raw = decode58(value)
    require(len(raw) == 32 and encode58(raw) == value, 'Noncanonical Solana address')
    return raw


def wallet_bytes(wallets):
    rows = list(wallets)
    require(rows == sorted(set(rows)), 'Wallets are not sorted and unique')
    for wallet in rows:
        address(wallet)
    return ''.join(wallet + '\n' for wallet in rows).encode()


def read_wallets(path):
    raw = Path(path).read_bytes()
    rows = raw.decode('ascii').splitlines()
    require(wallet_bytes(rows) == raw, 'Noncanonical wallet-list bytes')
    return rows


def on_curve(raw):
    require(len(raw) == 32, 'Expected 32-byte curve encoding')
    p = 2 ** 255 - 19
    n = int.from_bytes(raw, 'little')
    y, sign = n & (2 ** 255 - 1), n >> 255
    if y >= p:
        return False
    d = -121665 * pow(121666, p - 2, p) % p
    denominator = (d * y * y + 1) % p
    if not denominator:
        return False
    xx = (y * y - 1) * pow(denominator, p - 2, p) % p
    return sign == 0 if xx == 0 else pow(xx, (p - 1) // 2, p) == 1


def account_data(account):
    require(isinstance(account, dict) and not account.get('executable'), 'Invalid account')
    data = account['data']
    require(isinstance(data, list) and len(data) == 2 and data[1] == 'base64', 'Expected raw base64 account')
    return base64.b64decode(data[0], validate=True)
