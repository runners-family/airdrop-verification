"""Historical pure valuation helpers, extracted without live collection or prior-cohort comparison.
Historical deterministic method adapted for public replay.
"""
from .capture_store import Bundle
import base64
from collections import Counter
from decimal import Decimal
from fractions import Fraction
from functools import lru_cache
import gzip
import hashlib
import json
from pathlib import Path
import re
import struct
ALPHABET = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'
TOKEN = 'TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA'
TOKEN22 = 'TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb'
SYSTEM = '11111111111111111111111111111111'
INCINERATOR = '1nc1nerator11111111111111111111111111111111'
THRESHOLD = Fraction(100)
CEX_URL = 'registry:public-cex'
CEX_SHA256 = '732e7ea7967baa899aad19f71adc1c52592ac3b0b7e31a064557ba023c99d34e'
SYSTEM_WALLETS_URL = 'registry:issuer-wallets'
ZEC = ('A7bdiYdS5GjqGFtxf17ppRHtDKPkkRqbKtR27dxvQXaS', 8)
HYPE = ('98sMhvDwXj1RQi5c5Mndm3vPe9cBqPrbLaufMXFNMh5g', 9)
DEX_URL = 'prices:holder-markets'
P = 2 ** 255 - 19
D = -121665 * pow(121666, P - 2, P) % P

class Fail(ValueError):
    pass

def require(condition, message):
    if not condition:
        raise Fail(message)

def canonical(value):
    """Output canonicalization (from reproduce.py)."""
    return (json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=False, allow_nan=False) + '\n').encode('utf-8')

def job_bytes(job):
    """The collector's request canonicalization (ASCII), used for job_sha256."""
    return (json.dumps(job, sort_keys=True, separators=(',', ':')) + '\n').encode()

def sha(raw):
    return hashlib.sha256(raw).hexdigest()

def fingerprint(raw):
    return {'bytes': len(raw), 'sha256': sha(raw)}

def b58encode(raw):
    """From reproduce.py."""
    (number, result) = (int.from_bytes(raw, 'big'), '')
    while number:
        (number, index) = divmod(number, 58)
        result = ALPHABET[index] + result
    return '1' * (len(raw) - len(raw.lstrip(b'\x00'))) + result

def wallet_bytes(text):
    """From reproduce.py: canonical 32-byte base58 address or failure."""
    require(isinstance(text, str) and 32 <= len(text) <= 44, 'Invalid Solana address')
    number = 0
    for char in text:
        require(char in ALPHABET, 'Invalid base58 character')
        number = number * 58 + ALPHABET.index(char)
    raw = b'\x00' * (len(text) - len(text.lstrip('1')))
    raw += number.to_bytes((number.bit_length() + 7) // 8, 'big')
    require(len(raw) == 32 and b58encode(raw) == text, 'Noncanonical Solana address')
    return raw

@lru_cache(maxsize=None)
def on_curve(address):
    """From screen_100.py: compressed Edwards-Y decompression (PDAs are off-curve)."""
    y = (int.from_bytes(wallet_bytes(address), 'little') & (1 << 255) - 1) % P
    y2 = y * y % P
    (numerator, denominator) = ((y2 - 1) % P, (D * y2 + 1) % P)
    if denominator == 0:
        return False
    return pow(numerator * denominator % P, (P - 1) // 2, P) in (0, 1)

def u64(raw, offset):
    require(len(raw) >= offset + 8, 'Truncated u64')
    return int.from_bytes(raw[offset:offset + 8], 'little')

def number(value):
    """Exact rational from a JSON number/string (Decimal-parsed, no float rounding)."""
    require(value is not None and (not isinstance(value, bool)), 'Missing number')
    return Fraction(Decimal(str(value)))

def encoded(value):
    return [str(value.numerator), str(value.denominator)]

def usd_text(value, places=6):
    """Display only: truncated toward zero. Threshold tests always use the exact fraction."""
    scale = 10 ** places
    whole = abs(value) * scale // 1
    sign = '-' if value < 0 else ''
    return sign + str(whole // scale) + '.' + str(whole % scale).zfill(places)

def unique_object(pairs):
    obj = {}
    for (key, value) in pairs:
        require(key not in obj, 'Duplicate JSON object key: ' + key)
        obj[key] = value
    return obj

def parse_json(raw):
    return json.loads(raw, parse_float=Decimal, object_pairs_hook=unique_object)

def rpc_job(name, method, params):
    return {'name': name, 'rpc': {'jsonrpc': '2.0', 'id': 1, 'method': method, 'params': params}}

def multiplier(raw, timestamp):
    """From screen_100.py: active Token-2022 ScaledUiAmount multiplier (extension type 25)."""
    result = Fraction(1)
    offset = 166
    detail = None
    while offset + 4 <= len(raw):
        (kind, size) = struct.unpack_from('<HH', raw, offset)
        value = raw[offset + 4:offset + 4 + size]
        require(len(value) == size, 'Truncated mint extension')
        if kind == 25:
            require(size == 56, 'Unexpected ScaledUiAmount size')
            (current, effective, upcoming) = struct.unpack_from('<dqd', value, 32)
            result = Fraction.from_float(upcoming if timestamp >= effective else current)
            require(result > 0, 'Non-positive multiplier')
            detail = {'current': repr(current), 'new_multiplier_effective_timestamp': effective, 'new_multiplier': repr(upcoming), 'active': 'new' if timestamp >= effective else 'current'}
        offset += 4 + size
    return (result, detail)

def mint_info(account, slot, retrieved_timestamp):
    """Decode an SPL Token / Token-2022 mint (layout checks from next_batch.validate_mint_plan)."""
    require(account is not None and account['owner'] in {TOKEN, TOKEN22}, 'Missing/non-token mint')
    raw = base64.b64decode(account['data'][0], validate=True)
    require(len(raw) >= 82 and raw[45] == 1, 'Uninitialized mint')
    (extensions, offset) = ([], 166)
    if account['owner'] == TOKEN22 and len(raw) > 82:
        require(len(raw) >= 166 and raw[165] == 1, 'Invalid Token-2022 mint account type')
        while offset + 4 <= len(raw):
            kind = int.from_bytes(raw[offset:offset + 2], 'little')
            size = int.from_bytes(raw[offset + 2:offset + 4], 'little')
            require(offset + 4 + size <= len(raw), 'Truncated mint extension')
            extensions.append(kind)
            offset += 4 + size
    (scale, detail) = multiplier(raw, retrieved_timestamp) if account['owner'] == TOKEN22 else (Fraction(1), None)
    return {'program': account['owner'], 'decimals': raw[44], 'supply_raw': u64(raw, 36), 'slot': slot, 'extension_types': extensions, 'multiplier': scale, 'multiplier_detail': detail}

def token_holder_job(name, mint, program, slot):
    """Per-mint token-account scan, same filters/slices as the September plans, plus minContextSlot."""
    filters = [{'memcmp': {'offset': 0, 'bytes': mint}}]
    if program == TOKEN:
        filters = [{'dataSize': 165}] + filters
    return rpc_job(name, 'getProgramAccounts', [program, {'encoding': 'base64', 'commitment': 'finalized', 'minContextSlot': slot, 'withContext': True, 'filters': filters, 'dataSlice': {'offset': 0, 'length': 165 if program == TOKEN else 166}}])

def token_holders(data, job):
    """From next_batch.token_holders: positive raw balance per owner for one mint scan."""
    (program, options) = job['rpc']['params']
    require(program in {TOKEN, TOKEN22} and options['commitment'] == 'finalized' and options['withContext'], 'Unexpected token capture configuration')
    require(options['dataSlice'] == {'offset': 0, 'length': 165 if program == TOKEN else 166}, 'Unexpected token slice')
    filters = options['filters']
    mint = next((x['memcmp']['bytes'] for x in filters if x.get('memcmp', {}).get('offset') == 0))
    if program == TOKEN:
        require({'dataSize': 165} in filters, 'Missing SPL account-size filter')
    (seen, owners, accounts) = (set(), Counter(), Counter())
    for row in data['result']['value']:
        wallet_bytes(row['pubkey'])
        require(row['pubkey'] not in seen, 'Duplicate token account')
        seen.add(row['pubkey'])
        account = row['account']
        require(account['owner'] == program and account['executable'] is False, 'Wrong token account owner')
        require(account['data'][1] == 'base64', 'Wrong token encoding')
        raw = base64.b64decode(account['data'][0], validate=True)
        require(len(raw) in {165, 166} and b58encode(raw[:32]) == mint, 'Wrong mint or account length')
        require(raw[108] in {1, 2}, 'Uninitialized token account')
        if len(raw) == 166:
            require(program == TOKEN22 and raw[165] == 2, 'Wrong Token-2022 account type')
        amount = u64(raw, 64)
        if amount:
            owner = b58encode(raw[32:64])
            owners[owner] += amount
            accounts[owner] += 1
    return (mint, owners, accounts, data['result']['context']['slot'], len(seen))

def owner_amount_holders(data, job, mint):
    """From reproduce.balances: dataSize 165 + mint filter, slice 32/40 (owner, amount)."""
    (program, options) = job['rpc']['params']
    require(job['rpc']['method'] == 'getProgramAccounts' and program == TOKEN, 'Unexpected holder request')
    require(options.get('commitment') == 'finalized' and options.get('withContext') is True, 'Need finalized context')
    require(options.get('encoding') == 'base64' and options.get('dataSlice') == {'offset': 32, 'length': 40}, 'Unexpected account slice/encoding')
    require({'dataSize': 165} in options['filters'] and {'memcmp': {'offset': 0, 'bytes': mint}} in options['filters'], 'Missing mint filter')
    (owners, accounts, seen) = (Counter(), Counter(), set())
    for row in data['result']['value']:
        wallet_bytes(row['pubkey'])
        require(row['pubkey'] not in seen, 'Duplicate token account in capture')
        seen.add(row['pubkey'])
        require(row['account']['owner'] == TOKEN and row['account']['data'][1] == 'base64', 'Wrong token account')
        raw = base64.b64decode(row['account']['data'][0], validate=True)
        require(len(raw) == 40, 'Unexpected sliced length')
        amount = int.from_bytes(raw[32:], 'little')
        if amount:
            owner = b58encode(raw[:32])
            owners[owner] += amount
            accounts[owner] += 1
    return (owners, accounts, data['result']['context']['slot'], len(seen))

def exclusion_registry(bundle, holders_folder):
    """From screen_100.exclusions, same order of precedence; issuer list refreshed, CEX list pinned."""
    excluded = {SYSTEM: 'system_program', INCINERATOR: 'incinerator'}
    evidence = {}
    (data, record) = bundle.capture(holders_folder, 'xstocks-system-wallets', {'name': 'xstocks-system-wallets', 'source_id': SYSTEM_WALLETS_URL})
    require(data is not None, 'The xStocks issuer wallet list is required')
    for row in data['nodes']:
        require(row['networkType'] == 'Svm', 'Unexpected issuer wallet network')
        wallet_bytes(row['address'])
        excluded[row['address']] = 'issuer_operational_wallet'
    evidence['xstocks_issuer_wallets'] = {'count': len(data['nodes']), 'retrieved_at': record['retrieved_at'], 'source_id': SYSTEM_WALLETS_URL}
    (sql, record) = bundle.capture(holders_folder, 'dune-cex-solana', {'name': 'dune-cex-solana', 'source_id': CEX_URL, 'format': 'text'})
    require(sql is not None and record['body_sha256'] == CEX_SHA256, 'Pinned exchange registry changed')
    labels = 0
    for (address, name) in re.findall("\\('solana'\\s*,\\s*'([^']+)'\\s*,\\s*'([^']+)'", sql, re.I):
        try:
            wallet_bytes(address)
        except ValueError:
            continue
        excluded[address] = 'public_cex_label:' + name
        labels += 1
    evidence['pinned_cex_labels'] = {'valid_addresses': labels, 'sha256': CEX_SHA256, 'source_id': CEX_URL, 'retrieved_at': record['retrieved_at']}
    (prices, record) = bundle.capture(holders_folder, 'holder-market-prices', {'name': 'holder-market-prices', 'source_id': DEX_URL})
    require(prices is not None, 'DexScreener pairs are required')
    for pair in prices:
        excluded[pair['pairAddress']] = 'public_dex_pool'
    evidence['dex_pool_pairs'] = {'count': len(prices), 'retrieved_at': record['retrieved_at'], 'source_id': DEX_URL}
    return (excluded, evidence)

def owner_check_job(addresses, slot):
    """From screen_100.owner_jobs (batches of 100, digest-named), plus minContextSlot."""
    name = 'owner-check-' + sha(canonical(addresses))[:20]
    return rpc_job(name, 'getMultipleAccounts', [addresses, {'encoding': 'base64', 'dataSlice': {'offset': 0, 'length': 1}, 'commitment': 'finalized', 'minContextSlot': slot}])

def plan_owner_checks(candidates, already, slot):
    missing = sorted(set(candidates) - set(already))
    return [owner_check_job(missing[i:i + 100], slot) for i in range(0, len(missing), 100)]

def read_owner_checks(bundle, folder, jobs, slot):
    """Account info per checked address; failed batches are returned as gaps, never as 'no account'."""
    (info, slots, gaps, times) = ({}, [], [], [])
    for job in jobs:
        (data, record) = bundle.capture(folder, job['name'], job)
        if data is None:
            gaps.append({'capture': job['name'], 'addresses': len(job['rpc']['params'][0]), 'status': 'missing' if record is None else 'failed'})
            continue
        keys = job['rpc']['params'][0]
        require(len(keys) == len(data['result']['value']), 'Missing account check entries')
        context = data['result']['context']['slot']
        require(context >= slot, 'Account check below the reference slot')
        for (key, account) in zip(keys, data['result']['value']):
            require(key not in info, 'Duplicate account check: ' + key)
            info[key] = (account, context)
        slots.append(context)
        times.append(record['retrieved_at'])
    return (info, slots, gaps, times)

def owner_status(wallet, excluded, info):
    """From screen_100.report.owner_status; 'unchecked_owner_account' only when a check is missing."""
    if wallet in excluded:
        return excluded[wallet]
    if not on_curve(wallet):
        return 'off_curve_pda'
    if wallet not in info:
        return 'unchecked_owner_account'
    account = info[wallet][0]
    if account and account['executable']:
        return 'executable_account'
    if account and account['owner'] != SYSTEM:
        return 'program_owned_account'
    if account and (account.get('space', 0) != 0 or account['data'][0]):
        return 'system_account_with_data'
    return 'included'

def account_evidence(wallet, info):
    if wallet not in info:
        return None
    (account, slot) = info[wallet]
    if account is None:
        return {'exists': False, 'slot': slot}
    return {'exists': True, 'owner': account['owner'], 'executable': account['executable'], 'space': account.get('space'), 'lamports': account.get('lamports'), 'slot': slot}

def wallet_list_bytes(wallets):
    return ''.join((w + '\n' for w in sorted(wallets))).encode()
