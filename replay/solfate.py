"""Credential fingerprint and holder checks without personal metadata fields."""
import base64
import gzip
import hashlib
from pathlib import Path
from .core import account_data, address, canonical, encode58, loads, on_curve, require, wallet_bytes

TOKEN = 'TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb'
AUTHORITY = '2KJung5NgLQ84AcPrDhDj7sMvwbYd4CwCrpEqiGQuWa4'
POINTER = 'ListdawmTuyi3AYVyW5Tbhcpn6vDEogFPx2tnVXYpUL'
URI = 'https://arweave.net/pU-bAhOLQfDDQxByxThtgqfmXc7Wrcg15pzziDK-o5A'
ATA = 'ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL'


def pda(seeds, program):
    for bump in range(255, -1, -1):
        raw = hashlib.sha256(b''.join(seeds) + bytes([bump]) + address(program) + b'ProgramDerivedAddress').digest()
        if not on_curve(raw):
            return encode58(raw)
    raise ValueError('No PDA bump')


def extension_map(raw):
    require(len(raw) >= 166 and raw[165] == 1, 'Expected extended mint')
    offset, result = 166, {}
    while offset < len(raw):
        if not any(raw[offset:]):
            break
        require(offset + 4 <= len(raw), 'Truncated extension header')
        kind = int.from_bytes(raw[offset:offset + 2], 'little')
        length = int.from_bytes(raw[offset + 2:offset + 4], 'little')
        offset += 4
        require(offset + length <= len(raw) and kind not in result, 'Invalid repeated extension')
        result[kind] = raw[offset:offset + length]
        offset += length
    return result


def metadata(raw):
    require(len(raw) >= 64, 'Truncated metadata')
    authority, mint = encode58(raw[:32]), encode58(raw[32:64])
    offset, strings = 64, []
    for _ in range(3):
        require(offset + 4 <= len(raw), 'Truncated metadata string')
        size = int.from_bytes(raw[offset:offset + 4], 'little')
        offset += 4
        require(offset + size <= len(raw), 'Truncated metadata string')
        strings.append(raw[offset:offset + size].decode())
        offset += size
    require(raw[offset:] == bytes(4), 'Public metadata projection must omit identity key/value pairs')
    return authority, mint, strings


def check_mint(mint, account):
    require(account and account['owner'] == TOKEN, 'Wrong credential mint program')
    raw = account_data(account)
    require(len(raw) >= 166 and raw[45] == 1 and raw[44] == 0, 'Not initialized zero-decimal NFT')
    require(raw[:4] == b'\x01\0\0\0' and raw[4:36] == address(AUTHORITY), 'Wrong mint authority')
    extensions = extension_map(raw)
    require(extensions.get(9) == b'' and {18, 19, 22} <= set(extensions), 'Missing credential extensions')
    require(extensions[18] == address(POINTER) + address(mint), 'Wrong metadata pointer')
    require(extensions[22] == address(AUTHORITY) + address(mint), 'Wrong group-member pointer')
    authority, metadata_mint, strings = metadata(extensions[19])
    require(authority == AUTHORITY and metadata_mint == mint
            and strings == ['Solana DevList Membership', 'DevList', URI], 'Credential fingerprint differs')
    supply = int.from_bytes(raw[36:44], 'little')
    require(supply in (0, 1), 'Unexpected credential supply')
    return supply


def check_holder(mint, wallet, account):
    if not account or account['owner'] != TOKEN:
        return False
    raw = account_data(account)
    return (len(raw) >= 166 and raw[:32] == address(mint) and raw[32:64] == address(wallet)
            and int.from_bytes(raw[64:72], 'little') == 1 and raw[108] in (1, 2))


def derive(root, reference):
    root = Path(root)
    def capture(name):
        return loads(gzip.decompress((root / (name + '.json.gz')).read_bytes()))
    roster = capture('official-current-members')
    require(roster['request'] == {'source_id': 'solfate-public-roster'}, 'Unexpected roster source')
    members = roster['body']['members']
    require(len(members) == len({r['token'] for r in members}), 'Duplicate public roster mint')
    official = {row['token']: row for row in members}
    indexed, page = {}, 1
    while True:
        item = capture('issuer-assets-page-' + str(page))
        request = item['request']
        require(request['method'] == 'getAssetsByAuthority' and request['params'] ==
                {'authorityAddress': AUTHORITY, 'page': page, 'limit': 1000}, 'Issuer discovery plan differs')
        result = item['body']['result']
        require(result['page'] == page and result['limit'] == 1000, 'Issuer page differs')
        for row in result['items']:
            require(row['id'] not in indexed, 'Duplicate indexed mint')
            indexed[row['id']] = row
        if not result['items']:
            break
        page += 1
    def batches(prefix):
        result = {}
        for path in sorted(root.glob(prefix + '-*.json.gz')):
            row = loads(gzip.decompress(path.read_bytes()))
            request, body = row['request'], row['body']['result']
            require(request['method'] == 'getMultipleAccounts' and request['params'][1] ==
                    {'encoding': 'base64', 'commitment': 'finalized', 'minContextSlot': reference['reference_slot']},
                    'Account batch options differ')
            require(body['context']['slot'] >= reference['reference_slot'], 'Credential account read before reference')
            keys, values = request['params'][0], body['value']
            require(len(keys) == len(values) <= 100, 'Account batch lengths differ')
            for key, value in zip(keys, values):
                require(key not in result, 'Duplicate account proof')
                result[key] = value
        return result
    mints, holdings = batches('mints'), batches('holder-atas')
    require(set(mints) == set(indexed) | set(official), 'Discovered-mint universe differs from proofs')
    decisions, used, holders = [], set(), {}
    for mint in sorted(mints):
        supply = check_mint(mint, mints[mint])
        decision = {'mint': mint, 'supply': supply, 'qualifies': False,
                    'in_index': mint in indexed, 'in_roster': mint in official}
        if supply == 0:
            decision['reason'] = 'zero_current_supply'
        else:
            candidates = set()
            if mint in indexed and indexed[mint].get('ownership', {}).get('owner'):
                candidates.add(indexed[mint]['ownership']['owner'])
            if mint in official and official[mint].get('owner'):
                candidates.add(official[mint]['owner'])
            proven = []
            for wallet in sorted(candidates):
                key = pda([address(wallet), address(TOKEN), address(mint)], ATA)
                require(key in holdings, 'Missing discovered-owner holder proof')
                used.add(key)
                if check_holder(mint, wallet, holdings[key]):
                    proven.append((wallet, key))
            require(len(proven) == 1, 'Live mint lacks unique proven holder')
            wallet, key = proven[0]
            decision.update(wallet=wallet, token_account=key, qualifies=True)
            holders.setdefault(wallet, []).append(mint)
        decisions.append(decision)
    require(used == set(holdings), 'Unplanned holder-account proofs')
    return {'wallets.txt': wallet_bytes(sorted(holders)),
            'credential-decisions.jsonl': b''.join(canonical(row) for row in decisions)}, {
        'wallets': len(holders), 'discovered_mints': len(mints),
        'live_credentials': sum(row['qualifies'] for row in decisions),
        'burned_credentials': sum(row['supply'] == 0 for row in decisions),
        'issuer_index_pages': page,
        'privacy_projection': 'Arbitrary token-metadata additional key/value pairs omitted; credential fingerprint preserved.',
        'source_limit': 'Issuer index plus public roster; not an independently authenticated chain-wide mint census.'}
