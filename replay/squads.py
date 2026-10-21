"""Raw Squads account decoding, team selection and member attribution.

All on-curve member keys of qualifying teams receive this category. The 2–20
voter condition gates teams, rather than restricting awards to voting members.
"""
from collections import Counter
from pathlib import Path
from .core import account_data, address, canonical, encode58, loads, on_curve, require, wallet_bytes

PROGRAMS = {
    'v4_multisig': ('Multisig', 'v4', 'SQDS4ep65T869zMMBKyuUq6aD6EgTu8psMjkvj52pCf'),
    'v3_ms': ('Ms', 'v3', 'SMPLecH534NA9acpos4G6x7uf3LWbCAwZQE9e8ZekMu'),
    'smart_account_settings': ('Settings', 'smart', 'SMRTzfY6DfH5ik3TKiyLFfXexV8uSG3d2UksSCYdunG'),
}


def decode(raw, variant):
    def integer(offset, size):
        require(offset >= 0 and offset + size <= len(raw), 'Truncated Squads account')
        return int.from_bytes(raw[offset:offset + size], 'little')
    if variant == 'v3':
        threshold, proposals, external = integer(8, 2), integer(12, 4), False
        offset = 54
        count = integer(offset, 4)
        offset += 4
        stride = 32
    else:
        offset = 40 if variant == 'v4' else 24
        external = raw[offset:offset + 32] != bytes(32)
        offset += 32
        threshold = integer(offset, 2)
        offset += 6
        proposals = integer(offset, 8)
        offset += 16
        require(raw[offset] in (0, 1), 'Invalid optional address')
        offset += 1 + (32 if raw[offset] else 0)
        offset += 1 if variant == 'v4' else 9
        count = integer(offset, 4)
        offset += 4
        stride = 33
    require(offset + count * stride <= len(raw), 'Truncated members')
    members = [(raw[offset + i * stride:offset + i * stride + 32],
                integer(offset + i * stride + 32, 1) if stride == 33 else 7)
               for i in range(count)]
    require(len({key for key, _ in members}) == count, 'Duplicate team member')
    return threshold, proposals, external, members


def derive(data, reference):
    import hashlib
    import gzip
    root = Path(data)
    teams, slots = {}, {}
    for label, (name, variant, owner) in PROGRAMS.items():
        response = loads(gzip.decompress((root / (label + '.json.gz')).read_bytes()))
        result = response['result']
        slots[label] = result['context']['slot']
        require(slots[label] >= reference['reference_slot'], 'Account read predates reference')
        discriminator = hashlib.sha256(('account:' + name).encode()).digest()[:8]
        for row in result['value']:
            key = row['pubkey']
            address(key)
            require(row['account']['owner'] == owner, 'Wrong Squads account owner')
            raw = account_data(row['account'])
            if raw[:8] != discriminator:
                continue
            require(key not in teams, 'Duplicate team account')
            threshold, proposals, external, members = decode(raw, variant)
            teams[key] = dict(program=label, threshold=threshold, proposals=proposals,
                              external=external, members=members)
    frequencies = Counter(key for row in teams.values() for key, _ in row['members'])
    candidates = {}
    for key, row in teams.items():
        voters = sum(bool(permissions & 2) for _, permissions in row['members'])
        if (row['threshold'] >= 2 and not row['external'] and row['proposals'] >= 25
                and 2 <= voters <= 20 and row['threshold'] <= voters
                and not any(frequencies[member] > 20 for member, _ in row['members'])):
            candidates[key] = row
    activity = {}
    with gzip.open(root / 'activity.jsonl.gz', 'rt') as handle:
        for line in handle:
            row = loads(line)
            key = row['multisig']
            require(key in candidates and key not in activity, 'Unexpected activity candidate')
            last, previous = None, None
            for index, page in enumerate(row['pages']):
                request = page['request']
                require(request['method'] == 'getSignaturesForAddress' and request['params'][0] == key,
                        'Activity request differs from candidate')
                options = request['params'][1]
                expected = {'commitment': 'finalized', 'limit': 25}
                if index:
                    expected['before'] = previous
                require(options == expected, 'Activity cursor or options differ')
                rows = page['response']['result']
                require(len({r['signature'] for r in rows}) == len(rows), 'Duplicate activity signature')
                require(all(rows[i]['slot'] >= rows[i + 1]['slot'] for i in range(len(rows) - 1)),
                        'Unordered activity page')
                for signature in rows:
                    if signature['slot'] <= reference['reference_slot']:
                        last = signature.get('blockTime') or 0
                        break
                if rows:
                    previous = rows[-1]['signature']
                if last is not None:
                    break
            require(last is not None or (row['pages'] and not row['pages'][-1]['response']['result']),
                    'Activity capture ended without bounded result or terminal page')
            activity[key] = last
    require(set(activity) == set(candidates), 'Missing candidate activity')
    cutoff = reference['reference_block_time'] - 365 * 86400
    active = [key for key in sorted(candidates) if activity[key] and activity[key] >= cutoff]
    attribution = {}
    for key in active:
        for raw, permissions in candidates[key]['members']:
            if on_curve(raw):
                attribution.setdefault(encode58(raw), []).append(
                    {'team': key, 'permissions': permissions, 'has_vote': bool(permissions & 2)})
    wallets = sorted(attribution)
    decisions = [dict(wallet=wallet, qualifies=True, teams=attribution[wallet]) for wallet in wallets]
    return {'wallets.txt': wallet_bytes(wallets), 'decisions.jsonl': b''.join(canonical(r) for r in decisions)}, {
        'teams_read': len(teams), 'candidate_teams': len(candidates), 'active_teams': len(active),
        'wallets': len(wallets), 'nonvoting_wallets': sum(not any(t['has_vote'] for t in rows)
                                                      for rows in attribution.values()),
        'account_slots': slots,
    }
