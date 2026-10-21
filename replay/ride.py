"""Ride public-source routes plus complete captured successful program histories."""
from collections import Counter, defaultdict
from decimal import Decimal
import gzip
from pathlib import Path
from .core import address, canonical, loads, on_curve, require, wallet_bytes
from .ride_decoder import SOURCES, scan


def derive(root, reference):
    root = Path(root)
    def capture(name):
        return loads(gzip.decompress((root / (name + '.json.gz')).read_bytes()))
    indexed = defaultdict(dict)
    for role, field in (('voters', 'voterWallet'), ('creators', 'creatorWallet')):
        item = capture('api-' + role + '-limit-10000')
        require(item['request'] == {'source_id': 'ride-' + role, 'limit': 10000}, 'Unexpected Ride index plan')
        rows = item['body']['items']
        require(len(rows) < 10000 and len(rows) == len({row[field] for row in rows}), 'Truncated/duplicate Ride index')
        for row in rows:
            if int(row['totalStaked']) > 0:
                indexed[row[field]][role] = {'total_staked_raw': row['totalStaked'],
                                           'count': row.get('totalReceipts', row.get('totalBets'))}
    legacy = capture('legacy-leaderboard')
    require(legacy['request'] == {'source_id': 'ride-legacy-roster'}, 'Unexpected legacy source')
    legacy_rows = {row['wallet']: str(row['volumeUsd']) for row in legacy['body']['members']
                   if Decimal(str(row.get('volumeUsd', 0))) > 0}
    seen, funded, signers, resolvers, coverage = set(), defaultdict(list), defaultdict(Counter), Counter(), {}
    for source, program in SOURCES.items():
        page, cursor, rows = 0, None, []
        while True:
            item = capture(f'{source}-page-{page:03d}')
            request, result = item['request'], item['body']['result']
            require(request['method'] == 'getTransactionsForAddress' and request['params'][0] == program,
                    'Ride history source differs')
            options = request['params'][1]
            require(options['filters'] == {'status': 'succeeded', 'slot': {'lte': reference['reference_slot']}}
                    and options['transactionDetails'] == 'full' and options['encoding'] == 'jsonParsed'
                    and options['commitment'] == 'finalized' and options['sortOrder'] == 'desc'
                    and options.get('paginationToken') == cursor, 'Ride history query/cursor differs')
            rows.extend(result['data'])
            cursor = result.get('paginationToken')
            if not cursor:
                break
            page += 1
        cov = loads((root / (source + '-coverage.json')).read_bytes())
        require(cov['pages'] == page + 1 and cov['returned_rows'] == len(rows)
                and cov['slot_lte'] == reference['reference_slot'], 'Ride history coverage differs')
        coverage[source] = {'pages': page + 1, 'transactions': len(rows)}
        for transaction in rows:
            require(transaction['slot'] <= reference['reference_slot'] and transaction['meta']['err'] is None,
                    'Out-of-scope Ride transaction')
            signature = transaction['transaction']['signatures'][0]
            if signature in seen:
                continue
            seen.add(signature)
            keys, actions, instructions, _ = scan(transaction)
            for wallet in keys:
                for program, name in instructions:
                    signers[wallet][program + ':' + name] += 1
            if any(program == 'ride-gov' and name in ('ResolveBet', 'ResolveBetEarly') for program, name in instructions):
                resolvers.update(keys)
            for action in actions:
                funded[action['wallet']].append(action)
    candidates = set(indexed) | set(legacy_rows) | set(funded) | set(signers)
    decisions, included = [], []
    for wallet in sorted(candidates):
        actions = sorted(funded.get(wallet, []), key=lambda row:(row['slot'], row['signature']))
        routes = []
        if wallet in indexed and actions:
            routes.append('public_index')
        if wallet in legacy_rows:
            routes.append('legacy_snapshot')
        if actions and wallet not in resolvers:
            routes.append('program_history')
        ordinary = on_curve(address(wallet))
        qualifies = bool(routes and ordinary)
        if qualifies:
            included.append(wallet)
        decisions.append(dict(wallet=wallet, qualifies=qualifies, routes=routes, on_curve=ordinary,
                              public_index=indexed.get(wallet), legacy_snapshot_volume_usd=legacy_rows.get(wallet),
                              funded_actions_through_snapshot=len(actions),
                              first_funded_action=actions[0] if actions else None,
                              last_funded_action=actions[-1] if actions else None,
                              protocol_resolver_signatures=resolvers[wallet]))
    return {'wallets.txt': wallet_bytes(included),
            'decisions.jsonl': b''.join(canonical(row) for row in decisions)}, {
        'wallets': len(included), 'candidates_reviewed': len(candidates), 'unique_transactions': len(seen),
        'coverage': coverage,
        'source_limit': 'Captured public indexes and legacy roster; terminal captured successful program histories through reference.'}
