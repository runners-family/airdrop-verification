from .core import utc_epoch
"""Rebuild Phoenix eligibility from the captured board and boundary fills."""
from datetime import datetime, timezone
from decimal import Decimal
import gzip
from pathlib import Path
from .core import address, canonical, loads, on_curve, require, wallet_bytes

SORTS = ('pnl_lifetime', 'pnl1d', 'pnl7d', 'pnl30d')


def derive(root, reference):
    root = Path(root)
    def capture(name):
        return loads(gzip.decompress((root / (name + '.json.gz')).read_bytes()))
    def amount(value):
        calculated = Decimal(str(value['value'])) / Decimal(10) ** value['decimals']
        require(calculated == Decimal(value['ui']), 'Phoenix amount representations differ')
        return calculated
    boards, times = {}, []
    for sort in SORTS:
        row = capture('leaderboard-' + sort)
        require(row['request'] == {'source_id': 'phoenix-leaderboard', 'sort': sort}, 'Unexpected board request')
        require(row['body']['sortBy'] == sort, 'Board sort differs')
        require(utc_epoch(row['retrieved_at']) >= reference['reference_block_time'],
                'Board capture predates reference')
        times.append(row['retrieved_at'])
        boards[sort] = row['body']
    primary = boards['pnl_lifetime']
    anchor = primary['anchorTime']
    require(0 <= anchor - reference['reference_block_time'] < 86400, 'Anchor is outside disclosed window')
    universe = [row['userPubkey'] for row in primary['entries']]
    require(len(universe) == len(set(universe)), 'Duplicate primary authority')
    for board in boards.values():
        keys = [row['userPubkey'] for row in board['entries']]
        require(len(keys) == len(set(keys)) and set(keys) == set(universe), 'Board universe incomplete across sorts')
    decisions, included, off_curve, boundary = [], [], 0, 0
    for row in primary['entries']:
        wallet = row['userPubkey']
        raw = address(wallet)
        lifetime, day = amount(row['volumeLifetime']), amount(row['volume1d'])
        require(amount(row['lifetimeVolume']) == lifetime, 'Lifetime aliases differ')
        decision = dict(wallet=wallet, lifetime_volume_usd_at_anchor=str(lifetime),
                        volume_1d_usd_at_anchor=str(day), rank=row['rank'], qualifies=False,
                        on_curve=on_curve(raw))
        if lifetime < 10000:
            decision['reason'] = 'below_threshold_at_later_anchor'
        elif lifetime - day >= 10000:
            decision.update(qualification_method='leaderboard_bound',
                            volume_usd_before_anchor_minus_24h=str(lifetime - day), qualifies=True)
        else:
            boundary += 1
            fills, page = [], 0
            while True:
                capture_row = capture(f'fills-{wallet}-page-{page:03d}')
                require(capture_row['request']['source_id'] == 'phoenix-fills'
                        and capture_row['request']['wallet'] == wallet
                        and capture_row['request']['page'] == page, 'Fill page plan differs')
                body = capture_row['body']
                fills.extend(body['data'])
                if not body['hasMore']:
                    break
                page += 1
            identities = [(fill.get('signature'), fill.get('fillId'), fill.get('eventIndex')) for fill in fills]
            require(len(identities) == len(set(identities)), 'Duplicate fills')
            def notional(rows):
                return sum((abs(Decimal(fill['price']) * Decimal(fill['baseLotsDelta']))
                            for fill in rows), Decimal(0)).quantize(Decimal('0.000001'))
            def fill_time(fill):
                return int(datetime.strptime(fill['timestamp'], '%Y-%m-%dT%H:%M:%SZ').replace(tzinfo=timezone.utc).timestamp())
            require(notional(fill for fill in fills if fill_time(fill) <= anchor) == lifetime,
                    'Boundary fill history does not reproduce lifetime volume')
            value = notional(fill for fill in fills if fill['slot'] <= reference['reference_slot'])
            decision.update(qualification_method='fills_through_snapshot_slot',
                            volume_usd_through_snapshot_slot=str(value), fills_total=len(fills),
                            fills_after_snapshot_slot=sum(fill['slot'] > reference['reference_slot'] for fill in fills),
                            qualifies=value >= 10000)
        if decision['qualifies'] and not decision['on_curve']:
            decision['qualifies'] = False
            decision['reason'] = 'off_curve_authority_not_directly_attributed'
            off_curve += 1
        if decision['qualifies']:
            included.append(wallet)
        decisions.append(decision)
    outputs = {'wallets.txt': wallet_bytes(sorted(included)),
               'decisions.jsonl': b''.join(canonical(row) for row in sorted(decisions, key=lambda r:r['wallet']))}
    return outputs, {'wallets': len(included), 'authorities_reviewed': len(universe),
                     'boundary_authorities': boundary, 'off_curve_qualifiers': off_curve,
                     'capture_times': sorted(times), 'anchor_time': anchor,
                     'source_limit': 'Captured leaderboard; opt-outs and unavailable public-source coverage remain a lower bound.'}
