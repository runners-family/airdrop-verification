"""Discover every registry wrapper, value direct holders, and apply disclosed screens."""
from collections import defaultdict
from fractions import Fraction
import gzip
from pathlib import Path
from .core import account_data, canonical, loads, require, wallet_bytes
from .capture_store import Bundle
from . import holder_common as c


def derive(root, reference):
    root = Path(root)
    store = Bundle(root)
    folder = Path('data/overpass')
    def capture(name):
        body, record = store.capture(folder, name)
        require(body is not None, 'Missing required Overpass capture')
        return body, record
    def accounts(prefix, options):
        values, slots = {}, {}
        for path in sorted((root / folder).glob(prefix + '*.json.gz')):
            body, record = capture(path.name.removesuffix('.json.gz'))
            request = record['job']['rpc']
            require(request['method'] == 'getMultipleAccounts' and request['params'][1] ==
                    dict(options, minContextSlot=reference['reference_slot']), 'Account request scope differs')
            slot = body['result']['context']['slot']
            require(slot >= reference['reference_slot'], 'Account read predates reference')
            keys, rows = request['params'][0], body['result']['value']
            require(len(keys) == len(rows), 'Account response length differs')
            for key, row in zip(keys, rows):
                require(key not in values, 'Duplicate account proof')
                values[key], slots[key] = row, slot
        return values, slots
    registry, record = capture('overpass-registry')
    require(record['job'] == {'name': 'overpass-registry', 'source_id': 'registry:overpass'},
            'Registry request differs')
    require(registry['nextCursor'] is None, 'Registry not exhausted')
    mints, _ = accounts('overpass-wrapper-mints-', {'encoding': 'base64', 'commitment': 'finalized'})
    positions, pools, seen = defaultdict(list), set(), set()
    for wrapper in registry['items']:
        mint = wrapper['wrapperMint']
        require(mint not in seen, 'Duplicate wrapper')
        seen.add(mint)
        account = mints.get(mint)
        require(account and account['owner'] == c.TOKEN, 'Wrapper mint program differs')
        raw = account_data(account)
        require(len(raw) == 82 and raw[45] == 1 and raw[44] == wrapper['decimals'], 'Wrapper precision differs')
        pools.update((wrapper['wrapperVault'], wrapper['sourcePool']))
        body, record = capture('overpass-holders-' + mint)
        require(record['job']['rpc'] == {'id': 1, 'jsonrpc': '2.0', 'method': 'getProgramAccounts', 'params': [c.TOKEN, {
            'encoding': 'base64', 'commitment': 'finalized', 'minContextSlot': reference['reference_slot'],
            'withContext': True, 'filters': [{'dataSize': 165}, {'memcmp': {'offset': 0, 'bytes': mint}}],
            'dataSlice': {'offset': 32, 'length': 40}}]}, 'Holder capture query differs')
        holders, _, slot, _ = c.owner_amount_holders(body, record['job'], mint)
        require(slot >= reference['reference_slot'], 'Holder read predates reference')
        price = Fraction(str(wrapper['priceUsd'])) if wrapper.get('priceUsd') is not None else None
        require(price is None or price >= 0, 'Negative wrapper price')
        for wallet, amount in holders.items():
            value = Fraction(amount, 10 ** wrapper['decimals']) * price if price is not None else None
            positions[wallet].append(dict(mint=mint, amount_raw=str(amount), decimals=wrapper['decimals'],
                                          price_fraction=c.encoded(price) if price is not None else None,
                                          value=value, slot=slot))
    require(set(mints) == seen, 'Unplanned/missing wrapper mint proofs')
    screened, slots = accounts('owner-check-', {'encoding': 'base64', 'dataSlice': {'offset': 0, 'length': 1},
                                               'commitment': 'finalized'})
    excluded, _ = c.exclusion_registry(store, Path('data/legacy-services'))
    require(excluded == loads((root / 'expected/legacy-services.json').read_bytes()),
            'Reconstructed frozen service registry differs')
    excluded.update({wallet: 'overpass_vault_or_source_pool' for wallet in pools})
    info = {wallet:(account, slots[wallet]) for wallet, account in screened.items()}
    decisions, included = [], []
    for wallet, records in sorted(positions.items()):
        value = sum((row['value'] for row in records if row['value'] is not None), Fraction(0))
        missing = any(row['value'] is None for row in records)
        reason = c.owner_status(wallet, excluded, info) if value >= 100 or missing else 'below_100'
        require(reason != 'unchecked_owner_account', 'Missing candidate account screen')
        if reason == 'included' and value < 100:
            reason = 'unresolved_price'
        if reason == 'included':
            included.append(wallet)
        positions_public = []
        for row in records:
            positions_public.append({key: child for key, child in row.items() if key != 'value'} |
                                    {'value_fraction': c.encoded(row['value']) if row['value'] is not None else None})
        decisions.append(dict(wallet=wallet, qualifies=reason == 'included', decision=reason,
                              value_usd_fraction=c.encoded(value), unpriced=missing, positions=positions_public))
    return {'wallets.txt': wallet_bytes(included),
            'decisions.jsonl': b''.join(canonical(row) for row in decisions)}, {
        'wallets': len(included), 'wrapper_mints': len(seen), 'candidate_owners': len(positions),
        'source_limit': 'Captured official wrapper registry NAV and direct receipt holdings; known legacy service screens.'}
