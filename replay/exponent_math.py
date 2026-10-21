from .core import utc_epoch
"""Historical product valuation helpers, no collection or old-list comparisons.
Historical deterministic method adapted for public replay.
"""
import base64
from collections import defaultdict
from decimal import Decimal
import gzip
import hashlib
import json
from pathlib import Path
import datetime
from .core import decode58, encode58, on_curve, loads
D = Decimal
PROGRAM = 'HYEXCHtHkBagdStcJCp3xbbb9B7sdMdWXFNj6mdsG4hn'
TOKEN = 'TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA'
TOKEN_2022 = 'TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb'
ATA = 'ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL'
CORE = 'ExponentnaRg3CQbW6dqQNZKXp7gtZ9DGMp1cwC4HAS7'
STRATEGY_PROGRAMS = {'sVau1tXvayVWfotzm9Ahcv2qfnnfRWttt78BCnNC6dD', 'HycecAnELpjL1pMp435nEKWkcr7aNZ2QGQGXpzK1VEdV'}
WSOL = 'So11111111111111111111111111111111111111112'
MARKET_DISCRIMINATOR = 'cTqXrNHKo7H'
VAULT_DISCRIMINATOR = 'cJJWPqNMczr'
ORACLE_MAX_SKEW_SECONDS = 60
READ_FILES = set()

def read(path):
    READ_FILES.add(path.resolve())
    raw = path.read_bytes()
    return loads(gzip.decompress(raw) if path.suffix == '.gz' else raw)

def exists(path):
    return path.exists()

def account_bytes(row):
    return base64.b64decode(row['data'][0], validate=True)

def pda(program, seeds):
    for bump in range(255, -1, -1):
        raw = hashlib.sha256(b''.join([*seeds, bytes([bump]), decode58(program), b'ProgramDerivedAddress'])).digest()
        if not on_curve(raw):
            return encode58(raw)
    raise ValueError('No valid PDA bump')

def parse_type(kind, data, offset, types):
    if kind == 'pubkey':
        assert offset + 32 <= len(data)
        return (encode58(data[offset:offset + 32]), offset + 32)
    if kind == 'bool':
        assert data[offset] in (0, 1)
        return (bool(data[offset]), offset + 1)
    if isinstance(kind, str) and kind[:1] in ('u', 'i') and kind[1:].isdigit():
        size = int(kind[1:]) // 8
        assert offset + size <= len(data)
        return (int.from_bytes(data[offset:offset + size], 'little', signed=kind[0] == 'i'), offset + size)
    if isinstance(kind, dict) and 'array' in kind:
        (element, count) = kind['array']
        result = []
        for _ in range(count):
            (value, offset) = parse_type(element, data, offset, types)
            result.append(value)
        return (result, offset)
    if isinstance(kind, dict) and 'defined' in kind:
        name = kind['defined']['name']
        definition = types[name]
        if definition['kind'] == 'enum':
            (index, offset) = parse_type('u8', data, offset, types)
            variant = definition['variants'][index]
            fields = []
            for field in variant.get('fields', []):
                (value, offset) = parse_type(field.get('type') if isinstance(field, dict) and 'type' in field else field, data, offset, types)
                fields.append(value)
            return ({'variant': variant['name'], 'fields': fields}, offset)
        result = {}
        for field in definition['fields']:
            (result[field['name']], offset) = parse_type(field['type'], data, offset, types)
        if name == 'UFixValue64':
            assert -38 <= result['exp'] <= 38
            return (D(result['bits']) * D(10) ** result['exp'], offset)
        return (result, offset)
    raise ValueError('Unsupported account field: ' + str(kind))

def decode_account(name, data, idl):
    entry = next((a for a in idl['accounts'] if a['name'] == name))
    assert data[:8] == bytes(entry['discriminator'])
    types = {t['name']: t['type'] for t in idl['types']}
    (value, offset) = parse_type({'defined': {'name': name}}, data, 8, types)
    assert offset <= len(data)
    return value

def metadata(inputs, name):
    return read(inputs / (name + '.metadata.json'))

def batch_accounts(inputs, prefix, count):
    """Yield (address, account-or-None, context_slot) for numbered getMultipleAccounts batches."""
    for index in range(count):
        name = prefix + '-' + str(index)
        request = metadata(inputs, name)['rpc_request']['params'][0]
        result = read(inputs / (name + '.json.gz'))['result']
        assert len(request) == len(result['value'])
        for (address, row) in zip(request, result['value']):
            yield (address, row, result['context']['slot'])

def account_lists(inputs):
    return read(inputs / 'exponent-current-account-lists.json')

def spl_mint(row):
    """Parse the base SPL mint layout (same first 82 bytes for Token and Token-2022)."""
    if row is None or row['owner'] not in (TOKEN, TOKEN_2022):
        return None
    data = account_bytes(row)
    assert len(data) >= 82
    if not data[45]:
        return None
    return {'token_program': row['owner'], 'supply_atomic': str(int.from_bytes(data[36:44], 'little')), 'decimals': data[44]}

def decoded_strategies(inputs):
    path = inputs / 'exponent-decoded-strategy-state.json'
    return read(path) if exists(path) else []

def strategy_lp_coverage(inputs):
    """Captured strategy-vault accounts whose LP mint is unknown (not decodable with the pinned SDK
    layout and absent from the strategy_vaults table and the strategies API). Their holders cannot be
    scanned; under the October 13 method such strategies would be unpriced in any case."""
    lists = account_lists(inputs)
    known = {x['address'] for x in decoded_strategies(inputs)}
    known |= {x['address'] for x in table(inputs, 'strategy_vaults') if x.get('lp_mint')}
    known |= {x['address'] for x in read(inputs / 'exponent-strategies.json.gz')}
    unknown = []
    for (address, row, _) in batch_accounts(inputs, 'exponent-current-strategy-state', lists['batches']['strategy_state']):
        if row is not None and address not in known:
            assert row['owner'] in STRATEGY_PROGRAMS
            unknown.append({'strategy': address, 'owner_program': row['owner'], 'bytes': len(account_bytes(row))})
    return unknown

def exponent_registry_candidates(inputs):
    """Receipt mints whose current holders are valued: SY wrappers, legacy LP and strategy LP."""
    out = {}

    def put(entry):
        previous = out.get(entry['mint'])
        if previous is None:
            out[entry['mint']] = entry
        else:
            assert previous['label'] == entry['label'], ('Mint in two receipt families', entry['mint'])
            if 'account' in entry and 'account' not in previous:
                previous['account'] = entry['account']
    for x in read(inputs / 'exponent-sy-tokens.json.gz'):
        put({'label': 'SY', 'mint': x['mint'], 'name': x['ticker']})
    lists = account_lists(inputs)
    for (address, row, _) in batch_accounts(inputs, 'exponent-current-legacy-markets', lists['batches']['legacy_markets']):
        if row is None or row['owner'] != CORE:
            continue
        data = account_bytes(row)
        if data[:8] != decode58(MARKET_DISCRIMINATOR):
            continue
        put({'label': 'legacy LP', 'mint': encode58(data[136:168]), 'account': address})
    for x in decoded_strategies(inputs):
        put({'label': 'strategy LP', 'mint': x['data']['mintLp'], 'account': x['address']})
    for x in cpb_table_rows(inputs, 'strategy_vaults'):
        if x.get('lp_mint'):
            put({'label': 'strategy LP', 'mint': x['lp_mint'], 'account': x['address']})
    for x in read(inputs / 'exponent-strategies.json.gz'):
        put({'label': 'strategy LP', 'mint': x['lpMint'], 'account': x['address']})
    return [out[k] for k in sorted(out)]

def cpb_table_rows(inputs, name):
    return table(inputs, name)

def build_exponent_registry(inputs):
    lists = account_lists(inputs)
    mint_rows = {address: row for (address, row, _) in batch_accounts(inputs, 'exponent-current-extra-mints', lists['batches']['extra_mints'])}
    registry = []
    for entry in exponent_registry_candidates(inputs):
        assert entry['mint'] in mint_rows, ('Receipt mint not read', entry['mint'])
        parsed = spl_mint(mint_rows[entry['mint']])
        entry = dict(entry)
        if parsed is None:
            entry.update({'live': False, 'token_program': None, 'decimals': None, 'supply_atomic': '0'})
        else:
            entry.update({'live': True, **parsed})
        registry.append(entry)
    return registry

def mint_registry(inputs):
    rows = read(inputs / 'exponent-current-extra-mint-registry.json')
    return {r['mint']: r for r in rows if r['live']}

def hylo_exchange_rows(inputs):
    return read(inputs / 'hylo-current-exchange-state.json.gz')['result']['value']

def hylo_exo_pairs(inputs):
    idl = read(inputs / 'hylo-current-idl.json')
    discriminator = bytes(next((a for a in idl['accounts'] if a['name'] == 'ExoPair'))['discriminator'])
    pairs = []
    for row in hylo_exchange_rows(inputs):
        data = account_bytes(row['account'])
        if data[:8] == discriminator:
            pairs.append((row['pubkey'], decode_account('ExoPair', data, idl)))
    return pairs

def hylo_registry_candidates(inputs):
    """Official Hylo products (October 13 list) plus any exo product found on-chain."""
    base = [dict(x) for x in read(inputs / 'hylo-official-products-2026-10-13.json')]
    for x in base:
        for key in ('live', 'token_program', 'decimals'):
            x.pop(key, None)
    known = {x.get('collateral_mint') for x in base}
    for (_, pair) in hylo_exo_pairs(inputs):
        if pair['collateral_mint'] not in known:
            base.append({'protocol': 'hylo', 'label': 'exo-' + pair['collateral_mint'], 'mint': pda(PROGRAM, [b'exo_levercoin', decode58(pair['collateral_mint'])]), 'source': 'on-chain ExoPair account (exo_levercoin PDA)', 'collateral_mint': pair['collateral_mint']})
            known.add(pair['collateral_mint'])
    for x in base:
        if x.get('collateral_mint'):
            assert pda(PROGRAM, [b'exo_levercoin', decode58(x['collateral_mint'])]) == x['mint'], x['label']
    return base

def build_hylo_registry(inputs):
    candidates = hylo_registry_candidates(inputs)
    request = metadata(inputs, 'hylo-current-mint-metadata')['rpc_request']['params'][0]
    rows = read(inputs / 'hylo-current-mint-metadata.json.gz')['result']['value']
    accounts = dict(zip(request, rows))
    pairs = {pair['collateral_mint'] for (_, pair) in hylo_exo_pairs(inputs)}
    registry = []
    for entry in candidates:
        assert entry['mint'] in accounts, ('Hylo mint not read', entry['label'])
        parsed = spl_mint(accounts[entry['mint']])
        entry = dict(entry)
        entry['mint_account_exists'] = parsed is not None
        if entry.get('collateral_mint'):
            entry['exo_pair_on_chain'] = entry['collateral_mint'] in pairs
        live = parsed is not None and entry.get('exo_pair_on_chain', True)
        entry['live'] = live
        if parsed is not None:
            entry['token_program'] = parsed['token_program']
            entry['decimals'] = parsed['decimals']
            entry['supply_atomic'] = parsed['supply_atomic']
        registry.append(entry)
    for entry in registry:
        if entry.get('collateral_mint') and entry['mint_account_exists'] != entry['exo_pair_on_chain']:
            entry['coverage_gap'] = 'exo pair and levercoin mint disagree'
    return registry

def price_request_mints(inputs):
    mints = set()
    for x in read(inputs / 'exponent-tokens.json.gz'):
        mints.add(x.get('mint'))
    for x in read(inputs / 'exponent-sy-tokens.json.gz'):
        mints.add(x['mint'])
        for key in ('quote_asset', 'underlying_asset'):
            if isinstance(x.get(key), dict):
                mints.add(x[key].get('mint'))
    for x in read(inputs / 'exponent-all-vaults.json.gz'):
        mints.add(x.get('sy_token'))
    for x in read(inputs / 'exponent-markets.json.gz'):
        mints.update([x.get('syMint'), x.get('baseTokenMint')])
    for x in read(inputs / 'exponent-all-tranching.json.gz'):
        mints.update([x.get('quoteAssetMint'), x.get('syMint'), x.get('mintBase')])
    for x in read(inputs / 'exponent-strategies.json.gz'):
        for key in ('quoteToken', 'depositToken', 'lpToken'):
            if isinstance(x.get(key), dict):
                mints.add(x[key].get('mint'))
        for asset in x.get('assets') or []:
            if isinstance(asset, dict):
                mints.add(asset.get('mint'))
    for x in decoded_strategies(inputs):
        mints.add(x['data']['underlyingMint'])
        for entry in x['data'].get('tokenEntries') or []:
            mints.add(entry.get('mint'))
    for x in read(inputs / 'hylo-current-mint-registry.json'):
        mints.update([x.get('mint'), x.get('collateral_mint')])
    mints.discard(None)
    return sorted(mints)

def exo_price_dependencies(inputs):
    registry = read(inputs / 'hylo-current-mint-registry.json')
    pairs = []
    for (address, pair) in hylo_exo_pairs(inputs):
        product = next((m for m in registry if m.get('collateral_mint') == pair['collateral_mint'] and m['live']))
        auth = pda(PROGRAM, [b'exo_vault_auth', decode58(pair['collateral_mint'])])
        vault = pda(ATA, [decode58(auth), decode58(TOKEN), decode58(pair['collateral_mint'])])
        assert pda(PROGRAM, [b'exo_levercoin', decode58(pair['collateral_mint'])]) == product['mint']
        pairs.append({'label': product['label'], 'mint': product['mint'], 'decimals': product['decimals'], 'pair': address, 'collateral_mint': pair['collateral_mint'], 'collateral_vault': vault, 'oracle': pair['oracle'], 'oracle_feed_id': pair['oracle_feed_id'], 'virtual_stablecoin_supply': pair['virtual_stablecoin']['supply']})
    return pairs

def exo_accounts(inputs):
    batch = read(inputs / 'hylo-exo-current-price-accounts.json.gz')['result']
    request = metadata(inputs, 'hylo-exo-current-price-accounts')['rpc_request']['params'][0]
    return dict(zip(request, batch['value']))

def measurement_ts(inputs):
    """The Pyth publish time in the finalized exo price batch (how the October 13 constant was set)."""
    idl = read(inputs / 'hylo-current-idl.json')
    accounts = exo_accounts(inputs)
    times = [int(decode_account('PriceUpdateV2', account_bytes(accounts[d['oracle']]), idl)['price_message']['publish_time']) for d in exo_price_dependencies(inputs)]
    assert times
    captured = max(times)
    meta = metadata(inputs, 'hylo-exo-current-price-accounts')
    retrieved = float(meta['retrieved_at_unix']) if 'retrieved_at_unix' in meta else utc_epoch(meta['captured_at'])
    assert 0 <= retrieved - captured <= 600, ('Oracle publish time is not current', captured, retrieved)
    return captured

def table(inputs, name):
    inventory = read(inputs / ('exponent-table-' + name + '-inventory.json'))
    assert inventory['terminal_pagination']
    rows = []
    for page in inventory['pages']:
        batch = read(inputs / ('exponent-table-' + name + '-page-' + str(page['page']) + '.json.gz'))
        assert len(batch) == page['records']
        rows.extend(batch)
    assert len(rows) == inventory['records']
    return rows

def coverage_gaps(inputs):
    path = inputs / 'coverage-gaps.json'
    return read(path) if exists(path) else []

def holders(inputs, prefix):
    inventory = read(inputs / (prefix + '-das-inventory.json'))
    assert inventory['terminal_pagination']
    seen = set()
    assert inventory['pages'][-1]['accounts'] == 0, 'Missing terminal empty page'
    for page in inventory['pages']:
        result = read(inputs / (prefix + '-das-page-' + str(page['page']) + '.json.gz'))['result']
        rows = result['token_accounts']
        assert len(rows) == page['accounts']
        for row in rows:
            assert row['mint'] == inventory['mint'] and int(row['amount']) > 0
            assert row['address'] not in seen
            seen.add(row['address'])
            yield row
    assert len(seen) == inventory['accounts']

def fixed(value):
    return D(value['bits']) * D(10) ** int(value['exp'])

def hylo_prices(inputs, captured_ts):
    registry = read(inputs / 'hylo-current-mint-registry.json')
    stats = read(inputs / 'hylo-stats.json.gz')
    api = {x['mint']: D(str(x['price'])) for x in read(inputs / 'exponent-current-prices.json.gz')}
    prices = {'hyUSD': fixed(stats['exchangeStats']['raw']['stablecoinNav']), 'xSOL': fixed(stats['exchangeStats']['raw']['levercoinNav']), 'eHYUSD_formerly_sHYUSD': fixed(stats['stabilityPoolStats']['raw']['lpTokenNav'])}
    for product in registry:
        if product['label'] in ('hyloSOL', 'hyloSOL_plus') and product['live']:
            prices[product['label']] = api[product['mint']]
    dependencies = exo_price_dependencies(inputs)
    accounts = exo_accounts(inputs)
    idl = read(inputs / 'hylo-current-idl.json')
    for product in dependencies:
        pair_account = accounts[product['pair']]
        assert pair_account['owner'] == PROGRAM
        pair = decode_account('ExoPair', account_bytes(pair_account), idl)
        assert pair['collateral_mint'] == product['collateral_mint']
        oracle = decode_account('PriceUpdateV2', account_bytes(accounts[product['oracle']]), idl)
        assert oracle['verification_level']['variant'] == 'Full'
        message = oracle['price_message']
        assert message['feed_id'] == product['oracle_feed_id']
        assert int(message['price']) > 0
        assert abs(int(message['publish_time']) - captured_ts) <= ORACLE_MAX_SKEW_SECONDS
        mint = account_bytes(accounts[product['mint']])
        cmint = account_bytes(accounts[product['collateral_mint']])
        vault = account_bytes(accounts[product['collateral_vault']])
        assert accounts[product['mint']]['owner'] == TOKEN
        assert accounts[product['collateral_mint']]['owner'] == TOKEN
        assert accounts[product['collateral_vault']]['owner'] == TOKEN
        assert encode58(vault[:32]) == product['collateral_mint']
        auth = pda(PROGRAM, [b'exo_vault_auth', decode58(product['collateral_mint'])])
        assert encode58(vault[32:64]) == auth
        supply = D(int.from_bytes(mint[36:44], 'little')) / D(10) ** mint[44]
        collateral = D(int.from_bytes(vault[64:72], 'little')) / D(10) ** cmint[44]
        spot = D(message['price']) * D(10) ** int(message['exponent'])
        nav = (collateral * spot - pair['virtual_stablecoin']['supply']) / supply
        assert supply > 0 and nav > 0
        prices[product['label']] = nav
    assert all((x['label'] in prices for x in registry if x['live']))
    return prices

class Census:

    def __init__(self):
        self.values = defaultdict(lambda : defaultdict(D))
        self.components = defaultdict(list)
        self.unpriced = []

    def add(self, owner, product, value, amount=None, unit_price=None, source=None):
        value = D(value)
        assert value >= 0, (owner, product, value)
        if value:
            self.values[owner][product] += value
            self.components[owner].append({'product': product, 'source': source, 'amount_atomic': None if amount is None else str(amount), 'usd_per_atomic_unit': None if unit_price is None else str(unit_price), 'value_usd': str(value)})

    def missing(self, owner, product, units, source=None):
        if D(units):
            self.unpriced.append({'wallet': owner, 'product': product, 'atomic_units': str(units)})

    def records(self):
        for owner in sorted(self.values):
            products = self.values[owner]
            total = sum(products.values(), D(0))
            yield {'wallet': owner, 'authority_type': 'direct_wallet' if on_curve(decode58(owner)) else 'off_curve_authority', 'current_value_usd': str(total), 'meets_usd100': total >= 100, 'products_usd': {key: str(products[key]) for key in sorted(products)}}

def hylo_census(inputs, captured_ts):
    result = Census()
    prices = hylo_prices(inputs, captured_ts)
    gaps = {g['name'] for g in coverage_gaps(inputs)}
    for product in read(inputs / 'hylo-current-mint-registry.json'):
        if not product['live']:
            continue
        prefix = 'hylo-' + product['label']
        if not exists(inputs / (prefix + '-das-inventory.json')):
            assert any((name.startswith(prefix + '-das-page-') for name in gaps)), ('Missing holder inventory', prefix)
            continue
        unit = prices[product['label']] / D(10) ** product['decimals']
        for row in holders(inputs, prefix):
            result.add(row['owner'], product['label'], D(row['amount']) / D(10) ** product['decimals'] * prices[product['label']], amount=row['amount'], unit_price=unit, source=prefix + '-das')
    return (result, prices)

def raw_core_states(inputs):
    result = {}
    lists = account_lists(inputs)
    for (address, row, _) in batch_accounts(inputs, 'exponent-current-core-vaults', lists['batches']['core_vaults']):
        if row is None:
            continue
        assert row['owner'] == CORE
        data = account_bytes(row)
        assert data[:8] == decode58(VAULT_DISCRIMINATOR)
        result[address] = {'sy': encode58(data[40:72]), 'last_rate': D(int.from_bytes(data[337:369], 'little')) / 10 ** 12, 'high_rate': D(int.from_bytes(data[369:401], 'little')) / 10 ** 12, 'final_rate': D(int.from_bytes(data[401:433], 'little')) / 10 ** 12, 'maturity': int.from_bytes(data[264:268], 'little') + int.from_bytes(data[268:272], 'little')}
    return result

def strategy_underlying_decimals(inputs):
    name = 'exponent-current-strategy-underlying-mints'
    if not exists(inputs / (name + '.json.gz')):
        return {}
    request = metadata(inputs, name)['rpc_request']['params'][0]
    rows = read(inputs / (name + '.json.gz'))['result']['value']
    out = {}
    for (address, row) in zip(request, rows):
        parsed = spl_mint(row)
        if parsed is not None:
            out[address] = parsed['decimals']
    return out

def exponent_census(inputs, captured_ts, notes):
    result = Census()
    prices = {x['mint']: D(str(x['price'])) for x in read(inputs / 'exponent-current-prices.json.gz')}
    sy = {x['mint']: x for x in read(inputs / 'exponent-sy-tokens.json.gz')}
    vaults = {x['address']: dict(x) for x in read(inputs / 'exponent-all-vaults.json.gz') if all((x.get(k) is not None for k in ('pt_price', 'yt_price', 'sy_exchange_rate')))}
    for x in read(inputs / 'exponent-markets.json.gz'):
        vaults[x['vaultAddress']] = {'address': x['vaultAddress'], 'sy_token': x['syMint'], 'pt_price': x['ptPriceInAsset'], 'yt_price': x['ytPriceInAsset'], 'sy_exchange_rate': x['syExchangeRate']}
    sy_prices = {}
    for x in vaults.values():
        sy_prices[x['sy_token']] = D(str(x['sy_exchange_rate'])) * prices[sy[x['sy_token']]['quote_asset']['mint']]
    for x in read(inputs / 'exponent-all-tranching.json.gz'):
        sy_prices[x['syMint']] = D(str(x['currentSyExchangeRate'])) * prices[x['quoteAssetMint']]
    core = raw_core_states(inputs)
    for x in table(inputs, 'vaults'):
        if x['address'] in vaults:
            continue
        state = core.get(x['address'])
        assert state is not None
        metadata_ = sy[x['sy_token']]
        current_sy_usd = sy_prices.get(x['sy_token'], prices.get(x['sy_token']))
        if state['maturity'] < captured_ts and current_sy_usd is not None and (state['final_rate'] > 0):
            quote = prices[metadata_['quote_asset']['mint']]
            rate = current_sy_usd / quote
            vaults[x['address']] = {**x, 'sy_exchange_rate': rate, 'pt_price': min(D(1), rate / state['final_rate']), 'yt_price': D(0)}

    def rates(vault):
        x = vaults.get(vault)
        if not x:
            return None
        metadata_ = sy[x['sy_token']]
        scale = prices[metadata_['quote_asset']['mint']] / D(10) ** metadata_['decimals']
        return (D(str(x['pt_price'])) * scale, D(str(x['yt_price'])) * scale, D(str(x['sy_exchange_rate'])) * scale)
    for side in ('pt', 'yt'):
        seen = set()
        for x in table(inputs, 'user_' + side + '_balances'):
            key = (x['user_address'], x['vault_address'])
            assert key not in seen
            seen.add(key)
            amount = sum((D(x.get(k, 0)) for k in ('core_balance', 'orderbook_open', 'orderbook_filled')))
            rr = rates(x['vault_address'])
            if rr is None:
                result.missing(x['user_address'], side + ':' + x['vault_address'], amount)
            else:
                unit = rr[0 if side == 'pt' else 1]
                result.add(x['user_address'], side + ':' + x['vault_address'], amount * unit, amount=amount, unit_price=unit, source='exponent-table-user_' + side + '_balances')
    for x in table(inputs, 'user_sy_balances'):
        amount = D(x['orderbook_open']) + D(x['orderbook_filled'])
        rr = rates(x['vault_address'])
        if rr is None:
            result.missing(x['user_address'], 'orderbook_sy:' + x['vault_address'], amount)
        else:
            result.add(x['user_address'], 'orderbook_sy:' + x['vault_address'], amount * rr[2], amount=amount, unit_price=rr[2], source='exponent-table-user_sy_balances')
    market_vault = {x['address']: x['vault_address'] for x in table(inputs, 'clmm_markets')}
    seen = set()
    for x in table(inputs, 'user_clmm_lp_balances'):
        assert x['position_address'] not in seen and (not x['needs_recalc'])
        seen.add(x['position_address'])
        rr = rates(market_vault[x['market_address']])
        if rr is None:
            result.missing(x['user_address'], 'clmm:' + x['position_address'] + ':' + market_vault[x['market_address']], D(x['pt_balance']) + D(x['sy_balance']))
            continue
        value = D(x['pt_balance']) * rr[0] + D(x['sy_balance']) * rr[2]
        result.add(x['user_address'], 'clmm:' + x['position_address'], value, amount='pt=' + str(x['pt_balance']) + ';sy=' + str(x['sy_balance']), unit_price='pt=' + str(rr[0]) + ';sy=' + str(rr[2]), source='exponent-table-user_clmm_lp_balances')
    tranches = {x['address']: x for x in read(inputs / 'exponent-all-tranching.json.gz')}
    for x in table(inputs, 'user_tranching_lp_balances'):
        if not D(x['lp_balance']):
            continue
        t = tranches.get(x['market_address'])
        if t is None:
            result.missing(x['user_address'], 'tranche:' + x['market_address'], x['lp_balance'])
            continue
        field = 'sr' if x['tranche_side'] == 'senior' else 'jr'
        assert x['mint_lp'] == t['mintLpSenior' if field == 'sr' else 'mintLpJunior']
        unit = D(str(t[field + 'SyncedLpPriceNetAsset'])) * prices[t['quoteAssetMint']] / D(10) ** t['decimals']
        value = D(x['lp_balance']) / D(10) ** t['decimals'] * D(str(t[field + 'SyncedLpPriceNetAsset'])) * prices[t['quoteAssetMint']]
        result.add(x['user_address'], 'tranche:' + x['mint_lp'], value, amount=x['lp_balance'], unit_price=unit, source='exponent-table-user_tranching_lp_balances')
    mints = mint_registry(inputs)
    (lp_prices, market_lp) = ({}, {})
    lists = account_lists(inputs)
    for (market, row, _) in batch_accounts(inputs, 'exponent-current-legacy-markets', lists['batches']['legacy_markets']):
        if row is None:
            continue
        assert row['owner'] == CORE
        data = account_bytes(row)
        assert data[:8] == decode58(MARKET_DISCRIMINATOR)
        (vault, lp) = (encode58(data[104:136]), encode58(data[136:168]))
        rr = rates(vault)
        if rr is None or lp not in mints:
            continue
        supply = D(mints[lp]['supply_atomic'])
        if supply == 0:
            continue
        nav = D(int.from_bytes(data[372:380], 'little')) * rr[0] + D(int.from_bytes(data[380:388], 'little')) * rr[2]
        lp_prices[lp] = nav / supply
        market_lp[market] = lp
    seen = set()
    for row in read(inputs / 'exponent-current-legacy-lp-positions.json.gz')['result']['value']:
        assert row['pubkey'] not in seen
        seen.add(row['pubkey'])
        assert row['account']['owner'] == CORE
        data = account_bytes(row['account'])
        assert len(data) == 72
        (owner, market) = (encode58(data[:32]), encode58(data[32:64]))
        amount = int.from_bytes(data[64:72], 'little')
        lp = market_lp.get(market)
        if lp is None:
            result.missing(owner, 'legacy_lp:' + market, amount)
        else:
            result.add(owner, 'legacy_lp:' + lp, D(amount) * lp_prices[lp], amount=amount, unit_price=lp_prices[lp], source='exponent-current-legacy-lp-positions')
    for x in read(inputs / 'exponent-strategies.json.gz'):
        lp_prices[x['lpMint']] = D(str(x['lpPrice'])) * prices[x['quoteToken']['mint']] / D(10) ** x['lpDecimals']
    onchain_decimals = strategy_underlying_decimals(inputs)
    for x in decoded_strategies(inputs):
        state = x['data']
        assert x['owner'] in STRATEGY_PROGRAMS
        lp = state['mintLp']
        if lp in lp_prices or lp not in mints:
            continue
        f = state['financials']
        supply = int(mints[lp]['supply_atomic']) + int(f['pendingManagementFeeLp'])
        (last, fee) = (int(f['lastManagementFeeAccruedAt']), int(state['reservesConfig']['managementFeeBps']))
        if last and captured_ts > last:
            supply += supply * min(fee, 1000000) * (captured_ts - last) // (1000000 * 31536000)
        if supply:
            decimals = 9 if state['underlyingMint'] == WSOL else 6
            actual = onchain_decimals.get(state['underlyingMint'])
            if actual is not None and actual != decimals:
                notes.append({'strategy': x['address'], 'underlying_mint': state['underlyingMint'], 'heuristic_decimals': decimals, 'on_chain_decimals': actual})
                decimals = actual
            aum = D(f['aumInBase']) + D(f['aumInBaseInPositions'])
            lp_prices[lp] = aum / D(10) ** decimals * prices[state['underlyingMint']] / supply
    gaps = {g['name'] for g in coverage_gaps(inputs)}
    for (mint, x) in mints.items():
        prefix = 'exponent-extra-' + mint
        if not exists(inputs / (prefix + '-das-inventory.json')):
            if int(x['supply_atomic']) == 0:
                continue
            assert any((name.startswith(prefix + '-das-page-') for name in gaps)), ('Missing holder inventory', prefix)
            notes.append({'coverage_gap': prefix})
            continue
        if x['label'] == 'SY':
            price = sy_prices.get(mint, prices.get(mint))
            unit_price = price / D(10) ** x['decimals'] if price is not None else None
        else:
            unit_price = lp_prices.get(mint)
        for row in holders(inputs, prefix):
            if unit_price is None:
                result.missing(row['owner'], x['label'] + ':' + mint, row['amount'])
            else:
                result.add(row['owner'], x['label'] + ':' + mint, D(row['amount']) * unit_price, amount=row['amount'], unit_price=unit_price, source=prefix + '-das')
    return (result, {'sy_usd': sy_prices, 'lp_usd_per_atomic_unit': lp_prices})
