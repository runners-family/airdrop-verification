from .core import utc_epoch
"""Historical pure valuation helpers, extracted without live collection or prior-cohort comparison.
Historical deterministic method adapted for public replay.
"""
from collections import Counter, defaultdict
from datetime import datetime, timezone
from fractions import Fraction
import json
from pathlib import Path
from urllib.parse import quote
from .holder_common import CEX_URL, DEX_URL, HYPE, SYSTEM_WALLETS_URL, THRESHOLD, TOKEN, TOKEN22, ZEC, Bundle, account_evidence, canonical, encoded, exclusion_registry, mint_info, number, on_curve, owner_amount_holders, owner_status, plan_owner_checks, read_owner_checks, require, rpc_job, token_holder_job, token_holders, usd_text, wallet_list_bytes
REGISTRY_URL = 'registry:xstocks'
PRICE_URL = 'prices:xstocks/{}/price-data'
YAHOO_URL = 'prices:yahoo/{}?interval=1d&range=5d'
GROUPS = ('xstocks', 'zec', 'hype')

def registry_job(page):
    return {'name': 'stock-registry-page-' + str(page), 'source_id': REGISTRY_URL + ('?page=' + str(page) if page else '')}

def mint_batch_job(index, mints, slot):
    return rpc_job('stock-mints-' + str(index), 'getMultipleAccounts', [mints, {'encoding': 'base64', 'commitment': 'finalized', 'minContextSlot': slot}])

def holder_mints_job(slot):
    return rpc_job('holder-mints', 'getMultipleAccounts', [[ZEC[0], HYPE[0]], {'encoding': 'base64', 'commitment': 'finalized', 'minContextSlot': slot}])

def sliced_holder_job(name, mint, slot):
    return rpc_job(name, 'getProgramAccounts', ['TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA', {'encoding': 'base64', 'commitment': 'finalized', 'minContextSlot': slot, 'withContext': True, 'filters': [{'dataSize': 165}, {'memcmp': {'offset': 0, 'bytes': mint}}], 'dataSlice': {'offset': 32, 'length': 40}}])

def price_job(stock):
    return {'name': 'xstocks-price-' + stock['mint'], 'source_id': PRICE_URL.format(quote(stock['symbol'], safe='.'))}

def hk_code(asset):
    return str(asset['underlying']['symbol']).lstrip('0').zfill(4)

def yahoo_job(symbol):
    return {'name': 'underlying-' + symbol.replace('.', '-').replace('=', '_'), 'source_id': YAHOO_URL.format(symbol)}

def slot_job(name):
    return rpc_job(name, 'getSlot', [{'commitment': 'finalized'}])

class Context:

    def __init__(self, workspace, bundle_dir):
        self.bundle = Bundle(workspace)
        self.dir = Path(bundle_dir)
        self.scope = self.bundle.json(self.dir / 'scope.json')
        snapshot = self.bundle.json(self.scope['snapshot'])
        require(snapshot['reference_slot'] == self.scope['reference_slot'] and snapshot['reference_block_time'] == self.scope['reference_block_time'], 'Scope differs from snapshot')
        self.slot = self.scope['reference_slot']
        self.time = self.scope['reference_block_time']
        self.times = []
        self.context_slots = []

    def capture(self, name, job=None):
        (data, record) = self.bundle.capture(self.dir, name, job)
        if record is not None and record['ok']:
            stamp = utc_epoch(record['retrieved_at'])
            require(stamp >= self.time, 'Capture predates the reference block time: ' + name)
            self.times.append(record['retrieved_at'])
            if record.get('context_slot') is not None:
                require(record['context_slot'] >= self.slot, 'Context slot below the reference slot: ' + name)
                self.context_slots.append(record['context_slot'])
        return (data, record)

def registry(ctx):
    coverage = ctx.bundle.json(ctx.dir / 'stock-registry-coverage.json')
    require(coverage['complete'] and coverage['pages'], 'Issuer registry pagination is incomplete')
    (assets, stocks, seen) = ([], [], set())
    for (page, name) in enumerate(coverage['pages']):
        require(name == registry_job(page)['name'], 'Missing or reordered registry page')
        (data, record) = ctx.capture(name, registry_job(page))
        require(data is not None, 'Failed registry page ' + name)
        require(data['page'] == {'currentPage': page, 'hasNextPage': page < len(coverage['pages']) - 1}, 'Incomplete issuer registry pagination')
        for asset in data['nodes']:
            assets.append(asset)
            for deployment in asset['deployments']:
                if deployment['network'] == 'Solana':
                    require(deployment['address'] not in seen, 'Duplicate registry mint')
                    seen.add(deployment['address'])
                    stocks.append({'mint': deployment['address'], 'symbol': asset['symbol'], 'name': asset['name'], 'asset_id': asset['id']})
    by_id = {a['id']: a for a in assets}
    require(len(by_id) == len(assets), 'Duplicate registry asset id')
    return (stocks, by_id, len(coverage['pages']))

def stock_mints(ctx, stocks):
    (infos, gaps, jobs) = ({}, [], [])
    for index in range((len(stocks) + 99) // 100):
        batch = [s['mint'] for s in stocks[index * 100:(index + 1) * 100]]
        job = mint_batch_job(index, batch, ctx.slot)
        jobs.append(job)
        (data, record) = ctx.capture(job['name'], job)
        if data is None:
            gaps.extend(batch)
            continue
        stamp = utc_epoch(record['retrieved_at'])
        require(len(data['result']['value']) == len(batch), 'Missing mint response entries')
        for (mint, account) in zip(batch, data['result']['value']):
            if account is None or account['owner'] not in {TOKEN, TOKEN22}:
                gaps.append(mint)
                continue
            info = mint_info(account, data['result']['context']['slot'], stamp)
            info['retrieved_at'] = record['retrieved_at']
            infos[mint] = info
    return (infos, gaps, jobs)

def holder_jobs(stocks, infos, slot):
    return [token_holder_job('stock-holders-' + s['mint'], s['mint'], infos[s['mint']]['program'], slot) for s in stocks if s['mint'] in infos]

def hk_assets(by_id):
    return sorted({hk_code(a) for a in by_id.values() if (a.get('underlying') or {}).get('currency') == 'HKD'})

def stock_prices(ctx, stocks, by_id, infos):
    """Issuer USD quote; HK listings with no issuer quote use Yahoo underlying x HKD/USD (as in September)."""
    (fx, fx_record, fx_value) = (None, None, None)
    codes = hk_assets(by_id)
    if codes:
        (fx, fx_record) = ctx.capture(yahoo_job('HKDUSD=X')['name'], yahoo_job('HKDUSD=X'))
        if fx is not None:
            meta = fx['chart']['result'][0]['meta']
            require(meta['symbol'] == 'HKDUSD=X' and meta['currency'] == 'USD', 'Unexpected FX quote')
            fx_value = number(meta['regularMarketPrice'])
            require(fx_value > 0, 'Non-positive FX quote')
            fx = meta
    underlying = {}
    for code in codes:
        job = yahoo_job(code + '.HK')
        (data, record) = ctx.capture(job['name'], job)
        if data is None:
            continue
        meta = data['chart']['result'][0]['meta']
        require(meta['symbol'] == code + '.HK' and meta['currency'] == 'HKD', 'Unexpected underlying quote')
        local = number(meta['regularMarketPrice'])
        require(local > 0, 'Non-positive underlying quote')
        underlying[code] = (local, meta, record)
    (table, unpriced) = ({}, {})
    for stock in stocks:
        (mint, asset) = (stock['mint'], by_id[stock['asset_id']])
        entry = {'symbol': stock['symbol'], 'name': stock['name']}
        info = infos.get(mint)
        if info:
            entry.update({'program': info['program'], 'decimals': info['decimals'], 'supply_raw': str(info['supply_raw']), 'scaled_ui_multiplier': repr(float(info['multiplier'])), 'multiplier_detail': info['multiplier_detail'], 'mint_slot': info['slot']})
        job = price_job(stock)
        (data, record) = ctx.capture(job['name'], job)
        quote_value = None if data is None else data.get('quote')
        entry['issuer_quote'] = None if quote_value is None else str(quote_value)
        entry['issuer_quote_capture'] = job['name']
        entry['issuer_quote_retrieved_at'] = None if record is None else record['retrieved_at']
        currency = (asset.get('trading') or {}).get('currency') or (asset.get('underlying') or {}).get('currency')
        entry['trading_currency'] = currency
        hk = (asset.get('underlying') or {}).get('currency') == 'HKD'
        positive = quote_value is not None and number(quote_value) > 0
        (price, reason) = (None, None)
        if data is None:
            reason = 'issuer_quote_capture_failed'
        if hk and (not positive):
            code = hk_code(asset)
            if code in underlying and fx_value is not None:
                (local, meta, urec) = underlying[code]
                price = local * fx_value
                entry['price_source'] = 'underlying ' + meta['symbol'] + ' x HKDUSD=X'
                entry['underlying'] = {'listing': meta['symbol'], 'price_hkd': str(meta['regularMarketPrice']), 'usd_per_hkd': str(fx['regularMarketPrice']), 'quote_timestamp': meta['regularMarketTime'], 'fx_timestamp': fx['regularMarketTime'], 'retrieved_at': urec['retrieved_at'], 'fx_retrieved_at': fx_record['retrieved_at']}
            else:
                reason = 'underlying_quote_missing'
        elif positive and currency == 'USD':
            price = number(quote_value)
            entry['price_source'] = 'issuer_quote'
        elif reason is None:
            reason = 'no_positive_issuer_quote' if not positive else 'non_usd_trading_currency'
        if price is not None and info:
            entry['price_usd'] = usd_text(price, 10)
            entry['price_usd_fraction'] = encoded(price)
            table[mint] = (price * info['multiplier'] / 10 ** info['decimals'], price, entry)
        else:
            entry['unpriced_reason'] = reason or 'mint_account_missing'
            unpriced[mint] = entry
    return (table, unpriced)

def market_price(ctx, mint):
    (pairs, record) = ctx.capture('holder-market-prices', {'name': 'holder-market-prices', 'source_id': DEX_URL})
    require(pairs is not None, 'Missing DexScreener capture')
    rows = [p for p in pairs if p['chainId'] == 'solana' and p['baseToken']['address'] == mint and (p.get('priceUsd') is not None)]
    require(rows, 'Missing holder price for ' + mint)
    best = max(rows, key=lambda p: (number(p.get('liquidity', {}).get('usd', 0)), p['pairAddress']))
    price = number(best['priceUsd'])
    require(price > 0, 'Non-positive holder price')
    return (price, {'price_usd': str(best['priceUsd']), 'pair': best['pairAddress'], 'dex': best.get('dexId'), 'quote_token': best.get('quoteToken', {}).get('symbol'), 'liquidity_usd': str(best.get('liquidity', {}).get('usd')), 'retrieved_at': record['retrieved_at'], 'pairs_considered': len(rows), 'source': DEX_URL})

def values(ctx):
    (stocks, by_id, registry_pages) = registry(ctx)
    (infos, mint_gaps, _) = stock_mints(ctx, stocks)
    (table, unpriced) = stock_prices(ctx, stocks, by_id, infos)
    per_owner = defaultdict(dict)
    (accounts_scanned, holder_slots, scan_gaps) = (0, [], [])
    (reconciled, supply_differences) = (0, [])
    for job in holder_jobs(stocks, infos, ctx.slot):
        (data, record) = ctx.capture(job['name'], job)
        if data is None:
            scan_gaps.append({'capture': job['name'], 'status': 'missing' if record is None else 'failed'})
            continue
        (mint, owners, _, slot, count) = token_holders(data, job)
        holder_slots.append(slot)
        accounts_scanned += count
        summed = sum(owners.values())
        if summed == infos[mint]['supply_raw']:
            reconciled += 1
        else:
            supply_differences.append({'mint': mint, 'mint_supply_raw': str(infos[mint]['supply_raw']), 'summed_balances_raw': str(summed), 'mint_slot': infos[mint]['slot'], 'holder_slot': slot})
        for (owner, amount) in owners.items():
            per_owner[owner][mint] = per_owner[owner].get(mint, 0) + amount
    (holder_mints, _) = ctx.capture('holder-mints', holder_mints_job(ctx.slot))
    require(holder_mints is not None, 'Missing ZEC/HYPE mint accounts')
    simple = {}
    for ((group, (mint, decimals)), account) in zip((('zec', ZEC), ('hype', HYPE)), holder_mints['result']['value']):
        info = mint_info(account, holder_mints['result']['context']['slot'], 0)
        require(info['program'] == TOKEN and info['decimals'] == decimals, group + ' mint differs from the rule')
        job = sliced_holder_job(group + '-holders', mint, ctx.slot)
        (data, record) = ctx.capture(job['name'], job)
        require(data is not None, 'Missing ' + group + ' holder scan')
        (owners, accounts, slot, count) = owner_amount_holders(data, job, mint)
        (price, evidence) = market_price(ctx, mint)
        simple[group] = {'mint': mint, 'decimals': decimals, 'price': price, 'evidence': evidence, 'owners': owners, 'accounts': accounts, 'slot': slot, 'token_accounts_scanned': count, 'supply_raw': info['supply_raw'], 'mint_slot': info['slot'], 'summed_balances_raw': sum(owners.values())}
    usd = defaultdict(dict)
    unpriced_by_owner = defaultdict(list)
    for (owner, holdings) in per_owner.items():
        total = Fraction(0)
        for (mint, amount) in holdings.items():
            if mint in table:
                total += amount * table[mint][0]
            else:
                unpriced_by_owner[owner].append(mint)
        usd[owner]['xstocks'] = total
    for (group, row) in simple.items():
        for (owner, amount) in row['owners'].items():
            usd[owner][group] = Fraction(amount, 10 ** row['decimals']) * row['price']
    return {'stocks': stocks, 'by_id': by_id, 'registry_pages': registry_pages, 'infos': infos, 'mint_gaps': mint_gaps, 'table': table, 'unpriced': unpriced, 'per_owner': per_owner, 'accounts_scanned': accounts_scanned, 'holder_slots': holder_slots, 'scan_gaps': scan_gaps, 'simple': simple, 'usd': usd, 'unpriced_by_owner': unpriced_by_owner, 'supply_reconciled': reconciled, 'supply_differences': supply_differences}

def candidates(state, excluded):
    """Owners needing an RPC account check: >= USD100 in a group or holding unpriced xStocks."""
    wanted = set()
    for (owner, amounts) in state['usd'].items():
        if (owner in state['unpriced_by_owner'] or any((v >= THRESHOLD for v in amounts.values()))) and owner not in excluded and on_curve(owner):
            wanted.add(owner)
    return wanted

def owner_jobs(ctx):
    raw = ctx.bundle.json(ctx.dir / 'jobs' / 'owner-jobs.json')
    return raw

