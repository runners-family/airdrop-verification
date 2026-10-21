"""Historical P0/INF derivation; reviewed historical method"""
import base64,gzip,json
from decimal import Decimal as D
from pathlib import Path
from .defi_codec import IDL
from .defi_pricing import price_bank,raw as acct_raw
from .core import encode58 as b58encode,decode58,on_curve as curve
INF_MINT="5oVNBeEEQvYi1cX3ir8Dx5n1P7pdxydbGF2X4TxVusJm"
INF_POOL="AYhux5gJzCoeoc1PoJ1VxwPDe22RwcvpHviLDD1oCGvW"
SOL="So11111111111111111111111111111111111111112"
ROOT=capture=evidence=None
def on_curve(wallet):return curve(decode58(wallet))
def dumps(r):
    return json.dumps(r, sort_keys=True, default=str) + '\n'

def save(out, name, rows, gz=False):
    data = ''.join((dumps(r) for r in rows)).encode()
    if gz:
        (out / (name + '.jsonl.gz')).write_bytes(gzip.compress(data, compresslevel=6, mtime=0))
    else:
        (out / (name + '.jsonl')).write_bytes(data)

def record(name):
    return evidence.capture(name)[1]

def main(out):
    out.mkdir(parents=True, exist_ok=True)
    p = IDL('sources/p0-marginfi_0-1-11-json.source')
    bank_rows = p.accounts('p0-banks', 'Bank')
    for b in bank_rows:
        assert b['decoded_end'] <= b['data_length'], ('bank layout overrun', b['address'])
    banks = {b['address']: b for b in bank_rows}
    (acc, keys) = ({}, [])
    names = sorted([d.name for d in (ROOT / 'captures').iterdir() if d.name.startswith('oracle-mints-')], key=lambda n: int(n.rsplit('-', 1)[1]))
    for name in names:
        batch = record(name)['job']['rpc']['params'][0]
        value = capture(name)['result']['value']
        assert len(batch) == len(value)
        acc.update(zip(batch, value))
        keys += batch
    (out / 'oracle-mint-keys.json').write_text(json.dumps(keys) + '\n')
    clock = acct_raw(capture('valuation-clock')['result']['value'])
    clock_ts = int.from_bytes(clock[32:40], 'little', signed=True)
    prices = []
    for address in sorted(banks):
        b = banks[address]
        (pc, mult, ts, source, rate_source, error) = price_bank(b, acc)
        b['screen_price'] = pc * mult
        b['screen_price_source'] = source
        b['screen_price_timestamp'] = ts
        prices.append({'bank': address, 'mint': b['mint'], 'decimals': b['mint_decimals'], 'oracle_setup': b['config']['oracle_setup'], 'asset_tag': b['config']['asset_tag'], 'price_usd': pc * mult, 'base_price_usd': pc, 'integration_multiplier': mult, 'price_source': source, 'price_timestamp': ts, 'price_age_seconds_at_clock': clock_ts - ts if ts else None, 'integration_multiplier_source': rate_source, 'pricing_error': error, 'asset_share_value': b['asset_share_value'], 'liability_share_value': b['liability_share_value'], 'operational_state': b['config']['operational_state']})
    save(out, 'p0-bank-prices', prices)
    inv = capture('p0-account-inventory')
    owners = {}
    for r in inv['result']['value']:
        rawd = base64.b64decode(r['account']['data'][0])
        assert len(rawd) == 72
        owners[r['pubkey']] = b58encode(rawd[40:72])
    (wallets, positions, unknown_accounts, slots) = ({}, [], set(), [])
    unpriced_positions = []
    for ix in range(16):
        r = capture('p0-active-balance-' + str(ix))
        slots.append(r['result']['context']['slot'])
        for row in r['result']['value']:
            data = base64.b64decode(row['account']['data'][0])
            (bal, end) = p.decode('Balance', data, 0)
            assert end == 104 and bal['active'] == 1
            (assets, debt) = (bal['asset_shares'], bal['liability_shares'])
            if assets <= 0 and debt <= 0:
                continue
            assert assets >= 0 and debt >= 0
            bank = banks.get(bal['bank_pk'])
            owner = owners.get(row['pubkey'])
            if owner is None:
                unknown_accounts.add(row['pubkey'])
                continue
            w = wallets.setdefault(owner, {'wallet': owner, 'deposit_usd': D(0), 'borrow_usd': D(0), 'accounts': set(), 'unpriced_banks': set(), 'bank_cache_prices': set()})
            w['accounts'].add(row['pubkey'])
            if bank is None or bank['screen_price'] <= 0:
                w['unpriced_banks'].add(bal['bank_pk'])
                unpriced_positions.append({'wallet': owner, 'account': row['pubkey'], 'slot_index': ix, 'bank': bal['bank_pk'], 'asset_shares': assets, 'liability_shares': debt})
                continue
            scale = D(10) ** bank['mint_decimals']
            aq = assets * bank['asset_share_value'] / scale
            lq = debt * bank['liability_share_value'] / scale
            px = bank['screen_price']
            (av, lv) = (aq * px, lq * px)
            w['deposit_usd'] += av
            w['borrow_usd'] += lv
            if bank['screen_price_source'] == 'bank_cache':
                w['bank_cache_prices'].add(bank['address'])
            positions.append({'wallet': owner, 'account': row['pubkey'], 'slot_index': ix, 'bank': bank['address'], 'mint': bank['mint'], 'deposit_quantity': aq, 'borrow_quantity': lq, 'deposit_usd': av, 'borrow_usd': lv, 'price_usd': px, 'price_source': bank['screen_price_source'], 'price_timestamp': bank['screen_price_timestamp']})
    positions.sort(key=lambda x: (x['wallet'], x['account'], x['slot_index']))
    save(out, 'p0-valued-balances', positions, gz=True)
    save(out, 'p0-unpriced-balances', sorted(unpriced_positions, key=lambda x: (x['wallet'], x['account'], x['slot_index'])))
    rows = []
    for w in sorted(wallets.values(), key=lambda x: x['wallet']):
        for k in ['accounts', 'unpriced_banks', 'bank_cache_prices']:
            w[k] = sorted(w[k])
        w['meets_100_100'] = w['deposit_usd'] >= 100 and w['borrow_usd'] >= 100
        w['on_curve'] = on_curve(w['wallet'])
        rows.append(w)
    save(out, 'p0-wallet-values', rows, gz=True)
    p0_keys = [w['wallet'] for w in rows if w['meets_100_100'] and w['on_curve']]
    (out / 'p0-owner-check-keys.json').write_text(json.dumps(p0_keys, indent=2) + '\n')
    unpriced_banks_used = sorted(set((x['bank'] for x in unpriced_positions)))
    summary = {'banks': len(banks), 'wallets_with_positive_position': len(rows), 'meets_100_100_before_owner_checks': sum((w['meets_100_100'] for w in rows)), 'on_curve_100_100': len(p0_keys), 'unknown_account_authorities': sorted(unknown_accounts), 'inventory_accounts': len(owners), 'inventory_slot': inv['result']['context']['slot'], 'balance_slot_range': [min(slots), max(slots)], 'unpriced_bank_wallets': sum((bool(w['unpriced_banks']) for w in rows)), 'unpriced_banks_with_positions': unpriced_banks_used, 'unpriced_wallets_that_could_change_membership': sorted((w['wallet'] for w in rows if w['unpriced_banks'] and (not w['meets_100_100']))), 'valued_balance_count': len(positions), 'clock_unix_timestamp': clock_ts, 'banks_cache_priced_with_positions': sorted(set((x['bank'] for x in positions if x['price_source'] == 'bank_cache'))), 'oldest_used_price_age_seconds': max([b['price_age_seconds_at_clock'] for b in prices if b['bank'] in set((x['bank'] for x in positions)) and b['price_age_seconds_at_clock'] is not None] or [None])}
    (out / 'p0-preliminary-summary.json').write_text(json.dumps(summary, indent=2, default=str) + '\n')
    print('P0', json.dumps({k: v for (k, v) in summary.items() if k != 'unknown_account_authorities'}, default=str), flush=True)
    infraw = acct_raw(acc[INF_MINT])
    assert acc[INF_MINT]['owner'] == 'TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA' and len(infraw) == 82
    decs = infraw[44]
    supply = int.from_bytes(infraw[36:44], 'little')
    pool = acct_raw(acc[INF_POOL])
    total_sol = int.from_bytes(pool[:8], 'little')
    assert b58encode(pool[144:176]) == INF_MINT
    sol_banks = sorted([b for b in banks.values() if b['mint'] == SOL and b['config']['asset_tag'] == 1 and (b['screen_price_source'] == 'onchain_pyth')], key=lambda b: (-b['screen_price_timestamp'], b['address']))
    solbank = sol_banks[0]
    solprice = solbank['screen_price']
    infprice = D(total_sol) / D(10 ** 9) / (D(supply) / D(10 ** decs)) * solprice
    inf = capture('inf-token-accounts-small')
    agg = {}
    for row in inf['result']['value']:
        rawd = base64.b64decode(row['account']['data'][0])
        assert len(rawd) == 40
        owner = b58encode(rawd[:32])
        amount = int.from_bytes(rawd[32:40], 'little')
        if amount <= 0:
            continue
        w = agg.setdefault(owner, {'wallet': owner, 'amount_raw': 0, 'token_accounts': []})
        w['amount_raw'] += amount
        w['token_accounts'].append(row['pubkey'])
    ir = []
    for w in sorted(agg.values(), key=lambda x: x['wallet']):
        w['token_accounts'].sort()
        w['amount_inf'] = D(w['amount_raw']) / D(10 ** decs)
        w['value_usd'] = w['amount_inf'] * infprice
        w['meets_100'] = w['value_usd'] >= 100
        w['on_curve'] = on_curve(w['wallet'])
        ir.append(w)
    save(out, 'inf-wallet-values', ir, gz=True)
    inf_keys = [w['wallet'] for w in ir if w['meets_100'] and w['on_curve']]
    (out / 'inf-owner-check-keys.json').write_text(json.dumps(inf_keys, indent=2) + '\n')
    isum = {'mint': INF_MINT, 'decimals': decs, 'token_account_count': len(inf['result']['value']), 'positive_owners': len(ir), 'meets_100_before_exclusions': sum((w['meets_100'] for w in ir)), 'on_curve_100': len(inf_keys), 'price_usd': str(infprice), 'sol_price_usd': str(solprice), 'sol_price_bank': solbank['address'], 'sol_price_timestamp': solbank['screen_price_timestamp'], 'sol_price_banks_considered': [b['address'] for b in sol_banks], 'inf_supply_raw': str(supply), 'cached_pool_total_sol_lamports': str(total_sol), 'pool_version': pool[12], 'holder_slot': inf['result']['context']['slot'], 'oracle_batch_slots': [capture(n)['result']['context']['slot'] for n in names], 'valuation': 'pool cached SOL NAV / mint supply * captured Pyth SOL/USD (P0 SOL bank oracle), indicative, separate slots'}
    (out / 'inf-preliminary-summary.json').write_text(json.dumps(isum, indent=2) + '\n')
    print('INF', json.dumps(isum), flush=True)
