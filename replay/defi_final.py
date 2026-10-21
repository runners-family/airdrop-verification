"""Historical NFT/USD/account-screen math; reviewed historical method"""
import base64,collections
from decimal import Decimal as D
from .core import loads,encode58 as b58encode,decode58,on_curve as curve
class JSON:
    loads=staticmethod(loads)
json=JSON()
SYSTEM="11111111111111111111111111111111"
TOKEN="TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA"
INF_MINT="5oVNBeEEQvYi1cX3ir8Dx5n1P7pdxydbGF2X4TxVusJm"
def on_curve(wallet):return curve(decode58(wallet))
def account_status(wallet, excluded, accounts):
    if wallet in excluded:
        return excluded[wallet]
    if not on_curve(wallet):
        return 'off_curve_pda'
    if wallet not in accounts:
        return 'needs_owner_check'
    a = accounts[wallet]
    if a and a['executable']:
        return 'executable_account'
    if a and a['owner'] != SYSTEM:
        return 'program_owned_account'
    if a and a.get('space', 0) > 0:
        return 'system_account_with_data'
    return 'included'

def pair_value(amount, side, vault, now):
    pair = vault[side + 'Token']
    dex = vault.get(side + 'DexData')
    qty = D(amount)
    if qty == 0:
        return (D(0), [])
    if pair.get('token1'):
        assert dex is not None, 'missing smart-leg pricing'
        values = []
        for ix in [0, 1]:
            t = pair['token' + str(ix)]
            n = qty / D(10 ** 9) * D(dex['token' + str(ix) + 'PerShare']) / D(10 ** 18)
            values.append({'mint': t['address'], 'quantity': str(n), 'usd': str(n * D(t['price'])), 'price': t['price']})
        return (sum((D(v['usd']) for v in values)), values)
    t = pair['token0']
    scaled = t.get('scaledUiConfig')
    mult = D(1)
    if scaled:
        mult = D(str(scaled['multiplier']))
        if now >= int(scaled['newMultiplierEffectiveTimestamp']):
            mult = D(str(scaled['newMultiplier']))
    n = qty / D(10 ** 9) * mult
    price = D(str(t['price']))
    assert price > 0
    return (n * price, [{'mint': t['address'], 'quantity': str(n), 'usd': str(n * price), 'price': str(price)}])

def load_accounts(ev):
    (accounts, tokens, holder_scans, slots) = ({}, {}, {}, collections.defaultdict(list))
    for p in sorted((ev.root / 'captures').glob('*/record.json')):
        name = p.parent.name
        r = json.loads(p.read_bytes())
        if not r['ok']:
            continue
        if name.startswith(('owner-checks-', 'jup-nft-ata-')):
            (data, rec) = ev.capture(name)
            keys = rec['job']['rpc']['params'][0]
            assert len(keys) == len(data['result']['value'])
            slots[name.split('-')[0] + ('-ata' if 'ata' in name else '')].append(data['result']['context']['slot'])
            for (key, a) in zip(keys, data['result']['value']):
                if name.startswith('jup-nft-ata-'):
                    assert key not in tokens or tokens[key] == a, 'Conflicting NFT account proof'
                    tokens[key] = a
                else:
                    if a is not None and 'space' not in a:
                        raise AssertionError('account check without space field: ' + key)
                    assert key not in accounts or accounts[key] == a, 'Conflicting owner account proof'
                    accounts[key] = a
        elif name.startswith('jup-nft-holder-'):
            (data, rec) = ev.capture(name)
            mint = rec['job']['rpc']['params'][1]['filters'][1]['memcmp']['bytes']
            assert mint not in holder_scans or holder_scans[mint] == data['result']['value'], 'Conflicting NFT holder scan'
            holder_scans[mint] = data['result']['value']
            slots['jup-nft-holder'].append(data['result']['context']['slot'])
            for row in data['result']['value']:
                assert row['pubkey'] not in tokens or tokens[row['pubkey']] == row['account'], 'Conflicting NFT account proof'
                tokens[row['pubkey']] = row['account']
    return (accounts, tokens, holder_scans, slots)

def jupiter_values(ev, tokens, holder_scans):
    token_owners = {}
    for (key, a) in tokens.items():
        if not a or a['owner'] != TOKEN:
            continue
        raw = base64.b64decode(a['data'][0])
        if len(raw) != 165 or int.from_bytes(raw[64:72], 'little') != 1:
            continue
        token_owners.setdefault(b58encode(raw[:32]), {})[b58encode(raw[32:64])] = key
    vaults = {v['id']: v for v in ev.capture('jup-indexed-vaults')[0]}
    for p in sorted((ev.root / 'captures').glob('jup-single-vault-*/record.json')):
        if json.loads(p.read_bytes())['ok']:
            (v, _) = ev.capture(p.parent.name)
            vaults[v['id']] = v
    clock = ev.capture('valuation-clock')[0]
    now = int.from_bytes(base64.b64decode(clock['result']['value']['data'][0])[32:40], 'little', signed=True)
    amounts = ev.derived_rows('jup-onchain-borrow-amounts.jsonl')
    assert ev.derived_json('jup-onchain-borrow-errors.json') == []
    mint_supply = {}
    for p in sorted((ev.root / 'captures').glob('jup-nft-mints-*/record.json')):
        if json.loads(p.read_bytes())['ok']:
            (data, rec) = ev.capture(p.parent.name)
            for (key, a) in zip(rec['job']['rpc']['params'][0], data['result']['value']):
                mint_supply[key] = None if a is None else int.from_bytes(base64.b64decode(a['data'][0])[36:44], 'little')
    (wallets, review, valued, proof_count) = ({}, [], [], 0)
    for r in amounts:
        if int(r['borrow_raw']) <= 0:
            continue
        owners = token_owners.get(r['mint'], {})
        if len(owners) != 1:
            reason = 'no_positive_nft_holder' if r['mint'] in holder_scans and (not owners) else 'needs_nft_owner_proof'
            row = {**r, 'decision': reason, 'nft_mint_supply': mint_supply.get(r['mint'])}
            v = vaults.get(r['vault_id'])
            try:
                row['indicative_deposit_usd'] = str(pair_value(r['supply_raw'], 'supply', v, now)[0]) if v else None
                row['indicative_borrow_usd'] = str(pair_value(r['borrow_raw'], 'borrow', v, now)[0]) if v else None
            except (KeyError, AssertionError, ValueError, ArithmeticError):
                row['indicative_deposit_usd'] = row['indicative_borrow_usd'] = None
            review.append(row)
            continue
        owner = next(iter(owners))
        proof_count += 1
        w = wallets.setdefault(owner, {'wallet': owner, 'deposit_usd': D(0), 'borrow_usd': D(0), 'inf_collateral_usd': D(0), 'positions': [], 'unpriced_positions': []})
        v = vaults.get(r['vault_id'])
        if v is None:
            w['unpriced_positions'].append(r)
            continue
        try:
            (av, assets) = pair_value(r['supply_raw'], 'supply', v, now)
            (lv, debts) = pair_value(r['borrow_raw'], 'borrow', v, now)
        except (KeyError, AssertionError, ValueError, ArithmeticError) as e:
            w['unpriced_positions'].append({**r, 'error': str(e)})
            continue
        w['deposit_usd'] += av
        w['borrow_usd'] += lv
        w['inf_collateral_usd'] += sum((D(x['usd']) for x in assets if x['mint'] == INF_MINT))
        w['positions'].append(r['position'])
        valued.append({**r, 'wallet': owner, 'nft_token_account': owners[owner], 'deposit_usd': str(av), 'borrow_usd': str(lv), 'deposit_assets': assets, 'borrow_assets': debts})
    stats = {'onchain_positive_borrowing_nfts': sum((int(r['borrow_raw']) > 0 for r in amounts)), 'nft_owners_proven': proof_count, 'clock_unix_timestamp': now, 'vaults_priced': len(vaults)}
    return (wallets, review, valued, stats)
