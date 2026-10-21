"""Historical P0 oracle/integration valuation; reviewed historical method"""
import base64
from decimal import Decimal as D
from .defi_codec import IDL
capture=None
def raw(a):
    return base64.b64decode(a['data'][0])

def u64(d, o):
    return int.from_bytes(d[o:o + 8], 'little')

def sf(a):
    return D(int.from_bytes(bytes(a), 'little')) / D(2 ** 60)

def pyth(a):
    assert a['owner'] == 'rec2HHDDnjLfj4kE7VyEtFA1HPGQLK33259532cRyHp'
    d = raw(a)
    o = 73 if d[40] == 1 else 74
    return (D(int.from_bytes(d[o:o + 8], 'little', signed=True)) * D(10) ** int.from_bytes(d[o + 16:o + 20], 'little', signed=True), int.from_bytes(d[o + 20:o + 28], 'little', signed=True))

def price_bank(b, accounts):
    p = IDL('sources/p0-marginfi_0-1-11-json.source')
    config = b['config']
    setup = config['oracle_setup']
    keys = config['oracle_keys']
    mult = D(1)
    rate_source = 'none'
    clock = raw(capture('valuation-clock')['result']['value'])
    now = int.from_bytes(clock[32:40], 'little', signed=True)
    epoch = u64(clock, 16)
    if setup == 'Fixed':
        return (config['fixed_price'], D(1), 0, 'program_fixed_price', 'none', None)
    if setup == 'Scope':
        return (b['cache']['last_oracle_price'], b['cache']['price_multiplier'], b['cache']['last_oracle_price_timestamp'], 'bank_cache', 'bank_cache', 'scope_price_cache')
    try:
        (price, ts) = pyth(accounts[keys[0]])
        if setup == 'StakedWithPythPush':
            mint = raw(accounts[keys[1]])
            stake = accounts[keys[2]]
            supply = u64(mint, 36)
            assert supply > 0 and stake['owner'] == 'Stake11111111111111111111111111111111111111'
            mult = D(max(stake['lamports'] - 10 ** 9, 0)) / D(supply)
            rate_source = 'onchain_single_validator_pool'
        if setup in ['PythLST', 'KaminoLST', 'JuplendLST']:
            key = keys[1] if setup == 'PythLST' else keys[2]
            d = raw(accounts[key])
            assert d[0] == 1
            numerator = u64(d, 258)
            denom = u64(d, 266)
            last = u64(d, 274)
            assert denom > 0 and epoch - last <= 1
            price *= D(numerator) / D(denom)
            rate_source = 'onchain_stake_pool'
        if setup in ['PythMSOL', 'KaminoMSOL', 'JuplendMSOL']:
            key = keys[1] if setup == 'PythMSOL' else keys[2]
            d = raw(accounts[key])
            assert d[:8] == bytes([216, 146, 107, 94, 104, 75, 182, 177])
            numerator = max(sum((u64(d, o) for o in [226, 376, 496, 568])) - u64(d, 528), 0)
            denom = u64(d, 504)
            assert denom > 0
            price *= D(numerator) / D(denom)
            rate_source = 'onchain_marinade'
        if setup == 'PTPyth':
            ex = IDL('sources/price-src-vendor-exponent-idl-exponent_core-json.source')
            (v, end) = ex.decode('Vault', raw(accounts[keys[1]]), 8)
            assert v['pt_supply'] > 0 and v['duration'] > 0 and (v['start_ts'] + v['duration'] <= now + 5 * 365 * 24 * 60 * 60)
            assert v['last_seen_sy_exchange_rate'] > 0 and v['last_seen_sy_exchange_rate'] >= v['all_time_high_sy_exchange_rate']
            progress = min(max(D(now - v['start_ts']) / D(v['duration']), D(0)), D(1))
            expected = config['fixed_price'] + (1 - config['fixed_price']) * progress
            redemption = D(v['sy_for_pt']) / D(v['pt_supply']) * v['last_seen_sy_exchange_rate']
            price *= min(expected, redemption)
            rate_source = 'onchain_exponent'
        if config['asset_tag'] == 3:
            (r, end) = p.decode('MinimalReserve', raw(accounts[b['integration_acc_1']]), 8)
            liq = D(r['available_amount']) + sf(r['borrowed_amount_sf']) - sum((sf(r[k]) for k in ['accumulated_protocol_fees_sf', 'accumulated_referrer_fees_sf', 'pending_referrer_fees_sf']))
            mult = liq / D(r['mint_total_supply']) if r['mint_total_supply'] else D(1)
            rate_source = 'onchain_kamino_reserve'
        if config['asset_tag'] == 4:
            (r, end) = p.decode('MinimalSpotMarket', raw(accounts[b['integration_acc_1']]), 8)
            mult = D(int.from_bytes(bytes(r['cumulative_deposit_interest']), 'little')) / D(10) ** (19 - r['decimals'])
            rate_source = 'onchain_drift_spot_market'
        if config['asset_tag'] == 6:
            (l, end) = p.decode('Lending', raw(accounts[b['integration_acc_1']]), 8)
            mult = D(l['token_exchange_price']) / D(10 ** 12)
            rate_source = 'onchain_jupiter_lending_stored_exchange_price'
        assert price > 0 and mult > 0
        return (price, mult, ts, 'onchain_pyth', rate_source, None)
    except (AssertionError, KeyError, IndexError, ValueError) as e:
        return (D(0), D(0), 0, 'unresolved', rate_source, type(e).__name__ + ':' + str(e))
