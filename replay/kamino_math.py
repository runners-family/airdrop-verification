from .core import utc_epoch
"""Historical pure valuation helpers, extracted without live collection or prior-cohort comparison.
Historical deterministic method adapted for public replay.
"""
import base64
from collections import Counter, defaultdict
import copy
from datetime import datetime, timezone
from fractions import Fraction
import hashlib
import json
from pathlib import Path
from urllib.parse import quote
from .holder_common import THRESHOLD, TOKEN, TOKEN22, Bundle, account_evidence, b58encode, canonical, encoded, exclusion_registry, mint_info, number, on_curve, owner_status, plan_owner_checks, read_owner_checks, require, rpc_job, token_holder_job, token_holders, u64, usd_text, wallet_list_bytes
KLEND = 'KLend2g3cP87fffoy8q1mQqGKjrxjC8boSyAYavgmjD'
OBLIGATION = bytes([168, 206, 141, 106, 88, 76, 172, 167])
VAULTS_URL = 'registry:kamino-vaults'
METRICS_URL = 'metrics:kamino-vaults?limit=100'
SF = 2 ** 60

def obligations_template(slot):
    return rpc_job('kamino-obligations', 'getProgramAccountsV2', [KLEND, {'encoding': 'base64', 'commitment': 'finalized', 'minContextSlot': slot, 'withContext': True, 'limit': 2000, 'filters': [{'memcmp': {'offset': 0, 'bytes': 'VEdzkJnDweW'}}], 'dataSlice': {'offset': 0, 'length': 2240}}])

def page_job(template, page, cursor):
    job = copy.deepcopy(template)
    job['name'] += '-page-' + str(page)
    if cursor:
        job['rpc']['params'][1]['paginationKey'] = cursor
    return job

def metrics_job(page, token):
    return {'name': 'kamino-vault-metrics-page-' + str(page), 'source_id': METRICS_URL + ('&paginationToken=' + quote(token, safe='') if token else '')}

def share_mint_job(index, mints, slot):
    return rpc_job('kamino-share-mints-' + str(index), 'getMultipleAccounts', [mints, {'encoding': 'base64', 'commitment': 'finalized', 'minContextSlot': slot}])

def slot_job(name):
    return rpc_job(name, 'getSlot', [{'commitment': 'finalized'}])

def obligation(row, slot):
    """From next_batch.obligation (pinned klend layout: 8 x 136-byte deposits, 5 x 200-byte borrows)."""
    account = row['account']
    require(account['owner'] == KLEND and account['executable'] is False, 'Wrong obligation owner')
    raw = base64.b64decode(account['data'][0], validate=True)
    require(len(raw) == 2240 and raw[:8] == OBLIGATION, 'Wrong obligation discriminator or prefix length')
    deposits = 0
    for i in range(8):
        if u64(raw, 96 + i * 136 + 32):
            deposits += 1
    return {'wallet': b58encode(raw[64:96]), 'obligation': row['pubkey'], 'market': b58encode(raw[32:64]), 'slot': slot, 'last_update_slot': u64(raw, 16), 'stale_flag': raw[24], 'deposit_positions': deposits, 'deposited_sf': int.from_bytes(raw[1192:1208], 'little'), 'borrowed_sf': int.from_bytes(raw[2224:2240], 'little')}

class Context:

    def __init__(self, workspace, bundle_dir):
        self.bundle = Bundle(workspace)
        self.dir = Path(bundle_dir)
        self.scope = self.bundle.json(self.dir / 'scope.json')
        snapshot = self.bundle.json(self.scope['snapshot'])
        require(snapshot['reference_slot'] == self.scope['reference_slot'] and snapshot['reference_block_time'] == self.scope['reference_block_time'], 'Scope differs from snapshot')
        self.slot = self.scope['reference_slot']
        self.time = self.scope['reference_block_time']
        self.exclusions_dir = Path(self.scope['exclusion_sources_bundle'])
        (self.times, self.context_slots) = ([], [])

    def capture(self, name, job=None):
        (data, record) = self.bundle.capture(self.dir, name, job)
        if record is not None and record['ok']:
            require(utc_epoch(record['retrieved_at']) >= self.time, 'Capture predates the reference block time: ' + name)
            self.times.append(record['retrieved_at'])
            if record.get('context_slot') is not None:
                require(record['context_slot'] >= self.slot, 'Context slot below the reference slot: ' + name)
                self.context_slots.append(record['context_slot'])
        return (data, record)

def obligation_pages(ctx):
    """From next_batch.pages: verify the cursor chain, row count, slot range and completeness."""
    coverage = ctx.bundle.json(ctx.dir / 'kamino-obligations-coverage.json')
    template = obligations_template(ctx.slot)
    (cursor, seen, count, slots) = (None, set(), 0, [])
    for (number_, name) in enumerate(coverage['pages']):
        expected = page_job(template, number_, cursor)
        require(name == expected['name'], 'Missing or reordered obligation page')
        (data, record) = ctx.capture(name, expected)
        require(data is not None, 'Failed obligation page ' + name)
        value = data['result']['value']
        slots.append(data['result']['context']['slot'])
        count += len(value['accounts'])
        next_cursor = value['paginationKey']
        if next_cursor is not None:
            require(next_cursor not in seen, 'Repeated pagination cursor')
            seen.add(next_cursor)
        else:
            require(number_ == len(coverage['pages']) - 1, 'Page after terminal cursor')
        cursor = next_cursor
        yield (name, data)
    require(count == coverage['returned_rows'], 'Incorrect obligation row count')
    require(coverage['slot_range'] == ([min(slots), max(slots)] if slots else None), 'Incorrect page slot range')
    require(coverage['complete'] and coverage['pages'] and (cursor is None), 'Obligation pagination is incomplete')

def vault_registry(ctx):
    (vaults, record) = ctx.capture('kamino-vault-registry', {'name': 'kamino-vault-registry', 'source_id': VAULTS_URL})
    require(vaults is not None, 'Missing Kamino vault registry')
    seen = set()
    for vault in vaults:
        require(vault['address'] not in seen, 'Duplicate vault')
        seen.add(vault['address'])
    coverage = ctx.bundle.json(ctx.dir / 'kamino-vault-metrics-coverage.json')
    require(coverage['complete'], 'Vault metrics pagination incomplete')
    (metrics, token, times) = ({}, None, [])
    for (page, name) in enumerate(coverage['pages']):
        job = metrics_job(page, token)
        require(name == job['name'], 'Missing or reordered metrics page')
        (data, mrec) = ctx.capture(name, job)
        require(data is not None, 'Failed metrics page ' + name)
        for row in data['result']:
            require(row['kvault'] not in metrics, 'Duplicate vault metric')
            metrics[row['kvault']] = row
        times.append(mrec['retrieved_at'])
        token = data.get('paginationToken')
        require((token is None) == (page == len(coverage['pages']) - 1), 'Metrics cursor chain broken')
    return (vaults, record, metrics, times)

def share_mints(ctx, vaults):
    mints = [v['state']['sharesMint'] for v in vaults]
    require(len(mints) == len(set(mints)), 'Duplicate share mint')
    (infos, gaps, jobs) = ({}, [], [])
    for index in range((len(mints) + 99) // 100):
        batch = mints[index * 100:(index + 1) * 100]
        job = share_mint_job(index, batch, ctx.slot)
        jobs.append(job)
        (data, record) = ctx.capture(job['name'], job)
        if data is None:
            gaps.extend(batch)
            continue
        require(len(data['result']['value']) == len(batch), 'Missing mint entries')
        stamp = utc_epoch(record['retrieved_at'])
        for (mint, account) in zip(batch, data['result']['value']):
            if account is None:
                infos[mint] = None
                continue
            infos[mint] = mint_info(account, data['result']['context']['slot'], stamp)
    return (infos, gaps, jobs)

def holder_jobs(vaults, infos, slot):
    return [token_holder_job('kamino-vault-holders-' + v['state']['sharesMint'], v['state']['sharesMint'], infos[v['state']['sharesMint']]['program'], slot) for v in vaults if infos.get(v['state']['sharesMint']) and infos[v['state']['sharesMint']]['supply_raw']]

def values(ctx):
    (lending, debt) = (defaultdict(Fraction), defaultdict(Fraction))
    positions = defaultdict(list)
    stats = Counter()
    (seen, slots, pages) = (set(), [], 0)
    for (name, data) in obligation_pages(ctx):
        pages += 1
        slot = data['result']['context']['slot']
        slots.append(slot)
        for row in data['result']['value']['accounts']:
            require(row['pubkey'] not in seen, 'Overlapping obligation pages')
            seen.add(row['pubkey'])
            r = obligation(row, slot)
            (dep, bor) = (r['deposited_sf'], r['borrowed_sf'])
            stats['obligations'] += 1
            if dep or bor:
                lending[r['wallet']] += Fraction(dep, SF)
                debt[r['wallet']] += Fraction(bor, SF)
                positions[r['wallet']].append(r)
                stats['obligations_with_value'] += 1
            stats['positive_deposit_obligations_marked_stale'] += bool(r['deposit_positions']) and bool(r['stale_flag'])
            stats['negative_net_obligations'] += dep < bor
            stats['debt_only_obligations'] += not r['deposit_positions'] and bor > 0
    (vaults, registry_record, metrics, metric_times) = vault_registry(ctx)
    (infos, mint_gaps, _) = share_mints(ctx, vaults)
    (earn, earn_positions, unpriced_by_owner) = (defaultdict(Fraction), defaultdict(list), defaultdict(list))
    (vault_prices, scan_gaps, holder_slots, accounts_scanned) = ({}, [], [], 0)
    reconciled = Counter()
    jobs = {job['name']: job for job in holder_jobs(vaults, infos, ctx.slot)}
    for vault in vaults:
        state = vault['state']
        mint = state['sharesMint']
        info = infos.get(mint)
        entry = {'vault': vault['address'], 'name': state.get('name'), 'shares_mint': mint, 'shares_mint_decimals': state['sharesMintDecimals'], 'token_mint': state.get('tokenMint')}
        metric = metrics.get(vault['address'])
        if info is not None:
            require(info['decimals'] == state['sharesMintDecimals'], 'Share decimals differ from chain: ' + mint)
            entry.update({'supply_raw': str(info['supply_raw']), 'program': info['program'], 'mint_slot': info['slot']})
        if metric is not None:
            entry['share_price_usd'] = str(metric['sharePrice'])
        price = number(metric['sharePrice']) if metric is not None else None
        if price is not None:
            require(price >= 0, 'Negative share price')
        vault_prices[vault['address']] = entry
        name = 'kamino-vault-holders-' + mint
        if name not in jobs:
            entry['holders_scanned'] = False
            entry['reason'] = 'share_mint_capture_failed' if mint in mint_gaps else 'mint_account_missing' if info is None else 'zero_supply'
            continue
        (data, record) = ctx.capture(name, jobs[name])
        if data is None:
            scan_gaps.append({'capture': name, 'status': 'missing' if record is None else 'failed'})
            entry['holders_scanned'] = False
            entry['reason'] = 'holder_scan_failed'
            continue
        (smint, owners, _, slot, count) = token_holders(data, jobs[name])
        require(smint == mint, 'Holder scan mint mismatch')
        holder_slots.append(slot)
        accounts_scanned += count
        entry['holders_scanned'] = True
        entry['positive_owners'] = len(owners)
        entry['summed_balances_raw'] = str(sum(owners.values()))
        entry['summed_balances_equal_supply'] = sum(owners.values()) == info['supply_raw']
        reconciled[entry['summed_balances_equal_supply']] += 1
        for (owner, amount) in owners.items():
            if price is None:
                unpriced_by_owner[owner].append(vault['address'])
                continue
            value = amount * price / 10 ** state['sharesMintDecimals']
            earn[owner] += value
            earn_positions[owner].append({'vault': vault['address'], 'shares_mint': mint, 'shares_raw': str(amount), 'share_price_usd': str(metric['sharePrice']), 'usd': usd_text(value)})
    wallets = set(lending) | set(earn) | set(unpriced_by_owner)
    return {'lending': lending, 'debt': debt, 'positions': positions, 'stats': stats, 'obligation_slots': slots, 'pages': pages, 'vaults': vaults, 'registry_record': registry_record, 'metrics': metrics, 'metric_times': metric_times, 'infos': infos, 'mint_gaps': mint_gaps, 'earn': earn, 'earn_positions': earn_positions, 'unpriced_by_owner': unpriced_by_owner, 'vault_prices': vault_prices, 'scan_gaps': scan_gaps, 'holder_slots': holder_slots, 'accounts_scanned': accounts_scanned, 'wallets': wallets, 'reconciled': reconciled}

def amounts(state, wallet):
    lending = state['lending'].get(wallet, Fraction(0))
    earn = state['earn'].get(wallet, Fraction(0))
    return (lending + earn, lending, earn, state['debt'].get(wallet, Fraction(0)))

def candidates(state, excluded):
    wanted = set()
    for wallet in state['wallets']:
        (gross, _, _, debt) = amounts(state, wallet)
        if debt >= THRESHOLD and (gross >= THRESHOLD or wallet in state['unpriced_by_owner']) and (wallet not in excluded) and on_curve(wallet):
            wanted.add(wallet)
    return wanted
