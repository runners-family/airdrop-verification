"""Historical P0, INF and Jupiter raw account and valuation replay."""
from collections import defaultdict
from decimal import localcontext
import gzip
from pathlib import Path
from .core import account_data, canonical, decode58, encode58, loads, on_curve, require, sha, wallet_bytes
from .capture_store import Bundle
from . import holder_common, defi_codec as codec, defi_pricing as pricing, defi_p0 as p0, defi_final as final
from . import jupiter_math as jup


class Evidence:
    def __init__(self, root, derived, reference):
        self.root, self.derived, self.reference = root, derived, reference

    def check_request(self, name, request, body):
        slot = self.reference['reference_slot']
        base = dict(encoding='base64', commitment='finalized', minContextSlot=slot)
        program = 'MFv2hWf31Z9kbCa1snEPYctwafyhdvnV7FZnsebVacA'
        group = '4qp6Fx6tnZkY5Wropq9wUYgtFxXKwE6viZxFHg3rdAG8'
        p0_idl = codec.IDL('sources/p0-marginfi_0-1-11-json.source')
        def disc(idl, typename):
            return encode58(bytes(next(a['discriminator'] for a in idl.j['accounts'] if a['name'] == typename)))
        if request['method'] == 'getProgramAccounts':
            filters, sliced = None, None
            if name == 'p0-banks':
                filters = [{'memcmp': {'offset': 0, 'bytes': disc(p0_idl, 'Bank')}},
                           {'memcmp': {'offset': 41, 'bytes': group}}]
            elif name.startswith('p0-active-balance-') or name == 'p0-account-inventory':
                filters = [{'memcmp': {'offset': 0, 'bytes': disc(p0_idl, 'MarginfiAccount')}},
                           {'memcmp': {'offset': 8, 'bytes': group}}]
                if name == 'p0-account-inventory':
                    sliced = {'offset': 0, 'length': 72}
                else:
                    index = int(name.removeprefix('p0-active-balance-'))
                    require(0 <= index < 16, 'Unknown active balance slot')
                    filters.append({'memcmp': {'offset': 72 + 104 * index, 'bytes': '2'}})
                    sliced = {'offset': 72 + 104 * index, 'length': 104}
            elif name == 'inf-token-accounts-small':
                program = final.TOKEN
                filters = [{'dataSize': 165}, {'memcmp': {'offset': 0, 'bytes': final.INF_MINT}}]
                sliced = {'offset': 32, 'length': 40}
            elif name.startswith('jup-nft-holder-'):
                program = final.TOKEN
                mint = request['params'][1]['filters'][1]['memcmp']['bytes']
                filters = [{'dataSize': 165}, {'memcmp': {'offset': 0, 'bytes': mint}}]
            else:
                typename = {'jup-current-states': 'VaultState', 'jupiter-vault-configs': 'VaultConfig',
                    'jup-current-positions': 'Position', 'jup-ticks': 'Tick', 'jup-branches': 'Branch',
                    'jup-tick-liquidations': 'TickIdLiquidation'}.get(name)
                require(typename is not None, 'Unknown DeFi program discovery profile')
                program = jup.PROGRAM
                idl = codec.IDL('sources/jupiter-vaults-json.source')
                filters = [{'memcmp': {'offset': 0, 'bytes': disc(idl, typename)}}]
            options = dict(base, withContext=True, filters=filters)
            if sliced is not None:
                options['dataSlice'] = sliced
            require(request['params'] == [program, options], 'DeFi discovery scope differs')
            rows = body['result']['value']
            require(len(rows) == len({row['pubkey'] for row in rows}), 'Duplicate program account')
            for row in rows:
                require(row['account']['owner'] == program, 'Foreign program discovery account')
        elif request['method'] == 'getAccountInfo':
            require(name == 'valuation-clock' and request['params'] ==
                    ['SysvarC1ock11111111111111111111111111111111', base], 'Unexpected clock query')
        elif request['method'] == 'getMultipleAccounts':
            require(name.startswith(('oracle-mints-', 'owner-checks-', 'jup-nft-ata-', 'jup-nft-mints-')),
                    'Unknown DeFi multiple-account profile')
            options = dict(base)
            if name.startswith('owner-checks-'):
                options['dataSlice'] = {'offset': 0, 'length': 0}
            keys = request['params'][0]
            require(request['params'][1] == options and len(keys) == len(set(keys))
                    and 0 < len(keys) <= 100 and len(keys) == len(body['result']['value']),
                    'DeFi account query options/count differ')
        else:
            raise ValueError('Unknown DeFi RPC method')

    def capture(self, name):
        record = loads((self.root / 'captures' / name / 'record.json').read_bytes())
        require(record['ok'], 'Required DeFi capture failed')
        packed = (self.root / record['file']).read_bytes()
        raw = gzip.decompress(packed)
        require(sha(packed) == record['compressed_sha256'] and sha(raw) == record['body_sha256']
                and len(raw) == record['bytes'], 'DeFi projected capture differs')
        if 'rpc' in record['job']:
            request = record['job']['rpc']
            options = request['params'][-1]
            require(options['commitment'] == 'finalized' and options['minContextSlot'] == self.reference['reference_slot'],
                    'DeFi state request differs from reference')
            body = loads(raw)
            require(body['result']['context']['slot'] >= self.reference['reference_slot'], 'DeFi state predates reference')
            self.check_request(name, request, body)
        else:
            body = loads(raw)
        return body, record

    def derived_rows(self, name):
        raw = (self.derived / name).read_bytes()
        if name.endswith('.gz'):
            raw = gzip.decompress(raw)
        return [loads(line) for line in raw.splitlines() if line]

    def derived_json(self, name):
        return loads((self.derived / name).read_bytes())


def borrowers(ev):
    idl = codec.IDL('sources/jupiter-vaults-json.source')
    def rows(capture, typename):
        schema = next(a for a in idl.j['accounts'] if a['name'] == typename)
        output = []
        for row in ev.capture(capture)[0]['result']['value']:
            require(row['account']['owner'] == jup.PROGRAM, 'Foreign Jupiter account owner')
            raw = account_data(row['account'])
            require(raw[:8] == bytes(schema['discriminator']), 'Wrong Jupiter account discriminator')
            value, end = idl.decode(typename, raw, 8)
            require(end <= len(raw), 'Jupiter layout overrun')
            output.append(dict(address=row['pubkey'], **value))
        require(len(output) == len({row['address'] for row in output}), 'Duplicate Jupiter account')
        return output
    ticks = {(r['vault_id'], r['tick']): r for r in rows('jup-ticks', 'Tick')}
    branches = {(r['vault_id'], r['branch_id']): r for r in rows('jup-branches', 'Branch')}
    liquidations = {r['address']: r for r in rows('jup-tick-liquidations', 'TickIdLiquidation')}
    states = {r['vault_id']: r for r in rows('jup-current-states', 'VaultState')}
    positions = rows('jup-current-positions', 'Position')
    output, supply_only = [], []
    for position in positions:
        if position['is_supply_only_position']:
            supply_only.append(position['position_mint'])
            continue
        collateral, debt, branch, liquidated = jup.current(position, ticks, branches, liquidations)
        state = states[position['vault_id']]
        output.append(dict(position=position['address'], mint=position['position_mint'],
            vault_id=position['vault_id'], nft_id=position['nft_id'],
            supply_raw=str(collateral * state['vault_supply_exchange_price'] // 10**12),
            borrow_raw=str(debt * state['vault_borrow_exchange_price'] // 10**12),
            post_liquidation_branch=branch, liquidated=liquidated, remaining_debt_raw=str(debt)))
    output.sort(key=lambda r: r['position'])
    (ev.derived / 'jup-onchain-borrow-amounts.jsonl').write_bytes(b''.join(canonical(row) for row in output))
    (ev.derived / 'jup-onchain-borrow-errors.json').write_bytes(canonical([]))
    (ev.derived / 'jup-onchain-supply-only-mints.json').write_bytes(canonical(sorted(supply_only)))
    return dict(positions=len(positions), supply_only_positions=len(supply_only), borrow_positions=len(output),
                remaining_borrowers=sum(int(row['borrow_raw']) > 0 for row in output), errors=0,
                vault_states=len(states), ticks=len(ticks), branches=len(branches), tick_liquidations=len(liquidations))


def derive(package, reference, scratch):
    root = Path(package) / 'data/defi'
    derived = Path(scratch) / 'defi-derived'
    derived.mkdir()
    ev = Evidence(root, derived, reference)
    with localcontext() as context:
        context.rounding = 'ROUND_HALF_EVEN'
        context.prec = 50
        codec.ROOT, codec.capture = root, lambda name: ev.capture(name)[0]
        pricing.capture = codec.capture
        p0.ROOT, p0.capture, p0.evidence = root, codec.capture, ev
        p0.main(derived)
        jstats = borrowers(ev)
        accounts, tokens, holder_scans, slots = final.load_accounts(ev)
        jwallets, review, valued, pricing_stats = final.jupiter_values(ev, tokens, holder_scans)
        store = Bundle(package)
        excluded, _ = holder_common.exclusion_registry(store, Path('data/legacy-services'))
        require(excluded == loads((Path(package) / 'expected/legacy-services.json').read_bytes()),
                'Frozen service registry differs')
        outputs, counts = {}, {}
        for category, name, threshold in [('p0', 'p0-wallet-values.jsonl.gz', 'meets_100_100'),
                                         ('sanctum_inf', 'inf-wallet-values.jsonl.gz', 'meets_100')]:
            decisions, included = [], []
            for row in ev.derived_rows(name):
                status = final.account_status(row['wallet'], excluded, accounts) if row[threshold] else 'below_100'
                require(status != 'needs_owner_check', 'Missing qualifying DeFi account screen')
                decisions.append(dict(**row, decision=status))
                if status == 'included':
                    included.append(row['wallet'])
            outputs[category] = {'wallets.txt': wallet_bytes(sorted(included)),
                'decisions.jsonl': b''.join(canonical(row) for row in decisions)}
            counts[category] = dict(wallets=len(included), candidates=len(decisions))
        by_wallet = defaultdict(list)
        for row in valued:
            by_wallet[row['wallet']].append(row)
        decisions, included = [], []
        for wallet, row in sorted(jwallets.items()):
            threshold = row['deposit_usd'] >= 100 and row['borrow_usd'] >= 100
            status = final.account_status(wallet, excluded, accounts) if threshold else 'below_100'
            require(status != 'needs_owner_check', 'Missing qualifying Jupiter account screen')
            if status == 'included':
                included.append(wallet)
            decisions.append(dict(**row, decision=status, valued_positions=by_wallet[wallet]))
        outputs['jupiter_lend'] = {'wallets.txt': wallet_bytes(included),
            'decisions.jsonl': b''.join(canonical(row) for row in decisions),
            'review.jsonl': b''.join(canonical(row) for row in review)}
        counts['jupiter_lend'] = dict(wallets=len(included), candidates=len(decisions), unresolved_positions=len(review))
        return outputs, dict(groups=counts, raw_jupiter=jstats, jupiter_pricing=pricing_stats,
            p0=ev.derived_json('p0-preliminary-summary.json'), inf=ev.derived_json('inf-preliminary-summary.json'),
            source_limit='Unsigned finalized collection-window raw state, captured price/oracle/index values and proven NFT holders; unpriced or unproven positions are reported, not assumed eligible.')
