"""Mandatory raw discovery/decoding before the preserved Exponent/Hylo math."""
from collections import defaultdict
from decimal import Decimal, localcontext
import gzip
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
from .core import account_data, canonical, encode58, loads, require, sha, wallet_bytes
from . import exponent_math as math


def derive(root, reference, scratch):
    with localcontext() as context:
        context.rounding = 'ROUND_HALF_EVEN'
        context.prec = 80
        return _derive(root, reference, scratch)


def _derive(root, reference, scratch):
    root, scratch = Path(root), Path(scratch)
    inputs = root / 'data/exponent-hylo/inputs'
    original_read = math.read
    original_exists = math.exists
    original_decoder = math.decoded_strategies
    derived = {}
    def read(path):
        return derived[path.name] if path.name in derived else original_read(path)
    math.read = read
    math.exists = lambda path: path.name in derived or original_exists(path)
    try:
        metas = {}
        for path in sorted(inputs.glob('*.metadata.json')):
            meta = loads(path.read_bytes())
            name = path.name.removesuffix('.metadata.json')
            raw = gzip.decompress((inputs / (name + '.json.gz')).read_bytes())
            require(sha(raw) == meta['sha256'] and len(raw) == meta['bytes'], 'Product projection hash mismatch')
            require((meta['status'] == 200 or (meta['status'] == 206 and name.startswith('exponent-table-')))
                    and meta['retrieved_at_unix'] > reference['reference_block_time'],
                    'Product capture failed or predates reference')
            if 'rpc_request' in meta:
                request = meta['rpc_request']
                body = loads(raw)['result']
                if request['method'] == 'getTokenAccounts':
                    require(body['last_indexed_slot'] >= reference['reference_slot'], 'Holder index predates reference')
                else:
                    options = request['params'][-1]
                    require(options['commitment'] == 'finalized' and options['minContextSlot'] == reference['reference_slot']
                            and body['context']['slot'] >= reference['reference_slot'], 'State capture outside disclosed window')
            metas[name] = meta
        # Reconstruct every holder/table page inventory from the actual captures.
        holder_groups, table_groups = defaultdict(list), defaultdict(list)
        for name, meta in metas.items():
            if '-das-page-' in name:
                prefix, number = name.rsplit('-das-page-', 1)
                holder_groups[prefix].append((int(number), name, meta))
            if name.startswith('exponent-table-'):
                table, number = name.removeprefix('exponent-table-').rsplit('-page-', 1)
                table_groups[table].append((int(number), name, meta))
        for prefix, rows in holder_groups.items():
            rows.sort()
            require([number for number, _, _ in rows] == list(range(1, len(rows) + 1)), 'Holder pagination gap')
            pages, mint, total = [], None, 0
            for number, name, meta in rows:
                request = meta['rpc_request']
                require(request['method'] == 'getTokenAccounts' and request['params']['page'] == number,
                        'Holder page request differs')
                current_mint = request['params']['mint']
                require(mint in (None, current_mint), 'Holder mint changed across pages')
                mint = current_mint
                result = read(inputs / (name + '.json.gz'))['result']
                count = len(result['token_accounts'])
                require(number == len(rows) or count > 0, 'Nonterminal empty holder page')
                pages.append(dict(page=number, accounts=count, last_indexed_slot=result['last_indexed_slot']))
                total += count
            require(pages[-1]['accounts'] == 0, 'Missing terminal empty holder page')
            derived[prefix + '-das-inventory.json'] = dict(mint=mint, pages=pages, accounts=total, terminal_pagination=True)
        for table, rows in table_groups.items():
            rows.sort()
            require([number for number, _, _ in rows] == list(range(len(rows))), 'Table pagination gap')
            pages, count, reported_total = [], 0, None
            for number, name, meta in rows:
                records = read(inputs / (name + '.json.gz'))
                content_range = meta['content_range']
                span, size = content_range.split('/')
                require(size != '*', 'Table source omitted total coverage')
                size = int(size)
                require(reported_total in (None, size), 'Table total changed across pages')
                reported_total = size
                if records:
                    first, last = map(int, span.split('-'))
                    require(first == count and last - first + 1 == len(records), 'Table range gap/overlap')
                count += len(records)
                pages.append(dict(page=number, records=len(records)))
            require(count == reported_total, 'Table capture does not cover reported universe')
            derived['exponent-table-' + table + '-inventory.json'] = dict(
                pages=pages, records=count, table=table, terminal_pagination=True)
        # Raw strategy decoding is mandatory. An equivalent pure codec runtime
        # is differential-checked against the historical SDK runtime separately.
        node = shutil.which('node')
        require(node is not None, 'Node runtime is required for raw strategy decoding')
        with tempfile.TemporaryDirectory(prefix='strategy-decode-', dir=scratch) as temporary:
            command = [node, str(Path(__file__).with_name('decode-strategies.cjs')), str(inputs),
                       str(root / 'data/exponent-hylo/sdk/build'), temporary]
            result = subprocess.run(command, env={'PATH': os.defpath}, capture_output=True, text=True, timeout=120)
            require(result.returncode == 0, 'Mandatory raw strategy decoding failed')
            decoded = loads((Path(temporary) / 'decoded.json').read_bytes())
            unsupported = loads((Path(temporary) / 'unsupported.json').read_bytes())
        math.decoded_strategies = lambda _: decoded
        batches = {}
        for key, prefix in (('core_vaults', 'exponent-current-core-vaults'),
                            ('legacy_markets', 'exponent-current-legacy-markets'),
                            ('strategy_state', 'exponent-current-strategy-state'),
                            ('extra_mints', 'exponent-current-extra-mints')):
            numbers = sorted(int(name.removeprefix(prefix + '-')) for name in metas if name.startswith(prefix + '-'))
            require(numbers == list(range(len(numbers))) and numbers, 'Account batch numbering gap')
            batches[key] = len(numbers)
        derived['exponent-current-account-lists.json'] = {'batches': batches}
        def gpa(name):
            rows = read(inputs / (name + '.json.gz'))['result']['value']
            require(len(rows) == len({row['pubkey'] for row in rows}), 'Duplicate discovery account')
            return {row['pubkey'] for row in rows}
        discovered = {'market': gpa('exponent-discovery-market'), 'vault': gpa('exponent-discovery-vault'),
                      'strategy': set().union(*(gpa('exponent-discovery-strategy-' + program)
                                               for program in math.STRATEGY_PROGRAMS))}
        position_markets = {encode58(account_data(row['account'])[32:64])
                            for row in read(inputs / 'exponent-current-legacy-lp-positions.json.gz')['result']['value']}
        wanted = {
            'core_vaults': sorted(discovered['vault'] | {row['address'] for row in math.table(inputs, 'vaults')}),
            'legacy_markets': sorted(discovered['market'] | position_markets | {row['address'] for row in math.table(inputs, 'markets')}),
            'strategy_state': sorted(discovered['strategy'] | {row['address'] for row in math.table(inputs, 'strategy_vaults')}),
            'extra_mints': sorted({row['mint'] for row in math.exponent_registry_candidates(inputs)}),
        }
        for key, prefix in (('core_vaults', 'exponent-current-core-vaults'),
                            ('legacy_markets', 'exponent-current-legacy-markets'),
                            ('strategy_state', 'exponent-current-strategy-state'),
                            ('extra_mints', 'exponent-current-extra-mints')):
            actual = [address for address, _, _ in math.batch_accounts(inputs, prefix, batches[key])]
            require(actual == wanted[key], 'Raw account read universe differs from regenerated discovery: ' + key)
        derived['hylo-current-mint-registry.json'] = math.build_hylo_registry(inputs)
        derived['exponent-current-extra-mint-registry.json'] = math.build_exponent_registry(inputs)
        derived['coverage-gaps.json'] = []
        require(metas['exponent-current-prices']['request_body']['mints'] == math.price_request_mints(inputs),
                'Price request mint universe differs from raw product discovery')
        timestamp = math.measurement_ts(inputs)
        notes, outputs, counts = [], {}, {}
        for category in ('hylo', 'exponent'):
            census, _ = math.hylo_census(inputs, timestamp) if category == 'hylo' else math.exponent_census(inputs, timestamp, notes)
            records = {row['wallet']: row for row in census.records()}
            unpriced = defaultdict(list)
            for row in census.unpriced:
                unpriced[row['wallet']].append(row)
            decisions, included = [], []
            for wallet in sorted(set(records) | set(unpriced)):
                row = records.get(wallet)
                direct = math.on_curve(math.decode58(wallet))
                value = Decimal(row['current_value_usd']) if row else Decimal(0)
                qualifies = direct and value >= 100
                if qualifies:
                    included.append(wallet)
                decisions.append(dict(wallet=wallet, qualifies=qualifies, direct_wallet=direct,
                                      current_value_usd=str(value), products_usd=row['products_usd'] if row else {},
                                      components=census.components.get(wallet, []), unpriced=unpriced.get(wallet, [])))
            outputs[category] = {'wallets.txt': wallet_bytes(included),
                                 'decisions.jsonl': b''.join(canonical(row) for row in decisions)}
            counts[category] = dict(wallets=len(included), candidates_reviewed=len(decisions),
                                    unpriced_rows=len(census.unpriced))
        receipt = dict(groups=counts, raw_strategy_accounts_decoded=len(decoded), unsupported_strategy_layouts=len(unsupported),
                       capture_count=len(metas), measurement_unix=timestamp, valuation_notes=notes,
                       source_limit='Captured protocol/index tables and finalized state; indicative/cached prices, custody and unsupported/unpriced layouts remain disclosed limits.')
        return outputs, receipt
    finally:
        math.read = original_read
        math.exists = original_exists
        math.decoded_strategies = original_decoder
