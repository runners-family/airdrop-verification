"""Rebuild first-funder clusters and exact R4 decisions from projected captures."""
from collections import Counter, defaultdict
from fractions import Fraction
import gzip
import re
from pathlib import Path
from .core import address, canonical, loads, on_curve, require, utc_epoch, wallet_bytes
from .flows import find_funder, outflows, tx_items

SERVICE_CATEGORIES = frozenset((
    'Centralized Exchange', 'Cross-chain Bridge', 'DeFi', 'Fees', 'Transaction Sending', 'Payments',
    'Validator', 'Stake Pool', 'Restaking', 'Vault', 'Proprietary AMM', 'Game', 'DePIN', 'Casino & Gambling',
    'Tools', 'Authority', 'Treasury', 'Trading App or Trading Bot', 'Market Maker', 'Trading Firm',
    'Memecoin', 'Fundraise',
))
DAY = 86400
SYSTEM = '11111111111111111111111111111111'
LIMITS = (10, 40, 100)


def request(wallet, order='asc', limit=10, token=None, signatures=False):
    options = dict(transactionDetails='signatures' if signatures else 'full', sortOrder=order,
                   limit=limit, commitment='finalized', filters={'slot': {'lte': 458146998}})
    if signatures:
        pass
    else:
        options.update(encoding='jsonParsed', maxSupportedTransactionVersion=1)
        options['filters']['status'] = 'succeeded'
    if token is not None:
        options['paginationToken'] = token
    return dict(method='getTransactionsForAddress', params=[wallet, options])


def check_request(actual, expected):
    # The JSON-RPC envelope is transport-independent; check all method/params.
    require(actual['method'] == expected['method'] and actual['params'] == expected['params'],
            'Captured query differs from deterministic plan')


def check_page(result, order, limit, full=True):
    rows = result['data']
    require(len(rows) <= limit, 'History response exceeds requested bound')
    slots = [row['slot'] for row in rows]
    require(all(type(slot) is int and 0 <= slot <= 458146998 for slot in slots), 'Out-of-scope history slot')
    require(slots == sorted(slots, reverse=order == 'desc'), 'History response order differs')
    if full:
        require(all(row.get('meta') and row['meta']['err'] is None for row in rows),
                'Unsuccessful transaction in successful-only history')
    return rows


def check_label(row, phase):
    request_ = row['request']
    if phase in ('funders', 'funders-retry'):
        expected = 'funders:' + row['wallet'] + ':' + str(row['page'])
    elif phase == 'identity':
        keys = request_['addresses']
        require(keys == sorted(set(keys)) and keys, 'Identity lookup keys must be sorted and unique')
        expected = 'identity:' + keys[0] + ':' + str(len(keys))
    elif phase == 'accounts':
        keys = request_['params'][0]
        require(keys == sorted(set(keys)) and keys, 'Account lookup keys must be sorted and unique')
        expected = 'accounts:' + keys[0] + ':' + str(len(keys))
    elif phase == 'latest':
        expected = 'latest:' + request_['params'][0]
    else:
        require(phase == 'activity' and request_['params'][1]['sortOrder'] in ('asc', 'desc'),
                'Unknown activity capture scope')
        expected = 'activity:' + request_['params'][0] + ':' + request_['params'][1]['sortOrder']
    require(row['job'] == expected, 'Capture label differs from its logical query')


def last_attempt(attempts):
    """Identical duplicate retries are harmless; incompatible same-number retries fail."""
    seen = {}
    for row in attempts:
        key = row.get('page', 0), row['attempt']
        semantic = {field: row.get(field) for field in ('request', 'ok', 'body')}
        require(key not in seen or seen[key] == semantic, 'Conflicting duplicate capture attempt')
        seen[key] = semantic
    return attempts[-1]


def capture_lines(root, phase):
    for path in sorted((Path(root) / phase).glob('shard-*.jsonl.gz')):
        with gzip.open(path, 'rt') as handle:
            for line in handle:
                row = loads(line)
                require(type(row['ok']) is bool and type(row['attempt']) is int and row['attempt'] > 0,
                        'Invalid capture status/attempt fields')
                require(utc_epoch(row['retrieved_at']) >= 1792264090, 'Exclusion capture predates reference')
                check_label(row, phase)
                yield row


def jobs(root, phase):
    result = defaultdict(list)
    for row in capture_lines(root, phase):
        result[row['job']].append(row)
    return {key: sorted(rows, key=lambda row:(row.get('page', 0), row['attempt']))
            for key, rows in result.items()}


def resolve(wallet, attempts):
    by_page = defaultdict(list)
    for row in attempts:
        by_page[row['page']].append(row)
    require(sorted(by_page) == list(range(len(by_page))) and len(by_page) <= len(LIMITS), 'Funder page gap')
    pages, cursor, failed = [], None, 0
    for index in range(len(by_page)):
        rows = sorted(by_page[index], key=lambda row:row['attempt'])
        for row in rows:
            check_request(row['request'], request(wallet, limit=LIMITS[index], token=cursor))
            failed += not row['ok']
        last = last_attempt(rows)
        if not last['ok']:
            return {'wallet': wallet, 'status': 'failed'}, []
        result = last['body']['result']
        check_page(result, 'asc', LIMITS[index])
        if pages and pages[-1]['data'] and result['data']:
            require(pages[-1]['data'][-1]['slot'] <= result['data'][0]['slot'], 'History page order differs')
        pages.append(result)
        cursor = result.get('paginationToken')
    items = tx_items(pages)
    found, scanned = find_funder(wallet, items)
    more = bool(pages and len(pages[-1]['data']) == LIMITS[len(pages) - 1] and cursor)
    require(found is not None or not more or len(pages) == len(LIMITS), 'First-funder collection stopped early')
    row = dict(wallet=wallet, attempts=len(attempts), failed_attempts=failed,
               status='resolved' if found and found.get('funder') else 'unknown',
               txs_scanned=scanned, pages=len(pages), history='depth_limit' if found is None and more else 'complete_or_found')
    if found and found.get('funder'):
        row.update({field: found[field] for field in ('funder', 'method', 'level', 'lamports', 'slot', 'block_time',
                    'transaction_index', 'signature', 'fee_payer', 'tx_rank')})
    else:
        row['unknown_reason'] = ('no_transactions' if not items else 'unattributed_inflow' if found is not None
            else f'no_sol_inflow_in_first_{scanned}_txs' if more else 'no_sol_inflow_in_history')
        if found:
            row.update({field: found[field] for field in ('slot', 'block_time', 'signature', 'lamports')})
    flows = [(destination, asset, amount, item['slot']) for item in items
             for destination, asset, amount in outflows(wallet, item)]
    return row, flows


def max_window(times, width):
    left, best = 0, 0
    for right, timestamp in enumerate(times):
        while timestamp - times[left] > width:
            left += 1
        best = max(best, right - left + 1)
    return best


def rule_hits(n, near_count, w24, w7, returned_count, controller, busy):
    if not controller or busy:
        return []
    near = near_count * 5 >= n * 4
    burst24, burst7 = w24 * 5 >= n * 4, w7 * 5 >= n * 4
    result = []
    if n >= 25 and burst7 and near:
        result.append('R1')
    if burst24 and near:
        result.append('R2')
    if returned_count * 2 >= n and (burst7 or near):
        result.append('R3')
    return result


def derive(root, groups):
    root = Path(root)
    listed = sorted(set().union(*(set(rows) for rows in groups.values())))
    listed_set = set(listed)
    retries = defaultdict(list)
    for row in capture_lines(root, 'funders-retry'):
        require(row['wallet'] in listed_set, 'Retry for unlisted candidate')
        retries[row['wallet']].append(row)
    funders, flows = {}, {}
    files = sorted((root / 'funders').glob('shard-*.jsonl.gz'))
    require(len(files) == (len(listed) + 999) // 1000, 'Missing funder shard')
    for index, path in enumerate(files):
        require(path.name == f'shard-{index:04d}.jsonl.gz', 'Funder shard numbering gap')
        records = defaultdict(list)
        with gzip.open(path, 'rt') as handle:
            for line in handle:
                row = loads(line)
                require(type(row['ok']) is bool and type(row['attempt']) is int and row['attempt'] > 0
                        and utc_epoch(row['retrieved_at']) >= 1792264090, 'Invalid funder capture metadata')
                check_label(row, 'funders')
                records[row['wallet']].append(row)
        expected = listed[index * 1000:(index + 1) * 1000]
        require(set(records) == set(expected), 'Funder shard differs from regenerated candidate universe')
        for wallet in expected:
            funders[wallet], flows[wallet] = resolve(wallet, records[wallet] + retries.get(wallet, []))
    status = Counter(row['status'] for row in funders.values())
    require(not status['failed'], 'Unresolved collection failure')
    classifications = {}
    for key, attempts in jobs(root, 'identity').items():
        record = last_attempt(attempts)
        require(record['request']['source_id'] == 'historical-service-categories', 'Unexpected classification source')
        if not record['ok']:
            continue
        asked = set(record['request']['addresses'])
        require(len(asked) == len(record['request']['addresses']) <= 100, 'Duplicate/oversized identity query')
        for row in record['body']:
            require(row['address'] in asked, 'Unrequested service classification')
            require(row['address'] not in classifications or classifications[row['address']] == row,
                    'Conflicting service classifications')
            classifications[row['address']] = row
        for wallet in asked:
            classifications.setdefault(wallet, {'address': wallet, 'type': 'unknown', 'category': None})
    sql = gzip.decompress((root / 'services/cex.sql.gz').read_bytes()).decode()
    services = set()
    for wallet, _ in re.findall(r"\('solana'\s*,\s*'([^']+)'\s*,\s*'([^']+)'", sql, re.I):
        try:
            address(wallet)
        except ValueError:
            continue
        services.add(wallet)
    services |= {row['address'] for row in loads((root / 'services/issuers.json').read_bytes())['nodes']}
    services |= {wallet for wallet, row in classifications.items()
                 if (row.get('type') or 'unknown') != 'unknown' and row.get('category') in SERVICE_CATEGORIES}
    require({row['funder'] for row in funders.values() if row['status'] == 'resolved'} <= set(classifications),
            'Missing first-funder classification lookup')
    by_funder = defaultdict(list)
    for wallet, row in funders.items():
        if row['status'] == 'resolved' and row['funder'] not in services:
            by_funder[row['funder']].append(wallet)
    clusters = {funder: sorted(members) for funder, members in by_funder.items() if len(members) >= 10}
    latest, activity, accounts = {}, defaultdict(dict), {}
    wanted = {wallet for members in clusters.values() for wallet in members}
    for key, attempts in jobs(root, 'latest').items():
        record = last_attempt(attempts)
        if not record['ok']:
            continue
        wallet = record['request']['params'][0]
        if wallet not in wanted:
            continue
        check_request(record['request'], request(wallet, order='desc'))
        check_page(record['body']['result'], 'desc', 10)
        require(wallet not in latest, 'Duplicate latest history job')
        latest[wallet] = [(dest, asset, amount, item['slot'])
                          for item in tx_items([record['body']['result']])
                          for dest, asset, amount in outflows(wallet, item)]
    require(wanted <= set(latest), 'Missing cluster return sample')
    for key, attempts in jobs(root, 'activity').items():
        record = last_attempt(attempts)
        _, wallet, order = key.split(':')
        if wallet not in clusters:
            continue
        require(record['ok'], 'Missing funder activity sample')
        check_request(record['request'], request(wallet, order=order, signatures=True,
                                                limit=1000 if order == 'desc' else 1))
        check_page(record['body']['result'], order, 1000 if order == 'desc' else 1, full=False)
        require(order not in activity[wallet], 'Duplicate activity order')
        activity[wallet][order] = record['body']['result']['data']
    for key, attempts in jobs(root, 'accounts').items():
        record = last_attempt(attempts)
        if not record['ok']:
            continue
        require(record['request']['method'] == 'getMultipleAccounts', 'Unexpected account lookup')
        require(record['request']['params'][1] == {'encoding': 'base64', 'commitment': 'finalized',
                    'dataSlice': {'offset': 0, 'length': 0}} and
                record['body']['result']['context']['slot'] >= 458146998, 'Account query outside disclosed scope')
        asked = record['request']['params'][0]
        values = record['body']['result']['value']
        require(len(asked) == len(set(asked)) == len(values) and len(asked) <= 100, 'Account response length differs')
        for wallet, account in zip(asked, values):
            require(wallet not in accounts or accounts[wallet] == account, 'Conflicting account ownership capture')
            accounts[wallet] = account
    reach_global = defaultdict(set)
    for wallet in listed:
        for destination, _, _, _ in flows[wallet] + latest.get(wallet, []):
            reach_global[destination].add(wallet)
    metrics, reasons, excluded_clusters = [], {}, 0
    for funder, members in sorted(clusters.items()):
        n = len(members)
        rows = [funders[wallet] for wallet in members]
        amounts = sorted(row['lamports'] for row in rows)
        median = amounts[(n - 1) // 2]
        near = sum(abs(amount - median) * 100 <= median * 2 for amount in amounts)
        times = sorted(row['block_time'] for row in rows if row.get('block_time') is not None)
        w24, w7 = max_window(times, DAY), max_window(times, 7 * DAY)
        back, reach = set(), defaultdict(set)
        for wallet in members:
            for destination, _, _, _ in flows[wallet] + latest[wallet]:
                if destination == funder:
                    back.add(wallet)
                if destination not in (wallet, funder):
                    reach[destination].add(wallet)
        sinks = sorted((destination for destination, wallets in reach.items()
                        if len(wallets) >= 3 and destination not in services
                        and len(wallets) * 2 >= len(reach_global[destination])),
                       key=lambda destination:(-len(reach[destination]), destination))
        require({destination for destination, wallets in reach.items() if len(wallets) >= 3} <= set(classifications),
                'Missing possible common-sink service classification')
        if sinks:
            back |= reach[sinks[0]]
        require(funder in activity and 'desc' in activity[funder], 'Missing funder hot-wallet sample')
        signatures = activity[funder]['desc']
        timestamps = [row['blockTime'] for row in signatures if row.get('blockTime') is not None]
        span = max(timestamps) - min(timestamps) if len(timestamps) > 1 else 0
        busy = len(signatures) >= 1000 and span <= DAY
        require(funder in accounts, 'Missing funder account ownership')
        account = accounts[funder]
        controller = on_curve(address(funder)) or bool(account and account['owner'] == SYSTEM)
        hits = rule_hits(n, near, w24, w7, len(back), controller, busy)
        metrics.append(dict(funder=funder, members=members, wallets=n, amount_median_lamports=median,
                            near_identical_count=near, max_in_24h=w24, max_in_7d=w7,
                            returned_count=len(back), common_sink=sinks[0] if sinks else None,
                            funder_activity_count=len(signatures), funder_activity_span_seconds=span,
                            controller=controller, busy=busy, rules=hits))
        if hits:
            excluded_clusters += 1
            for wallet in members:
                reasons[wallet] = dict(wallet=wallet, funder=funder, rules=hits, role='funded wallet')
    funded = len(reasons)
    for row in metrics:
        funder = row['funder']
        if row['rules'] and funder in listed_set and funder not in reasons:
            reasons[funder] = dict(wallet=funder, funder=funder, rules=row['rules'], role='cluster funder')
    final = {key: [wallet for wallet in rows if wallet not in reasons] for key, rows in groups.items()}
    outputs = {'excluded-wallets.txt': wallet_bytes(sorted(reasons)),
               'excluded.jsonl': b''.join(canonical(reasons[wallet]) for wallet in sorted(reasons)),
               'clusters.jsonl': b''.join(canonical(row) for row in metrics),
               'funders.jsonl': b''.join(canonical(funders[wallet]) for wallet in listed)}
    receipt = dict(resolved=status['resolved'], unknown=status['unknown'], failed=status['failed'],
                   clusters=len(clusters), excluded_clusters=excluded_clusters, excluded_funded_members=funded,
                   excluded_listed_funders=len(reasons) - funded, exclusions=len(reasons),
                   removed_memberships=sum(len(groups[key]) - len(final[key]) for key in groups))
    return final, outputs, receipt
