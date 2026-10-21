"""Reviewed historical attribution and history-validation functions.
Historical deterministic method adapted for public replay.
No previous wallet list or live collection dependency.
"""
from collections import Counter
import copy
from .core import address, decode58, canonical, require, on_curve as _on_curve
LEGACY='2KehYt3KsEQR53jYcxjbQp2d2kCp4AkuQW68atufRwSr'
V3='BASKT7aKd8n7ibpUbwLP3Wiyxyi3yoiXsxBk4Hpumate'
TOKEN='TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA'
TOKEN22='TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb'
SYSTEM='11111111111111111111111111111111'
LEGACY_AUTHORITY='BLBYiq48WcLQ5SxiftyKmPtmsZPUBEnDEjqEnKGAR4zx'
def on_curve(wallet):
    return _on_curve(decode58(wallet))
def wallet_bytes(wallet):
    address(wallet)
    return decode58(wallet)
def nonzero_args(raw, kind):
    offsets = {'amount': (8, 8), 'single': (9, 8), 'array10': (8, 80), 'array20': (8, 160)}
    if kind not in offsets:
        return None
    (offset, size) = offsets[kind]
    require(len(raw) >= offset + size, 'Truncated user instruction')
    return any(raw[offset:offset + size])

def positive_token_effect(children, keys, destination, kind):
    for ix in children:
        if keys[ix['programIdIndex']] not in {TOKEN, TOKEN22}:
            continue
        raw = decode58(ix['data'])
        if len(raw) < 9 or int.from_bytes(raw[1:9], 'little') == 0:
            continue
        opcode = raw[0]
        if kind == 'mint' and opcode in {7, 14} and (ix['accounts'][1] in destination):
            return True
        if kind == 'transfer' and opcode in {3, 12}:
            index = 1 if opcode == 3 else 2
            if ix['accounts'][index] in destination:
                return True
    return False

def transaction_events(tx, program, registry):
    if tx['meta']['err'] is not None:
        return ([], Counter({'failed_transaction': 1}))
    (msg, meta) = (tx['transaction']['message'], tx['meta'])
    loaded = meta.get('loadedAddresses') or {}
    keys = msg['accountKeys'] + loaded.get('writable', []) + loaded.get('readonly', [])
    require(all((isinstance(k, str) for k in keys)), 'Expected raw transaction keys')
    groups = {g['index']: g['instructions'] for g in meta.get('innerInstructions') or []}
    token_balances = meta.get('preTokenBalances', []) + meta.get('postTokenBalances', [])
    instructions = []
    for (top, ix) in enumerate(msg['instructions']):
        children = groups.get(top, [])
        instructions.append((str(top), ix, children, True))
        for (inner, child) in enumerate(children):
            height = child.get('stackHeight')
            subtree = []
            if height is not None:
                for following in children[inner + 1:]:
                    if following.get('stackHeight') is None or following['stackHeight'] <= height:
                        break
                    subtree.append(following)
            instructions.append((f'{top}.{inner}', child, subtree, height is not None))
    (events, skipped) = ([], Counter())
    for (location, ix, children, subtree_known) in instructions:
        if keys[ix['programIdIndex']] != program:
            continue
        raw = decode58(ix['data'])
        variants = registry.get((program, raw[:8]))
        if variants is None:
            skipped['non_qualifying_instruction:' + raw[:8].hex()] += 1
            continue
        if isinstance(variants, dict):
            variants = [variants]
        matches = [r for r in variants if len(ix['accounts']) >= r.get('minimum_accounts', 0) and all((keys[ix['accounts'][int(i)]] == address for (i, address) in r.get('fixed_accounts', {}).items()))]
        if not matches:
            skipped['unresolved_account_layout:' + variants[0]['name']] += 1
            continue
        comparable = ['name', 'position', 'kind', 'amount_check', 'destination_position']
        require(len({canonical({k: r.get(k) for k in comparable}) for r in matches}) == 1, 'Ambiguous instruction account layout')
        rule = matches[-1]
        account_index = ix['accounts'][rule['position']]
        if rule['kind'] == 'token_owner':
            owners = {b['owner'] for b in token_balances if b['accountIndex'] == account_index and b.get('owner')}
            if len(owners) != 1:
                skipped['unresolved_receipt_owner'] += 1
                continue
            owner = owners.pop()
        else:
            owner = keys[account_index]
        wallet_bytes(owner)
        effect = nonzero_args(raw, rule['amount_check'])
        evidence_type = 'positive_instruction_amount'
        if effect is None:
            evidence_type = 'positive_inner_token_effect'
            if not subtree_known:
                skipped['unresolved_inner_instruction_tree'] += 1
                continue
            if rule['amount_check'] == 'mint':
                dest = {ix['accounts'][rule['destination_position']]}
                recorded_owners = {b['owner'] for b in token_balances if b['accountIndex'] in dest and b.get('owner')}
                if recorded_owners and recorded_owners != {owner}:
                    skipped['unresolved_mint_beneficiary_mismatch'] += 1
                    continue
                effect = positive_token_effect(children, keys, dest, 'mint')
            elif rule['amount_check'] == 'transfer':
                effect = positive_token_effect(children, keys, {account_index}, 'transfer')
            else:
                dest = {ix['accounts'][i] for i in range(9, len(ix['accounts']), 3)}
                effect = positive_token_effect(children, keys, dest, 'transfer')
        if not effect:
            skipped['zero_or_unproven_amount:' + rule['name']] += 1
            continue
        events.append({'wallet': owner, 'program': program, 'instruction': rule['name'], 'account_schema': rule.get('schema', 'published_v3_sdk_1.0.22'), 'instruction_location': location, 'amount_evidence': evidence_type, 'signature': tx['transaction']['signatures'][0], 'slot': tx['slot'], 'block_time': tx.get('blockTime')})
    return (events, skipped)

def history(inputs, root, name, slot_interval=None, authority_history=False, prefix=False):
    coverage = inputs.json(root / (name + '-coverage.json'))
    template = inputs.json(root / (name + '-template.json'))
    require(coverage['complete'] and (prefix or coverage['next_cursor'] is None), 'History incomplete: ' + name)
    options = template['rpc']['params'][1]
    address = LEGACY_AUTHORITY if authority_history else V3 if '-v3-' in name else LEGACY
    require(template['rpc']['method'] == 'getTransactionsForAddress' and template['rpc']['params'][0] == address and (options['commitment'] == 'finalized') and (options['sortOrder'] == 'desc') and (options['filters']['status'] == 'succeeded'), 'Wrong history scope')
    if authority_history:
        if prefix:
            query_interval = options['filters']['slot']
            require(slot_interval and query_interval['gte'] <= slot_interval['gte'] and (query_interval['lt'] == slot_interval['lt']) and (options['filters'] == {'status': 'succeeded', 'slot': query_interval}), 'Wrong prefix query scope')
            require(coverage['complete_scope'] == 'declared_slot_interval' and coverage['membership_slot_range'] == slot_interval, 'Wrong prefix membership scope')
        else:
            query_interval = slot_interval
            require(options['filters'] == {'status': 'succeeded', 'slot': slot_interval or {'lte': 447525400}}, 'Wrong authority-history scope')
    elif slot_interval:
        require(options['filters'] == {'status': 'succeeded', 'slot': slot_interval}, 'Wrong slot range')
    else:
        require(options['filters']['slot'] == {'lte': 447525400} and options['filters']['blockTime'] == ({'lt': 1781786586} if 'earlier' in name else {'gte': 1781786586}), 'History boundary changed')
    (cursor, seen_cursors, count, slots) = (None, set(), 0, [])
    for (i, page) in enumerate(coverage['pages']):
        expected = copy.deepcopy(template)
        expected['name'] += '-page-' + str(i)
        require(page == expected['name'], 'Missing/reordered history page')
        if cursor is not None:
            expected['rpc']['params'][1]['paginationToken'] = cursor
        (data, record) = inputs.capture(root, page)
        require(record['job'] == expected, 'Broken history request chain')
        result = data['result']
        for tx in result['data']:
            require(tx['slot'] <= 447525400 and tx['blockTime'] is not None, 'Out-of-scope transaction')
            if authority_history:
                loaded = tx['meta'].get('loadedAddresses') or {}
                keys = tx['transaction']['message']['accountKeys'] + loaded.get('writable', []) + loaded.get('readonly', [])
                require(LEGACY_AUTHORITY in keys, 'Authority missing from returned transaction')
                if query_interval:
                    require(query_interval['gte'] <= tx['slot'] < query_interval['lt'], 'Wrong authority slot interval')
            elif slot_interval:
                require(slot_interval['gte'] <= tx['slot'] < slot_interval['lt'] and tx['blockTime'] < 1781786586, 'Wrong slot interval')
            else:
                require((tx['blockTime'] < 1781786586) == ('earlier' in name), 'Wrong history time interval')
            require(not slots or tx['slot'] <= slots[-1], 'History is not descending')
            slots.append(tx['slot'])
            count += 1
            if prefix and tx['slot'] < slot_interval['gte']:
                require(i == len(coverage['pages']) - 1, 'Page after prefix boundary')
            else:
                yield (page, tx)
        cursor = result.get('paginationToken')
        if cursor is None:
            require(i == len(coverage['pages']) - 1, 'Page after terminal cursor')
        else:
            require(cursor not in seen_cursors, 'Repeated history cursor')
            seen_cursors.add(cursor)
    if prefix and cursor is not None:
        require(slots and slots[-1] < slot_interval['gte'] and (coverage['termination'] == 'crossed_lower_slot_bound'), 'Prefix stopped before boundary')
    else:
        require(cursor is None, 'History cursor is not terminal')
    require(coverage['pages'] and cursor == coverage['next_cursor'] and (count == coverage['returned_rows']), 'Incomplete history')
    require(coverage['slot_range'] == ([min(slots), max(slots)] if slots else None), 'Wrong history slot range')

def classify(wallet, excluded, previous, accounts):
    if wallet in excluded:
        return excluded[wallet]
    if not on_curve(wallet):
        return 'off_curve_pda'
    if wallet in previous:
        return previous[wallet]
    if wallet not in accounts:
        return 'pending_owner_check'
    a = accounts[wallet]
    if a and a['executable']:
        return 'executable_account'
    if a and a['owner'] != SYSTEM:
        return 'program_owned_account'
    if a and (a.get('space', 0) != 0 or a['data'][0]):
        return 'system_account_with_data'
    return 'included'

def validate_authority_plan(plan):
    require(plan['address'] == LEGACY_AUTHORITY, 'Wrong legacy authority')
    upper = 0
    seen_names = set()
    for segment in plan['segments']:
        require(segment.get('history_mode', 'terminal_cursor') in {'terminal_cursor', 'verified_descending_prefix'}, 'Unknown history mode')
        interval = segment['slot']
        require(type(interval['gte']) is int and type(interval['lt']) is int and (interval['gte'] == upper) and (interval['lt'] > upper), 'Gap or overlap in authority history ranges')
        require(segment['name'] not in seen_names, 'Repeated history segment')
        seen_names.add(segment['name'])
        upper = interval['lt']
    require(upper == 447525401, 'History does not cover the complete cutoff range')
