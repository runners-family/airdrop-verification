from .core import utc_epoch
"""Reviewed fresh history validation; reviewed historical method"""
import copy
from datetime import datetime
from .core import require

def epoch(text):
    return utc_epoch(text)

def fresh_capture(inputs, root, name, block_time):
    (data, record) = inputs.capture(root, name)
    require(epoch(record['retrieved_at']) >= block_time, 'Capture predates the snapshot: ' + name)
    return (data, record)

def fresh_history(inputs, root, spec, snapshot_slot, block_time, require_key=None):
    """Validate a fresh descending getTransactionsForAddress chain bounded by spec['slot']."""
    (name, address, slot_filter) = (spec['name'], spec['address'], spec['slot'])
    coverage = inputs.json(root / (name + '-coverage.json'))
    template = inputs.json(root / (name + '-template.json'))
    require(coverage['source'] == name and coverage['complete'] and (coverage['termination'] == 'terminal_cursor') and (coverage['next_cursor'] is None), 'Incomplete fresh history: ' + name)
    expected_template = {'name': name, 'rpc': {'jsonrpc': '2.0', 'id': 1, 'method': 'getTransactionsForAddress', 'params': [address, {'transactionDetails': 'full', 'sortOrder': 'desc', 'limit': 1000, 'maxSupportedTransactionVersion': 1, 'commitment': 'finalized', 'encoding': 'json', 'filters': {'status': 'succeeded', 'slot': slot_filter}}]}}
    require(template == expected_template, 'Unexpected fresh history scope: ' + name)
    low = slot_filter.get('gte', 0)
    high = slot_filter['lt'] if 'lt' in slot_filter else slot_filter['lte'] + 1
    require(high == snapshot_slot + 1, 'Fresh history must end exactly at the snapshot slot: ' + name)
    (cursor, seen_cursors, count, slots, retrieved) = (None, set(), 0, [], [])
    for (i, page) in enumerate(coverage['pages']):
        expected = copy.deepcopy(template)
        expected['name'] += '-page-' + str(i)
        require(page == expected['name'], 'Missing/reordered history page: ' + page)
        if cursor is not None:
            expected['rpc']['params'][1]['paginationToken'] = cursor
        (data, record) = fresh_capture(inputs, root, page, block_time)
        require(record['job'] == expected, 'Broken history request chain: ' + page)
        retrieved.append(record['retrieved_at'])
        result = data['result']
        for tx in result['data']:
            require(low <= tx['slot'] < high and tx['blockTime'] is not None, 'Out-of-scope transaction: ' + page)
            if require_key:
                loaded = tx['meta'].get('loadedAddresses') or {}
                keys = tx['transaction']['message']['accountKeys'] + loaded.get('writable', []) + loaded.get('readonly', [])
                require(require_key in keys, 'Queried address missing from returned transaction')
            require(not slots or tx['slot'] <= slots[-1], 'History is not descending')
            slots.append(tx['slot'])
            count += 1
            yield (page, tx)
        cursor = result.get('paginationToken')
        if cursor is None:
            require(i == len(coverage['pages']) - 1, 'Page after terminal cursor')
        else:
            require(cursor not in seen_cursors, 'Repeated history cursor')
            seen_cursors.add(cursor)
    require(cursor is None and coverage['pages'] and (count == coverage['returned_rows']), 'Incomplete history: ' + name)
    require(coverage['slot_range'] == ([min(slots), max(slots)] if slots else None), 'Wrong history slot range')
    spec['_retrieved_at'] = [min(retrieved), max(retrieved)]
