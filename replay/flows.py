"""Historical deterministic transaction attribution, extracted without live client.
Historical deterministic method adapted for public replay.
"""
from .core import canonical, require

SYSTEM = '11111111111111111111111111111111'
TOKEN = 'TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA'
TOKEN22 = 'TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb'
WSOL = 'So11111111111111111111111111111111111111112'
SYSTEM_INFLOW = {'transfer': ('source', 'destination'), 'transferWithSeed': ('source', 'destination'), 'createAccount': ('source', 'newAccount'), 'createAccountWithSeed': ('source', 'newAccount')}

def tx_items(pages):
    """Concatenate saved pages, drop duplicates by signature, order by (slot, transactionIndex)."""
    (seen, items) = ({}, [])
    for page in pages:
        for item in page['data']:
            signature = item['transaction']['signatures'][0]
            if signature in seen:
                require(item == seen[signature], 'Conflicting duplicate transaction')
            if signature not in seen:
                seen[signature] = item
                items.append(item)
    items.sort(key=lambda item: (item['slot'], item.get('transactionIndex', 0)))
    return items

def keys_of(item):
    return [key['pubkey'] if isinstance(key, dict) else key for key in item['transaction']['message']['accountKeys']]

def instructions(item):
    """Yield ((top_index, inner_index or None), instruction) in execution order."""
    inner = {}
    for group in (item.get('meta') or {}).get('innerInstructions') or []:
        inner[group['index']] = group['instructions']
    for (index, instruction) in enumerate(item['transaction']['message']['instructions']):
        yield ((index, None), instruction)
        for (sub, child) in enumerate(inner.get(index, [])):
            yield ((index, sub), child)

def lamport_deltas(item):
    (keys, meta) = (keys_of(item), item['meta'])
    return {key: post - pre for (key, pre, post) in zip(keys, meta['preBalances'], meta['postBalances'])}

def first_inflow(wallet, item):
    """The first native SOL inflow to `wallet` in one transaction, or None.

    Order of evidence inside the transaction: (1) the first system transfer / transferWithSeed /
    createAccount(WithSeed) credited to the wallet from another account, top-level or inner (CPI), in
    execution order; (2) else the first token closeAccount whose lamports go to the wallet from an
    account it does not own (wrapped-SOL / rent unwrap by another party: the closing owner is the
    sender); (3) else, if the wallet's lamport balance rose, the account with the largest lamport
    decrease (the fee payer's fee added back) is recorded as the source ("balance_delta"); when that
    account is a token account (wrapped SOL), its owner is recorded instead ("balance_delta_token_owner").
    """
    keys = keys_of(item)
    if wallet not in keys or not item.get('meta') or item['meta'].get('preBalances') is None:
        return None
    deltas = lamport_deltas(item)
    fee_payer = keys[0]
    base = {'signature': item['transaction']['signatures'][0], 'slot': item['slot'], 'transaction_index': item.get('transactionIndex'), 'block_time': item.get('blockTime'), 'fee_payer': fee_payer, 'wallet_lamport_delta': deltas.get(wallet, 0)}
    close = None
    for (position, instruction) in instructions(item):
        parsed = instruction.get('parsed')
        if not isinstance(parsed, dict):
            continue
        (kind, info) = (parsed.get('type'), parsed.get('info') or {})
        program = instruction.get('programId')
        if program == SYSTEM and kind in SYSTEM_INFLOW:
            (source_key, target_key) = SYSTEM_INFLOW[kind]
            lamports = int(info.get('lamports') or 0)
            if info.get(target_key) == wallet and info.get(source_key) not in (None, wallet) and (lamports > 0):
                return dict(base, funder=info[source_key], method='system_' + kind, lamports=lamports, level='top' if position[1] is None else 'inner', position=list(position))
        if close is None and program in (TOKEN, TOKEN22) and (kind == 'closeAccount') and (info.get('destination') == wallet):
            owner = info.get('owner') or info.get('multisigOwner')
            if owner and owner != wallet:
                closed = info.get('account')
                lamports = -deltas.get(closed, 0) if closed in deltas else 0
                if lamports > 0:
                    close = dict(base, funder=owner, method='token_close_account', lamports=lamports, level='top' if position[1] is None else 'inner', position=list(position), closed_account=closed)
    if close:
        return close
    if deltas.get(wallet, 0) > 0:
        fee = item['meta'].get('fee') or 0
        (best, best_delta) = (None, 0)
        for key in keys:
            if key == wallet:
                continue
            delta = deltas.get(key, 0) + (fee if key == fee_payer else 0)
            if delta < best_delta:
                (best, best_delta) = (key, delta)
        if best is not None:
            owner = token_owner_map(item).get(best, (None, None))[0]
            if owner and owner != wallet:
                return dict(base, funder=owner, method='balance_delta_token_owner', lamports=deltas[wallet], level='tx', position=None, token_account=best)
            return dict(base, funder=best, method='balance_delta', lamports=deltas[wallet], level='tx', position=None)
        return dict(base, funder=None, method='unattributed_inflow', lamports=deltas[wallet], level='tx', position=None)
    return None

def find_funder(wallet, items):
    """(inflow-or-None, tx_depth_scanned). Scans transactions in order and stops at the first inflow."""
    for (depth, item) in enumerate(items, 1):
        found = first_inflow(wallet, item)
        if found:
            found['tx_rank'] = depth
            return (found, depth)
    return (None, len(items))

def token_owner_map(item):
    keys = keys_of(item)
    owners = {}
    meta = item.get('meta') or {}
    for row in (meta.get('preTokenBalances') or []) + (meta.get('postTokenBalances') or []):
        index = row.get('accountIndex')
        if index is not None and index < len(keys) and row.get('owner'):
            owners[keys[index]] = (row['owner'], row.get('mint'))
    return owners

def outflows(wallet, item):
    """Outgoing native SOL and SPL token transfers authorised by `wallet` in one transaction.

    Returns [(destination_owner_or_account, asset, raw_amount)]; asset is "SOL" or the mint. The
    destination of a token transfer is resolved to the owner of the receiving token account when the
    transaction's token balances name it."""
    rows = []
    owners = None
    for (_, instruction) in instructions(item):
        parsed = instruction.get('parsed')
        if not isinstance(parsed, dict):
            continue
        (kind, info) = (parsed.get('type'), parsed.get('info') or {})
        program = instruction.get('programId')
        if program == SYSTEM and kind in ('transfer', 'transferWithSeed'):
            if info.get('source') == wallet and info.get('destination') not in (None, wallet):
                lamports = int(info.get('lamports') or 0)
                if lamports > 0:
                    rows.append((info['destination'], 'SOL', lamports))
        elif program in (TOKEN, TOKEN22) and kind in ('transfer', 'transferChecked'):
            authority = info.get('authority') or info.get('multisigAuthority')
            if authority != wallet:
                continue
            if owners is None:
                owners = token_owner_map(item)
            destination = info.get('destination')
            (owner, mint) = owners.get(destination, (destination, info.get('mint')))
            amount = info.get('amount')
            if amount is None and isinstance(info.get('tokenAmount'), dict):
                amount = info['tokenAmount'].get('amount')
            mint = info.get('mint') or mint or 'unknown_mint'
            if owner != wallet and amount is not None and (int(amount) > 0):
                rows.append((owner, mint, int(amount)))
    return rows
