"""Full credential discovery, raw proof and exact native/wrapped funds replay."""
import gzip
from pathlib import Path
from .core import account_data, address, canonical, encode58, loads, require, wallet_bytes
from .solfate import extension_map, pda

TOKEN = 'TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA'
TOKEN22 = 'TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb'
GROUP = 'GT22s89nU4iWFkNXj1Bw6uYhJJWDRPpShHt4Bk8f99Te'
WSOL = 'So11111111111111111111111111111111111111112'
WSOL22 = '9pan9bMn5HatX4EJdBwg9VgCa7Uz5HL8N1m5D3NdXejP'
SYSTEM = '11111111111111111111111111111111'
ATA = 'ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL'
URI = 'https://r2.solanamobiledappstore.com/skr/sgt-metadata.json'


def token_data(account):
    require(account and account['owner'] == TOKEN22, 'Credential account is not Token-2022')
    return account_data(account)


def verify_mint(mint, account):
    raw = token_data(account)
    require(len(raw) >= 82 and raw[45] == 1 and raw[44] == 0
            and int.from_bytes(raw[36:44], 'little') == 1, 'Invalid live zero-decimal credential')
    extensions = extension_map(raw)
    pointer, member = extensions.get(18, b''), extensions.get(23, b'')
    require(len(pointer) == 64 and pointer[32:] == address(GROUP), 'Wrong official metadata pointer')
    require(len(member) == 72 and member[:32] == address(mint)
            and member[32:64] == address(GROUP), 'Wrong official self/group membership')
    return int.from_bytes(member[64:72], 'little')


def verify_holder(mint, wallet, account):
    raw = token_data(account)
    require(len(raw) >= 165 and raw[108] in (1, 2) and (len(raw) == 165 or raw[165] == 2),
            'Invalid credential token account')
    require(raw[:32] == address(mint) and raw[32:64] == address(wallet)
            and int.from_bytes(raw[64:72], 'little') == 1, 'Credential holder/mint/balance differs')


def derive(root, reference):
    captures = {}
    with gzip.open(Path(root) / 'captures.jsonl.gz', 'rt') as handle:
        for line in handle:
            row = loads(line)
            require(row['label'] not in captures, 'Duplicate capture label')
            if row['ok'] and 'result' in row['body']:
                captures[row['label']] = (row['request'], row['body']['result'])
    indexed, discovery = {}, {}
    def largest(mint):
        request, result = captures['largest-' + mint]
        require(request['method'] == 'getTokenLargestAccounts' and request['params'] ==
                [mint, {'commitment': 'finalized'}], 'Largest-holder query scope differs')
        require(result['context']['slot'] >= reference['reference_slot'], 'Largest-holder read predates reference')
        holders = [row['address'] for row in result['value'] if row['amount'] == '1']
        require(len(holders) <= 1, 'Credential has conflicting largest holders')
        return holders[0] if holders else None
    def holder_account(mint, holder, encoding, label):
        request, result = captures[label + mint]
        require(request['method'] == 'getMultipleAccounts' and request['params'] ==
                [[holder], {'commitment': 'finalized', 'encoding': encoding}], 'Credential holder query differs')
        require(result['context']['slot'] >= reference['reference_slot'] and len(result['value']) == 1,
                'Credential holder proof incomplete or old')
        return result['value'][0]
    for label, (request, result) in sorted(captures.items()):
        if request['method'] == 'searchAssets':
            params = request['params']
            expected = {'jsonUri': URI, 'interface': 'V1_NFT', 'frozen': params['frozen'],
                        'compressed': False, 'page': params['page'], 'limit': 1000,
                        'options': {'showGrandTotal': True},
                        'sortBy': {'sortBy': 'created', 'sortDirection': 'asc'}}
            require(params == expected and type(params['frozen']) is bool, 'Credential index scope differs')
            key = (params['frozen'], params['page'])
            require(key not in discovery, 'Duplicate successful issuer page')
            discovery[key] = result
            require(result['page'] == params['page'] and result['limit'] == 1000, 'Issuer page metadata differs')
            if result.get('last_indexed_slot') is not None:
                require(result['last_indexed_slot'] >= reference['reference_slot'], 'Index predates reference')
            for item in result['items']:
                entry = [item['ownership']['owner'],
                         (item.get('token_info') or {}).get('associated_token_address')]
                require(item['id'] not in indexed or indexed[item['id']] == entry,
                        'Conflicting duplicate indexed credential')
                indexed[item['id']] = entry
    for frozen in (True, False):
        pages = sorted((number, result) for (flag, number), result in discovery.items() if flag is frozen)
        require(pages and [number for number, _ in pages] == list(range(1, len(pages) + 1)), 'Issuer page gap')
        require(not pages[-1][1]['items'], 'Issuer discovery lacks terminal empty page')
        short_seen = False
        for _, result in pages:
            count = len(result['items'])
            require(count <= 1000 and (not short_seen or count == 0), 'Issuer pagination continued after short page')
            short_seen |= count < 1000
    for mint, entry in indexed.items():
        if not entry[1] and 'largest-' + mint in captures:
            holder = largest(mint)
            if holder and 'holder-' + mint in captures:
                account = holder_account(mint, holder, 'jsonParsed', 'holder-')
                require(account is None or account['data']['parsed']['info']['mint'] == mint,
                        'Parsed holder proof has wrong mint')
                entry[:] = [account['data']['parsed']['info']['owner'] if account else entry[0], holder]
    verified, decisions = {}, {}
    for label, (request, result) in captures.items():
        if not label.startswith('raw-proof-'):
            continue
        keys = request['params'][0]
        require(len(keys) % 2 == 0 and len(keys) == len(result['value']), 'Invalid raw proof batch')
        require(request['method'] == 'getMultipleAccounts' and request['params'][1] ==
                {'encoding': 'base64', 'commitment': 'finalized'}
                and result['context']['slot'] >= reference['reference_slot'], 'Proof predates reference')
        half = len(keys) // 2
        for index in range(half):
            mint, holder = keys[index], keys[index + half]
            require(mint in indexed and indexed[mint][1] == holder, 'Raw proof not tied to discovery')
            require(mint not in decisions, 'Repeated indexed-mint proof')
            wallet = indexed[mint][0]
            row = {'mint': mint, 'wallet': wallet, 'source_capture': label, 'qualifies': False}
            try:
                member_number = verify_mint(mint, result['value'][index])
                verify_holder(mint, wallet, result['value'][half + index])
                verified[mint] = wallet
                row.update(qualifies=True, member_number=member_number)
            except ValueError:
                row['reason'] = 'closed_or_failed_raw_credential_proof'
            decisions[mint] = row
    require(set(decisions) == set(indexed), 'Missing raw proof for indexed credential candidate')
    pointer_accounts, cursor = {}, None
    pages = sorted(((int(label.rsplit('-', 1)[1]), label, req, result)
                    for label, (req, result) in captures.items() if req['method'] == 'getProgramAccountsV2'))
    for expected_number, (number, label, request, result) in enumerate(pages, 1):
        require(number == expected_number, 'Pointer discovery page gap')
        options = request['params'][1]
        require(options.get('paginationKey') == cursor, 'Pointer discovery cursor mismatch')
        require(request['params'][0] == TOKEN22 and options['commitment'] == 'finalized'
                and options['filters'] == [{'memcmp': {'offset': 202, 'bytes': GROUP}}],
                'Pointer discovery scope differs')
        for row in result['accounts']:
            require(row['pubkey'] not in pointer_accounts, 'Repeated pointer candidate')
            pointer_accounts[row['pubkey']] = row['account']
        cursor = result.get('paginationKey')
    require(pages and cursor is None, 'Pointer discovery did not exhaust pagination')
    extras = sorted(set(pointer_accounts) - set(indexed))
    for mint in extras:
        row = {'mint': mint, 'qualifies': False, 'source_capture': 'pointer-discovery'}
        if 'largest-' + mint in captures and 'holder-raw-' + mint in captures:
            holder = largest(mint)
            require(holder is not None, 'Raw credential holder lacks largest-holder discovery')
            account = holder_account(mint, holder, 'base64', 'holder-raw-')
            if account:
                wallet = encode58(account_data(account)[32:64])
                row['wallet'] = wallet
                try:
                    # Stronger than the original shortcut: verify the raw mint's
                    # official self/group and supply as well as its holder.
                    number = verify_mint(mint, pointer_accounts[mint])
                    verify_holder(mint, wallet, account)
                    verified[mint] = wallet
                    row.update(qualifies=True, member_number=number)
                except ValueError:
                    row['reason'] = 'closed_or_failed_raw_credential_proof'
        decisions[mint] = row
    group_request, group_result = captures['group-account']
    require(group_request['method'] == 'getAccountInfo' and group_request['params'] ==
            [GROUP, {'commitment': 'finalized', 'encoding': 'base64'}] and
            group_result['context']['slot'] >= reference['reference_slot'], 'Official group query differs or predates reference')
    group = token_data(group_result['value'])
    group_extension = extension_map(group).get(21, b'')
    require(len(group_extension) == 80 and group_extension[32:64] == address(GROUP), 'Wrong official group counter')
    issued = int.from_bytes(group_extension[64:72], 'little')
    holders = set(verified.values())
    totals = {}
    def wrapped(account, wallet, mint, program):
        if not account or account['owner'] not in (TOKEN, TOKEN22):
            return 0
        raw = account_data(account)
        if len(raw) < 72:
            return 0
        require(account['owner'] == program and raw[:32] == address(mint) and raw[32:64] == address(wallet),
                'Wrapped-SOL account attribution differs')
        return max(int.from_bytes(raw[64:72], 'little'), account['lamports'] - (len(raw) + 128) * 3480 * 2)
    for label, (request, result) in captures.items():
        if not label.startswith('balances-'):
            continue
        keys, values = request['params'][0], result['value']
        require(request['method'] == 'getMultipleAccounts'
                and request['params'][1] == {'encoding': 'base64', 'commitment': 'finalized'}
                and result['context']['slot'] >= reference['reference_slot'], 'Funds read outside disclosed scope')
        require(len(keys) % 3 == 0 and len(keys) == len(values), 'Invalid funds batch')
        third = len(keys) // 3
        for index in range(third):
            wallet = keys[index]
            require(wallet not in totals, 'Repeated wallet funds observation')
            require(keys[third + index] == pda([address(wallet), address(TOKEN), address(WSOL)], ATA)
                    and keys[2 * third + index] == pda([address(wallet), address(TOKEN22), address(WSOL22)], ATA),
                    'Funds accounts differ from derived ATAs')
            native = values[index]['lamports'] if values[index] and values[index]['owner'] == SYSTEM else 0
            totals[wallet] = native + wrapped(values[third + index], wallet, WSOL, TOKEN) + wrapped(
                values[2 * third + index], wallet, WSOL22, TOKEN22)
    require(holders <= set(totals), 'Missing balance captures for credential holders')
    passing = sorted(wallet for wallet in holders if totals[wallet] >= 100_000_000)
    mints_by_holder = {}
    for mint, wallet in verified.items():
        mints_by_holder.setdefault(wallet, []).append(mint)
    wallet_decisions = [{'wallet': wallet, 'qualifies': totals[wallet] >= 100_000_000,
                         'lamports_native_plus_wrapped': totals[wallet],
                         'credential_mints': sorted(mints_by_holder[wallet])}
                        for wallet in sorted(holders)]
    return {'wallets.txt': wallet_bytes(passing),
            'decisions.jsonl': b''.join(canonical(row) for row in wallet_decisions),
            'credential-decisions.jsonl': b''.join(canonical(decisions[mint]) for mint in sorted(decisions))}, {
        'wallets': len(passing), 'indexed_mints': len(indexed), 'pointer_mints': len(pointer_accounts),
        'verified_live_credentials': len(verified), 'holder_wallets': len(holders), 'group_counter': issued,
        'pointer_pages': len(pages), 'extra_pointer_candidates': len(extras),
        'source_limit': 'Captured issuer/index and finalized collection-window account observations; unsigned provider assertions.'}
