"""Rebuild beneficiaries from captured histories, role schemas and account checks."""
from collections import Counter, defaultdict
import hashlib
from pathlib import Path
import re
from .core import canonical, decode58, encode58, loads, on_curve, require, wallet_bytes
from .capture_store import Bundle
from . import symmetry_decoder as dec
from .symmetry_history import fresh_capture, fresh_history
from . import holder_common as holder
from .symmetry_abi import declarations

SELECTED = {
    'buyFund': ('buyer', 'address', 'amount'), 'sellFund': ('seller', 'address', 'amount'),
    'instantBurn': ('seller', 'address', 'amount'), 'mintFund': ('buyer', 'address', 'mint'),
    'instantMint': ('buyerFundTokenAccount', 'token_owner', 'array20'),
    'singleTokenDeposit': ('buyerFundTokenAccount', 'token_owner', 'single'),
    'claimToken': ('sellerTokenAccount', 'token_owner', 'transfer'),
    'claimTokenFromBuyState': ('buyerTokenAccount', 'token_owner', 'transfer'),
}


def idl_address(program):
    key = decode58(program)
    for bump in range(255, -1, -1):
        base = hashlib.sha256(bytes([bump]) + key + b'ProgramDerivedAddress').digest()
        if not on_curve(base):
            return encode58(hashlib.sha256(base + b'anchor:idl' + key).digest())
    raise ValueError('Cannot derive IDL address')


def registry(root, reference):
    source = loads((root / 'role-sources.json').read_bytes())
    require(source['legacy_authority'] == dec.LEGACY_AUTHORITY, 'Published authority differs')
    proof = source['onchain_legacy_idl']
    require(proof['owner'] == dec.LEGACY and not proof['executable'] and
            proof['context_slot'] >= reference['reference_slot'] and
            proof['request']['params'] == [idl_address(dec.LEGACY), {'commitment': 'finalized',
                'encoding': 'base64', 'minContextSlot': reference['reference_slot']}], 'Invalid IDL capture')
    fixed = {'systemProgram': dec.SYSTEM, 'tokenProgram': dec.TOKEN, 'pdaAccount': dec.LEGACY_AUTHORITY}
    result = defaultdict(list)
    for label, schema in [('published_sdk_0.1.80', source['sdk_legacy_idl']),
                          ('captured_onchain_idl', proof['idl'])]:
        seen = set()
        for ix in schema['instructions']:
            require(ix['name'] in SELECTED and ix['name'] not in seen, 'Duplicate/unknown selected IDL rule')
            seen.add(ix['name'])
            name, kind, check = SELECTED[ix['name']]
            accounts = [row['name'] for row in ix['accounts']]
            require('pdaAccount' in accounts, 'Legacy authority role missing')
            rule = dict(name=ix['name'], position=accounts.index(name), kind=kind,
                        amount_check=check, schema=label,
                        fixed_accounts={str(i): fixed[a] for i, a in enumerate(accounts) if a in fixed})
            if check == 'mint':
                rule['destination_position'] = accounts.index('buyerFundTokenAccount')
            relevant = [rule['position'], *map(int, rule['fixed_accounts'])]
            if 'destination_position' in rule:
                relevant.append(rule['destination_position'])
            rule['minimum_accounts'] = max(relevant) + 1
            snake = re.sub(r'(?<!^)(?=[A-Z])', '_', ix['name']).lower()
            result[(dec.LEGACY, hashlib.sha256(('global:' + snake).encode()).digest()[:8])].append(rule)
        require(seen == set(SELECTED), 'Incomplete legacy role schema')
    abi = declarations(*[(root / 'sources' / (name + '.cjs.source')).read_text()
                         for name in ('symmetry-v3-deposit', 'symmetry-v3-withdraw')])
    require(abi == source['v3_declarations'], 'V3 ABI projection differs from SDK declarations')
    for row in abi:
        result[(dec.V3, bytes.fromhex(row['discriminator']))] = row['rule']
    require(source['v3_version'] == '1.0.22', 'Unexpected V3 rule version')
    return result


def derive(package, reference):
    root = Path(package) / 'data/symmetry'
    bundle = Bundle(package)
    fresh_root, old_root = Path('data/symmetry/fresh'), Path('data/symmetry/legacy')
    scope = loads((root / 'scope.json').read_bytes())
    plan = loads((root / 'legacy-plan.json').read_bytes())
    dec.validate_authority_plan(plan)
    rules = registry(root, reference)
    slot, timestamp = reference['reference_slot'], reference['reference_block_time']
    require(scope['fresh']['legacy_authority_history']['slot'] == {'gte': 447525401, 'lt': slot + 1},
            'Legacy history gap')
    sources = [('fresh', dec.V3, scope['fresh']['v3_history'], dec.V3)]
    sources += [('legacy', dec.LEGACY, spec, None) for spec in plan['segments']]
    sources += [('fresh', dec.LEGACY, scope['fresh']['legacy_authority_history'], dec.LEGACY_AUTHORITY)]
    seen, by_owner, skips, segments, authority_new = set(), defaultdict(list), Counter(), [], set()
    for origin, program, spec, key in sources:
        folder = fresh_root if origin == 'fresh' else old_root
        iterator = (fresh_history(bundle, folder, dict(spec), slot, timestamp, require_key=key)
                    if origin == 'fresh' else dec.history(bundle, folder, spec['name'],
                        slot_interval=spec['slot'], authority_history=True,
                        prefix=spec.get('history_mode') == 'verified_descending_prefix'))
        count = 0
        for page, tx in iterator:
            require(tx['meta']['err'] is None, 'Unsuccessful history transaction')
            signature = tx['transaction']['signatures'][0]
            require((program, signature) not in seen, 'Duplicate/overlapping transaction')
            seen.add((program, signature))
            if origin == 'fresh' and program == dec.LEGACY:
                authority_new.add(signature)
            events, skipped = dec.transaction_events(tx, program, rules)
            skips.update(skipped)
            for event in events:
                event['capture'] = (folder / (page + '.json.gz')).as_posix()
                by_owner[event['wallet']].append(event)
            count += 1
        segments.append(dict(source=spec['name'], transactions=count))
    cross_only, cross_events = 0, 0
    spec = scope['fresh']['legacy_program_crosscheck']
    for _, tx in fresh_history(bundle, fresh_root, dict(spec), slot, timestamp, require_key=dec.LEGACY):
        require(tx['meta']['err'] is None, 'Unsuccessful program cross-check transaction')
        if tx['transaction']['signatures'][0] not in authority_new:
            cross_only += 1
            cross_events += len(dec.transaction_events(tx, dec.LEGACY, rules)[0])
    require(cross_events == 0, 'Program-only history contains unaccounted qualifying events')
    for spec in scope['tail_rechecks']:
        newest = bundle.json(fresh_root / (spec['after'] + '-coverage.json'))['slot_range'][1]
        require(spec['slot']['gte'] == newest + 1, 'Tail query has a coverage gap')
        require(sum(1 for _ in fresh_history(bundle, fresh_root, dict(spec), slot, timestamp,
                                            require_key=spec['address'])) == 0, 'Missing tail transactions')
    accounts, contexts = {}, []
    for path in sorted((root / 'fresh').glob('owner-check-*.json.gz')):
        body, record = fresh_capture(bundle, fresh_root, path.name.removesuffix('.json.gz'), timestamp)
        rpc = record['job']['rpc']
        require(rpc['method'] == 'getMultipleAccounts' and rpc['params'][1] == {
            'encoding': 'base64', 'dataSlice': {'offset': 0, 'length': 1},
            'commitment': 'finalized', 'minContextSlot': slot}, 'Unexpected owner-check request')
        require(body['result']['context']['slot'] >= slot and
                len(rpc['params'][0]) == len(body['result']['value']), 'Incomplete/old owner check')
        contexts.append(body['result']['context']['slot'])
        for wallet, account in zip(rpc['params'][0], body['result']['value']):
            require(wallet not in accounts, 'Duplicate owner check')
            accounts[wallet] = account
    services, _ = holder.exclusion_registry(bundle, Path('data/legacy-services'))
    require(services == loads((Path(package) / 'expected/legacy-services.json').read_bytes()),
            'Reconstructed frozen service registry differs')
    decisions, wallets = [], []
    for wallet, events in sorted(by_owner.items()):
        decision = dec.classify(wallet, services, {}, accounts)
        require(decision != 'pending_owner_check', 'Missing beneficiary owner check')
        if decision == 'included':
            wallets.append(wallet)
        decisions.append(dict(wallet=wallet, decision=decision, qualifying_actions=len(events),
                              events=sorted(events, key=lambda e: (e['slot'], e['signature'], e['instruction_location']))))
    return {'wallets.txt': wallet_bytes(wallets), 'decisions.jsonl': b''.join(canonical(row) for row in decisions)}, {
        'wallets': len(wallets), 'candidates': len(decisions), 'transactions': len(seen), 'segments': segments,
        'program_only_crosscheck_transactions': cross_only, 'program_only_qualifying_events': cross_events,
        'skipped_instructions': dict(skips), 'owner_context_slot_range': [min(contexts), max(contexts)],
        'source_limit': 'Published SDK/on-chain IDL projections and unsigned provider history captures; complete cursor traversal is provider-relative.'}
