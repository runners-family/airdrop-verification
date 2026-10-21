"""Historical instruction decoding, extracted without collection/comparison code.
Historical deterministic method adapted for public replay.
"""
import hashlib
from .core import decode58, require

GOV = 'soGovSpYWEyohCPzQu3cwKrvBDBqL4kCbj3kBXvD8LW'
LEGACY = 'sowEL1Rtn3p479rg34gW7mVPeCNY58Es5rkLpFsCJAW'
EXECUTOR = 'tRADeQ3SJVHnFXv1rpwZzVt5HE6DWDu4J6cH34Md6ZA'
SOURCES = {'ride-gov': GOV, 'ride-legacy': LEGACY, 'ride-executor': EXECUTOR}
TOKEN_PROGRAMS = {'spl-token', 'spl-token-2022'}
GOV_TAGS = {0: 'CreateRealm', 1: 'DepositGoverningTokens', 3: 'CreateGovernance', 4: 'CreateProposal', 5: 'InsertInstruction', 6: 'CastVote', 7: 'CastSowellianVote', 8: 'RelinquishVote', 9: 'ExecuteTransaction', 10: 'SetGovernanceConfig', 11: 'SetRealmAuthority', 12: 'SetRealmConfig', 13: 'CreateTokenOwnerRecord', 14: 'CreateNativeTreasury', 16: 'CreateProposalWithTransactions', 17: 'SetGovernanceLimits', 18: 'CloseProposal', 19: 'SetOrUpdateSowellianConfig', 20: 'SetSowellianGovernanceConfig', 21: 'SettleBet', 22: 'ResolveBet', 23: 'WithdrawPayoff', 24: 'CloseReceipt', 25: 'CloseBet', 26: 'CastSecondaryVote', 27: 'CloseSecondary', 29: 'ResolveBetEarly'}
GOV_USER = {4, 16, 7, 26}
GOV_RESOLVER = {22, 29}
ANCHOR_NAMES = ['CastSowellianVote', 'CreateBet', 'CreateProposal', 'WithdrawPayoff', 'SettleBet', 'ResolveBet', 'RegisterVote', 'SignOffProposal', 'CreateVoterWeightRecord', 'CreateRegistrar', 'UpdateRegistrarImpact', 'UpdateRegistrarProposalExecutionLimit', 'ConfigureGovernance', 'CreateIntent', 'ExecuteIntent', 'CloseIntents', 'ReclaimExpired', 'CreatePerpIntent', 'PerpDeposit', 'PerpOpen', 'PerpClose', 'PerpRequestWithdraw', 'PerpFinalize', 'ExecuteIntentBegin', 'ExecuteIntentSettle']
LEGACY_USER = {'CastSowellianVote', 'CreateBet', 'CreateProposal'}

def snake(name):
    return ''.join(('_' + c.lower() if c.isupper() and i else c.lower() for (i, c) in enumerate(name)))
ANCHOR = {hashlib.sha256(('global:' + snake(n)).encode()).digest()[:8]: n for n in ANCHOR_NAMES}

def instruction_name(ix):
    program = ix.get('programId')
    if program not in (GOV, LEGACY, EXECUTOR) or 'data' not in ix:
        return (None, None)
    raw = decode58(ix['data']) if ix['data'] else b''
    if program == GOV:
        return ('ride-gov', GOV_TAGS.get(raw[0], 'gov_tag_%02x' % raw[0]) if raw else 'gov_empty')
    return ('ride-legacy' if program == LEGACY else 'ride-executor', ANCHOR.get(raw[:8], 'anchor_' + raw[:8].hex()))

def scan(tx):
    """Return (signers, funded_actions, instruction_names) for one transaction."""
    keys = tx['transaction']['message']['accountKeys']
    signers = [k['pubkey'] for k in keys if k['signer']]
    (owners, mints) = ({}, {})
    for b in (tx['meta'].get('preTokenBalances') or []) + (tx['meta'].get('postTokenBalances') or []):
        owners[keys[b['accountIndex']]['pubkey']] = b.get('owner')
        mints[keys[b['accountIndex']]['pubkey']] = b.get('mint')
    inner = {g['index']: g['instructions'] for g in tx['meta'].get('innerInstructions') or []}
    flat = []
    for (index, ix) in enumerate(tx['transaction']['message']['instructions']):
        flat.append((1, ix))
        for child in inner.get(index, []):
            require(child.get('stackHeight') is not None, 'Inner instruction without stackHeight')
            flat.append((child['stackHeight'], child))
    (actions, names, registrars) = ([], [], {})
    for (position, (height, ix)) in enumerate(flat):
        (program, name) = instruction_name(ix)
        if not program:
            continue
        names.append((program, name))
        if program == 'ride-legacy' and name == 'CreateRegistrar' and (len(ix.get('accounts') or []) >= 3):
            registrars[ix['accounts'][0]] = ix['accounts'][2]
        user = program == 'ride-gov' and any((GOV_TAGS.get(t) == name for t in GOV_USER)) or (program == 'ride-legacy' and name in LEGACY_USER)
        if not user:
            continue
        for (child_height, child) in flat[position + 1:]:
            if child_height <= height:
                break
            parsed = child.get('parsed')
            if child.get('program') not in TOKEN_PROGRAMS or not isinstance(parsed, dict) or parsed.get('type') not in ('transfer', 'transferChecked'):
                continue
            info = parsed['info']
            authority = info.get('authority')
            raw_amount = info.get('amount') or (info.get('tokenAmount') or {}).get('amount')
            amount = int(raw_amount) if raw_amount else 0
            source_owner = owners.get(info.get('source'))
            if authority in signers and amount > 0 and (source_owner == authority) and (owners.get(info.get('destination')) != authority):
                actions.append({'wallet': authority, 'program': program, 'instruction': name, 'signature': tx['transaction']['signatures'][0], 'slot': tx['slot'], 'block_time': tx.get('blockTime'), 'mint': info.get('mint') or mints.get(info.get('source')), 'amount_raw': str(amount), 'destination': info.get('destination')})
                if program == 'ride-legacy':
                    actions[-1]['legacy_registrar'] = (ix.get('accounts') or [None])[0]
    return (signers, actions, names, registrars)
