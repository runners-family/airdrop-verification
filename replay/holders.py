"""Run the preserved rational holding valuation with explicit candidate decisions."""
from fractions import Fraction
from pathlib import Path
from .core import canonical, require, wallet_bytes
from . import holder_common as c
from . import holders_math as h
from . import kamino_math as k


def derive(root, kind):
    folder = Path('data') / kind
    module = h if kind == 'holders' else k
    ctx = module.Context(root, folder)
    exclusions, _ = c.exclusion_registry(ctx.bundle, folder if kind == 'holders' else Path('data/holders'))
    state = module.values(ctx)
    jobs = ctx.bundle.json(folder / 'jobs/owner-jobs.json')
    info, slots, gaps, _ = c.read_owner_checks(ctx.bundle, folder, jobs, ctx.slot)
    wanted = module.candidates(state, exclusions)
    require(not gaps and wanted <= set(info), 'Missing qualifying-candidate account screens')
    decisions, included = {}, {}
    if kind == 'holders':
        for group in ('xstocks', 'zec', 'hype'):
            rows, keep = [], []
            for wallet in sorted(state['usd']):
                if group not in state['usd'][wallet]:
                    continue
                value = state['usd'][wallet][group]
                missing = state['unpriced_by_owner'].get(wallet, []) if group == 'xstocks' else []
                reason = c.owner_status(wallet, exclusions, info)
                if value < 100:
                    reason = 'unresolved_missing_price' if missing and reason == 'included' else 'below_100'
                qualifies = value >= 100 and reason == 'included'
                if qualifies:
                    keep.append(wallet)
                rows.append(dict(wallet=wallet, qualifies=qualifies, decision=reason,
                                 usd_fraction=c.encoded(value), usd=c.usd_text(value),
                                 unpriced_mints=sorted(missing), account=c.account_evidence(wallet, info)))
            decisions[group], included[group] = rows, keep
        gaps = state['scan_gaps']
        receipt = {'mint_registry_entries': len(state['stocks']), 'priced_mints': len(state['table']),
                   'unpriced_mints': len(state['unpriced']), 'token_accounts_scanned': state['accounts_scanned']}
    else:
        rows, keep = [], []
        for wallet in sorted(state['wallets']):
            gross, lending, earn, debt = k.amounts(state, wallet)
            missing = state['unpriced_by_owner'].get(wallet, [])
            reason = c.owner_status(wallet, exclusions, info)
            if gross < 100:
                reason = 'unresolved_missing_price' if missing and reason == 'included' and debt >= 100 else 'deposits_below_100'
            elif debt < 100:
                reason = 'below_100_outstanding_borrow'
            qualifies = gross >= 100 and debt >= 100 and reason == 'included'
            if qualifies:
                keep.append(wallet)
            rows.append(dict(wallet=wallet, qualifies=qualifies, decision=reason,
                             deposit_usd_fraction=c.encoded(gross), borrow_usd_fraction=c.encoded(debt),
                             lending_usd_fraction=c.encoded(lending), earn_usd_fraction=c.encoded(earn),
                             unpriced_vaults=sorted(missing), obligations=state['positions'].get(wallet, []),
                             account=c.account_evidence(wallet, info)))
        decisions['kamino'], included['kamino'] = rows, keep
        gaps = state['scan_gaps']
        receipt = {'obligation_pages': state['pages'], 'vaults': len(state['vaults']),
                   'token_accounts_scanned': state['accounts_scanned']}
    require(not gaps, 'Missing required holder scans')
    outputs = {group: {'wallets.txt': wallet_bytes(keep),
                       'decisions.jsonl': b''.join(canonical(row) for row in decisions[group])}
               for group, keep in included.items()}
    receipt.update(wallets={group:len(keep) for group, keep in included.items()},
                   candidates_reviewed={group:len(rows) for group, rows in decisions.items()},
                   owner_slots=[min(slots), max(slots)] if slots else None,
                   source_limit='Captured finalized state and indicative issuer/market prices across a collection window; known service screens.')
    return outputs, receipt
