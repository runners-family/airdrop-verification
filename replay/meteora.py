"""Raw positions → pool math → capped current liquidity → wallet screens."""
from decimal import Decimal, localcontext
from pathlib import Path
from .core import account_data, canonical, loads, require, wallet_bytes
from .capture_store import Bundle
from . import holder_common
from . import meteora_math as math
from .meteora_layouts import load as load_layouts


def derive(package, reference):
    root = Path(package) / 'data/meteora'
    with localcontext() as context:
        context.rounding = 'ROUND_HALF_EVEN'
        context.prec = 60
        context.Emax, context.Emin = 999999, -999999
        math.ROOT, math.CAP, math.S = root, root / 'captures/onchain', reference['reference_slot']
        math.L = load_layouts(root)
        math.D, math.A = math.L.DLMM, math.L.DAMM
        math.DAMM_POOL_SLICE = {'offset': 0, 'length': math.A['pool_layout_version'] + 8}
        math.C.configure(math.L, math.S)
        raw, record = math.netcap.read_capture(math.CAP / 'quote-mints/batch-00000')
        require(record['request'] == math.C.multi_payload(math.C.QUOTE_MINTS, {'offset': 0, 'length': 82}),
                'Quote mint proof query differs')
        quote_proofs = loads(raw)['result']
        require(quote_proofs['context']['slot'] >= math.S and len(quote_proofs['value']) == 3,
                'Quote mint proof coverage differs')
        for mint, account in zip(math.C.QUOTE_MINTS, quote_proofs['value']):
            data = account_data(account)
            require(account['owner'] == math.L.TOKEN_PROGRAM and len(data) == 82 and data[45] == 1
                    and data[44] == math.QUOTE_DECIMALS[mint], 'Quote mint precision/program differs')
        for function in vars(math).values():
            if hasattr(function, 'cache_clear'):
                function.cache_clear()
        # compute is intentionally called once: it also reconstructs all batched
        # read universes from raw position/pool state and validates each request.
        state = math.compute()
        values = {}
        for wallet, positions in state['wallets'].items():
            total = capped = fees = Decimal(0)
            facts = []
            for position in positions:
                value = math.position_value(position, state['pools'], state['Q'], state['ref'])
                if value is None:
                    facts.append(dict(program=position[math.P_PROG], position=position[math.P_POS],
                                      gap=position[math.P_GAP] or 'pool_not_valued'))
                    continue
                limit = math.depth_capped_usd(value, state['pools'], state['Q'], state['ref'])
                total += value['usd']
                capped += limit
                fees += value['fee_usd']
                facts.append(dict(program=position[math.P_PROG], position=position[math.P_POS],
                    pool=position[math.P_POOL], amount_x=str(position[math.P_AX]), amount_y=str(position[math.P_AY]),
                    usd=str(value['usd']), usd_depth_capped=str(limit), usd_unclaimed_fees=str(value['fee_usd']),
                    source_x=value['source_x'], source_y=value['source_y'], written_after_reference=position[math.P_CHANGED]))
            values[wallet] = total, capped, fees, facts
        requested = sorted(wallet for wallet, (total, _, _, _) in values.items() if total >= 100)
        checks = math.Multi('wallet-accounts', requested, {'offset': 0, 'length': 0})
        accounts = checks.all()
        store = Bundle(package)
        exclusions, _ = holder_common.exclusion_registry(store, Path('data/legacy-services'))
        require(exclusions == loads((Path(package) / 'expected/legacy-services.json').read_bytes()),
                'Frozen service registry differs')
        decisions, included = [], []
        account_failures, missing = 0, 0
        for wallet, (total, capped, fees, facts) in sorted(values.items()):
            if capped < 100:
                status = 'below_100'
            elif wallet not in accounts:
                missing += 1
                status = 'missing_account_capture'
            else:
                account = accounts[wallet]
                if wallet in exclusions:
                    status = 'known_excluded_account_review'
                elif account and account['executable']:
                    status = 'executable_account_review'
                elif account and account['owner'] != '11111111111111111111111111111111':
                    status = 'program_owned_account_review'
                elif account and account.get('space') != 0:
                    status = 'system_data_or_unknown_space_review'
                else:
                    status = 'included'
                account_failures += status != 'included'
            if status == 'included':
                included.append(wallet)
            decisions.append(dict(wallet=wallet, decision=status, usd=str(total), usd_depth_capped=str(capped),
                                  usd_unclaimed_fees=str(fees), positions=facts))
        return {'wallets.txt': wallet_bytes(included), 'decisions.jsonl': b''.join(canonical(row) for row in decisions)}, {
            'wallets': len(included), 'candidate_wallets': len(values), 'positions': len(state['positions']),
            'pool_accounts': len(state['pools']), 'account_failures': account_failures,
            'qualifying_but_missing_account_captures': missing, 'account_capture_window': checks.meta(),
            'sol_usd': str(state['sol_usd']), 'raw_diagnostics': state['diag'],
            'source_limit': 'Current finalized state captured after the reference, not exact state at that slot; unpriced/layout/holder gaps and missing wallet captures are reported. Non-quote sides use the selected pricing pool quote-depth cap.'}
