"""Integer equivalent of pinned lend-read 0.0.14 tick/liquidation math.

The entire historical borrower output is compared with the reviewed SDK as a
release test. This module has no RPC client, transport or wallet dependency.
"""
from .core import decode58, encode58, require
from .meteora_pda import find_pda_raw

MIN_TICK = -16383
INIT_TICK = -2147483648
FACTORS = (18419115400608638658, 18391528108445969703, 18336477419114433396,
    18226869890870665593, 18009616477100071088, 17582847377087825313,
    16759408633341240198, 15226414841393184936, 12568272644527235157,
    8563108841104354677, 3975055583337633975, 856577552520149366,
    39775317560084773, 85764505686420, 398745188)
MAX_FACTOR = (1 << 50) - 1
EXP_MASK = (1 << 15) - 1
PROGRAM = 'jupr81YtYssSyPt8jbnGuiWon5f6x9TcDEFxYe3Bdzi'


def ratio(tick):
    require(MIN_TICK <= tick <= -MIN_TICK, 'Tick out of range')
    factor = 1 << 64
    for bit, constant in enumerate(FACTORS):
        if abs(tick) & (1 << bit):
            factor = factor * constant >> 64
    if tick > 0:
        factor = ((1 << 128) - 1) // factor
        return (factor >> 16) + bool(factor % 65536)
    return factor >> 16


def mul_div(normal, first, second):
    if not first or not second:
        return 0
    exponent = (second & EXP_MASK) - (first & EXP_MASK)
    require(exponent >= 0, 'Invalid connection exponent')
    if exponent >= 129:
        return 0
    result = normal * (first >> 15) // ((second >> 15) << exponent)
    require(result <= (1 << 64) - 1, 'Debt factor overflow')
    return result


def multiply(first, second):
    coefficient = (first >> 15) * (second >> 15)
    shift = 35 if coefficient > (1 << 69) - 1 else 34
    exponent = (first & EXP_MASK) + (second & EXP_MASK) + shift - 16384
    require(exponent >= 0, 'Debt factor exponent underflow')
    return MAX_FACTOR if exponent > EXP_MASK else ((coefficient >> shift) << 15) | exponent


def liquidation_address(vault, tick, tick_id):
    seeds = [b'tick_id_liquidation', vault.to_bytes(2, 'little'),
             (tick + 16383).to_bytes(4, 'little'), ((tick_id + 2) // 3).to_bytes(4, 'little')]
    return encode58(find_pda_raw(seeds, decode58(PROGRAM))[0])


def current(position, ticks, branches, liquidations):
    tick = MIN_TICK if position['tick'] == INIT_TICK else position['tick']
    collateral, dust = position['supply_amount'], position['dust_debt_amount']
    debt = (ratio(tick) * (collateral + 1) >> 48) + 1 if tick > MIN_TICK else 0
    branch_id, liquidated = 0, False
    if tick > MIN_TICK:
        state = ticks[(position['vault_id'], tick)]
        if state['is_liquidated'] or state['total_ids'] > position['tick_id']:
            liquidated = True
            if state['total_ids'] == position['tick_id']:
                fully, branch_id, factor = state['is_fully_liquidated'], state['liquidation_branch_id'], state['debt_factor']
            else:
                old = liquidations.get(liquidation_address(position['vault_id'], tick, position['tick_id']), {})
                suffix = '_' + str((position['tick_id'] + 2) % 3 + 1)
                fully = old.get('is_fully_liquidated' + suffix, 0)
                branch_id, factor = old.get('liquidation_branch_id' + suffix, 0), old.get('debt_factor' + suffix, 0)
            if fully == 1:
                # Historical SDK's early return has no userLiquidationStatus key.
                return 0, 0, branch_id, False
            seen = set()
            branch = branches[(position['vault_id'], branch_id)]
            while branch['status'] == 2:
                require(branch['branch_id'] not in seen, 'Liquidation branch cycle')
                seen.add(branch['branch_id'])
                factor = multiply(factor, branch['debt_factor'])
                if factor == MAX_FACTOR:
                    break
                branch = branches[(position['vault_id'], branch['connected_branch_id'])]
            if branch['status'] == 3 or factor == MAX_FACTOR:
                debt = collateral = 0
            else:
                initial = debt
                debt = mul_div(initial, branch['debt_factor'], factor)
                debt = debt * 9999 // 10000 if debt > initial // 100 else 0
                collateral = 0
                if debt:
                    at = ratio(branch['minima_tick'])
                    lower = at * 10000 // 10015
                    final = lower + (at - lower) * branch['minima_tick_partials'] // ((1 << 30) - 1)
                    collateral = debt * (1 << 48) // final
            # Historical SDK also omits the user flag in this early return.
            liquidated = False
    return collateral, max(debt - dust, 0), branch_id, liquidated
