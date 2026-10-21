"""Independent exact reconstruction of the allocation, without importing verify.py."""
from collections import defaultdict
from fractions import Fraction
from pathlib import Path
from .core import canonical, loads, read_wallets, require, sha, wallet_bytes


def largest_remainder(total, weights):
    require(type(total) is int and total >= 0, 'Invalid total')
    require(weights and all(w > 0 for w in weights.values()), 'Invalid weights')
    denominator = sum(weights.values())
    quotas = {key: Fraction(total) * value / denominator for key, value in weights.items()}
    budgets = {key: value.numerator // value.denominator for key, value in quotas.items()}
    residual = total - sum(budgets.values())
    order = sorted(quotas, key=lambda key: (-(quotas[key] - budgets[key]), key))
    for key in order[:residual]:
        budgets[key] += 1
    require(sum(budgets.values()) == total, 'Rounding failed')
    return budgets


def calculate(config, groups):
    require(set(groups) == {g['id'] for g in config['groups']}, 'Category inventory differs')
    scale = 10 ** config['decimals']
    total = int(config['supply_base_units'])
    fixed, weighted = {}, {}
    for group in config['groups']:
        key = group['id']
        require(groups[key] == sorted(set(groups[key])), 'Noncanonical group')
        # Configuration is intentionally checked against its published recipe below.
        if group['rule'] == 'fixed_per_wallet':
            fixed[key] = int(group['tokens_per_wallet']) * scale * len(groups[key])
        elif group['rule'] == 'fixed_share':
            value = total * Fraction(group['share_percent']) / 100
            require(value.denominator == 1, 'Nonintegral fixed share')
            fixed[key] = int(value)
        elif group['rule'] == 'remainder_pool':
            weighted[key] = Fraction(group['weight'])
        elif group['rule'] == 'remainder_per_wallet':
            weighted[key] = Fraction(group['weight_per_wallet']) * len(groups[key])
        else:
            raise ValueError('Unsupported allocation rule')
    require(sum(fixed.values()) <= total, 'Fixed budget exceeds supply')
    budgets = fixed | largest_remainder(total - sum(fixed.values()), weighted)
    mapping = defaultdict(int)
    for key, rows in sorted(groups.items()):
        require(rows, 'Empty category')
        quotient, residual = divmod(budgets[key], len(rows))
        for index, wallet in enumerate(rows):
            mapping[wallet] += quotient + int(index < residual)
    require(sum(mapping.values()) == total, 'Supply not assigned exactly')
    csv = ('wallet,amount\n' + ''.join(f'{w},{mapping[w]}\n' for w in sorted(mapping))).encode()
    return budgets, dict(mapping), csv
