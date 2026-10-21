"""Only the captured token prices and per-share values used by the rule."""
from decimal import Decimal
from .core import address, require
from .projection import select


def numeric(value):
    require(type(value) is int or isinstance(value, Decimal) or
            (isinstance(value, str) and value and Decimal(value).is_finite()), 'Invalid valuation scalar')
    return value


def vault(original):
    row = select(original, {'id'}, {'id'})
    require(type(row['id']) is int, 'Invalid vault ID')
    for side in ('supply', 'borrow'):
        pair = original[side + 'Token']
        result = {}
        for token in ('token0', 'token1'):
            value = pair.get(token)
            if value:
                result[token] = dict(address=value['address'], price=numeric(value['price']))
                address(value['address'])
                if value.get('scaledUiConfig'):
                    config = select(value['scaledUiConfig'], {'multiplier', 'newMultiplier', 'newMultiplierEffectiveTimestamp'},
                                    {'multiplier', 'newMultiplier', 'newMultiplierEffectiveTimestamp'})
                    result[token]['scaledUiConfig'] = {key: numeric(child) for key, child in config.items()}
            else:
                result[token] = None
        row[side + 'Token'] = result
        dex = original.get(side + 'DexData')
        row[side + 'DexData'] = ({key: numeric(dex[key]) for key in ('token0PerShare', 'token1PerShare')}
                                if dex else None)
    return row
