"""Allowlisted public product/index data used by the Exponent/Hylo method."""
from .core import require
from .projection import select

TABLES = {
    'vaults': {'address', 'sy_token'}, 'markets': {'address', 'vault_address'},
    'strategy_vaults': {'address', 'lp_mint'}, 'clmm_markets': {'address', 'vault_address'},
    'user_pt_balances': {'user_address', 'vault_address', 'core_balance', 'orderbook_open', 'orderbook_filled'},
    'user_yt_balances': {'user_address', 'vault_address', 'core_balance', 'orderbook_open', 'orderbook_filled'},
    'user_sy_balances': {'user_address', 'vault_address', 'orderbook_open', 'orderbook_filled'},
    'user_clmm_lp_balances': {'position_address', 'user_address', 'market_address', 'needs_recalc', 'pt_balance', 'sy_balance'},
    'user_tranching_lp_balances': {'user_address', 'market_address', 'lp_balance', 'mint_lp', 'tranche_side'},
}
PRODUCTS = {
    'exponent-tokens': {'mint'},
    'exponent-current-prices': {'mint', 'price', 'ticker', 'timestamp'},
    'exponent-all-vaults': {'address', 'sy_token', 'pt_price', 'yt_price', 'sy_exchange_rate'},
    'exponent-markets': {'vaultAddress', 'syMint', 'baseTokenMint', 'ptPriceInAsset', 'ytPriceInAsset', 'syExchangeRate'},
    'exponent-all-tranching': {'address', 'syMint', 'quoteAssetMint', 'mintBase', 'mintLpSenior', 'mintLpJunior',
                              'srSyncedLpPriceNetAsset', 'jrSyncedLpPriceNetAsset', 'decimals', 'currentSyExchangeRate'},
    'exponent-sy-tokens': {'mint', 'ticker', 'decimals', 'quote_asset', 'underlying_asset'},
    'exponent-strategies': {'address', 'lpMint', 'lpPrice', 'lpDecimals', 'quoteToken', 'depositToken', 'lpToken', 'assets'},
}


def project(name, value):
    if name.startswith('exponent-table-'):
        table = name.removeprefix('exponent-table-').rsplit('-page-', 1)[0]
        require(table in TABLES, 'Unreviewed product table')
        return [select(row, TABLES[table]) for row in value]
    if name in PRODUCTS:
        result = []
        for original in value:
            row = select(original, PRODUCTS[name])
            for key in ('quote_asset', 'underlying_asset', 'quoteToken', 'depositToken', 'lpToken'):
                if key in row and row[key] is not None:
                    row[key] = select(row[key], {'mint'}) if isinstance(row[key], dict) else None
            if 'assets' in row and row['assets'] is not None:
                row['assets'] = [select(item, {'mint'}) for item in row['assets'] if isinstance(item, dict)]
            result.append(row)
        return result
    if name == 'hylo-stats':
        result = {}
        for key, fields in (('exchangeStats', ('stablecoinNav', 'levercoinNav')),
                            ('stabilityPoolStats', ('lpTokenNav',))):
            result[key] = {'raw': {field: select(value[key]['raw'][field], {'bits', 'exp'}, {'bits', 'exp'})
                                   for field in fields}}
        return result
    raise ValueError('Unreviewed product source profile')


def idl(value):
    def project_type(item):
        if isinstance(item, dict):
            return {key: project_type(child) for key, child in item.items() if key in {
                'name', 'type', 'kind', 'fields', 'variants', 'array', 'defined', 'discriminator',
                'option', 'vec', 'tuple', 'serialization', 'repr', 'generics', 'size',
            }}
        if isinstance(item, list):
            return [project_type(child) for child in item]
        require(item is None or type(item) in (str, int, bool), 'Unsupported IDL primitive')
        return item
    return {'accounts': project_type(value['accounts']), 'types': project_type(value['types'])}
