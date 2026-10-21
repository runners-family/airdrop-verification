"""Minimal fields consumed by the historical issuer/market valuation helpers."""
from urllib.parse import urlsplit
from .core import require
from .projection import select


def locator(name, original):
    if name.startswith('stock-registry-page-'):
        number = int(name.removeprefix('stock-registry-page-'))
        return 'registry:xstocks' + ('?page=' + str(number) if number else '')
    if name.startswith('xstocks-price-'):
        return 'prices:xstocks/' + urlsplit(original).path.split('/assets/', 1)[1]
    if name.startswith('underlying-'):
        return 'prices:yahoo/' + urlsplit(original).path.rsplit('/', 1)[1] + '?interval=1d&range=5d'
    if name.startswith('kamino-vault-metrics-page-'):
        query = urlsplit(original).query
        require(query.startswith('limit=100') and all(part.split('=',1)[0] in {'limit', 'paginationToken'}
                                                     for part in query.split('&')), 'Unknown metrics query')
        return 'metrics:kamino-vaults?' + query
    return {'dune-cex-solana': 'registry:public-cex', 'xstocks-system-wallets': 'registry:issuer-wallets',
            'holder-market-prices': 'prices:holder-markets',
            'kamino-vault-registry': 'registry:kamino-vaults'}[name]


def http_body(name, value):
    if name.startswith('stock-registry-page-'):
        body = select(value, {'nodes', 'page'}, {'nodes', 'page'})
        body['page'] = select(body['page'], {'currentPage', 'hasNextPage'}, {'currentPage', 'hasNextPage'})
        body['nodes'] = []
        for original in value['nodes']:
            row = select(original, {'id', 'name', 'symbol', 'deployments', 'underlying', 'trading'},
                         {'id', 'name', 'symbol', 'deployments'})
            row['deployments'] = [select(item, {'network', 'address'}, {'network', 'address'})
                                   for item in row['deployments']]
            for key in ('underlying', 'trading'):
                if key in row and row[key] is not None:
                    row[key] = select(row[key], {'symbol', 'currency'})
            body['nodes'].append(row)
        return body
    if name.startswith('xstocks-price-'):
        return select(value, {'quote'})
    if name.startswith('underlying-'):
        return {'chart': {'result': [{'meta': select(item['meta'], {
            'symbol', 'currency', 'regularMarketPrice', 'regularMarketTime'},
            {'symbol', 'currency', 'regularMarketPrice', 'regularMarketTime'})}
                                    for item in value['chart']['result']]}}
    if name == 'xstocks-system-wallets':
        return {'nodes': [select(row, {'address', 'networkType'}, {'address', 'networkType'}) for row in value['nodes']]}
    if name == 'holder-market-prices':
        return [dict(select(row, {'chainId', 'pairAddress', 'dexId', 'priceUsd'}, {'pairAddress'}),
                     baseToken=select(row['baseToken'], {'address'}, {'address'}),
                     quoteToken=select(row['quoteToken'], {'symbol', 'address'}),
                     liquidity=select(row.get('liquidity', {}), {'usd'})) for row in value]
    if name == 'kamino-vault-registry':
        return [{'address': row['address'], 'state': select(row['state'], {
            'sharesMint', 'sharesMintDecimals', 'tokenMint'}, {'sharesMint', 'sharesMintDecimals'})} for row in value]
    if name.startswith('kamino-vault-metrics-page-'):
        return dict(select(value, {'paginationToken'}), result=[select(row, {'kvault', 'sharePrice'},
                                                                      {'kvault', 'sharePrice'}) for row in value['result']])
    raise ValueError('Unreviewed issuer/market response profile')
