"""Exact logical RPC selectors reconstructed from the historical collector."""
import hashlib
from .core import encode58 as b58encode
QUOTE_MINTS=['EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v','Es9vMFrzaCERmJfrF4H2FYD4KCoNkY11McCe8BenwNYB','So11111111111111111111111111111111111111112']
def anchor_account_discriminator(name):
    return hashlib.sha256(('account:'+name).encode()).digest()[:8]
L=SCANS=None
S=458146998
def configure(layouts, slot):
    global L, S, SCANS
    (L, S) = (layouts, slot)
    SCANS = {'dlmm-positions': dict(program=L.DLMM_PROGRAM, disc=L.DLMM['disc_position_v2'], data_slice=None, limit=2000), 'dlmm-positions-legacy-check': dict(program=L.DLMM_PROGRAM, disc=anchor_account_discriminator('Position'), data_slice={'offset': 0, 'length': 0}, limit=10000), 'damm-v2-positions': dict(program=L.DAMM_PROGRAM, disc=L.DAMM['disc_position'], data_slice=None, limit=10000), 'dlmm-positions-changed-since-S': dict(program=L.DLMM_PROGRAM, disc=L.DLMM['disc_position_v2'], data_slice={'offset': 0, 'length': 0}, limit=10000, changed_since=True), 'damm-v2-positions-changed-since-S': dict(program=L.DAMM_PROGRAM, disc=L.DAMM['disc_position'], data_slice={'offset': 0, 'length': 0}, limit=10000, changed_since=True)}

def scan_payload(label, cursor):
    spec = SCANS[label]
    config = {'encoding': 'base64', 'commitment': 'finalized', 'minContextSlot': S, 'withContext': True, 'filters': [{'memcmp': {'offset': 0, 'bytes': b58encode(spec['disc'])}}], 'limit': spec['limit']}
    if spec['data_slice'] is not None:
        config['dataSlice'] = spec['data_slice']
    if spec.get('changed_since'):
        config['changedSinceSlot'] = S
    if cursor:
        config['paginationKey'] = cursor
    return {'jsonrpc': '2.0', 'id': 1, 'method': 'getProgramAccountsV2', 'params': [spec['program'], config]}

def multi_payload(keys, data_slice):
    cfg = {'encoding': 'base64', 'commitment': 'finalized', 'minContextSlot': S}
    if data_slice is not None:
        cfg['dataSlice'] = data_slice
    return {'jsonrpc': '2.0', 'id': 1, 'method': 'getMultipleAccounts', 'params': [list(keys), cfg]}
