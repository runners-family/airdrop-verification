"""Pure IDL layout derivation; reviewed historical method"""
from pathlib import Path
from types import SimpleNamespace
from .core import loads
class JSON:
    loads=staticmethod(loads)
json=JSON()
PRIM = {'u8': 1, 'i8': 1, 'bool': 1, 'u16': 2, 'i16': 2, 'u32': 4, 'i32': 4, 'u64': 8, 'i64': 8, 'u128': 16, 'i128': 16, 'pubkey': 32}
class Idl:

    def __init__(self, path):
        self.path = Path(path)
        self.doc = json.loads(self.path.read_text())
        self.types = {t['name']: t for t in self.doc['types']}
        self.disc = {a['name']: bytes(a['discriminator']) for a in self.doc['accounts']}

    def size(self, ty):
        if isinstance(ty, str):
            return PRIM[ty]
        if 'array' in ty:
            (inner, n) = ty['array']
            return self.size(inner) * n
        if 'defined' in ty:
            t = self.types[ty['defined']['name']]
            assert t.get('serialization') in ('bytemuck', 'bytemuckunsafe'), 'not a zero-copy type: ' + t['name']
            kind = t['type']
            assert kind['kind'] == 'struct', 'unexpected kind in zero-copy type: ' + t['name']
            return sum((self.size(f['type']) for f in kind['fields']))
        raise ValueError('unknown IDL type: %r' % (ty,))

    def struct(self, name):
        """{field: (offset_within_struct, size, type)} for a zero-copy struct."""
        t = self.types[name]
        assert t.get('serialization') in ('bytemuck', 'bytemuckunsafe'), name
        (out, off) = ({}, 0)
        for f in t['type']['fields']:
            s = self.size(f['type'])
            out[f['name']] = (off, s, f['type'])
            off += s
        return out

    def struct_size(self, name):
        return self.size({'defined': {'name': name}})

    def account_offset(self, name, field):
        """Offset in account data (8-byte discriminator first)."""
        return 8 + self.struct(name)[field][0]

def _const(idl, name):
    return [c for c in idl.doc['constants'] if c['name'] == name][0]['value']

def load(root):
    ROOT = Path(root)
    DLMM_IDL = Idl(ROOT / 'inputs' / 'idl' / 'lb_clmm-0.12.0.idl.json')
    DAMM_IDL = Idl(ROOT / 'inputs' / 'idl' / 'cp_amm-0.2.5.idl.json')
    DLMM_PROGRAM = DLMM_IDL.doc['address']
    DAMM_PROGRAM = DAMM_IDL.doc['address']
    assert DLMM_PROGRAM == 'LBUZKhRxPF3XUpBCjp4YzTKgLccjZhTSDM9YuVaPwxo'
    assert DAMM_PROGRAM == 'cpamdpZCGKUy5JxQXB4dcpGPiikHawvSWAd6mEn1sGG'
    BINS_PER_ARRAY = int(_const(DLMM_IDL, 'MAX_BIN_PER_ARRAY'))
    DEFAULT_BINS_PER_POSITION = int(_const(DLMM_IDL, 'DEFAULT_BIN_PER_POSITION'))
    POSITION_MAX_LENGTH = int(_const(DLMM_IDL, 'POSITION_MAX_LENGTH'))
    BASIS_POINT_MAX = int(_const(DLMM_IDL, 'BASIS_POINT_MAX'))
    _pos = DLMM_IDL.struct('PositionV2')
    _fee = DLMM_IDL.struct('FeeInfo')
    _bin = DLMM_IDL.struct('Bin')
    _ba = DLMM_IDL.struct('BinArray')
    _pair = DLMM_IDL.struct('LbPair')
    _pbd = DLMM_IDL.struct('PositionBinData')
    DLMM = {'disc_position_v2': DLMM_IDL.disc['PositionV2'], 'disc_bin_array': DLMM_IDL.disc['BinArray'], 'disc_lb_pair': DLMM_IDL.disc['LbPair'], 'position_base_size': 8 + DLMM_IDL.struct_size('PositionV2'), 'pos_lb_pair': 8 + _pos['lb_pair'][0], 'pos_owner': 8 + _pos['owner'][0], 'pos_liquidity_shares': 8 + _pos['liquidity_shares'][0], 'pos_fee_infos': 8 + _pos['fee_infos'][0], 'pos_lower_bin_id': 8 + _pos['lower_bin_id'][0], 'pos_upper_bin_id': 8 + _pos['upper_bin_id'][0], 'fee_info_size': DLMM_IDL.struct_size('FeeInfo'), 'fee_x_per_token_complete': _fee['fee_x_per_token_complete'][0], 'fee_y_per_token_complete': _fee['fee_y_per_token_complete'][0], 'fee_x_pending': _fee['fee_x_pending'][0], 'fee_y_pending': _fee['fee_y_pending'][0], 'pbd_size': DLMM_IDL.struct_size('PositionBinData'), 'pbd_liquidity_share': _pbd['liquidity_share'][0], 'pbd_fee_info': _pbd['fee_info'][0], 'bin_array_size': 8 + DLMM_IDL.struct_size('BinArray'), 'ba_index': 8 + _ba['index'][0], 'ba_lb_pair': 8 + _ba['lb_pair'][0], 'ba_bins': 8 + _ba['bins'][0], 'bin_size': DLMM_IDL.struct_size('Bin'), 'bin_amount_x': _bin['amount_x'][0], 'bin_amount_y': _bin['amount_y'][0], 'bin_price': _bin['price'][0], 'bin_liquidity_supply': _bin['liquidity_supply'][0], 'bin_fee_x_per_token_stored': _bin['fee_amount_x_per_token_stored'][0], 'bin_fee_y_per_token_stored': _bin['fee_amount_y_per_token_stored'][0], 'lb_pair_size': 8 + DLMM_IDL.struct_size('LbPair'), 'pair_active_id': 8 + _pair['active_id'][0], 'pair_bin_step': 8 + _pair['bin_step'][0], 'pair_status': 8 + _pair['status'][0], 'pair_token_x_mint': 8 + _pair['token_x_mint'][0], 'pair_token_y_mint': 8 + _pair['token_y_mint'][0]}
    assert DLMM_IDL.struct_size('PositionV2') == 8112, 'SDK POSITION_MIN_SIZE'
    assert DLMM['pbd_size'] == 112, 'SDK POSITION_BIN_DATA_SIZE'
    assert BINS_PER_ARRAY == 70 and DEFAULT_BINS_PER_POSITION == 70
    assert DLMM['bin_size'] * BINS_PER_ARRAY + DLMM['ba_bins'] == DLMM['bin_array_size']
    assert _pos['liquidity_shares'][2] == {'array': ['u128', 70]} and _pos['fee_infos'][2]['array'][1] == 70
    _dpos = DAMM_IDL.struct('Position')
    _pool = DAMM_IDL.struct('Pool')
    DAMM = {'disc_position': DAMM_IDL.disc['Position'], 'disc_pool': DAMM_IDL.disc['Pool'], 'position_size': 8 + DAMM_IDL.struct_size('Position'), 'pos_pool': 8 + _dpos['pool'][0], 'pos_nft_mint': 8 + _dpos['nft_mint'][0], 'pos_fee_a_checkpoint': 8 + _dpos['fee_a_per_token_checkpoint'][0], 'pos_fee_b_checkpoint': 8 + _dpos['fee_b_per_token_checkpoint'][0], 'pos_fee_a_pending': 8 + _dpos['fee_a_pending'][0], 'pos_fee_b_pending': 8 + _dpos['fee_b_pending'][0], 'pos_unlocked_liquidity': 8 + _dpos['unlocked_liquidity'][0], 'pos_vested_liquidity': 8 + _dpos['vested_liquidity'][0], 'pos_permanent_locked_liquidity': 8 + _dpos['permanent_locked_liquidity'][0], 'pool_size': 8 + DAMM_IDL.struct_size('Pool'), 'pool_token_a_mint': 8 + _pool['token_a_mint'][0], 'pool_token_b_mint': 8 + _pool['token_b_mint'][0], 'pool_liquidity': 8 + _pool['liquidity'][0], 'pool_sqrt_min_price': 8 + _pool['sqrt_min_price'][0], 'pool_sqrt_max_price': 8 + _pool['sqrt_max_price'][0], 'pool_sqrt_price': 8 + _pool['sqrt_price'][0], 'pool_status': 8 + _pool['pool_status'][0], 'pool_collect_fee_mode': 8 + _pool['collect_fee_mode'][0], 'pool_type': 8 + _pool['pool_type'][0], 'pool_fee_a_per_liquidity': 8 + _pool['fee_a_per_liquidity'][0], 'pool_fee_b_per_liquidity': 8 + _pool['fee_b_per_liquidity'][0], 'pool_permanent_lock_liquidity': 8 + _pool['permanent_lock_liquidity'][0], 'pool_token_a_amount': 8 + _pool['token_a_amount'][0], 'pool_token_b_amount': 8 + _pool['token_b_amount'][0], 'pool_layout_version': 8 + _pool['layout_version'][0]}
    assert _dpos['fee_a_per_token_checkpoint'][1] == 32 and _pool['fee_a_per_liquidity'][1] == 32
    for f in ('sqrt_min_price', 'sqrt_max_price', 'sqrt_price', 'liquidity'):
        assert _pool[f][2] == 'u128', f
    for f in ('unlocked_liquidity', 'vested_liquidity', 'permanent_locked_liquidity'):
        assert _dpos[f][2] == 'u128', f
    TOKEN_ACCOUNT = {'mint': 0, 'owner': 32, 'amount': 64}
    TOKEN_PROGRAM = 'TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA'
    TOKEN_2022_PROGRAM = 'TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb'
    MINT_DECIMALS_OFFSET = 44
    return SimpleNamespace(**locals())
