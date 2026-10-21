"""Historical deterministic current LP valuation; reviewed historical method
No collector, old wallet list or external transport code.
"""
import base64
import collections
import decimal
import functools
import hashlib
import sys
from decimal import Decimal
from pathlib import Path
from .core import loads, decode58 as b58decode, encode58 as b58encode, on_curve
from . import meteora_requests as C
from . import meteora_capture as netcap
from .meteora_pda import find_pda_raw
class JSON:
    loads=staticmethod(loads)
json=JSON()
def wallet_on_curve(wallet):
    return on_curve(b58decode(wallet))
ROOT=CAP=L=D=A=DAMM_POOL_SLICE=None
S=458146998
USDC,USDT,WSOL=C.QUOTE_MINTS
QUOTE_DECIMALS={USDC:6,USDT:6,WSOL:9}
SOL_PRICE_POOLS=5
THRESHOLD=Decimal(100)
DLMM_GROUP_ARRAYS=6000
DAMM_GROUP_POOLS=120000
Z16=bytes(16)
U64_MAX=(1<<64)-1
U128_MAX=(1<<128)-1
U256=1<<256
ONE_Q64=1<<64
DEAD_LIQUIDITY=100<<64
intern=sys.intern
RESUME_CUT='2026-10-18T08:50:00'
READ_WINDOWS=('first_run','resumed_run')
P_PROG,P_POS,P_POOL,P_OWNER,P_METHOD,P_AX,P_AY,P_FX,P_FY,P_GAP,P_CHANGED=range(11)
def read_window(retrieved_at):
    return 'first_run' if retrieved_at < RESUME_CUT else 'resumed_run'

def u(b):
    return int.from_bytes(b, 'little')

def iter_scan(label):
    """Yield (page_no, context_slot, record, accounts) for a getProgramAccountsV2 scan, checking that
    each saved request is exactly the request the paging rule asks for and that paging ended."""
    folder = CAP / label
    (cursor, page) = (None, 0)
    while True:
        base = folder / ('page-%05d' % page)
        (raw, rec) = netcap.read_capture(base)
        assert rec['request'] == C.scan_payload(label, cursor), 'unexpected request in ' + str(base)
        data = json.loads(raw)
        del raw
        ctx = data['result']['context']['slot']
        assert ctx >= S
        value = data['result']['value']
        yield (page, ctx, rec, value['accounts'])
        cursor = value.get('paginationKey')
        if not cursor:
            break
        page += 1
    assert not (folder / ('page-%05d.record.json' % (page + 1))).exists(), 'extra page after terminal page: ' + label

@functools.lru_cache(maxsize=None)
def scan_meta(label):
    (pages, n) = ([], 0)
    for (page, ctx, rec, accounts) in iter_scan(label):
        pages.append((ctx, rec['retrieved_at']))
        n += len(accounts)
    return {'pages': len(pages), 'accounts': n, 'context_slot_min': min((p[0] for p in pages)), 'context_slot_max': max((p[0] for p in pages)), 'first_retrieved_at': min((p[1] for p in pages)), 'last_retrieved_at': max((p[1] for p in pages)), 'terminal_pagination': True}

@functools.lru_cache(maxsize=None)
def scan_addresses(label):
    out = set()
    for (_, _, _, accounts) in iter_scan(label):
        out.update((a['pubkey'] for a in accounts))
    return frozenset(out)

class Multi:
    """Reader for a getMultipleAccounts capture made by collect.run_multi over `keys` (100 per call)."""

    def __init__(self, label, keys, data_slice, per=100):
        (self.label, self.keys, self.data_slice, self.per) = (label, list(keys), data_slice, per)
        self.folder = CAP / label
        self.nb = (len(self.keys) + per - 1) // per
        self.failed = set()
        for i in range(self.nb):
            base = self.folder / ('batch-%05d' % i)
            if not base.with_name(base.name + '.record.json').exists():
                assert (self.folder / ('FAILED-batch-%05d.json' % i)).exists(), 'missing batch without failure record: %s %d' % (label, i)
                self.failed.add(i)
        extra = [p.name for p in self.folder.glob('batch-*.record.json') if int(p.name[6:11]) >= self.nb]
        assert not extra, 'unexpected extra batches in ' + label
        (self.slots, self.times) = ([], [])

    def gap_keys(self):
        return {k for i in self.failed for k in self.keys[i * self.per:(i + 1) * self.per]}

    def batches(self, first=0, last=None):
        """Yield (keys, values) for batches first..last (inclusive), verifying each request."""
        last = self.nb - 1 if last is None else last
        for i in range(first, last + 1):
            if i in self.failed:
                continue
            chunk = self.keys[i * self.per:(i + 1) * self.per]
            (raw, rec) = netcap.read_capture(self.folder / ('batch-%05d' % i))
            assert rec['request'] == C.multi_payload(chunk, self.data_slice), 'unexpected request in %s %d' % (self.label, i)
            data = json.loads(raw)
            ctx = data['result']['context']['slot']
            assert ctx >= S and len(data['result']['value']) == len(chunk)
            self.slots.append(ctx)
            self.times.append(rec['retrieved_at'])
            self.current = (i, ctx, rec['retrieved_at'])
            yield (chunk, data['result']['value'])

    def all(self):
        out = {}
        for (chunk, vals) in self.batches():
            out.update(zip(chunk, vals))
        return out

    def meta(self):
        return {'keys': len(self.keys), 'batches': self.nb, 'failed_batches': len(self.failed), 'failed_keys': len(self.gap_keys()), 'context_slot_min': min(self.slots) if self.slots else None, 'context_slot_max': max(self.slots) if self.slots else None, 'first_retrieved_at': min(self.times) if self.times else None, 'last_retrieved_at': max(self.times) if self.times else None}

def acc_bytes(acc):
    return base64.b64decode(acc['data'][0])

def dlmm_price_q64(bin_step, bin_id):
    """Q64.64 bin price: the SDK/program pow(ONE + (bin_step << 64) / 10000, bin_id)."""
    base = ONE_Q64 + (bin_step << 64) // L.BASIS_POINT_MAX
    if bin_id == 0:
        return ONE_Q64
    invert = bin_id < 0
    exp = -bin_id if invert else bin_id
    if exp > 524288:
        return 0
    (squared, result) = (base, ONE_Q64)
    if squared >= result:
        squared = U128_MAX // squared
        invert = not invert
    for bit in range(19):
        if exp & 1 << bit:
            result = result * squared >> 64
        squared = squared * squared >> 64
    if result == 0:
        return 0
    return U128_MAX // result if invert else result

def dlmm_position_records(pairs=None):
    """Yield (pubkey, lb_pair, owner, lower, upper, entries, pend_x, pend_y, size_ok) for every captured
    PositionV2 (only those whose lb_pair is in `pairs`, when given). entries = [(i, share, fee_x_complete,
    fee_y_complete)] for bins with a non-zero share; pending fees are summed over all bins."""
    (base_size, pbd) = (D['position_base_size'], D['pbd_size'])
    (so, fo, fis) = (D['pos_liquidity_shares'], D['pos_fee_infos'], D['fee_info_size'])
    (fxp, fyp) = (D['fee_x_pending'], D['fee_y_pending'])
    (pls, pfi) = (D['pbd_liquidity_share'], D['pbd_fee_info'])
    (lo_off, up_off) = (D['pos_lower_bin_id'], D['pos_upper_bin_id'])
    for (_, _, _, accounts) in iter_scan('dlmm-positions'):
        for a in accounts:
            if pairs is not None:
                head = base64.b64decode(a['account']['data'][0][:56])
                if b58encode(head[8:40]) not in pairs:
                    continue
            raw = acc_bytes(a['account'])
            assert raw[:8] == D['disc_position_v2'] and len(raw) >= base_size and (a['account']['owner'] == L.DLMM_PROGRAM)
            lower = int.from_bytes(raw[lo_off:lo_off + 4], 'little', signed=True)
            upper = int.from_bytes(raw[up_off:up_off + 4], 'little', signed=True)
            width = upper - lower + 1
            assert 1 <= width <= L.POSITION_MAX_LENGTH, 'bad position width'
            ext = max(0, width - L.DEFAULT_BINS_PER_POSITION)
            assert len(raw) >= base_size + ext * pbd, 'position shorter than its width'
            (entries, pend_x, pend_y) = ([], 0, 0)
            for i in range(width):
                if i < 70:
                    (s_off, f_off) = (so + 16 * i, fo + fis * i)
                else:
                    b = base_size + pbd * (i - 70)
                    (s_off, f_off) = (b + pls, b + pfi)
                pend_x += u(raw[f_off + fxp:f_off + fxp + 8])
                pend_y += u(raw[f_off + fyp:f_off + fyp + 8])
                sb = raw[s_off:s_off + 16]
                if sb != Z16:
                    entries.append((i, u(sb), u(raw[f_off:f_off + 16]), u(raw[f_off + 16:f_off + 32])))
            yield (a['pubkey'], b58encode(raw[8:40]), b58encode(raw[40:72]), lower, upper, entries, pend_x, pend_y, len(raw) == base_size + ext * pbd)

@functools.lru_cache(maxsize=None)
def _dlmm_needs():
    (pairs, arrays) = (set(), set())
    for (pub, pair, owner, lower, upper, entries, px, py, _) in dlmm_position_records():
        pairs.add(pair)
        for e in entries:
            arrays.add((pair, (lower + e[0]) // L.BINS_PER_ARRAY))
    return (tuple(sorted(pairs)), tuple(sorted(arrays)))

def dlmm_pair_keys():
    return list(_dlmm_needs()[0])

@functools.lru_cache(maxsize=None)
def dlmm_bin_array_requests():
    """((lb_pair, index, pda), ...) sorted by (lb_pair, index): every array holding a bin with shares."""
    prog = b58decode(L.DLMM_PROGRAM)
    return tuple(((pair, idx, b58encode(find_pda_raw([b'bin_array', b58decode(pair), idx.to_bytes(8, 'little', signed=True)], prog)[0])) for (pair, idx) in _dlmm_needs()[1]))

def decode_lb_pair(raw):
    assert raw[:8] == D['disc_lb_pair'] and len(raw) == D['lb_pair_size']
    g = lambda name, n: raw[D[name]:D[name] + n]
    return {'mint_x': intern(b58encode(g('pair_token_x_mint', 32))), 'mint_y': intern(b58encode(g('pair_token_y_mint', 32))), 'active_id': int.from_bytes(g('pair_active_id', 4), 'little', signed=True), 'bin_step': u(g('pair_bin_step', 2)), 'status': g('pair_status', 1)[0]}

def bin_fields(arr, j):
    """(amount_x, amount_y, price, supply, fee_x_stored, fee_y_stored) of bin j in a BinArray's raw bytes."""
    b = D['ba_bins'] + D['bin_size'] * j
    return (u(arr[b + D['bin_amount_x']:b + D['bin_amount_x'] + 8]), u(arr[b + D['bin_amount_y']:b + D['bin_amount_y'] + 8]), u(arr[b + D['bin_price']:b + D['bin_price'] + 16]), u(arr[b + D['bin_liquidity_supply']:b + D['bin_liquidity_supply'] + 16]), u(arr[b + D['bin_fee_x_per_token_stored']:b + D['bin_fee_x_per_token_stored'] + 16]), u(arr[b + D['bin_fee_y_per_token_stored']:b + D['bin_fee_y_per_token_stored'] + 16]))

def dlmm_compute(diag, changed):
    pair_keys = dlmm_pair_keys()
    pm = Multi('dlmm-lb-pairs', pair_keys, None)
    pair_acc = pm.all()
    pair_gaps = pm.gap_keys()
    info = {}
    for k in pair_keys:
        acc = pair_acc.get(k)
        if acc is None:
            continue
        assert acc['owner'] == L.DLMM_PROGRAM
        info[k] = decode_lb_pair(acc_bytes(acc))
    del pair_acc
    reqs = dlmm_bin_array_requests()
    bm = Multi('dlmm-bin-arrays', [r[2] for r in reqs], None)
    gap_pdas = bm.gap_keys()
    (groups, start) = ([], 0)
    for i in range(1, len(reqs) + 1):
        if i == len(reqs) or (i - start >= DLMM_GROUP_ARRAYS and reqs[i][0] != reqs[i - 1][0]):
            groups.append((start, i))
            start = i
    group_of = {}
    for (g, (a, b)) in enumerate(groups):
        for r in reqs[a:b]:
            group_of[r[0]] = g
    no_array_pairs = frozenset((p for p in pair_keys if p not in group_of))
    an = collections.Counter()
    chk = collections.Counter()
    reserves = collections.defaultdict(lambda : [0, 0])
    positions = []
    for g in range(max(1, len(groups))):
        (arrays, missing) = ({}, 0)
        if groups:
            (a, b) = groups[g]
            want = {r[2]: (r[0], r[1]) for r in reqs[a:b]}
            for (chunk, vals) in bm.batches(a // 100, (b - 1) // 100):
                for (pda, acc) in zip(chunk, vals):
                    if pda not in want:
                        continue
                    (pair, idx) = want[pda]
                    if acc is None:
                        arrays[pair, idx] = None
                        continue
                    raw = acc_bytes(acc)
                    assert acc['owner'] == L.DLMM_PROGRAM and raw[:8] == D['disc_bin_array'] and (len(raw) == D['bin_array_size'])
                    assert b58encode(raw[D['ba_lb_pair']:D['ba_lb_pair'] + 32]) == pair
                    assert int.from_bytes(raw[D['ba_index']:D['ba_index'] + 8], 'little', signed=True) == idx
                    arrays[pair, idx] = raw
            chk['needed_bin_arrays_not_initialized'] += sum((1 for v in arrays.values() if v is None))
            members = frozenset((p for (p, gg) in group_of.items() if gg == g)) | (no_array_pairs if g == 0 else frozenset())
        else:
            members = no_array_pairs
        share_sum = collections.defaultdict(int)
        for (pub, pair, owner, lower, upper, entries, pend_x, pend_y, size_ok) in dlmm_position_records(members):
            if not size_ok:
                an['position_account_larger_than_its_width'] += 1
            gap = None
            ax = ay = fx = fy = 0
            if pair not in info:
                gap = 'lb_pair_not_captured' if pair in pair_gaps else 'lb_pair_account_missing'
            else:
                for (i, share, fxc, fyc) in entries:
                    bin_id = lower + i
                    idx = bin_id // L.BINS_PER_ARRAY
                    key = (pair, idx)
                    if key not in arrays:
                        gap = 'bin_array_not_captured'
                        break
                    arr = arrays[key]
                    if arr is None:
                        an['share_in_uninitialized_bin_array'] += 1
                        continue
                    (bax, bay, bprice, supply, fxs, fys) = bin_fields(arr, bin_id - idx * L.BINS_PER_ARRAY)
                    share_sum[pair, bin_id] += share
                    if supply == 0:
                        an['share_in_bin_with_zero_supply'] += 1
                        continue
                    if share > supply:
                        an['share_above_bin_supply'] += 1
                    ax += share * bax // supply
                    ay += share * bay // supply
                    (dfx, dfy) = (fxs - fxc, fys - fyc)
                    if dfx < 0 or dfy < 0:
                        an['fee_checkpoint_above_bin_fee_stored'] += 1
                        (dfx, dfy) = (max(dfx, 0), max(dfy, 0))
                    fx += (share >> 64) * dfx >> 64
                    fy += (share >> 64) * dfy >> 64
            if gap:
                ax = ay = 0
                (fx, fy) = (pend_x, pend_y)
            else:
                fx += pend_x
                fy += pend_y
                r = reserves[pair]
                r[0] += ax
                r[1] += ay
            positions.append(('dlmm', pub, intern(pair), intern(owner), None, ax, ay, fx, fy, gap, pub in changed))
        for ((pair, bin_id), total) in share_sum.items():
            idx = bin_id // L.BINS_PER_ARRAY
            (_, _, bprice, supply, _, _) = bin_fields(arrays[pair, idx], bin_id - idx * L.BINS_PER_ARRAY)
            chk['bins_with_captured_shares'] += 1
            chk['bins_shares_equal_supply' if total == supply else 'bins_shares_below_supply' if total < supply else 'bins_shares_above_supply'] += 1
            if bprice:
                chk['bins_stored_price_equals_computed' if bprice == dlmm_price_q64(info[pair]['bin_step'], bin_id) else 'bins_stored_price_differs'] += 1
        del arrays, share_sum
    positions.sort(key=lambda p: p[P_POS])
    pools = {}
    for (k, v) in info.items():
        r = reserves.get(k, (0, 0))
        pools[k] = ('dlmm', v['mint_x'], v['mint_y'], dlmm_price_q64(v['bin_step'], v['active_id']), r[0], r[1], v['active_id'])
    diag['dlmm_lb_pairs'] = pm.meta()
    diag['dlmm_bin_arrays'] = bm.meta()
    diag['dlmm_checks'] = dict(sorted(chk.items()), needed_bin_arrays=len(reqs), bin_array_groups=len(groups), bin_arrays_not_captured=len(gap_pdas), lb_pairs=len(pair_keys), lb_pairs_not_captured=len(pair_gaps), lb_pairs_missing_account=len([k for k in pair_keys if k not in info and k not in pair_gaps]), positions=len(positions), positions_with_shares=sum((1 for p in positions if p[P_AX] or p[P_AY])), anomalies=dict(sorted(an.items())))
    return (positions, pools)

def damm_position_records(pools=None):
    """Yield (pubkey, pool, nft_mint, liquidity, ckA, ckB, pendA, pendB, permanent) for captured Positions
    with liquidity > 0 or stored pending fees > 0 (only those in `pools`, when given)."""
    for (_, _, _, accounts) in iter_scan('damm-v2-positions'):
        for a in accounts:
            if pools is not None:
                head = base64.b64decode(a['account']['data'][0][:56])
                if b58encode(head[8:40]) not in pools:
                    continue
            raw = acc_bytes(a['account'])
            assert raw[:8] == A['disc_position'] and len(raw) == A['position_size'] and (a['account']['owner'] == L.DAMM_PROGRAM)
            lu = u(raw[A['pos_unlocked_liquidity']:A['pos_unlocked_liquidity'] + 16])
            lv = u(raw[A['pos_vested_liquidity']:A['pos_vested_liquidity'] + 16])
            lp = u(raw[A['pos_permanent_locked_liquidity']:A['pos_permanent_locked_liquidity'] + 16])
            pa = u(raw[A['pos_fee_a_pending']:A['pos_fee_a_pending'] + 8])
            pb = u(raw[A['pos_fee_b_pending']:A['pos_fee_b_pending'] + 8])
            if not (lu or lv or lp or pa or pb):
                continue
            yield (a['pubkey'], b58encode(raw[8:40]), b58encode(raw[40:72]), lu + lv + lp, u(raw[A['pos_fee_a_checkpoint']:A['pos_fee_a_checkpoint'] + 32]), u(raw[A['pos_fee_b_checkpoint']:A['pos_fee_b_checkpoint'] + 32]), pa, pb, lp)

@functools.lru_cache(maxsize=None)
def _damm_index():
    (pools, mints, n) = (set(), set(), 0)
    for rec in damm_position_records():
        n += 1
        pools.add(rec[1])
        mints.add(rec[2])
    return (tuple(sorted(pools)), tuple(sorted(mints)), n)

def damm_pool_keys():
    return list(_damm_index()[0])

@functools.lru_cache(maxsize=None)
def damm_relevant_nft_mints_and_pdas():
    mints = list(_damm_index()[1])
    prog = b58decode(L.DAMM_PROGRAM)
    pdas = [b58encode(find_pda_raw([b'position_nft_account', b58decode(m)], prog)[0]) for m in mints]
    return (mints, pdas)

def decode_damm_pool(acc):
    raw = acc_bytes(acc)
    assert raw[:8] == A['disc_pool'] and len(raw) == DAMM_POOL_SLICE['length'] and (acc['space'] == A['pool_size'])
    f = lambda name, n: raw[A[name]:A[name] + n]
    return {'mint_x': intern(b58encode(f('pool_token_a_mint', 32))), 'mint_y': intern(b58encode(f('pool_token_b_mint', 32))), 'liquidity': u(f('pool_liquidity', 16)), 'sqrt_min': u(f('pool_sqrt_min_price', 16)), 'sqrt_max': u(f('pool_sqrt_max_price', 16)), 'sqrt_price': u(f('pool_sqrt_price', 16)), 'collect_fee_mode': f('pool_collect_fee_mode', 1)[0], 'pool_type': f('pool_type', 1)[0], 'fee_a_per_liquidity': u(f('pool_fee_a_per_liquidity', 32)), 'fee_b_per_liquidity': u(f('pool_fee_b_per_liquidity', 32)), 'token_a_amount': u(f('pool_token_a_amount', 8)), 'token_b_amount': u(f('pool_token_b_amount', 8)), 'layout_version': f('pool_layout_version', 1)[0]}

def damm_amounts(p, liq):
    """Token amounts for `liq` liquidity (SDK getWithdrawQuote, rounding down)."""
    if p['collect_fee_mode'] == 2:
        if p['liquidity'] == 0:
            return (0, 0)
        return (liq * p['token_a_amount'] // p['liquidity'], liq * p['token_b_amount'] // p['liquidity'])
    (lo, hi, sp) = (p['sqrt_min'], p['sqrt_max'], p['sqrt_price'])
    sp = min(max(sp, lo), hi)
    a = liq * (hi - sp) // (sp * hi) if sp and hi else 0
    b = liq * (sp - lo) >> 128
    return (a, b)

def damm_fee(pending, liq, per_liq, checkpoint):
    acc = liq * ((per_liq - checkpoint) % U256) >> 128
    return min(U64_MAX, pending + min(U64_MAX, acc))

def _token_account(acc, mint):
    """Owner of a token account holding exactly 1 of `mint`, else None."""
    if acc is None or acc['owner'] not in (L.TOKEN_PROGRAM, L.TOKEN_2022_PROGRAM):
        return None
    raw = acc_bytes(acc)
    if len(raw) >= 72 and b58encode(raw[0:32]) == mint and (u(raw[64:72]) == 1):
        return b58encode(raw[32:64])
    return None

@functools.lru_cache(maxsize=None)
def _holders_stage1():
    (mints, pdas) = damm_relevant_nft_mints_and_pdas()
    m = Multi('damm-v2-nft-accounts', pdas, {'offset': 0, 'length': 72})
    pda_index = {p: i for (i, p) in enumerate(pdas)}
    holder = {}
    windows = collections.Counter()
    for (chunk, vals) in m.batches():
        windows[read_window(m.current[2])] += 1
        for (pda, acc) in zip(chunk, vals):
            mint = mints[pda_index[pda]]
            h = _token_account(acc, mint)
            if h:
                holder[mint] = (intern(h), 'position_nft_account_pda')
    del pda_index
    missing = tuple((mint for mint in mints if mint not in holder))
    meta = m.meta()
    meta['batches_by_read_window'] = dict(sorted(windows.items()))
    return (holder, missing, meta)

def damm_nft_not_in_pda():
    return list(_holders_stage1()[1])

@functools.lru_cache(maxsize=None)
def _das():
    missing = _holders_stage1()[1]
    folder = CAP / 'damm-v2-nft-das'
    assert json.loads((folder / 'ids.json').read_text())['ids'] == list(missing), 'DAS id list differs from PDA misses'
    (owner, failed, n) = ({}, 0, 0)
    for start in range(0, len(missing), 1000):
        ids = list(missing[start:start + 1000])
        base = folder / ('das-batch-%05d' % (start // 1000))
        if not base.with_name(base.name + '.record.json').exists():
            assert (folder / ('FAILED-das-batch-%05d.json' % (start // 1000))).exists()
            failed += len(ids)
            continue
        (raw, rec) = netcap.read_capture(base)
        assert rec['request'] == {'jsonrpc': '2.0', 'id': 1, 'method': 'getAssetBatch', 'params': {'ids': ids}}
        res = json.loads(raw)['result']
        assert len(res) == len(ids)
        n += 1
        for (mint, asset) in zip(ids, res):
            o = ((asset or {}).get('ownership') or {}).get('owner')
            if asset and asset.get('id') == mint and o:
                owner[mint] = o
    return (owner, failed, n)

def damm_nft_unresolved_after_das():
    missing = _holders_stage1()[1]
    owner = _das()[0]
    return [m for m in missing if m not in owner]

@functools.lru_cache(maxsize=None)
def _largest_rows():
    unresolved = damm_nft_unresolved_after_das()
    folder = CAP / 'damm-v2-nft-largest'
    assert json.loads((folder / 'mints.json').read_text())['mints'] == unresolved
    (rows, failed) = ({}, 0)
    for m in unresolved:
        base = folder / ('largest-' + m)
        if not base.with_name(base.name + '.record.json').exists():
            assert (folder / ('FAILED-' + m + '.json')).exists()
            failed += 1
            continue
        (raw, rec) = netcap.read_capture(base)
        assert rec['request'] == {'jsonrpc': '2.0', 'id': 1, 'method': 'getTokenLargestAccounts', 'params': [m, {'commitment': 'finalized', 'minContextSlot': S}]}
        data = json.loads(raw)
        assert data['result']['context']['slot'] >= S
        ones = [r['address'] for r in data['result']['value'] if r['amount'] == '1']
        if ones:
            rows[m] = ones[0]
    return (rows, failed)

def damm_largest_holding_accounts():
    return sorted(set(_largest_rows()[0].values()))

@functools.lru_cache(maxsize=None)
def damm_holders():
    (holder, missing, pda_meta) = _holders_stage1()
    holder = dict(holder)
    (das_owner, das_failed, das_batches) = _das()
    for m in missing:
        if m in das_owner:
            holder[m] = (intern(das_owner[m]), 'das_getAssetBatch')
    (rows, largest_failed) = _largest_rows()
    accounts = sorted(set(rows.values()))
    lm = Multi('damm-v2-nft-largest-accounts', accounts, {'offset': 0, 'length': 72})
    acc = lm.all()
    for m in damm_nft_unresolved_after_das():
        h = _token_account(acc.get(rows[m]), m) if m in rows else None
        if h:
            holder[m] = (intern(h), 'getTokenLargestAccounts')
    mints = damm_relevant_nft_mints_and_pdas()[0]
    diag = {'damm_v2_nft_pda_accounts': pda_meta, 'damm_v2_nft_largest_accounts': lm.meta(), 'damm_v2_holders': {'nft_mints_checked': len(mints), 'resolved_by_method': dict(sorted(collections.Counter((v[1] for v in holder.values())).items())), 'not_in_pda': len(missing), 'das_batches': das_batches, 'das_failed_ids': das_failed, 'largest_lookups': len(damm_nft_unresolved_after_das()), 'largest_failed': largest_failed, 'unresolved': len([m for m in mints if m not in holder])}}
    return (holder, diag)

def damm_compute(diag, changed):
    keys = damm_pool_keys()
    pm = Multi('damm-v2-pools', keys, DAMM_POOL_SLICE)
    gaps = pm.gap_keys()
    (holder, hdiag) = damm_holders()
    diag.update(hdiag)
    groups = [(i, min(i + DAMM_GROUP_POOLS, len(keys))) for i in range(0, len(keys), DAMM_GROUP_POOLS)]
    (pools, positions) = ({}, [])
    (an, chk) = (collections.Counter(), collections.Counter())
    drift = {w: collections.Counter() for w in READ_WINDOWS}
    mismatch = {}
    for (a, b) in groups:
        grp = {}
        members = frozenset(keys[a:b])
        for (chunk, vals) in pm.batches(a // 100, (b - 1) // 100):
            window = read_window(pm.current[2])
            drift[window]['batches'] += 1
            for (k, acc) in zip(chunk, vals):
                if k not in members or acc is None:
                    continue
                assert acc['owner'] == L.DAMM_PROGRAM
                p = decode_damm_pool(acc)
                p['window'] = window
                if not p['sqrt_min'] <= p['sqrt_price'] <= p['sqrt_max']:
                    an['pool_sqrt_price_outside_range'] += 1
                if p['collect_fee_mode'] == 2:
                    chk['compounding_pools'] += 1
                chk['collect_fee_mode_%d' % p['collect_fee_mode']] += 1
                chk['layout_version_%d' % p['layout_version']] += 1
                p['captured_liquidity'] = 0
                grp[k] = p
        for (pub, pool, nft, liq, cka, ckb, pa, pb, lp) in damm_position_records(members):
            h = holder.get(nft)
            p = grp.get(pool)
            if p is None:
                gap = 'pool_not_captured' if pool in gaps else 'pool_account_missing'
                ax = ay = 0
                (fx, fy) = (pa, pb)
            else:
                gap = None
                (ax, ay) = damm_amounts(p, liq)
                fx = damm_fee(pa, liq, p['fee_a_per_liquidity'], cka)
                fy = damm_fee(pb, liq, p['fee_b_per_liquidity'], ckb)
                p['captured_liquidity'] += liq
            positions.append(('damm_v2', pub, intern(pool), h[0] if h else None, h[1] if h else None, ax, ay, fx, fy, gap, pub in changed))
        for (k, p) in grp.items():
            c = p['captured_liquidity']
            expected = p['liquidity'] - (DEAD_LIQUIDITY if p['collect_fee_mode'] == 2 else 0)
            state = 'equal' if c == expected else 'below' if c < expected else 'above'
            chk['pools_captured_liquidity_%s_pool' % state] += 1
            drift[p['window']]['pools'] += 1
            drift[p['window']]['pools_liquidity_' + state] += 1
            if state != 'equal':
                (mx, my) = damm_amounts(p, abs(c - expected))
                mismatch[k] = (p['window'], mx, my)
            (rx, ry) = damm_amounts(p, p['liquidity'])
            pools[k] = ('damm_v2', p['mint_x'], p['mint_y'], p['sqrt_price'], rx, ry, None)
        del grp
    positions.sort(key=lambda p: p[P_POS])
    diag['damm_v2_pools'] = pm.meta()
    diag['damm_v2_pool_read_windows'] = {w: dict(sorted(c.items())) for (w, c) in drift.items()}
    diag['_damm_v2_pool_mismatch'] = mismatch
    diag['damm_v2_checks'] = dict(sorted(chk.items()), positions_scanned=scan_meta('damm-v2-positions')['accounts'], positions_with_liquidity_or_pending_fees=len(positions), pools=len(keys), pools_not_captured=len(gaps), pools_missing_account=len([k for k in keys if k not in pools and k not in gaps]), positions_nft_holder_unresolved=sum((1 for p in positions if p[P_OWNER] is None)), anomalies=dict(sorted(an.items())))
    return (positions, pools)

def fmt(d, places=6, rounding=decimal.ROUND_FLOOR):
    if d is None:
        return None
    if d != 0 and d.adjusted() > 40:
        return '%.6E' % d
    return format(d.quantize(Decimal(1).scaleb(-places), rounding=rounding), 'f')

def pool_price(pool):
    """Raw price of the pool: units of token y (DAMM v2 token B) per unit of token x (token A)."""
    if pool[0] == 'dlmm':
        return Decimal(pool[3]) / Decimal(ONE_Q64)
    return Decimal(pool[3] * pool[3]) / Decimal(1 << 128)

def sol_price(all_pools):
    """Median USD/SOL of the SOL_PRICE_POOLS largest SOL-USDC pools; size = USDC side + SOL side at the pool's price."""
    cands = []
    for (addr, p) in all_pools.items():
        if {p[1], p[2]} != {WSOL, USDC}:
            continue
        P = pool_price(p)
        if P <= 0:
            continue
        if p[1] == WSOL:
            (usd_per_sol, sol_raw, usdc_raw) = (P * Decimal(1000), p[4], p[5])
        else:
            (usd_per_sol, sol_raw, usdc_raw) = (Decimal(1000) / P, p[5], p[4])
        tvl = Decimal(usdc_raw) / Decimal(10 ** 6) + Decimal(sol_raw) / Decimal(10 ** 9) * usd_per_sol
        cands.append((tvl, addr, p[0], usd_per_sol))
    cands.sort(key=lambda c: (-c[0], c[1]))
    top = cands[:SOL_PRICE_POOLS]
    assert len(top) == SOL_PRICE_POOLS, 'not enough SOL-USDC pools'
    prices = sorted((c[3] for c in top))
    return (prices[len(prices) // 2], [{'program': c[2], 'pool': c[1], 'size_usd': fmt(c[0], 2), 'usd_per_sol': fmt(c[3], 6)} for c in top], len(cands))

def price_tables(all_pools, sol_usd):
    """Q: USD per raw unit of the quote tokens. ref: for every other token, its price in the captured pool
    pairing it with SOL/USDC/USDT whose quote side holds the most USD (ties: lowest pool address)."""
    Q = {USDC: Decimal(1) / Decimal(10 ** 6), USDT: Decimal(1) / Decimal(10 ** 6), WSOL: sol_usd / Decimal(10 ** 9)}
    ref = {}
    for addr in sorted(all_pools):
        p = all_pools[addr]
        (qx, qy) = (Q.get(p[1]), Q.get(p[2]))
        if (qx is None) == (qy is None):
            continue
        P = pool_price(p)
        if qy is not None:
            (tok, depth, price) = (p[1], Decimal(p[5]) * qy, P * qy)
        else:
            if P <= 0:
                continue
            (tok, depth, price) = (p[2], Decimal(p[4]) * qx, qx / P)
        cur = ref.get(tok)
        if cur is None or depth > cur[0]:
            ref[tok] = (depth, addr, p[0], price)
    return (Q, ref)

def side_prices(pool, Q, ref):
    """(usd_per_raw_x, usd_per_raw_y, source_x, source_y); None = unpriced (valued at 0)."""
    (mx, my) = (pool[1], pool[2])
    (qx, qy) = (Q.get(mx), Q.get(my))
    if qx is not None and qy is not None:
        return (qx, qy, 'quote', 'quote')
    P = pool_price(pool)
    if qy is not None:
        return (P * qy, qy, 'own_pool', 'quote')
    if qx is not None:
        return (qx, qx / P, 'quote', 'own_pool') if P > 0 else (qx, None, 'quote', 'unpriced')
    (rx, ry) = (ref.get(mx), ref.get(my))
    return (rx[3] if rx else None, ry[3] if ry else None, 'reference_pool' if rx else 'unpriced', 'reference_pool' if ry else 'unpriced')

def position_value(pos, pools, Q, ref):
    """dict with USD of each side, of unclaimed fees, of the quote-token part, and price sources."""
    pool = pools.get(pos[P_POOL])
    if pool is None or pos[P_GAP]:
        return None
    (px, py, sx, sy) = side_prices(pool, Q, ref)
    ux = Decimal(pos[P_AX]) * px if px is not None else Decimal(0)
    uy = Decimal(pos[P_AY]) * py if py is not None else Decimal(0)
    fee = (Decimal(pos[P_FX]) * px if px is not None else Decimal(0)) + (Decimal(pos[P_FY]) * py if py is not None else Decimal(0))
    quote = (ux if pool[1] in Q else Decimal(0)) + (uy if pool[2] in Q else Decimal(0))
    unpriced = [s for (s, pr, amt, f) in (('x', px, pos[P_AX], pos[P_FX]), ('y', py, pos[P_AY], pos[P_FY])) if pr is None and (amt or f)]
    return {'pool': pool, 'usd_x': ux, 'usd_y': uy, 'usd': ux + uy, 'fee_usd': fee, 'quote_usd': quote, 'source_x': sx, 'source_y': sy, 'unpriced': unpriced}

def quote_depth_usd(pool, Q):
    """USD value of the SOL/USDC/USDT held by a pool (DLMM: sum of captured positions; DAMM v2: from pool liquidity)."""
    d = Decimal(0)
    if pool[1] in Q:
        d += Decimal(pool[4]) * Q[pool[1]]
    if pool[2] in Q:
        d += Decimal(pool[5]) * Q[pool[2]]
    return d

def depth_capped_usd(v, pools, Q, ref):
    """Sensitivity variant: each non-quote side is capped at the quote-token USD held by the pool that priced it
    (its own pool, or its reference pool); quote sides unchanged. Bounds tokens whose pool price is not backed
    by SOL/USDC/USDT liquidity."""
    pool = v['pool']
    out = Decimal(0)
    for (side, mint, other) in (('x', pool[1], pool[2]), ('y', pool[2], pool[1])):
        u = v['usd_' + side]
        if mint in Q or u == 0:
            out += u
            continue
        src = v['source_' + side]
        if src == 'own_pool':
            out += min(u, quote_depth_usd(pool, Q))
        elif src == 'reference_pool':
            out += min(u, quote_depth_usd(pools[ref[mint][1]], Q))
    return out

@functools.lru_cache(maxsize=None)
def compute():
    diag = {}
    changed = {'dlmm': scan_addresses('dlmm-positions-changed-since-S'), 'damm_v2': scan_addresses('damm-v2-positions-changed-since-S')}
    (dlmm_pos, dlmm_pools) = dlmm_compute(diag, changed['dlmm'])
    (damm_pos, damm_pools) = damm_compute(diag, changed['damm_v2'])
    pools = dict(dlmm_pools)
    pools.update(damm_pools)
    (sol_usd, sol_pools, sol_cands) = sol_price(pools)
    (Q, ref) = price_tables(pools, sol_usd)
    wallets = collections.defaultdict(list)
    skipped = collections.Counter()
    for (idx, pos) in enumerate(dlmm_pos + damm_pos):
        if pos[P_GAP]:
            skipped['data_gap:' + pos[P_GAP]] += 1
            continue
        w = pos[P_OWNER]
        if w is None:
            skipped['damm_v2_nft_holder_unresolved'] += 1
            continue
        if not wallet_on_curve(w):
            skipped['off_curve_owner:' + pos[P_PROG]] += 1
            continue
        wallets[w].append(pos)
    return {'diag': diag, 'positions': dlmm_pos + damm_pos, 'pools': pools, 'sol_usd': sol_usd, 'sol_pools': sol_pools, 'sol_candidates': sol_cands, 'Q': Q, 'ref': ref, 'wallets': dict(wallets), 'skipped': skipped, 'changed': changed}

@functools.lru_cache(maxsize=None)
def wallet_values():
    """{wallet: (usd_liquidity, usd_fees, usd_unchanged_since_S, [(pos, value_dict)])} (on-curve wallets only)."""
    r = compute()
    out = {}
    for (w, plist) in r['wallets'].items():
        tot = fees = unchanged = Decimal(0)
        vals = []
        for pos in plist:
            v = position_value(pos, r['pools'], r['Q'], r['ref'])
            vals.append((pos, v))
            if v is None:
                continue
            tot += v['usd']
            fees += v['fee_usd']
            if not pos[P_CHANGED]:
                unchanged += v['usd']
        out[w] = (tot, fees, unchanged, vals)
    return out

def wallets_for_account_reads():
    return sorted((w for (w, v) in wallet_values().items() if v[0] >= THRESHOLD))
