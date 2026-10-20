#!/usr/bin/env python3
"""Independently reproduce the final allocation with Python 3.10+, standard library only, offline."""
import argparse
import csv
import hashlib
import json
from collections import Counter
from fractions import Fraction
from pathlib import Path

HERE = Path(__file__).resolve().parent
CSV_SHA256 = "4d78c121a841c28c3a02963a0bf5266166aa963e42eafe60d615f715ebd731a2"
MERKLE_ROOT = "256aa62ae42df907f0630982248f01af34b166af952a96b7c4d0af2c3a7fcbbb"
BASE58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"


def require(ok, message):
    if not ok:
        raise SystemExit("FAIL: " + message)


def key(value):
    require(bool(value) and all(c in BASE58 for c in value), "invalid address")
    n = 0
    for c in value:
        n = n * 58 + BASE58.index(c)
    require(len(value) - len(value.lstrip("1")) + (n.bit_length() + 7) // 8 == 32, "invalid address length")
    return n.to_bytes(32, "big")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--wallet", help="show a participant's category awards")
    parser.add_argument("--distributor", help="optionally verify the Merkle root using the public distribution account")
    args = parser.parse_args()
    manifest = json.loads((HERE / "checksums.json").read_text())
    for item in manifest["files"]:
        p = HERE / item["path"]
        require(p.resolve().is_relative_to(HERE), "unsafe file path")
        b = p.read_bytes()
        require(len(b) == item["bytes"] and hashlib.sha256(b).hexdigest() == item["sha256"], "changed file: " + item["path"])
    config = json.loads((HERE / "allocation.json").read_text())
    require(config['decimals'] == 6 and config['supply_base_units'] == 10**15, "supply or decimals")
    require(config['claims_sha256'] == CSV_SHA256 and config['expected_merkle_root'] == MERKLE_ROOT, "locked commitment")
    groups = config['groups']
    require(len(groups) == 18 and len({g['id'] for g in groups}) == 18, "category count")
    lists, totals, weights = {}, {}, {}
    for g in groups:
        raw = (HERE / g['wallets_file']).read_bytes()
        require(hashlib.sha256(raw).hexdigest() == g['wallets_sha256'], "category list checksum")
        wallets = raw.decode().splitlines()
        require(wallets == sorted(set(wallets)) and len(wallets) == g['wallets'], "category count, order or duplicates")
        lists[g['id']] = wallets
        if g['rule'] == 'fixed_share':
            value = Fraction(str(g['share_percent'])) * config['supply_base_units'] / 100
            require(value.denominator == 1, "fractional fixed-share budget")
            totals[g['id']] = int(value)
        elif g['rule'] == 'fixed_per_wallet':
            totals[g['id']] = g['tokens_per_wallet'] * 10**6 * len(wallets)
        elif g['rule'] == 'remainder_pool':
            weights[g['id']] = Fraction(g['weight'])
        elif g['rule'] == 'remainder_per_wallet':
            weights[g['id']] = Fraction(g['weight_per_wallet']) * len(wallets)
        else:
            require(False, "unknown budget rule")
    remaining = config['supply_base_units'] - sum(totals.values())
    exact = {gid: remaining * weight / sum(weights.values()) for gid, weight in weights.items()}
    floors = {gid: amount.numerator // amount.denominator for gid, amount in exact.items()}
    extras = remaining - sum(floors.values())
    winners = sorted(weights, key=lambda gid: (-(exact[gid] - floors[gid]), gid))[:extras]
    totals.update({gid: amount + (gid in winners) for gid, amount in floors.items()})
    require(sum(totals.values()) == 10**15, "unallocated supply")
    require(totals['solana_seeker'] > totals['meteora_liquidity_provider'] > totals['phoenix_perps'] > totals['symmetry'], "category budget order")
    require(all(value < totals['symmetry'] for gid, value in totals.items() if gid not in {'solana_seeker', 'meteora_liquidity_provider', 'phoenix_perps', 'symmetry'}), "remaining category budget order")
    awards, memberships, wallet_awards = Counter(), 0, []
    for g in groups:
        require(totals[g['id']] == g['total_base_units'], "category budget differs")
        wallets = lists[g['id']]
        base, extra = divmod(totals[g['id']], len(wallets))
        memberships += len(wallets)
        for i, wallet in enumerate(wallets):
            amount = base + (i < extra)
            awards[wallet] += amount
            if wallet == args.wallet:
                wallet_awards.append({'category': g['label'], 'amount_base_units': amount})
    expected = ('wallet,amount\n' + ''.join(f'{wallet},{awards[wallet]}\n' for wallet in sorted(awards))).encode()
    csv_data = (HERE / 'claims.csv').read_bytes()
    require(expected == csv_data and hashlib.sha256(csv_data).hexdigest() == CSV_SHA256, "wallet awards differ from locked CSV")
    require(len(awards) == config['wallet_count'] == 144542 and memberships == config['category_memberships'] == 156259, "final inventory")
    print("PASS: all 18 category budgets, 156,259 category awards and 144,542 final wallet awards match exactly.")
    print("PASS: exactly 1,000,000,000 RUNNERS; zero unallocated base units; locked CSV checksum matches.")
    if args.wallet:
        key(args.wallet)
        print(json.dumps({'wallet': args.wallet, 'eligible': bool(wallet_awards), 'total_base_units': awards[args.wallet], 'awards': wallet_awards}, indent=2))
    if args.distributor:
        distributor = key(args.distributor)
        level = sorted(hashlib.sha256(b'RUNNERS:airdrop:leaf:v1' + distributor + key(wallet) + amount.to_bytes(8, 'little')).digest() for wallet, amount in awards.items())
        while len(level) > 1:
            level = [hashlib.sha256(b'RUNNERS:airdrop:node:v1' + b''.join(sorted(level[i:i+2]))).digest() if i+1 < len(level) else level[i] for i in range(0, len(level), 2)]
        require(level[0].hex() == MERKLE_ROOT, "Merkle root differs")
        print("PASS: Merkle root matches the locked commitment.")
    else:
        print("Merkle-root verification was not requested. Pass --distributor with the public distribution account to run it.")


if __name__ == '__main__':
    main()
