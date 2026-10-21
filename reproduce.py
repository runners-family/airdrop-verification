#!/usr/bin/env python3
"""Replay published evidence offline. Missing stages never produce a full PASS."""
import argparse
import json
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent))
from replay.core import address, canonical, file_hash, loads, read_wallets, require, safe_path, sha, wallet_bytes
from replay.allocation import calculate

REQUIRED = {'seeker', 'meteora', 'phoenix', 'symmetry', 'squads', 'kamino', 'defi',
            'exponent-hylo', 'holders', 'solfate', 'islanddao', 'ride', 'overpass', 'exclusions'}
CLAIMS_SHA256 = '4d78c121a841c28c3a02963a0bf5266166aa963e42eafe60d615f715ebd731a2'


def check_manifest(root, expected):
    require(root.is_dir() and not root.is_symlink(), 'Evidence root must be a real directory')
    for name in ('data-manifest.json', 'data-manifest.sha256'):
        require((root / name).is_file() and not (root / name).is_symlink(), 'Manifest must not be symlinked')
    manifest_raw = (root / 'data-manifest.json').read_bytes()
    require(sha(manifest_raw) == expected, 'Data manifest pin differs')
    require((root / 'data-manifest.sha256').read_bytes() ==
            (expected + '  data-manifest.json\n').encode(), 'Data manifest sidecar differs')
    manifest = loads(manifest_raw)
    require(manifest['schema'] == 'runners-public-data-manifest-v1', 'Unsupported manifest')
    for relative, meta in manifest['files'].items():
        require(relative not in ('data-manifest.json', 'data-manifest.sha256'), 'Manifest cannot list itself/sidecar')
        path = safe_path(root, relative)
        require(path.is_file() and not (root / relative).is_symlink(), 'Missing or symlinked data file')
        require(path.stat().st_size == meta['bytes'] and file_hash(path) == meta['sha256'],
                'Data file digest differs: ' + relative)
    paths = list(root.rglob('*'))
    require(not any(path.is_symlink() for path in paths), 'Evidence tree contains a symlink')
    require(all(path.is_file() or path.is_dir() for path in paths), 'Evidence tree contains a special file')
    present = {path.relative_to(root).as_posix() for path in paths if path.is_file()}
    require(present == set(manifest['files']) | {'data-manifest.json', 'data-manifest.sha256'},
            'Data inventory contains unlisted files')
    return manifest


def islanddao(root):
    raw = (root / 'data/islanddao/organizer-roster.txt').read_bytes()
    source = loads((root / 'data/islanddao/source.json').read_bytes())
    require(source['attribution'] == 'Provided by the IslandDAO organizers', 'Organizer attribution differs')
    rows = [line.strip() for line in raw.decode('utf-8-sig').splitlines() if line.strip()]
    result = wallet_bytes(sorted(set(rows)))
    require(len(rows) == len(set(rows)) == source['normalized_count'] == 168, 'Organizer roster differs')
    require(sha(result) == source['normalized_sha256'], 'Organizer normalization differs')
    return {'islanddao_participants': {'wallets.txt': result}}, {'wallets': 168,
            'source': 'Provided by the IslandDAO organizers'}


def run_stage(stage, root, reference, scratch):
    if stage == 'islanddao':
        return islanddao(root)
    if stage == 'squads':
        from replay.squads import derive
        outputs, receipt = derive(root / 'data/squads', reference)
        return {'squads_teams': outputs}, receipt
    if stage == 'phoenix':
        from replay.phoenix import derive
        outputs, receipt = derive(root / 'data/phoenix', reference)
        return {'phoenix_perps': outputs}, receipt
    if stage == 'solfate':
        from replay.solfate import derive
        outputs, receipt = derive(root / 'data/solfate', reference)
        return {'solana_builder': outputs}, receipt
    if stage == 'seeker':
        from replay.seeker import derive
        outputs, receipt = derive(root / 'data/seeker', reference)
        return {'solana_seeker': outputs}, receipt
    if stage in {'holders', 'kamino'}:
        from replay.holders import derive
        return derive(root, stage)
    if stage == 'ride':
        from replay.ride import derive
        outputs, receipt = derive(root / 'data/ride', reference)
        return {'ride_markets': outputs}, receipt
    if stage == 'exponent-hylo':
        from replay.exponent import derive
        return derive(root, reference, scratch)
    if stage == 'defi':
        from replay.defi import derive
        return derive(root, reference, scratch)
    if stage == 'meteora':
        from replay.meteora import derive
        outputs, receipt = derive(root, reference)
        return {'meteora_liquidity_provider': outputs}, receipt
    if stage == 'symmetry':
        from replay.symmetry import derive
        outputs, receipt = derive(root, reference)
        return {'symmetry': outputs}, receipt
    if stage == 'overpass':
        from replay.overpass import derive
        outputs, receipt = derive(root, reference)
        return {'overpass': outputs}, receipt
    raise ValueError('Required stage is not implemented: ' + stage)


def allocation_check(root, groups=None, out=None):
    config = loads((root / 'allocation.json').read_bytes())
    if groups is None:
        groups = {row['id']: read_wallets(safe_path(root, row['wallets_file'])) for row in config['groups']}
    budgets, amounts, csv = calculate(config, groups)
    for row in config['groups']:
        require(budgets[row['id']] == row['total_base_units'], 'Category budget differs')
    baseline = (root / 'claims.csv').read_bytes()
    if out is not None:
        (out / 'claims.csv').write_bytes(csv)
    if csv != baseline and out is not None:
        expected = {}
        lines = baseline.decode('ascii').splitlines()
        require(lines and lines[0] == 'wallet,amount', 'Unexpected supplied CSV header')
        for line in lines[1:]:
            wallet, amount = line.split(',')
            address(wallet)
            require(wallet not in expected and amount.isdigit(), 'Duplicate/invalid supplied CSV row')
            expected[wallet] = int(amount)
        differences = [dict(wallet=wallet, supplied_base_units=expected.get(wallet),
                            regenerated_base_units=amounts.get(wallet))
                       for wallet in sorted(set(expected) | set(amounts)) if expected.get(wallet) != amounts.get(wallet)]
        (out / 'claim-differences.json').write_bytes(canonical(dict(wallet_amount_differences=differences,
            supplied_sha256=sha(baseline), regenerated_sha256=sha(csv),
            differing_byte_positions=sum(a != b for a, b in zip(csv, baseline)) + abs(len(csv) - len(baseline)))))
    require(csv == baseline, 'CSV bytes differ')
    require(sha(csv) == config['claims_sha256'] == CLAIMS_SHA256, 'CSV hash differs from the pinned public release')
    require(len(amounts) == 144542 and sum(map(len, groups.values())) == 156259 and
            sum(amounts.values()) == 10**15 and config['decimals'] == 6, 'Published inventory/supply differs')
    return {'wallets': len(amounts), 'memberships': sum(map(len, groups.values())),
            'base_units': sum(amounts.values()), 'csv_sha256': sha(csv), 'csv_bytes': len(csv),
            'wallet_differences': 0, 'amount_differences': 0, 'byte_differences': 0}


def explain_wallet(wallet, root, out, groups):
    address(wallet)
    config = loads((root / 'allocation.json').read_bytes())
    budgets, amounts, _ = calculate(config, groups)
    categories = []
    for row in config['groups']:
        category = row['id']
        pre = out / 'pre-exclusion' / category
        pre_members = read_wallets(pre / 'wallets.txt')
        final_members = groups[category]
        amount = 0
        if wallet in final_members:
            quotient, residual = divmod(budgets[category], len(final_members))
            amount = quotient + (final_members.index(wallet) < residual)
        reasons = []
        for path in sorted(pre.glob('*.jsonl')):
            for line in path.open('rb'):
                if wallet.encode() not in line:
                    continue
                fact = loads(line)
                if fact.get('wallet') == wallet or fact.get('owner') == wallet:
                    reasons.append(dict(file=path.relative_to(out).as_posix(), fact=fact))
        categories.append(dict(category=category, in_regenerated_prelist=wallet in pre_members,
            in_regenerated_final_list=wallet in final_members, gross_base_units=amount,
            evidence=reasons, decision_detail='Not present in the captured regenerated candidate/list universe.'
                if not reasons and wallet not in pre_members else None))
    exclusion = None
    for line in (out / 'exclusions/excluded.jsonl').read_bytes().splitlines():
        row = loads(line)
        if row['wallet'] == wallet:
            exclusion = row
            break
    return dict(wallet=wallet, gross_base_units=amounts.get(wallet, 0), categories=categories,
                cluster_exclusion=exclusion,
                organizer_roster_source='Provided by the IslandDAO organizers',
                source_limit='Explanation of the captured replay; no assertion about an uncaptured wallet or human identity.')


def exclusion_check(root, groups, out):
    from replay.exclusions import derive
    final, outputs, receipt = derive(root / 'data/exclusions', groups)
    for name in ('excluded-wallets.txt', 'excluded.jsonl'):
        require(outputs[name] == (root / 'expected/exclusions' / name).read_bytes(),
                'Reconstructed exclusion set/reasons differ: ' + name)
    config = loads((root / 'allocation.json').read_bytes())
    for row in config['groups']:
        raw = wallet_bytes(final[row['id']])
        require(raw == safe_path(root, row['wallets_file']).read_bytes(), 'Reconstructed final list differs')
        target = out / 'post-exclusion' / (row['id'] + '.txt')
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(raw)
    target = out / 'exclusions'
    target.mkdir()
    for name, raw in outputs.items():
        (target / name).write_bytes(raw)
    return final, receipt


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--data', type=Path, required=True)
    parser.add_argument('--manifest-sha256', required=True)
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument('--all', action='store_true')
    group.add_argument('--stage', choices=sorted(REQUIRED))
    group.add_argument('--allocation-only', action='store_true')
    parser.add_argument('--out', type=Path, required=True)
    parser.add_argument('--wallet', help='Write an explanation after a complete successful source replay')
    args = parser.parse_args()
    root, out = args.data.resolve(), args.out.resolve()
    require(not out.exists(), 'Output directory must not exist')
    require(root != out and root not in out.parents, 'Output must be outside evidence')
    check_manifest(root, args.manifest_sha256)
    reference = loads((root / 'snapshot.json').read_bytes())
    implemented = set(loads((root / 'source-status.json').read_bytes())['implemented_stages'])
    if args.all:
        require(implemented == REQUIRED, 'Full replay unavailable; missing stages: ' + ', '.join(sorted(REQUIRED - implemented)))
        stages = sorted(REQUIRED - {'exclusions'})
    elif args.stage:
        require(args.stage in implemented, 'Requested source stage is unavailable')
        stages = [] if args.stage == 'exclusions' else [args.stage]
    else:
        stages = []
    require(args.wallet is None or args.all, '--wallet requires the complete source replay')
    receipts = {}
    regenerated = {}
    out.mkdir(parents=True)
    for stage in stages:
        groups, receipt = run_stage(stage, root, reference, out)
        for category, files in groups.items():
            require(category not in regenerated, 'Category generated more than once')
            regenerated[category] = files['wallets.txt'].decode('ascii').splitlines()
            target = out / 'pre-exclusion' / category
            target.mkdir(parents=True)
            for name, raw in files.items():
                (target / name).write_bytes(raw)
            supplied = (root / 'expected/pre-exclusion' / (category + '.txt')).read_bytes()
            if files['wallets.txt'] != supplied:
                expected_set, actual_set = set(supplied.decode('ascii').splitlines()), set(regenerated[category])
                (target / 'list-differences.json').write_bytes(canonical(dict(
                    supplied_only=sorted(expected_set - actual_set), regenerated_only=sorted(actual_set - expected_set),
                    supplied_sha256=sha(supplied), regenerated_sha256=sha(files['wallets.txt']))))
                raise ValueError('Regenerated prelist differs: ' + category)
        receipts[stage] = receipt
    if args.all or args.stage == 'exclusions':
        if not args.all:
            regenerated = {path.stem: read_wallets(path) for path in (root / 'expected/pre-exclusion').glob('*.txt')}
        regenerated, receipt = exclusion_check(root, regenerated, out)
        receipt['candidate_source'] = 'regenerated source categories' if args.all else 'supplied comparison prelists; eligibility not verified by this stage'
        receipts['exclusions'] = receipt
    if args.all or args.allocation_only:
        receipts['allocation'] = allocation_check(root, regenerated if args.all else None, out)
    if args.wallet:
        (out / 'wallet-explanation.json').write_bytes(canonical(explain_wallet(args.wallet, root, out, regenerated)))
    result = {'full_source_replay': bool(args.all), 'data_manifest_sha256': args.manifest_sha256, 'stages': receipts,
              'eligibility_authenticity': 'External historical source assertions; see source-by-source limits.',
              'on_chain_commitment': 'NOT TESTED'}
    (out / 'receipt.json').write_bytes(canonical(result))
    print(json.dumps(result, sort_keys=True))


if __name__ == '__main__':
    try:
        main()
    except (ValueError, KeyError, OSError, UnicodeError) as error:
        raise SystemExit('REPLAY FAILED: ' + str(error))
