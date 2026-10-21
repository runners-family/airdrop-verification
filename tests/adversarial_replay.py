#!/usr/bin/env python3
"""Historical-data integration mutations, with manifests deliberately repinned.

Use public evidence only. Files are hardlinked for space, then unlinked before
any mutation. The original evidence is never written or renamed.
"""
import argparse
import gzip
import os
from pathlib import Path
import shutil
import subprocess
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from replay.core import canonical, encode58, file_hash, loads, require, sha, wallet_bytes
from reproduce import check_manifest


def replace(path, raw):
    path.unlink()
    path.write_bytes(raw)


def repin(root, relative):
    manifest = loads((root / 'data-manifest.json').read_bytes())
    path = root / relative
    manifest['files'][relative].update(bytes=path.stat().st_size, sha256=file_hash(path))
    raw = canonical(manifest)
    digest = sha(raw)
    replace(root / 'data-manifest.json', raw)
    replace(root / 'data-manifest.sha256', (digest + '  data-manifest.json\n').encode())
    return digest


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--data', type=Path, required=True)
    parser.add_argument('--manifest-sha256', required=True)
    parser.add_argument('--out', type=Path, required=True)
    args = parser.parse_args()
    root, out = args.data.resolve(), args.out.resolve()
    require(not out.exists() and root not in out.parents and root != out, 'Use a new output outside evidence')
    check_manifest(root, args.manifest_sha256)
    out.mkdir(parents=True)
    receipts = []
    for case in ('inserted-comparison-wallet', 'omitted-comparison-wallet', 'missing-activity-page'):
        copy = out / case
        shutil.copytree(root, copy, copy_function=os.link)
        if case.endswith('comparison-wallet'):
            relative = 'expected/pre-exclusion/squads_teams.txt'
            path = copy / relative
            rows = path.read_text().splitlines()
            if case.startswith('inserted'):
                wallet = encode58(bytes.fromhex(sha(b'RUNNERS nonparticipant mutation fixture')))
                require(wallet not in rows, 'Mutation fixture already present')
                rows.append(wallet)
            else:
                rows.pop()
            replace(path, wallet_bytes(sorted(rows)))
            expected_failure = 'Regenerated prelist differs'
        else:
            relative = 'data/squads/activity.jsonl.gz'
            path = copy / relative
            temporary = path.with_suffix('.mutation')
            with gzip.open(path, 'rb') as incoming, temporary.open('xb') as target:
                with gzip.GzipFile(fileobj=target, mode='wb', filename='', mtime=0) as outgoing:
                    for index, line in enumerate(incoming):
                        if index == 0:
                            row = loads(line)
                            row['pages'] = []
                            line = canonical(row)
                        outgoing.write(line)
            path.unlink()
            temporary.rename(path)
            expected_failure = 'Activity capture ended'
        digest = repin(copy, relative)
        command = [sys.executable, '-I', '-B', str(Path(__file__).resolve().parents[1] / 'reproduce.py'),
                   '--data', str(copy), '--manifest-sha256', digest, '--stage', 'squads',
                   '--out', str(out / (case + '-result'))]
        result = subprocess.run(command, env={'PATH': os.defpath, 'TZ': 'UTC'}, capture_output=True,
                                text=True, timeout=600)
        passed = result.returncode != 0 and expected_failure in result.stderr + result.stdout
        receipts.append(dict(case=case, manifest_recomputed=True, rejected_by_source_replay=passed))
        require(passed, 'Mutation was not rejected for the intended source-consistency reason: ' + case)
        shutil.rmtree(copy)
    (out / 'summary.json').write_bytes(canonical({'adversarial_replay': receipts}))
    print('All three repinned-manifest mutations rejected by source replay.')


if __name__ == '__main__':
    main()
