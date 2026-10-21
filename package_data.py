#!/usr/bin/env python3
"""Build deterministic, neutral data assets from a verified local evidence tree."""
import argparse
import gzip
from pathlib import Path
import sys
import tarfile

sys.path.insert(0, str(Path(__file__).resolve().parent))
from replay.core import canonical, file_hash, loads, require
from reproduce import check_manifest

TAR_INPUT_LIMIT = 500 * 1024 * 1024
ASSET_LIMIT = 512 * 1024 * 1024


def entry_info(relative, size):
    info = tarfile.TarInfo(relative)
    info.size, info.mode, info.mtime = size, 0o644, 0
    info.uid = info.gid = 0
    info.uname = info.gname = ''
    return info


def chunks(files):
    current, used = {}, 10240  # Reserve the final tar block padding.
    for relative, meta in sorted(files.items()):
        header = entry_info(relative, meta['bytes']).tobuf(format=tarfile.GNU_FORMAT)
        cost = len(header) + ((meta['bytes'] + 511) // 512) * 512
        require(cost + 10240 <= TAR_INPUT_LIMIT, 'Single evidence file exceeds the portable part bound')
        if current and used + cost > TAR_INPUT_LIMIT:
            yield current
            current, used = {}, 10240
        current[relative] = meta
        used += cost
    if current:
        yield current


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--evidence', type=Path, required=True)
    parser.add_argument('--manifest-sha256', required=True)
    parser.add_argument('--out', type=Path, required=True)
    args = parser.parse_args()
    root, out = args.evidence.resolve(), args.out.resolve()
    require(not out.exists() and root != out and root not in out.parents, 'Use a new output outside evidence')
    manifest = check_manifest(root, args.manifest_sha256)
    out.mkdir(parents=True)
    groups = {}
    for relative, meta in manifest['files'].items():
        parts = relative.split('/')
        group = parts[1] if parts[0] == 'data' else 'common'
        groups.setdefault(group, {})[relative] = meta
    for relative in ('data-manifest.json', 'data-manifest.sha256'):
        path = root / relative
        groups['common'][relative] = dict(bytes=path.stat().st_size, sha256=file_hash(path))
    assets = []
    for group, all_files in sorted(groups.items()):
        for number, files in enumerate(chunks(all_files), 1):
            name = 'evidence-' + group + '-%03d.tar.gz' % number
            path = out / name
            with path.open('xb') as target:
                with gzip.GzipFile(fileobj=target, mode='wb', filename='', mtime=0, compresslevel=1) as compressed:
                    with tarfile.open(fileobj=compressed, mode='w', format=tarfile.GNU_FORMAT) as archive:
                        for relative, meta in sorted(files.items()):
                            info = entry_info(relative, meta['bytes'])
                            with (root / relative).open('rb') as source:
                                archive.addfile(info, source)
            require(path.stat().st_size <= ASSET_LIMIT, 'Compressed asset exceeds portable part bound')
            assets.append(dict(name=name, bytes=path.stat().st_size, sha256=file_hash(path),
                               files={relative: {key: meta[key] for key in ('bytes', 'sha256')}
                                      for relative, meta in sorted(files.items())}))
    index = dict(schema='runners-evidence-assets-v1', data_manifest_sha256=args.manifest_sha256,
                 tar_input_limit_bytes=TAR_INPUT_LIMIT, asset_limit_bytes=ASSET_LIMIT, assets=assets)
    raw = canonical(index)
    (out / 'evidence-index.json').write_bytes(raw)
    print('Built %d pinned evidence assets.' % len(assets))


if __name__ == '__main__':
    main()
