#!/usr/bin/env python3
"""Fetch explicit public data assets, or read local assets, and verify before use.

This optional preparation step uses the network only when --base-url is given.
The replay itself never downloads anything. No credentials or wallet APIs exist.
"""
import argparse
import gzip
import hashlib
import re
from pathlib import Path
import sys
import tarfile
import tempfile
from urllib.parse import urlsplit
from urllib.request import Request, urlopen

sys.path.insert(0, str(Path(__file__).resolve().parent))
from replay.core import file_hash, loads, require, safe_path, sha
from package_data import entry_info


def validate_index(index):
    require(set(index) == {'schema', 'data_manifest_sha256', 'assets', 'tar_input_limit_bytes', 'asset_limit_bytes'} and
            index['schema'] == 'runners-evidence-assets-v1', 'Unsupported evidence asset index')
    require(index['tar_input_limit_bytes'] == 500 * 1024 * 1024 and index['asset_limit_bytes'] == 512 * 1024 * 1024,
            'Unsupported portable part bounds')
    require(re.fullmatch('[0-9a-f]{64}', index['data_manifest_sha256']) is not None and
            isinstance(index['assets'], list) and index['assets'], 'Invalid index pin/assets')
    seen = set()
    for asset in index['assets']:
        require(set(asset) == {'name', 'bytes', 'sha256', 'files'}, 'Unknown asset index fields')
        name = asset['name']
        require(re.fullmatch('evidence-[a-z0-9-]+[.]tar[.]gz', name) is not None and name not in seen,
                'Invalid/repeated asset filename')
        seen.add(name)
        require(type(asset['bytes']) is int and 0 < asset['bytes'] <= index['asset_limit_bytes'] and
                re.fullmatch('[0-9a-f]{64}', asset['sha256']) is not None and
                isinstance(asset['files'], dict) and asset['files'], 'Invalid asset size/hash/inventory')
        for relative, meta in asset['files'].items():
            safe_path(Path('/neutral-public-root'), relative)
            require(set(meta) == {'bytes', 'sha256'} and type(meta['bytes']) is int and meta['bytes'] >= 0 and
                    re.fullmatch('[0-9a-f]{64}', meta['sha256']) is not None, 'Invalid archive member metadata')
        declared_tar_bytes = 10240 + sum(len(entry_info(relative, meta['bytes']).tobuf(format=tarfile.GNU_FORMAT))
            + ((meta['bytes'] + 511) // 512) * 512 for relative, meta in asset['files'].items())
        require(declared_tar_bytes <= index['tar_input_limit_bytes'], 'Declared tar input exceeds part bound')


def extract(archive, destination, expected_files):
    observed = set()
    total = 0
    with gzip.open(archive, 'rb') as expanded:
        for chunk in iter(lambda: expanded.read(1024 * 1024), b''):
            total += len(chunk)
            require(total <= 500 * 1024 * 1024, 'Actual tar input exceeds portable part bound')
    with tarfile.open(archive, 'r:gz') as source:
        for member in source:
            require(member.isfile() and member.name in expected_files and member.name not in observed,
                    'Archive contains a link, special, repeated or unplanned entry')
            require(not member.pax_headers and member.uid == member.gid == member.mtime == 0
                    and member.uname == member.gname == '' and member.mode == 0o644,
                    'Archive contains non-neutral metadata')
            path = safe_path(destination, member.name)
            require(not path.exists(), 'Archive would overwrite an existing file')
            meta = expected_files[member.name]
            require(member.size == meta['bytes'], 'Archive entry size differs')
            path.parent.mkdir(parents=True, exist_ok=True)
            digest, total = hashlib.sha256(), 0
            with source.extractfile(member) as incoming, path.open('xb') as outgoing:
                for chunk in iter(lambda: incoming.read(1024 * 1024), b''):
                    total += len(chunk)
                    require(total <= meta['bytes'], 'Archive expanded beyond its bound')
                    digest.update(chunk)
                    outgoing.write(chunk)
            require(total == meta['bytes'] and digest.hexdigest() == meta['sha256'], 'Extracted entry hash differs')
            observed.add(member.name)
    require(observed == set(expected_files), 'Archive omits required files')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--index', type=Path, required=True)
    parser.add_argument('--index-sha256', required=True)
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument('--from-directory', type=Path)
    group.add_argument('--base-url')
    parser.add_argument('--destination', type=Path, required=True)
    args = parser.parse_args()
    raw = args.index.read_bytes()
    require(sha(raw) == args.index_sha256, 'Evidence index pin differs')
    index = loads(raw)
    validate_index(index)
    destination = args.destination.resolve()
    require(not destination.exists(), 'Destination must not already exist')
    destination.parent.mkdir(parents=True, exist_ok=True)
    if args.base_url:
        location = urlsplit(args.base_url)
        require(location.scheme == 'https' and location.hostname and not location.username and not location.password
                and not location.query and not location.fragment, 'Use a public HTTPS asset base URL without credentials/query')
    with tempfile.TemporaryDirectory(prefix='evidence-fetch-', dir=destination.parent) as temporary:
        stage = Path(temporary) / 'evidence'
        stage.mkdir()
        all_files = set()
        for asset in index['assets']:
            name = asset['name']
            require(Path(name).name == name and name.endswith('.tar.gz'), 'Invalid asset filename')
            require(not (all_files & set(asset['files'])), 'Data assets have overlapping entries')
            all_files.update(asset['files'])
            if args.from_directory:
                archive = safe_path(args.from_directory, name)
                require(not archive.is_symlink(), 'Data asset must be a regular file')
            else:
                archive = Path(temporary) / name
                request = Request(args.base_url.rstrip('/') + '/' + name, headers={'User-Agent': 'RUNNERS-evidence-verifier'})
                with urlopen(request, timeout=60) as incoming, archive.open('xb') as outgoing:
                    final = urlsplit(incoming.url)
                    require(final.scheme == 'https' and not final.username and not final.password,
                            'Unsafe asset redirect')
                    size = 0
                    for chunk in iter(lambda: incoming.read(1024 * 1024), b''):
                        size += len(chunk)
                        require(size <= asset['bytes'], 'Download exceeds pinned size')
                        outgoing.write(chunk)
            require(archive.stat().st_size == asset['bytes'] and file_hash(archive) == asset['sha256'],
                    'Data asset size/hash differs')
            extract(archive, stage, asset['files'])
            if not args.from_directory:
                archive.unlink()
        from reproduce import check_manifest
        check_manifest(stage, index['data_manifest_sha256'])
        stage.rename(destination)
    print('Evidence assets and complete extracted inventory verified.')


if __name__ == '__main__':
    try:
        main()
    except (ValueError, OSError, KeyError, tarfile.TarError) as error:
        raise SystemExit('FETCH FAILED: ' + str(error))
