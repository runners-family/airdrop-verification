#!/usr/bin/env python3
"""Combine verified local stage projections into a separate portable data tree.

Only immutable public files are hardlinked. Private crosswalks stay beside the
output, never inside it. No original evidence directory is modified.
"""
import argparse
import gzip
import os
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent))
from replay.core import canonical, file_hash, loads, require, safe_path, sha
from replay.projection import encode, identity_rows
from reproduce import check_manifest, REQUIRED

OMIT = {'README.md', 'criteria.md', 'verify.py', 'checksums.json', 'source-status.json', 'projection-provenance.json'}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--part', nargs=2, action='append', required=True, metavar=('DIRECTORY', 'MANIFEST_SHA256'))
    parser.add_argument('--out', type=Path, required=True)
    args = parser.parse_args()
    out = args.out.resolve()
    require(not out.exists(), 'Use a new assembled output')
    out.mkdir(parents=True)
    inventory, provenance, private, stages = {}, {}, [], set()
    for directory, digest in args.part:
        root = Path(directory).resolve()
        manifest = check_manifest(root, digest)
        stages |= set(loads((root / 'source-status.json').read_bytes())['implemented_stages'])
        source_provenance = loads((root / 'projection-provenance.json').read_bytes())['files']
        private_source = root.with_name(root.name + '.private-provenance.json')
        if private_source.is_file():
            private.extend(loads(private_source.read_bytes())['files'])
        for row in source_provenance:
            private.append(row)
            public = {key: value for key, value in row.items() if key != 'original_sha256'}
            if row['transformation'] == 'official-sdk-layout-source-v1' and 'original_sha256' in row:
                public['original_sha256'] = row['original_sha256']
            provenance[row['public_path']] = public
        for relative, meta in manifest['files'].items():
            if relative in OMIT:
                continue
            if relative in inventory:
                require(inventory[relative] == meta, 'Conflicting data between stage projections')
                continue
            target = safe_path(out, relative)
            target.parent.mkdir(parents=True, exist_ok=True)
            if relative.startswith('data/exclusions/identity/'):
                # One final minimal category/knownness projection. This drops
                # arbitrary provider type text while preserving rule semantics.
                with gzip.open(root / relative, 'rb') as incoming, target.open('xb') as handle:
                    with gzip.GzipFile(fileobj=handle, mode='wb', filename='', mtime=0) as outgoing:
                        for line in incoming:
                            row = loads(line)
                            if row['body'] is not None:
                                row['body'] = identity_rows(row['body'])
                            outgoing.write(encode(row))
                meta = dict(bytes=target.stat().st_size, sha256=file_hash(target), schema='cluster-capture-projection-v2')
                provenance[relative].update(public_sha256=meta['sha256'], transformation=meta['schema'])
            else:
                os.link(root / relative, target)
            inventory[relative] = meta
    require(stages == REQUIRED, 'Assembled data is missing required source stages')
    provenance = {key: row for key, row in provenance.items() if key in inventory}
    for relative, meta in inventory.items():
        row = provenance.setdefault(relative, dict(public_path=relative, public_sha256=meta['sha256'],
                                                   transformation=meta['schema']))
        require(row['public_sha256'] == meta['sha256'] and row['transformation'] == meta['schema'],
                'Projection provenance does not match exported bytes/profile: ' + relative)
    def write(relative, value, schema):
        raw = encode(value)
        (out / relative).write_bytes(raw)
        inventory[relative] = dict(bytes=len(raw), sha256=sha(raw), schema=schema)
    write('projection-provenance.json', dict(schema='projection-provenance-v1',
          authentication='Exported projection hashes are pins, not provider authentication. Original transport/identity hashes are withheld.',
          files=[provenance[key] for key in sorted(provenance)]), 'projection-provenance-v1')
    write('source-status.json', dict(schema='source-status-v1', implemented_stages=sorted(stages),
          full_source_replay='Requires a complete successful reproduce.py --all receipt.',
          source_trust='Unsigned historical provider assertions and the disclosed organizer roster'), 'source-status-v1')
    raw = encode(dict(schema='runners-public-data-manifest-v1', files=inventory))
    digest = sha(raw)
    (out / 'data-manifest.json').write_bytes(raw)
    (out / 'data-manifest.sha256').write_text(digest + '  data-manifest.json\n')
    private_path = out.with_name(out.name + '.private-provenance.json')
    private_path.write_bytes(encode(dict(schema='private-stage-crosswalk-v1', files=private)))
    private_path.chmod(0o600)
    print(canonical(dict(files=len(inventory), bytes=sum(row['bytes'] for row in inventory.values()),
                         manifest_sha256=digest, stages=sorted(stages))).decode(), end='')


if __name__ == '__main__':
    main()
