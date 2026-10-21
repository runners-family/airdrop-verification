#!/usr/bin/env python3
"""Create a separate, schema-allowlisted public evidence projection.

Original files are read only. The destination must be new. No credentials or
network access are used. This tool never publishes, signs, or modifies lists.
"""
import argparse
import base64
import gzip
import json
import shutil
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent))
from replay.core import canonical, file_hash, loads, read_wallets, require, sha, wallet_bytes
from replay.projection import encode, identity_rows, project_request, rpc_response, select, strict

SNAPSHOT = 'output/airdrop-snapshot-2026-10-17'
EXCLUSIONS = 'output/airdrop-sybil-exclusions-2026-10-19-v1'
BASE_CLAIMS = '4d78c121a841c28c3a02963a0bf5266166aa963e42eafe60d615f715ebd731a2'


class Export:
    def __init__(self, source, destination):
        self.source = source.resolve()
        self.destination = destination.resolve()
        require(not self.destination.exists(), 'Destination must not exist')
        require(self.destination != self.source and not self.source.is_relative_to(self.destination),
                'Destination must be separate from original evidence')
        self.destination.mkdir(parents=True)
        self.rows = {}
        self.provenance = []
        index = self.source / SNAPSHOT / 'index.json'
        require(file_hash(index) == '42131c62e13c9c6f24c587c97f8679f7e49543da057b93306718b08bb2a5d8cf',
                'Historical source index changed')
        self.original_pins = {}
        index_data = loads(index.read_bytes())
        bundles = {row['bundle']: row['bundle_manifest_sha256'] for row in index_data['groups']}
        bundles.update({row['bundle']: row['bundle_manifest_sha256']
                        for key, row in index_data['supporting_bundles'].items() if key == 'meteora-current'})
        for relative, digest in bundles.items():
            folder = self.source / relative
            manifest_path = folder / 'manifest.json'
            require(file_hash(manifest_path) == digest, 'Historical source manifest changed')
            manifest = loads(manifest_path.read_bytes())
            entries = manifest['files']
            if isinstance(entries, list):
                for row in entries:
                    self.original_pins[str(folder / row['path'])] = row
            else:
                for key, row in entries.items():
                    candidate = self.source / key if key.startswith('output/') else folder / key
                    self.original_pins[str(candidate)] = row
            for section in ('external_inputs', 'external', 'inputs'):
                for key, row in manifest.get(section, {}).items():
                    if isinstance(row, dict) and {'bytes', 'sha256'} <= set(row):
                        self.original_pins[str(self.source / key)] = row

    def check_original(self, path):
        meta = self.original_pins.get(str(path))
        require(meta is not None, 'Original input is not in the selected source manifest')
        require(path.stat().st_size == meta['bytes'] and file_hash(path) == meta['sha256'],
                'Original source file changed')

    def write(self, relative, raw, schema, original=None):
        from replay.core import safe_path
        path = safe_path(self.destination, relative)
        require(not path.exists(), 'Duplicate publication path')
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(raw)
        self.rows[relative] = {'bytes': len(raw), 'sha256': sha(raw), 'schema': schema}
        if original is not None:
            # Raw source paths and transport records are deliberately not exported.
            self.provenance.append({'public_path': relative, 'original_sha256': file_hash(original),
                                    'public_sha256': sha(raw), 'transformation': schema})

    def json(self, relative, value, schema, original=None):
        self.write(relative, encode(value), schema, original)

    def gzip(self, relative, raw, schema, original=None):
        self.write(relative, gzip.compress(raw, compresslevel=6, mtime=0), schema, original)

    def baseline(self):
        public = Path(__file__).resolve().parent
        require(file_hash(public / 'claims.csv') == BASE_CLAIMS, 'Baseline claims changed')
        for name in ('allocation.json', 'claims.csv'):
            self.write(name, (public / name).read_bytes(), 'baseline-unchanged-v1')
        for path in sorted((public / 'wallets').glob('*.txt')):
            read_wallets(path)
            self.write('wallets/' + path.name, path.read_bytes(), 'wallet-list-v1')
        reference = loads((self.source / SNAPSHOT / 'snapshot.json').read_bytes())
        self.json('snapshot.json', {key: reference[key] for key in ('reference_slot', 'reference_block_time')},
                  'snapshot-reference-v1')
        selected = loads((self.source / SNAPSHOT / 'selected-cohorts.json').read_bytes())
        for row in selected:
            path = self.source / row['wallets']
            raw = wallet_bytes(read_wallets(path))
            require(sha(raw) == row['wallets_sha256'], 'Original prelist changed')
            self.write('expected/pre-exclusion/' + row['id'] + '.txt', raw, 'comparison-only-wallet-list-v1')
        for name in ('excluded-wallets.txt', 'excluded.jsonl'):
            path = self.source / EXCLUSIONS / name
            # These reason rows contain only addresses, rule IDs and cluster roles.
            if name.endswith('.jsonl'):
                rows = []
                for line in path.read_bytes().splitlines():
                    rows.append(strict(loads(line), {'wallet', 'funder', 'rules', 'role'},
                                       {'wallet', 'funder', 'rules', 'role'}))
                raw = b''.join(canonical(row) for row in rows)
            else:
                raw = wallet_bytes(read_wallets(path))
            self.write('expected/exclusions/' + name, raw, 'comparison-only-exclusion-v1', path)

    def squads(self):
        root = self.source / SNAPSHOT / 'squads'
        for label in ('v4_multisig', 'v3_ms', 'smart_account_settings'):
            source = root / 'raw' / (label + '.json.gz')
            self.check_original(source)
            response = loads(gzip.decompress(source.read_bytes()))
            projected = rpc_response(response, 'getProgramAccounts')
            self.gzip('data/squads/' + label + '.json.gz', encode(projected), 'rpc-account-projection-v1', source)
        source = root / 'activity-captures.jsonl.gz'
        self.check_original(source)
        out = self.destination / 'data/squads/activity.jsonl.gz'
        # Stream the larger JSONL inputs; gzip carries no original filename or time.
        with source.open('rb') as original, out.open('wb') as target:
            with gzip.GzipFile(fileobj=original, mode='rb') as incoming:
                with gzip.GzipFile(fileobj=target, mode='wb', filename='', mtime=0) as outgoing:
                    for line in incoming:
                        row = strict(loads(line), {'multisig', 'pages', 'complete'}, {'multisig', 'pages'})
                        require(row.get('complete') is True, 'Incomplete Squads capture')
                        pages = []
                        for page in row['pages']:
                            page = strict(page, {'request', 'sha256', 'response'}, {'request', 'sha256', 'response'})
                            require(sha(page['response'].encode()) == page['sha256'], 'Original activity body changed')
                            pages.append({'request': project_request(page['request']),
                                          'response': rpc_response(loads(page['response']), 'getSignaturesForAddress')})
                        outgoing.write(encode({'multisig': row['multisig'], 'pages': pages}))
        self.rows['data/squads/activity.jsonl.gz'] = {
            'bytes': out.stat().st_size, 'sha256': file_hash(out), 'schema': 'signature-activity-projection-v1'}
        self.provenance.append({'public_path': 'data/squads/activity.jsonl.gz',
                                'original_sha256': file_hash(source), 'public_sha256': file_hash(out),
                                'transformation': 'signature-activity-projection-v1'})

    def islanddao(self):
        source = self.source / 'output/airdrop-islanddao-inclusion-2026-10-17/inputs/v5-accepted-wallets.txt'
        require(file_hash(source) == '1faadd07333ec8a1ffc07ab10504a164e68abba0caeb776df366453966d83e07',
                'Original organizer roster changed')
        rows = [line.strip() for line in source.read_text(encoding='utf-8-sig').splitlines() if line.strip()]
        raw = wallet_bytes(sorted(set(rows)))
        require(len(rows) == len(set(rows)) == 168, 'Organizer roster inventory differs')
        self.write('data/islanddao/organizer-roster.txt', source.read_bytes(), 'original-organizer-roster-v1', source)
        self.json('data/islanddao/source.json', {'attribution': 'Provided by the IslandDAO organizers',
                  'criterion': 'Fixed original 168-wallet organizer roster; no additional participant test.',
                  'normalized_sha256': sha(raw), 'normalized_count': 168}, 'organizer-source-v1')

    def read_triplet(self, root, name):
        folder = root / 'captures' / name
        for filename in ('record.json', 'request.json', 'body.gz'):
            self.check_original(folder / filename)
        record = loads((folder / 'record.json').read_bytes())
        request = (folder / 'request.json').read_bytes()
        packed = (folder / 'body.gz').read_bytes()
        raw = gzip.decompress(packed)
        require(record['request_sha256'] == sha(request) and record['gzip_sha256'] == sha(packed)
                and record['sha256'] == sha(raw) and record['bytes'] == len(raw), 'Original capture integrity failed')
        require(record['http_status'] == 200, 'Required capture unsuccessful')
        return loads(request), record, loads(raw)

    def phoenix(self):
        root = self.source / SNAPSHOT / 'phoenix'
        for folder in sorted((root / 'captures').iterdir()):
            if not folder.is_dir():
                continue
            name = folder.name
            if name.startswith('probe-trades-history-'):
                # API-shape probe, not a membership or boundary calculation input.
                continue
            request, record, body = self.read_triplet(root, name)
            if name.startswith('leaderboard-'):
                sort = name.removeprefix('leaderboard-')
                projected = select(body, {'anchorTime', 'sortBy', 'entries'}, {'anchorTime', 'sortBy', 'entries'})
                projected['entries'] = []
                for entry in body['entries']:
                    row = select(entry, {'userPubkey', 'rank', 'volumeLifetime', 'lifetimeVolume', 'volume1d'},
                                 {'userPubkey', 'rank', 'volumeLifetime', 'lifetimeVolume', 'volume1d'})
                    for key in ('volumeLifetime', 'lifetimeVolume', 'volume1d'):
                        row[key] = strict(row[key], {'value', 'decimals', 'ui'}, {'value', 'decimals', 'ui'})
                    projected['entries'].append(row)
                locator = {'source_id': 'phoenix-leaderboard', 'sort': sort}
            elif name.startswith('fills-'):
                wallet, number = name.removeprefix('fills-').split('-page-')
                projected = {'hasMore': body['hasMore'], 'data': [select(row, {
                    'signature', 'fillId', 'eventIndex', 'timestamp', 'price', 'baseLotsDelta', 'slot'},
                    {'timestamp', 'price', 'baseLotsDelta', 'slot'}) for row in body['data']]}
                locator = {'source_id': 'phoenix-fills', 'wallet': wallet, 'page': int(number)}
            else:
                raise ValueError('Unreviewed Phoenix capture profile')
            self.gzip('data/phoenix/' + name + '.json.gz', encode({
                'request': locator, 'retrieved_at': record['retrieved_at'], 'body': projected}),
                'phoenix-market-facts-projection-v1', folder / 'body.gz')

    def solfate(self):
        root = self.source / SNAPSHOT / 'solfate'
        for folder in sorted((root / 'captures').iterdir()):
            if not folder.is_dir():
                continue
            name = folder.name
            request, record, body = self.read_triplet(root, name)
            if name == 'official-current-members':
                locator = {'source_id': 'solfate-public-roster'}
                projected = {'members': [select(row, {'token', 'owner'}, {'token'}) for row in body['members']]}
            elif name.startswith(('issuer-assets-page-', 'mints-', 'holder-atas-')):
                locator = project_request(request)
                projected = rpc_response(body, request['method'], strip_metadata=True)
            else:
                raise ValueError('Unreviewed Solfate capture profile')
            self.gzip('data/solfate/' + name + '.json.gz', encode({
                'request': locator, 'retrieved_at': record['retrieved_at'], 'body': projected}),
                'solfate-credential-facts-projection-v1', folder / 'body.gz')

    def seeker(self):
        source = self.source / SNAPSHOT / 'seeker/captures.jsonl.gz'
        self.check_original(source)
        relative = 'data/seeker/captures.jsonl.gz'
        target = self.destination / relative
        target.parent.mkdir(parents=True)
        with gzip.open(source, 'rb') as incoming, target.open('wb') as handle:
            with gzip.GzipFile(fileobj=handle, mode='wb', filename='', mtime=0) as outgoing:
                for line in incoming:
                    row = strict(loads(line), {'label', 'record', 'source'}, {'label', 'record', 'source'})
                    record = row['record']
                    require(sha(row['source'].encode()) == record['sha256'], 'Original Seeker response changed')
                    request = project_request(record['request'])
                    body = rpc_response(loads(row['source']), request['method'], strip_metadata=True)
                    outgoing.write(encode({'label': row['label'], 'request': request, 'body': body,
                                           'ok': str(record['http_status']) == '200',
                                           'retrieved_at': record.get('retrieved_at')}))
        self.rows[relative] = {'bytes': target.stat().st_size, 'sha256': file_hash(target),
                               'schema': 'seeker-raw-proof-projection-v1'}
        self.provenance.append({'public_path': relative, 'original_sha256': file_hash(source),
                                'public_sha256': file_hash(target), 'transformation': 'seeker-raw-proof-projection-v1'})

    def exclusions(self):
        root = self.source / 'output/airdrop-sybil-check-2026-10-19-v1'
        manifest_path = root / 'manifest.json'
        require(file_hash(manifest_path) == '2a3d427f8d9aa50ed5e4c3e7e35d28f8701ce6349baea130d6336fd51a19c017',
                'Original cluster source manifest changed')
        for row in loads(manifest_path.read_bytes())['files']:
            self.original_pins[str(root / row['path'])] = row
        phases = ('funders', 'funders-retry', 'identity', 'accounts', 'latest', 'activity')
        allowed = {'wallet', 'page', 'attempt', 'job', 'request', 'retrieved_at', 'http_status', 'ok',
                   'body', 'body_encoding', 'body_sha256', 'bytes', 'elapsed_ms', 'error', 'transport_error'}
        for phase in phases:
            for source in sorted((root / 'captures' / phase).glob('shard-*.jsonl.gz')):
                self.check_original(source)
                relative = 'data/exclusions/' + phase + '/' + source.name
                target = self.destination / relative
                target.parent.mkdir(parents=True, exist_ok=True)
                with gzip.open(source, 'rb') as incoming, target.open('wb') as handle:
                    with gzip.GzipFile(fileobj=handle, mode='wb', filename='', mtime=0) as outgoing:
                        for line in incoming:
                            row = strict(loads(line), allowed, {'attempt', 'job', 'request', 'ok'})
                            saved_request = strict(row['request'], {'body', 'url'}, {'body', 'url'})
                            if phase == 'identity':
                                request = strict(saved_request['body'], {'addresses'}, {'addresses'})
                                request['source_id'] = 'historical-service-categories'
                            else:
                                request = project_request(saved_request['body'])
                            body = None
                            if row['body'] is not None:
                                raw = (base64.b64decode(row['body'], validate=True)
                                       if row['body_encoding'] == 'base64' else row['body'].encode())
                                require(sha(raw) == row['body_sha256'] and len(raw) == row['bytes'],
                                        'Original cluster response integrity failed')
                                if row['ok']:
                                    original = loads(raw)
                                    body = identity_rows(original) if phase == 'identity' else rpc_response(
                                        original, request['method'], instruction_data_limits={})
                            projected = select(row, {'wallet', 'page', 'attempt', 'job', 'retrieved_at',
                                                     'http_status', 'ok'})
                            projected.update(request=request, body=body)
                            outgoing.write(encode(projected))
                self.rows[relative] = {'bytes': target.stat().st_size, 'sha256': file_hash(target),
                                       'schema': 'cluster-capture-projection-v1'}
                self.provenance.append({'public_path': relative, 'original_sha256': file_hash(source),
                    'public_sha256': file_hash(target), 'transformation': 'cluster-capture-projection-v1'})
        holders = self.source / SNAPSHOT / 'holders/captures'
        source = holders / 'dune-cex-solana/attempt-1.body.gz'
        self.check_original(source)
        raw = gzip.decompress(source.read_bytes())
        require(sha(raw) == '732e7ea7967baa899aad19f71adc1c52592ac3b0b7e31a064557ba023c99d34e',
                'Pinned public exchange registry changed')
        self.gzip('data/exclusions/services/cex.sql.gz', raw, 'public-exchange-registry-v1', source)
        source = holders / 'xstocks-system-wallets/attempt-1.body.gz'
        self.check_original(source)
        body = loads(gzip.decompress(source.read_bytes()))
        self.json('data/exclusions/services/issuers.json', {'nodes': [select(row, {'address'}, {'address'})
                  for row in body['nodes']]}, 'issuer-address-registry-projection-v1', source)

    def holding_bundle(self, kind):
        from replay.projection_http import http_body, locator
        root = self.source / SNAPSHOT / kind
        folder = 'data/' + kind
        for source in sorted((root / 'captures').glob('*/record.json')):
            self.check_original(source)
            record = loads(source.read_bytes())
            name = record['name']
            job = strict(record['job'], {'name', 'rpc', 'url', 'format', 'timeout'}, {'name'})
            projected_job = {'name': name}
            if 'rpc' in job:
                projected_job['rpc'] = project_request(job['rpc'])
            else:
                projected_job['source_id'] = locator(name, job['url'])
                if 'format' in job:
                    projected_job['format'] = job['format']
            if 'timeout' in job:
                projected_job['timeout'] = job['timeout']
            body, original = None, source
            if record['ok']:
                original = root / record['file']
                self.check_original(original)
                packed = original.read_bytes()
                raw = gzip.decompress(packed)
                require(sha(packed) == record['compressed_sha256'] and sha(raw) == record['body_sha256']
                        and len(raw) == record['bytes'], 'Original holding capture integrity failed')
                if job.get('format') == 'text':
                    body = raw.decode()
                else:
                    parsed = loads(raw)
                    body = rpc_response(parsed, job['rpc']['method'], strip_metadata='all') if 'rpc' in job else http_body(name, parsed)
            projected = {key: record.get(key) for key in ('name', 'ok', 'http_status', 'retrieved_at', 'context_slot')}
            projected.update(job=projected_job, body=body, body_sha256=record.get('body_sha256') if job.get('format') == 'text' else None)
            self.gzip(folder + '/' + name + '.json.gz', encode(projected), 'holding-market-facts-projection-v1', original)
        supplements = ['jobs/owner-jobs.json', 'stock-registry-coverage.json'] if kind == 'holders' else [
            'jobs/owner-jobs.json', 'kamino-obligations-coverage.json', 'kamino-vault-metrics-coverage.json']
        for relative in supplements:
            source = root / relative
            self.check_original(source)
            value = loads(source.read_bytes())
            if relative == 'jobs/owner-jobs.json':
                value = [dict(name=strict(row, {'name', 'rpc'}, {'name', 'rpc'})['name'],
                              rpc=project_request(row['rpc'])) for row in value]
            else:
                value = select(value, {'complete', 'pages', 'source', 'termination', 'next_cursor',
                                       'returned_rows', 'slot_range'}, {'complete', 'pages', 'source'})
                value['source'] = relative.removesuffix('-coverage.json')
                require(type(value['complete']) is bool and isinstance(value['pages'], list)
                        and all(isinstance(page, str) and page.replace('-', '').isalnum() for page in value['pages']),
                        'Invalid coverage fields')
                require(isinstance(value['source'], str) and value['source'].replace('-', '').isalnum(),
                        'Invalid coverage source')
                require('termination' not in value or value['termination'] in {'terminal_cursor', 'no_next_page', 'hasNextPage_false'},
                        'Unknown coverage termination')
                require('next_cursor' not in value or value['next_cursor'] is None, 'Incomplete coverage')
                require('returned_rows' not in value or type(value['returned_rows']) is int, 'Invalid row count')
                require('slot_range' not in value or value['slot_range'] is None or
                        (len(value['slot_range']) == 2 and all(type(slot) is int for slot in value['slot_range'])),
                        'Invalid slot range')
            self.json(folder + '/' + relative, value, 'capture-page-coverage-v2', source)
        reference = loads((self.source / SNAPSHOT / 'snapshot.json').read_bytes())
        scope = {key: reference[key] for key in ('reference_slot', 'reference_block_time')}
        scope['snapshot'] = 'snapshot.json'
        if kind == 'kamino':
            scope['exclusion_sources_bundle'] = 'data/holders'
        self.json(folder + '/scope.json', scope, 'portable-snapshot-scope-v1')

    def holders(self):
        self.holding_bundle('holders')

    def kamino(self):
        self.holding_bundle('kamino')

    def ride(self):
        root = self.source / SNAPSHOT / 'ride'
        for folder in sorted((root / 'captures').iterdir()):
            if not folder.is_dir() or folder.name == 'api-funds-pnl':
                continue
            name = folder.name
            request, record, body = self.read_triplet(root, name)
            if '-page-' in name and name.startswith(('ride-gov-', 'ride-legacy-', 'ride-executor-')):
                projected_request = project_request(request)
                projected = rpc_response(body, request['method'], instruction_data_limits={
                    'soGovSpYWEyohCPzQu3cwKrvBDBqL4kCbj3kBXvD8LW': 1,
                    'sowEL1Rtn3p479rg34gW7mVPeCNY58Es5rkLpFsCJAW': 8,
                    'tRADeQ3SJVHnFXv1rpwZzVt5HE6DWDu4J6cH34Md6ZA': 8})
            elif name in ('api-voters-limit-10000', 'api-creators-limit-10000'):
                role = 'voters' if 'voters' in name else 'creators'
                field = 'voterWallet' if role == 'voters' else 'creatorWallet'
                projected_request = {'source_id': 'ride-' + role, 'limit': 10000}
                projected = {'items': [select(row, {field, 'totalStaked', 'totalReceipts', 'totalBets'},
                                              {field, 'totalStaked'}) for row in body['items']]}
            elif name == 'legacy-leaderboard':
                projected_request = {'source_id': 'ride-legacy-roster'}
                projected = {'members': [select(row, {'wallet', 'volumeUsd'}, {'wallet'}) for row in body['members']]}
            else:
                raise ValueError('Unreviewed Ride capture profile')
            self.gzip('data/ride/' + name + '.json.gz', encode({
                'request': projected_request, 'retrieved_at': record['retrieved_at'], 'body': projected}),
                'ride-user-action-projection-v1', folder / 'body.gz')
        for name in ('ride-gov', 'ride-legacy', 'ride-executor'):
            source = root / 'captures' / (name + '-coverage.json')
            self.check_original(source)
            data = select(loads(source.read_bytes()), {'pages', 'returned_rows', 'slot_lte'},
                          {'pages', 'returned_rows', 'slot_lte'})
            self.json('data/ride/' + name + '-coverage.json', data, 'history-coverage-v1', source)

    def exponent_hylo(self):
        from replay.projection_products import idl, project
        root = self.source / SNAPSHOT / 'exponent-hylo'
        inputs = root / 'inputs'
        for source in sorted(inputs.glob('*.metadata.json')):
            self.check_original(source)
            original = loads(source.read_bytes())
            name = source.name.removesuffix('.metadata.json')
            body_path = inputs / (name + '.json.gz')
            self.check_original(body_path)
            raw = gzip.decompress(body_path.read_bytes())
            require(sha(raw) == original['sha256'] and len(raw) == original['bytes'], 'Original product capture changed')
            require(original['status'] == 200 or (original['status'] == 206 and name.startswith('exponent-table-')),
                    'Product capture failed; historical gap needs explicit handling')
            meta = select(original, {'name', 'captured_at', 'retrieved_at', 'retrieved_at_unix',
                                      'context_slot', 'last_indexed_slot', 'status'}, {'name', 'retrieved_at_unix'})
            if 'rpc_request' in original:
                request = project_request(original['rpc_request'])
                body = rpc_response(loads(raw), request['method'], strip_metadata=True)
                meta['rpc_request'] = request
            else:
                body = project(name, loads(raw))
                meta['source_id'] = name.split('-page-', 1)[0]
                if 'request_body' in original:
                    meta['request_body'] = strict(original['request_body'], {'mints'}, {'mints'})
                headers = original.get('response_headers', {})
                ranges = [value for key, value in headers.items() if key.lower() == 'content-range']
                if ranges:
                    require(len(ranges) == 1, 'Conflicting content-range headers')
                    meta['content_range'] = ranges[0]
            encoded = encode(body)
            meta.update(bytes=len(encoded), sha256=sha(encoded))
            self.gzip('data/exponent-hylo/inputs/' + name + '.json.gz', encoded,
                      'product-source-facts-projection-v1', body_path)
            self.json('data/exponent-hylo/inputs/' + name + '.metadata.json', meta,
                      'product-source-metadata-projection-v1', source)
        source = inputs / 'hylo-current-idl.json'
        self.check_original(source)
        self.json('data/exponent-hylo/inputs/hylo-current-idl.json', idl(loads(source.read_bytes())),
                  'official-account-idl-projection-v1', source)
        source = inputs / 'hylo-official-products-2026-10-13.json'
        self.check_original(source)
        products = [select(row, {'protocol', 'label', 'mint', 'source', 'collateral_mint'},
                           {'protocol', 'label', 'mint'}) for row in loads(source.read_bytes())]
        self.json('data/exponent-hylo/inputs/hylo-official-products-2026-10-13.json', products,
                  'official-hylo-product-registry-projection-v1', source)
        for source in sorted((root / 'sdk/build').rglob('*.js')):
            self.check_original(source)
            self.write('data/exponent-hylo/sdk/build/' + source.relative_to(root / 'sdk/build').as_posix(),
                       source.read_bytes(), 'official-sdk-layout-source-v1', source)

    def legacy_services(self):
        if 'data/legacy-services/dune-cex-solana.json.gz' in self.rows:
            return
        from replay.projection_http import http_body, locator
        root = self.source / 'output/airdrop-filter-100'
        manifest_path = root / 'final-results/manifest.json'
        require(file_hash(manifest_path) == '77ff60a979a62f01a364665f7266348d5da11a577aea30bb38c1c46ae9d0e1bb',
                'Original frozen service-source manifest changed')
        for relative, meta in loads(manifest_path.read_bytes())['inputs'].items():
            self.original_pins[str(self.source / relative)] = meta
        for name in ('dune-cex-solana', 'xstocks-system-wallets', 'holder-market-prices'):
            source = root / 'captures' / name / 'record.json'
            self.check_original(source)
            record = loads(source.read_bytes())
            body_path = root / record['file']
            self.check_original(body_path)
            packed = body_path.read_bytes()
            raw = gzip.decompress(packed)
            require(record['ok'] and sha(packed) == record['compressed_sha256']
                    and sha(raw) == record['body_sha256'] and len(raw) == record['bytes'], 'Frozen service capture changed')
            job = {'name': name, 'source_id': locator(name, record['job']['url'])}
            if record['job'].get('format') == 'text':
                body = raw.decode()
                job['format'] = 'text'
            else:
                body = http_body(name, loads(raw))
            projected = {key: record.get(key) for key in ('name', 'ok', 'http_status', 'retrieved_at', 'context_slot')}
            projected.update(job=job, body=body, body_sha256=record['body_sha256'] if name == 'dune-cex-solana' else None)
            self.gzip('data/legacy-services/' + name + '.json.gz', encode(projected),
                      'frozen-service-source-projection-v1', body_path)
        source = root / 'final-results/exclusions.json'
        require(file_hash(source) == '6b069dadac8b4518cfc7b6aaccadbeecb1b8b795cb2ecb461f38d3d1849e4514',
                'Original frozen service comparison changed')
        self.json('expected/legacy-services.json', loads(source.read_bytes()), 'comparison-only-service-registry-v1', source)

    def overpass(self):
        self.legacy_services()
        root = self.source / SNAPSHOT / 'overpass'
        for source in sorted((root / 'captures').glob('*/record.json')):
            self.check_original(source)
            record = loads(source.read_bytes())
            require(record['ok'], 'Required Overpass capture unsuccessful')
            name = record['name']
            job = {'name': name}
            body_path = root / record['file']
            self.check_original(body_path)
            packed = body_path.read_bytes()
            raw = gzip.decompress(packed)
            require(sha(packed) == record['compressed_sha256'] and sha(raw) == record['body_sha256']
                    and len(raw) == record['bytes'], 'Original Overpass capture changed')
            parsed = loads(raw)
            if 'rpc' in record['job']:
                job['rpc'] = project_request(record['job']['rpc'])
                body = rpc_response(parsed, job['rpc']['method'], strip_metadata=True)
            else:
                require(name == 'overpass-registry', 'Unknown Overpass source profile')
                job['source_id'] = 'registry:overpass'
                body = {'nextCursor': parsed['nextCursor'], 'items': [select(row, {
                    'wrapperMint', 'wrapperVault', 'sourcePool', 'decimals', 'priceUsd'},
                    {'wrapperMint', 'wrapperVault', 'sourcePool', 'decimals'}) for row in parsed['items']]}
            projected = {key: record.get(key) for key in ('name', 'ok', 'http_status', 'retrieved_at', 'context_slot')}
            projected.update(job=job, body=body)
            self.gzip('data/overpass/' + name + '.json.gz', encode(projected), 'overpass-wrapper-facts-projection-v1', body_path)

    def symmetry(self):
        import hashlib
        import re
        import zlib
        from replay.symmetry import SELECTED
        from replay.symmetry_decoder import LEGACY, V3, TOKEN, TOKEN22, LEGACY_AUTHORITY
        self.legacy_services()
        root = self.source / SNAPSHOT / 'symmetry'
        old = self.source / 'output/airdrop-open-cohorts'
        scope_path = root / 'scope.json'
        self.check_original(scope_path)
        scope = loads(scope_path.read_bytes())
        plan_path = old / 'legacy-authority-segments.json'
        self.check_original(plan_path)
        plan = loads(plan_path.read_bytes())
        plan = dict(address=plan['address'], segments=[select(row, {'name', 'slot', 'history_mode'},
                    {'name', 'slot'}) for row in plan['segments']])
        self.json('data/symmetry/legacy-plan.json', plan, 'symmetry-history-plan-v1', plan_path)
        public_scope = dict(fresh=scope['fresh'], tail_rechecks=scope['tail_rechecks'])
        self.json('data/symmetry/scope.json', public_scope, 'symmetry-history-scope-v1', scope_path)
        limits = {TOKEN: 9, TOKEN22: 9, V3: {'585c9edb5347efa4': 88,
            'a1cf302d079ce98f': 8, '5331700269c16a7e': 8, 'default': 8}, LEGACY: {'default': 8}}
        for name, (_, _, check) in SELECTED.items():
            snake = re.sub(r'(?<!^)(?=[A-Z])', '_', name).lower()
            discriminator = hashlib.sha256(('global:' + snake).encode()).digest()[:8].hex()
            limits[LEGACY][discriminator] = {'amount': 16, 'single': 17, 'array20': 168}.get(check, 8)

        def capture(folder, name):
            record_path = folder / 'captures' / name / 'record.json'
            self.check_original(record_path)
            record = loads(record_path.read_bytes())
            require(record['ok'], 'Required Symmetry capture failed')
            body_path = folder / record['file']
            self.check_original(body_path)
            packed = body_path.read_bytes()
            raw = gzip.decompress(packed)
            require(sha(packed) == record['compressed_sha256'] and sha(raw) == record['body_sha256']
                    and len(raw) == record['bytes'], 'Symmetry capture changed')
            return record, raw, body_path

        def history(folder, target, name):
            coverage_path, template_path = folder / (name + '-coverage.json'), folder / (name + '-template.json')
            self.check_original(coverage_path)
            self.check_original(template_path)
            coverage = select(loads(coverage_path.read_bytes()), {
                'complete', 'next_cursor', 'pages', 'returned_rows', 'slot_range', 'source', 'termination',
                'complete_scope', 'membership_slot_range'}, {'complete', 'next_cursor', 'pages', 'returned_rows', 'slot_range'})
            template = strict(loads(template_path.read_bytes()), {'name', 'rpc'}, {'name', 'rpc'})
            template['rpc'] = project_request(template['rpc'])
            self.json(target + '/' + name + '-coverage.json', coverage, 'symmetry-history-coverage-v1', coverage_path)
            self.json(target + '/' + name + '-template.json', template, 'symmetry-history-request-v1', template_path)
            for page in coverage['pages']:
                record, raw, body_path = capture(folder, page)
                job = strict(record['job'], {'name', 'rpc'}, {'name', 'rpc'})
                job['rpc'] = project_request(job['rpc'])
                body = rpc_response(loads(raw), job['rpc']['method'], instruction_data_limits=limits)
                projected = select(record, {'name', 'ok', 'http_status', 'retrieved_at'}, {'name', 'ok', 'retrieved_at'})
                projected.update(job=job, body=body)
                self.gzip(target + '/' + page + '.json.gz', encode(projected), 'symmetry-instruction-facts-projection-v1', body_path)
        for spec in plan['segments']:
            history(old, 'data/symmetry/legacy', spec['name'])
        for spec in [*scope['fresh'].values(), *scope['tail_rechecks']]:
            history(root, 'data/symmetry/fresh', spec['name'])
        for path in sorted((root / 'captures').glob('owner-check-*/record.json')):
            name = path.parent.name
            record, raw, body_path = capture(root, name)
            job = strict(record['job'], {'name', 'rpc'}, {'name', 'rpc'})
            job['rpc'] = project_request(job['rpc'])
            projected = select(record, {'name', 'ok', 'http_status', 'retrieved_at'}, {'name', 'ok', 'retrieved_at'})
            projected.update(job=job, body=rpc_response(loads(raw), job['rpc']['method']))
            self.gzip('data/symmetry/fresh/' + name + '.json.gz', encode(projected), 'symmetry-owner-account-projection-v1', body_path)
        def idl(value):
            return {'instructions': [dict(name=ix['name'], accounts=[{'name': a['name']} for a in ix['accounts']])
                    for ix in value['instructions'] if ix['name'] in SELECTED]}
        _, raw, sdk_path = capture(root, 'symmetry-legacy-fundsIDL')
        text = raw.decode()
        text = text[text.index('export const'):]
        sdk = json.JSONDecoder().raw_decode(text[text.index('=') + 1:].lstrip())[0]
        record, raw, chain_path = capture(root, 'symmetry-legacy-onchain-idl')
        body = loads(raw)
        account = body['result']['value']
        data = base64.b64decode(account['data'][0], validate=True)
        size = int.from_bytes(data[40:44], 'little')
        chain = loads(zlib.decompress(data[44:44 + size]))
        _, config, _ = capture(root, 'symmetry-legacy-config')
        require(('FUNDS_PROGRAM_PDA = new PublicKey("' + LEGACY_AUTHORITY + '")').encode() in config,
                'Published legacy authority differs')
        sources = dict(legacy_authority=LEGACY_AUTHORITY, sdk_legacy_idl=idl(sdk), v3_version='1.0.22',
                       onchain_legacy_idl=dict(owner=account['owner'], executable=account['executable'],
                           context_slot=body['result']['context']['slot'], request=project_request(record['job']['rpc']),
                           authority=__import__('replay.core', fromlist=['encode58']).encode58(data[8:40]), idl=idl(chain)))
        from replay.symmetry_abi import declarations
        v3 = []
        for name in ('symmetry-v3-deposit', 'symmetry-v3-withdraw'):
            _, raw, original = capture(root, name)
            self.write('data/symmetry/sources/' + name + '.cjs.source', raw,
                       'reviewed-sdk-instruction-source-v1', original)
            v3.append(raw.decode())
        sources['v3_declarations'] = declarations(*v3)
        self.json('data/symmetry/role-sources.json', sources, 'symmetry-idl-role-projection-v1', chain_path)

    def meteora(self):
        from replay.projection_products import idl
        self.legacy_services()
        root = self.source / SNAPSHOT / 'meteora-current'
        for source in sorted((root / 'captures/onchain').rglob('*.record.json')):
            self.check_original(source)
            record = loads(source.read_bytes())
            body_path = source.with_name(source.name.removesuffix('.record.json') + '.body.gz')
            self.check_original(body_path)
            raw = gzip.decompress(body_path.read_bytes())
            require(record['http_status'] == 200 and record['error'] in (None, '') and
                    sha(raw) == record['sha256'] and len(raw) == record['bytes'], 'Original LP capture differs')
            request = project_request(record['request'])
            body = rpc_response(loads(raw), request['method'], strip_metadata='all')
            encoded = encode(body)
            projected = select(record, {'attempt', 'http_status', 'context_slot', 'retrieved_at', 'started_at'},
                               {'http_status', 'retrieved_at'})
            projected.update(request=request, error=None, bytes=len(encoded), sha256=sha(encoded))
            relative = source.relative_to(root).as_posix().removesuffix('.record.json')
            self.gzip('data/meteora/' + relative + '.json.gz', encoded, 'lp-onchain-state-projection-v1', body_path)
            self.json('data/meteora/' + relative + '.record.json', projected, 'lp-request-metadata-projection-v1', source)
        for source in sorted((root / 'captures/onchain').rglob('*.json')):
            if source.name.endswith('.record.json'):
                continue
            if source.name in {'ids.json', 'mints.json'}:
                self.check_original(source)
                key = source.stem
                value = strict(loads(source.read_bytes()), {key}, {key})
                from replay.core import address
                require(len(value[key]) == len(set(value[key])), 'Repeated discovery query key')
                for wallet in value[key]:
                    address(wallet)
                self.json('data/meteora/' + source.relative_to(root).as_posix(), value, 'lp-query-universe-v1', source)
            elif source.name.startswith('FAILED'):
                self.check_original(source)
                # Math uses the presence of this marker to disclose a missing
                # request. Transport error text is deliberately not published.
                self.json('data/meteora/' + source.relative_to(root).as_posix(), {'capture_missing': True},
                          'lp-failed-capture-marker-v1', source)
        for source in sorted((root / 'inputs/idl').glob('*.idl.json')):
            self.check_original(source)
            original = loads(source.read_bytes())
            value = idl(original)
            value['address'] = original['address']
            value['constants'] = [select(row, {'name', 'value'}, {'name', 'value'}) for row in original['constants']]
            self.json('data/meteora/' + source.relative_to(root).as_posix(), value, 'lp-official-idl-layout-projection-v1', source)
        source = root / 'inputs/known-exclusions.json'
        self.check_original(source)
        require(loads(source.read_bytes()) == loads((self.source / 'output/airdrop-filter-100/final-results/exclusions.json').read_bytes()),
                'LP source service screen differs from frozen registry')

    def defi(self):
        from replay.projection_products import idl
        from replay.projection_defi import vault
        self.legacy_services()
        root = self.source / SNAPSHOT / 'defi'
        for source in sorted((root / 'captures').glob('*/record.json')):
            self.check_original(source)
            record = loads(source.read_bytes())
            name = source.parent.name
            original_job = record['job']
            # Position list/index requests only guided extra NFT proofs and
            # historical diffs. The exhaustive raw program scan independently
            # enumerates every current borrower, and each holder proof is raw.
            if 'rpc' not in original_job and name != 'jup-indexed-vaults' and not name.startswith('jup-single-vault-'):
                continue
            job = {'name': name}
            body_path = root / record['file']
            self.check_original(body_path)
            raw = gzip.decompress(body_path.read_bytes())
            require(sha(raw) == record['body_sha256'] and len(raw) == record['bytes']
                    and file_hash(body_path) == record['compressed_sha256'], 'Original DeFi capture differs')
            if 'rpc' in original_job:
                job['rpc'] = project_request(original_job['rpc'])
                body = rpc_response(loads(raw), job['rpc']['method'], strip_metadata='all')
            else:
                job['source_id'] = name
                parsed = loads(raw)
                body = [vault(row) for row in parsed] if isinstance(parsed, list) else vault(parsed)
            encoded = encode(body)
            compressed = gzip.compress(encoded, compresslevel=6, mtime=0)
            relative = 'captures/' + name + '/body.json.gz'
            self.write('data/defi/' + relative, compressed, 'defi-chain-price-facts-projection-v1', body_path)
            projected = select(record, {'ok', 'http_status', 'retrieved_at'}, {'ok', 'retrieved_at'})
            projected.update(name=name, job=job, file=relative, bytes=len(encoded), body_sha256=sha(encoded),
                             compressed_sha256=sha(compressed), job_sha256=sha(canonical(job)))
            self.json('data/defi/captures/' + name + '/record.json', projected, 'defi-source-request-projection-v1', source)
        for name in ('p0-marginfi_0-1-11-json.source', 'price-src-vendor-exponent-idl-exponent_core-json.source',
                     'jupiter-vaults-json.source'):
            source = root / 'sources' / name
            self.check_original(source)
            value = loads(source.read_bytes())
            projected = idl(value)
            projected['address'] = value['address']
            self.json('data/defi/sources/' + name, projected, 'defi-official-idl-projection-v1', source)

    def finish(self, stages):
        private_path = self.destination.with_name(self.destination.name + '.private-provenance.json')
        private_path.write_bytes(encode({'schema': 'private-projection-crosswalk-v1', 'files': self.provenance}))
        private_path.chmod(0o600)
        public_provenance = []
        for row in self.provenance:
            public = {key: child for key, child in row.items() if key != 'original_sha256'}
            if row['transformation'] == 'official-sdk-layout-source-v1':
                public['original_sha256'] = row['original_sha256']
            public_provenance.append(public)
        self.json('projection-provenance.json', {'schema': 'projection-provenance-v1',
                  'authentication': 'New hashes pin exported projections; unsigned source responses remain assertions. Private transport and identity-source hashes are withheld.',
                  'files': public_provenance}, 'projection-provenance-v1')
        self.json('source-status.json', {'schema': 'source-status-v1', 'implemented_stages': stages,
                  'full_source_replay': 'Run the complete offline replay; stage availability alone is not validation.',
                  'source_trust': 'Unsigned historical provider assertions and the disclosed organizer roster'}, 'source-status-v1')
        manifest = {'schema': 'runners-public-data-manifest-v1', 'files': self.rows}
        # Manifest is not a self-referential entry; its hash is the independent pin.
        raw = encode(manifest)
        (self.destination / 'data-manifest.json').write_bytes(raw)
        (self.destination / 'data-manifest.sha256').write_text(sha(raw) + '  data-manifest.json\n')
        print(json.dumps({'files': len(self.rows), 'bytes': sum(row['bytes'] for row in self.rows.values()),
                          'manifest_sha256': sha(raw), 'stages': stages}))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source-root', required=True, type=Path)
    parser.add_argument('--out', required=True, type=Path)
    parser.add_argument('--stages', default='squads,islanddao,phoenix,solfate,seeker')
    args = parser.parse_args()
    stages = args.stages.split(',')
    require(set(stages) <= {'squads', 'islanddao', 'phoenix', 'solfate', 'seeker', 'exclusions', 'holders', 'kamino', 'ride', 'exponent-hylo', 'overpass', 'symmetry', 'meteora', 'defi'},
            'Unknown/unimplemented export stage')
    export = Export(args.source_root, args.out)
    export.baseline()
    for stage in stages:
        getattr(export, stage.replace('-', '_'))()
    export.finish(stages)


if __name__ == '__main__':
    main()
