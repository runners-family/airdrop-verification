import base64
from decimal import Decimal
import hashlib
import gzip
import json
import os
from pathlib import Path
import struct
import subprocess
import tarfile
import time
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from replay.allocation import largest_remainder
from replay.core import canonical, encode58, loads, safe_path, utc_epoch, sha
from replay.projection import project_request, rpc_response, redact_token_metadata, identity_rows, transaction, account
from replay.squads import decode
from privacy_scan import Scanner
from replay.exclusions import max_window, rule_hits
from replay.flows import first_inflow
from replay.defi_codec import IDL
from replay.jupiter_math import ratio, mul_div, multiply, MAX_FACTOR
from fetch_data import extract, validate_index
from package_data import chunks, TAR_INPUT_LIMIT


class Boundaries(unittest.TestCase):
    def test_asset_bytes_ignore_filesystem_times(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            evidence = root / 'evidence'
            evidence.mkdir()
            raw = canonical({'source': 'synthetic captured fact'})
            (evidence / 'capture.json').write_bytes(raw)
            manifest = canonical({'schema': 'runners-public-data-manifest-v1', 'files': {
                'capture.json': {'bytes': len(raw), 'sha256': sha(raw), 'schema': 'synthetic-v1'}}})
            (evidence / 'data-manifest.json').write_bytes(manifest)
            (evidence / 'data-manifest.sha256').write_text(sha(manifest) + '  data-manifest.json\n')
            for number in (1, 2):
                os.utime(evidence / 'capture.json', (number, number))
                result = subprocess.run([sys.executable, '-I', '-B',
                    str(Path(__file__).resolve().parents[1] / 'package_data.py'), '--evidence', str(evidence),
                    '--manifest-sha256', sha(manifest), '--out', str(root / str(number))],
                    env={'PATH': os.defpath, 'TZ': 'UTC'}, capture_output=True, timeout=30)
                self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual({p.name: p.read_bytes() for p in (root / '1').iterdir()},
                             {p.name: p.read_bytes() for p in (root / '2').iterdir()})
            index_path = root / '1/evidence-index.json'
            def scan_index():
                return subprocess.run([sys.executable, '-I', '-B',
                    str(Path(__file__).resolve().parents[1] / 'privacy_scan.py'), str(root / '1'),
                    '--asset-index', str(index_path), '--asset-index-sha256', sha(index_path.read_bytes())],
                    env={'PATH': os.defpath, 'TZ': 'UTC'}, capture_output=True, timeout=30)
            result = scan_index()
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertTrue(loads(result.stdout)['archive_index_coverage'])
            index = loads(index_path.read_bytes())
            files = index['assets'][0]['files']
            files['different.json'] = files.pop('capture.json')
            index_path.write_bytes(canonical(index))
            result = scan_index()
            self.assertNotEqual(result.returncode, 0)
            self.assertFalse(loads(result.stdout)['archive_index_coverage'])

    def test_quoted_and_bearer_credentials_detected(self):
        token = ''.join(['synthetic'] * 5)
        for key in ('authorization', 'X-Api-Key', 'api_key', 'access_token', 'secret_key', 'private_key', 'cookie'):
            scan = Scanner()
            scan.inspect_value({key: token})
            self.assertGreater(scan.counts['credential_pattern'], 0)
        for raw in (json.dumps({'authorization': token}).encode(),
                    ('Authorization: Bearer ' + token).encode()):
            scan = Scanner()
            scan.inspect_bytes(raw)
            self.assertGreater(scan.counts['credential_pattern'], 0)

    def test_archive_parts_bound_and_keep_each_file(self):
        files = {name: {'bytes': TAR_INPUT_LIMIT // 2, 'sha256': '0' * 64} for name in ('c', 'a', 'b')}
        parts = list(chunks(files))
        self.assertEqual([name for part in parts for name in part], ['a', 'b', 'c'])
        self.assertEqual(len(parts), 3)
        with self.assertRaises(ValueError):
            list(chunks({'oversized': {'bytes': TAR_INPUT_LIMIT}}))

    def test_asset_index_rejects_transport_and_path_fields(self):
        value = dict(schema='runners-evidence-assets-v1', data_manifest_sha256='0' * 64,
                     tar_input_limit_bytes=500 * 1024 * 1024, asset_limit_bytes=512 * 1024 * 1024,
                     assets=[dict(name='evidence-common.tar.gz', bytes=1, sha256='0' * 64,
                                  files={'entry': dict(bytes=1, sha256='0' * 64)})])
        validate_index(value)
        value['assets'][0]['files']['entry']['bytes'] = 500 * 1024 * 1024
        with self.assertRaises(ValueError):
            validate_index(value)
        value['assets'][0]['files']['entry']['bytes'] = 1
        value['assets'][0]['headers'] = {'Authorization': 'unwanted'}
        with self.assertRaises(ValueError):
            validate_index(value)

    def test_archive_scanner_reaches_encoded_payload(self):
        import io
        raw = canonical({'data': [base64.b64encode(b'SYNTHETIC_PRIVATE_MARKER').decode(), 'base64']})
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / 'evidence-test.tar.gz'
            with path.open('wb') as handle, gzip.GzipFile(fileobj=handle, mode='wb', filename='', mtime=0) as compressed:
                with tarfile.open(fileobj=compressed, mode='w') as target:
                    member = tarfile.TarInfo('capture.json')
                    member.size, member.mode = len(raw), 0o644
                    target.addfile(member, io.BytesIO(raw))
            scan = Scanner(['SYNTHETIC_PRIVATE_MARKER'])
            scan.inspect_file(path, path.name)
            self.assertGreater(scan.counts['private_marker'], 0)
            self.assertEqual(scan.counts['unreadable'], 0)

    def test_gzip_host_metadata_rejected(self):
        import io
        scan = Scanner()
        packed = io.BytesIO()
        with gzip.GzipFile(fileobj=packed, mode='wb', filename='unwanted-host-filename', mtime=0) as handle:
            handle.write(b'{}')
        with self.assertRaises(ValueError):
            scan.inspect_stream(io.BytesIO(packed.getvalue()), 'capture.json.gz')

    def test_archive_scanner_reaches_trailing_bytes(self):
        import io
        tar = io.BytesIO()
        with tarfile.open(fileobj=tar, mode='w'):
            pass
        packed = io.BytesIO()
        with gzip.GzipFile(fileobj=packed, mode='wb', filename='', mtime=0) as handle:
            handle.write(tar.getvalue() + b'SYNTHETIC_PRIVATE_MARKER')
        scan = Scanner(['SYNTHETIC_PRIVATE_MARKER'])
        scan.inspect_stream(io.BytesIO(packed.getvalue()), 'evidence-test.tar.gz')
        self.assertGreater(scan.counts['private_marker'], 0)

    def test_archive_scanner_accepts_large_canonical_json_line(self):
        import io
        raw = canonical({'padding': 'a' * (2 * 1024 * 1024 + 1)})
        packed = io.BytesIO()
        with gzip.GzipFile(fileobj=packed, mode='wb', filename='', mtime=0) as compressed:
            with tarfile.open(fileobj=compressed, mode='w') as target:
                member = tarfile.TarInfo('manifest.json')
                member.size, member.mode = len(raw), 0o644
                target.addfile(member, io.BytesIO(raw))
        scan = Scanner()
        scan.inspect_stream(io.BytesIO(packed.getvalue()), 'evidence-test.tar.gz')
        self.assertEqual(scan.counts['findings'], 0)
        self.assertEqual(scan.counts['files'], 1)

    def test_known_rpc_owner_sentinel_preserved(self):
        key = '11111111111111111111111111111111'
        tx = dict(slot=458146998, blockTime=1792264090, transaction={
            'signatures': ['1' * 64], 'message': {'accountKeys': [key], 'instructions': []}}, meta={
            'err': None, 'fee': 0, 'preBalances': [0], 'postBalances': [0],
            'preTokenBalances': [{'accountIndex': 0, 'mint': key, 'owner': chr(0),
                                 'uiTokenAmount': {'amount': '1', 'decimals': 0}}]})
        self.assertEqual(transaction(tx, {})['meta']['preTokenBalances'][0]['owner'], chr(0))
        tx['meta']['preTokenBalances'][0]['owner'] = 'arbitrary non-address'
        with self.assertRaises(ValueError):
            transaction(tx, {})

    def test_nested_token_metadata_allowlist(self):
        key = '11111111111111111111111111111111'
        value = dict(owner=key, lamports=1, executable=False, data={'program': 'spl-token',
            'parsed': {'type': 'account', 'info': {'owner': key, 'mint': key,
                'tokenAmount': {'amount': '1', 'decimals': 9, 'unneeded': {'name': 'private detail'}}}}})
        self.assertNotIn(b'private detail', canonical(account(value)))

    def test_utc_is_host_timezone_independent(self):
        if not hasattr(time, 'tzset'):
            self.skipTest('Host TZ mutation check requires tzset; explicit UTC parsing remains portable')
        before = os.environ.get('TZ')
        try:
            for zone in ('UTC', 'Pacific/Honolulu'):
                os.environ['TZ'] = zone
                time.tzset()
                self.assertEqual(utc_epoch('2026-10-17T19:08:10'), 1792264090)
                self.assertEqual(utc_epoch('2026-10-17T19:08:10Z'), 1792264090)
        finally:
            if before is None:
                os.environ.pop('TZ', None)
            else:
                os.environ['TZ'] = before
            time.tzset()

    def test_archive_escape_and_links_rejected(self):
        import io
        for name, link in (('../escape', False), ('entry', True)):
            with tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                archive = root / 'test.tar.gz'
                with tarfile.open(archive, 'w:gz') as target:
                    entry = tarfile.TarInfo(name)
                    if link:
                        entry.type, entry.linkname = tarfile.SYMTYPE, '../escape'
                        target.addfile(entry)
                    else:
                        entry.size = 1
                        target.addfile(entry, io.BytesIO(b'x'))
                (root / 'out').mkdir()
                with self.assertRaises(ValueError):
                    extract(archive, root / 'out', {name: {'bytes': 1, 'sha256': sha(b'x')}})
                self.assertFalse((root / 'escape').exists())

    def test_idl_truncation_and_tags(self):
        decoder = IDL.__new__(IDL)
        decoder.types = {'Choice': {'kind': 'enum', 'variants': [{'name': 'First'}]}}
        for kind, raw in [('u64', bytes(7)), ('pubkey', bytes(31)), ('bool', b'\x02'),
                          ({'option': 'u8'}, b'\x02\x00'), ({'defined': 'Choice'}, b'\x01'),
                          ({'vec': 'u64'}, b'\xff\xff\xff\xff')]:
            with self.assertRaises(ValueError):
                decoder.val(kind, raw, 0)
        self.assertEqual(decoder.val('u64', b'\xff' * 8, 0), (2**64 - 1, 8))

    def test_jupiter_integer_boundaries(self):
        self.assertEqual(ratio(0), 1 << 48)
        self.assertLess(ratio(-1), ratio(0))
        self.assertGreater(ratio(1), ratio(0))
        with self.assertRaises(ValueError):
            ratio(16384)
        coefficient = 1 << 34
        factor = (coefficient << 15) | 16384
        self.assertEqual(mul_div(10000, factor, factor), 10000)
        self.assertEqual(mul_div(10000, 0, factor), 0)
        self.assertEqual(multiply(factor, factor), factor + 34)
        self.assertEqual(multiply(MAX_FACTOR, MAX_FACTOR), MAX_FACTOR)

    def test_node_codec_boundaries(self):
        result = subprocess.run(['node', str(Path(__file__).with_name('codec-boundaries.cjs'))],
                                capture_output=True, text=True, timeout=15)
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_exact_numbers(self):
        raw = b'{"value":0.123456789012345678901234567890}'
        value = loads(raw)
        self.assertEqual(value['value'], Decimal('0.123456789012345678901234567890'))
        self.assertEqual(loads(canonical(value)), value)

    def test_noncanonical_paths(self):
        for path in ('../outside', '/absolute', 'a//b', 'a/./b', 'a/../b', 'a\\b', 'C:/outside'):
            with self.assertRaises(ValueError):
                safe_path(Path('/tmp'), path)

    def test_duplicate_key(self):
        with self.assertRaises(ValueError):
            loads('{"x":1,"x":2}')

    def test_largest_remainder_tie(self):
        self.assertEqual(largest_remainder(2, {'c': 1, 'a': 1, 'b': 1}), {'c': 0, 'a': 1, 'b': 1})

    def test_squads_v3_offsets(self):
        raw = bytearray(58 + 64)
        raw[:8] = hashlib.sha256(b'account:Ms').digest()[:8]
        struct.pack_into('<H', raw, 8, 2)
        struct.pack_into('<I', raw, 12, 25)
        struct.pack_into('<I', raw, 54, 2)
        raw[58:90] = bytes([1]) * 32
        raw[90:122] = bytes([2]) * 32
        threshold, proposals, external, members = decode(bytes(raw), 'v3')
        self.assertEqual((threshold, proposals, external), (2, 25, False))
        self.assertEqual(members, [(bytes([1]) * 32, 7), (bytes([2]) * 32, 7)])

    def test_request_headers_fail_closed(self):
        with self.assertRaises(ValueError):
            project_request({'method': 'getSlot', 'params': [], 'headers': {'authorization': 'secret'}})
        with self.assertRaises(ValueError):
            project_request({'method': 'getSlot', 'params': [{'credential': 'secret'}]})

    def test_identity_projection(self):
        row = {'address': '11111111111111111111111111111111', 'type': 'known',
               'category': 'DeFi', 'name': 'Private Person', 'socials': {'url': 'private'}}
        self.assertEqual(identity_rows([row]), [{'address': row['address'], 'type': 'classified', 'category': 'DeFi'}])
        row['category'] = 'unneeded personal free text'
        self.assertIsNone(identity_rows([row])[0]['category'])

    def test_additional_metadata_removed(self):
        def string(text):
            body = text.encode()
            return struct.pack('<I', len(body)) + body
        body = bytes(64) + string('name') + string('symbol') + string('uri')
        body += struct.pack('<I', 1) + string('social') + string('private-identity')
        raw = bytes(165) + b'\x01' + struct.pack('<HH', 19, len(body)) + body
        projected, changed = redact_token_metadata(raw)
        self.assertTrue(changed)
        self.assertNotIn(b'private-identity', projected)
        self.assertEqual(projected[-4:], bytes(4))
        self.assertEqual(projected[:166], raw[:166])

    def test_encoded_and_embedded_scan(self):
        scan = Scanner(['SYNTHETIC_PRIVATE_MARKER'])
        scan.inspect_value({'response': json.dumps({'data': [base64.b64encode(
            b'SYNTHETIC_PRIVATE_MARKER').decode(), 'base64']})})
        self.assertGreater(scan.counts['private_marker'], 0)

    def test_pattern_cache_preserves_every_occurrence(self):
        scan = Scanner(['SYNTHETIC_PRIVATE_MARKER'])
        for _ in range(3):
            scan.inspect_bytes(b'SYNTHETIC_PRIVATE_MARKER')
        for _ in range(2):
            scan.inspect_bytes(b'https' + b'://example.invalid/proof')
        self.assertEqual(scan.counts['private_marker'], 3)
        self.assertEqual(scan.counts['endpoint_or_url'], 2)
        self.assertEqual(scan.counts['findings'], 5)
        self.assertEqual(scan.counts['decoded_layers'], 5)
        other = Scanner(['SYNTHETIC_PRIVATE_MARKER'])
        other._small_patterns = other._patterns
        cached = Scanner(['SYNTHETIC_PRIVATE_MARKER'])
        fixture = {'response': json.dumps({'data': [base64.b64encode(
            b'SYNTHETIC_PRIVATE_MARKER').decode(), 'base64']}), 'repeated': ['same'] * 100}
        for current in (other, cached):
            current.inspect_value(fixture)
        self.assertEqual(other.counts, cached.counts)

    def test_binary_public_key_markers_in_encoded_fields(self):
        raw = bytes(range(32))
        marker = encode58(raw)
        scan = Scanner([marker, 'SYNTHETIC_PRIVATE_MARKER'])
        scan.inspect_value({'response': json.dumps({'data': [base64.b64encode(
            b'prefix' + raw + b'suffix').decode(), 'base64']})})
        self.assertGreater(scan.counts['private_binary_marker'], 0)
        instruction = Scanner([marker])
        instruction.inspect_value({'instructionData': encode58(b'prefix' + raw + b'suffix')})
        self.assertGreater(instruction.counts['private_binary_marker'], 0)
        vector = Scanner([marker])
        vector.inspect_value({'type': 'Buffer', 'data': list(b'prefix' + raw + b'suffix')})
        self.assertGreater(vector.counts['private_binary_marker'], 0)
        direct = Scanner([marker])
        for _ in range(2):
            direct.inspect_bytes(raw)
        self.assertEqual(direct.counts['private_binary_marker'], 2)
        self.assertEqual(direct.counts['private_marker'], 0)
        self.assertEqual(direct.counts['findings'], 2)
        clean = Scanner([marker])
        clean.inspect_value({'data': [base64.b64encode(bytes(reversed(raw))).decode(), 'base64']})
        self.assertEqual(clean.counts['findings'], 0)

    def test_r4_exact_boundaries(self):
        self.assertEqual(rule_hits(25, 20, 0, 20, 0, True, False), ['R1'])
        self.assertEqual(rule_hits(25, 19, 0, 20, 0, True, False), [])
        self.assertEqual(rule_hits(10, 8, 8, 8, 5, True, False), ['R2', 'R3'])
        self.assertEqual(rule_hits(10, 8, 8, 8, 5, True, True), [])
        self.assertEqual(rule_hits(10, 8, 8, 8, 5, False, False), [])
        self.assertEqual(max_window([0, 86400, 86401], 86400), 2)
        self.assertEqual(max_window([0, 86400], 86400), 2)

    def test_first_funder_follows_instruction_order(self):
        wallet, first, second = 'wallet', 'first', 'second'
        tx = {'slot': 1, 'transactionIndex': 0, 'blockTime': 1,
              'transaction': {'signatures': ['synthetic-signature'], 'message': {
                  'accountKeys': [first, second, wallet], 'instructions': [
                      {'programId': '11111111111111111111111111111111', 'parsed': {
                          'type': 'transfer', 'info': {'source': first, 'destination': wallet, 'lamports': 1}}},
                      {'programId': '11111111111111111111111111111111', 'parsed': {
                          'type': 'transfer', 'info': {'source': second, 'destination': wallet, 'lamports': 9}}}]}},
              'meta': {'preBalances': [100, 100, 0], 'postBalances': [99, 91, 10], 'fee': 0}}
        self.assertEqual(first_inflow(wallet, tx)['funder'], first)

    def test_decimal_threshold_is_exact(self):
        from replay.holder_common import number
        self.assertLess(number('99.9999999999999999999999999999'), 100)
        self.assertEqual(number('100.0000000000000000000000000000'), 100)


if __name__ == '__main__':
    unittest.main()
