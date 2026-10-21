#!/usr/bin/env python3
"""Publication gate over decompressed files, embedded JSON and encoded data.

Supply private markers separately. Results contain only aggregate counts: no
matched text, role labels, marker values, or hashes of private marker values.
This detects known patterns, not every possible personal association on-chain.
"""
import argparse
import base64
import gzip
import json
import io
from pathlib import Path
import re
import subprocess
import sys
import tarfile
from functools import lru_cache

sys.path.insert(0, str(Path(__file__).resolve().parent))
from replay.core import address, decode58, loads, require

URL = re.compile(rb'(?:https?|wss?)://[^\s\x00<>"\x27\\]+', re.I)
HOME_PATH = re.compile(rb'/(?:Us' + rb'ers|ho' + rb'me)/[^\s\x00"\x27<>]+', re.I)
SECRET = re.compile(rb'(?:api[_-]?key|authorization|x-api-key|access_token|secret_key|private_key|cookie)["\x27]?\s*[=:]\s*["\x27]?(?:Bearer\s+)?[A-Za-z0-9_./+=:-]{16,}', re.I)
BEARER = re.compile(rb'\bBearer\s+[A-Za-z0-9._~+/-]{16,}={0,2}', re.I)
PRIVATE_KEY = re.compile(rb'-----BEGIN [A-Z ]*PRIVATE KEY-----')
CREDENTIAL_KEYS = {'authorization', 'xapikey', 'apikey', 'accesstoken', 'secretkey', 'privatekey', 'cookie'}
ALLOWED_URLS = (
    b'https://arweave.net/pU-bAhOLQfDDQxByxThtgqfmXc7Wrcg15pzziDK-o5A',
    b'https://r2.solanamobiledappstore.com/skr/sgt-metadata.json',
)


class Scanner:
    def __init__(self, markers=(), allowed_urls=()):
        self.markers = [value.encode().lower() for value in markers if value]
        self.binary_markers = []
        for value in markers:
            try:
                raw = address(value)
            except ValueError:
                continue
            if raw not in self.binary_markers:
                self.binary_markers.append(raw)
        self.allowed = tuple(ALLOWED_URLS) + tuple(value.encode() for value in allowed_urls)
        self.counts = {'files': 0, 'decoded_layers': 0, 'findings': 0,
                       'endpoint_or_url': 0, 'personal_path': 0, 'credential_pattern': 0,
                       'private_marker': 0, 'private_binary_marker': 0, 'unreadable': 0}
        self._small_patterns = lru_cache(maxsize=65536)(self._patterns)
        self._credential_key = lru_cache(maxsize=8192)(
            lambda key: re.sub('[^a-z0-9]', '', key.lower()) in CREDENTIAL_KEYS)
        self.archive_members = {}

    def inspect_bytes(self, raw):
        self.counts['decoded_layers'] += 1
        events = self._small_patterns(raw) if len(raw) <= 256 else self._patterns(raw)
        for key, count in zip(('endpoint_or_url', 'personal_path', 'credential_pattern',
                               'private_marker', 'private_binary_marker'), events):
            self.counts[key] += count
            self.counts['findings'] += count

    def _patterns(self, raw):
        urls = sum(match.group() not in self.allowed for match in URL.finditer(raw))
        paths = len(HOME_PATH.findall(raw))
        credentials = len(SECRET.findall(raw)) + len(PRIVATE_KEY.findall(raw)) + len(BEARER.findall(raw))
        lower = raw.lower()
        markers = sum(value in lower for value in self.markers)
        binary_markers = sum(value in raw for value in self.binary_markers)
        return urls, paths, credentials, markers, binary_markers

    def inspect_value(self, value, field='', depth=0):
        require(depth < 80, 'Nested data exceeds scan depth')
        if isinstance(value, dict):
            for key, child in value.items():
                self.inspect_bytes(key.encode())
                if self._credential_key(key) and child:
                    self.counts['credential_pattern'] += 1
                    self.counts['findings'] += 1
                self.inspect_value(child, key, depth + 1)
        elif isinstance(value, list):
            if len(value) == 2 and value[1] == 'base64' and isinstance(value[0], str):
                self.inspect_bytes(base64.b64decode(value[0], validate=True))
            elif (len(value) >= 32 and self.binary_markers
                  and all(type(child) is int and 0 <= child <= 255 for child in value)):
                # Buffer/Uint8Array JSON projections may retain byte vectors.
                self.inspect_bytes(bytes(value))
            for child in value:
                self.inspect_value(child, field, depth + 1)
        elif isinstance(value, str):
            raw = value.encode()
            self.inspect_bytes(raw)
            stripped = value.lstrip()
            if stripped.startswith(('{', '[')):
                try:
                    nested = loads(value)
                except (ValueError, UnicodeError):
                    nested = None
                if isinstance(nested, (dict, list)):
                    self.inspect_value(nested, field, depth + 1)
            if field in {'data', 'instructionData', 'accountData'} and value:
                # Solana unparsed instructions are commonly base58; account bytes base64.
                for decoder in (lambda x: base64.b64decode(x, validate=True), decode58):
                    try:
                        decoded = decoder(value)
                    except (ValueError, UnicodeError):
                        continue
                    self.inspect_bytes(decoded)

    def inspect_file(self, path, relative):
        self.counts['files'] += 1
        self.inspect_bytes(relative.encode())
        try:
            require(not path.is_symlink(), 'Symlinks are not publication files')
            with path.open('rb') as handle:
                self.inspect_stream(handle, relative)
        except (ValueError, OSError, UnicodeError, tarfile.TarError, EOFError):
            self.counts['unreadable'] += 1
            self.counts['findings'] += 1

    def inspect_stream(self, incoming, relative):
        path = Path(relative)
        if path.suffix == '.gz':
            # Public gzip headers contain no original filename, comment, extra
            # fields or collection/computer timestamp, including nested assets.
            header = incoming.read(10)
            require(len(header) == 10 and header[:3] == b'\x1f\x8b\x08' and header[3] == 0
                    and header[4:8] == bytes(4), 'Gzip header exposes metadata')
            incoming = io.BufferedReader(_Prefixed(header, incoming))
        if relative.endswith('.tar.gz'):
            require(relative not in self.archive_members, 'Repeated archive path')
            self.archive_members[relative] = set()
            with gzip.GzipFile(fileobj=incoming, mode='rb') as expanded:
                checked = _ScannedTar(expanded, self)
                with tarfile.open(fileobj=checked, mode='r|') as archive:
                    seen = set()
                    for member in archive:
                        require(member.isfile() and member.name not in seen, 'Archive link/special/duplicate')
                        require(not member.pax_headers and member.uid == member.gid == member.mtime == 0
                                and member.uname == member.gname == '' and member.mode == 0o644,
                                'Archive exposes host metadata')
                        from replay.core import safe_path
                        safe_path(Path('/neutral-public-root'), member.name)
                        seen.add(member.name)
                        self.archive_members[relative].add(member.name)
                        self.counts['files'] += 1
                        self.inspect_bytes(member.name.encode())
                        with archive.extractfile(member) as handle:
                            self.inspect_stream(handle, member.name)
                # Tar parsers stop at their terminator. Scan the remaining
                # decompressed bytes too, including padding or appended content.
                while checked.read(1024 * 1024):
                    pass
                checked.finish()
            return
        if path.suffix == '.gz':
            # JSONL is scanned one record at a time to avoid duplicating GB streams.
            if path.name.endswith('.jsonl.gz'):
                with gzip.GzipFile(fileobj=incoming, mode='rb') as handle:
                    for line in handle:
                        self.inspect_bytes(line)
                        self.inspect_value(loads(line))
                return
            with gzip.GzipFile(fileobj=incoming, mode='rb') as handle:
                raw = handle.read()
        else:
            raw = incoming.read()
        self.inspect_bytes(raw)
        if path.suffix == '.json' or path.name.endswith('.json.gz') or (path.suffix == '.source' and raw.lstrip().startswith((b'{', b'['))):
            self.inspect_value(loads(raw))
        elif path.suffix == '.gz' and not path.name.endswith('.sql.gz'):
            raise ValueError('Unrecognized compressed publication format')
        elif path.suffix == '.jsonl':
            for line in raw.splitlines():
                self.inspect_value(loads(line))


class _Prefixed(io.RawIOBase):
    """Replay a small inspected header without seeking a streaming tar member."""
    def __init__(self, prefix, source):
        self.prefix, self.source = prefix, source

    def readable(self):
        return True

    def readinto(self, buffer):
        size = len(buffer)
        value = self.prefix[:size]
        self.prefix = self.prefix[size:]
        if len(value) < size:
            value += self.source.read(size - len(value))
        buffer[:len(value)] = value
        return len(value)


class _ScannedTar(io.RawIOBase):
    def __init__(self, source, scanner):
        self.source, self.scanner = source, scanner
        self.total, self.pending = 0, bytearray()

    def readable(self):
        return True

    def readinto(self, buffer):
        value = self.source.read(len(buffer))
        self.total += len(value)
        require(self.total <= 500 * 1024 * 1024, 'Tar input exceeds public part bound')
        # Pending bytes have no delimiter. Search only new bytes and retain a
        # complete token across reads, including large canonical JSON lines.
        # The existing total tar bound also bounds this buffer.
        cut = max(value.rfind(b'\0'), value.rfind(b'\n')) + 1
        if cut:
            self.pending.extend(value[:cut])
            self.scanner.inspect_bytes(bytes(self.pending))
            self.pending.clear()
            self.pending.extend(value[cut:])
        else:
            self.pending.extend(value)
        buffer[:len(value)] = value
        return len(value)

    def finish(self):
        if self.pending:
            self.scanner.inspect_bytes(bytes(self.pending))
            self.pending.clear()

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('root', type=Path)
    parser.add_argument('--private-markers', type=Path)
    parser.add_argument('--allowed-url', action='append', default=[])
    parser.add_argument('--asset-index', type=Path, help='Optional exact member coverage check for an asset directory')
    parser.add_argument('--asset-index-sha256')
    args = parser.parse_args()
    markers = []
    if args.private_markers:
        private = loads(args.private_markers.read_bytes())
        require(isinstance(private, list) and all(isinstance(v, str) for v in private), 'Expected private string array')
        markers = private
    scan = Scanner(markers, args.allowed_url)
    for path in sorted(args.root.rglob('*')):
        if path.is_file() or path.is_symlink():
            scan.inspect_file(path, path.relative_to(args.root).as_posix())
    if args.asset_index:
        from replay.core import sha
        from fetch_data import validate_index
        require(args.asset_index_sha256 is not None, 'Asset index needs an independent pin')
        raw = args.asset_index.read_bytes()
        require(sha(raw) == args.asset_index_sha256, 'Asset index pin differs')
        index = loads(raw)
        validate_index(index)
        expected = {row['name']: set(row['files']) for row in index['assets']}
        covered = scan.archive_members == expected
        scan.counts.update(archive_index_coverage=covered, archive_assets=len(scan.archive_members),
                           archive_members=sum(map(len, scan.archive_members.values())))
        if not covered:
            scan.counts['unreadable'] += 1
            scan.counts['findings'] += 1
    else:
        require(args.asset_index_sha256 is None, 'Asset index pin supplied without index')
    print(json.dumps(scan.counts, sort_keys=True))
    raise SystemExit(1 if scan.counts['findings'] else 0)


if __name__ == '__main__':
    main()
