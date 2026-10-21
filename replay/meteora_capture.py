"""Read only the new, package-pinned capture projection."""
import gzip
from pathlib import Path
from .core import loads, require, sha


def read_capture(path):
    path = Path(path)
    record = loads(path.with_name(path.name + '.record.json').read_bytes())
    raw = gzip.decompress(path.with_name(path.name + '.json.gz').read_bytes())
    require(record['http_status'] == 200 and record['error'] is None and
            len(raw) == record['bytes'] and sha(raw) == record['sha256'], 'LP projected capture differs')
    return raw, record
