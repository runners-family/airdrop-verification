"""Package-relative capture adapter; the top-level manifest pins projected bytes."""
import gzip
from pathlib import Path, PurePath
from .core import file_hash, loads, require, safe_path


class Bundle:
    def __init__(self, workspace):
        self.workspace = Path(workspace).resolve()
        self.used = {}

    def path(self, relative):
        return safe_path(self.workspace, relative.as_posix() if isinstance(relative, PurePath) else relative)

    def exists(self, relative):
        return self.path(relative).exists()

    def read(self, relative):
        path = self.path(relative)
        raw = path.read_bytes()
        self.used[relative.as_posix() if isinstance(relative, PurePath) else relative] = {'bytes': len(raw), 'sha256': file_hash(path)}
        return raw

    def json(self, relative):
        return loads(self.read(relative))

    def capture(self, folder, name, expected_job=None):
        path = Path(folder) / (name + '.json.gz')
        if not self.exists(path):
            return None, None
        record = loads(gzip.decompress(self.read(path)))
        require(record['name'] == name, 'Capture label differs')
        if expected_job is not None:
            require(record['job'] == expected_job, 'Capture request differs from reconstructed plan: ' + name)
        return (record['body'] if record['ok'] else None), record
