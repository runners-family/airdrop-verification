"""Reviewed IDL decoder; source reviewed historical method"""
import base64,struct
from decimal import Decimal
from pathlib import Path
from .core import loads,encode58 as b58encode,require
ROOT=None
capture=None
class IDL:

    def __init__(self, file):
        self.j = loads((ROOT / file).read_bytes())
        self.types = {x['name']: x['type'] for x in self.j['types']}

    def decode(self, name, data, offset=0):
        return self.val({'defined': {'name': name}}, data, offset)

    def val(self, t, d, o):
        def take(size):
            require(type(o) is int and o >= 0 and size >= 0 and o + size <= len(d), 'Truncated IDL value')
            return d[o:o + size]
        if isinstance(t, str):
            if t in ['pubkey', 'publicKey']:
                return (b58encode(take(32)), o + 32)
            if t == 'bool':
                require(take(1)[0] in (0, 1), 'Invalid IDL boolean')
                return (bool(d[o]), o + 1)
            if t[0] in 'ui' and t[1:].isdigit():
                n = int(t[1:]) // 8
                return (int.from_bytes(take(n), 'little', signed=t[0] == 'i'), o + n)
            if t in ['f64', 'f32']:
                n = int(t[1:]) // 8
                return (struct.unpack('<d' if n == 8 else '<f', take(n))[0], o + n)
            raise ValueError(t)
        if 'array' in t:
            (typ, n) = t['array']
            require(type(n) is int and 0 <= n <= len(d), 'Invalid IDL array length')
            res = []
            for i in range(n):
                (v, o) = self.val(typ, d, o)
                res.append(v)
            return (res, o)
        if 'vec' in t:
            (n, o) = self.val('u32', d, o)
            return self.val({'array': [t['vec'], n]}, d, o)
        if 'option' in t:
            (flag, o) = self.val('u8', d, o)
            require(flag in (0, 1), 'Invalid IDL option flag')
            if flag:
                return self.val(t['option'], d, o)
            return (None, o)
        name = t['defined']
        name = name['name'] if isinstance(name, dict) else name
        if name == 'Number':
            return (Decimal(int.from_bytes(take(32), 'little')) / Decimal(10 ** 12), o + 32)
        if name == 'WrappedI80F48':
            return (Decimal(int.from_bytes(take(16), 'little', signed=True)) / Decimal(2 ** 48), o + 16)
        t = self.types[name]
        if t['kind'] == 'struct':
            res = {}
            for f in t['fields']:
                (res[f['name']], o) = self.val(f['type'], d, o)
            return (res, o)
        if t['kind'] == 'enum':
            ix = take(1)[0]
            o += 1
            require(ix < len(t['variants']), 'Invalid IDL enum variant')
            v = t['variants'][ix]
            assert not v.get('fields'), v
            return (v['name'], o)
        raise ValueError(t)

    def accounts(self, cname, name):
        c = capture(cname)
        res = []
        schema = next(a for a in self.j['accounts'] if a['name'] == name)
        seen = set()
        for row in c['result']['value']:
            require(row['pubkey'] not in seen, 'Duplicate IDL account')
            seen.add(row['pubkey'])
            require(row['account']['owner'] == self.j['address'], 'Foreign IDL account program')
            raw = base64.b64decode(row['account']['data'][0])
            require(raw[:8] == bytes(schema['discriminator']), 'Wrong IDL account discriminator')
            (v, end) = self.decode(name, raw, 8)
            res.append({'address': row['pubkey'], 'data_length': len(raw), 'decoded_end': end, **v})
        return res

    def offsets(self, name):
        o = 8
        res = {}
        for f in self.types[name]['fields']:
            res[f['name']] = o
            (_, o) = self.val(f['type'], bytes(8192), o)
        return (res, o)
