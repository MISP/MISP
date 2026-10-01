"""Record and compare snapshots of MISP API behaviour.

A suite is a module under suites/ exposing cases(config) -> [Case]. Each case
issues a request and reduces the response to a JSON-serialisable value with
its extractor. Recording stores that value; comparing reproduces it, live or
from a second recording, and reports a structural diff.
"""

import difflib
import fnmatch
import gzip
import hashlib
import json
import os
import re
import ssl
import time
import urllib.error
import urllib.request
from dataclasses import dataclass
from typing import Any, Callable, Optional

INLINE_LIMIT = 256 * 1024
CASE_NAME = re.compile(r'^[A-Za-z0-9_.-]+$')
DIFF_LIMIT = 20
TEXT_DIFF_LINES = 40
SAMPLE = 10


class OracleError(Exception):
    pass


@dataclass
class Config:
    url: str
    users: dict
    store: str
    verify_tls: bool = True
    timeout: int = 900

    @classmethod
    def load(cls, path):
        with open(path) as f:
            raw = json.load(f)
        missing = [k for k in ('url', 'users', 'store') if k not in raw]
        if missing:
            raise OracleError(
                'config %s lacks: %s' % (path, ', '.join(missing)))
        return cls(
            url=raw['url'].rstrip('/'),
            users=raw['users'],
            store=os.path.expanduser(raw['store']),
            verify_tls=raw.get('verify_tls', True),
            timeout=int(raw.get('timeout', 900)),
        )


@dataclass
class Response:
    status: int
    headers: dict
    body: bytes

    def text(self):
        return self.body.decode('utf-8', errors='replace')

    def json(self):
        return json.loads(self.body)


class Client:
    def __init__(self, config):
        self.config = config
        self.context = None
        if not config.verify_tls:
            self.context = ssl.create_default_context()
            self.context.check_hostname = False
            self.context.verify_mode = ssl.CERT_NONE

    def request(self, method, path, body=None, user='admin',
                accept='application/json'):
        if user not in self.config.users:
            raise OracleError('no API key configured for user %r' % user)
        headers = {
            'Authorization': self.config.users[user],
            'Accept': accept,
        }
        data = None
        if body is not None:
            data = json.dumps(body).encode()
            headers['Content-Type'] = 'application/json'
        req = urllib.request.Request(
            self.config.url + path, data=data, headers=headers,
            method=method)
        try:
            with urllib.request.urlopen(
                    req, timeout=self.config.timeout,
                    context=self.context) as r:
                return Response(r.status, dict(r.headers), r.read())
        except urllib.error.HTTPError as e:
            return Response(e.code, dict(e.headers), e.read())


@dataclass
class Case:
    name: str
    path: str = ''
    extract: Optional[Callable[[Response], Any]] = None
    method: str = 'GET'
    body: Any = None
    user: str = 'admin'
    accept: str = 'application/json'
    description: str = ''
    # A custom runner replaces the single request: run(client) returns
    # (status, value). Used for multi-request cases such as write round-trips.
    run: Optional[Callable[[Client], tuple]] = None

    def __post_init__(self):
        if not CASE_NAME.match(self.name):
            raise OracleError('invalid case name %r' % self.name)
        if self.run is None and (not self.path or self.extract is None):
            raise OracleError(
                'case %s needs either run, or path and extract' % self.name)

    def execute(self, client):
        started = time.monotonic()
        if self.run is not None:
            status, value = self.run(client)
        else:
            response = client.request(
                self.method, self.path, self.body, self.user, self.accept)
            status = response.status
            try:
                value = self.extract(response)
            except Exception as e:
                value = {
                    'extract_error': '%s: %s' % (type(e).__name__, e),
                    'body_head': response.text()[:500],
                }
        return {
            'case': self.name,
            'status': status,
            'value': value,
            'meta': {
                'elapsed_ms': round((time.monotonic() - started) * 1000),
                'method': self.method,
                'path': self.path,
                'user': self.user,
            },
        }


# Extractors and normalisers

def pick(obj, path):
    """Resolve a dotted path; 'x[]' iterates a list. Returns a list."""
    current = [obj]
    for part in path.split('.'):
        iterate = part.endswith('[]')
        key = part[:-2] if iterate else part
        nxt = []
        for item in current:
            if key:
                if not isinstance(item, dict) or key not in item:
                    continue
                item = item[key]
            if iterate:
                if isinstance(item, list):
                    nxt.extend(item)
            else:
                nxt.append(item)
        current = nxt
    return current


def drop_keys(obj, keys):
    keys = set(keys)
    if isinstance(obj, dict):
        return {k: drop_keys(v, keys) for k, v in obj.items()
                if k not in keys}
    if isinstance(obj, list):
        return [drop_keys(v, keys) for v in obj]
    return obj


def mask_keys(obj, keys, token='<masked>'):
    keys = set(keys)
    if isinstance(obj, dict):
        return {k: (token if k in keys else mask_keys(v, keys, token))
                for k, v in obj.items()}
    if isinstance(obj, list):
        return [mask_keys(v, keys, token) for v in obj]
    return obj


def substitute(text, substitutions):
    for pattern, replacement in substitutions:
        text = re.sub(pattern, replacement, text)
    return text


def ids_at(path, cast=int):
    """Sorted id list at path; duplicates are kept so they stay visible."""
    def extract(response):
        return sorted(cast(v) for v in pick(response.json(), path))
    return extract


def json_without(drop=(), mask=()):
    def extract(response):
        return mask_keys(drop_keys(response.json(), drop), mask)
    return extract


def text_with(substitutions=()):
    def extract(response):
        return substitute(response.text(), substitutions)
    return extract


def status_only(response):
    return None


# Snapshot store

class Store:
    def __init__(self, root, label):
        if not CASE_NAME.match(label):
            raise OracleError('invalid label %r' % label)
        self.dir = os.path.join(root, label)

    def _case_path(self, suite, case):
        return os.path.join(self.dir, suite, case + '.json')

    def save(self, suite, result):
        path = self._case_path(suite, result['case'])
        os.makedirs(os.path.dirname(path), exist_ok=True)
        blobs = []

        def externalise(value):
            if isinstance(value, str) and len(value) > INLINE_LIMIT:
                raw = value.encode('utf-8')
                name = '%s.%d.txt.gz' % (result['case'], len(blobs))
                with gzip.open(os.path.join(os.path.dirname(path), name),
                               'wb') as f:
                    f.write(raw)
                blobs.append(name)
                return {'$blob': name,
                        'sha256': hashlib.sha256(raw).hexdigest(),
                        'bytes': len(raw)}
            if isinstance(value, dict):
                return {k: externalise(v) for k, v in value.items()}
            if isinstance(value, list):
                return [externalise(v) for v in value]
            return value

        stored = dict(result, value=externalise(result['value']))
        with open(path, 'w') as f:
            json.dump(stored, f, indent=1, sort_keys=True,
                      ensure_ascii=False)

    def load(self, suite, case):
        path = self._case_path(suite, case)
        if not os.path.exists(path):
            return None
        with open(path) as f:
            stored = json.load(f)
        directory = os.path.dirname(path)

        def internalise(value):
            if isinstance(value, dict) and set(value) == {
                    '$blob', 'sha256', 'bytes'}:
                with gzip.open(os.path.join(directory, value['$blob']),
                               'rb') as f:
                    return f.read().decode('utf-8')
            if isinstance(value, dict):
                return {k: internalise(v) for k, v in value.items()}
            if isinstance(value, list):
                return [internalise(v) for v in value]
            return value

        stored['value'] = internalise(stored['value'])
        return stored

    def case_names(self, suite):
        directory = os.path.join(self.dir, suite)
        if not os.path.isdir(directory):
            return []
        return sorted(f[:-5] for f in os.listdir(directory)
                      if f.endswith('.json'))


# Structural diff

def _is_scalar(v):
    return v is None or isinstance(v, (str, int, float, bool))


def _short(v):
    s = json.dumps(v, ensure_ascii=False, sort_keys=True)
    return s if len(s) <= 120 else s[:117] + '...'


def diff(a, b, path='$', out=None):
    """Differences between baseline a and current b, as readable lines."""
    if out is None:
        out = []
    if len(out) >= DIFF_LIMIT:
        return out
    if type(a) is not type(b) and not (
            isinstance(a, (int, float)) and isinstance(b, (int, float))
            and not isinstance(a, bool) and not isinstance(b, bool)):
        out.append('%s: type %s -> %s (%s -> %s)' % (
            path, type(a).__name__, type(b).__name__, _short(a), _short(b)))
    elif isinstance(a, dict):
        for k in sorted(set(a) | set(b), key=str):
            if k not in b:
                out.append('%s.%s: removed (was %s)' % (path, k, _short(a[k])))
            elif k not in a:
                out.append('%s.%s: added (%s)' % (path, k, _short(b[k])))
            else:
                diff(a[k], b[k], '%s.%s' % (path, k), out)
            if len(out) >= DIFF_LIMIT:
                break
    elif isinstance(a, list):
        if a != b:
            if all(_is_scalar(x) for x in a + b):
                _diff_scalar_lists(a, b, path, out)
            else:
                if len(a) != len(b):
                    out.append('%s: length %d -> %d' % (path, len(a), len(b)))
                for i, (x, y) in enumerate(zip(a, b)):
                    diff(x, y, '%s[%d]' % (path, i), out)
                    if len(out) >= DIFF_LIMIT:
                        break
    elif isinstance(a, str) and ('\n' in a or '\n' in b
                                 or len(a) > 200 or len(b) > 200):
        if a != b:
            lines = list(difflib.unified_diff(
                a.splitlines(), b.splitlines(), 'baseline', 'current',
                lineterm='', n=1))
            out.append('%s: text differs (%d diff lines)' % (path, len(lines)))
            out.extend('    ' + l for l in lines[:TEXT_DIFF_LINES])
    elif a != b:
        out.append('%s: %s -> %s' % (path, _short(a), _short(b)))
    return out


def _diff_scalar_lists(a, b, path, out):
    def counts(items):
        c = {}
        for x in items:
            k = json.dumps(x, sort_keys=True)
            c[k] = c.get(k, 0) + 1
        return c
    ca, cb = counts(a), counts(b)
    removed = [k for k in ca for _ in range(ca[k] - cb.get(k, 0))]
    added = [k for k in cb for _ in range(cb[k] - ca.get(k, 0))]
    if not removed and not added:
        out.append('%s: same items, different order' % path)
        return
    out.append('%s: %d items -> %d (removed %d, added %d)' % (
        path, len(a), len(b), len(removed), len(added)))
    if removed:
        out.append('    removed: %s' % ', '.join(removed[:SAMPLE]))
    if added:
        out.append('    added: %s' % ', '.join(added[:SAMPLE]))


def compare_results(baseline, current):
    lines = []
    if baseline['status'] != current['status']:
        lines.append('$status: %s -> %s' % (
            baseline['status'], current['status']))
    diff(baseline['value'], current['value'], '$', lines)
    return lines


def select(cases, pattern):
    return [c for c in cases if fnmatch.fnmatch(c.name, pattern)]
