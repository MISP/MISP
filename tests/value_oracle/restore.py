"""Reset a test instance to a database dump, including derived Redis state.

Workers are stopped through supervisor while the dump loads. Redis keys are
removed by prefix only: the background job queues share the database and must
survive. Correlation exclusions are re-cached from the table because MISP only
rebuilds that set when an exclusion is saved.
"""

import glob
import gzip
import os
import subprocess
import tempfile
import time
import xmlrpc.client

from core import OracleError

REQUIRED = ('dump', 'database', 'mysql_user', 'mysql_password', 'redis_db',
            'supervisor_url', 'supervisor_group', 'app_dir')
REDIS_PREFIXES = ('misp:*', 'workflow:*', 'eventreport_picture_*')
EXCLUSIONS_KEY = 'misp:correlation_exclusions'


def resp(*args):
    out = b'*%d\r\n' % len(args)
    for a in args:
        a = a if isinstance(a, bytes) else str(a).encode()
        out += b'$%d\r\n%s\r\n' % (len(a), a)
    return out


class Restorer:
    def __init__(self, settings, log=print):
        if not settings:
            raise OracleError('config has no "restore" section')
        missing = [k for k in REQUIRED if k not in settings]
        if missing:
            raise OracleError('restore config lacks: ' + ', '.join(missing))
        self.s = dict(settings)
        self.s['dump'] = os.path.expanduser(self.s['dump'])
        self.log = log
        if not os.path.isfile(self.s['dump']):
            raise OracleError('dump not found: ' + self.s['dump'])

    def run(self):
        steps = [
            ('stop workers', self.stop_workers),
            ('load dump', self.load_dump),
            ('clear redis', self.clear_redis),
            ('cache exclusions', self.cache_exclusions),
            ('check workflows', self.check_workflows),
            ('clear cake caches', self.clear_cake_caches),
            ('start workers', self.start_workers),
        ]
        for name, step in steps:
            started = time.monotonic()
            detail = step()
            self.log('%-18s %6.1fs  %s' % (
                name, time.monotonic() - started, detail or ''))

    def _supervisor(self):
        return xmlrpc.client.ServerProxy(self.s['supervisor_url']).supervisor

    def stop_workers(self):
        self._supervisor().stopProcessGroup(self.s['supervisor_group'], True)
        return self._worker_states()

    def start_workers(self):
        self._supervisor().startProcessGroup(self.s['supervisor_group'], True)
        return self._worker_states()

    def _worker_states(self):
        states = {}
        for p in self._supervisor().getAllProcessInfo():
            if p['group'] == self.s['supervisor_group']:
                states[p['statename']] = states.get(p['statename'], 0) + 1
        return ' '.join('%s=%d' % kv for kv in sorted(states.items()))

    def _defaults_file(self):
        cnf = tempfile.NamedTemporaryFile('w', suffix='.cnf')
        cnf.write('[client]\nuser=%s\npassword=%s\n' % (
            self.s['mysql_user'], self.s['mysql_password']))
        cnf.flush()
        return cnf

    def _mysql(self, args, **kwargs):
        with self._defaults_file() as cnf:
            return subprocess.run(
                ['mysql', '--defaults-extra-file=' + cnf.name] + args
                + [self.s['database']], check=True, **kwargs)

    def load_dump(self):
        with self._defaults_file() as cnf:
            proc = subprocess.Popen(
                ['mysql', '--defaults-extra-file=' + cnf.name,
                 self.s['database']], stdin=subprocess.PIPE)
            with gzip.open(self.s['dump'], 'rb') as dump:
                while True:
                    chunk = dump.read(1 << 20)
                    if not chunk:
                        break
                    proc.stdin.write(chunk)
            proc.stdin.close()
            if proc.wait() != 0:
                raise OracleError('mysql import failed (exit %d)'
                                  % proc.returncode)
        count = self.query('SELECT COUNT(*) FROM attributes')
        return 'attributes=%s' % count.strip()

    def query(self, sql):
        return self._mysql(['-N', '--raw', '-e', sql],
                           capture_output=True).stdout.decode()

    def _redis(self, args, payload=None):
        return subprocess.run(
            ['redis-cli', '-n', str(self.s['redis_db'])] + args,
            input=payload, capture_output=True, check=True).stdout

    def clear_redis(self):
        removed = 0
        for prefix in REDIS_PREFIXES:
            keys = [k for k in self._redis(['--scan', '--pattern', prefix])
                    .split(b'\n') if k]
            for i in range(0, len(keys), 1000):
                self._redis(['--pipe'], resp('UNLINK', *keys[i:i + 1000]))
            removed += len(keys)
        return 'removed %d keys' % removed

    def cache_exclusions(self):
        values = [bytes.fromhex(h) for h in self.query(
            'SELECT HEX(value) FROM correlation_exclusions').split()]
        payload = resp('DEL', EXCLUSIONS_KEY)
        if values:
            payload += resp('SADD', EXCLUSIONS_KEY, *values)
        self._redis(['--pipe'], payload)
        return '%d values' % len(values)

    def check_workflows(self):
        enabled = int(self.query(
            'SELECT COUNT(*) FROM workflows WHERE enabled = 1').strip())
        if enabled:
            return ('WARNING: %d enabled workflows; run Workflow::rebuildRedis'
                    % enabled)
        return 'none enabled'

    def clear_cake_caches(self):
        removed = 0
        for sub in ('models', 'persistent'):
            for path in glob.glob(os.path.join(
                    self.s['app_dir'], 'tmp', 'cache', sub, '*')):
                if os.path.basename(path) != 'empty' and os.path.isfile(path):
                    os.unlink(path)
                    removed += 1
        return 'removed %d files' % removed
