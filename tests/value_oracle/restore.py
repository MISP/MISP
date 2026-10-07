"""Reset a test instance to a database dump, including derived Redis state.

Workers are stopped through supervisor while the tables are replaced. Redis
keys are removed by prefix only: the background job queues share the
database and must survive. Correlation exclusions are re-cached from the
table because MISP only rebuilds that set when an exclusion is saved.

With a standby database configured, the dump is kept pre-loaded there and a
restore swaps it in with one RENAME TABLE, then refills the standby in the
background. The standby runs the dump's own statements, minus the tables in
standby_skip, which keep their current contents in the target. Nothing else
is changed: loading each table in one transaction or adding its indexes
after the data changes the index sizes, and that is enough to change which
index the optimizer picks, and with it the row order of unordered reads. A
marker table, written last, records the dump and the loader that produced
the standby; only a standby whose marker matches is swapped in, otherwise
the restore loads the dump in full.
"""

import contextlib
import fcntl
import glob
import json
import os
import re
import subprocess
import sys
import tempfile
import threading
import time
import xmlrpc.client

from core import OracleError

REQUIRED = ('dump', 'database', 'mysql_user', 'mysql_password', 'redis_db',
            'supervisor_url', 'supervisor_group', 'app_dir')
REDIS_PREFIXES = ('misp:*', 'workflow:*', 'eventreport_picture_*')
EXCLUSIONS_KEY = 'misp:correlation_exclusions'

LOADER_VERSION = 2
MARKER = '_standby_ready'
OLD_PREFIX = '_old_'
HEADER = b'-- Table structure for table `'
NAME_RE = re.compile(r'^[A-Za-z0-9_$]{1,64}$')


def resp(*args):
    out = b'*%d\r\n' % len(args)
    for a in args:
        a = a if isinstance(a, bytes) else str(a).encode()
        out += b'$%d\r\n%s\r\n' % (len(a), a)
    return out


def quoted(name):
    if not NAME_RE.match(name):
        raise OracleError('unexpected table or database name %r' % name)
    return '`%s`' % name


class DumpRewriter:
    """Copies a mysqldump (MariaDB, one row per line) line by line into a
    client stream, counting each table's rows, optionally leaving tables out
    and emitting a timing mark before and after each table. With neither
    option the output is the input, byte for byte."""

    def __init__(self, skip=(), marks=False):
        self.skip = frozenset(skip)
        self.marks = marks
        self.rows = {}
        self.skipped = []

    def mark(self, out, table, phase):
        if self.marks:
            out.write(b"SELECT 'mark', '%s', '%s', UNIX_TIMESTAMP(NOW(6));\n"
                      % (table.encode(), phase))

    def copy(self, lines, out):
        state, table = 'outside', None
        for line in lines:
            if state == 'data':
                if line[:1] == b'(':
                    self.rows[table] += 1
                elif line.startswith(b'UNLOCK TABLES;'):
                    out.write(line)
                    self.mark(out, table, b'done')
                    state, table = 'outside', None
                    continue
                out.write(line)
            elif state == 'skip':
                if line.startswith(HEADER):
                    raise OracleError('dump: no data section for ' + table)
                if line.startswith(b'UNLOCK TABLES;'):
                    state, table = 'outside', None
            elif line.startswith(HEADER):
                if table is not None:
                    raise OracleError('dump: no data section for ' + table)
                table = line[len(HEADER):line.rindex(b'`')].decode()
                quoted(table)
                if table in self.skip:
                    self.skipped.append(table)
                    state = 'skip'
                    continue
                self.rows[table] = 0
                self.mark(out, table, b'start')
                state = 'structure'
                out.write(line)
            else:
                if state == 'structure' and line.startswith(b'LOCK TABLES '):
                    state = 'data'
                out.write(line)
        if state != 'outside':
            raise OracleError('dump ends inside table %s' % table)


class Mysql:
    def __init__(self, user, password):
        self.user = user
        self.password = password

    @contextlib.contextmanager
    def defaults_file(self):
        with tempfile.NamedTemporaryFile('w', suffix='.cnf') as cnf:
            cnf.write('[client]\nuser=%s\npassword=%s\n' % (
                self.user, self.password))
            cnf.flush()
            yield '--defaults-extra-file=' + cnf.name

    def run(self, database, args, **kwargs):
        with self.defaults_file() as defaults:
            return subprocess.run(['mysql', defaults] + args + [database],
                                  check=True, **kwargs)

    def query(self, database, sql):
        return self.run(database, ['-N', '--raw', '-B', '-e', sql],
                        capture_output=True).stdout.decode()

    def tables(self, database):
        return self.query('information_schema', (
            "SELECT table_name FROM tables WHERE table_schema = '%s'"
            " AND table_type = 'BASE TABLE' ORDER BY table_name")
            % quoted(database)[1:-1]).split()

    def load(self, database, dump, rewriter, trailer=None, on_mark=None):
        """Streams the gzipped dump through the rewriter into one client.
        trailer(rewriter) returns statements to send after the dump;
        on_mark(table, phase, unix_ts) sees each timing mark as the server
        reaches it."""
        unzip = subprocess.Popen(['gzip', '-dc', dump],
                                 stdout=subprocess.PIPE, bufsize=1 << 20)
        with self.defaults_file() as defaults:
            client = subprocess.Popen(
                ['mysql', defaults, '-N', '-B', '--unbuffered', database],
                stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                bufsize=1 << 20)
            reader = threading.Thread(target=read_marks,
                                      args=(client.stdout, on_mark))
            reader.start()
            try:
                rewriter.copy(unzip.stdout, client.stdin)
                if trailer is not None:
                    client.stdin.write(trailer(rewriter))
            except BrokenPipeError:
                pass
            except BaseException:
                client.kill()
                raise
            finally:
                try:
                    client.stdin.close()
                except BrokenPipeError:
                    pass
                unzip.stdout.close()
                unzip.wait()
                client.wait()
                reader.join()
        if client.returncode != 0:
            raise OracleError('mysql import into %s failed (exit %d)'
                              % (database, client.returncode))
        if unzip.returncode != 0:
            raise OracleError('gzip -dc %s failed (exit %d)'
                              % (dump, unzip.returncode))


def read_marks(stream, on_mark):
    for line in stream:
        parts = line.decode(errors='replace').rstrip('\n').split('\t')
        if on_mark is not None and len(parts) == 4 and parts[0] == 'mark':
            on_mark(parts[1], parts[2], float(parts[3]))


class Standby:
    def __init__(self, settings, mysql, log=print):
        self.db = settings['standby_database']
        self.target = settings['database']
        if self.db == self.target:
            raise OracleError('standby_database must differ from database')
        quoted(self.db)
        quoted(self.target)
        self.dump = settings['dump']
        self.skip = sorted(settings.get('standby_skip', []))
        self.mysql = mysql
        self.log = log
        base = os.path.dirname(self.dump)
        self.lock_path = os.path.expanduser(
            settings.get('standby_lock', os.path.join(base, 'standby.lock')))
        self.log_path = os.path.expanduser(settings.get(
            'standby_log', os.path.join(base, 'standby_refill.log')))

    def identity(self):
        st = os.stat(self.dump)
        return {'path': os.path.realpath(self.dump), 'size': st.st_size,
                'mtime_ns': st.st_mtime_ns}

    @contextlib.contextmanager
    def locked(self, waiting=None):
        with open(self.lock_path, 'a') as f:
            try:
                fcntl.flock(f, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError:
                if waiting is not None:
                    waiting()
                fcntl.flock(f, fcntl.LOCK_EX)
            yield

    def busy(self):
        with open(self.lock_path, 'a') as f:
            try:
                fcntl.flock(f, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError:
                return True
            fcntl.flock(f, fcntl.LOCK_UN)
            return False

    def marker(self):
        if MARKER not in self.mysql.tables(self.db):
            return None
        return json.loads(self.mysql.query(
            self.db, 'SELECT doc FROM %s' % quoted(MARKER)))

    def status(self):
        """Returns (ready, reason)."""
        tables = self.mysql.tables(self.db)
        if MARKER not in tables:
            return False, ('empty' if not tables else
                           'no ready marker (%d tables)' % len(tables))
        try:
            doc = self.marker()
        except ValueError as e:
            return False, 'unreadable marker: %s' % e
        if doc.get('loader') != LOADER_VERSION:
            return False, 'loaded by loader version %s, this is %s' % (
                doc.get('loader'), LOADER_VERSION)
        if doc.get('identity') != self.identity():
            return False, 'loaded from another dump: %s' % doc.get('identity')
        if doc.get('skipped') != self.skip:
            return False, 'loaded without %s, configured %s' % (
                doc.get('skipped'), self.skip)
        expected = set(doc['tables']) | {MARKER}
        if set(tables) != expected:
            return False, 'tables differ from the marker (%d missing, %d '\
                'extra)' % (len(expected - set(tables)),
                            len(set(tables) - expected))
        return True, 'ready: %d tables, loaded %s' % (
            len(doc['tables']), doc['finished'])

    def swap_plan(self, doc, target_tables):
        """The RENAME TABLE statement that moves every non-skipped target
        table out (into the standby, prefixed) and the standby's tables in,
        and the tables to drop afterwards. None, reason when the swap would
        leave the target without a table the standby lacks."""
        missing = [t for t in self.skip if t not in target_tables]
        if missing:
            return None, 'the target lacks %s, which the standby leaves out'\
                % ', '.join(missing)
        out = [t for t in target_tables if t not in self.skip]
        for t in out + [MARKER]:
            quoted(OLD_PREFIX + t)
        tgt, stb = quoted(self.target), quoted(self.db)
        renames = (['%s.%s TO %s.%s' % (tgt, quoted(t), stb,
                                        quoted(OLD_PREFIX + t)) for t in out]
                   + ['%s.%s TO %s.%s' % (stb, quoted(t), tgt, quoted(t))
                      for t in sorted(doc['tables'])]
                   + ['%s.%s TO %s.%s' % (stb, quoted(MARKER), stb,
                                          quoted(OLD_PREFIX + MARKER))])
        drops = [OLD_PREFIX + t for t in out + [MARKER]]
        extra = [t for t in out if t not in doc['tables']]
        return {'rename': 'RENAME TABLE ' + ', '.join(renames),
                'drop': drops, 'extra': extra}, None

    def swap(self):
        """Swaps a ready standby in. Returns (detail, None), or (None,
        reason) when it refused before changing anything."""
        doc = self.marker()
        plan, reason = self.swap_plan(doc, self.mysql.tables(self.target))
        if plan is None:
            return None, reason
        started = time.monotonic()
        self.mysql.query(self.db, 'SET SESSION lock_wait_timeout = 60; '
                         + plan['rename'])
        renamed = time.monotonic() - started
        self.drop(plan['drop'])
        return ('%d tables in (rename %.2fs); dropped old tables and %s'
                % (len(doc['tables']), renamed,
                   ', '.join(plan['extra']) or 'no extra table')), None

    def drop(self, tables):
        for i in range(0, len(tables), 50):
            self.mysql.query(self.db, 'DROP TABLE IF EXISTS ' + ', '.join(
                quoted(t) for t in tables[i:i + 50]))

    def marker_sql(self, rewriter):
        doc = json.dumps({
            'identity': self.identity(), 'loader': LOADER_VERSION,
            'skipped': self.skip, 'tables': rewriter.rows,
            'finished': time.strftime('%Y-%m-%d %H:%M:%S')}, sort_keys=True)
        doc = doc.replace('\\', '\\\\').replace("'", "\\'")
        return ("CREATE TABLE %s (doc mediumtext NOT NULL) ENGINE=InnoDB;\n"
                "INSERT INTO %s VALUES ('%s');\nCOMMIT;\n" % (
                    quoted(MARKER), quoted(MARKER), doc)).encode()

    def refill(self, force=False):
        """Loads the standby from the dump, holding the lock throughout."""
        with self.locked(waiting=lambda: self.log(
                'waiting for another standby load to finish')):
            ready, reason = self.status()
            if ready and not force:
                return 'already %s' % reason
            started = time.monotonic()
            self.drop(self.mysql.tables(self.db))
            rewriter = DumpRewriter(self.skip, marks=True)
            timer = MarkTimer(rewriter, self.log)
            self.mysql.load(self.db, self.dump, rewriter, self.marker_sql,
                            timer.on_mark)
            missing = sorted(set(self.skip) - set(rewriter.skipped))
            if missing:
                self.log('note: the dump has no table %s' % missing)
            return 'loaded %d tables (%d rows) in %.0fs, skipped %s' % (
                len(rewriter.rows), sum(rewriter.rows.values()),
                time.monotonic() - started, ', '.join(rewriter.skipped))

    def spawn_refill(self, config_path):
        cmd = [sys.executable, '-B', '-u',
               os.path.join(os.path.dirname(os.path.abspath(__file__)),
                            'oracle.py')]
        if config_path:
            cmd += ['--config', config_path]
        cmd += ['standby', 'refill']
        with open(self.log_path, 'ab') as out:
            out.write(('\n== %s refill\n' % time.strftime(
                '%Y-%m-%d %H:%M:%S')).encode())
            out.flush()
            proc = subprocess.Popen(cmd, stdin=subprocess.DEVNULL,
                                    stdout=out, stderr=subprocess.STDOUT,
                                    start_new_session=True)
        return 'started in the background (pid %d, log %s)' % (
            proc.pid, self.log_path)


class MarkTimer:
    """Logs one line per table as its last mark arrives."""

    def __init__(self, rewriter, log):
        self.rewriter = rewriter
        self.log = log
        self.seen = {}

    def on_mark(self, table, phase, ts):
        marks = self.seen.setdefault(table, {})
        marks[phase] = ts
        if phase == 'done':
            self.log('  %-34s %10d rows %8.1fs' % (
                table, self.rewriter.rows.get(table, 0),
                ts - marks['start']))


class Restorer:
    def __init__(self, settings, log=print, config_path=None):
        if not settings:
            raise OracleError('config has no "restore" section')
        missing = [k for k in REQUIRED if k not in settings]
        if missing:
            raise OracleError('restore config lacks: ' + ', '.join(missing))
        self.s = dict(settings)
        self.s['dump'] = os.path.expanduser(self.s['dump'])
        self.log = log
        self.config_path = config_path
        if not os.path.isfile(self.s['dump']):
            raise OracleError('dump not found: ' + self.s['dump'])
        self.mysql = Mysql(self.s['mysql_user'], self.s['mysql_password'])
        self.standby = (Standby(self.s, self.mysql, log)
                        if self.s.get('standby_database') else None)

    def run(self, refill=True):
        steps = [
            ('stop workers', self.stop_workers),
            ('restore tables', self.restore_tables),
            ('clear redis', self.clear_redis),
            ('cache exclusions', self.cache_exclusions),
            ('check workflows', self.check_workflows),
            ('clear cake caches', self.clear_cake_caches),
            ('start workers', self.start_workers),
        ]
        if self.standby is not None and refill:
            steps.append(('refill standby', lambda: self.standby.spawn_refill(
                self.config_path)))
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

    def restore_tables(self):
        if self.standby is not None:
            with self.standby.locked(waiting=lambda: self.log(
                    'waiting for the running standby refill')):
                ready, reason = self.standby.status()
                if ready:
                    detail, reason = self.standby.swap()
                    if detail is not None:
                        return 'swapped standby: ' + detail
            self.log('standby %s not used (%s); full load'
                     % (self.standby.db, reason))
        return self.load_dump()

    def load_dump(self):
        rewriter = DumpRewriter()
        self.mysql.load(self.s['database'], self.s['dump'], rewriter)
        extra = [t for t in self.mysql.tables(self.s['database'])
                 if t not in rewriter.rows]
        for i in range(0, len(extra), 50):
            self.query('DROP TABLE ' + ', '.join(
                quoted(t) for t in extra[i:i + 50]))
        count = self.query('SELECT COUNT(*) FROM attributes')
        return 'full load, attributes=%s; dropped %s' % (
            count.strip(), ', '.join(extra) or 'no extra table')

    def query(self, sql):
        return self.mysql.query(self.s['database'], sql)

    def _redis(self, args, payload=None):
        return subprocess.run(
            ['redis-cli', '-n', str(self.s['redis_db'])] + args,
            input=payload, capture_output=True, check=True).stdout

    def redis(self, *args):
        return self._redis(list(args))

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
