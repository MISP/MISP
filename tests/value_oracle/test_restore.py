import contextlib
import io
import json
import os
import tempfile
import threading
import time
import unittest

import core
import restore

DUMP = b'''/*M!999999\\- enable the sandbox mode */
-- MariaDB dump 10.19  Distrib 10.11.14-MariaDB, for debian-linux-gnu (x86_64)
/*!40014 SET @OLD_UNIQUE_CHECKS=@@UNIQUE_CHECKS, UNIQUE_CHECKS=0 */;

--
-- Table structure for table `attributes`
--

DROP TABLE IF EXISTS `attributes`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8mb4 */;
CREATE TABLE `attributes` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `event_id` int(11) NOT NULL,
  `value1` text NOT NULL,
  PRIMARY KEY (`id`),
  UNIQUE KEY `uuid` (`uuid`),
  KEY `event_id` (`event_id`),
  KEY `value1` (`value1`(255))
) ENGINE=InnoDB AUTO_INCREMENT=9 DEFAULT CHARSET=utf8mb3;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `attributes`
--

LOCK TABLES `attributes` WRITE;
/*!40000 ALTER TABLE `attributes` DISABLE KEYS */;
INSERT INTO `attributes` VALUES
(1,1,'a;b'),
(2,1,'(x)');
INSERT INTO `attributes` VALUES
(3,2,'c');
/*!40000 ALTER TABLE `attributes` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `logs`
--

DROP TABLE IF EXISTS `logs`;
CREATE TABLE `logs` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  PRIMARY KEY (`id`)
) ENGINE=InnoDB;

--
-- Dumping data for table `logs`
--

LOCK TABLES `logs` WRITE;
/*!40000 ALTER TABLE `logs` DISABLE KEYS */;
INSERT INTO `logs` VALUES
(1),
(2);
/*!40000 ALTER TABLE `logs` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `foo`
--

DROP TABLE IF EXISTS `foo`;
CREATE TABLE `foo` (
  `test` int(11) DEFAULT NULL,
  KEY `test` (`test`)
) ENGINE=InnoDB;

--
-- Dumping data for table `foo`
--

LOCK TABLES `foo` WRITE;
/*!40000 ALTER TABLE `foo` DISABLE KEYS */;
/*!40000 ALTER TABLE `foo` ENABLE KEYS */;
UNLOCK TABLES;
/*!40014 SET UNIQUE_CHECKS=@OLD_UNIQUE_CHECKS */;

-- Dump completed on 2026-10-01 17:45:34
'''


def rewrite(dump=DUMP, **options):
    rewriter = restore.DumpRewriter(**options)
    out = io.BytesIO()
    rewriter.copy(io.BytesIO(dump), out)
    return rewriter, out.getvalue()


class RespTest(unittest.TestCase):
    def test_encoding(self):
        self.assertEqual(b'*2\r\n$3\r\nDEL\r\n$1\r\nk\r\n',
                         restore.resp('DEL', 'k'))

    def test_binary_and_numbers(self):
        self.assertEqual(b'*3\r\n$4\r\nSADD\r\n$2\r\n\x00\n\r\n$1\r\n7\r\n',
                         restore.resp('SADD', b'\x00\n', 7))


class DumpRewriterTest(unittest.TestCase):
    def test_plain_copy_is_byte_identical(self):
        rewriter, out = rewrite()
        self.assertEqual(DUMP, out)
        self.assertEqual({'attributes': 3, 'logs': 2, 'foo': 0},
                         rewriter.rows)
        self.assertEqual([], rewriter.skipped)

    def test_skip_drops_the_whole_section(self):
        rewriter, out = rewrite(skip=('logs',))
        self.assertNotIn(b'`logs`', out)
        self.assertEqual(['logs'], rewriter.skipped)
        self.assertEqual({'attributes': 3, 'foo': 0}, rewriter.rows)
        self.assertEqual(DUMP.replace(
            DUMP[DUMP.index(b'-- Table structure for table `logs`'):
                 DUMP.index(b'UNLOCK TABLES;\n\n--\n-- Table structure for '
                            b'table `foo`') + len(b'UNLOCK TABLES;\n')],
            b''), out)

    def test_skipping_the_last_table_keeps_the_trailer(self):
        _, out = rewrite(skip=('foo',))
        self.assertTrue(out.endswith(
            b'UNLOCK TABLES;\n\n--\n/*!40014 SET UNIQUE_CHECKS='
            b'@OLD_UNIQUE_CHECKS */;\n\n-- Dump completed on 2026-10-01 '
            b'17:45:34\n'))

    def test_marks_are_the_only_lines_added(self):
        _, plain = rewrite(skip=('logs',))
        _, out = rewrite(marks=True, skip=('logs',))
        lines = out.split(b'\n')
        marks = [line for line in lines if line.startswith(b"SELECT 'mark'")]
        self.assertEqual([
            b"SELECT 'mark', 'attributes', 'start', UNIX_TIMESTAMP(NOW(6));",
            b"SELECT 'mark', 'attributes', 'done', UNIX_TIMESTAMP(NOW(6));",
            b"SELECT 'mark', 'foo', 'start', UNIX_TIMESTAMP(NOW(6));",
            b"SELECT 'mark', 'foo', 'done', UNIX_TIMESTAMP(NOW(6));"], marks)
        self.assertEqual(plain, b'\n'.join(
            line for line in lines if line not in marks))
        self.assertLess(out.index(b"'attributes', 'start'"),
                        out.index(b'DROP TABLE IF EXISTS `attributes`'))
        self.assertGreater(out.index(b"'attributes', 'done'"),
                           out.index(b'UNLOCK TABLES;'))

    def test_truncated_dump(self):
        with self.assertRaises(core.OracleError):
            rewrite(DUMP[:DUMP.index(b'(3,2')])
        with self.assertRaises(core.OracleError):
            rewrite(DUMP[:DUMP.index(b'UNLOCK TABLES;\n/*!40014')],
                    skip=('foo',))

    def test_refuses_odd_table_names(self):
        with self.assertRaises(core.OracleError):
            rewrite(DUMP.replace(b'`foo`', b'`fo o`'))


class FakeMysql:
    def __init__(self, tables, marker=None):
        self.tables_of = tables
        self.marker = marker
        self.queries = []

    def tables(self, database):
        return sorted(self.tables_of.get(database, []))

    def query(self, database, sql):
        self.queries.append((database, sql))
        return json.dumps(self.marker) if sql.startswith('SELECT doc') \
            else ''


class StandbyTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.dump = os.path.join(self.tmp.name, 'dump.sql.gz')
        open(self.dump, 'wb').close()
        self.settings = {'dump': self.dump, 'database': 'target',
                         'standby_database': 'standby',
                         'standby_skip': ['logs', 'audit_logs']}

    def tearDown(self):
        self.tmp.cleanup()

    def standby(self, mysql):
        return restore.Standby(self.settings, mysql, log=lambda *a: None)

    def marker(self, standby, **changes):
        doc = {'identity': standby.identity(),
               'loader': restore.LOADER_VERSION,
               'skipped': ['audit_logs', 'logs'],
               'tables': {'attributes': 3, 'events': 1},
               'finished': '2026-10-06 18:00:00'}
        doc.update(changes)
        return doc

    def test_lock_and_log_default_beside_the_dump(self):
        standby = self.standby(FakeMysql({}))
        self.assertEqual(os.path.join(self.tmp.name, 'standby.lock'),
                         standby.lock_path)
        self.assertEqual(os.path.join(self.tmp.name, 'standby_refill.log'),
                         standby.log_path)

    def test_refuses_the_target_as_standby(self):
        self.settings['standby_database'] = 'target'
        with self.assertRaises(core.OracleError):
            self.standby(FakeMysql({}))

    def test_status(self):
        mysql = FakeMysql({'standby': []})
        standby = self.standby(mysql)
        self.assertEqual((False, 'empty'), standby.status())
        mysql.tables_of['standby'] = ['attributes', 'events']
        self.assertFalse(standby.status()[0])
        mysql.tables_of['standby'].append(restore.MARKER)
        mysql.marker = self.marker(standby)
        self.assertEqual(
            (True, 'ready: 2 tables, loaded 2026-10-06 18:00:00'),
            standby.status())
        for change in ({'loader': 0}, {'skipped': ['logs']},
                       {'identity': dict(standby.identity(), size=1)},
                       {'tables': {'attributes': 3}}):
            mysql.marker = self.marker(standby, **change)
            self.assertFalse(standby.status()[0], change)

    def test_status_after_the_dump_changed(self):
        mysql = FakeMysql({'standby': ['attributes', 'events',
                                       restore.MARKER]})
        standby = self.standby(mysql)
        mysql.marker = self.marker(standby)
        with open(self.dump, 'wb') as f:
            f.write(b'new')
        ready, reason = standby.status()
        self.assertFalse(ready)
        self.assertIn('another dump', reason)

    def test_swap_plan(self):
        standby = self.standby(FakeMysql({}))
        plan, reason = standby.swap_plan(
            self.marker(standby),
            ['attribute_values', 'attributes', 'audit_logs', 'logs'])
        self.assertIsNone(reason)
        self.assertEqual(
            'RENAME TABLE `target`.`attribute_values` TO '
            '`standby`.`_old_attribute_values`, `target`.`attributes` TO '
            '`standby`.`_old_attributes`, `standby`.`attributes` TO '
            '`target`.`attributes`, `standby`.`events` TO `target`.`events`, '
            '`standby`.`_standby_ready` TO `standby`.`_old__standby_ready`',
            plan['rename'])
        self.assertEqual(['_old_attribute_values', '_old_attributes',
                          '_old__standby_ready'], plan['drop'])
        self.assertEqual(['attribute_values'], plan['extra'])

    def test_swap_refuses_without_the_skipped_tables(self):
        standby = self.standby(FakeMysql({}))
        plan, reason = standby.swap_plan(self.marker(standby),
                                         ['attributes', 'logs'])
        self.assertIsNone(plan)
        self.assertIn('audit_logs', reason)

    def test_swap_runs_one_rename_then_drops(self):
        mysql = FakeMysql({'target': ['attributes', 'audit_logs', 'logs'],
                           'standby': ['attributes', 'events',
                                       restore.MARKER]})
        standby = self.standby(mysql)
        mysql.marker = self.marker(standby)
        detail, reason = standby.swap()
        self.assertIsNone(reason)
        self.assertIn('2 tables in', detail)
        renames = [sql for _, sql in mysql.queries if 'RENAME' in sql]
        self.assertEqual(1, len(renames))
        self.assertTrue(renames[0].startswith(
            'SET SESSION lock_wait_timeout = 60; RENAME TABLE '))
        self.assertEqual(
            ('standby', 'DROP TABLE IF EXISTS `_old_attributes`, '
                        '`_old__standby_ready`'), mysql.queries[-1])

    def test_marker_sql_round_trips(self):
        standby = self.standby(FakeMysql({}))
        rewriter = restore.DumpRewriter()
        rewriter.rows = {'attributes': 3}
        sql = standby.marker_sql(rewriter).decode()
        self.assertTrue(sql.startswith('CREATE TABLE `_standby_ready`'))
        doc = sql[sql.index("VALUES ('") + 9:sql.index("');")]
        doc = json.loads(doc.replace("\\'", "'").replace('\\\\', '\\'))
        self.assertEqual({'attributes': 3}, doc['tables'])
        self.assertEqual(['audit_logs', 'logs'], doc['skipped'])
        self.assertEqual(restore.LOADER_VERSION, doc['loader'])
        self.assertTrue(sql.endswith('COMMIT;\n'))

    def test_lock_is_exclusive(self):
        standby = self.standby(FakeMysql({}))
        self.assertFalse(standby.busy())
        with standby.locked():
            other = self.standby(FakeMysql({}))
            self.assertTrue(other.busy())
        self.assertFalse(standby.busy())

    def test_locked_waits_for_the_holder(self):
        standby = self.standby(FakeMysql({}))
        held, events = threading.Event(), []

        def holder():
            with self.standby(FakeMysql({})).locked():
                held.set()
                time.sleep(0.3)
                events.append('released')

        thread = threading.Thread(target=holder)
        thread.start()
        held.wait()
        with standby.locked(waiting=lambda: events.append('waiting')):
            events.append('acquired')
        thread.join()
        self.assertEqual(['waiting', 'released', 'acquired'], events)


class RestorerConfigTest(unittest.TestCase):
    def settings(self, dump):
        return {k: 'x' for k in restore.REQUIRED} | {'dump': dump}

    def test_missing_section(self):
        with self.assertRaises(core.OracleError):
            restore.Restorer(None)

    def test_missing_keys(self):
        with self.assertRaises(core.OracleError):
            restore.Restorer({'dump': '/nonexistent'})

    def test_missing_dump(self):
        with self.assertRaises(core.OracleError):
            restore.Restorer(self.settings('/nonexistent/dump.sql.gz'))

    def test_valid(self):
        with tempfile.NamedTemporaryFile(suffix='.sql.gz') as f:
            restorer = restore.Restorer(self.settings(f.name))
            self.assertEqual(f.name, restorer.s['dump'])
            self.assertIsNone(restorer.standby)

    def test_standby_configured(self):
        with tempfile.NamedTemporaryFile(suffix='.sql.gz') as f:
            restorer = restore.Restorer(self.settings(f.name) | {
                'standby_database': 'standby'})
            self.assertEqual('standby', restorer.standby.db)
            self.assertEqual([], restorer.standby.skip)

    def test_full_load_drops_tables_the_dump_lacks(self):
        with tempfile.NamedTemporaryFile(suffix='.sql.gz') as f:
            restorer = restore.Restorer(self.settings(f.name) | {
                'database': 'target'})
            mysql = FakeMysql({'target': ['attribute_values', 'attributes',
                                          'logs', 'value_ip_ranges']})

            def load(database, dump, rewriter, **kwargs):
                rewriter.rows = {'attributes': 3, 'logs': 2}
            mysql.load = load
            restorer.mysql = mysql
            detail = restorer.load_dump()
        self.assertIn(('target', 'DROP TABLE `attribute_values`, '
                                 '`value_ip_ranges`'), mysql.queries)
        self.assertIn('dropped attribute_values, value_ip_ranges', detail)

    def test_restore_tables_swaps_only_a_ready_standby(self):
        class FakeStandby:
            db = 'standby'

            def __init__(self, ready, swapped):
                self.ready, self.swapped = ready, swapped

            def locked(self, waiting=None):
                return contextlib.nullcontext()

            def status(self):
                return self.ready, 'why not'

            def swap(self):
                return self.swapped

        logged = []
        with tempfile.NamedTemporaryFile(suffix='.sql.gz') as f:
            restorer = restore.Restorer(self.settings(f.name),
                                        log=logged.append)
        restorer.load_dump = lambda: 'loaded'
        restorer.standby = FakeStandby(True, ('7 tables in', None))
        self.assertEqual('swapped standby: 7 tables in',
                         restorer.restore_tables())
        for ready, swapped in ((False, None), (True, (None, 'refused'))):
            restorer.standby = FakeStandby(ready, swapped)
            self.assertEqual('loaded', restorer.restore_tables())
        self.assertEqual(['standby standby not used (why not); full load',
                          'standby standby not used (refused); full load'],
                         logged)

    def test_cake_cache_clear_keeps_placeholders(self):
        with tempfile.TemporaryDirectory() as app, \
                tempfile.NamedTemporaryFile(suffix='.sql.gz') as f:
            for sub in ('models', 'persistent'):
                d = os.path.join(app, 'tmp', 'cache', sub)
                os.makedirs(d)
                for name in ('empty', 'cake_model_x'):
                    open(os.path.join(d, name), 'w').close()
            restorer = restore.Restorer(
                self.settings(f.name) | {'app_dir': app})
            self.assertEqual('removed 2 files', restorer.clear_cake_caches())
            self.assertTrue(os.path.exists(
                os.path.join(app, 'tmp', 'cache', 'models', 'empty')))


if __name__ == '__main__':
    unittest.main()
