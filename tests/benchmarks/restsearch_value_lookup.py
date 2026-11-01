#!/usr/bin/env python3
"""Compare exact-value OR and deduplicating UNION using real MISP SQL rendering.

Requires an EMPTY disposable MariaDB database named misp_restsearch_test.
Never run against a MISP application database. No existing tables are dropped.
SQL, plans, row equality checks and server timings are retained in --output.
"""
import argparse
import json
import random
import shlex
import statistics
import subprocess
from pathlib import Path


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--cake', required=True, help='CakePHP lib/Cake directory')
    parser.add_argument('--mysql-command', required=True,
                        help='MariaDB client command selecting the disposable DB')
    parser.add_argument('--output', required=True, type=Path)
    parser.add_argument('--rows', type=int, default=100000)
    parser.add_argument('--repeats', type=int, default=5)
    parser.add_argument('--reuse-fixture', action='store_true',
                        help='Only profile an existing synthetic fixture')
    parser.add_argument('--legacy-deleted-index', action='store_true',
                        help='Include the optional historical deleted index')
    args = parser.parse_args()
    if args.rows < 10000 or args.repeats < 2:
        parser.error('Use at least 10000 rows and two timing repetitions')
    repo = Path(__file__).resolve().parents[2]
    client = shlex.split(args.mysql_command) + ['--raw', '--skip-column-names']
    args.output.mkdir(parents=True, exist_ok=True)

    def sql(statement):
        return subprocess.run(client, input=statement, text=True,
                              capture_output=True, check=True).stdout.strip()

    if sql('SELECT DATABASE();') != 'misp_restsearch_test':
        raise RuntimeError('Refusing a database other than misp_restsearch_test')
    schema = json.loads((repo / 'db_schema.json').read_text())
    tables = ['attributes', 'events', 'objects', 'attribute_tags', 'event_tags']
    existing = sql('SHOW TABLES;').splitlines()
    if args.reuse_fixture:
        if sorted(existing) != sorted(tables) or int(sql(
                'SELECT COUNT(*) FROM attributes;')) != args.rows:
            raise RuntimeError('Existing fixture does not match requested setup')
        for table in tables:
            primary = sql('SELECT COLUMN_NAME FROM information_schema.STATISTICS '
                          f"WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='{table}' "
                          "AND INDEX_NAME='PRIMARY' ORDER BY SEQ_IN_INDEX;")
            columns = sql('SELECT COLUMN_NAME, IS_NULLABLE '
                          'FROM information_schema.COLUMNS '
                          f"WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='{table}';")
            nullable = dict(line.split('\t') for line in columns.splitlines())
            expected = {c['column_name']: c['is_nullable']
                        for c in schema['schema'][table]}
            if primary != 'id' or nullable != expected:
                raise RuntimeError(f'Existing {table} keys/nullability differ')
        prefixes = sql('SELECT INDEX_NAME, SUB_PART '
                       'FROM information_schema.STATISTICS '
                       "WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='attributes' "
                       "AND INDEX_NAME IN ('value1', 'value2');")
        if dict(line.split('\t') for line in prefixes.splitlines()) != {
                'value1': '255', 'value2': '255'}:
            raise RuntimeError('Existing value index prefixes differ')
        deleted_index = sql('SELECT COUNT(*) FROM information_schema.STATISTICS '
                            "WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='attributes' "
                            "AND INDEX_NAME='deleted';")
        if bool(int(deleted_index)) != args.legacy_deleted_index:
            raise RuntimeError('Existing legacy deleted index setting differs')
    elif existing:
        raise RuntimeError('Refusing a nonempty database; use a fresh test DB')

    def quote(value):
        return "'" + str(value).replace('\\', '\\\\').replace("'", "''") + "'"

    statements = ['SET NAMES utf8mb3;', 'SET SESSION query_cache_type=OFF;']
    for table in tables:
        columns = schema['schema'][table]
        definitions = [
            f"`{c['column_name']}` {c['column_type']} " +
            ('NOT NULL' if c['is_nullable'] == 'NO' else 'NULL') +
            (' AUTO_INCREMENT' if c['extra'] == 'auto_increment' else '')
            for c in columns]
        types = {c['column_name']: c['data_type'] for c in columns}
        for column, unique in schema['indexes'][table].items():
            if column == 'id':
                definitions.append('PRIMARY KEY (`id`)')
                continue
            suffix = '(255)' if types[column] == 'text' else ''
            kind = 'UNIQUE KEY' if unique else 'KEY'
            definitions.append(f'{kind} `{column}` (`{column}`{suffix})')
        statements.append(f'CREATE TABLE `{table}` ({",".join(definitions)}) '
                          'ENGINE=InnoDB DEFAULT CHARSET=utf8mb3 '
                          'COLLATE=utf8mb3_unicode_ci;')
        # The captured legacy query probes whether this optional index exists.
        if table == 'attributes' and args.legacy_deleted_index:
            statements.append('CREATE INDEX deleted ON attributes(deleted);')
        count = args.rows if table == 'attributes' else 2000
        batch = []
        for number in range(1, count + 1):
            values = {}
            for column in columns:
                name, kind = column['column_name'], column['data_type']
                values[name] = (0 if kind in ['int', 'tinyint', 'bigint'] else
                                '2026-01-01' if kind == 'date' else '')
            values.update(id=number, uuid=f'{number:036d}')
            values.update({k: v for k, v in {
                'event_id': number if table == 'objects' else number % 2000 + 1,
                'org_id': number % 10 + 1, 'orgc_id': number % 10 + 1,
                'distribution': number % (5 if table == 'events' else 6),
                'sharing_group_id': number % 3,
                'published': int(number % 3 != 0), 'to_ids': int(number % 4 != 0),
                'deleted': int(number % 17 == 0), 'tag_id': number % 7 + 1,
                'attribute_id': number * 10,
                'object_id': number % 2000 + 1 if number % 5 == 0 else 0,
                'value1': ('common.example' if number % 100 == 0 else
                           f'ioc-{number:06d}.example'),
                'value2': ('common.example' if number % 1000 == 0 else
                           f'hash-{number:06d}' if number % 10 == 0 else ''),
                'type': 'domain', 'info': 'Synthetic benchmark event',
                'comment': 'Representative padding ' * 8,
            }.items() if k in values})
            if table == 'attributes' and number in [1, 2]:
                values['value1'] = 'x' * 260 + str(number)
            if table == 'attributes' and number == 3:
                values['value1'] = 'CAFÉ.example'
                values['value2'] = 'cafe.example'
            batch.append('(' + ','.join(quote(values[c['column_name']])
                                       for c in columns) + ')')
            if len(batch) == 1000 or number == count:
                statements.append(f'INSERT INTO `{table}` VALUES ' +
                                  ','.join(batch) + ';')
                batch = []
    statements.append('ANALYZE TABLE ' + ','.join(tables) + ';')
    fixture = args.output / 'fixture.sql'
    fixture.write_text('\n'.join(statements))
    if not args.reuse_fixture:
        sql(fixture.read_text())

    rng = random.Random(20260923)
    cases = []
    for size in [1, 10, 100, 1000]:
        numbers = rng.sample(range(1, args.rows + 1), size)
        values = [f'ioc-{n:06d}.example' if i % 2 else f'missing-{n}.example'
                  for i, n in enumerate(numbers)]
        for admin in [False, True]:
            cases.append(dict(name=f'exact-{size}-' + ('admin' if admin else 'acl'),
                              values=values, admin=admin, limit=500))
    for name, values in [
        ('common', ['common.example']),
        ('collation-dedup', ['cafe.example', 'CAFÉ.example', 'cafe.example']),
        ('prefix-collision', ['x' * 260 + '2']),
        ('composite', [f'hash-{n:06d}' for n in range(10, 1001, 10)]),
    ]:
        for admin in [False, True]:
            for limit in [500, args.rows]:
                suffix = 'admin' if admin else 'acl'
                cases.append(dict(name=f'{name}-{limit}-{suffix}', values=values,
                                  admin=admin, limit=limit))
    # Preserve current tag strategy shapes when adding the value candidate join.
    for name, condition in [
        ('tag-exists', 'EXISTS (SELECT 1 FROM attribute_tags AS TagMatch '
         'WHERE TagMatch.attribute_id = Attribute.id AND TagMatch.tag_id = 1)'),
        ('tag-in', 'Attribute.id IN (SELECT attribute_id FROM attribute_tags '
         'WHERE tag_id = 1)'),
    ]:
        cases.append(dict(name=name, values=['common.example'], admin=False,
                          limit=500, conditions=[condition]))

    report = {'database': sql('SELECT VERSION();'), 'rows': args.rows,
              'repeats': args.repeats, 'seed': 20260923,
              'legacy_deleted_index': args.legacy_deleted_index, 'cases': []}
    for case in cases:
        case['legacy_deleted_index'] = args.legacy_deleted_index
        compiled = subprocess.run(
            ['php', str(Path(__file__).with_name('RestSearchValueQuery.php')),
             args.cake], input=json.dumps(case), text=True,
            capture_output=True, check=True)
        queries = json.loads(compiled.stdout)
        id_output = sql(queries['or_ids'] +
                        "; SELECT '__MISP_UNION_IDS__'; " + queries['union_ids'] + ';')
        id_lines = id_output.splitlines()
        boundary = id_lines.index('__MISP_UNION_IDS__')
        ids = [id_lines[:boundary], id_lines[boundary + 1:]]
        if ids[0] != ids[1]:
            raise AssertionError('Different ordered row IDs: ' + case['name'])
        case_result = dict(case, equal_ids=True,
                           matched_rows=len(ids[0]),
                           queries=queries, plans={}, times_ms={})
        times = {'or': [], 'union': []}
        schedule = []
        for repetition in range(args.repeats + 1):
            order = ['or', 'union'] if repetition % 2 else ['union', 'or']
            for name in order:
                schedule.append((repetition, name))
        # One client session avoids measuring container/client startup and keeps
        # session settings identical. MariaDB supplies server execution timings.
        raw = sql('SET SESSION query_cache_type=OFF;\n' + '\n'.join(
            'ANALYZE FORMAT=JSON ' + queries[name] + ';'
            for _, name in schedule))
        decoder = json.JSONDecoder()
        for repetition, name in schedule:
            raw = raw.lstrip()
            plan, end = decoder.raw_decode(raw)
            raw = raw[end:]
            case_result['plans'][name] = plan
            if repetition:  # Discard the first warmup for both shapes.
                times[name].append(plan['query_block']['r_total_time_ms'])
        if raw.strip():
            raise RuntimeError('Unexpected trailing database output')
        for name in times:
            case_result['times_ms'][name] = {
                'samples': times[name], 'median': statistics.median(times[name])}
        report['cases'].append(case_result)
        (args.output / 'results.json').write_text(json.dumps(report, indent=2))
        print(case['name'], case_result['matched_rows'],
              {k: round(v['median'], 3)
               for k, v in case_result['times_ms'].items()}, flush=True)


if __name__ == '__main__':
    main()
