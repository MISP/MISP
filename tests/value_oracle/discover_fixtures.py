#!/usr/bin/env python3
"""
Pick representative attribute values from the frozen test database.

The values exercise the value-matching edge cases (case variants, values
present in both value slots, long values sharing a 64-character prefix,
proposals, deleted rows, ...). Run once against the baseline schema; suites
read the result through the config's "fixtures" path, so every later
comparison uses exactly the same inputs.

Usage:
    discover_fixtures.py [--config PATH] [--out PATH]
"""

import argparse
import json
import os
import re
import sys

sys.dont_write_bytecode = True
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import core  # noqa: E402
import restore  # noqa: E402

LIVE = 'deleted = 0'

QUERIES = {
    'ip_common': f"""
        SELECT value1 FROM attributes
        WHERE type = 'ip-dst' AND {LIVE} AND value1 <> '0.0.0.0'
        GROUP BY value1 HAVING SUM(object_id = 0) > 0
        ORDER BY COUNT(*) DESC, value1 LIMIT 1""",
    'ip_hub': f"""
        SELECT value1 FROM attributes WHERE type = 'ip-dst' AND {LIVE}
        GROUP BY value1 HAVING COUNT(*) > 1000
        ORDER BY COUNT(*) DESC, value1 LIMIT 1""",
    'domain_common': f"""
        SELECT value1 FROM attributes WHERE type = 'domain' AND {LIVE}
        GROUP BY value1 ORDER BY COUNT(*) DESC, value1 LIMIT 1""",
    'case_variant': f"""
        SELECT MIN(BINARY value1) FROM attributes
        WHERE type IN ('url', 'text', 'filename') AND {LIVE}
        GROUP BY value1 HAVING COUNT(DISTINCT BINARY value1) > 1
        ORDER BY COUNT(*) DESC, MIN(BINARY value1) LIMIT 1""",
    'accent_variant': f"""
        SELECT MIN(BINARY value1) FROM attributes WHERE {LIVE}
        GROUP BY value1
        HAVING COUNT(DISTINCT CAST(LOWER(value1) AS BINARY)) > 1
        ORDER BY COUNT(*) DESC, MIN(BINARY value1) LIMIT 1""",
    'cross_slot_hash': f"""
        SELECT MIN(value2) FROM attributes
        WHERE type = 'filename|sha256' AND {LIVE} AND value2 IN (
            SELECT value1 FROM attributes WHERE type = 'sha256')""",
    'port_value2': f"""
        SELECT value2 FROM attributes WHERE type = 'ip-dst|port' AND {LIVE}
        GROUP BY value2 HAVING COUNT(*) BETWEEN 5 AND 500
        ORDER BY COUNT(*) DESC, value2 LIMIT 1""",
    'composite_full': f"""
        SELECT CONCAT(value1, '|', value2) FROM attributes
        WHERE type = 'ip-dst|port' AND {LIVE} ORDER BY id LIMIT 1""",
    'url_common': f"""
        SELECT value1 FROM attributes
        WHERE type = 'url' AND {LIVE} AND LENGTH(value1) < 100
        GROUP BY value1 ORDER BY COUNT(*) DESC, value1 LIMIT 1""",
    'long_shared_prefix': f"""
        SELECT MIN(BINARY value1) FROM attributes
        WHERE {LIVE} AND LENGTH(value1) > 64
        GROUP BY LEFT(value1, 64)
        HAVING COUNT(DISTINCT BINARY value1) > 10
        ORDER BY COUNT(*) DESC, MIN(BINARY value1) LIMIT 1""",
    'long_text': f"""
        SELECT value1 FROM attributes
        WHERE type = 'text' AND {LIVE}
          AND LENGTH(value1) BETWEEN 300 AND 2000
        ORDER BY id LIMIT 1""",
    'object_only_ip': f"""
        SELECT value1 FROM attributes WHERE type = 'ip-dst' AND {LIVE}
        GROUP BY value1 HAVING SUM(object_id = 0) = 0
        ORDER BY COUNT(*) DESC, value1 LIMIT 1""",
    'deleted_only': """
        SELECT value1 FROM attributes WHERE type = 'ip-dst'
        GROUP BY value1 HAVING SUM(deleted = 0) = 0 AND COUNT(*) > 0
        ORDER BY COUNT(*) DESC, value1 LIMIT 1""",
    'percent_literal': f"""
        SELECT value1 FROM attributes
        WHERE type = 'url' AND {LIVE} AND value1 LIKE '%\\%%'
        ORDER BY id LIMIT 1""",
    'proposal_event': """
        SELECT s.event_id FROM shadow_attributes s
        JOIN events e ON e.id = s.event_id
        WHERE s.deleted = 0 AND s.old_id > 0
        GROUP BY s.event_id ORDER BY e.attribute_count, s.event_id
        LIMIT 1""",
    'proposal_value': """
        SELECT value1 FROM shadow_attributes
        WHERE deleted = 0 AND value1 <> '' ORDER BY id LIMIT 1""",
}


# Events holding the common values plus the lowest ids: a bounded set for
# event-scope negation and quick-filter cases, which time out unbounded.
EVENT_SAMPLE = f"""
    SELECT GROUP_CONCAT(id ORDER BY id) FROM (
        (SELECT DISTINCT a.event_id AS id FROM attributes a
         WHERE a.{LIVE} AND a.value1 IN (
             (SELECT value1 FROM attributes WHERE type = 'domain' AND {LIVE}
              GROUP BY value1 ORDER BY COUNT(*) DESC, value1 LIMIT 1),
             (SELECT value1 FROM attributes WHERE type = 'ip-dst' AND {LIVE}
              AND value1 <> '0.0.0.0' GROUP BY value1
              HAVING SUM(object_id = 0) > 0
              ORDER BY COUNT(*) DESC, value1 LIMIT 1))
         ORDER BY a.event_id LIMIT 25)
        UNION
        (SELECT id FROM events ORDER BY id LIMIT 25)) AS sample"""


def first_value(db, sql):
    # Hex keeps values with newlines or tabs intact through the mysql CLI.
    hexed = re.sub(r'^\s*SELECT\s+(.*?)\s+FROM',
                   r'SELECT HEX(CAST(\1 AS CHAR)) FROM', sql, count=1,
                   flags=re.S)
    rows = db.query(hexed).split()
    if not rows or rows[0] == 'NULL':
        return None
    return bytes.fromhex(rows[0]).decode('utf-8')


def derive(found):
    domain = found.get('domain_common')
    if domain:
        label = domain.split('.')[0]
        found['substring_term'] = '%' + label[1:] + '%'
        found['prefix_term'] = label[:4] + '%'
        found['suffix_term'] = '%.' + domain.rsplit('.', 1)[-1]
        found['domain_upper'] = domain.upper()
    if found.get('case_variant'):
        found['case_variant_upper'] = found['case_variant'].upper()
    return found


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.split('\n')[1])
    parser.add_argument('--config')
    parser.add_argument('--out')
    args = parser.parse_args(argv)
    path = args.config or os.environ.get('VALUE_ORACLE_CONFIG')
    if not path:
        raise SystemExit('no config: pass --config or set '
                         'VALUE_ORACLE_CONFIG')
    config = core.Config.load(os.path.expanduser(path))
    out = os.path.expanduser(args.out or config.fixtures or '')
    if not out:
        raise SystemExit('no output path: pass --out or set "fixtures"')
    db = restore.Restorer(config.restore)

    found = {}
    for name, sql in QUERIES.items():
        found[name] = first_value(db, sql)
        print('%-20s %s' % (name, (found[name] or '-')[:70].replace(
            '\n', ' ')))
    sample = first_value(db, EVENT_SAMPLE)
    found['event_sample'] = sample.split(',') if sample else None
    if found.get('ip_common'):
        found['ip_event'] = first_value(
            db, "SELECT MIN(event_id) FROM attributes WHERE value1 = '%s'"
            % found['ip_common'].replace("'", "''"))
    derive(found)
    with open(out, 'w') as f:
        json.dump(found, f, indent=1, sort_keys=True, ensure_ascii=False)
    print('written to %s' % out)


if __name__ == '__main__':
    main()
