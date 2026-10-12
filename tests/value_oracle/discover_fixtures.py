#!/usr/bin/env python3
"""
Pick representative attribute values from the frozen test database.

The values exercise the value-matching edge cases (case variants, values
present in both value slots, long values sharing a 64-character prefix,
proposals, deleted rows, ...). Run once against the baseline schema; suites
read the result through the config's "fixtures" path, so every later
comparison uses exactly the same inputs. A re-run only adds picks missing
from an existing file; --refresh recomputes all of them.

Usage:
    discover_fixtures.py [--config PATH] [--out PATH] [--refresh]
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
# What a saved attribute correlates with on 2.x (MispAttribute constants).
NON_CORRELATING = ("'comment', 'http-method', 'aba-rtn', 'gender', "
                   "'counter', 'integer', 'float', 'port', 'nationality', "
                   "'cortex', 'boolean', 'anonymised'")
CORRELATING = f"""a.deleted = 0 AND a.disable_correlation = 0
          AND e.disable_correlation = 0
          AND a.type NOT IN ({NON_CORRELATING})"""
SINGLE = 'COUNT(DISTINCT BINARY a.value1) = 1'
# Correlation fixture: a domain stored three to eight times, once in an
# org-only event of another org than the lesser user's.
RESTRICTED_TARGET = f"""
        SELECT MIN(BINARY a.value1) FROM attributes a
        JOIN events e ON e.id = a.event_id
        WHERE a.type = 'domain' AND {CORRELATING}
        GROUP BY a.value1
        HAVING COUNT(*) BETWEEN 3 AND 8 AND COUNT(DISTINCT a.event_id) >= 3
           AND {SINGLE}
           AND SUM(e.distribution = 0 AND e.org_id <> LESSER_ORG
                   AND e.orgc_id <> LESSER_ORG) = 1
           AND SUM(e.distribution = 3 AND a.distribution IN (3, 5)) >= 2
        ORDER BY COUNT(*) DESC, 1 LIMIT 1"""


def correlation_fixture_queries():
    """Stored values a scratch attribute matches, or deliberately misses,
    when it is saved (suites/correlation_fixture.py). Counts stay well under
    MISP.correlation_limit unless over-correlation is the point."""
    def grouped(where, having, order='COUNT(*) DESC, 1', offset=0):
        return f"""
        SELECT MIN(BINARY a.value1) FROM attributes a
        JOIN events e ON e.id = a.event_id
        WHERE {where}
        GROUP BY a.value1 HAVING {having}
        ORDER BY {order} LIMIT 1{' OFFSET %d' % offset if offset else ''}"""

    domain = f"a.type = 'domain' AND {CORRELATING}"
    small = (f'COUNT(*) BETWEEN 3 AND 5 AND COUNT(DISTINCT a.event_id) >= 3 '
             f'AND MIN(e.distribution) = 3 AND {SINGLE}')
    filename = (f"a.type = 'filename' AND {CORRELATING} "
                "AND a.value1 REGEXP '^[a-z0-9_]+[.](exe|dll)$'")
    exclusion_hits = """(
            SELECT COUNT(*) FROM attributes a
            WHERE a.value1 = CONVERT(x.value USING utf8mb3)
                  COLLATE utf8mb3_unicode_ci
              AND a.deleted = 0 AND a.disable_correlation = 0)"""
    return {
        'cf_exact': grouped(domain, small),
        'cf_disabled_source': grouped(domain, small, offset=1),
        'cf_case': grouped(
            f"a.type IN ('filename', 'text') AND {CORRELATING}",
            'COUNT(DISTINCT BINARY a.value1) > 1 '
            'AND COUNT(DISTINCT CAST(LOWER(a.value1) AS BINARY)) = 1 '
            'AND COUNT(*) BETWEEN 3 AND 10 '
            'AND COUNT(DISTINCT a.event_id) >= 3'),
        'cf_accent': grouped(
            f"a.type IN ('email-subject', 'text', 'filename') "
            f"AND {CORRELATING} AND LENGTH(a.value1) < 60 "
            "AND HEX(a.value1) REGEXP '^(..)*C3[AB][0-9A-F]'",
            f'COUNT(*) BETWEEN 2 AND 6 AND COUNT(DISTINCT a.event_id) >= 2 '
            f'AND {SINGLE}'),
        # The spelling with a no-break space, of a value also stored with a
        # plain one.
        'cf_nbsp': f"""
        SELECT MAX(IF(INSTR(CAST(a.value1 AS BINARY), X'C2A0') > 0,
                      CAST(a.value1 AS BINARY), NULL))
        FROM attributes a JOIN events e ON e.id = a.event_id
        WHERE {CORRELATING} AND LENGTH(a.value1) < 40
        GROUP BY a.value1
        HAVING SUM(INSTR(CAST(a.value1 AS BINARY), X'C2A0') > 0) > 0
           AND SUM(INSTR(CAST(a.value1 AS BINARY), X'C2A0') = 0) > 0
           AND COUNT(*) BETWEEN 2 AND 6
        ORDER BY COUNT(*) DESC, 1 LIMIT 1""",
        # One of several distinct values sharing their first 128 characters.
        'cf_long_prefix': f"""
        SELECT MIN(BINARY a.value1) FROM attributes a
        JOIN events e ON e.id = a.event_id
        WHERE {CORRELATING} AND LENGTH(a.value1) BETWEEN 129 AND 191
        GROUP BY LEFT(a.value1, 128)
        HAVING COUNT(DISTINCT BINARY a.value1) BETWEEN 3 AND 8
           AND COUNT(*) <= 12
        ORDER BY COUNT(*) DESC, 1 LIMIT 1""",
        # Longer than the 191 characters correlation_values keeps.
        'cf_long_191': grouped(
            f"a.type = 'text' AND {CORRELATING} "
            'AND CHAR_LENGTH(a.value1) BETWEEN 200 AND 400',
            f'COUNT(*) BETWEEN 2 AND 5 AND COUNT(DISTINCT a.event_id) >= 2 '
            f'AND {SINGLE}'),
        # 2.x stores a 4-byte character as '?': a stored value holding one.
        'cf_four_byte': grouped(
            f"a.type = 'url' AND {CORRELATING} AND LENGTH(a.value1) < 80 "
            "AND a.value1 LIKE '%?%'",
            f'COUNT(*) BETWEEN 2 AND 6 AND COUNT(DISTINCT a.event_id) >= 2 '
            f'AND {SINGLE}'),
        'cf_cidr_v4': """
        SELECT CONCAT(SUBSTRING_INDEX(a.value1, '.', 3), '.0/24')
        FROM attributes a
        WHERE a.type IN ('ip-src', 'ip-dst', 'ip-src|port', 'ip-dst|port')
          AND a.deleted = 0 AND a.disable_correlation = 0
          AND a.value1 REGEXP '^[0-9]+[.][0-9]+[.][0-9]+[.][0-9]+$'
        GROUP BY SUBSTRING_INDEX(a.value1, '.', 3)
        HAVING COUNT(DISTINCT a.value1) BETWEEN 2 AND 3
           AND COUNT(*) BETWEEN 3 AND 6 AND COUNT(DISTINCT a.event_id) >= 2
        ORDER BY COUNT(*) DESC, 1 LIMIT 1""",
        'cf_cidr_v6': """
        SELECT CONCAT(INET6_NTOA(CONCAT(LEFT(INET6_ATON(a.value1), 8),
                                        UNHEX('0000000000000000'))), '/64')
        FROM attributes a
        WHERE a.type IN ('ip-src', 'ip-dst') AND a.deleted = 0
          AND a.disable_correlation = 0 AND a.value1 LIKE '%:%'
          AND a.value1 NOT LIKE '%/%' AND INET6_ATON(a.value1) IS NOT NULL
        GROUP BY LEFT(INET6_ATON(a.value1), 8)
        HAVING COUNT(DISTINCT a.value1) BETWEEN 2 AND 4
           AND COUNT(DISTINCT a.event_id) >= 2 AND COUNT(*) <= 6
        ORDER BY COUNT(*) DESC, 1 LIMIT 1""",
        'cf_excluded': f"""
        SELECT x.value FROM correlation_exclusions x
        WHERE x.value NOT LIKE '%\\%%'
          AND {exclusion_hits} BETWEEN 2 AND 15
        ORDER BY x.value LIMIT 1""",
        'cf_excluded_case': f"""
        SELECT x.value FROM correlation_exclusions x
        WHERE x.value NOT LIKE '%\\%%' AND x.value REGEXP '[a-zA-Z]'
          AND {exclusion_hits} BETWEEN 2 AND 15
        ORDER BY x.value LIMIT 1""",
        'cf_excluded_wildcard': """
        SELECT a.value1 FROM correlation_exclusions x
        JOIN attributes a ON a.value1 LIKE CONVERT(x.value USING utf8mb3)
                                         COLLATE utf8mb3_unicode_ci
        WHERE x.value LIKE '%\\%' AND x.value NOT LIKE '\\%%'
          AND a.deleted = 0 AND a.disable_correlation = 0
        GROUP BY a.value1 HAVING COUNT(*) BETWEEN 2 AND 15
        ORDER BY COUNT(*) DESC, 1 LIMIT 1""",
        # Stored with correlation disabled in one event, enabled in others.
        'cf_disabled_target': grouped(
            "a.type IN ('filename', 'text') AND a.deleted = 0 "
            "AND e.disable_correlation = 0",
            'SUM(a.disable_correlation = 0) BETWEEN 2 AND 5 '
            'AND SUM(a.disable_correlation = 1) BETWEEN 1 AND 3 '
            'AND COUNT(DISTINCT IF(a.disable_correlation = 0, a.event_id, '
            'NULL)) >= 2 AND COUNT(DISTINCT a.event_id) > COUNT(DISTINCT '
            f'IF(a.disable_correlation = 0, a.event_id, NULL)) AND {SINGLE}'),
        'cf_over_blocked': grouped(
            domain,
            'COUNT(*) BETWEEN 25 AND 100 '
            'AND MIN(a.value1) IN (SELECT value FROM over_correlating_values)',
            order='COUNT(*), 1'),
        'cf_over_new': grouped(
            f"a.type IN ('url', 'filename', 'text') AND {CORRELATING}",
            'COUNT(*) BETWEEN 25 AND 80 AND COUNT(DISTINCT a.event_id) >= 5 '
            f'AND {SINGLE} AND MIN(a.value1) NOT IN '
            '(SELECT value FROM over_correlating_values) '
            'AND MIN(a.value1) NOT IN '
            '(SELECT value FROM correlation_exclusions)',
            order='COUNT(*), 1'),
        # A port-sized number stored as a correlating value1.
        'cf_primary_number': grouped(
            f"{CORRELATING} AND a.value1 REGEXP '^[1-9][0-9]{{3}}$'",
            'COUNT(*) BETWEEN 2 AND 5 AND COUNT(DISTINCT a.event_id) >= 2'),
        'cf_trailing': grouped(
            filename, f'COUNT(*) BETWEEN 3 AND 5 '
            f'AND COUNT(DISTINCT a.event_id) >= 3 AND {SINGLE}'),
        'cf_trailing_alt': grouped(
            filename, f'COUNT(*) BETWEEN 3 AND 5 '
            f'AND COUNT(DISTINCT a.event_id) >= 3 AND {SINGLE}', offset=1),
    }


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
    # Export sample: one event per shape, see suites/exports.py.
    'export_small': f"""
        SELECT a.event_id FROM attributes a JOIN events e ON e.id = a.event_id
        WHERE a.{LIVE} AND e.published = 1 AND e.distribution = 3
          AND e.attribute_count BETWEEN 15 AND 60
        GROUP BY a.event_id
        HAVING SUM(a.type LIKE '%|%') > 2 AND SUM(a.object_id > 0) > 3
           AND SUM(a.to_ids) > 5
        ORDER BY COUNT(DISTINCT a.type) DESC, a.event_id LIMIT 1""",
    'export_composite': f"""
        SELECT a.event_id FROM attributes a JOIN events e ON e.id = a.event_id
        WHERE a.{LIVE} AND e.published = 1 AND e.distribution = 3
          AND e.attribute_count BETWEEN 300 AND 3000
        GROUP BY a.event_id HAVING SUM(a.type LIKE '%|%') > 0.8 * COUNT(*)
        ORDER BY COUNT(DISTINCT IF(a.type LIKE '%|%', a.type, NULL)) DESC,
                 MIN(e.attribute_count), a.event_id LIMIT 1""",
    'export_objects': """
        SELECT o.event_id FROM objects o JOIN events e ON e.id = o.event_id
        WHERE o.deleted = 0 AND e.published = 1 AND e.distribution = 3
          AND e.attribute_count <= 6000
        GROUP BY o.event_id HAVING COUNT(DISTINCT o.name) > 1
        ORDER BY COUNT(*) DESC, o.event_id LIMIT 1""",
    'export_object_acl': """
        SELECT o.event_id FROM objects o JOIN events e ON e.id = o.event_id
        WHERE o.deleted = 0 AND o.distribution = 0 AND e.distribution > 0
          AND e.published = 1
        GROUP BY o.event_id ORDER BY MIN(e.attribute_count), o.event_id
        LIMIT 1""",
    'export_object_distribution': """
        SELECT event_id FROM objects WHERE deleted = 0
        GROUP BY event_id HAVING MAX(distribution) < 5
        ORDER BY COUNT(*) DESC, event_id LIMIT 1""",
    'export_proposals': """
        SELECT s.event_id FROM shadow_attributes s
        JOIN events e ON e.id = s.event_id
        WHERE s.deleted = 0 AND e.attribute_count <= 1000
        GROUP BY s.event_id
        HAVING SUM(s.old_id = 0) > 0 AND SUM(s.old_id > 0) > 0
        ORDER BY COUNT(*) DESC, s.event_id LIMIT 1""",
    'export_proposal_delete': """
        SELECT s.event_id FROM shadow_attributes s
        JOIN events e ON e.id = s.event_id
        WHERE s.deleted = 0 AND s.proposal_to_delete = 1
        GROUP BY s.event_id ORDER BY MIN(e.attribute_count), s.event_id
        LIMIT 1""",
    'export_largest': """
        SELECT id FROM events ORDER BY attribute_count DESC, id LIMIT 1""",
    # REST sample: one attribute, object or event per shape (suites/rest.py).
    'rest_attribute_composite': """
        SELECT MIN(id) FROM attributes
        WHERE type = 'ip-dst|port' AND deleted = 0 AND object_id = 0""",
    'rest_attribute_object': """
        SELECT MIN(a.id) FROM attributes a JOIN objects o ON o.id = a.object_id
        WHERE a.deleted = 0 AND o.deleted = 0""",
    'rest_attribute_malware': """
        SELECT MIN(id) FROM attributes
        WHERE type = 'malware-sample' AND deleted = 0 AND object_id > 0""",
    'rest_attribute_proposed': """
        SELECT MIN(s.old_id) FROM shadow_attributes s
        JOIN attributes a ON a.id = s.old_id
        WHERE s.deleted = 0 AND a.deleted = 0 AND s.proposal_to_delete = 0""",
    'rest_attribute_deleted': """
        SELECT MIN(a.id) FROM attributes a JOIN events e ON e.id = a.event_id
        WHERE a.deleted = 1 AND e.distribution = 3""",
    'rest_attribute_org_only': """
        SELECT MIN(id) FROM attributes WHERE deleted = 0 AND event_id = (
            SELECT id FROM events WHERE distribution = 0
            ORDER BY attribute_count DESC, id LIMIT 1)""",
    'rest_object_malware': """
        SELECT MIN(object_id) FROM attributes
        WHERE type = 'malware-sample' AND deleted = 0 AND object_id > 0""",
    'rest_object_org_only': """
        SELECT MIN(o.id) FROM objects o JOIN events e ON e.id = o.event_id
        WHERE o.deleted = 0 AND o.distribution = 0 AND e.distribution > 0
          AND e.published = 1""",
    'rest_attachment_event': """
        SELECT event_id FROM attributes
        WHERE type IN ('attachment', 'malware-sample') AND deleted = 0
        GROUP BY event_id ORDER BY COUNT(*) DESC, event_id LIMIT 1""",
    'rest_proposal': """
        SELECT MIN(id) FROM shadow_attributes
        WHERE deleted = 0 AND old_id > 0""",
    'payload_attribute_tagged': """
        SELECT MIN(a.id) FROM attributes a
        JOIN attribute_tags t ON t.attribute_id = a.id
        JOIN sightings s ON s.attribute_id = a.id
        WHERE a.deleted = 0""",
    # Correlation sample (suites/correlations.py); run after a full
    # recorrelation, which the dump's correlation tables predate.
    'correlation_event_dense': """
        SELECT x.eid FROM (
            SELECT event_id AS eid FROM default_correlations
            UNION ALL SELECT 1_event_id FROM default_correlations) x
        JOIN events e ON e.id = x.eid WHERE e.attribute_count <= 2000
        GROUP BY x.eid ORDER BY COUNT(*) DESC, x.eid LIMIT 1""",
    'correlation_event_cidr': """
        SELECT MIN(a.event_id) FROM attributes a
        WHERE a.deleted = 0 AND a.type IN ('ip-src', 'ip-dst')
          AND a.value1 LIKE '%/%' AND a.id IN (
            SELECT attribute_id FROM default_correlations
            UNION SELECT 1_attribute_id FROM default_correlations)""",
    'correlation_event_restricted': """
        SELECT MIN(x.eid) FROM (
            SELECT event_id AS eid, 1_event_id AS other
            FROM default_correlations
            UNION ALL SELECT 1_event_id, event_id FROM default_correlations) x
        JOIN events e ON e.id = x.eid JOIN events o ON o.id = x.other
        WHERE e.distribution = 3 AND o.distribution = 0
          AND e.orgc_id <> o.orgc_id AND e.attribute_count <= 2000""",
    # Plans sample (suites/plans.py): an event of the size class of the
    # exploration's correlation probe (EXP section 4, shape E), and an IPv4
    # address inside a stored CIDR block.
    'plan_correlation_event': """
        SELECT event_id FROM attributes GROUP BY event_id
        HAVING COUNT(*) BETWEEN 20000 AND 30000
        ORDER BY COUNT(*) DESC, event_id LIMIT 1""",
    'plan_ip_in_cidr': """
        SELECT INET_NTOA(INET_ATON(SUBSTRING_INDEX(value1, '/', 1)) + 1)
        FROM attributes
        WHERE type IN ('ip-src', 'ip-dst') AND deleted = 0
          AND disable_correlation = 0 AND value1 LIKE '%.%/%'
          AND CAST(SUBSTRING_INDEX(value1, '/', -1) AS UNSIGNED)
              BETWEEN 8 AND 30
        ORDER BY id LIMIT 1""",
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


def lesser_org(config):
    if 'lesser' not in config.users:
        return None
    response = core.Client(config).request('GET', '/users/view/me',
                                           user='lesser')
    if response.status != 200:
        return None
    return int(response.json()['User']['org_id'])


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
    parser.add_argument('--refresh', action='store_true',
                        help='recompute picks already in the output file')
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
    if os.path.exists(out) and not args.refresh:
        with open(out) as f:
            found = json.load(f)
    queries = dict(QUERIES, **correlation_fixture_queries())
    if 'cf_restricted' not in found:
        org = lesser_org(config)
        if org is not None:
            queries['cf_restricted'] = RESTRICTED_TARGET.replace(
                'LESSER_ORG', str(org))
    for name, sql in queries.items():
        if name in found:
            continue
        found[name] = first_value(db, sql)
        print('%-26s %s' % (name, (found[name] or '-')[:70].replace(
            '\n', ' ')))
    if 'event_sample' not in found:
        sample = first_value(db, EVENT_SAMPLE)
        found['event_sample'] = sample.split(',') if sample else None
    if found.get('ip_common') and 'ip_event' not in found:
        found['ip_event'] = first_value(
            db, "SELECT MIN(event_id) FROM attributes WHERE value1 = '%s'"
            % found['ip_common'].replace("'", "''"))
    derive(found)
    with open(out, 'w') as f:
        json.dump(found, f, indent=1, sort_keys=True, ensure_ascii=False)
    print('written to %s' % out)


if __name__ == '__main__':
    main()
