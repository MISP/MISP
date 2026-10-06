#!/usr/bin/env python3
"""
Behaviour oracle: snapshot MISP API output, then prove later code returns
the same thing.

Usage:
    oracle.py list
    oracle.py record SUITE[,SUITE...] --label LABEL [--case GLOB]
    oracle.py compare SUITE[,SUITE...] --baseline LABEL
                      [--current LABEL] [--save LABEL] [--case GLOB]
    oracle.py timings SUITE[,SUITE...] --baseline LABEL [--current LABEL]
                      [--case GLOB]
    oracle.py restore [--yes] [--no-refill]
    oracle.py standby status|refill [--background] [--force]
    oracle.py selftest

Without --current, compare runs the cases live. The config (JSON: url,
users {name: api key}, store, optional verify_tls and timeout) comes from
--config or $VALUE_ORACLE_CONFIG; see config.example.json. Exit status is
non-zero when anything differs, is missing or fails. restore resets the
instance to the configured dump and needs the config's "restore" section;
with restore.standby_database set it swaps in the pre-loaded standby and
refills it in the background (--no-refill leaves that to "standby refill").
timings lists how long recorded cases took, which compare never looks at.
"""

import argparse
import fnmatch
import importlib
import os
import pkgutil
import sys
import unittest

sys.dont_write_bytecode = True
HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

import core  # noqa: E402
import restore  # noqa: E402
import suites  # noqa: E402


def config_path(args):
    path = args.config or os.environ.get('VALUE_ORACLE_CONFIG')
    if not path:
        raise core.OracleError(
            'no config: pass --config or set VALUE_ORACLE_CONFIG')
    return os.path.abspath(os.path.expanduser(path))


def load_config(args):
    return core.Config.load(config_path(args))


def suite_names():
    return sorted(m.name for m in pkgutil.iter_modules(suites.__path__))


def load_cases(name, config, pattern):
    if name not in suite_names():
        raise core.OracleError('unknown suite %r' % name)
    module = importlib.import_module('suites.' + name)
    cases = module.cases(config)
    names = [c.name for c in cases]
    if len(names) != len(set(names)):
        raise core.OracleError('duplicate case names in suite %s' % name)
    return core.select(cases, pattern)


def teardown(name, config):
    """Runs the suite's optional teardown(config), which undoes what its
    cases changed on the instance."""
    hook = getattr(importlib.import_module('suites.' + name), 'teardown',
                   None)
    if hook is not None:
        hook(config)


def cmd_list(args):
    config = load_config(args)
    for name in suite_names():
        cases = load_cases(name, config, '*')
        print('%s (%d cases)' % (name, len(cases)))
        for c in cases:
            print('  %-40s %s' % (c.name, c.description))
    return 0


def cmd_record(args):
    config = load_config(args)
    client = core.Client(config)
    store = core.Store(config.store, args.label)
    failed = 0
    for name in args.suites.split(','):
        try:
            for case in load_cases(name, config, args.case):
                result = case.execute(client)
                store.save(name, result)
                flag = 'ok' if 200 <= result['status'] < 300 else 'HTTP'
                if flag != 'ok':
                    failed += 1
                print('%-4s %s/%s (%s, %d ms)' % (
                    flag, name, case.name, result['status'],
                    result['meta']['elapsed_ms']))
        finally:
            teardown(name, config)
    print('recorded into %s%s' % (
        store.dir, '; %d non-2xx' % failed if failed else ''))
    return 0


def cmd_compare(args):
    config = load_config(args)
    baseline = core.Store(config.store, args.baseline)
    current_store = (core.Store(config.store, args.current)
                     if args.current else None)
    save = core.Store(config.store, args.save) if args.save else None
    client = core.Client(config) if current_store is None else None
    totals = {'PASS': 0, 'DIFF': 0, 'NEW': 0, 'GONE': 0}
    for name in args.suites.split(','):
        try:
            compare_suite(name, config, args, baseline, current_store, client,
                          save, totals)
        finally:
            if current_store is None:
                teardown(name, config)
    print(' '.join('%s=%d' % kv for kv in totals.items()))
    return 0 if totals['DIFF'] + totals['NEW'] + totals['GONE'] == 0 else 1


def compare_suite(name, config, args, baseline, current_store, client, save,
                  totals):
    cases = load_cases(name, config, args.case)
    seen = set()
    for case in cases:
        seen.add(case.name)
        base = baseline.load(name, case.name)
        if current_store is not None:
            current = current_store.load(name, case.name)
            if current is None:
                totals['GONE'] += 1
                print('GONE %s/%s (not in %s)' % (
                    name, case.name, args.current))
                continue
        else:
            current = case.execute(client)
            if save is not None:
                save.save(name, current)
        if base is None:
            totals['NEW'] += 1
            print('NEW  %s/%s (no baseline)' % (name, case.name))
            continue
        lines = core.compare_results(base, current)
        if lines:
            totals['DIFF'] += 1
            print('DIFF %s/%s' % (name, case.name))
            for line in lines:
                print('     ' + line)
        else:
            totals['PASS'] += 1
            print('PASS %s/%s' % (name, case.name))
    if args.case == '*':
        for orphan in sorted(set(baseline.case_names(name)) - seen):
            totals['GONE'] += 1
            print('GONE %s/%s (in baseline, no longer defined)' % (
                name, orphan))


def cmd_timings(args):
    """Elapsed time per recorded case, plus the SQL time of the value
    statements where the suite measured it (plans), side by side for two
    labels."""
    config = load_config(args)
    labels = [args.baseline] + ([args.current] if args.current else [])
    stores = [core.Store(config.store, label) for label in labels]
    print('%-52s %s%s' % ('case', ''.join('%16s' % l for l in labels),
                          '   ratio' if args.current else ''))
    for name in args.suites.split(','):
        names = set()
        for store in stores:
            names.update(store.case_names(name))
        for case in sorted(n for n in names
                           if fnmatch.fnmatch(n, args.case)):
            metas = [store.load_meta(name, case) for store in stores]
            cells = [timing_cell(meta) for meta in metas]
            line = '%-52s %s' % ('%s/%s' % (name, case),
                                 ''.join('%16s' % c for c in cells))
            elapsed = [(m or {}).get('elapsed_ms') for m in metas]
            if args.current and elapsed[0] and elapsed[1] is not None:
                line += '%8.2f' % (elapsed[1] / elapsed[0])
            print(line)
    return 0


def timing_cell(meta):
    if meta is None:
        return '-'
    cell = '%d' % meta.get('elapsed_ms', 0)
    sql = meta.get('timings', {}).get('value_sql_ms')
    if sql is not None:
        cell += ' (%d)' % sql
    return cell


def cmd_restore(args):
    config = load_config(args)
    restorer = restore.Restorer(config.restore,
                                config_path=config_path(args))
    target = config.restore['database']
    if not args.yes:
        answer = input('Overwrite database %s and its Redis state? [y/N] '
                       % target)
        if answer.strip().lower() != 'y':
            print('aborted')
            return 1
    restorer.run(refill=not args.no_refill)
    return 0


def cmd_standby(args):
    config = load_config(args)
    standby = restore.Restorer(config.restore).standby
    if standby is None:
        raise core.OracleError('config has no restore.standby_database')
    if args.action == 'status':
        ready, reason = standby.status()
        print('%s: %s%s' % (standby.db, reason,
                            '; a load is running' if standby.busy() else ''))
        return 0 if ready else 1
    if args.background:
        print(standby.spawn_refill(config_path(args)))
    else:
        print(standby.refill(force=args.force))
    return 0


def cmd_selftest(args):
    tests = unittest.defaultTestLoader.discover(HERE, pattern='test_*.py')
    result = unittest.TextTestRunner(verbosity=1).run(tests)
    return 0 if result.wasSuccessful() else 1


def main(argv=None):
    parser = argparse.ArgumentParser(
        description='MISP behaviour oracle (record / compare snapshots)')
    parser.add_argument('--config', help='path to the oracle config JSON')
    sub = parser.add_subparsers(dest='command', required=True)

    sub.add_parser('list').set_defaults(func=cmd_list)

    p = sub.add_parser('record')
    p.add_argument('suites')
    p.add_argument('--label', required=True)
    p.add_argument('--case', default='*')
    p.set_defaults(func=cmd_record)

    p = sub.add_parser('compare')
    p.add_argument('suites')
    p.add_argument('--baseline', required=True)
    p.add_argument('--current')
    p.add_argument('--save')
    p.add_argument('--case', default='*')
    p.set_defaults(func=cmd_compare)

    p = sub.add_parser('timings')
    p.add_argument('suites')
    p.add_argument('--baseline', required=True)
    p.add_argument('--current')
    p.add_argument('--case', default='*')
    p.set_defaults(func=cmd_timings)

    p = sub.add_parser('restore')
    p.add_argument('--yes', action='store_true')
    p.add_argument('--no-refill', action='store_true')
    p.set_defaults(func=cmd_restore)

    p = sub.add_parser('standby')
    p.add_argument('action', choices=('status', 'refill'))
    p.add_argument('--background', action='store_true')
    p.add_argument('--force', action='store_true')
    p.set_defaults(func=cmd_standby)

    sub.add_parser('selftest').set_defaults(func=cmd_selftest)

    args = parser.parse_args(argv)
    try:
        return args.func(args)
    except core.OracleError as e:
        print('error: %s' % e, file=sys.stderr)
        return 2


if __name__ == '__main__':
    sys.exit(main())
