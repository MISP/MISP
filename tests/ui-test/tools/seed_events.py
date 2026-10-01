#!/usr/bin/env python3
"""Reset the local MISP instance and seed the events used by the tricky UI tests.

Usage:
    MISP_KEY=<your API key> python3 tests/ui-test/tools/seed_events.py           # dry run: shows what would be deleted
    MISP_KEY=<your API key> python3 tests/ui-test/tools/seed_events.py --yes     # delete ALL events, then seed
    MISP_KEY=<your API key> python3 tests/ui-test/tools/seed_events.py --reports-only  # only (re)attach the test reports

Each seeded event also gets an Event Report "Test – <test name>" with the GitHub link to the test,
its description, steps, expected result and seeded data.

Every seeded event gets a custom tag `qa:<test-slug>` matching the test in
tests/ui-test/event/..., so it is easy to find the event for a test.
"""
import glob
import json
import os
import re
import ssl
import sys
import urllib.error
import urllib.request

URL = os.environ.get('MISP_URL', 'https://localhost:8443').rstrip('/')
KEY = os.environ.get('MISP_KEY')
GITHUB = os.environ.get('GITHUB_TESTS_URL', 'https://github.com/MISP/MISP/blob/ui_test/tests/ui-test').rstrip('/')
TESTS_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), '..')
CTX = ssl._create_unverified_context()  # local instance, self-signed certificate


def call(method, path, body=None):
    req = urllib.request.Request(
        URL + path,
        data=None if body is None else json.dumps(body).encode(),
        method=method,
        headers={'Authorization': KEY, 'Accept': 'application/json', 'Content-Type': 'application/json'},
    )
    try:
        with urllib.request.urlopen(req, context=CTX) as r:
            return r.status, json.loads(r.read() or b'null')
    except urllib.error.HTTPError as e:
        raw = e.read()
        try:
            return e.code, json.loads(raw)
        except ValueError:
            return e.code, raw.decode(errors='replace')[:300]


def ensure_tag(name, colour='#7c3aed'):
    status, added = call('POST', '/tags/add', {'Tag': {'name': name, 'colour': colour, 'exportable': True}})
    if status == 200 and isinstance(added, dict) and 'Tag' in added:
        return added['Tag']['id']
    # Already exists: the GET /tags/search/<name> form does not match names with ':', the POST one does
    _, found = call('POST', '/tags/search', {'tag': name})
    for t in found if isinstance(found, list) else []:
        tag = t.get('Tag', t)
        if tag.get('name') == name:
            return tag['id']
    raise SystemExit(f'Could not create or find tag {name!r}')


results = []


def add_event(info, tags=(), date='2026-10-01', extends=None, publish=False, test=''):
    event = {'info': info, 'date': date, 'distribution': 0, 'threat_level_id': 4, 'analysis': 0}
    if extends:
        event['extends_uuid'] = extends
    status, res = call('POST', '/events/add', {'Event': event})
    if status != 200 or not isinstance(res, dict) or 'Event' not in res:
        results.append((test, info, f'REFUSED (HTTP {status}): {json.dumps(res)[:200]}'))
        return None
    ev = res['Event']
    for tag in tags:
        ensure_tag(tag, '#2e7d32' if tag == 'tlp:green' else '#7c3aed')
        call('POST', '/tags/attachTagToObject', {'uuid': ev['uuid'], 'tag': tag})
    if publish:
        call('POST', f"/events/publish/{ev['id']}")
    results.append((test, info, f"created id={ev['id']} date={ev['date']} extends={ev.get('extends_uuid') or '-'}"))
    return ev


def seed_review_cases():
    """Events added during the event test review (edit, pagination, performance)."""
    # edit/edit.md
    add_event('QA edit published', ['qa:event-edit-published'], publish=True, test='event-edit-published')
    add_event('QA edit empty info', ['qa:event-edit-empty-info'], test='event-edit-empty-info')
    # index/filters.md: 70 events, more than one page (60 per page)
    for i in range(1, 71):
        add_event(f'QA page filter {i:02d}', ['qa:event-index-filter-pagination'], test='event-index-filter-pagination')
    # view/performance.md: one event with 2,000 attributes
    big = add_event('QA big event', ['qa:event-view-big-event'], test='event-view-big-event')
    if big:
        values = ['198.51.100.250'] + [f'10.{i // 250}.{i % 250}.1' for i in range(1999)]
        attrs = [{'type': 'ip-dst', 'category': 'Network activity', 'value': v, 'to_ids': False} for v in values]
        status, res = call('POST', f"/attributes/add/{big['id']}", attrs)
        count = len(res.get('Attribute', [])) if isinstance(res, dict) else 0
        results.append(('event-view-big-event', 'QA big event attributes',
                        f'{count} attribute(s) added (HTTP {status})'))


def load_tests():
    """Map each test slug to (relative file path, test name, section markdown)."""
    tests = {}
    for path in sorted(glob.glob(os.path.join(TESTS_DIR, '*', '**', '*.md'), recursive=True)):
        rel = os.path.relpath(path, TESTS_DIR)
        text = open(path, encoding='utf-8').read()
        if '\n# E2E Tests\n' not in text:
            continue
        for sec in re.split(r'(?=^### )', text.split('\n# E2E Tests\n', 1)[1], flags=re.M):
            m = re.match(r'### (.+)\n<a id="([^"]+)"></a>\n', sec)
            if m:
                tests[m.group(2)] = (rel, m.group(1), sec[m.end():].strip())
    return tests


def attach_reports():
    """Add to every qa:<slug> event an Event Report with the test name, its GitHub link and its content."""
    tests = load_tests()
    added = 0
    for slug, (rel, name, body) in tests.items():
        status, res = call('POST', '/events/restSearch',
                           {'tags': [f'qa:{slug}'], 'metadata': True, 'returnFormat': 'json'})
        events = res.get('response', []) if isinstance(res, dict) else []
        if not events:
            continue
        url = f'{GITHUB}/{rel}#{slug}'
        content = f'# {name}\n\n**Test:** [{rel}#{slug}]({url})\n\n{body}\n'
        for e in events:
            eid = e['Event']['id']
            _, existing = call('GET', f'/eventReports/index/event_id:{eid}')
            names = [r.get('EventReport', r).get('name') for r in existing] if isinstance(existing, list) else []
            if f'Test – {name}' in names:
                continue
            status, _ = call('POST', f'/eventReports/add/{eid}',
                             {'EventReport': {'name': f'Test – {name}', 'distribution': 5, 'content': content}})
            added += status == 200
    print(f'Added {added} test report(s).')


def main():
    if not KEY:
        raise SystemExit('Set MISP_KEY to your API key (Global Actions > My Profile > Auth keys).')
    status, events = call('GET', '/events/index')
    if status != 200:
        raise SystemExit(f'Cannot list events (HTTP {status}): {events}')
    print(f'{len(events)} event(s) on {URL}:')
    for e in events:
        print(f"  - #{e['id']} {e['info'][:70]!r}")
    if '--reports-only' in sys.argv:
        attach_reports()
        return
    if '--yes' not in sys.argv:
        print('\nDry run. Re-run with --yes to delete ALL these events and seed the QA events.')
        return

    for e in events:
        call('POST', f"/events/delete/{e['id']}")
    print(f'Deleted {len(events)} event(s).')

    # Tag attached to no event (index/filters: filter by tag)
    ensure_tag('qa:unused-tag', '#9e9e9e')

    # view/actions.md
    add_event('QA unpublish redirect', ['qa:event-publish-unpublish'], publish=True, test='event-publish-unpublish')
    add_event('QA view by UUID', ['qa:event-view-uuid'], test='event-view-uuid')
    a = add_event('QA cycle A', ['qa:event-extends-cycle'], test='event-extends-cycle')
    if a:
        b = add_event('QA cycle B', ['qa:event-extends-cycle'], extends=a['uuid'], test='event-extends-cycle')
        if b:
            status, res = call('POST', f"/events/edit/{a['id']}", {'Event': {'extends_uuid': b['uuid']}})
            ok = status == 200 and isinstance(res, dict) and res.get('Event', {}).get('extends_uuid') == b['uuid']
            results.append(('event-extends-cycle', 'QA cycle A -> extends QA cycle B',
                            'ACCEPTED (cycle exists)' if ok else f'REFUSED (HTTP {status}): {json.dumps(res)[:200]}'))
    parent = add_event('QA parent', ['qa:event-delete-extended'], test='event-delete-extended')
    if parent:
        add_event('QA child', ['qa:event-delete-extended'], extends=parent['uuid'], test='event-delete-extended')

    # index/filters.md
    add_event('QA unique search 7f3k', ['qa:event-index-search-single'], test='event-index-search-single')
    add_event('QA filter published green', ['qa:event-index-combined-filters', 'tlp:green'], publish=True, test='event-index-combined-filters')
    add_event('QA filter unpublished green', ['qa:event-index-combined-filters', 'tlp:green'], test='event-index-combined-filters')
    add_event('QA filter published no tlp', ['qa:event-index-combined-filters'], publish=True, test='event-index-combined-filters')

    # index/selection.md
    add_event('QA mass delete 1', ['qa:event-index-mass-delete'], test='event-index-mass-delete')
    add_event('QA mass delete 2', ['qa:event-index-mass-delete'], test='event-index-mass-delete')

    # edit/edit.md
    add_event('QA concurrent edit', ['qa:event-edit-concurrent'], test='event-edit-concurrent')
    add_event('QA edit deleted', ['qa:event-edit-deleted'], test='event-edit-deleted')
    add_event('QA edit logged out', ['qa:event-edit-logged-out'], test='event-edit-logged-out')

    # add/fields.md - created through the API to see how the server reacts
    add_event('QA extends unknown UUID', ['qa:event-add-extends-unknown-uuid'],
              extends='7c9e6679-7425-40de-944b-e07fc1f90ae7', test='event-add-extends-unknown-uuid')
    add_event('QA line 1\nQA line 2', ['qa:event-add-multiline-info'], test='event-add-multiline-info')
    add_event('QA date 1900', ['qa:event-add-extreme-dates'], date='1900-01-01', test='event-add-extreme-dates')
    add_event('QA date 9999', ['qa:event-add-extreme-dates'], date='9999-12-31', test='event-add-extreme-dates')

    seed_review_cases()
    attach_reports()

    print('\nResults:')
    for test, info, outcome in results:
        print(f'  [{test}] {info!r}: {outcome}')


if __name__ == '__main__':
    main()
