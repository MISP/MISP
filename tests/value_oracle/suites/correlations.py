"""Correlations under each engine: the Default and NoAcl pair sets after a
full recorrelation, and what the API shows for sample events, OnDemand
included.

The first case of each engine switches the instance to it
(correlations/switchEngine). For Default and NoAcl it then recorrelates
everything through the CLI (Admin jobGenerateCorrelation, about 50 minutes
per engine on the dev box) and records the engine's table as unordered [low, high]
attribute-id pairs, plus the over-correlation index. The view cases record,
for sample events and for both users, the related events from events/view and
the related attributes that attributes/restSearch returns with
includeCorrelations. teardown() switches the instance back to the engine it
found.

The suite rewrites the correlation tables: run it after the other suites, and
restore before the next comparison run.
"""

import os
import subprocess

from core import Case, Client, OracleError
from restore import Restorer
from suites.restsearch import load_fixtures

USERS = ('admin', 'lesser')
# label, engine name, correlation table (None: computed when read)
ENGINES = (
    ('default', 'Default', 'default_correlations'),
    ('noacl', 'NoAcl', 'no_acl_correlations'),
    ('ondemand', 'OnDemand', None),
)
VIEW_EVENTS = (
    ('dense', 'correlation_event_dense'),
    ('cidr', 'correlation_event_cidr'),
    ('restricted', 'correlation_event_restricted'),
    ('ip', 'ip_event'),
    ('composite', 'export_composite'),
)
OVER_CORRELATION_LIMIT = 10000
# The engine the instance was on before the suite switched it.
STATE = {'original': None, 'current': None}


def current_engine(client):
    response = client.request(
        'GET', '/servers/getSetting/MISP.correlation_engine')
    if response.status != 200:
        raise OracleError('cannot read the correlation engine (HTTP %d)'
                          % response.status)
    return response.json().get('value') or 'Default'


def switch_engine(client, engine):
    if STATE['original'] is None:
        STATE['original'] = current_engine(client)
        STATE['current'] = STATE['original']
    if STATE['current'] == engine:
        return
    response = client.request(
        'POST', '/correlations/switchEngine/%s' % engine)
    if response.status != 200:
        raise OracleError('cannot switch to %s (HTTP %d): %s' % (
            engine, response.status, response.text()[:200]))
    STATE['current'] = engine


def recorrelate(app_dir):
    if not app_dir:
        raise OracleError('recorrelating needs restore.app_dir in the config')
    run = subprocess.run(
        [os.path.join(app_dir, 'Console', 'cake'), 'Admin',
         'jobGenerateCorrelation'],
        capture_output=True, text=True)
    if run.returncode != 0:
        raise OracleError('recorrelation failed (exit %d): %s' % (
            run.returncode, (run.stdout + run.stderr)[-500:]))


def pairs(db, table):
    rows = db.query(
        'SELECT LEAST(attribute_id, 1_attribute_id), '
        'GREATEST(attribute_id, 1_attribute_id) FROM %s '
        'ORDER BY 1, 2' % table)
    return [[int(a), int(b)] for a, b in
            (line.split('\t') for line in rows.splitlines() if line)]


def over_correlations(client):
    response = client.request(
        'GET', '/correlations/overCorrelations/limit:%d'
        % OVER_CORRELATION_LIMIT)
    rows = [r['OverCorrelatingValue'] for r in response.json()]
    return response.status, sorted(
        [r['value'], int(r['occurrence']), bool(r['over_correlation']),
         bool(r['excluded'])] for r in rows)


def engine_case(label, engine, table, config):
    def run(client):
        switch_engine(client, engine)
        recorrelate((config.restore or {}).get('app_dir'))
        found = pairs(Restorer(config.restore, log=lambda *a: None), table)
        status, over = over_correlations(client)
        return status, {'count': len(found), 'pairs': found,
                        'over_correlations': over}
    return Case('correlation.%s.recorrelated' % label, run=run,
                description='%s engine: full recorrelation' % engine)


def view_case(label, engine, name, event_id, user):
    def run(client):
        switch_engine(client, engine)
        view = client.request('GET', '/events/view/%s' % event_id,
                              user=user)
        search = client.request('POST', '/attributes/restSearch', {
            'eventid': event_id, 'includeCorrelations': 1,
            'returnFormat': 'json'}, user=user)
        value = {'view_status': view.status,
                 'search_status': search.status}
        if view.status == 200:
            value['related_events'] = sorted(
                int(r['Event']['id'])
                for r in view.json()['Event'].get('RelatedEvent', []))
        if search.status == 200:
            value['related_attributes'] = sorted(
                [int(a['id']), int(r['id'])]
                for a in search.json()['response']['Attribute']
                for r in a.get('RelatedAttribute') or [])
        return max(view.status, search.status), value
    return Case('correlation.%s.view.%s.%s' % (label, name, user), run=run,
                description='%s engine: correlations of event %s'
                % (engine, event_id))


def cases(config):
    fx = load_fixtures(config)
    out = []
    for label, engine, table in ENGINES:
        if table is not None:
            out.append(engine_case(label, engine, table, config))
        for name, key in VIEW_EVENTS:
            if fx.get(key):
                for user in USERS:
                    out.append(view_case(label, engine, name, fx[key], user))
    return out


def teardown(config):
    if STATE['original'] is not None and \
            STATE['current'] != STATE['original']:
        switch_engine(Client(config), STATE['original'])
