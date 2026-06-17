#!/usr/bin/env python3
"""Browser-level verification of the event index mass tag/cluster actions.

Companion to tests/testlive_event_mass_actions.py (API level): this one
drives headless chromium over CDP through the real UI path. See
docs/dev/event-index-mass-actions-prd.md §9.4-9.5.

Usage:
    HOST=localhost:5007 AUTH=<site-admin-key> \
    MISP_ADMIN_EMAIL=<web-login> MISP_ADMIN_PASSWORD=<password> \
    python3 ui_event_mass_actions_check.py

Requires: chromium-browser, websocket-client, lxml, pymisp.

Verifies on the real event index: 4 mass buttons exist and are hidden,
checking rows reveals them (computed visibility), the tag picker opens
from the toolbar button, and the full quickSubmitTagForm /
quickSubmitGalaxyForm 'selected' round-trips attach tags/clusters
(asserted via API afterwards). Then attribute-flow non-regression on the
event view, and non-tagger button gating via a Read Only session.
"""
import base64
import json
import os
import subprocess
import sys
import tempfile
import time
import uuid

import requests
import websocket
from lxml.html import fromstring
from pymisp import PyMISP, MISPOrganisation, MISPUser

try:
    URL = 'http://' + os.environ['HOST']
    KEY = os.environ['AUTH']
except KeyError:
    import keys
    URL = keys.url
    KEY = keys.key
ADMIN_EMAIL = os.environ.get('MISP_ADMIN_EMAIL')
ADMIN_PW = os.environ.get('MISP_ADMIN_PASSWORD')
if not ADMIN_EMAIL or not ADMIN_PW:
    sys.exit('Set MISP_ADMIN_EMAIL and MISP_ADMIN_PASSWORD (web login is needed '
             'for the browser session; the API key alone cannot drive the UI).')
RND = str(uuid.uuid4())[:8]
SHOTS = os.environ.get('SHOTS_DIR', '/tmp/t6-shots')
os.makedirs(SHOTS, exist_ok=True)

failures = []


def check(name, ok, detail=''):
    print(('PASS  ' if ok else 'FAIL  ') + name + (f'  [{detail}]' if detail and not ok else ''))
    if not ok:
        failures.append(name)


def login(email, password):
    s = requests.Session()
    r = s.get(URL + '/users/login')
    doc = fromstring(r.text)
    data = {'_method': 'POST'}
    for field in ('key', 'fields', 'unlocked', 'debug'):
        val = doc.xpath(f'//input[@name="data[_Token][{field}]"]/@value')
        if val:
            data[f'data[_Token][{field}]'] = val[0]
    data['data[User][email]'] = email
    data['data[User][password]'] = password
    r = s.post(URL + '/users/login', data=data, allow_redirects=True)
    assert 'users/login' not in r.url, 'login failed for ' + email
    return s


class CDP:
    def __init__(self, ws_url):
        self.ws = websocket.create_connection(ws_url, timeout=60)
        self._id = 0

    def cmd(self, method, **params):
        self._id += 1
        self.ws.send(json.dumps({'id': self._id, 'method': method, 'params': params}))
        while True:
            msg = json.loads(self.ws.recv())
            if msg.get('id') == self._id:
                if 'error' in msg:
                    raise RuntimeError(f"{method}: {msg['error']}")
                return msg.get('result', {})

    def eval(self, expr):
        res = self.cmd('Runtime.evaluate', expression=expr, returnByValue=True)
        if res.get('exceptionDetails'):
            raise RuntimeError(json.dumps(res['exceptionDetails'])[:400])
        return res['result'].get('value')

    def poll(self, expr, want=True, timeout=20):
        end = time.time() + timeout
        while time.time() < end:
            try:
                if self.eval(expr) == want:
                    return True
            except RuntimeError:
                pass  # evaluate during navigation can fail transiently
            time.sleep(0.4)
        return False

    def mark(self):
        self.eval("window.__t6marker = 1")

    def wait_reload(self, timeout=30):
        # marker vanishes when the page reloads; then wait for readiness + jQuery
        gone = self.poll("window.__t6marker === undefined", timeout=timeout)
        ready = self.poll("document.readyState === 'complete' && typeof $ === 'function'",
                          timeout=timeout)
        return gone and ready

    def shot(self, name):
        data = self.cmd('Page.captureScreenshot', format='png')['data']
        path = os.path.join(SHOTS, name)
        with open(path, 'wb') as f:
            f.write(base64.b64decode(data))
        print('shot  ' + path)


# ---- fixtures via API ----------------------------------------------------
admin = PyMISP(URL, KEY)


def api(method, path, data=None):
    r = admin._prepare_request(method, path, data=data or {})
    return r.json()


# clean leftovers from previous runs
leftovers = api('POST', 'events/index', {'searcheventinfo': 't6ui'})
for ev in leftovers if isinstance(leftovers, list) else []:
    api('POST', f"events/delete/{ev['id']}")

tag1 = api('POST', 'tags/add', {'name': f't6ui-tag-{RND}', 'colour': '#112233'})['Tag']
tag2 = api('POST', 'tags/add', {'name': f't6ui-tag2-{RND}', 'colour': '#112233'})['Tag']

# first default cluster from a non-local_only galaxy
found = api('POST', 'galaxy_clusters/restSearch', {'default': 1, 'limit': 10})
found = found.get('response', found) if isinstance(found, dict) else found
CLUSTER_ID = None
for entry in found:
    galaxy = api('GET', f"galaxies/view/{entry['GalaxyCluster']['galaxy_id']}")['Galaxy']
    if not galaxy.get('local_only'):
        CLUSTER_ID = entry['GalaxyCluster']['id']
        cluster_tag = entry['GalaxyCluster']['tag_name']
        break
assert CLUSTER_ID, 'no usable default galaxy cluster on this instance'

events = []
for i in range(2):
    events.append(api('POST', 'events/add', {
        'info': f't6ui-{RND}-index-{i}', 'distribution': 0,
        'analysis': 0, 'threat_level_id': 4})['Event'])
fixture_ids = sorted(int(e['id']) for e in events)

ev_attr = api('POST', 'events/add', {
    'info': f't6ui-{RND}-attrfixture', 'distribution': 0,
    'analysis': 0, 'threat_level_id': 4})['Event']
attrs = []
for i in range(2):
    attrs.append(api('POST', f"attributes/add/{ev_attr['id']}",
                     {'type': 'ip-dst', 'value': f'198.51.100.{10 + i}'})['Attribute'])


def event_tags(eid):
    ev = api('GET', f'events/view/{eid}')['Event']
    return {t['name']: t['local'] for t in ev.get('Tag', [])}


def attribute_tags(eid, aid):
    ev = api('GET', f'events/view/{eid}')['Event']
    out = {}
    for a in ev.get('Attribute', []):
        if str(a['id']) == str(aid):
            out = {t['name']: t.get('local') for t in a.get('Tag', [])}
    return out


# ---- browser session ------------------------------------------------------
web = login(ADMIN_EMAIL, ADMIN_PW)
cookie = web.cookies['CAKEPHP']

profile = tempfile.mkdtemp(prefix='t6-cdp-', dir=os.path.expanduser('~'))
proc = subprocess.Popen(
    ['/usr/bin/chromium-browser', '--headless=new', '--remote-debugging-port=9777',
     '--remote-allow-origins=*',
     f'--user-data-dir={profile}', '--window-size=1600,900', '--disable-gpu', 'about:blank'],
    stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
try:
    targets = None
    for _ in range(60):
        try:
            targets = requests.get('http://127.0.0.1:9777/json', timeout=2).json()
            if any(t['type'] == 'page' for t in targets):
                break
        except Exception:
            pass
        time.sleep(0.5)
    page = [t for t in targets if t['type'] == 'page'][0]
    cdp = CDP(page['webSocketDebuggerUrl'])
    cdp.cmd('Network.enable')
    cdp.cmd('Page.enable')
    cdp.cmd('Network.setCookie', name='CAKEPHP', value=cookie, url=URL)

    index_url = f"{URL}/events/index/searcheventinfo:t6ui-{RND}-index"
    cdp.cmd('Page.navigate', url=index_url)
    assert cdp.poll("document.readyState === 'complete' && typeof $ === 'function'", timeout=30)

    # §9.4 buttons exist, hidden with zero selection
    state = json.loads(cdp.eval(
        "JSON.stringify({mt: $('.mass-tag').length, mg: $('.mass-galaxy').length,"
        " vt: $('.mass-tag:visible').length, vg: $('.mass-galaxy:visible').length,"
        " rows: $('.select[data-id]').length})"))
    check('4 buttons present (2 tag + 2 galaxy)', state['mt'] == 2 and state['mg'] == 2, str(state))
    check('buttons hidden with zero selection', state['vt'] == 0 and state['vg'] == 0, str(state))
    check('index filtered to the 2 fixture events', state['rows'] == 2, str(state))
    if state['rows'] != 2:
        print('ABORT: refusing to run round-trips against an unfiltered index')
        sys.exit(1)

    # §9.4 checking rows reveals the buttons (computed visibility)
    after = json.loads(cdp.eval(
        "var ids=[]; $('.select[data-id]').each(function(){ this.click();"
        " ids.push($(this).data('id')); });"
        "JSON.stringify({ids: ids, vt: $('.mass-tag:visible').length,"
        " vg: $('.mass-galaxy:visible').length,"
        " collected: getSelectedEventIds()})"))
    check('buttons visible after selection', after['vt'] == 2 and after['vg'] == 2, str(after))
    check('getSelectedEventIds collects the fixture ids',
          sorted(json.loads(after['collected'])) == fixture_ids, str(after))
    cdp.shot('01_index_buttons_visible.png')

    # §9.4 picker opens from the toolbar button (bootstrap popover)
    cdp.eval("document.getElementById('multi-tag-button').click()")
    opened = cdp.poll("$('.popover:visible').text().indexOf('All Tags') !== -1")
    check('tag picker popover opens from toolbar', opened)
    cdp.shot('02_tag_picker_open.png')
    cdp.eval("$('#multi-tag-button').popover('hide'); undefined")

    # §9.4 full tag round-trip through the real JS path (admin -> global)
    cdp.mark()
    cdp.eval(f"quickSubmitTagForm(['{tag1['id']}'], {{id: 'selected', local: false}})")
    check('index reloaded after mass tag submit', cdp.wait_reload())
    ok = all(event_tags(e['id']).get(tag1['name']) is False for e in events)
    check('mass tag round-trip attached global tag to both events', ok,
          str([event_tags(e['id']) for e in events]))

    # cluster round-trip (re-select after reload)
    cdp.eval("$('.select[data-id]').each(function(){ this.click(); }); undefined")
    cdp.mark()
    cdp.eval(f"quickSubmitGalaxyForm([{CLUSTER_ID}], {{target_id: 'selected',"
             " target_type: 'event', local: 0, mirrorOnEvent: false})")
    check('index reloaded after mass cluster submit', cdp.wait_reload())
    ok = all(event_tags(e['id']).get(cluster_tag) is False for e in events)
    check('mass cluster round-trip attached cluster to both events', ok,
          str([event_tags(e['id']) for e in events]))
    cdp.shot('03_index_after_roundtrips.png')

    # §9.5 attribute flow non-regression on the event view
    cdp.cmd('Page.navigate', url=f"{URL}/events/view/{ev_attr['id']}")
    have_rows = cdp.poll("$('.select_attribute').length === 2", timeout=30)
    check('event view shows 2 attribute checkboxes', have_rows)

    cdp.eval("$('.select_attribute').each(function(){ this.click(); }); undefined")
    cdp.mark()
    cdp.eval(f"quickSubmitGalaxyForm([{CLUSTER_ID}], {{target_id: 'selected',"
             " target_type: 'attribute', local: 0, mirrorOnEvent: false})")
    check('event view reloaded after attribute mass cluster', cdp.wait_reload())
    ok = all(attribute_tags(ev_attr['id'], a['id']).get(cluster_tag) is not None for a in attrs)
    check('attribute mass cluster still works (scope-aware branch)', ok,
          str([attribute_tags(ev_attr['id'], a['id']) for a in attrs]))

    have_rows = cdp.poll("$('.select_attribute').length === 2", timeout=30)
    cdp.eval("$('.select_attribute').each(function(){ this.click(); }); undefined")
    cdp.eval(f"quickSubmitAttributeTagForm(['{tag2['id']}'], {{id: 'selected'}})")
    deadline = time.time() + 20
    ok = False
    while time.time() < deadline and not ok:
        ok = all(attribute_tags(ev_attr['id'], a['id']).get(tag2['name']) is not None
                 for a in attrs)
        time.sleep(1)
    check('attribute mass tag still works', ok,
          str([attribute_tags(ev_attr['id'], a['id']) for a in attrs]))
finally:
    proc.terminate()

# ---- §9.4 non-tagger gating (server-side requirement) ----------------------
ro_pw = str(uuid.uuid4())
org = MISPOrganisation()
org.name = f't6ui org {RND}'
org = admin.add_organisation(org, pythonify=True)
user = MISPUser()
user.email = f't6ui.ro.{RND}@user.local'
user.org_id = org.id
user.role_id = 6  # Read Only: perm_tagger = 0
user.password = ro_pw
user.change_pw = 0
user = admin.add_user(user, pythonify=True)
api('POST', f'admin/users/edit/{user.id}',
    {'change_pw': 0, 'termsaccepted': 1, 'newsread': int(time.time())})
ro = login(user.email, ro_pw)
html = ro.get(URL + '/events/index').text
check('toolbar rendered for read-only user', 'multi-export-button' in html)
check('mass tag/galaxy buttons absent for non-tagger',
      all(b not in html for b in ('multi-tag-button', 'multi-local-tag-button',
                                  'multi-galaxy-button', 'multi-local-galaxy-button')))

# ---- cleanup ---------------------------------------------------------------
for e in events + [ev_attr]:
    api('POST', f"events/delete/{e['id']}")
for t in (tag1, tag2):
    api('POST', f"tags/delete/{t['id']}")
admin.delete_user(user)
admin.delete_organisation(org)

print()
if failures:
    print('FAILURES:', failures)
    sys.exit(1)
print(f'ALL CHECKS PASSED — screenshots in {SHOTS}')
