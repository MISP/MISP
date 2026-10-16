"""Every export format of the event and attribute scopes over a fixed sample
of events, recorded byte for byte after normalisation.

The sample holds one event per shape (the export_* fixtures): small and
mixed, composite-heavy, object-heavy, an org-only object in a community
event, objects carrying their own distribution, new and edit proposals, a
deletion proposal, and the largest event. Every format runs as the site
admin; json and csv also run as the lesser user, whose view is ACL-filtered.

Normalisation of every body:
- PHP debug blocks collapse to level, message and file: their element ids are
  random and their traces carry line numbers.
- Date-times inside the request's own time window are generation timestamps;
  the frozen data predates every recording.
- Random ids (STIX 1 package, STIX 2 bundle, multi-attribute YARA rule
  names, converter temp file names in error messages) and day-granular
  stamps (suricata updated_at, the RPZ serial) are masked.
- xlsx bodies are unzipped and recorded per member.

Bodies are compared without their row order (core.unordered_form): the event
fetch reads attributes in whichever index's order the optimizer picks, which
2.x never fixed and which moves when indexes change.

opendata is not recorded: it publishes to an external portal. HANGS lists
cases that never complete on 2.x. ProcessTool::execute() reads a converter's
stdout to EOF before its stderr, so a converter that reports more than a pipe
buffer of parse errors blocks for good: Apache answers 504 after 300 s, and
the PHP worker and the converter stay stuck until killed.
"""

import io
import re
import zipfile
from datetime import datetime, timedelta, timezone

from core import Case
from suites.restsearch import load_fixtures

EVENT_FORMATS = (
    'attack', 'attack-sightings', 'cache', 'context', 'context-markdown',
    'count', 'csv', 'hashes', 'hosts', 'json', 'kunai', 'netfilter',
    'rpz', 'snort', 'stix', 'stix2', 'suricata',
    'text', 'xlsx', 'xml', 'yara', 'yara-json',
)
ATTRIBUTE_FORMATS = tuple(
    f for f in EVENT_FORMATS
    if f not in ('attack', 'context', 'context-markdown'))
LESSER_FORMATS = ('json', 'csv')
SCOPES = (
    ('event', '/events/restSearch', EVENT_FORMATS),
    ('attr', '/attributes/restSearch', ATTRIBUTE_FORMATS),
)
SAMPLE = (
    'small', 'composite', 'objects', 'object_acl', 'object_distribution',
    'proposals', 'proposal_delete', 'largest',
)
# 2.x answers stix under a JSON Accept header with STIX 1 JSON.
ACCEPT = {'stix': 'application/xml'}
HANGS = {
    ('attr', 'objects', 'stix'),
    ('attr', 'largest', 'stix'),
}
WINDOW_SLACK = 5

DEBUG_START = '<pre class="cake-error">'
DEBUG_END = '</pre></div></pre>'
DEBUG_HEAD = re.compile(
    r'.*?<b>([A-Za-z ]+)</b> \(\d+\)</a>: (.*?) '
    r'\[<b>(.*?)</b>, line <b>\d+</b>\]', re.S)
TEMP_FILE = re.compile(r'(\\?/tmp\\?/MISP)[A-Za-z0-9]{6}')
DATETIME = re.compile(
    r'(\d{4})-(\d\d)-(\d\d)[T ](\d\d):(\d\d):(\d\d)(\.\d+)?'
    r'(Z|[+-]\d\d:?\d\d| [+-]\d{4})?')
SUBSTITUTIONS = {
    'rpz': [(r'(SOA \S+ \S+ \()\d+', r'\1<serial>')],
    'stix': [(r'STIXPackage-[0-9a-f-]{36}', 'STIXPackage-<random>', 1)],
    'stix2': [(r'"bundle--[0-9a-f-]{36}"', '"bundle--<random>"')],
    'suricata': [(r'updated_at \d{4}_\d\d_\d\d', 'updated_at <today>')],
    'yara': [(r'MISP_MULTI_ATTRIBUTES_[0-9a-f]{32}',
              'MISP_MULTI_ATTRIBUTES_<random>')],
    'yara-json': [(r'MISP_MULTI_ATTRIBUTES_[0-9a-f]{32}',
                   'MISP_MULTI_ATTRIBUTES_<random>')],
}


def collapse_php_debug(text):
    pieces = text.split(DEBUG_START)
    out = [pieces[0]]
    for piece in pieces[1:]:
        end = piece.find(DEBUG_END)
        head = DEBUG_HEAD.match(piece, 0, end) if end >= 0 else None
        if head is None:
            out.append(DEBUG_START + piece)
            continue
        out.append('[php %s: %s in %s]\n' % head.groups())
        out.append(piece[end + len(DEBUG_END):])
    return ''.join(out)


def _instants(match):
    year, month, day, hour, minute, second = map(int, match.groups()[:6])
    fraction = float(match.group(7) or 0)
    try:
        naive = datetime(year, month, day, hour, minute, second)
    except ValueError:
        return []
    zone = (match.group(8) or '').strip()
    if zone:
        if zone == 'Z':
            offset = timedelta(0)
        else:
            digits = zone[1:].replace(':', '')
            offset = timedelta(hours=int(digits[:2]), minutes=int(digits[2:]))
            if zone[0] == '-':
                offset = -offset
        stamps = [naive.replace(tzinfo=timezone(offset)).timestamp()]
    else:
        # Naive date-times are written in UTC by PHP and in local time by
        # the python converters.
        stamps = [naive.replace(tzinfo=timezone.utc).timestamp(),
                  naive.timestamp()]
    return [s + fraction for s in stamps]


def mask_generated(text, started, finished):
    low, high = started - WINDOW_SLACK, finished + WINDOW_SLACK

    def replace(match):
        if any(low <= t <= high for t in _instants(match)):
            return '<generated>'
        return match.group(0)
    return DATETIME.sub(replace, text)


def normalise(fmt, text, started, finished):
    text = collapse_php_debug(text)
    text = mask_generated(text, started, finished)
    text = TEMP_FILE.sub(r'\1<tmp>', text)
    for rule in SUBSTITUTIONS.get(fmt, ()):
        pattern, replacement = rule[0], rule[1]
        count = rule[2] if len(rule) > 2 else 0
        text = re.sub(pattern, replacement, text, count=count)
    return text


def xlsx_members(body, started, finished):
    with zipfile.ZipFile(io.BytesIO(body)) as archive:
        return {name: mask_generated(
                    archive.read(name).decode('utf-8'), started, finished)
                for name in sorted(archive.namelist())}


def export_body(fmt):
    def extract(response):
        if fmt == 'xlsx' and response.body.startswith(b'PK'):
            body = xlsx_members(
                response.body, response.started, response.finished)
        else:
            body = normalise(
                fmt, response.text(), response.started, response.finished)
        return {
            'content_type': response.header('Content-Type'),
            'result_count': response.header('X-Result-Count'),
            'body': body,
        }
    return extract


def sample_events(fixtures):
    return [(name, fixtures['export_' + name]) for name in SAMPLE
            if fixtures.get('export_' + name)]


def cases(config):
    out = []
    for sample, event_id in sample_events(load_fixtures(config)):
        for scope, path, formats in SCOPES:
            for fmt in formats:
                if (scope, sample, fmt) in HANGS:
                    continue
                users = ('admin', 'lesser') if fmt in LESSER_FORMATS \
                    else ('admin',)
                for user in users:
                    out.append(Case(
                        '%s.%s.%s.%s' % (scope, sample, fmt, user), path,
                        export_body(fmt), method='POST', user=user,
                        accept=ACCEPT.get(fmt, 'application/json'),
                        body={'eventid': event_id, 'returnFormat': fmt},
                        description='%s export of event %s' % (fmt, event_id),
                        unordered=True))
    return out
