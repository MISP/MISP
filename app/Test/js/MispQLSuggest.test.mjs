// Unit tests for the MispQL console's completion engine: text plus caret
// in, suggestions out.
//
// Run with:
//   node --test app/Test/js/MispQLSuggest.test.mjs

import { test, describe } from 'node:test';
import assert from 'node:assert/strict';

import { suggest, lookupItems, describeAt, TYPE_DOC } from '../../webroot/js/mispql/suggest.mjs';

const ALL_OPS = ['=', '!=', '>', '<', '>=', '<=', 'IN', 'NOT IN'];
const STR_OPS = ['=', '!=', 'IN', 'NOT IN', 'LIKE', 'NOT LIKE'];
const SUB_OPS = ['=', 'IN', 'LIKE'];
const num = (type, level) => ({ type, operators: ALL_OPS, level });
const str = (level) => ({ type: 'string', operators: STR_OPS, level });
const sub = (type, level, operators = SUB_OPS) => ({ type, operators, level });
const bool = (level, operators = ['=', '!=']) => ({ type: 'bool', operators, level });

// The slice of the server's language pack the fixtures touch: full
// definitions for the tables they complete against, stubs for the rest.
const stub = (endpoint, description) => ({
  endpoint,
  description,
  fields: {},
  order_by: {},
  formats: ['json', 'count'],
  default_columns: [],
  aliases: {},
});

const PACK = {
  language: '1.0',
  keywords: ['AND', 'ASC', 'BY', 'COUNT', 'DATABASES', 'DESC', 'DESCRIBE', 'FALSE', 'FORMAT', 'FROM', 'IN', 'LIKE', 'LIMIT', 'NOT', 'OFFSET', 'OR', 'ORDER', 'SELECT', 'SHOW', 'TABLES', 'TRUE', 'USE', 'WHERE', 'WHOAMI'],
  client_statements: ['USE', 'SHOW DATABASES'],
  renderings: ['table', 'flat'],
  limits: { max_depth: 5, max_nodes: 50, max_list: 100, max_value_length: 1024, max_length: 1048576, max_nesting: 64 },
  tables: {
    attributes: {
      endpoint: '/attributes/restSearch',
      description: 'Attributes, each with its event and its tags',
      fields: {
        id: num('int', ['attribute']),
        event_id: num('int', ['attribute']),
        object_id: num('int', ['attribute']),
        distribution: num('int', ['attribute']),
        timestamp: num('timestamp', ['attribute']),
        event_timestamp: num('timestamp', ['event']),
        publish_timestamp: num('timestamp', ['event']),
        threat_level_id: num('int', ['event']),
        to_ids: bool(['attribute']),
        published: bool(['event']),
        uuid: { type: 'string', operators: ['=', '!=', 'IN', 'NOT IN'], level: ['attribute'] },
        type: str(['attribute']),
        category: str(['attribute']),
        object_relation: str(['attribute']),
        comment: str(['attribute']),
        eventinfo: str(['event']),
        value: str(['attribute']),
        tags: str(['attribute', 'event']),
        org: { type: 'string', operators: ['=', '!=', 'IN', 'NOT IN'], level: ['event'] },
      },
      order_by: {
        id: 'id',
        event_id: 'event_id',
        object_id: 'object_id',
        type: 'type',
        category: 'category',
        value: 'value',
        distribution: 'distribution',
        timestamp: 'timestamp',
        object_relation: 'object_relation',
        publish_timestamp: 'Event.publish_timestamp',
      },
      formats: ['attack-sightings', 'count', 'csv', 'hashes', 'hosts', 'json', 'kunai', 'netfilter', 'opendata', 'rpz', 'snort', 'stix', 'stix2', 'suricata', 'text', 'xlsx', 'xml', 'yara', 'yara-json'],
      default_columns: ['id', 'event_id', 'category', 'type', 'value', 'to_ids', 'timestamp', 'Tag'],
      aliases: {
        eventinfo: 'Event.info',
        org: 'Event.Orgc.name',
        tags: 'Tag',
        event_timestamp: 'Event.timestamp',
        publish_timestamp: 'Event.publish_timestamp',
        threat_level_id: 'Event.threat_level_id',
      },
    },
    events: {
      endpoint: '/events/restSearch',
      description: 'Events; attribute and object fields select events holding a match',
      fields: {
        id: num('int', ['event']),
        event_id: num('int', ['event']),
        uuid: { type: 'string', operators: ['=', '!=', 'IN', 'NOT IN'], level: ['event'] },
        distribution: num('int', ['event']),
        analysis: num('int', ['event']),
        threat_level_id: num('int', ['event']),
        org_id: num('int', ['event']),
        orgc_id: num('int', ['event']),
        org: { type: 'string', operators: ['=', '!=', 'IN', 'NOT IN'], level: ['event'] },
        eventinfo: str(['event']),
        date: num('date', ['event']),
        timestamp: num('timestamp', ['event']),
        event_timestamp: num('timestamp', ['event']),
        publish_timestamp: num('timestamp', ['event']),
        published: bool(['event']),
        tags: str(['event', 'attribute']),
        type: sub('string', ['attribute']),
        category: sub('string', ['attribute']),
        object_relation: sub('string', ['attribute']),
        comment: sub('string', ['attribute']),
        value: sub('string', ['attribute']),
        to_ids: bool(['attribute'], ['=']),
        object_name: sub('string', ['object']),
        object_template_uuid: sub('string', ['object'], ['=', 'IN']),
      },
      order_by: {
        id: 'id',
        event_id: 'id',
        eventinfo: 'info',
        analysis: 'analysis',
        threat_level_id: 'threat_level_id',
        distribution: 'distribution',
        timestamp: 'timestamp',
        event_timestamp: 'timestamp',
        publish_timestamp: 'publish_timestamp',
      },
      formats: ['attack', 'attack-sightings', 'context', 'context-markdown', 'count', 'csv', 'hashes', 'hosts', 'json', 'kunai', 'netfilter', 'opendata', 'rpz', 'snort', 'stix', 'stix2', 'suricata', 'text', 'xlsx', 'xml', 'yara', 'yara-json'],
      default_columns: ['id', 'date', 'info', 'Orgc.name', 'threat_level_id', 'analysis', 'published', 'attribute_count', 'Tag'],
      aliases: {
        event_id: 'id',
        eventinfo: 'info',
        org: 'Orgc.name',
        event_timestamp: 'timestamp',
        tags: 'Tag',
      },
    },
    objects: {
      endpoint: '/objects/restSearch',
      description: 'Objects, each with the attributes of it you can see',
      fields: {
        id: num('int', ['object']),
        object_id: num('int', ['object']),
        uuid: { type: 'string', operators: ['=', '!=', 'IN', 'NOT IN'], level: ['object'] },
        distribution: num('int', ['object']),
        timestamp: num('timestamp', ['object']),
        object_name: str(['object']),
        object_template_uuid: { type: 'string', operators: ['=', '!=', 'IN', 'NOT IN'], level: ['object'] },
        event_id: num('int', ['event']),
        orgc_id: num('int', ['event']),
        org: { type: 'string', operators: ['=', '!=', 'IN', 'NOT IN'], level: ['event'] },
        eventinfo: str(['event']),
        date: num('date', ['event']),
        event_timestamp: num('timestamp', ['event']),
        publish_timestamp: num('timestamp', ['event']),
        threat_level_id: num('int', ['event']),
        published: bool(['event']),
        tags: str(['event', 'attribute']),
        type: sub('string', ['attribute']),
        category: sub('string', ['attribute']),
        object_relation: sub('string', ['attribute']),
        comment: sub('string', ['attribute']),
        value: sub('string', ['attribute']),
        to_ids: bool(['attribute'], ['=']),
      },
      order_by: {},
      formats: ['json', 'stix2', 'count'],
      default_columns: ['id', 'event_id', 'name', 'meta-category', 'comment', 'timestamp'],
      aliases: {
        object_id: 'id',
        object_name: 'name',
        object_template_uuid: 'template_uuid',
        orgc_id: 'Event.orgc_id',
      },
    },
    galaxy_clusters: stub('/galaxy_clusters/restSearch', 'Galaxy clusters, with their galaxy'),
    event_reports: stub('/event_reports/restSearch', 'Event reports, searched as children of their event'),
    notes: stub('/analyst_data/restSearch/Note', 'Analyst notes'),
    opinions: stub('/analyst_data/restSearch/Opinion', 'Analyst opinions'),
    relationships: stub('/analyst_data/restSearch/Relationship', 'Analyst relationships'),
    collections: stub('/collections/restSearch', 'Collections, each with its elements'),
    tags: {
      endpoint: '/tags/restSearch',
      description: 'Every tag on the instance, with usage counts',
      fields: {
        id: num('int', ['tag']),
        name: str(['tag']),
        colour: { type: 'string', operators: ['=', '!=', 'IN', 'NOT IN'], level: ['tag'] },
        exportable: bool(['tag']),
        org_id: num('int', ['tag']),
        user_id: num('int', ['tag']),
        hide_tag: bool(['tag']),
        numerical_value: num('int', ['tag']),
        is_galaxy: bool(['tag']),
        is_custom_galaxy: bool(['tag']),
        local_only: bool(['tag']),
      },
      order_by: { id: 'id', name: 'name', numerical_value: 'numerical_value' },
      formats: ['json', 'count'],
      default_columns: ['id', 'name', 'numerical_value', 'hide_tag', 'is_galaxy', 'count', 'attribute_count'],
      aliases: {},
    },
    organisations: stub('/organisations/restSearch', 'Every organisation, local and external'),
  },
};

function at(textWithCaret) {
  const caret = textWithCaret.indexOf('|');
  const text = textWithCaret.slice(0, caret) + textWithCaret.slice(caret + 1);
  return suggest(text, caret, PACK);
}

const labels = (r) => r.items.map((i) => i.label);

function kinds(r) {
  const seen = {};
  r.items.forEach((i) => { seen[i.kind] = 1; });
  return Object.keys(seen).sort();
}

const FIXTURES = [
  ['|', (r) => { assert.deepEqual(labels(r).slice(0, 4), ['SELECT', 'DESCRIBE', 'SHOW TABLES', 'WHOAMI']); }],
  ['SELECT * FROM |', (r) => { assert.deepEqual(kinds(r), ['table']); assert.equal(r.items.length, 11); }],
  ['select * from att|', (r) => { assert.deepEqual(labels(r), ['attributes']); }],
  ['sel|', (r) => { assert.equal(r.items[0].insert, 'select '); }],
  ['SELECT * FROM attributes WHERE |', (r) => {
    assert.ok(labels(r).indexOf('eventinfo') !== -1, 'eventinfo');
    assert.ok(labels(r).indexOf('NOT') !== -1, 'NOT');
  }],
  ['SELECT * FROM attributes WHERE to_ids |', (r) => { assert.deepEqual(labels(r), ['=', '!=']); }],
  ['SELECT * FROM attributes WHERE to_ids = |', (r) => { assert.deepEqual(labels(r), ['TRUE', 'FALSE']); }],
  ['SELECT * FROM events WHERE type |', (r) => { assert.deepEqual(labels(r), ['=', 'IN', 'LIKE']); }],
  ['SELECT * FROM events WHERE tags NOT |', (r) => { assert.deepEqual(labels(r), ['IN', 'LIKE']); }],
  ['SELECT * FROM events WHERE date >= |', (r) => { assert.deepEqual(kinds(r), ['value']); }],
  ["SELECT * FROM attributes WHERE type = 'x' |", (r) => {
    assert.deepEqual(labels(r), ['AND', 'OR', 'ORDER BY', 'LIMIT', 'FORMAT']);
  }],
  ["SELECT * FROM attributes WHERE (type = 'x' |", (r) => { assert.ok(labels(r).indexOf(')') !== -1, 'close'); }],
  ["SELECT * FROM attributes WHERE type = 'dom|", (r) => { assert.equal(r.items.length, 0); }],
  ['SELECT * FROM attributes LIMIT 10|', (r) => { assert.equal(r.items.length, 0); }],
  ['SELECT * FROM events ORDER BY |', (r) => {
    assert.ok(labels(r).indexOf('eventinfo') !== -1 && labels(r).indexOf('event_id') !== -1, 'sort names');
  }],
  ['SELECT * FROM objects ORDER BY |', (r) => {
    assert.equal(r.items.length, 0);
    assert.ok(/cannot be sorted/.test(r.hint), r.hint);
  }],
  ['SELECT * FROM tags LIMIT 5 FORMAT |', (r) => { assert.deepEqual(labels(r), ['table', 'flat', 'json']); }],
  ['SELECT id, | FROM events', (r) => {
    assert.ok(labels(r).indexOf('eventinfo') !== -1, 'alias');
    assert.deepEqual(kinds(r), ['column']);
  }],
  ['SELECT * FROM　|', (r) => { assert.deepEqual(kinds(r), ['table']); }],
  ['SELECT * FROM attributes WHERE attributes.|', (r) => { assert.ok(labels(r).indexOf('value') !== -1, 'qualified'); }],
  ['DESCRIBE |', (r) => { assert.deepEqual(kinds(r), ['table']); }],
  ['SELECT * FROM events LIMIT 1; SELECT * FROM |', (r) => { assert.deepEqual(kinds(r), ['table']); }],
];

describe('Suggestions', () => {
  FIXTURES.forEach(([text, check]) => {
    test(JSON.stringify(text), () => { check(at(text)); });
  });
});

// The same pack, with the lists and lookups the server adds to it.
const VPACK = structuredClone(PACK);
VPACK.values = {
  attribute_types: [
    { value: 'domain', label: 'Network activity', description: 'A domain name used in the malware' },
    { value: 'domain|ip', label: 'Network activity', description: 'A domain name and its IP address' },
    { value: 'ip-dst', label: 'Network activity', description: 'A destination IP address' },
    { value: 'ip-dst|port', label: 'Network activity', description: 'A destination IP address and a port' },
    { value: 'md5', label: 'Payload delivery', description: 'A checksum in MD5 format' },
  ],
  distribution_inherit: [
    { value: 0, label: 'Your organisation only' }, { value: 1, label: 'This community only' },
    { value: 2, label: 'Connected communities' }, { value: 3, label: 'All communities' },
    { value: 4, label: 'Sharing group' }, { value: 5, label: 'Inherited' },
  ],
  threat_levels: [{ value: 1, label: 'High' }, { value: 2, label: 'Medium' }, { value: 3, label: 'Low' }, { value: 4, label: 'Undefined' }],
  object_templates: ['domain-ip', 'file', 'url'],
};
VPACK.sources = {
  tags: [{ url: '/tags/pickerSearch', insert: 'value' }, { url: '/galaxy_clusters/pickerSearch', insert: 'value' }],
  organisations: [{ url: '/organisations/pickerSearch', insert: 'label' }],
  galaxy_names: [{ url: '/galaxies/pickerScopes', insert: 'name', whole: true }],
};
Object.assign(VPACK.tables.attributes.fields.type, { values: 'attribute_types' });
Object.assign(VPACK.tables.attributes.fields.distribution, { values: 'distribution_inherit' });
Object.assign(VPACK.tables.attributes.fields.threat_level_id, { values: 'threat_levels' });
Object.assign(VPACK.tables.attributes.fields.tags, { lookup: 'tags' });
Object.assign(VPACK.tables.attributes.fields.org, { lookup: 'organisations' });
Object.assign(VPACK.tables.events.fields.type, { values: 'attribute_types' });
Object.assign(VPACK.tables.events.fields.object_name, { values: 'object_templates' });
VPACK.tables.galaxy_clusters.fields = { galaxy_name: { type: 'string', operators: STR_OPS, level: ['galaxy'], lookup: 'galaxy_names' } };

function vat(textWithCaret) {
  const caret = textWithCaret.indexOf('|');
  const text = textWithCaret.slice(0, caret) + textWithCaret.slice(caret + 1);
  const r = suggest(text, caret, VPACK);
  r.text = text;
  r.replaced = text.slice(r.from, r.to);
  return r;
}

const ATTR = 'SELECT * FROM attributes WHERE ';

const VALUE_FIXTURES = [
  [ATTR + 'type = |', (r) => {
    assert.deepEqual(labels(r), ['domain', 'domain|ip', 'ip-dst', 'ip-dst|port', 'md5']);
    assert.deepEqual(kinds(r), ['value']);
    assert.equal(r.items[2].insert, "'ip-dst' ");
    assert.equal(r.items[2].detail, 'Network activity', 'the default category');
    assert.equal(r.items[2].doc, 'A destination IP address', 'the type description');
  }],
  [ATTR + 'type != |', (r) => {
    assert.equal(r.items.length, 5);
    assert.equal(r.hint, '', 'named values need no type sentence');
  }],
  [ATTR + "tags = '|", (r) => { assert.equal(r.hint, 'Type 2 characters to look names up.'); }],
  [ATTR + "tags = 'tl|", (r) => { assert.equal(r.hint, ''); }],
  [ATTR + "eventinfo = '|", (r) => { assert.match(r.hint, /quoted/); }],
  [ATTR + 'type = ip|', (r) => {
    assert.deepEqual(labels(r), ['ip-dst', 'ip-dst|port', 'domain|ip']);
    assert.equal(r.replaced, 'ip', 'a bare word is written over, quoted');
  }],
  [ATTR + "type = 'ip-d|", (r) => {
    assert.equal(r.quoted, true);
    assert.equal(r.prefix, 'ip-d');
    assert.deepEqual(labels(r), ['ip-dst', 'ip-dst|port']);
    assert.equal(r.replaced, "'ip-d");
  }],
  [ATTR + "type = 'ip|-src' LIMIT 5", (r) => {
    assert.equal(r.replaced, "'ip-src'", 'the whole value, closing quote included');
  }],
  [ATTR + "type = 'ip| AND category = 'Network activity'", (r) => {
    assert.equal(r.replaced, "'ip", 'a quote pairing with a later one keeps the text it swallowed');
    assert.deepEqual(labels(r), ['ip-dst', 'ip-dst|port', 'domain|ip']);
  }],
  [ATTR + "type = 'domain|", (r) => {
    assert.deepEqual(labels(r), ['domain', 'domain|ip'], 'a value named in full stays offered');
  }],
  [ATTR + "type IN ('domain', |", (r) => { assert.equal(r.items.length, 5); assert.equal(r.state, 'in_value'); }],
  [ATTR + "type NOT IN ('md|", (r) => { assert.deepEqual(labels(r), ['md5']); }],
  [ATTR + "type LIKE '|", (r) => { assert.equal(r.items.length, 0, 'a pattern, not a name'); }],
  [ATTR + "type = 'ip-dst'|", (r) => { assert.equal(r.items.length, 0, 'past the closing quote'); }],
  [ATTR + 'distribution = |', (r) => {
    assert.deepEqual(labels(r), ['0', '1', '2', '3', '4', '5']);
    assert.equal(r.items[0].insert, '0 ', 'a number stays bare');
    assert.equal(r.items[0].detail, 'Your organisation only');
  }],
  [ATTR + 'distribution = 1|', (r) => {
    assert.deepEqual(labels(r), ['1']);
    assert.equal(r.replaced, '1');
  }],
  [ATTR + 'distribution = comm|', (r) => { assert.deepEqual(labels(r), ['1', '2', '3'], 'matched by name'); }],
  [ATTR + 'distribution < |', (r) => { assert.equal(r.items.length, 0, 'levels are not typed by order'); }],
  [ATTR + 'distribution IN (0, |', (r) => { assert.equal(r.items.length, 6); }],
  [ATTR + "distribution = '|", (r) => { assert.equal(r.items.length, 0, 'a level is a number'); }],
  [ATTR + 'threat_level_id != |', (r) => { assert.deepEqual(r.items.map((i) => i.detail), ['High', 'Medium', 'Low', 'Undefined']); }],
  ["SELECT * FROM events WHERE object_name = 'fi|", (r) => {
    assert.deepEqual(labels(r), ['file']);
    assert.equal(r.items[0].detail, '', 'a bare list has no names');
  }],
  ['SELECT * FROM events LIMIT 1; ' + ATTR + "type = 'md|", (r) => { assert.deepEqual(labels(r), ['md5']); }],
  [ATTR + "tags = 'tlp:a|", (r) => {
    assert.equal(r.items.length, 0);
    assert.deepEqual(r.lookup, { source: 'tags', prefix: 'tlp:a', min: 2 });
    assert.equal(r.replaced, "'tlp:a");
  }],
  [ATTR + 'tags = tl|', (r) => { assert.deepEqual(r.lookup, { source: 'tags', prefix: 'tl', min: 2 }); }],
  [ATTR + "tags IN ('tlp:red', 'tl|", (r) => { assert.equal(r.lookup.prefix, 'tl'); }],
  [ATTR + "tags != 'O''Br|", (r) => { assert.equal(r.lookup.prefix, "O'Br", 'a doubled quote is one quote'); }],
  [ATTR + "tags LIKE 'tlp|", (r) => { assert.equal(r.lookup, null); }],
  [ATTR + "org = 'CI|", (r) => { assert.equal(r.lookup.source, 'organisations'); }],
  [ATTR + "eventinfo = 'phish|", (r) => {
    assert.equal(r.items.length, 0);
    assert.equal(r.lookup, null, 'free text');
  }],
  ["SELECT * FROM galaxy_clusters WHERE galaxy_name = |", (r) => {
    assert.deepEqual(r.lookup, { source: 'galaxy_names', prefix: '', min: 0 }, 'a whole list needs nothing typed');
  }],
];

describe('Value suggestions', () => {
  VALUE_FIXTURES.forEach(([text, check]) => {
    test(JSON.stringify(text), () => { check(vat(text)); });
  });

  test('looked-up rows become quoted values, once each', () => {
    const items = lookupItems([
      { value: 'tlp:amber', detail: '', doc: 'Limited disclosure' },
      { value: "O'Brien Ltd", detail: '' },
      { value: 'tlp:amber' },
      { value: '%wild' },
      { value: '' },
    ]);
    assert.deepEqual(items.map((i) => i.insert), ["'tlp:amber' ", "'O''Brien Ltd' "]);
    assert.equal(items[0].doc, 'Limited disclosure');
    assert.equal(items[0].kind, 'value');
  });

  test('a pack without lists offers what it offered before', () => {
    assert.equal(at(ATTR + 'distribution = |').items.length, 0);
    assert.equal(at(ATTR + "tags = 'tlp|").lookup, null);
  });
});

// The same pack, with what each field means, as the server adds it.
const DPACK = structuredClone(PACK);
DPACK.tables.attributes.fields.type.description = "The attribute's type.";
DPACK.tables.attributes.fields.eventinfo.description = "The event's info.";
DPACK.tables.attributes.fields.org.description = "The event's creator organisation.";
DPACK.tables.attributes.fields.timestamp.description = 'When it was last changed.';
DPACK.tables.events.fields.value.description = "The attribute's value.";
DPACK.tables.galaxy_clusters.fields = { 'meta.<key>': Object.assign(str(['galaxy_element']), { description: 'A meta value.' }) };

// The text with `^` before the character the pointer rests on.
function hover(textWithPointer) {
  const p = textWithPointer.indexOf('^');
  const text = textWithPointer.slice(0, p) + textWithPointer.slice(p + 1);
  const r = describeAt(text, p, DPACK);
  return r && Object.assign({ written: text.slice(r.from, r.to) }, r);
}

const HOVER_FIXTURES = [
  ["SELECT * FROM attributes WHERE ty^pe = 'x'", { kind: 'field', name: 'type', table: 'attributes', written: 'type' }],
  ["SELECT * FROM attributes WHERE NOT (^type = 'x')", { kind: 'field', name: 'type', written: 'type' }],
  ['SELECT * FROM attributes ORDER BY ^timestamp DESC', { kind: 'field', name: 'timestamp' }],
  ['SELECT * FROM attributes ORDER BY ^eventinfo', null],
  ['SELECT * FROM ^attributes', { kind: 'table', name: 'attributes', table: 'attributes' }],
  ['DESCRIBE ^events', { kind: 'table', name: 'events' }],
  ["SELECT * FROM attributes WHERE ^attributes.type = 'x'", { kind: 'table', name: 'attributes', written: 'attributes' }],
  ["SELECT * FROM attributes WHERE attributes.t^ype = 'x'", { kind: 'field', name: 'type', written: 'type' }],
  ["SELECT * FROM galaxy_clusters WHERE me^ta.synonyms = 'x'", { kind: 'field', name: 'meta.synonyms', written: 'meta.synonyms' }],
  ["SELECT * FROM galaxy_clusters WHERE meta.`cfr-^x` = 'x'", { kind: 'field', name: 'meta.`cfr-x`' }],
  ['SELECT id, Event.i^nfo FROM attributes', { kind: 'column', name: 'Event.info', field: 'eventinfo', written: 'Event.info' }],
  ['SELECT ^org FROM attributes', { kind: 'column', name: 'org', field: 'org' }],
  ['SELECT ^value FROM events', null],
  ["SELECT * FROM events WHERE ^value = 'x'", { kind: 'field', name: 'value', table: 'events' }],
  ['SELECT ^nope FROM attributes', null],
  ["SELECT * FROM attributes WHERE ^nope = 'x'", null],
  ["SELECT * FROM attributes WHERE type = '^x'", null],
  ["^SELECT * FROM attributes WHERE type = 'x'", null],
  ["SELECT * FROM events LIMIT 1; SELECT * FROM attributes WHERE ^type = 'x'", { kind: 'field', table: 'attributes' }],
  ['SELECT ^id, value FROM attributes; SELECT * FROM events', { kind: 'column', table: 'attributes' }],
];

describe('What a name means', () => {
  HOVER_FIXTURES.forEach(([text, want]) => {
    test(JSON.stringify(text), () => {
      const r = hover(text);
      if (want === null) {
        assert.equal(r, null);
        return;
      }
      assert.ok(r, 'something to say');
      Object.keys(want).forEach((k) => { assert.equal(r[k], want[k], k); });
    });
  });

  test('a field answers with its definition, a table with none', () => {
    assert.equal(hover("SELECT * FROM attributes WHERE ^type = 'x'").def.description, "The attribute's type.");
    assert.equal(hover('SELECT * FROM galaxy_clusters WHERE ^meta.x = 1').def.description, 'A meta value.');
    assert.equal(hover('SELECT * FROM ^attributes').def, null);
  });

  test('a field suggestion says what it means, then the literals it takes', () => {
    const r = suggest('SELECT * FROM attributes WHERE ty', 33, DPACK);
    assert.equal(r.items[0].doc, "The attribute's type.");
    assert.equal(r.items[0].typeDoc, TYPE_DOC.string);
    assert.deepEqual(r.items[0].notes, []);
  });

  test('a field read inside the records says so', () => {
    const r = suggest('SELECT * FROM events WHERE valu', 31, DPACK);
    assert.equal(r.items[0].doc, "The attribute's value.");
    assert.deepEqual(r.items[0].notes, ['Matched against the attributes inside; positive operators only.']);
  });

  test('without a sentence, the type sentence stays the doc', () => {
    const r = at('SELECT * FROM attributes WHERE ty|');
    assert.equal(r.items[0].doc, TYPE_DOC.string);
    assert.equal(r.items[0].typeDoc, '');
  });

  test('a column says what its field means and where it is printed', () => {
    const items = suggest('SELECT  FROM attributes', 7, DPACK).items;
    const doc = (label) => items.filter((i) => i.label === label)[0].doc;
    assert.equal(doc('eventinfo'), "The event's info. Printed as Event.info.");
    assert.equal(doc('type'), "The attribute's type.");
    assert.equal(doc('Tag'), '');
  });
});
