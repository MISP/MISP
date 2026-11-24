// Unit tests for the MispQL console's completion engine: text plus caret
// in, suggestions out.
//
// Run with:
//   node --test app/Test/js/MispQLSuggest.test.mjs

import { test, describe } from 'node:test';
import assert from 'node:assert/strict';

import { suggest } from '../../webroot/js/mispql/suggest.mjs';

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
