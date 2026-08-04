// Unit tests for the configure form's pure shape helpers.
//
// Run with:
//   node --test app/Test/js/KVShape.test.mjs
//
// No framework dependencies — uses Node's built-in test runner
// (stable in Node 20+, experimental in 18.x but functional). No DOM
// access required because the helpers are pulled from
// `kvshape.module.mjs` rather than the DOM-coupled
// `configure.module.mjs`.
//
// Phase 2 tracker entry: "Bottom-tier dot-notation flattening on
// read; re-nesting on save; round-trip lossless for nested objects,
// arrays, scalars, booleans (unit-tested)".

import { test, describe } from 'node:test';
import assert from 'node:assert/strict';

import {
  flatten,
  reNest,
  asArray,
  seedFromPlaceholder,
} from '../../webroot/js/dashboard/kvshape.module.mjs';

// ---- flatten ----

describe('flatten', () => {
  test('empty object → empty result', () => {
    assert.deepEqual(flatten({}), {});
  });

  test('flat scalar leaves are JSON-stringified', () => {
    assert.deepEqual(flatten({ a: 1, b: 'two', c: true, d: null }), {
      a: '1',
      b: '"two"',
      c: 'true',
      d: 'null',
    });
  });

  test('nested object produces dot paths', () => {
    assert.deepEqual(flatten({ a: { b: 1, c: 2 } }), {
      'a.b': '1',
      'a.c': '2',
    });
  });

  test('multi-level nesting', () => {
    assert.deepEqual(flatten({ a: { b: { c: 'x' } } }), {
      'a.b.c': '"x"',
    });
  });

  test('array values are JSON-stringified at the leaf', () => {
    assert.deepEqual(flatten({ tags: ['a', 'b'] }), {
      tags: '["a","b"]',
    });
  });

  test('numeric array at a leaf', () => {
    assert.deepEqual(flatten({ local: [0, 1] }), {
      local: '[0,1]',
    });
  });

  test('empty nested object is preserved as "{}"', () => {
    assert.deepEqual(flatten({ a: {} }), { a: '{}' });
  });

  test('empty array at leaf is "[]"', () => {
    assert.deepEqual(flatten({ a: [] }), { a: '[]' });
  });

  test('mixed nesting + arrays + scalars in one object', () => {
    assert.deepEqual(flatten({
      filter: { type: 'Member', local: [0, 1] },
      threshold: 10,
    }), {
      'filter.type': '"Member"',
      'filter.local': '[0,1]',
      threshold: '10',
    });
  });

  test('boolean leaves stringify correctly', () => {
    assert.deepEqual(flatten({ active: true, hidden: false }), {
      active: 'true',
      hidden: 'false',
    });
  });

  test('string with embedded quote stays JSON-safe', () => {
    assert.deepEqual(flatten({ a: 'he said "hi"' }), {
      a: '"he said \\"hi\\""',
    });
  });

  test('reusing the out accumulator across calls is supported', () => {
    // The function signature exposes the accumulator; calling code
    // doesn't rely on this in production but the contract works.
    const out = { existing: '"keep"' };
    flatten({ added: 1 }, '', out);
    assert.deepEqual(out, { existing: '"keep"', added: '1' });
  });
});

// ---- reNest ----

describe('reNest', () => {
  test('empty input → empty object', () => {
    assert.deepEqual(reNest({}), {});
  });

  test('single flat leaf JSON-parses', () => {
    assert.deepEqual(reNest({ a: '1' }), { a: 1 });
  });

  test('dot-path key becomes nested object', () => {
    assert.deepEqual(reNest({ 'a.b': '1' }), { a: { b: 1 } });
  });

  test('multiple keys under same parent merge', () => {
    assert.deepEqual(reNest({ 'a.b': '1', 'a.c': '2' }), {
      a: { b: 1, c: 2 },
    });
  });

  test('non-JSON value falls back to raw string', () => {
    assert.deepEqual(reNest({ a: 'not json' }), { a: 'not json' });
  });

  test('JSON array string is parsed to array', () => {
    assert.deepEqual(reNest({ a: '[1,2,3]' }), { a: [1, 2, 3] });
  });

  test('JSON null is parsed to actual null', () => {
    assert.deepEqual(reNest({ a: 'null' }), { a: null });
  });

  test('JSON booleans parse', () => {
    assert.deepEqual(reNest({ a: 'true', b: 'false' }), { a: true, b: false });
  });

  test('quoted string parses to unquoted string', () => {
    assert.deepEqual(reNest({ a: '"hello"' }), { a: 'hello' });
  });

  test('empty object JSON literal "{}" parses to empty object', () => {
    assert.deepEqual(reNest({ a: '{}' }), { a: {} });
  });

  test('multi-level dot-path nests correctly', () => {
    assert.deepEqual(reNest({ 'a.b.c': '1' }), { a: { b: { c: 1 } } });
  });

  test('conflicting prefix/leaf — later key wins', () => {
    // Key "a.b" defines a as an object containing b; the later "a"
    // key reassigns a to a scalar (last write wins).
    assert.deepEqual(reNest({ 'a.b': '1', a: '2' }), { a: 2 });
  });

  test('intermediate non-object is replaced when nested path arrives', () => {
    // The reverse of the prior test: scalar a first, then a.b. The
    // function detects cur[parts[i]] isn't a plain object and
    // overwrites with a fresh one, so the deeper write wins.
    assert.deepEqual(reNest({ a: '2', 'a.b': '1' }), { a: { b: 1 } });
  });
});

// ---- round trip ----

describe('round-trip: reNest(flatten(x)) === x', () => {
  // The lossless contract called out in the Phase 2 tracker entry.

  function roundTrip(label, input) {
    test(label, () => {
      assert.deepEqual(reNest(flatten(input)), input);
    });
  }

  roundTrip('empty object', {});
  roundTrip('scalar leaves',
    { a: 1, b: 'two', c: true, d: null, e: false });
  roundTrip('nested object',
    { filter: { type: 'Member' } });
  roundTrip('multi-level nesting',
    { a: { b: { c: 'deep' } } });
  roundTrip('numeric array leaf',
    { local: [0, 1] });
  roundTrip('string array leaf',
    { tags: ['tlp:white', 'tlp:green'] });
  roundTrip('mixed-type array',
    { mixed: [1, 'two', true, null] });
  roundTrip('empty object leaf',
    { a: {} });
  roundTrip('empty array leaf',
    { a: [] });
  roundTrip('OrganisationMapWidget placeholder shape',
    { filter: { type: 'Member', local: [0, 1] } });
  roundTrip('multiple top-level keys',
    { time_window: '7d', threshold: 10, over_time: false });
  roundTrip('object inside array stays as array',
    { logs: [{ id: 1 }, { id: 2 }] });
  // Strings that look like JSON tokens round-trip cleanly because
  // flatten JSON-stringifies them (double-encoded) and reNest
  // unwraps once.
  roundTrip('string containing brackets',
    { a: '[not actually an array]' });
  roundTrip('string containing braces',
    { a: '{not an object}' });
  roundTrip('string "true" as literal', { a: 'true' });
  roundTrip('string "null" as literal', { a: 'null' });
});

// ---- asArray ----

describe('asArray', () => {
  test('null on non-string input', () => {
    assert.equal(asArray(null), null);
    assert.equal(asArray(undefined), null);
    assert.equal(asArray(42), null);
    assert.equal(asArray(['a', 'b']), null);
    assert.equal(asArray({}), null);
  });

  test('null on string that does not start with [', () => {
    assert.equal(asArray('foo'), null);
    assert.equal(asArray('{"a":1}'), null);
    assert.equal(asArray(''), null);
  });

  test('parses a valid JSON array', () => {
    assert.deepEqual(asArray('[1,2,3]'), [1, 2, 3]);
    assert.deepEqual(asArray('["a","b"]'), ['a', 'b']);
    assert.deepEqual(asArray('[]'), []);
  });

  test('tolerates leading/trailing whitespace', () => {
    assert.deepEqual(asArray('  [1,2]  '), [1, 2]);
  });

  test('null on malformed bracket-string', () => {
    assert.equal(asArray('[invalid'), null);
    assert.equal(asArray('[1,2,'), null);
  });

  test('null when bracket-prefix parses to non-array', () => {
    // Pathological: a JSON literal starting with [ but parsing to
    // something else — JSON doesn't allow that, so this is dead-
    // weight defensiveness, but the contract honours it.
    assert.equal(asArray('[1, 2]xxx'), null); // trailing garbage
  });

  test('numeric inside array preserved as numbers', () => {
    const result = asArray('[0, 1]');
    assert.deepEqual(result, [0, 1]);
    assert.equal(typeof result[0], 'number');
  });
});

// ---- seedFromPlaceholder ----

describe('seedFromPlaceholder', () => {
  test('empty / non-string input returns empty array', () => {
    assert.deepEqual(seedFromPlaceholder('', new Set()), []);
    assert.deepEqual(seedFromPlaceholder(null, new Set()), []);
    assert.deepEqual(seedFromPlaceholder(undefined, new Set()), []);
    assert.deepEqual(seedFromPlaceholder(42, new Set()), []);
  });

  test('malformed JSON returns empty array (matches MISP legacy ' +
       'placeholders with trailing commas / unescaped quotes)', () => {
    const malformed = '{"a": "b",}'; // trailing comma
    assert.deepEqual(seedFromPlaceholder(malformed, new Set()), []);
  });

  test('non-object JSON returns empty array', () => {
    assert.deepEqual(seedFromPlaceholder('[1,2,3]', new Set()), []);
    assert.deepEqual(seedFromPlaceholder('"plain string"', new Set()), []);
    assert.deepEqual(seedFromPlaceholder('null', new Set()), []);
  });

  test('plain object becomes flat dot-notation entries', () => {
    const raw = '{"threshold": 10, "filter": {"type": "Member"}}';
    const result = seedFromPlaceholder(raw, new Set());
    assert.deepEqual(result, [
      ['threshold', '10'],
      ['filter.type', '"Member"'],
    ]);
  });

  test('handledKeys filter drops schema-handled top-level keys', () => {
    const raw = '{"threshold": 10, "filter": {"type": "Member"}}';
    const handled = new Set(['threshold']);
    const result = seedFromPlaceholder(raw, handled);
    assert.deepEqual(result, [
      ['filter.type', '"Member"'],
    ]);
  });

  test('arrays at leaves survive flatten and stay editable as chips ' +
       '(asArray will pick them up downstream)', () => {
    const raw = '{"filter": {"local": [0, 1]}}';
    const result = seedFromPlaceholder(raw, new Set());
    assert.deepEqual(result, [
      ['filter.local', '[0,1]'],
    ]);
    // Verify the value is asArray-detectable so the chip-input path
    // fires on first render.
    assert.deepEqual(asArray(result[0][1]), [0, 1]);
  });

  test('missing handledKeys param is tolerated (defensive)', () => {
    // The kvshape helper guards against missing `.has` so callers
    // that forget to pass a Set don't blow up.
    const raw = '{"a": 1}';
    assert.deepEqual(seedFromPlaceholder(raw, undefined), [['a', '1']]);
    assert.deepEqual(seedFromPlaceholder(raw, null), [['a', '1']]);
  });
});
