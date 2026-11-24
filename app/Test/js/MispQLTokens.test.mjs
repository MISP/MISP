// Unit tests for the MispQL console's tokenizer and highlighter.
//
// Run with:
//   node --test app/Test/js/MispQLTokens.test.mjs

import { test, describe } from 'node:test';
import assert from 'node:assert/strict';

import {
  WHITE_SPACE,
  cpToIndex,
  indexToCp,
  cpLength,
  tokenize,
  significant,
} from '../../webroot/js/mispql/tokens.mjs';
import { highlightHTML } from '../../webroot/js/mispql/writer.mjs';

describe('Offsets', () => {
  test('code point and string index agree on ASCII', () => {
    assert.equal(cpToIndex('SELECT', 3), 3);
    assert.equal(indexToCp('SELECT', 3), 3);
  });

  test('an emoji is one code point and two string units', () => {
    const s = 'a🦠b';
    assert.equal(s.length, 4);
    assert.equal(cpLength(s), 3);
    assert.equal(cpToIndex(s, 2), 3);
    assert.equal(indexToCp(s, 3), 2);
  });

  test('a combining accent is a code point of its own', () => {
    const s = 'café!';
    assert.equal(cpLength(s), 6);
    assert.equal(cpToIndex(s, 5), 5);
  });
});

describe('White_Space', () => {
  test('all 25 code points separate words in the writer tokenizer', () => {
    assert.equal(WHITE_SPACE.length, 25);
    WHITE_SPACE.forEach((cp) => {
      const toks = significant(tokenize('SELECT' + String.fromCodePoint(cp) + '*'));
      assert.deepEqual(
        toks.map((t) => t.kind),
        ['keyword', 'symbol'],
        'U+' + cp.toString(16),
      );
    });
  });

  test('U+001C-U+001F, ZWSP and BOM are not spaces', () => {
    [0x1C, 0x1D, 0x1E, 0x1F, 0x200B, 0xFEFF].forEach((cp) => {
      const toks = tokenize('SELECT' + String.fromCodePoint(cp) + '*');
      assert.equal(toks[1].kind, 'bad', 'U+' + cp.toString(16));
    });
  });
});

describe('Highlight', () => {
  test('an underline covers exactly the given range, after an emoji', () => {
    const text = "SELECT * FROM events WHERE eventinfo = '🦠' AND id = 'x' LIMIT 1";
    const start = text.indexOf("id = 'x'");
    const end = start + "id = 'x'".length;
    const html = highlightHTML(text, [{ start, end }]);
    const re = /class="[^"]*mq-err[^"]*"[^>]*>([^<]*)</g;
    let under = '';
    let m;
    while ((m = re.exec(html)) !== null) {
      under += m[1].replace(/&#39;/g, "'").replace(/&amp;/g, '&');
    }
    assert.equal(under, "id = 'x'");
  });
});
