// Event report elements (markdownEditor/event-report.js) are doT templates
// filled with values sanitizeObject() escaped. A report's author controls
// those values, and the templates put some of them in quoted attributes.
//
// Run with:
//   node --test app/Test/js/EventReportElementEscaping.test.mjs

import { test } from 'node:test';
import assert from 'node:assert/strict';

import { file, lines, run } from './browserScript.mjs';

// jQuery's $('</p>').text(value).html(): escapes & < > only.
function $() {
    let text = '';
    return {
        text(value) { text = String(value); return this; },
        html() { return text.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;'); },
    };
}

const page = run([
    file('doT.js'),
    lines('markdownEditor/markdownEditor.js', 'function sanitizeObject(', '}'),
    lines('markdownEditor/event-report.js', 'var dotTemplateSuggestionAttribute = '),
    lines('markdownEditor/event-report.js', 'var dotTemplateTag = '),
].join('\n'), { $ });

/** The attributes of the first tag in html, decoded as a browser would. */
function attributes(html) {
    const tag = /^<[a-z]+((?:\s+[\w-]+(?:="[^"]*")?)*)\s*>/.exec(html);
    assert.ok(tag, `no opening tag in ${html}`);
    const found = {};
    for (const [, name, value = ''] of tag[1].matchAll(/\s+([\w-]+)(?:="([^"]*)")?/g)) {
        found[name] = value
            .replace(/&quot;|&#34;/g, '"')
            .replace(/&#0?39;/g, "'")
            .replace(/&lt;|&#60;/g, '<')
            .replace(/&gt;|&#62;/g, '>')
            .replace(/&#47;/g, '/')
            .replace(/&amp;|&#38;/g, '&');
    }
    return found;
}

test('a suggestion keeps a value with quotes inside its attribute', () => {
    const value = `report.exe" data-planted="1`;
    const html = page.dotTemplateSuggestionAttribute(page.sanitizeObject({
        scope: 'suggestion',
        elementid: value,
        eventid: 1,
        type: 'filename',
        origValue: value,
        value,
        indexStart: 0,
        suggestionkey: 'suggestion-0',
        checked: false,
    }));

    const found = attributes(html);
    assert.deepEqual(Object.keys(found).sort(), ['class', 'data-elementid', 'data-indexstart', 'data-scope', 'data-suggestionkey']);
    assert.equal(found['data-elementid'], value);
});

test('a field the template encodes again is not escaped twice', () => {
    const value = `a&b"c'<d>`;
    const found = attributes(page.dotTemplateTag(page.sanitizeObject({ scope: 'tag', elementid: value, eventid: 1, value })));

    assert.equal(found['data-elementid'], value);
    assert.equal(found['data-scope'], 'tag');
});
