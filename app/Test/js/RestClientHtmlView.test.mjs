// The REST client's HTML view (misp.js insertHTMLRestResponse) shows a
// text/html response, which can come from any server the client may query:
// it is rendered in an empty sandbox, never put into the page.
//
// Run with:
//   node --test app/Test/js/RestClientHtmlView.test.mjs

import { test } from 'node:test';
import assert from 'node:assert/strict';

import { lines, run } from './browserScript.mjs';

const RESPONSE = '<p>x<i>y</i></p>';

function page() {
    const created = [];
    const appended = [];
    const html = [];
    function $(arg) {
        if (arg.startsWith('<')) {
            const element = { markup: arg, attrs: {}, attr(name, value) { this.attrs[name] = value; return this; } };
            created.push(element);
            return element;
        }
        return {
            text: () => (arg === '#rest-response-hidden-container' ? RESPONSE : ''),
            append(child) { appended.push(child); return this; },
            html(value) { html.push(value); return this; },
        };
    }
    const context = run(lines('misp.js', 'function insertHTMLRestResponse(', '}'), { $ });
    return { insert: context.insertHTMLRestResponse, created, appended, html };
}

test('the response goes into an empty sandbox, not into the page', () => {
    const { insert, appended, html } = page();

    insert();

    assert.deepEqual(html, []);
    assert.equal(appended.length, 1);
    const [frame] = appended;
    assert.match(frame.markup, /^<iframe\b/);
    const sandbox = /\ssandbox(?:="([^"]*)")?[\s/>]/.exec(frame.markup);
    assert.ok(sandbox, 'no sandbox attribute');
    assert.equal(sandbox[1] ?? '', '');
    assert.equal(frame.attrs.srcdoc, RESPONSE);
});
