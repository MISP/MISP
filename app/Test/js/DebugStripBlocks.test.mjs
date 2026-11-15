// The Overmind debug strip (mispOvermind.js) lists debug blocks it finds in
// response bodies, JSON strings and attribute values. Any stored value can
// look like one, so what it lists is rebuilt from plain markup, never
// imported as it came.
//
// Run with:
//   node --test app/Test/js/DebugStripBlocks.test.mjs

import { test } from 'node:test';
import assert from 'node:assert/strict';

import { lines, run } from './browserScript.mjs';

class FakeText {
    constructor(data) {
        this.nodeType = 3;
        this.data = data;
    }

    get textContent() { return this.data; }
}

class FakeElement {
    constructor(tag, attributes = {}, children = []) {
        this.nodeType = 1;
        this.tagName = tag.toUpperCase();
        this.attributes = { ...attributes };
        this.childNodes = children;
        this.dataset = {};
        this.style = Object.fromEntries((attributes.style || '').split(';')
            .map(declaration => declaration.split(':').map(part => part.trim()))
            .filter(([property]) => property));
        this.classList = Object.assign((attributes.class || '').split(/\s+/).filter(Boolean), {
            add(name) { this.push(name); },
            contains(name) { return this.includes(name); },
        });
    }

    get id() { return this.attributes.id || ''; }
    set href(value) { this.attributes.href = value; }
    get textContent() { return this.childNodes.map(child => child.textContent).join(''); }
    getAttribute(name) { return name in this.attributes ? this.attributes[name] : null; }
    appendChild(child) { this.childNodes.push(child); return child; }
    querySelector() { return null; }
}

const el = (tag, attributes, children) => new FakeElement(tag, attributes, children);
const text = data => new FakeText(data);

function strip() {
    const page = run(lines('mispOvermind.js', 'const DEBUG_BLOCK_SELECTOR', '};') + '\nthis.debugStrip = debugStrip;', {
        Node: { ELEMENT_NODE: 1, ATTRIBUTE_NODE: 2, TEXT_NODE: 3 },
        document: {
            createElement: tag => new FakeElement(tag),
            createTextNode: data => new FakeText(data),
            importNode: node => node,
        },
    });
    return page.debugStrip;
}

test('a block parsed out of a response is rebuilt, not imported', () => {
    const debugStrip = strip();
    const added = [];
    debugStrip.add = content => added.push(content);
    const block = el('pre', { class: 'cake-error', title: 'stored', onclick: 'void 0' }, [
        text('Warning'),
        el('img', { src: 'data:,' }),
    ]);

    debugStrip.adoptParsed(block, 'Page');

    assert.equal(added.length, 1);
    const [copy] = added;
    assert.notEqual(copy, block);
    assert.deepEqual(copy.attributes, {});
    assert.deepEqual([...copy.classList], ['cake-error']);
    assert.deepEqual(copy.childNodes.map(child => child.nodeType), [3, 3]);
});

test('only Cake classes and the display and colour styles are kept', () => {
    const copy = strip().inert(el('div', {
        class: 'cake-error position-fixed',
        style: 'display: none; color: red; background: url(/x)',
    }));

    assert.deepEqual([...copy.classList], ['cake-error']);
    assert.deepEqual({ ...copy.style }, { display: 'none', color: 'red' });
});

test('the Trace, Code and stack trace links still toggle their section', () => {
    const debugStrip = strip();
    const copy = debugStrip.inert(el('pre', { class: 'cake-error' }, [
        el('a', {
            href: 'javascript:void(0);',
            onclick: "document.getElementById('e1-trace').style.display = 'none'",
        }, [el('b', {}, [text('Warning')])]),
        el('a', { href: '#', onclick: "traceToggle(event, 'file-excerpt-0')" }, [text('line 1')]),
        el('div', { id: 'e1-trace', class: 'cake-stack-trace', style: 'display: none;' }, [text('trace')]),
    ]));
    const [link, excerptLink, trace] = copy.childNodes;

    assert.deepEqual(link.attributes, { href: '#' });
    assert.equal(link.dataset.ovDebugToggle, 'e1-trace');
    assert.equal(excerptLink.dataset.ovDebugToggle, 'file-excerpt-0');
    assert.deepEqual(trace.attributes, {});
    assert.equal(trace.dataset.ovDebugId, 'e1-trace');

    const entry = { querySelectorAll: () => [trace] };
    link.closest = selector => (selector === '.ov-debug-entry' ? entry : link);
    debugStrip.toggle({ target: link, preventDefault() {} });
    assert.equal(trace.style.display, '');
});
