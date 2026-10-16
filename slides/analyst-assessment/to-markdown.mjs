#!/usr/bin/env node
//
// deck.html -> deck.md
//
//   node to-markdown.mjs [in.html] [out.md]
//
// No dependencies. It reads the same restricted vocabulary the deck is
// written in (see the comment at the top of deck.html), so as long as
// you stay inside that vocabulary an edit to the slides shows up here
// without touching this file.
//
// Slides are separated by `---`, which is what most Markdown slide
// tools (Marp, reveal-md, Slidev, Pandoc's slide formats) read as a
// slide break.

import { readFileSync, writeFileSync } from 'node:fs';

const IN = process.argv[2] || new URL('./deck.html', import.meta.url).pathname;
const OUT = process.argv[3] || new URL('./deck.md', import.meta.url).pathname;

const html = readFileSync(IN, 'utf8');

/* ---- tiny helpers ------------------------------------------------- */

const ENTITIES = {
    amp: '&', lt: '<', gt: '>', quot: '"', '#39': "'", apos: "'",
    nbsp: ' ', mdash: '—', ndash: '–', hellip: '…',
    times: '×', rarr: '→', larr: '←',
};
const unescape = (s) => s.replace(/&(#?\w+);/g, (m, k) =>
    Object.prototype.hasOwnProperty.call(ENTITIES, k) ? ENTITIES[k] : m);

// Collapse runs of whitespace, the way HTML itself does.
const flat = (s) => s.replace(/\s+/g, ' ').trim();

/** Inline HTML -> inline Markdown. */
const inline = (s) => unescape(
    flat(s)
        .replace(/<br\s*\/?>/gi, '\n')
        .replace(/<(strong|b)\b[^>]*>(.*?)<\/\1>/gi, '**$2**')
        .replace(/<(em|i)\b[^>]*>(.*?)<\/\1>/gi, '*$2*')
        .replace(/<code\b[^>]*>(.*?)<\/code>/gi, '`$1`')
        .replace(/<cite\b[^>]*>(.*?)<\/cite>/gi, '— $1')
        .replace(/<a\b[^>]*href="([^"]*)"[^>]*>(.*?)<\/a>/gi, '[$2]($1)')
        .replace(/<[^>]+>/g, '')
).replace(/``/g, '').split('\n').map((l) => l.trim()).join('\n');

/** Every top-level <tag ...>…</tag> inside a chunk, in document order. */
function* blocks(html) {
    const re = /<(section|div|figure|pre|table|ul|ol|blockquote|h1|h2|h3|p)\b([^>]*)>/gi;
    let m;
    let cursor = 0;
    while ((m = re.exec(html)) !== null) {
        if (m.index < cursor) { continue; }
        const tag = m[1].toLowerCase();
        const open = new RegExp(`<${tag}\\b[^>]*>`, 'gi');
        const close = new RegExp(`</${tag}\\s*>`, 'gi');
        // Walk forward counting nested opens until the matching close.
        let depth = 1;
        let i = re.lastIndex;
        let end = -1;
        while (depth > 0) {
            open.lastIndex = i;
            close.lastIndex = i;
            const o = open.exec(html);
            const c = close.exec(html);
            if (!c) { break; }
            if (o && o.index < c.index) { depth++; i = o.index + o[0].length; }
            else { depth--; i = c.index + c[0].length; end = i; }
        }
        if (end === -1) { continue; }
        yield {
            tag,
            attrs: m[2] || '',
            inner: html.slice(re.lastIndex, end - `</${tag}>`.length),
            outer: html.slice(m.index, end),
        };
        cursor = end;
        re.lastIndex = end;
    }
}

const classOf = (attrs) => {
    const m = /class="([^"]*)"/i.exec(attrs);
    return m ? m[1] : '';
};

const attr = (s, name) => {
    const m = new RegExp(`${name}="([^"]*)"`, 'i').exec(s);
    return m ? m[1] : '';
};

/* ---- block renderers ---------------------------------------------- */

function listOf(inner, ordered) {
    const out = [];
    let n = 1;
    for (const item of inner.matchAll(/<li\b[^>]*>([\s\S]*?)<\/li>/gi)) {
        const text = inline(item[1]).replace(/\n/g, ' ');
        out.push((ordered ? `${n++}. ` : '- ') + text);
    }
    return out.join('\n');
}

function tableOf(inner) {
    const rows = [];
    for (const tr of inner.matchAll(/<tr\b[^>]*>([\s\S]*?)<\/tr>/gi)) {
        const cells = [...tr[1].matchAll(/<(th|td)\b[^>]*>([\s\S]*?)<\/\1>/gi)]
            .map((c) => inline(c[2]).replace(/\n/g, ' ').replace(/\|/g, '\\|'));
        if (cells.length) { rows.push(cells); }
    }
    if (!rows.length) { return ''; }
    const head = rows[0];
    const body = rows.slice(1);
    const line = (r) => '| ' + r.join(' | ') + ' |';
    return [
        line(head),
        '| ' + head.map(() => '---').join(' | ') + ' |',
        ...body.map(line),
    ].join('\n');
}

function figureOf(inner) {
    const img = /<img\b[^>]*>/i.exec(inner);
    const cap = /<figcaption\b[^>]*>([\s\S]*?)<\/figcaption>/i.exec(inner);
    const out = [];
    if (img) {
        const src = attr(img[0], 'src');
        const alt = flat(unescape(attr(img[0], 'alt')));
        out.push(`![${alt}](${src})`);
    }
    if (cap) { out.push('*' + inline(cap[1]) + '*'); }
    return out.join('\n\n');
}

function codeOf(inner, attrs) {
    const body = /<code\b[^>]*>([\s\S]*?)<\/code>/i.exec(inner);
    const raw = body ? body[1] : inner;
    const lang = attr(attrs || '', 'data-lang');
    return '```' + lang + '\n'
        + unescape(raw.replace(/<[^>]+>/g, '')).replace(/^\n+|\n+$/g, '')
        + '\n```';
}

function quoteOf(inner) {
    return inline(inner).split('\n')
        .map((l) => '> ' + l).join('\n');
}

/** Render the blocks inside one slide (or one column). */
function render(chunk, depth) {
    const parts = [];
    for (const b of blocks(chunk)) {
        const cls = classOf(b.attrs);
        switch (b.tag) {
            case 'h1':
                parts.push('# ' + inline(b.inner));
                break;
            case 'h2':
                parts.push('## ' + inline(b.inner).replace(/\n/g, ' '));
                break;
            case 'h3':
                parts.push('### ' + inline(b.inner));
                break;
            case 'p': {
                const text = inline(b.inner);
                if (!text) { break; }
                if (/\bkicker\b/.test(cls)) { parts.push('**' + text + '**'); }
                else if (/\bnote\b/.test(cls)) { parts.push('> ' + text); }
                else { parts.push(text); }
                break;
            }
            case 'ul': parts.push(listOf(b.inner, false)); break;
            case 'ol': parts.push(listOf(b.inner, true)); break;
            case 'table': parts.push(tableOf(b.inner)); break;
            case 'figure': parts.push(figureOf(b.inner)); break;
            case 'pre': parts.push(codeOf(b.inner, b.attrs)); break;
            case 'blockquote': parts.push(quoteOf(b.inner)); break;
            case 'div':
                // cols, tiles and tile are pure layout: recurse through.
                parts.push(render(b.inner, depth + 1));
                break;
            default:
                break;
        }
    }
    return parts.filter(Boolean).join('\n\n');
}

/* ---- run ----------------------------------------------------------- */

const title = (/<title>([\s\S]*?)<\/title>/i.exec(html) || [, 'Deck'])[1];
const deck = (/<div id="deck">([\s\S]*)<\/div><!-- \/#deck -->/i.exec(html)
    || [, html])[1];

const out = [`<!-- Generated from deck.html by to-markdown.mjs. `
    + `Edit deck.html, not this file. -->`, '', `<!-- ${unescape(title)} -->`];

let n = 0;
for (const slide of blocks(deck)) {
    if (slide.tag !== 'section') { continue; }
    n++;
    out.push('', '---', '');
    out.push(render(slide.inner, 0));
}

writeFileSync(OUT, out.join('\n').replace(/\n{3,}/g, '\n\n') + '\n');
console.log(`${n} slides -> ${OUT}`);
