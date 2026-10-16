// Unit tests for the value Neighbourhood graph (value-neighbourhood.js on
// pivot-explorer.js).
//
//   node tests/js/value-neighbourhood.test.js
//
// Zero dependencies. The explorer and the value host run for real in a vm
// with a DOM stub; the seed fetch answers with a fixture and the test reads
// the {nodes, edges} and options handed to `new Pivotick()`.

'use strict';

const fs = require('fs');
const path = require('path');
const vm = require('vm');
const assert = require('assert');

const JS = path.join(__dirname, '..', '..', 'app', 'webroot', 'js');
const read = f => fs.readFileSync(path.join(JS, f), 'utf8');
const MODULES = ['misp-pivot-nodes.js', 'pivot-sidebar-model.js', 'pivot-sidebar-view.js',
                 'pivot-explorer.js', 'value-neighbourhood.js'].map(f => [f, read(f)]);

function makeEl(tag) {
    return {
        tagName: String(tag).toUpperCase(), className: '', children: [], style: {}, attrs: {},
        dataset: {}, _listeners: {},
        getContext() { return { font: '', measureText: s => ({ width: String(s).length * 6 }) }; },
        appendChild(c) { this.children.push(c); return c; },
        insertBefore(c) { this.children.unshift(c); return c; },
        get firstChild() { return this.children[0] || null; },
        removeChild(c) { this.children = this.children.filter(x => x !== c); return c; },
        focus() {},
        setAttribute(k, v) { this.attrs[k] = String(v); },
        getAttribute(k) { return k in this.attrs ? this.attrs[k] : null; },
        addEventListener(t, f) { (this._listeners[t] = this._listeners[t] || []).push(f); },
        removeEventListener() {},
        querySelector() { return null; },
        getBoundingClientRect() { return { top: 0, bottom: 0 }; },
        classList: { add() {}, remove() {}, contains() { return false; } },
        set textContent(v) { this._text = v; }, get textContent() { return this._text || ''; },
        set innerHTML(v) { this._html = v; }, get innerHTML() { return this._html || ''; },
    };
}

/** Run the value host against `seed`; resolves to what it built. */
function build(seed, routes) {
    let constructed = null;
    const fetchLog = [];
    const errors = [];
    const sandbox = {
        document: {
            readyState: 'complete', getElementById: () => null, createElement: makeEl,
            createTextNode: t => ({ textContent: String(t) }), addEventListener() {},
            documentElement: makeEl('html'), body: makeEl('body'), head: makeEl('head'),
        },
        window: {
            Pivotick: function Pivotick(container, data, opts) {
                const live = {};
                const index = nodes => (nodes || []).forEach(n => {
                    const potentials = new Map();
                    live[n.id] = { id: n.id, getData: () => n.data,
                                   setPotential(id, c) { potentials.set(id, c); }, potentials };
                    index(n.children);
                });
                index(data.nodes);
                this.getMutableNode = id => live[id];
                this.getMutableNodes = () => Object.values(live);
                this.getMutableEdges = () => [];
                const listeners = this.listeners = {};
                this.on = (evt, f) => { (listeners[evt] = listeners[evt] || []).push(f); };
                this.addLive = n => { index([n]); (listeners.nodeAdd || []).forEach(f => f()); };
                this.pivots = { invalidate() {} };
                const root = makeEl('div');
                this.UIManager = { getRootContainer: () => root };
                constructed = { data, opts, graph: this, live };
            },
            location: { href: '' }, addEventListener() {}, requestAnimationFrame: f => f(),
            open() {}, navigator: {},
        },
        fetch: (url, init) => {
            fetchLog.push({ url: String(url), init: init || {} });
            const route = (routes || []).find(r => r[0].test(String(url)));
            const body = route ? route[1](init) : seed;
            return Promise.resolve({ ok: true, status: 200, json: () => Promise.resolve(body) });
        },
        console: { log() {}, warn() {}, error: (...a) => errors.push(a.map(String).join(' ')) },
        Promise, JSON, Object, String, Number, Array, Math, RegExp, Error, Map, Set,
        encodeURIComponent, setTimeout, AbortController,
        MutationObserver: function () { this.observe = function () {}; },
    };
    sandbox.globalThis = sandbox;
    vm.createContext(sandbox);
    MODULES.forEach(([f, src]) => vm.runInContext(src, sandbox, { filename: f }));
    const explorer = sandbox.window.MispValueNeighbourhood.explorer({
        value: seed.value.value, b64: seed.value.b64, baseurl: '/misp',
        containerEl: makeEl('div'), loaderEl: makeEl('div'),
    });
    explorer.init();
    return new Promise(res => setTimeout(res, 0)).then(() => {
        assert.deepStrictEqual(errors, [], 'no errors while building: ' + errors.join(' | '));
        assert.ok(constructed, 'Pivotick was constructed');
        return Object.assign(constructed, { fetchLog, sandbox, explorer });
    });
}

/* ─────────────────────────── fixture ──────────────────────────── */

const card = (id, uuid, info) => ({ id: String(id), uuid, info, date: '2026-09-01',
    Orgc: { name: 'CIRCL', uuid: 'org-1' }, Tag: [], Galaxy: [] });
const attr = (uuid, value, extra) => Object.assign({ id: uuid.length, uuid, value, type: 'ip-dst',
    category: 'Network activity', to_ids: true, deleted: false, Tag: [] }, extra);

function seed(overrides) {
    return Object.assign({
        value: { value: '8.8.8.8', b64: 'OC44LjguOA==', types: ['ip-dst'] },
        Object: [{
            id: '11', uuid: 'obj-pdns', name: 'passive-dns', 'meta-category': 'network',
            event_id: '1', template_uuid: 'tpl', template_version: '1', holds: ['a-rdata'],
            Attribute: [attr('a-rdata', '8.8.8.8', { object_relation: 'rdata', event_id: '1' }),
                        attr('a-rrname', 'dns.example', { object_relation: 'rrname', type: 'domain', event_id: '1' })],
        }],
        Attribute: [attr('a-plain', '8.8.8.8', { event_id: '2', comment: 'resolver\nsecond line' }),
                    attr('a-free', '8.8.8.8', { event_id: '2', Relationship: [{
            uuid: 'rel-1', relationship_type: 'derived-from', related_object_type: 'Event',
            related_object_uuid: 'ev-9', authors: 'a@b', orgc_uuid: 'org-1',
            related_object: { Event: { id: '9', uuid: 'ev-9', info: 'Elsewhere', Orgc: { name: 'X' } } },
        }] })],
        events: { 1: card(1, 'ev-1', 'Passive DNS dump'), 2: card(2, 'ev-2', 'Resolver list'),
                  3: card(3, 'ev-3', 'Far event') },
        references: [{ uuid: 'ref-1', object_uuid: 'obj-pdns', referenced_uuid: 'obj-far',
                       referenced_type: 'object', relationship_type: 'resolves-to' }],
        far: { objects: [{ id: '30', uuid: 'obj-far', name: 'domain-ip', event_id: '3',
                           Attribute: [attr('a-far', 'dns.example', { type: 'domain', event_id: '3' })] }],
               attributes: [] },
        Feed: [{ id: '5', name: 'CIRCL OSINT Feed', source_format: 'misp', event_uuids: ['fe-1'] }],
        Server: [{ id: '7', name: 'Training Main' }],
        near: [{ value: '8.8.8.0/24', b64: 'OC44LjguMC8yNA==', engine: 'cidr', closeness: 24, event_id: 4 }],
        ui_priorities: {},
        meta: { occurrences: { total: 40, units: 30, seeded: 2 }, budget: 60,
                facets: { template: {}, org: [], year: {} } },
    }, overrides);
}

/* ─────────────────────────── tests ────────────────────────────── */

const tests = [];
const test = (name, fn) => tests.push([name, fn]);
const byId = (built, id) => built.data.nodes.find(n => n.id === id);
const edgesOf = (built, kind) => built.data.edges.filter(e => e.data.kind === kind);

test('the seed is fetched from the value graph endpoint', () => build(seed()).then(b => {
    assert.strictEqual(b.fetchLog[0].url, '/misp/values/graph/OC44LjguOA%3D%3D.json');
}));

test('the value sits at the centre as a value node', () => build(seed()).then(b => {
    const v = byId(b, 'value:OC44LjguOA==');
    assert.ok(v);
    assert.strictEqual(v.data.type, 'value');
    assert.strictEqual(v.data.centre, true);
    assert.strictEqual(v.data.label, '8.8.8.8');
}));

test('an object holding the value lands closed, joined by the relation it files it under', () => build(seed()).then(b => {
    const o = byId(b, 'obj:obj-pdns');
    assert.ok(o && o.children.length === 2);
    assert.strictEqual(o.children.find(c => c.id === 'attr:a-rdata').data.holds_value, true);
    assert.strictEqual(o.children.find(c => c.id === 'attr:a-rrname').data.holds_value, undefined);
    const occ = edgesOf(b, 'occurrence').find(e => e.to === 'obj:obj-pdns');
    assert.strictEqual(occ.from, 'value:OC44LjguOA==');
    assert.strictEqual(occ.data.label, 'rdata');
}));

test('an event-level occurrence lands as its attribute, labelled by type', () => build(seed()).then(b => {
    assert.ok(byId(b, 'attr:a-free'));
    const occ = edgesOf(b, 'occurrence').find(e => e.to === 'attr:a-free');
    assert.strictEqual(occ.data.label, 'ip-dst');
}));

test('every occurrence sits beside its event card', () => build(seed()).then(b => {
    const inEvent = edgesOf(b, 'in-event').map(e => e.from + '>' + e.to);
    assert.ok(inEvent.includes('obj:obj-pdns>event:ev-1'));
    assert.ok(inEvent.includes('attr:a-free>event:ev-2'));
    assert.ok(inEvent.includes('obj:obj-far>event:ev-3'));
}));

test('nothing is "this event": every element is another event\'s', () => build(seed()).then(b => {
    ['obj:obj-pdns', 'attr:a-free', 'obj:obj-far'].forEach(id => assert.strictEqual(byId(b, id).data.scope, 'foreign'));
}));

test('a reference reaches its far end, drawn with its event', () => build(seed()).then(b => {
    const ref = edgesOf(b, 'object-reference');
    assert.strictEqual(ref.length, 1);
    assert.strictEqual(ref[0].to, 'obj:obj-far');
    assert.strictEqual(ref[0].data.label, 'resolves-to');
}));

test('an analyst relationship draws its far end', () => build(seed()).then(b => {
    const rel = edgesOf(b, 'analyst-relationship');
    assert.strictEqual(rel.length, 1);
    assert.strictEqual(rel[0].from, 'attr:a-free');
    assert.strictEqual(rel[0].to, 'event:ev-9');
    assert.ok(byId(b, 'event:ev-9'));
}));

const clusterSeed = () => {
    const s = seed();
    s.Attribute[0].Relationship = [{
        uuid: 'rel-2', relationship_type: 'related-to', related_object_type: 'GalaxyCluster',
        related_object_uuid: 'gc-1', authors: 'a@b', orgc_uuid: 'org-1',
        related_object: { GalaxyCluster: { uuid: 'gc-1', value: 'APT1', type: 'threat-actor',
            tag_name: 'misp-galaxy:threat-actor="APT1"', Galaxy: { name: 'Threat Actor' } } },
    }];
    return s;
};
const APT1 = 'cluster:misp-galaxy:threat-actor="APT1"';

test('a claim on a galaxy cluster draws the cluster', () => build(clusterSeed()).then(b => {
    const rel = edgesOf(b, 'analyst-relationship').find(e => e.to === APT1);
    assert.strictEqual(rel.from, 'attr:a-plain');
    const c = byId(b, APT1);
    assert.strictEqual(c.data.type, 'cluster');
    assert.strictEqual(c.data.value, 'APT1');
}));

test('a claimed cluster is a lead, named by its galaxy', () => build(clusterSeed()).then(b => {
    const L = b.sandbox.window.MispValueNeighbourhood.leads(clusterSeed(), b.explorer.kit);
    const end = L.ends.find(e => e.id === APT1);
    assert.strictEqual(end.type, 'cluster');
    assert.strictEqual(end.name, 'Threat Actor');
    assert.strictEqual(end.label, 'APT1');
}));

test('feeds and servers that know the value point at it', () => build(seed()).then(b => {
    assert.strictEqual(edgesOf(b, 'feed-correlation')[0].from, 'feed:5');
    assert.strictEqual(edgesOf(b, 'feed-correlation')[0].to, 'value:OC44LjguOA==');
    assert.strictEqual(edgesOf(b, 'server-correlation')[0].from, 'server:7');
}));

test('a near value is a value node on a near edge', () => build(seed()).then(b => {
    const n = byId(b, 'value:OC44LjguMC8yNA==');
    assert.ok(n && n.data.type === 'value' && !n.data.centre);
    assert.strictEqual(edgesOf(b, 'near')[0].data.label, 'in /24');
}));

test('the rest of the occurrences sit on the value\'s rim', () => build(seed()).then(b => {
    assert.strictEqual(b.live['value:OC44LjguOA=='].potentials.get('more-occurrences'), 27);
}));

test('no rim count once everything is drawn', () => build(seed({ meta: { occurrences: { units: 3, seeded: 3 } } })).then(b => {
    assert.strictEqual(b.live['value:OC44LjguOA=='].potentials.get('more-occurrences') || 0, 0);
}));

test('the rim count shrinks as occurrences land', () => build(seed()).then(b => {
    b.graph.addLive({ id: 'attr:landed', data: { type: 'attribute', occurrence_of: 'value:OC44LjguOA==' } });
    assert.strictEqual(b.live['value:OC44LjguOA=='].potentials.get('more-occurrences'), 26);
}));

test('an occurrence a reference or claim leaves is a lead; a plain one is not', () => build(seed()).then(b => {
    assert.strictEqual(byId(b, 'obj:obj-pdns').data.lead, true);
    assert.strictEqual(byId(b, 'attr:a-free').data.lead, true);
    assert.strictEqual(byId(b, 'attr:a-plain').data.lead, undefined);
    const occ = to => edgesOf(b, 'occurrence').find(e => e.to === to);
    assert.strictEqual(occ('obj:obj-pdns').data.lead, true);
    assert.strictEqual(occ('attr:a-plain').data.lead, undefined);
    assert.strictEqual(b.opts.render.edgeTypeAccessor({ getData: () => occ('obj:obj-pdns').data }), 'occurrence-lead');
    assert.strictEqual(b.opts.render.edgeTypeAccessor({ getData: () => occ('attr:a-plain').data }), 'occurrence');
}));

test('leads are gathered by far end, new things first', () => build(seed()).then(b => {
    const L = b.sandbox.window.MispValueNeighbourhood.leads(seed(), b.explorer.kit);
    assert.deepStrictEqual(Array.from(L.leadUnits, u => u.id).sort(), ['attr:a-free', 'obj:obj-pdns']);
    assert.deepStrictEqual(Array.from(L.ends, e => e.id), ['obj:obj-far', 'event:ev-9']);
    assert.strictEqual(L.ends[0].via[0].rel, 'resolves-to');
    assert.strictEqual(L.ends[0].via[0].dir, 'out');
    assert.strictEqual(L.ends[0].label, 'dns.example');
}));

test('the by-event rule folds an event\'s plain occurrences and leaves leads free', () => build(seed()).then(b => {
    const rule = b.opts.UI.simplify.rules.find(r => r.id === 'by-event');
    assert.ok(rule && rule.minSize === 3);
    const node = (id, data) => ({ id, getData: () => data });
    const ev = node('event:ev-2', { type: 'event' });
    const plain = node('attr:p', { type: 'attribute', occurrence_of: 'value:x' });
    const lead = node('attr:l', { type: 'attribute', occurrence_of: 'value:x', lead: true });
    const far = node('attr:f', { type: 'attribute' });
    const view = { nodes: [plain, lead, far, ev], groupOf: () => null,
                   outNeighbours: () => [ev], inNeighbours: () => [] };
    const out = rule.partition(view);
    assert.deepStrictEqual(Array.from(out.entries()), [['attr:p', 'event:event:ev-2']]);
    const order = Array.from(b.opts.UI.simplify.rules, r => r.id || r.kind);
    assert.strictEqual(order.indexOf('by-event'), order.indexOf('landings') + 1);
}));

test('the graph opens as a horizontal tree from the value, rim counts shown', () => build(seed()).then(b => {
    assert.strictEqual(b.opts.layout.type, 'tree');
    assert.strictEqual(b.opts.layout.horizontal, true);
    assert.strictEqual(b.opts.layout.rootId, 'value:OC44LjguOA==');
    assert.strictEqual(b.opts.pivotRimBadgeVisible, 'always');
    // Too big to fit legibly: open at the cards' zoom, on the value.
    assert.strictEqual(b.opts.render.minFitScale, 0.82);
    assert.strictEqual(b.opts.render.fitAnchor, 'value:OC44LjguOA==');
}));

test('stories: one per event, newest first, with roles, links and context', () => build(seed()).then(b => {
    const V = b.sandbox.window.MispValueNeighbourhood;
    // Same date: the event holding the value more often comes first.
    assert.deepStrictEqual(Array.from(V.stories(seed()), s => s.id), ['2', '1']);
    const s = seed();
    s.events[1].date = '2026-09-20';
    const list = V.stories(s);
    assert.deepStrictEqual(Array.from(list, x => x.id), ['1', '2']);
    const pdns = list[0];
    assert.strictEqual(pdns.roles[pdns.roleOrder[0]].label.rel, 'rdata');
    assert.strictEqual(pdns.links[0].rel, 'resolves-to');
    assert.strictEqual(pdns.links[0].name, 'domain-ip');
    assert.strictEqual(list[1].count, 2);
    assert.strictEqual(list[1].notes[0], 'resolver');
    assert.strictEqual(list[1].claims, 1);
}));

test('no provenance: no "this event" legend or facet', () => build(seed()).then(b => {
    const sections = b.opts.UI.legend.sections.map(s => s.id || s.title);
    assert.ok(!sections.includes('provenance'));
    assert.ok(!b.opts.UI.filter.facets.some(f => f.key === 'scope'));
}));

test('read-only: nothing is drawn or deleted', () => build(seed()).then(b => {
    assert.strictEqual(b.opts.UI.editors.edgeCreator.enabled, false);
    assert.strictEqual(b.opts.UI.editors.deletion.enabled, false);
}));

test('the value\'s pivots, and none that need a page event', () => build(seed()).then(b => {
    const ids = b.opts.pivots.map(p => p.id);
    ['more-occurrences', 'where-else', 'feed-events', 'tags', 'tagged-events', 'related-clusters',
     'object-surroundings', 'card-ids', 'card-network', 'card-attributes'].forEach(id => assert.ok(ids.includes(id), id));
    ['event-elements', 'correlations', 'card-correlations'].forEach(id => assert.ok(!ids.includes(id), id));
}));

test('value nodes draw, and occurrence and near edges are styled', () => build(seed()).then(b => {
    assert.ok(b.opts.render.nodeStyleMap.value);
    assert.ok(b.opts.render.edgeStyleMap.occurrence);
    assert.ok(b.opts.render.edgeStyleMap.near.dashed);
}));

test('the payload handed to the explorer holds every record drawn', () => build(seed()).then(b => {
    const p = b.sandbox.window.MispValueNeighbourhood.payloadOf(seed());
    assert.deepStrictEqual(Array.from(p.Event.Object, o => o.uuid), ['obj-pdns', 'obj-far']);
    assert.deepStrictEqual(Array.from(p.Event.Attribute, a => a.uuid), ['a-plain', 'a-free']);
}));

function moreOccurrences(b) {
    return b.opts.pivots.find(p => p.id === 'more-occurrences');
}

test('more occurrences applies to value nodes only', () => build(seed()).then(b => {
    const p = moreOccurrences(b);
    const applies = p.appliesTo(b.graph.getMutableNodes()).map(n => n.id).sort();
    assert.deepStrictEqual(applies, ['value:OC44LjguMC8yNA==', 'value:OC44LjguOA==']);
}));

test('more occurrences counts with facets, excluding what is drawn', () => {
    let posted = null;
    const routes = [[/graphOccurrences/, init => {
        posted = JSON.parse(init.body);
        return { total: 28, by_template: { 'passive-dns': 20, '': 8 },
                 by_org: [{ id: 9, name: 'CIRCL', count: 28 }], by_year: { 2025: 10, 2026: 18 } };
    }]];
    return build(seed(), routes).then(b => {
        const centre = b.graph.getMutableNode('value:OC44LjguOA==');
        return moreOccurrences(b).summarize([centre], { year: ['2026'] }, {}).then(s => {
            assert.deepStrictEqual(posted.values, ['8.8.8.8']);
            assert.strictEqual(posted.count, true);
            assert.deepStrictEqual(posted.year, ['2026']);
            assert.ok(posted.exclude.includes('obj-pdns') && posted.exclude.includes('a-free'));
            assert.strictEqual(s.total, 28);
            const template = s.facets.find(f => f.key === 'template');
            assert.deepStrictEqual(template.options.map(o => o.label), ['passive-dns', 'Not in an object']);
            assert.strictEqual(s.facets.find(f => f.key === 'org').options[0].value, '9');
        });
    });
});

test('more occurrences says the window it lands and the whole set it matched', () => {
    const routes = [[/graphOccurrences/, () => ({ total: 48195, by_template: {}, by_org: [], by_year: {} })]];
    return build(seed(), routes).then(b => {
        const centre = b.graph.getMutableNode('value:OC44LjguOA==');
        return moreOccurrences(b).summarize([centre], {}, {}).then(s => {
            assert.strictEqual(s.total, 200);
            assert.strictEqual(s.matched, 48195);
            assert.strictEqual(moreOccurrences(b).maxCandidates, 200);
        });
    });
});

test('more occurrences lands units joined to the value that holds them', () => {
    const routes = [[/graphOccurrences/, () => ({
        Object: [{ id: '40', uuid: 'obj-new', name: 'domain-ip', event_id: '6', holds: ['a-n1'],
                   Attribute: [attr('a-n1', '8.8.8.8', { object_relation: 'ip', event_id: '6' })] }],
        Attribute: [attr('a-n2', '8.8.8.8', { event_id: '7' })],
        events: { 6: card(6, 'ev-6', 'Six'), 7: card(7, 'ev-7', 'Seven') },
        ui_priorities: {},
    })]];
    return build(seed(), routes).then(b => {
        const centre = b.graph.getMutableNode('value:OC44LjguOA==');
        return moreOccurrences(b).fetch([centre], {}, {}).then(r => {
            const ids = Array.from(r.nodes, n => n.id).sort();
            assert.deepStrictEqual(ids, ['attr:a-n2', 'event:ev-6', 'event:ev-7', 'obj:obj-new']);
            const occ = Array.from(r.edges).filter(e => e.data.kind === 'occurrence');
            assert.deepStrictEqual(Array.from(occ, e => e.from + '>' + e.to).sort(),
                ['value:OC44LjguOA==>attr:a-n2', 'value:OC44LjguOA==>obj:obj-new']);
            assert.strictEqual(occ.find(e => e.to === 'obj:obj-new').data.label, 'ip');
        });
    });
});

test('where else this appears lands a drawn attribute\'s other occurrences as correlations', () => {
    let posted = null;
    const routes = [[/graphOccurrences/, init => {
        posted = JSON.parse(init.body);
        return { Object: [], Attribute: [attr('a-e1', 'dns.example', { type: 'domain', event_id: '8' })],
                 events: { 8: card(8, 'ev-8', 'Eight') }, ui_priorities: {} };
    }]];
    return build(seed(), routes).then(b => {
        const p = b.opts.pivots.find(x => x.id === 'where-else');
        const rrname = b.graph.getMutableNode('attr:a-rrname');
        assert.deepStrictEqual(p.appliesTo([rrname, b.graph.getMutableNode('value:OC44LjguOA==')]).map(n => n.id),
            ['attr:a-rrname']);
        return p.fetch([rrname], {}, {}).then(r => {
            assert.deepStrictEqual(posted.values, ['dns.example']);
            const corr = Array.from(r.edges).filter(e => e.data.kind === 'correlation');
            assert.deepStrictEqual(corr.map(e => e.from + '>' + e.to), ['attr:a-rrname>attr:a-e1']);
        });
    });
});

test('tagged events sends no page event', () => {
    let url = null;
    const routes = [[/taggedEvents/, () => ({ total: 0, events: [] })]];
    return build(seed(), routes).then(b => {
        const p = b.opts.pivots.find(x => x.id === 'tagged-events');
        const tag = { id: 'tag:tlp:clear', getData: () => ({ type: 'tag', name: 'tlp:clear' }) };
        return Promise.resolve(p.fetch([tag], {}, {})).then(() => {
            url = b.fetchLog.map(f => f.url).find(u => /taggedEvents/.test(u));
            assert.strictEqual(url, '/misp/events/taggedEvents/0.json');
        });
    });
});

/* ─────────────────────────── runner ───────────────────────────── */

(async () => {
    let passed = 0, failed = 0;
    for (const [name, fn] of tests) {
        try {
            await fn();
            passed++;
            console.log('  ok   ' + name);
        } catch (e) {
            failed++;
            console.log('  FAIL ' + name + '\n       ' + (e && e.stack || e).split('\n').slice(0, 4).join('\n       '));
        }
    }
    console.log('\n' + (failed ? 'FAILED' : 'OK') + ' — ' + passed + ' passed, ' + failed + ' failed');
    process.exit(failed ? 1 : 0);
})();
