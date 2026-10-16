// Unit tests for the galaxy cluster's Pivot Explorer (cluster-pivot-explorer.js
// on pivot-explorer.js).
//
//   node tests/js/cluster-pivot-explorer.test.js
//
// Zero dependencies. The explorer and the cluster host run for real in a vm
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
                 'pivot-explorer.js', 'cluster-pivot-explorer.js'].map(f => [f, read(f)]);

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

/** Run the cluster host against `seed`; resolves to what it built. */
function build(seed, routes, config) {
    let constructed = null;
    const fetchLog = [];
    const errors = [];
    const notices = [];
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
                    live[n.id] = { id: n.id, getData: () => n.data };
                    index(n.children);
                });
                index(data.nodes);
                this.getMutableNode = id => live[id];
                this.getMutableNodes = () => Object.values(live);
                this.getMutableEdges = () => [];
                this.on = () => {};
                this.pivots = { invalidate() {} };
                this.notifier = { info: (title, msg) => notices.push([title, msg]) };
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
    const explorer = sandbox.window.MispClusterPivotExplorer.explorer(Object.assign({
        clusterId: '72473', baseurl: '/misp', containerEl: makeEl('div'), loaderEl: makeEl('div'),
        text: { truncatedTitle: 'Not every relation is drawn', truncated: 'The newest %s each way.' },
    }, config));
    explorer.init();
    return new Promise(res => setTimeout(res, 0)).then(() => {
        assert.deepStrictEqual(errors, [], 'no errors while building: ' + errors.join(' | '));
        assert.ok(constructed, 'Pivotick was constructed');
        return Object.assign(constructed, { fetchLog, notices });
    });
}

/* ─────────────────────────── fixture ──────────────────────────── */

const APT1 = 'cluster:misp-galaxy:threat-actor="APT1"';
const G0006 = 'cluster:misp-galaxy:mitre-intrusion-set="APT1 - G0006"';
const COMMENT = 'cluster:misp-galaxy:threat-actor="Comment Crew"';

const lean = (id, uuid, value, type, galaxy) => ({ id: String(id), uuid, value, type, galaxy_name: galaxy,
    tag_name: 'misp-galaxy:' + type + '="' + value + '"' });

function seed(overrides) {
    return Object.assign({
        cluster: {
            id: '72473', uuid: 'CL-APT1', value: 'APT1', type: 'threat-actor',
            tag_name: 'misp-galaxy:threat-actor="APT1"', description: 'PLA Unit 61398',
            Galaxy: { id: '87', name: 'Threat Actor', type: 'threat-actor' },
            GalaxyElement: [{ key: 'synonyms', value: 'Comment Panda' }],
            Note: [{ uuid: 'note-1', note: 'Reviewed', authors: 'a@b' }],
            Relationship: [{
                uuid: 'rel-out', relationship_type: 'similar-to', authors: 'a@b', orgc_uuid: 'org-1',
                object_type: 'GalaxyCluster', object_uuid: 'CL-APT1',
                related_object_type: 'GalaxyCluster', related_object_uuid: 'CL-CC',
                related_object: { GalaxyCluster: { id: '9', uuid: 'CL-CC', value: 'Comment Crew', type: 'threat-actor',
                    tag_name: 'misp-galaxy:threat-actor="Comment Crew"', Galaxy: { name: 'Threat Actor' } } },
            }],
            RelationshipInbound: [{
                uuid: 'rel-in', relationship_type: 'related-to', authors: 'c@d', orgc_uuid: 'org-2',
                object_type: 'Attribute', object_uuid: 'attr-ip',
                related_object_type: 'GalaxyCluster', related_object_uuid: 'CL-APT1',
                related_object: { Attribute: { id: '5', uuid: 'attr-ip', value: '8.8.8.8', type: 'ip-dst',
                    category: 'Network activity', event_id: '4074',
                    Event: { id: '4074', uuid: 'ev-4074', info: 'Event from DEV2' },
                    Organisation: { name: 'DEV2' } } },
            }],
        },
        outbound: [{ relation: 'similar', cluster: lean(47747, 'CL-G0006', 'APT1 - G0006', 'mitre-intrusion-set',
                                                       'MITRE ATT&CK Groups') }],
        inbound: [{ relation: 'similar', cluster: lean(47747, 'CL-G0006', 'APT1 - G0006', 'mitre-intrusion-set',
                                                      'MITRE ATT&CK Groups') },
                  { relation: 'similar', cluster: lean(72474, 'CL-APT1', 'APT1', 'threat-actor', 'Threat Actor') }],
        totals: { outbound: 1, inbound: 2 },
        budget: 500,
    }, overrides);
}

/* ─────────────────────────── tests ────────────────────────────── */

const tests = [];
const test = (name, fn) => tests.push([name, fn]);
const byId = (built, id) => built.data.nodes.find(n => n.id === id);
const edgesOf = (built, kind) => built.data.edges.filter(e => e.data.kind === kind);
// Arrays built inside the vm carry its realm's prototypes.
const same = (actual, expected) => assert.deepStrictEqual(JSON.parse(JSON.stringify(actual)), expected);

test('the seed is fetched from the cluster graph endpoint, by id', () => build(seed()).then(b => {
    assert.strictEqual(b.fetchLog[0].url, '/misp/galaxy_clusters/graph/72473.json');
}));

test('the cluster sits at the centre, keyed by its tag, with its id and its notes', () => build(seed()).then(b => {
    const c = byId(b, APT1);
    assert.ok(c);
    same([c.data.type, c.data.centre, c.data.cluster_id, c.data.uuid, c.data.galaxy_name],
                           ['cluster', true, '72473', 'CL-APT1', 'Threat Actor']);
    assert.strictEqual(c.data.analyst_count, 1);
}));

test('a galaxy relation runs from the cluster holding it, both ways', () => build(seed()).then(b => {
    const rel = edgesOf(b, 'cluster-relation').map(e => [e.id, e.from, e.to, e.data.label]);
    same(rel, [
        ['clrel:' + APT1 + '>' + G0006 + ':similar', APT1, G0006, 'similar'],
        ['clrel:' + G0006 + '>' + APT1 + ':similar', G0006, APT1, 'similar'],
    ]);
    assert.strictEqual(byId(b, G0006).data.cluster_id, '47747');
}));

test('a relation from a twin carrying the same tag is left out', () => build(seed()).then(b => {
    assert.ok(!edgesOf(b, 'cluster-relation').some(e => e.from === e.to));
    assert.strictEqual(b.data.nodes.filter(n => n.id === APT1).length, 1);
}));

test('an analyst relationship reaches its far end, an attribute beside its event', () => build(seed()).then(b => {
    const rel = edgesOf(b, 'analyst-relationship').map(e => [e.id, e.from, e.to, e.data.label, e.data.orgc]);
    same(rel, [
        ['analyst:rel-out', APT1, COMMENT, 'similar-to', 'org-1'],
        ['analyst:rel-in', 'attr:attr-ip', APT1, 'related-to', 'org-2'],
    ]);
    assert.strictEqual(byId(b, COMMENT).data.cluster_id, '9');
    assert.strictEqual(byId(b, 'attr:attr-ip').data.label, '8.8.8.8');
    assert.ok(edgesOf(b, 'in-event').some(e => e.from === 'attr:attr-ip' && e.to === 'event:ev-4074'));
}));

test('a cluster with nothing linked still opens on itself', () => build(seed({
    cluster: Object.assign(seed().cluster, { Relationship: [], RelationshipInbound: [] }),
    outbound: [], inbound: [], totals: { outbound: 0, inbound: 0 },
})).then(b => {
    same(b.data.nodes.map(n => n.id), [APT1]);
    same(b.data.edges, []);
}));

test('the pivots: both relation directions, analyst relationships, then what a cluster leads to',
    () => build(seed()).then(b => {
        same(b.opts.pivots.map(p => p.id), ['related-clusters', 'relating-clusters',
            'cluster-relationships', 'tagged-events', 'tags', 'feed-events', 'object-surroundings',
            'card-ids', 'card-network', 'card-attributes']);
    }));

test('analyst relationships: offered on a cluster other than the centre, asked by id', () => {
    const other = seed({ cluster: { id: '47747', uuid: 'CL-G0006', value: 'APT1 - G0006', type: 'mitre-intrusion-set',
        tag_name: 'misp-galaxy:mitre-intrusion-set="APT1 - G0006"', RelationshipInbound: [{
            uuid: 'rel-ev', relationship_type: 'attributed-to', object_type: 'Event', object_uuid: 'ev-1',
            related_object_type: 'GalaxyCluster', related_object_uuid: 'CL-G0006',
            related_object: { Event: { id: '1', uuid: 'ev-1', info: 'Campaign' } } }] } });
    return build(seed(), [[/galaxy_clusters\/graph\/47747\.json$/, () => other]]).then(b => {
        const p = b.opts.pivots.find(x => x.id === 'cluster-relationships');
        const centre = b.live[APT1], g0006 = b.live[G0006];
        same(p.appliesTo([centre, g0006]).map(n => n.id), [G0006]);
        return Promise.resolve(p.summarize([g0006], {}, {})).then(s => {
            assert.strictEqual(s.total, 1);
            return p.fetch([g0006], {}, {});
        }).then(r => {
            assert.ok(b.fetchLog.some(f => f.url === '/misp/galaxy_clusters/graph/47747.json'));
            same(r.nodes.map(n => n.id), ['event:ev-1']);
            same(r.edges.filter(e => e.data.kind === 'analyst-relationship').map(e => [e.from, e.to]),
                                   [['event:ev-1', G0006]]);
        });
    });
});

test('relating clusters asks the inbound side of the relations', () => {
    const routes = [[/relatedClusters\/47747\/inbound\.json$/, () => ({ relations: [] })]];
    return build(seed(), routes).then(b => {
        const p = b.opts.pivots.find(x => x.id === 'relating-clusters');
        return Promise.resolve(p.summarize([b.live[G0006]], {}, {})).then(() => {
            assert.ok(b.fetchLog.some(f => f.url === '/misp/galaxy_clusters/relatedClusters/47747/inbound.json'));
        });
    });
});

test('a cluster with more relations than were drawn says so', () => build(seed({
    totals: { outbound: 653, inbound: 2 },
})).then(b => {
    same(b.notices, [['Not every relation is drawn', 'The newest 500 each way.']]);
}));

test('every relation drawn: no notice', () => build(seed()).then(b => {
    same(b.notices, []);
}));

test('nothing to write without the analyst role; relationships with it, never a reference', () =>
    build(seed()).then(b => {
        assert.strictEqual(b.opts.UI.editors.edgeCreator.enabled, false);
        return build(seed(), null, { canAnalyst: true });
    }).then(b => {
        assert.strictEqual(b.opts.UI.editors.edgeCreator.enabled, true);
        assert.strictEqual(b.opts.callbacks.isValidConnection(b.live[APT1], b.live[G0006]), true);
        let form = null;
        const obj = uuid => ({ getData: () => ({ type: 'object', uuid }) });
        return Promise.resolve(b.opts.callbacks.onBeforeEdgeCreate({
            kind: 'edge', source: obj('o1'), target: obj('o2'),
            promptData: f => { form = f; return Promise.resolve(null); },
        })).then(() => {
            const keys = form.fields.map(f => f.key);
            assert.ok(!keys.includes('kind'), 'only one kind on offer: ' + keys.join(','));
            assert.ok(keys.includes('distribution'), 'the analyst relationship form: ' + keys.join(','));
        });
    }));

test('the centre\'s notes reach the analyst panel', () => build(seed()).then(b => {
    assert.ok(b.opts.UI.extraPanels.some(p => p.id === 'analyst-data'));
}));

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
