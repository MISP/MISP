// Unit tests for the Pivot Explorer graph builder.
//
//   node tests/js/pivot-explorer-graph.test.js
//
// Zero dependencies — plain node, no package.json, no test runner. Exits 0 on
// success, 1 on the first failing assertion's suite.
//
// What this covers: `computeConnectivity()` and `buildGraphData()` in
// app/webroot/js/pivot-explorer.js are pure functions from a MISP event payload
// to pivotick's {nodes, edges}. They are the substance of the layer work in
// docs/dev/pivot-explorer-v16-prd.md §9 (tasks 3, 3b, 3c, 5, 5b), and they need
// no browser — so they are tested here rather than by clicking through
// /events/view. Anything visual (styling, legend, layout) still needs the
// manual pass in PRD §8.
//
// Since task 3c draws every live object, "which level put this object on the
// canvas" shows only once L2 is over budget: the tests that care rebuild the
// event with `fillers(1501)` and check what L1 alone seeds.
//
// How it works: the module is an IIFE with no exports, so rather than reaching
// inside it, we stub just enough DOM for it to boot, resolve its event fetch
// with a fixture, and capture the {nodes, edges} it hands to `new Pivotick()`.
// Assertions therefore run through the real code path, and the module needs no
// test-only seam. The editor tray is read the same way, off the extraPanel the
// module hands over at construction time.

'use strict';

const fs = require('fs');
const path = require('path');
const vm = require('vm');

// PIVOT_EXPLORER_JS overrides the module under test, so the suite can be
// pointed at a deliberately broken copy to check that it still fails.
const MODULE_PATH = process.env.PIVOT_EXPLORER_JS
    || path.join(__dirname, '..', '..', 'app', 'webroot', 'js', 'pivot-explorer.js');
const SRC = fs.readFileSync(MODULE_PATH, 'utf8');
// The node renderers the module requires beside Pivotick, loaded for real.
const NODES_SRC = fs.readFileSync(
    path.join(__dirname, '..', '..', 'app', 'webroot', 'js', 'misp-pivot-nodes.js'), 'utf8');
// The sidebar's view-models and view, which the element loads beside it.
const SIDEBAR_SRC = ['pivot-sidebar-model.js', 'pivot-sidebar-view.js'].map(f => [f, fs.readFileSync(
    path.join(__dirname, '..', '..', 'app', 'webroot', 'js', f), 'utf8')]);

/* ─────────────────────────── DOM stub ─────────────────────────── */

function textNode(t) {
    return { tagName: '#text', _text: String(t), children: [],
             get textContent() { return this._text; } };
}

function makeEl(tag) {
    return {
        tagName: String(tag).toUpperCase(),
        className: '', type: '', placeholder: '', autocomplete: '', value: '',
        children: [], style: {}, attrs: {}, _html: '', _listeners: {},
        // A canvas for the node renderers' text measuring: 6px a character.
        getContext() { return { font: '', measureText: s => ({ width: String(s).length * 6 }) }; },
        appendChild(c) { this.children.push(c); return c; },
        insertBefore(c) { this.children.unshift(c); return c; },
        get firstChild() { return this.children[0] || null; },
        removeChild(c) { this.children = this.children.filter(x => x !== c); return c; },
        setAttribute(k, v) { this.attrs[k] = String(v); },
        getAttribute(k) { return k in this.attrs ? this.attrs[k] : null; },
        addEventListener(t, f) { (this._listeners[t] = this._listeners[t] || []).push(f); },
        removeEventListener() {},
        querySelector() { return null; },
        focus() {},
        // Layout, as a test sets it: `_rect` in viewport coordinates.
        getBoundingClientRect() { return Object.assign({ top: 0, bottom: 0 }, this._rect); },
        classList: {
            _s: new Set(),
            add(c) { this._s.add(c); }, remove(c) { this._s.delete(c); },
            contains(c) { return this._s.has(c); },
        },
        get textContent() { return this.children.map(c => c.textContent).join(''); },
        set textContent(v) { this.children = [textNode(v)]; },
        get innerHTML() { return this._html; },
        set innerHTML(v) { this._html = String(v); if (v === '') this.children = []; },
    };
}

/** Depth-first walk, collecting elements whose className contains `cls`. */
function findByClass(el, cls, out) {
    out = out || [];
    if (el && typeof el.className === 'string' && el.className.split(/\s+/).indexOf(cls) !== -1) {
        out.push(el);
    }
    (el && el.children || []).forEach(c => findByClass(c, cls, out));
    return out;
}

/* ───────────────────────── the driver ─────────────────────────── */

/**
 * Boot the module against `payload` and return what it built.
 * Resolves to { nodes, edges, panel, tray, trayGroups, trayEmptyHtml, errors }.
 */
function buildGraph(payload, options) {
    options = options || {};
    const errors = [];
    const fetchLog = [];
    let constructed = null;

    const card = makeEl('div');
    card.dataset = {
        peEventId: '1',
        peBaseurl: options.baseurl !== undefined ? options.baseurl : '/misp',
        peCanEdit: options.canEdit === false ? '0' : '1',
        peCanAnalyst: options.canAnalyst ? '1' : '0',
        peAnalystSharing: options.analystSharing !== undefined ? options.analystSharing : '',
        peOrgUuid: options.orgUuid || '',
        peSiteAdmin: options.siteAdmin ? '1' : '0',
        peValueCard: options.valueCard ? '1' : '0',
        peCanEnrich: options.canEnrich ? '1' : '0',
        peLibMissing: 'lib missing',
        peLoadFailed: 'load failed',
    };
    const pane = makeEl('div');
    pane.classList.add('active');

    const graphEl = makeEl('div');
    const layout = options.layout || {};
    graphEl._rect = { top: layout.graphTop || 0, bottom: (layout.graphTop || 0) + 720 };
    card._rect = { bottom: graphEl._rect.bottom + (layout.cardBorder || 0) };
    const byId = {
        'pe-card': card,
        'pe-stage': makeEl('div'),
        'pivot-explorer-loader': makeEl('div'),
        'pivot-explorer-graph': graphEl,
        'tab-pivot-explorer': pane,
    };
    const resizers = [];

    const sandbox = {
        document: {
            readyState: 'complete',
            getElementById: id => (id in byId ? byId[id] : null),
            createElement: makeEl,
            createTextNode: textNode,
            addEventListener() {},
            removeEventListener() {},
            documentElement: makeEl('html'),
            body: makeEl('body'),
            head: makeEl('head'),
        },
        window: {
            // Just enough graph for the element pivot to ask what is drawn.
            Pivotick: function Pivotick(container, data, opts) {
                constructed = { data, opts };
                const drawn = {};
                (function index(nodes) {
                    (nodes || []).forEach(n => { drawn[n.id] = n; index(n.children); });
                })(data.nodes);
                this.getNode = id => drawn[id] || undefined;
                this.nodeList = data.nodes.slice();
                this.getNodes = () => this.nodeList;
                // Live nodes, children included, carrying declared potential.
                const live = this.live = {};
                this.liveNode = (raw, sources) => {
                    const potentials = new Map();
                    const vouched = new Set(sources || ['seed']);
                    return live[raw.id] = {
                        id: raw.id, getData: () => raw.data,
                        setPotential(pivotId, count) {
                            if (count) potentials.set(pivotId, count); else potentials.delete(pivotId);
                        },
                        getPotentials: () => potentials,
                        hasSource: s => vouched.has(s),
                        dropSource: s => { vouched.delete(s); return vouched.size === 0; },
                    };
                };
                Object.keys(drawn).forEach(id => this.liveNode(drawn[id]));
                this.getMutableNode = id => live[id];
                this.getMutableNodes = () => Object.keys(live).map(id => live[id]);
                // Edges carry provenance like nodes: what the library's removeBySource reads.
                const liveEdge = (e, sources) => ({
                    id: e.id || e.from + '>' + e.to, from: { id: e.from }, to: { id: e.to },
                    getData: () => e.data, vouched: new Set(sources),
                    hasSource(s) { return this.vouched.has(s); },
                    dropSource(s) { this.vouched.delete(s); return this.vouched.size === 0; },
                });
                const liveEdges = this.liveEdges = data.edges.map(e => liveEdge(e, ['seed']));
                this.getMutableEdges = () => liveEdges.slice();
                this.getMutableEdge = id => liveEdges.find(e => e.id === id);
                this.addedEdges = [];
                this.addEdge = e => { this.addedEdges.push(e); liveEdges.push(liveEdge(e, [])); };
                this.batchChanges = fn => fn();
                this.removedBy = [];
                // The library's rule: drop the claim, delete only what nothing else vouches for.
                this.removeBySource = source => {
                    this.removedBy.push(source);
                    const edges = liveEdges.filter(e => e.hasSource(source) && e.dropSource(source));
                    edges.forEach(e => liveEdges.splice(liveEdges.indexOf(e), 1));
                    const nodes = Object.keys(live).map(id => live[id])
                        .filter(n => n.hasSource(source) && n.dropSource(source));
                    nodes.forEach(n => delete live[n.id]);
                    return { nodes, edges };
                };
                this.renderer = { updates: 0, update() { this.updates++; } };
                this.dataUpdates = [];
                this.updateData = nodes => { this.dataUpdates.push((nodes || []).map(n => n.id)); };
                this.listeners = {};
                this.on = (evt, f) => { (this.listeners[evt] = this.listeners[evt] || []).push(f); };
                // The save ledger: which ids a savable run created, which are written.
                this.pivots = { invalidated: [], invalidate(id) { this.invalidated.push(id); },
                                savable: new Set(), saved: new Set(), saves: [],
                                isSavable(n) { return this.savable.has(n.id); },
                                isSaved(n) { return this.saved.has(n.id); },
                                save(target, options) { this.saves.push([target, options]); return Promise.resolve({}); } };
                this.selected = [];
                this.selectElement = n => { this.selected.push(n); };
                const root = makeEl('div');
                this.UIManager = { sidebar: { shown: 0, showSidebar() { this.shown++; } },
                                   getRootContainer: () => root };
                const notices = this.notices = [];
                this.notifier = {};
                ['success', 'warning', 'error', 'info'].forEach(level => {
                    this.notifier[level] = (title, msg) => notices.push({ level, title, msg });
                });
                constructed.graph = this;
            },
            location: { href: '' },
            innerHeight: layout.innerHeight || 1000,
            scrollY: layout.scrollY || 0,
            getComputedStyle: el => ({ marginBottom: el === card ? (layout.cardMargin || 0) + 'px' : '0px' }),
            addEventListener: (t, f) => { if (t === 'resize') resizers.push(f); },
            requestAnimationFrame: f => f(),
            opened: [],
            open(url, target, features) { this.opened.push([url, target, features]); },
            navigator: options.navigator || {},
            crypto: require('crypto').webcrypto,
        },
        Image: function () { return { src: '' }; },
        fetch: (url, init) => {
            fetchLog.push({ url: String(url), init: init || {} });
            const route = (options.routes || []).find(r => r[0].test(String(url)));
            const body = route ? (typeof route[1] === 'function' ? route[1](init) : route[1]) : payload;
            // A route answering { __status: 500 } stands for a failed request.
            const status = body && body.__status ? body.__status : 200;
            return Promise.resolve({ ok: status < 400, status, json: () => Promise.resolve(body) });
        },
        console: { log() {}, error: (...a) => errors.push(a.map(String).join(' ')) },
        Promise, JSON, Object, String, Number, Array, Math, RegExp, Error,
        encodeURIComponent, setTimeout, AbortController, TextEncoder, btoa,
        MutationObserver: function () { this.observe = function () {}; },
    };
    sandbox.globalThis = sandbox;

    vm.createContext(sandbox);
    vm.runInContext(NODES_SRC, sandbox, { filename: 'misp-pivot-nodes.js' });
    SIDEBAR_SRC.forEach(([f, src]) => vm.runInContext(src, sandbox, { filename: f }));
    vm.runInContext(SRC, sandbox, { filename: 'pivot-explorer.js' });

    // The build happens in a promise chain off fetch(); let it settle.
    return new Promise(res => setTimeout(res, 0)).then(() => {
        if (!constructed) {
            throw new Error('Pivotick was never constructed. errors=' + JSON.stringify(errors));
        }
        // What the element pivot offers at open, unnarrowed: everything the
        // canvas does not hold. Still called the tray, which it replaced.
        const elements = constructed.opts.pivots.find(p => p.id === 'event-elements');
        const tray = elements.fetch([], {}, {}).nodes.map(n => ({
            id: n.id, label: n.data.label, kind: n.data.type,
        }));
        return {
            nodes: constructed.data.nodes,
            edges: constructed.data.edges,
            opts: constructed.opts,
            graph: constructed.graph,
            win: sandbox.window,
            graphEl, resizers,
            fetchLog,
            tray, errors,
        };
    });
}

/* ─────────────────────── fixture builders ─────────────────────── */

// Real payloads always carry the event's uuid; an analyst relationship
// targeting an Event resolves against it.
const ev = parts => ({
    Event: Object.assign({ id: '1', uuid: 'EV-SELF', Attribute: [], Object: [] }, parts),
});

const attr = o => Object.assign({
    type: 'ip-dst', category: 'Network activity', value: 'v', to_ids: false, comment: '',
}, o);

const obj = o => Object.assign({
    name: 'file', 'meta-category': 'file', Attribute: [], ObjectReference: [],
}, o);

const ref = o => Object.assign({ referenced_type: '1', relationship_type: 'related-to' }, o);

// An object nothing references whose one attribute a feed hits: what L2 draws.
const fedObj = o => obj(Object.assign({
    Attribute: [attr({ uuid: o.uuid + '-hit', Feed: [{ id: '1', name: 'CIRCL OSINT Feed' }] })],
}, o));

// Another event, as Relationship::getRelatedElement() attaches it: a
// fetchSimpleEvent row, with no Orgc.
const otherEvent = o => Object.assign({ id: '99', uuid: 'R', info: '', date: '' }, o);

// Objects L2 would draw — each a feed hit, 2 nodes with its attribute — so
// enough of them blow the 1,500-node budget, the seed stops at L1 and the L1
// rule becomes observable on its own. No test seam — this is the same
// arithmetic a 28,410-object event triggers.
const fillers = n => {
    const out = [];
    for (let i = 0; i < n; i++) out.push(fedObj({ uuid: 'fill-' + i, name: 'filler' }));
    return out;
};

// An outbound analyst relationship, as it arrives on an Attribute or Object.
const arel = o => Object.assign({
    relationship_type: 'analysed-with', authors: 'alice', orgc_uuid: 'org-1',
    related_object_type: 'Object',
}, o);

// An analyst relationship pointing at another event, carrying that event's
// record the way the payload does.
const toEvent = (record, o) => arel(Object.assign({
    related_object_type: 'Event', related_object_uuid: record.uuid,
    related_object: { Event: record },
}, o));

/* ──────────────────────── assertions ──────────────────────────── */

let passed = 0, failed = 0;
const failures = [];

function eq(label, actual, expected) {
    const a = JSON.stringify(actual), e = JSON.stringify(expected);
    if (a === e) { passed++; return; }
    failed++; failures.push(label);
    console.log('  FAIL  ' + label + '\n          expected ' + e + '\n          actual   ' + a);
}

function ok(label, cond, detail) {
    if (cond) { passed++; return; }
    failed++; failures.push(label);
    console.log('  FAIL  ' + label + (detail !== undefined ? '\n          ' + detail : ''));
}

const ids = nodes => nodes.map(n => n.id).sort();
// Every node the canvas holds, nested children included — what the budget counts.
const countAll = nodes =>
    (nodes || []).reduce((n, x) => n + 1 + countAll(x.children), 0);
const trayLabels = g => g.tray.map(t => t.label).filter(l => l !== 'filler');
const edgeKeys = edges => edges.map(e => e.from + '->' + e.to + ':' + e.data.label).sort();
const byId = (nodes, id) => nodes.filter(n => n.id === id)[0];

/* ───────────────────────────── tests ──────────────────────────── */

const TESTS = [];
const test = (name, fn) => TESTS.push({ name, fn });

test('connectivity: a reference seeds both ends into L1; a feed hit brings an object in via L2; an untouched one stays in the tray', async () => {
    const g = await buildGraph(ev({ Object: [
        obj({ uuid: 'A', ObjectReference: [ref({ referenced_uuid: 'B' })] }),
        obj({ uuid: 'B' }),
        obj({ uuid: 'C' }),
        fedObj({ uuid: 'F' }),
    ] }));
    eq('nodes', ids(g.nodes), ['feed:1', 'obj:A', 'obj:B', 'obj:F']);
    eq('edges', edgeKeys(g.edges), ['feed:1->attr:F-hit:', 'obj:A->obj:B:related-to']);
    eq('the untouched object is left for the tray', g.tray.map(t => t.id), ['obj:C']);
    eq('no console errors', g.errors, []);
});

test('an object counts as connected when a reference points at one of its child attributes', async () => {
    const g = await buildGraph(ev({ Object: [
        obj({ uuid: 'A', ObjectReference: [ref({ referenced_uuid: 'd1', referenced_type: '0' })] }),
        obj({ uuid: 'D', Attribute: [attr({ uuid: 'd1', value: 'child' })] }),
    ] }));
    eq('both objects present', ids(g.nodes), ['obj:A', 'obj:D']);
    eq('edge targets the attribute, not its owning object',
       edgeKeys(g.edges), ['obj:A->attr:d1:related-to']);
    eq('tray is empty', g.tray, []);
});

test('event-level attributes appear only when a reference points at them', async () => {
    const g = await buildGraph(ev({
        Attribute: [attr({ uuid: 'e1', value: 'seen' }), attr({ uuid: 'e2', value: 'unseen' })],
        Object: [obj({ uuid: 'A', ObjectReference: [ref({ referenced_uuid: 'e1', referenced_type: '0' })] })],
    }));
    eq('only the referenced one is a node', ids(g.nodes), ['attr:e1', 'obj:A']);
    eq('the unreferenced one is in the tray', g.tray.map(t => t.label), ['unseen']);
});

test('soft-deleted records are tombstones, in all three encodings', async () => {
    const g = await buildGraph(ev({ Object: [
        // deleted:true on the reference -> no edge, and B is not pulled in
        obj({ uuid: 'A', ObjectReference: [ref({ referenced_uuid: 'B', deleted: true })] }),
        obj({ uuid: 'B' }),
        // deleted:1 on the object itself -> absent even though it is referenced
        obj({ uuid: 'X', deleted: 1, ObjectReference: [ref({ referenced_uuid: 'Y' })] }),
        // deleted:'1' on a child attribute -> not nested
        obj({ uuid: 'Y', Attribute: [attr({ uuid: 'y1', deleted: '1' }), attr({ uuid: 'y2' })],
              ObjectReference: [ref({ referenced_uuid: 'B' })] }),
    ] }));
    eq('the live linked objects, and only those', ids(g.nodes), ['obj:B', 'obj:Y']);
    ok('the deleted object X is absent', !byId(g.nodes, 'obj:X'));
    ok('Y is present via its live reference', !!byId(g.nodes, 'obj:Y'));
    eq('A\'s only reference is a tombstone, so it is left for the tray', g.tray.map(t => t.id), ['obj:A']);
    eq('only the live edge survives', edgeKeys(g.edges), ['obj:Y->obj:B:related-to']);
    const y = byId(g.nodes, 'obj:Y');
    eq('the deleted child attribute is not nested', y.children.map(c => c.id), ['attr:y2']);
});

test('object attributes are nested as children, with no containment edges', async () => {
    const g = await buildGraph(ev({ Object: [
        obj({ uuid: 'A', Attribute: [attr({ uuid: 'a1' }), attr({ uuid: 'a2' })],
              ObjectReference: [ref({ referenced_uuid: 'B' })] }),
        obj({ uuid: 'B' }),
    ] }));
    eq('children are not top-level nodes', ids(g.nodes), ['obj:A', 'obj:B']);
    eq('both children nested', byId(g.nodes, 'obj:A').children.map(c => c.id), ['attr:a1', 'attr:a2']);
    eq('containment produces no edge — only the reference does',
       edgeKeys(g.edges), ['obj:A->obj:B:related-to']);
});

test('edges dedupe on from/to/label, and dangling references are dropped', async () => {
    const g = await buildGraph(ev({ Object: [
        obj({ uuid: 'A', ObjectReference: [
            ref({ referenced_uuid: 'B' }),
            ref({ referenced_uuid: 'B' }),                              // exact duplicate
            ref({ referenced_uuid: 'B', relationship_type: 'includes' }), // different label
            ref({ referenced_uuid: 'nope' }),                            // dangling
        ] }),
        obj({ uuid: 'B' }),
    ] }));
    eq('duplicate collapsed, distinct label kept, dangling dropped',
       edgeKeys(g.edges), ['obj:A->obj:B:includes', 'obj:A->obj:B:related-to']);
});

test('a missing relationship_type falls back to related-to', async () => {
    const g = await buildGraph(ev({ Object: [
        obj({ uuid: 'A', ObjectReference: [ref({ referenced_uuid: 'B', relationship_type: '' })] }),
        obj({ uuid: 'B' }),
    ] }));
    eq('label defaulted', edgeKeys(g.edges), ['obj:A->obj:B:related-to']);
});

test('image attachments carry image + imageUrl; other attachments do not', async () => {
    const g = await buildGraph(ev({
        Attribute: [
            attr({ uuid: 'img', type: 'attachment', value: 'shot.PNG' }),
            attr({ uuid: 'doc', type: 'attachment', value: 'report.pdf' }),
        ],
        Object: [obj({ uuid: 'A', ObjectReference: [
            ref({ referenced_uuid: 'img', referenced_type: '0' }),
            ref({ referenced_uuid: 'doc', referenced_type: '0' }),
        ] })],
    }), { baseurl: '/misp' });
    const img = byId(g.nodes, 'attr:img').data;
    const doc = byId(g.nodes, 'attr:doc').data;
    eq('image flagged (extension match is case-insensitive)', img.image, true);
    eq('thumbnail URL is the ACL-checked viewPicture route',
       img.imageUrl, '/misp/attributes/viewPicture/img/webp');
    ok('non-image attachment is not flagged', doc.image == null, JSON.stringify(doc));
    ok('non-image attachment has no imageUrl', doc.imageUrl == null);
});

// Pivotick skips a null or undefined value everywhere it scans data (filter,
// table, Review tab, properties), so node data is passed as the payload has it.
test('a field the payload leaves null is carried as null, not stripped', async () => {
    const g = await buildGraph(ev({
        Attribute: [attr({ uuid: 'e1', object_relation: null, comment: null, category: 'Other' })],
        Object: [obj({ uuid: 'A', ObjectReference: [ref({ referenced_uuid: 'e1', referenced_type: '0' })] })],
    }));
    const d = byId(g.nodes, 'attr:e1').data;
    eq('object_relation and comment as the payload has them',
       [d.object_relation, d.comment], [null, null]);
    ok('a present value survives', d.category === 'Other');
});

test('a label is the whole value: the canvas shortens it, not the builder', async () => {
    const long = 'x'.repeat(80);
    const g = await buildGraph(ev({
        uuid: 'EV', info: 'i'.repeat(80),
        Attribute: [attr({ uuid: 'e1', value: long })],
        Object: [obj({ uuid: 'A', name: 'n'.repeat(80),
                       ObjectReference: [ref({ referenced_uuid: 'e1', referenced_type: '0' })] })],
        Relationship: [toEvent(otherEvent({ uuid: 'R', info: 'r'.repeat(80) }), { object_uuid: 'EV' })],
    }));
    eq('attribute', byId(g.nodes, 'attr:e1').data.label, long);
    eq('object', byId(g.nodes, 'obj:A').data.label, 'n'.repeat(80));
    eq('event', byId(g.nodes, 'event:EV').data.label, 'i'.repeat(80));
    eq('related event', byId(g.nodes, 'event:R').data.label, 'r'.repeat(80));
    ok('the canvas is left its default truncation',
       !('textTruncate' in g.opts.render.defaultNodeStyle));
});

test('no node can be expanded: the renderer draws no chevron and binds no Enter', async () => {
    const g = await buildGraph(ev({ Object: [obj({ uuid: 'A', Attribute: [attr({ uuid: 'a1' })],
                                                   ObjectReference: [ref({ referenced_uuid: 'B' })] }),
                                              obj({ uuid: 'B' })] }));
    eq('expansion is off renderer-wide', g.opts.render.enableNodeExpansion, false);
    eq('the object still carries its attributes as children',
       byId(g.nodes, 'obj:A').children.map(c => c.id), ['attr:a1']);
});

test('INVARIANT: every live element is either on the canvas or in the tray, never both', async () => {
    const payload = ev({
        Attribute: [
            attr({ uuid: 'e1', value: 'referenced' }),
            attr({ uuid: 'e2', value: 'loose-1' }),
            attr({ uuid: 'e3', value: 'loose-2' }),
            attr({ uuid: 'e4', value: 'gone', deleted: true }),
        ],
        Object: [
            obj({ uuid: 'A', ObjectReference: [
                ref({ referenced_uuid: 'e1', referenced_type: '0' }),
                ref({ referenced_uuid: 'B' }),
            ] }),
            obj({ uuid: 'B' }),
            fedObj({ uuid: 'C', name: 'url' }),
            obj({ uuid: 'D', name: 'domain' }),
        ],
    });
    const g = await buildGraph(payload);

    const canvas = new Set(g.nodes.map(n => n.id.replace(/^(obj|attr):/, '')));
    // Tray chips carry the label, so map fixture labels back to uuids.
    const trayLabels = new Set(g.tray.map(t => t.label));

    eq('canvas holds the L1 spine and the L2 object a feed hits',
       [...canvas].sort(), ['A', 'B', 'C', 'e1', 'feed:1']);
    eq('tray holds the event-level leftovers and the object nothing links',
       [...trayLabels].sort(), ['domain', 'loose-1', 'loose-2']);
    ok('no element is in both places',
       ![...trayLabels].some(l => ['referenced', 'url'].indexOf(l) !== -1));
    ok('the deleted attribute appears in neither', !canvas.has('e4') && !trayLabels.has('gone'));
});

test('an event with nothing in it builds an empty graph and offers nothing', async () => {
    const g = await buildGraph(ev({}));
    eq('no nodes', g.nodes, []);
    eq('no edges', g.edges, []);
    eq('the element pivot counts nothing',
       g.opts.pivots.find(p => p.id === 'event-elements').summarize([], {}).total, 0);
    eq('no console errors', g.errors, []);
});

test('a read-only viewer still gets the element pivot — putting an element on the canvas is not an edit', async () => {
    const g = await buildGraph(ev({ Object: [
        obj({ uuid: 'A', ObjectReference: [ref({ referenced_uuid: 'B' })] }),
        obj({ uuid: 'B' }),
        obj({ uuid: 'C' }),
    ] }), { canEdit: false });
    eq('graph still builds', ids(g.nodes), ['obj:A', 'obj:B']);
    ok('the element pivot is declared', g.opts.pivots.some(p => p.id === 'event-elements'));
    eq('and offers what the canvas left out', g.tray.map(t => t.id), ['obj:C']);
});

test('edges are tagged with the kind that created them (D1 dimension 1)', async () => {
    const g = await buildGraph(ev({ Object: [
        obj({ uuid: 'A', ObjectReference: [
            ref({ referenced_uuid: 'B' }),
            ref({ referenced_uuid: 'B', relationship_type: 'includes' }),
        ] }),
        obj({ uuid: 'B' }),
    ] }));
    eq('every edge carries object-reference',
       [...new Set(g.edges.map(e => e.data.kind))], ['object-reference']);
    eq('the label still carries relationship_type',
       g.edges.map(e => e.data.label).sort(), ['includes', 'related-to']);
});

test('the edge-kind dimension is declared for pivotick', async () => {
    const g = await buildGraph(ev({ Object: [
        obj({ uuid: 'A', ObjectReference: [ref({ referenced_uuid: 'B' })] }),
        obj({ uuid: 'B' }),
    ] }));
    const r = g.opts.render;

    ok('edgeTypeAccessor declared', typeof r.edgeTypeAccessor === 'function');
    eq('it reads .kind off the edge data',
       r.edgeTypeAccessor({ getData: () => ({ kind: 'object-reference' }) }), 'object-reference');
    eq('it tolerates an edge with no getData', r.edgeTypeAccessor({}), undefined);
    eq('it tolerates an edge whose data is null',
       r.edgeTypeAccessor({ getData: () => null }), undefined);

    eq('object-reference is styled in D1 blue',
       r.edgeStyleMap['object-reference'], { strokeColor: '#428bca' });
    eq('the implemented kinds are styled',
       Object.keys(r.edgeStyleMap),
       ['object-reference', 'in-event', 'analyst-relationship', 'correlation',
        'feed-correlation', 'feed-event', 'server-correlation', 'tag', 'cluster-relation', 'enrichment']);
    eq('in-event is thin grey, with no arrowhead',
       r.edgeStyleMap['in-event'], { strokeColor: '#6c737d', strokeWidth: 1, markerEnd: 'none' });
    eq('correlations are dashed grey (D1 palette)',
       r.edgeStyleMap['correlation'], { strokeColor: '#888', dashed: true });
    eq('analyst relationships are dashed orange (D1 palette)',
       r.edgeStyleMap['analyst-relationship'], { strokeColor: '#f39a1f', dashed: true });

    const facets = g.opts.UI.filter.edgeFacets;
    eq('two edge facets — the layer switch, then what an edge asserts', facets.length, 2);
    eq('the first is the kind facet', facets[0],
       { key: 'kind', label: 'Relationship', type: 'multiselect' });
});

test('5c: relationship_type is the second edge dimension, a pattern box', async () => {
    const g = await buildGraph(ev({ Object: [
        obj({ uuid: 'A', ObjectReference: [ref({ referenced_uuid: 'B', relationship_type: 'child-of' })],
              Relationship: [arel({ object_uuid: 'A', related_object_uuid: 'B',
                                    relationship_type: 'seen-with' })] }),
        obj({ uuid: 'B', ObjectReference: [ref({ referenced_uuid: 'A', relationship_type: '' })] }),
    ] }));
    const facet = g.opts.UI.filter.edgeFacets[1];
    // Pivotick compiles a regex facet case-insensitively and matches nothing
    // against a missing value; that is its to test, not ours to redo.
    eq('declared as the library\'s regex box — not a 143-row list, not our own matcher',
       facet, { key: 'relationship_type', label: 'Asserts', type: 'regex' });
    eq('every authored edge carries the type it asserts, the default included',
       g.edges.map(e => e.data.kind + ':' + e.data.relationship_type).sort(),
       ['analyst-relationship:seen-with', 'object-reference:child-of', 'object-reference:related-to']);
    eq('and it is the label drawn', g.edges.map(e => e.data.label === e.data.relationship_type),
       [true, true, true]);
});

test('5c: derived edges assert nothing, so carry no relationship_type', async () => {
    const g = await buildGraph(feedEvent());
    const derived = g.edges.filter(e => /-correlation$/.test(e.data.kind));
    ok('there are derived edges', derived.length > 0, String(derived.length));
    derived.forEach(e => ok('no relationship_type on ' + e.from + '->' + e.to,
                            !('relationship_type' in e.data), JSON.stringify(e.data)));
});

test('INVARIANT: every kind the builder emits resolves to a styled kind', async () => {
    // Closes the loop between the tag and the style map: a typo on either side
    // silently drops edges back to the default stroke. Must keep holding as
    // tasks 3, 5 and 5b add their own kinds.
    const g = await buildGraph(ev({
        Attribute: [attr({ uuid: 'e1' })],
        Object: [
            obj({ uuid: 'A', ObjectReference: [
                ref({ referenced_uuid: 'B' }),
                ref({ referenced_uuid: 'e1', referenced_type: '0' }),
            ] }),
            obj({ uuid: 'B', Attribute: [attr({ uuid: 'b1' })] }),
        ],
    }));
    const styled = Object.keys(g.opts.render.edgeStyleMap);
    const accessor = g.opts.render.edgeTypeAccessor;

    ok('there are edges to check', g.edges.length === 2, String(g.edges.length));
    g.edges.forEach(e => {
        const resolved = accessor({ getData: () => e.data });
        ok('kind ' + JSON.stringify(resolved) + ' for ' + e.from + '->' + e.to + ' is styled',
           styled.indexOf(resolved) !== -1, 'styled kinds: ' + JSON.stringify(styled));
    });
});

test('an analyst relationship becomes an edge of its own kind', async () => {
    const g = await buildGraph(ev({ Object: [
        obj({ uuid: 'A', Relationship: [
            arel({ object_uuid: 'A', related_object_uuid: 'B' }),
        ] }),
        obj({ uuid: 'B' }),
    ] }));
    eq('both endpoints seeded with no object reference in sight',
       ids(g.nodes), ['obj:A', 'obj:B']);
    eq('one analyst edge', edgeKeys(g.edges), ['obj:A->obj:B:analysed-with']);
    eq('tagged with its kind', g.edges[0].data.kind, 'analyst-relationship');
    eq('provenance carried on the edge',
       [g.edges[0].data.authors, g.edges[0].data.orgc], ['alice', 'org-1']);
});

test('D5 prime: an analyst relationship alone is enough to seed an element', async () => {
    // Before task 3 neither of these was on the canvas: A has no object
    // reference, and e1 is an event-level attribute nothing references.
    const g = await buildGraph(ev({
        Attribute: [attr({ uuid: 'e1', value: 'linked-by-analyst' }),
                    attr({ uuid: 'e2', value: 'truly-loose' })],
        Object: [
            obj({ uuid: 'A', Relationship: [
                arel({ object_uuid: 'A', related_object_uuid: 'e1',
                       related_object_type: 'Attribute' }),
            ] }),
            obj({ uuid: 'Z' }),
        ],
    }));
    eq('the analyst-linked pair is seeded, and nothing else',
       ids(g.nodes), ['attr:e1', 'obj:A']);
    eq('edge points at the attribute', edgeKeys(g.edges), ['obj:A->attr:e1:analysed-with']);
    eq('the untouched attribute and object stay in the tray',
       g.tray.map(t => t.label).sort(), ['file', 'truly-loose']);
});

test('a relationship on a child attribute pulls its owning object in', async () => {
    const g = await buildGraph(ev({ Object: [
        obj({ uuid: 'OWNER', Attribute: [
            attr({ uuid: 'c1', Relationship: [
                arel({ object_uuid: 'c1', related_object_uuid: 'T' }),
            ] }),
        ] }),
        obj({ uuid: 'T' }),
    ] }));
    eq('owner seeded via its child', ids(g.nodes), ['obj:OWNER', 'obj:T']);
    eq('the child is nested, not top-level',
       byId(g.nodes, 'obj:OWNER').children.map(c => c.id), ['attr:c1']);
    eq('the edge starts at the child attribute',
       edgeKeys(g.edges), ['attr:c1->obj:T:analysed-with']);
});

test('CLOSES THE TASK-2 GAP: kind is part of edge identity', async () => {
    // Same pair, same label, two different kinds — both edges belong. This is
    // what makes `kind` in the dedupe key observable.
    const g = await buildGraph(ev({ Object: [
        obj({ uuid: 'A',
              ObjectReference: [ref({ referenced_uuid: 'B', relationship_type: 'includes' })],
              Relationship: [arel({ object_uuid: 'A', related_object_uuid: 'B',
                                    relationship_type: 'includes' })] }),
        obj({ uuid: 'B' }),
    ] }));
    eq('two edges, not one', g.edges.length, 2);
    eq('one of each kind',
       g.edges.map(e => e.data.kind).sort(), ['analyst-relationship', 'object-reference']);
    eq('both carry the same label',
       [...new Set(g.edges.map(e => e.data.label))], ['includes']);
});

test('relationships the canvas cannot draw are skipped, not half-drawn', async () => {
    const g = await buildGraph(ev({ Object: [
        obj({ uuid: 'A', Relationship: [
            // legal AnalystData targets with no node on this canvas
            arel({ object_uuid: 'A', related_object_uuid: 'r1', related_object_type: 'EventReport' }),
            arel({ object_uuid: 'A', related_object_uuid: 'g1', related_object_type: 'GalaxyCluster' }),
            arel({ object_uuid: 'A', related_object_uuid: 'o1', related_object_type: 'Organisation' }),
            // Event resolves since task 3b, but only to this event or one of its
            // correlated neighbours — 'ev1' is neither
            arel({ object_uuid: 'A', related_object_uuid: 'ev1', related_object_type: 'Event' }),
            // an Object in some *other* event
            arel({ object_uuid: 'A', related_object_uuid: 'elsewhere' }),
            // self-reference — the model rejects these, we guard anyway
            arel({ object_uuid: 'A', related_object_uuid: 'A' }),
            // the one that does resolve
            arel({ object_uuid: 'A', related_object_uuid: 'B' }),
        ] }),
        obj({ uuid: 'B' }),
    ] }));
    eq('only the resolvable relationship drew an edge',
       edgeKeys(g.edges), ['obj:A->obj:B:analysed-with']);
    eq('no phantom nodes for unresolvable targets', ids(g.nodes), ['obj:A', 'obj:B']);
    eq('no console errors', g.errors, []);
});

test('a claim on a galaxy cluster lands on the cluster node', async () => {
    const apt1 = { uuid: 'gc-1', value: 'APT1', type: 'threat-actor',
                   tag_name: 'misp-galaxy:threat-actor="APT1"',
                   Galaxy: { name: 'Threat Actor', type: 'threat-actor' } };
    const toCluster = (rec, o) => arel(Object.assign({
        related_object_type: 'GalaxyCluster', related_object_uuid: rec.uuid,
        related_object: { GalaxyCluster: rec },
    }, o));
    const cid = 'cluster:' + apt1.tag_name;
    const g = await buildGraph(ev({
        Relationship: [toCluster(apt1, { relationship_type: 'linked-to' })],
        Attribute: [attr({ uuid: 'a1', value: '8.8.8.8',
            Relationship: [toCluster(apt1, { relationship_type: 'related-to' })] })],
        Object: [obj({ uuid: 'A', Relationship: [
            toCluster(Object.assign({}, apt1, { uuid: 'gc-2', deleted: true,
                tag_name: 'misp-galaxy:threat-actor="gone"' })),
        ] })],
    }));
    eq('one cluster node for both claims, the deleted cluster left out',
       ids(g.nodes), ['attr:a1', cid, 'event:EV-SELF']);
    eq('both claims end on it', edgeKeys(g.edges),
       ['attr:a1->' + cid + ':related-to', 'event:EV-SELF->' + cid + ':linked-to']);
    const d = byId(g.nodes, cid).data;
    eq('drawn as the tags pivot draws it',
       [d.type, d.value, d.galaxy_type, d.galaxy_name, d.uuid],
       ['cluster', 'APT1', 'threat-actor', 'Threat Actor', 'gc-1']);
    eq('no console errors', g.errors, []);
});

test('an object whose only reference dangles is not seeded by it', async () => {
    // Task 3 fixed the source being seeded before the target was checked. L2
    // draws only an object a feed or server hits, so the dangler is not drawn
    // at all.
    const g = await buildGraph(ev({ Object: [
        obj({ uuid: 'A', name: 'dangler', ObjectReference: [
            ref({ referenced_uuid: 'not-in-this-event' }),
        ] }),
        obj({ uuid: 'B', name: 'linked', ObjectReference: [ref({ referenced_uuid: 'C' })] }),
        obj({ uuid: 'C', name: 'target' }),
    ] }));
    eq('the linked pair is drawn, the dangler is not', ids(g.nodes), ['obj:B', 'obj:C']);
    eq('no edge was invented', edgeKeys(g.edges), ['obj:B->obj:C:related-to']);
    eq('the dangler is left in the tray', trayLabels(g), ['dangler']);
});

test('...and once L2 does not fit, the dangler is gone entirely', async () => {
    // The L1 rule in isolation. This is the assertion task 3 shipped, preserved
    // at the resolution where it is still visible.
    const g = await buildGraph(ev({ Object: [
        obj({ uuid: 'A', name: 'dangler', ObjectReference: [
            ref({ referenced_uuid: 'not-in-this-event' }),
        ] }),
        obj({ uuid: 'B', name: 'linked', ObjectReference: [ref({ referenced_uuid: 'C' })] }),
        obj({ uuid: 'C', name: 'target' }),
    ].concat(fillers(1501)) }));
    eq('only the real pair survives', ids(g.nodes), ['obj:B', 'obj:C']);
    eq('and it still drew exactly one edge', edgeKeys(g.edges), ['obj:B->obj:C:related-to']);
    eq('the dangler is offered in the tray instead',
       trayLabels(g), ['dangler']);
});

test('a reference to a deleted element does not seed its source', async () => {
    const objects = [
        obj({ uuid: 'A', name: 'points-at-tombstone',
              ObjectReference: [ref({ referenced_uuid: 'D' })] }),
        obj({ uuid: 'D', deleted: true }),
    ];
    const g = await buildGraph(ev({ Object: objects }));
    eq('neither the tombstone nor its source is drawn', ids(g.nodes), []);
    eq('and it seeded no edge', g.edges, []);
    const over = await buildGraph(ev({ Object: objects.concat(fillers(1501)) }));
    eq('L2 put the source there, not the reference', over.nodes, []);
});

test('a deleted link between two on-canvas elements still draws nothing', async () => {
    // The realistic soft-delete: a user removes one link of several. Both ends
    // stay on the canvas for other reasons, so the seeding pass cannot save us
    // here — the drawing pass has to honour the tombstone itself.
    const g = await buildGraph(ev({ Object: [
        obj({ uuid: 'A', ObjectReference: [
            ref({ referenced_uuid: 'B', relationship_type: 'includes' }),
            ref({ referenced_uuid: 'B', relationship_type: 'was-linked', deleted: true }),
        ], Relationship: [
            arel({ object_uuid: 'A', related_object_uuid: 'B',
                   relationship_type: 'was-asserted', deleted: 1 }),
        ] }),
        obj({ uuid: 'B' }),
    ] }));
    eq('both ends are on the canvas', ids(g.nodes), ['obj:A', 'obj:B']);
    eq('only the live reference drew an edge',
       edgeKeys(g.edges), ['obj:A->obj:B:includes']);
});

test('a relationship pointing at a tombstoned element seeds neither end', async () => {
    // The deleted attribute is never drawn, so seeding its partner would leave
    // that partner alone on the canvas with nothing to connect to.
    const parts = {
        Attribute: [attr({ uuid: 'e1', value: 'gone', deleted: true })],
        Object: [obj({ uuid: 'A', name: 'points-at-gone', Relationship: [
            arel({ object_uuid: 'A', related_object_uuid: 'e1',
                   related_object_type: 'Attribute' }),
        ] })],
    };
    const g = await buildGraph(ev(parts));
    eq('neither the tombstoned attribute nor its partner is drawn', ids(g.nodes), []);
    eq('no edges', g.edges, []);
    const over = await buildGraph(ev(Object.assign({}, parts,
        { Object: parts.Object.concat(fillers(1501)) })));
    eq('L2 put the source there, not the relationship', over.nodes, []);
});

test('the target TYPE gates resolution, not just whether the uuid exists', async () => {
    // 'B' is a real Object here. A relationship naming uuid B but declaring a
    // non-canvas target type must still be skipped — otherwise the type check is
    // only working by accident, rescued by uuids that happen not to exist.
    const objects = [
        obj({ uuid: 'A', Relationship: [
            arel({ object_uuid: 'A', related_object_uuid: 'B', related_object_type: 'EventReport' }),
            arel({ object_uuid: 'A', related_object_uuid: 'B', related_object_type: 'GalaxyCluster' }),
            arel({ object_uuid: 'A', related_object_uuid: 'B', related_object_type: 'Event' }),
        ] }),
        obj({ uuid: 'B' }),
    ];
    const g = await buildGraph(ev({ Object: objects }));
    eq('no edges — every target type is off-canvas', g.edges, []);
    eq('so neither object is drawn', ids(g.nodes), []);
    const over = await buildGraph(ev({ Object: objects.concat(fillers(1501)) }));
    eq('nothing was seeded by them', over.nodes, []);
});

test('an event-level attribute can be the source of a relationship', async () => {
    const g = await buildGraph(ev({
        Attribute: [attr({ uuid: 'e1', value: 'source-attr', Relationship: [
            arel({ object_uuid: 'e1', related_object_uuid: 'B' }),
        ] })],
        Object: [obj({ uuid: 'B' })],
    }));
    eq('both ends seeded', ids(g.nodes), ['attr:e1', 'obj:B']);
    eq('edge runs from the event-level attribute',
       edgeKeys(g.edges), ['attr:e1->obj:B:analysed-with']);
    eq('nothing left in the tray', g.tray, []);
});

test('tombstones apply to analyst relationships too', async () => {
    const objects = [
        // a deleted relationship on a live object
        obj({ uuid: 'A', Relationship: [
            arel({ object_uuid: 'A', related_object_uuid: 'B', deleted: true }),
        ] }),
        obj({ uuid: 'B' }),
        // a live relationship on a deleted object
        obj({ uuid: 'X', deleted: 1, Relationship: [
            arel({ object_uuid: 'X', related_object_uuid: 'B' }),
        ] }),
        // a live relationship on a deleted child attribute
        obj({ uuid: 'Y', Attribute: [attr({ uuid: 'y1', deleted: '1', Relationship: [
            arel({ object_uuid: 'y1', related_object_uuid: 'B' }),
        ] })] }),
        // a deleted object whose child attribute is live and carries one: the
        // tombstoned owner takes the child's relationship with it
        obj({ uuid: 'W', deleted: true, Attribute: [attr({ uuid: 'w1', Relationship: [
            arel({ object_uuid: 'w1', related_object_uuid: 'B' }),
        ] })] }),
    ];
    const g = await buildGraph(ev({ Object: objects }));
    eq('nothing is drawn: every relationship is a tombstone or on one',
       ids(g.nodes), []);
    eq('no edges', g.edges, []);
    const over = await buildGraph(ev({ Object: objects.concat(fillers(1501)) }));
    eq('nothing was seeded by a tombstoned relationship', over.nodes, []);
});

test('null provenance on an analyst relationship is carried as null', async () => {
    const g = await buildGraph(ev({ Object: [
        obj({ uuid: 'A', Relationship: [
            arel({ object_uuid: 'A', related_object_uuid: 'B', authors: null, orgc_uuid: null }),
        ] }),
        obj({ uuid: 'B' }),
    ] }));
    const d = g.edges[0].data;
    eq('authors and orgc as the payload has them', [d.authors, d.orgc], [null, null]);
    eq('the kind and label survive', [d.kind, d.label], ['analyst-relationship', 'analysed-with']);
});

test('INVARIANT still holds with two kinds in play', async () => {
    const g = await buildGraph(ev({
        Attribute: [attr({ uuid: 'e1', value: 'analyst-linked' }),
                    attr({ uuid: 'e2', value: 'loose' })],
        Object: [
            obj({ uuid: 'A', ObjectReference: [ref({ referenced_uuid: 'B' })],
                  Relationship: [arel({ object_uuid: 'A', related_object_uuid: 'e1',
                                        related_object_type: 'Attribute' })] }),
            obj({ uuid: 'B' }),
            obj({ uuid: 'C', name: 'url' }),
        ],
    }));
    const canvas = new Set(g.nodes.map(n => n.id.replace(/^(obj|attr):/, '')));
    const tray = new Set(g.tray.map(t => t.label));
    eq('canvas', [...canvas].sort(), ['A', 'B', 'e1']);
    eq('tray holds what no relationship touches',
       [...tray].sort(), ['loose', 'url']);

    const styled = Object.keys(g.opts.render.edgeStyleMap);
    const accessor = g.opts.render.edgeTypeAccessor;
    g.edges.forEach(e => {
        ok('kind ' + JSON.stringify(e.data.kind) + ' is styled',
           styled.indexOf(accessor({ getData: () => e.data })) !== -1);
    });
});

/* ──────────────────── event nodes (task 3b, revised) ───────────────────── */

test('correlated events are not drawn: the Correlations tab lists them', async () => {
    const g = await buildGraph(ev({
        RelatedEvent: [{ Event: otherEvent({ id: '22', uuid: 'R1' }) }],
        Attribute: [attr({ uuid: 'e1' })],
    }));
    eq('nothing seeded', g.nodes, []);
    eq('no edges', g.edges, []);
});

test('another event is labelled by what an analyst recognises it by', async () => {
    const g = await buildGraph(ev({ Attribute: [attr({ uuid: 'e1', Relationship: [
        toEvent(otherEvent({ id: '22', uuid: 'R1', info: 'campaign x', date: '2026-01-02',
                             Orgc: { name: 'CIRCL' }, Org: { name: 'HOST' } }), { object_uuid: 'e1' }),
        toEvent(otherEvent({ id: '23', uuid: 'R2', info: '', date: '2026-01-03' }), { object_uuid: 'e1' }),
    ] })] }));
    const a = byId(g.nodes, 'event:R1').data;
    eq('type drives the event node style', a.type, 'event');
    eq('label is the event info', a.label, 'campaign x');
    eq('description is date and creating org', a.description, '2026-01-02 · CIRCL');
    eq('it carries the id the navigation needs', a.event_id, '22');
    eq('and says it is not this event', a.scope, 'foreign');

    const b = byId(g.nodes, 'event:R2').data;
    eq('an event with no info falls back to its id', b.label, 'Event 23');
    eq('and its description to the date alone — the record has no Orgc', b.description, '2026-01-03');
    ok('another event is a leaf, not an expandable container (PRD §4)',
       g.nodes.every(n => !n.children));
});

test('the event node is drawn only when something connects to it', async () => {
    // A bare hexagon would make the seed permanently non-empty and put D11's
    // "nothing to draw" message (task 4) out of reach.
    const g = await buildGraph(ev({ Object: [obj({ uuid: 'A' })] }));
    ok('no event node', !byId(g.nodes, 'event:EV-SELF'), ids(g.nodes));
});

test('an analyst relationship can point at the event itself', async () => {
    const g = await buildGraph(ev({ Attribute: [attr({ uuid: 'e1', value: 'src',
        Relationship: [arel({ object_uuid: 'e1', related_object_uuid: 'EV-SELF',
                              related_object_type: 'Event' })] })] }));
    eq('the event node is drawn for the assertion to land on',
       ids(g.nodes), ['attr:e1', 'event:EV-SELF']);
    eq('edge', edgeKeys(g.edges), ['attr:e1->event:EV-SELF:analysed-with']);
    eq('with the analyst kind', g.edges[0].data.kind, 'analyst-relationship');
});

test('an analyst relationship can point at another event, drawn from the record it carries', async () => {
    const g = await buildGraph(ev({ Attribute: [attr({ uuid: 'e1', Relationship: [
        toEvent(otherEvent({ id: '22', uuid: 'R1', info: 'other' }), { object_uuid: 'e1' }),
    ] })] }));
    eq('the other event, and not this one', ids(g.nodes), ['attr:e1', 'event:R1']);
    eq('one analyst edge', g.edges.map(e => e.from + '->' + e.to + ':' + e.data.kind),
       ['attr:e1->event:R1:analyst-relationship']);
    eq('drawn from the attached record', byId(g.nodes, 'event:R1').data.label, 'other');
});

test('an event the viewer cannot see is not drawable', async () => {
    // getRelatedElement() comes back empty for an event the user may not see,
    // or one that does not exist — the relationship still arrives.
    const g = await buildGraph(ev({ Attribute: [attr({ uuid: 'e1', Relationship: [
        arel({ object_uuid: 'e1', related_object_uuid: 'R1', related_object_type: 'Event',
               related_object: [] }),
        arel({ object_uuid: 'e1', related_object_uuid: 'R2', related_object_type: 'Event',
               related_object: { Event: otherEvent({ uuid: 'NOT-R2' }) } }),
    ] })] }));
    eq('neither end is seeded', g.nodes, []);
});

test('the event itself can be a relationship source', async () => {
    const g = await buildGraph(ev({
        Attribute: [attr({ uuid: 'e1' })],
        Relationship: [
            arel({ object_uuid: 'EV-SELF', object_type: 'Event', related_object_uuid: 'e1',
                   related_object_type: 'Attribute', relationship_type: 'blocks' }),
            toEvent(otherEvent({ id: '22', uuid: 'R1' }),
                    { object_uuid: 'EV-SELF', object_type: 'Event', relationship_type: 'similar' }),
        ],
    }));
    eq('the event and both targets', ids(g.nodes), ['attr:e1', 'event:EV-SELF', 'event:R1']);
    eq('an edge each, out of the event', edgeKeys(g.edges),
       ['event:EV-SELF->attr:e1:blocks', 'event:EV-SELF->event:R1:similar']);
});

test('two relationships to one event draw it once, and charge it once', async () => {
    const r1 = otherEvent({ id: '22', uuid: 'R1' });
    const g = await buildGraph(ev({ Attribute: [
        attr({ uuid: 'e1', Relationship: [toEvent(r1, { object_uuid: 'e1' })] }),
        attr({ uuid: 'e2', Relationship: [toEvent(r1, { object_uuid: 'e2' })] }),
    ] }));
    eq('one event node', ids(g.nodes), ['attr:e1', 'attr:e2', 'event:R1']);
    eq('two edges', g.edges.length, 2);
});

test('with no event uuid in the payload the event is no endpoint', async () => {
    const g = await buildGraph(ev({ uuid: null,
        Relationship: [toEvent(otherEvent({ uuid: 'R1' }), { object_uuid: 'x' })] }));
    eq('nothing drawn', g.nodes, []);
    eq('no edges', g.edges, []);
});

// Another event's attribute or object, as Relationship::getRelatedElement()
// attaches it: the record, its event, and that event's creator org.
const farRecord = (key, o, event) => ({ [key]: Object.assign({
    Event: Object.assign({ id: '77', uuid: 'EV-77', info: 'elsewhere' }, event),
    Organisation: { name: 'CIRCL', uuid: 'org-c' },
}, o) });

// An inbound analyst relationship, as it arrives in RelationshipInbound:
// related_object is its source.
const inrel = o => Object.assign({
    relationship_type: 'connects-to', authors: 'bob', orgc_uuid: 'org-2', uuid: 'IN1',
}, o);

test('an inbound relationship from another event draws its source beside its event', async () => {
    const g = await buildGraph(ev({ Attribute: [attr({ uuid: 'e1', RelationshipInbound: [inrel({
        object_type: 'Attribute', object_uuid: 'x1',
        related_object_type: 'Attribute', related_object_uuid: 'e1',
        related_object: farRecord('Attribute', attr({ uuid: 'x1', value: '8.8.8.8', event_id: '77' })),
    })] })] }));
    eq('this attribute, the source, and its event', ids(g.nodes), ['attr:e1', 'attr:x1', 'event:EV-77']);
    eq('the relationship points at this event, the source sits in its own', edgeKeys(g.edges),
       ['attr:x1->attr:e1:connects-to', 'attr:x1->event:EV-77:']);
    const x1 = byId(g.nodes, 'attr:x1').data;
    eq('the source is foreign', [x1.scope, x1.event_id, x1.label], ['foreign', '77', '8.8.8.8']);
    eq('its card names the org', byId(g.nodes, 'event:EV-77').data.org, 'CIRCL');
    const rel = g.edges.filter(e => e.data.kind === 'analyst-relationship')[0].data;
    eq('deletable like any analyst relationship', [rel.uuid, rel.orgc], ['IN1', 'org-2']);
});

test('an outbound relationship to another event\'s object draws it closed', async () => {
    const g = await buildGraph(ev({ Attribute: [attr({ uuid: 'e1', Relationship: [arel({
        object_uuid: 'e1', related_object_uuid: 'o9', relationship_type: 'derived-from',
        related_object: farRecord('Object', { uuid: 'o9', name: 'domain-ip', 'meta-category': 'network' }),
    })] })] }));
    eq('drawn', ids(g.nodes), ['attr:e1', 'event:EV-77', 'obj:o9']);
    eq('no children', byId(g.nodes, 'obj:o9').children, undefined);
    eq('edges', edgeKeys(g.edges), ['attr:e1->obj:o9:derived-from', 'obj:o9->event:EV-77:']);
});

test('the event itself can be an inbound relationship\'s target', async () => {
    const g = await buildGraph(ev({ RelationshipInbound: [inrel({
        object_type: 'Attribute', object_uuid: 'x1', related_object_type: 'Event',
        related_object_uuid: 'EV-SELF', relationship_type: 'similar-to',
        related_object: farRecord('Attribute', attr({ uuid: 'x1' })),
    })] }));
    eq('the event, the source and its event', ids(g.nodes), ['attr:x1', 'event:EV-77', 'event:EV-SELF']);
    ok('the edge', edgeKeys(g.edges).includes('attr:x1->event:EV-SELF:similar-to'));
});

test('a relationship inside this event, seen from both ends, draws one edge', async () => {
    const both = { uuid: 'R', relationship_type: 'blocks', object_type: 'Attribute',
                   object_uuid: 'e1', related_object_type: 'Attribute', related_object_uuid: 'e2' };
    const g = await buildGraph(ev({ Attribute: [
        attr({ uuid: 'e1', Relationship: [arel(Object.assign({}, both))] }),
        attr({ uuid: 'e2', RelationshipInbound: [inrel(Object.assign({}, both, {
            related_object: { Attribute: attr({ uuid: 'e1', Event: { id: '1', uuid: 'EV-SELF' } }) } }))] }),
    ] }));
    eq('both attributes, no card', ids(g.nodes), ['attr:e1', 'attr:e2']);
    eq('one edge', edgeKeys(g.edges), ['attr:e1->attr:e2:blocks']);
});

test('a far end the viewer cannot read, or a tombstone, is not drawable', async () => {
    const g = await buildGraph(ev({ Attribute: [attr({ uuid: 'e1', RelationshipInbound: [
        inrel({ object_type: 'Attribute', object_uuid: 'x1', related_object: [] }),
        inrel({ object_type: 'Attribute', object_uuid: 'x2',
                related_object: farRecord('Attribute', attr({ uuid: 'NOT-x2' })) }),
        inrel({ object_type: 'Attribute', object_uuid: 'x3',
                related_object: farRecord('Attribute', attr({ uuid: 'x3', deleted: true })) }),
        inrel({ object_type: 'Attribute', object_uuid: 'x4',
                related_object: { Attribute: attr({ uuid: 'x4' }) } }),
    ] })] }));
    eq('neither end is seeded', g.nodes, []);
});

test('two foreign elements of one event share its card, also drawn as an endpoint', async () => {
    const g = await buildGraph(ev({ Attribute: [attr({ uuid: 'e1', Relationship: [
        arel({ object_uuid: 'e1', related_object_uuid: 'o9',
               related_object: farRecord('Object', { uuid: 'o9' }) }),
        toEvent(otherEvent({ id: '77', uuid: 'EV-77' }), { object_uuid: 'e1' }),
    ], RelationshipInbound: [inrel({ object_type: 'Attribute', object_uuid: 'x1',
        related_object: farRecord('Attribute', attr({ uuid: 'x1' })) })] })] }));
    eq('one card', ids(g.nodes), ['attr:e1', 'attr:x1', 'event:EV-77', 'obj:o9']);
});

test('the event is fetched with its server correlations', async () => {
    const g = await buildGraph(ev({}));
    ok('asked for', g.fetchLog.some(f => /\/misp\/events\/view\/1\/includeServerCorrelations:1\.json$/.test(f.url)));
});

test('double-click on another event opens it, and does nothing anywhere else', async () => {
    const g = await buildGraph(ev({ Attribute: [attr({ uuid: 'e1', Relationship: [
        toEvent(otherEvent({ id: '22', uuid: 'R1' }), { object_uuid: 'e1' }),
    ] })] }));
    const dbl = g.opts.callbacks.onNodeDbclick;
    ok('the callback is declared', typeof dbl === 'function');

    dbl({}, { getData: () => ({ type: 'event', event_id: '22' }) });
    eq('navigates to the other event', g.win.location.href, '/misp/events/view/22');

    g.win.location.href = '';
    dbl({}, { getData: () => ({ type: 'event', event_id: '1' }) });
    eq('but not to the event we are already on', g.win.location.href, '');

    dbl({}, { getData: () => ({ type: 'object', uuid: 'A' }) });
    eq('and not for any other node type', g.win.location.href, '');

    dbl({}, { getData: () => null });
    eq('a node with no data is survivable', g.win.location.href, '');
});

/* ─────────────────────── task 3c — L2 ─────────────────────────── */

test('L2: an object only a feed hits is drawn whole, its hit its only edge', async () => {
    const g = await buildGraph(ev({ Object: [
        obj({ uuid: 'C', name: 'file',
              Attribute: [attr({ uuid: 'c1', Feed: [{ id: '1', name: 'CIRCL OSINT Feed' }] }),
                          attr({ uuid: 'c2' })] }),
    ] }));
    eq('the object and the feed', ids(g.nodes), ['feed:1', 'obj:C']);
    eq('with its attributes nested inside it',
       byId(g.nodes, 'obj:C').children.map(c => c.id), ['attr:c1', 'attr:c2']);
    eq('and one edge, the hit', edgeKeys(g.edges), ['feed:1->attr:c1:']);
});

test('L2: an object nothing links is left for the tray', async () => {
    const g = await buildGraph(ev({ Object: [
        obj({ uuid: 'C', name: 'file', Attribute: [attr({ uuid: 'c1' }), attr({ uuid: 'c2' })] }),
        obj({ uuid: 'D', name: 'gone-hit', Attribute: [attr({ uuid: 'd1', deleted: true,
            Feed: [{ id: '1', name: 'CIRCL OSINT Feed' }] })] }),
    ] }));
    eq('nothing on the canvas', g.nodes, []);
    eq('both in the tray, a hit on a deleted attribute counting for nothing',
       trayLabels(g).sort(), ['file', 'gone-hit']);
});

test('L2 never adds a bare event-level attribute (D10 governing principle)', async () => {
    // 80% of all attributes are event-level; seeding those means seeding the
    // whole event again, and a bare attribute conveys less than its table row.
    const g = await buildGraph(ev({
        Attribute: [attr({ uuid: 'e1', value: 'one' }), attr({ uuid: 'e2', value: 'two' })],
    }));
    eq('nothing on the canvas', g.nodes, []);
    eq('both are in the tray', trayLabels(g).sort(), ['one', 'two']);
});

test('the budget is all-or-nothing: one node over and L2 is skipped whole', async () => {
    const at = await buildGraph(ev({ Object: fillers(750) }));
    eq('1,500 nodes fit, and every object is drawn, beside its feed', at.nodes.length, 751);
    eq('so the tray is empty', at.tray, []);

    const over = await buildGraph(ev({ Object: fillers(751) }));
    eq('one object over, and not a single one is drawn', over.nodes, []);
    eq('the skipped objects fall back to the tray (D4)', over.tray.length, 751);
});

test('over budget, the seed falls back to the relationship spine', async () => {
    // Event 4116 in miniature: L2 does not fit, so L1 carries the graph and
    // the element pivot carries the rest.
    const g = await buildGraph(ev({
        Object: [
            obj({ uuid: 'A', ObjectReference: [ref({ referenced_uuid: 'B' })],
                  Relationship: [toEvent(otherEvent({ uuid: 'R1' }), { object_uuid: 'A' })] }),
            obj({ uuid: 'B' }),
        ].concat(fillers(1501)),
    }));
    eq('L1 survives, the event it relates to included', ids(g.nodes),
       ['event:R1', 'obj:A', 'obj:B']);
    eq('with both their edges', g.edges.length, 2);
});

test('an object is counted at its true cost — children included — before L2 is judged', async () => {
    // 750 two-attribute objects is 2,250 nodes, not 750. Counting the parents
    // alone would let a 28,410-object event through the budget three times over.
    const heavy = [];
    for (let i = 0; i < 750; i++) {
        heavy.push(obj({ uuid: 'h' + i,
                         Attribute: [attr({ uuid: 'h' + i + 'a', Feed: [{ id: '1' }] }),
                                     attr({ uuid: 'h' + i + 'b' })] }));
    }
    const g = await buildGraph(ev({ Object: heavy }));
    eq('L2 is refused', g.nodes, []);
    eq('all 750 fall back to the element pivot', g.tray.length, 750);
});

test('a deleted child does not cost the budget anything', async () => {
    // 750 fed objects with one tombstoned child each: 1,500 live nodes, not 2,250.
    const many = fillers(750);
    many.forEach((o, i) => o.Attribute.push(attr({ uuid: 'd' + i + 'x', deleted: true })));
    const g = await buildGraph(ev({ Object: many }));
    eq('all drawn, beside the feed, and no tombstone was nested', countAll(g.nodes), 1501);
});

test('a skipped L2 leaves the tray as the only route to those objects', async () => {
    // The invariant, at the resolution where it actually bites: 1,501 objects
    // are in exactly one of the two places, and it is not the canvas.
    const g = await buildGraph(ev({
        Attribute: [attr({ uuid: 'e1', value: 'loose' })],
        Object: fillers(1501),
    }));
    eq('canvas empty', g.nodes, []);
    eq('tray holds the objects and the attribute', g.tray.length, 1502);
    eq('the attribute among them', trayLabels(g), ['loose']);
});

test('INVARIANT: every kind the builder emits resolves to a styled kind — both authored ones', async () => {
    const g = await buildGraph(ev({
        Attribute: [attr({ uuid: 'e1' })],
        Object: [
            obj({ uuid: 'A',
                  ObjectReference: [ref({ referenced_uuid: 'e1', referenced_type: '0' })],
                  Relationship: [arel({ object_uuid: 'A', related_object_uuid: 'B' }),
                                 toEvent(otherEvent({ uuid: 'R1' }), { object_uuid: 'A' })] }),
            obj({ uuid: 'B' }),
        ],
    }));
    const styled = Object.keys(g.opts.render.edgeStyleMap);
    const accessor = g.opts.render.edgeTypeAccessor;

    eq('both kinds are in play at once',
       [...new Set(g.edges.map(e => e.data.kind))].sort(),
       ['analyst-relationship', 'object-reference']);
    g.edges.forEach(e => {
        const resolved = accessor({ getData: () => e.data });
        ok('kind ' + JSON.stringify(resolved) + ' for ' + e.from + '->' + e.to + ' is styled',
           styled.indexOf(resolved) !== -1, 'styled kinds: ' + JSON.stringify(styled));
    });
});

/* ───────────────────────── pivot (R1) ────────────────────────── */

// A node as pivotick hands it to a pivot: only getData() is read.
const pnode = data => ({ getData: () => data });

// Counts and pairs as /events/correlationCounts and /events/correlatedAttributes
// shape them.
const COUNTS = {
    total: 3,
    attributes: { e1: 1, c1: 2 },
    objects: { A: 2 },
    events: { '7': 2, '8': 1 },
    limit: 5000,
};
const pair = (src, uuid, evId, evUuid) => ({
    source_uuid: src,
    Attribute: { id: '9' + uuid, uuid, type: 'ip-dst', category: 'Network activity', value: '10.0.0.' + uuid },
    Event: { id: evId, uuid: evUuid, info: 'Event ' + evId },
    Object: null,
});
const PAIRS = {
    pairs: [pair('c1', 'x1', '7', 'R7'), pair('c1', 'x2', '7', 'R7'), pair('e1', 'x3', '8', 'R8')],
    events: {
        '7': {
            id: '7', uuid: 'R7', info: 'Event 7', date: '2024-01-02',
            published: true, publish_timestamp: '1700000000', distribution: '3',
            attribute_count: '36', object_count: 9,
            Orgc: { name: 'CIRCL', uuid: 'O1' },
            Tag: [{ name: 'tlp:white', colour: '#ffffff', is_galaxy: false }],
            Galaxy: [{ type: 'tool', GalaxyCluster: [{ value: 'BabyShark' }] }],
        },
    },
};

function pivotFixture() {
    return ev({
        Attribute: [attr({ uuid: 'e1' })],
        Object: [obj({ uuid: 'A', Attribute: [attr({ uuid: 'c1' })] }),
                 obj({ uuid: 'B', ObjectReference: [ref({ referenced_uuid: 'A' })], Relationship: [
                     toEvent(otherEvent({ uuid: 'R7', id: '7' }), { object_uuid: 'B' })] })],
    });
}

function withPivots(extraRoutes) {
    return buildGraph(pivotFixture(), {
        routes: (extraRoutes || []).concat([
            [/correlationCounts\/1\.json$/, COUNTS],
            [/correlatedAttributes\/1\.json$/, PAIRS],
        ]),
    }).then(g => new Promise(res => setTimeout(() => res(g), 0)));
}

const pivot = (g, id) => g.opts.pivots.find(p => p.id === id);

test('the correlation pivot is declared, capped at the canvas budget, and savable by nobody', async () => {
    const g = await withPivots();
    eq('after the element pivot, correlations, feed events, tags and clusters, then what a tag leads to',
       g.opts.pivots.map(p => p.id),
       ['event-elements', 'correlations', 'feed-events', 'tags', 'tagged-events', 'related-clusters', 'relating-clusters',
        'object-surroundings',
        'card-attributes', 'card-ids', 'card-network', 'card-correlations']);
    g.opts.pivots.filter(p => p.id !== 'event-elements').forEach(p => {
        eq(p.id + ' refuses above 1,500', p.maxCandidates, 1500);
        ok(p.id + ' has no save — correlations are derived', p.save === undefined);
    });
    ok('the counts were asked for once the graph existed',
       g.fetchLog.some(f => /\/misp\/events\/correlationCounts\/1\.json$/.test(f.url)));
});

test('a one-click pivot lands up to 25 new candidates without Review', async () => {
    const g = await withPivots();
    eq('the limit', g.opts.pivotQuickIngestLimit, 25);
});

test('groups: every landing arrives grouped', async () => {
    const g = await withPivots();
    eq('the option', g.opts.pivotIngestGrouped, true);
});

test('groups: MISP declares its rules, a smallest group of 5, pivot landings and same neighbours on', async () => {
    const g = await withPivots();
    const s = g.opts.UI.simplify;
    eq('in order', s.rules.map(r => r.kind),
       ['landings', 'neighbours', 'chains', 'degree', 'kcore', 'communities']);
    eq('landings and neighbours start on', s.rules.filter(r => r.enabled).map(r => r.kind), ['landings', 'neighbours']);
    eq('5 wherever a rule has a smallest group',
       s.rules.filter(r => 'minSize' in r).map(r => r.minSize), [5, 5, 5]);
    ok('every rule types by MISP\'s kinds, none on its own',
       typeof s.typeOf === 'function' && s.rules.every(r => !r.typeOf));
});

test('groups: a kind is the element and MISP\'s own type', async () => {
    const g = await withPivots();
    const typeOf = g.opts.UI.simplify.typeOf;
    eq('an attribute by its type', typeOf(pnode({ type: 'attribute', 'attr-type': 'ip-dst' })), 'attribute:ip-dst');
    ok('ip-src and ip-dst apart',
       typeOf(pnode({ type: 'attribute', 'attr-type': 'ip-src' })) !== typeOf(pnode({ type: 'attribute', 'attr-type': 'ip-dst' })));
    eq('an object by its template', typeOf(pnode({ type: 'object', name: 'url' })), 'object:url');
    ok('never with an attribute of that name',
       typeOf(pnode({ type: 'object', name: 'url' })) !== typeOf(pnode({ type: 'attribute', 'attr-type': 'url' })));
    eq('a cluster by its galaxy type',
       typeOf(pnode({ type: 'cluster', galaxy_type: 'mitre-attack-pattern', galaxy_name: 'Attack Pattern' })),
       'cluster:mitre-attack-pattern');
    eq('a tag by its namespace', typeOf(pnode({ type: 'tag', name: 'tlp:amber' })), 'tag:tlp');
    eq('a tag with none by its name', typeOf(pnode({ type: 'tag', name: 'suspicious' })), 'tag:suspicious');
    eq('an event by its element', typeOf(pnode({ type: 'event' })), 'event');
    eq('a screenshot by its element', typeOf(pnode({ type: 'attribute', 'attr-type': 'attachment', image: true })), 'image');
});

test('groups: a card reads N × name', async () => {
    const g = await withPivots();
    const s = g.opts.UI.simplify;
    s.typeOf(pnode({ type: 'cluster', galaxy_type: 'mitre-attack-pattern', galaxy_name: 'Attack Pattern' }));
    eq('an attribute', s.typeLabel('attribute:ip-dst', 9), '9 × ip-dst');
    eq('an object', s.typeLabel('object:file', 12), '12 × file');
    eq('a cluster by its galaxy\'s name', s.typeLabel('cluster:mitre-attack-pattern', 3), '3 × Attack Pattern');
    eq('a galaxy never seen by its type', s.typeLabel('cluster:tool', 2), '2 × tool');
    eq('a tag', s.typeLabel('tag:tlp', 4), '4 × tlp');
    eq('an element', s.typeLabel('event', 6), '6 × event');
    eq('a rule typing by element', s.typeLabel('taxonomy', 2), '2 × tag');
    eq('no type', s.typeLabel(undefined, 2), '2 × node');
});

test('groups: a node stands for its entity\'s hue in every group', async () => {
    const g = await withPivots();
    const colorOf = g.opts.UI.simplify.colorOf;
    const P = g.win.MispPivotNodes.palette();
    eq('an attribute', colorOf(pnode({ type: 'attribute' })), P.attribute.core);
    eq('a cluster', colorOf(pnode({ type: 'cluster' })), P.galaxy.core);
    eq('a tag', colorOf(pnode({ type: 'tag' })), P.tag.core);
    ok('the style leaves the colour to the library', !('color' in g.opts.render.groupStyle(
        { rule: 'landings', members: [pnode({ type: 'attribute' })], typeCounts: {} }, {})));
});

test('groups: zoomed in, a group draws the deck chip of its kind, naming its pivot', async () => {
    const g = await withPivots();
    const members = Array.from({ length: 12 }, () => ({ type: 'attribute', 'attr-type': 'ip-dst' }));
    const countTier = { width: 26, height: 26, minRenderedSize: 26, style: {} };
    const st = g.opts.render.groupStyle({
        rule: 'landings', members: members.map(pnode), typeCounts: { 'attribute:ip-dst': 12 },
        landing: { runId: 'event-elements#3', pivotId: 'event-elements', pivotLabel: 'Event elements' },
    }, { tiers: [countTier] });
    eq('the library\'s count tier, then a 140 x 44 chip',
       st.tiers.map(t => [t.width, t.height]), [[26, 26], [140, 44]]);
    ok('the count tier is the library\'s own', st.tiers[0] === countTier);
    eq('spaced like an element', st.layoutSize, 45);
    eq('it engages where an element chip does', st.tiers[1].minRenderedSize, 2 * 45 * 0.8);
    const card = st.tiers[1].style.html();
    ok('the card is the deck', /12/.test(card.innerHTML) && /ip-dst/.test(card.innerHTML));
    ok('it names the pivot it landed from', /Event elements/.test(card.innerHTML));
    eq('the open group\'s chip is the label', typeof g.opts.render.groupOutline, 'function');
});

test('groups: only a group shows a tooltip, with its first three values', async () => {
    const g = await withPivots();
    const t = g.opts.UI.tooltip;
    eq('per kind', t.enabled, { nodes: false, edges: false, groups: true });
    const members = ['110.45.145.103', '114.215.130.173', '119.29.11.203', '124.248.228.30']
        .map((v, i) => ({ id: 'a' + i, getData: () => ({ label: v }) }));
    const el = t.renderGroupExtra({ members });
    const texts = el.children.map(c => c.textContent);
    eq('three values, then the rest counted',
       texts, ['110.45.145.103', '114.215.130.173', '119.29.11.203', '+1 more']);
    eq('no count when all are shown', t.renderGroupExtra({ members: members.slice(0, 3) }).children.length, 3);
});

test('the correlation pivot applies only where the counts say something correlates', async () => {
    const g = await withPivots();
    const p = pivot(g, 'correlations');
    const nodes = [
        pnode({ type: 'attribute', uuid: 'e1' }),
        pnode({ type: 'object', uuid: 'A' }),
        pnode({ type: 'object', uuid: 'B' }),
        pnode({ type: 'event', uuid: 'R7', event_id: '7' }),
    ];
    eq('it keeps the correlated attribute and object',
       p.appliesTo(nodes).map(n => n.getData().uuid), ['e1', 'A']);
    const s = p.summarize(p.appliesTo(nodes), {});
    eq('summarize is the counts, summed over the origin', s.total, 3);
    eq('each correlating attribute can be picked, with its own count',
       s.facets.map(f => [f.key, f.type, f.options.map(o => [o.value, o.count])]),
       [['attribute', 'multiselect', [['e1', 1], ['c1', 2]]]]);
    eq('picking one counts only it', p.summarize(p.appliesTo(nodes), { attribute: ['c1'] }).total, 2);
    eq('one attribute offers no choice', p.summarize([nodes[0]], {}), { total: 1 });
});

test('an object\'s correlations can be fetched for one of its attributes', async () => {
    let body = null;
    const g = await withPivots([[/correlatedAttributes/, init => { body = JSON.parse(init.body); return PAIRS; }]]);
    await pivot(g, 'correlations').fetch([pnode({ type: 'object', uuid: 'A' }), pnode({ type: 'attribute', uuid: 'e1' })],
                                         { attribute: ['c1'] }, {});
    eq('only the picked one is asked for', body, { attribute_uuids: ['c1'] });
});

test('before the counts arrive, no pivot applies', async () => {
    const g = await buildGraph(pivotFixture());     // counts route answers with the event payload
    eq('correlations', pivot(g, 'correlations').appliesTo([pnode({ type: 'attribute', uuid: 'e1' })]).length, 0);
});

const potentials = (g, id) => {
    const n = g.graph.getMutableNode(id);
    return n ? Array.from(n.getPotentials()) : undefined;
};

test('15: every counted element declares what its pivot would bring, as rim potential', async () => {
    const g = await withPivots();
    eq('an unlinked attribute is not drawn yet, so declares nothing yet', potentials(g, 'attr:e1'), undefined);
    eq('an object, its own count', potentials(g, 'obj:A'), [['correlations', 2]]);
    eq('a child attribute, for when its object is expanded', potentials(g, 'attr:c1'), [['correlations', 2]]);
    eq('an object nothing correlates with declares nothing', potentials(g, 'obj:B'), []);
    eq('another event declares nothing, however much it shares', potentials(g, 'event:R7'), []);
    eq('one render to draw them', g.graph.renderer.updates, 1);
    eq('no console errors', g.errors, []);
});

test('15: an element that lands later declares its own on arrival', async () => {
    const g = await withPivots();
    const land = (id, data) => {
        const n = g.graph.liveNode({ id, data });
        g.graph.listeners.nodeAdd.forEach(f => f(n));
        return Array.from(n.getPotentials());
    };
    eq('this event\'s attribute, put on the canvas by the element pivot',
       land('attr:e1', { type: 'attribute', uuid: 'e1' }), [['correlations', 1]]);
});

// Another event's elements, counted by a POST to the same endpoint.
const FOREIGN_COUNTS = { total: 5, attributes: { x1: 3, x2: 2 }, objects: { OB: 2 }, events: { '9': 5 } };

function withForeignCounts(answer) {
    const asked = [];
    return withPivots([[/correlationCounts\/1\.json$/, init => {
        if (!init || init.method !== 'POST') return COUNTS;
        asked.push(JSON.parse(init.body));
        return answer ? answer() : FOREIGN_COUNTS;
    }]]).then(g => Object.assign(g, { asked }));
}

const settle = () => new Promise(res => setTimeout(res, 0)).then(() => new Promise(res => setTimeout(res, 0)));

function landForeign(g, id, data, children) {
    const n = g.graph.liveNode({ id, data });
    if (children) n.children = children.map(c => ({ getData: () => c }));
    g.graph.listeners.nodeAdd.forEach(f => f(n));
    return n;
}

test('another event\'s elements are counted as they land, together in one request', async () => {
    const g = await withForeignCounts();
    const updates = g.graph.renderer.updates;
    const a = landForeign(g, 'attr:x1', { type: 'attribute', uuid: 'x1', scope: 'foreign', event_id: '7' });
    const o = landForeign(g, 'obj:OB', { type: 'object', uuid: 'OB', scope: 'foreign', event_id: '7' },
                          [{ type: 'attribute', uuid: 'x2' }]);
    landForeign(g, 'attr:e1', { type: 'attribute', uuid: 'e1' });
    eq('nothing declared before the answer', Array.from(a.getPotentials()), []);
    await settle();
    eq('one request, an object by its children, this event\'s own left out', g.asked, [{ attribute_uuids: ['x1', 'x2'] }]);
    eq('the attribute declares its count', Array.from(a.getPotentials()), [['correlations', 3]]);
    eq('the object its own', Array.from(o.getPotentials()), [['correlations', 2]]);
    eq('one render for the batch', g.graph.renderer.updates, updates + 1);
    landForeign(g, 'attr:x1', { type: 'attribute', uuid: 'x1', scope: 'foreign', event_id: '7' });
    await settle();
    eq('never asked twice', g.asked.length, 1);
    eq('no console errors', g.errors, []);
});

test('a failed count for another event\'s element is asked again when it lands again', async () => {
    let fail = true;
    const g = await withForeignCounts(() => (fail ? { __status: 500 } : FOREIGN_COUNTS));
    landForeign(g, 'attr:x1', { type: 'attribute', uuid: 'x1', scope: 'foreign' });
    await settle();
    fail = false;
    const n = landForeign(g, 'attr:x1', { type: 'attribute', uuid: 'x1', scope: 'foreign' });
    await settle();
    eq('asked twice', g.asked.length, 2);
    eq('declared the second time', Array.from(n.getPotentials()), [['correlations', 3]]);
});

test('correlations apply to another event\'s attribute and object once counted', async () => {
    const g = await withForeignCounts();
    const a = landForeign(g, 'attr:x1', { type: 'attribute', uuid: 'x1', scope: 'foreign', value: '1.1.1.1', 'attr-type': 'ip-dst' });
    const o = landForeign(g, 'obj:OB', { type: 'object', uuid: 'OB', scope: 'foreign' },
                          [{ type: 'attribute', uuid: 'x2', value: 'evil.example', object_relation: 'domain' }]);
    const p = pivot(g, 'correlations');
    eq('before the counts, neither', p.appliesTo([a, o]).length, 0);
    await settle();
    eq('both, after', p.appliesTo([a, o]).map(n => n.id), ['attr:x1', 'obj:OB']);
    const s = p.summarize([a, o], {});
    eq('summed', s.total, 5);
    eq('each named from its node', s.facets[0].options.map(x => [x.label, x.count]),
       [['ip-dst: 1.1.1.1', 3], ['domain: evil.example', 2]]);
});

test('another event\'s object fetches by its drawn children', async () => {
    let body = null;
    const g = await withPivots([[/correlatedAttributes/, init => { body = JSON.parse(init.body); return PAIRS; }]]);
    const o = { id: 'obj:OB', getData: () => ({ type: 'object', uuid: 'OB', scope: 'foreign' }),
                children: [{ getData: () => ({ type: 'attribute', uuid: 'x2' }) }] };
    await pivot(g, 'correlations').fetch([o, pnode({ type: 'attribute', uuid: 'x1', scope: 'foreign' })], {}, {});
    eq('its children, then the attribute', body, { attribute_uuids: ['x2', 'x1'] });
});

test('a pair already drawn the other way is not drawn again', async () => {
    let pairs = [pair('x1', 'x2', '8', 'R8'), pair('x2', 'x1', '7', 'R7')];
    const g = await withPivots([[/correlatedAttributes/, () => ({ pairs, events: {} })]]);
    const r = await pivot(g, 'correlations').fetch([pnode({ type: 'attribute', uuid: 'x1' }), pnode({ type: 'attribute', uuid: 'x2' })], {}, {});
    eq('one correlation edge for the two', r.edges.filter(e => e.data.kind === 'correlation').map(e => e.id), ['corr:x1:x2']);
    g.graph.getMutableEdge = id => (id === 'corr:x1:x2' ? {} : undefined);
    pairs = [pair('x2', 'x1', '7', 'R7')];
    const again = await pivot(g, 'correlations').fetch([pnode({ type: 'attribute', uuid: 'x2' })], {}, {});
    eq('nor one already on the canvas', again.edges.filter(e => e.data.kind === 'correlation'), []);
});

test('an object origin fetches by its live attributes', async () => {
    let body = null;
    const g = await withPivots([[/correlatedAttributes/, init => { body = JSON.parse(init.body); return PAIRS; }]]);
    await pivot(g, 'correlations').fetch([pnode({ type: 'object', uuid: 'A' }), pnode({ type: 'attribute', uuid: 'e1' })], {}, {});
    eq('the object expands to its child attribute, the attribute stays itself',
       body, { attribute_uuids: ['c1', 'e1'] });
});

test('a correlated attribute outside any object lands free, beside its event\'s empty card', async () => {
    const g = await withPivots();
    const r = await pivot(g, 'correlations').fetch([pnode({ type: 'attribute', uuid: 'e1' })], {}, {});
    eq('each card once, each attribute free, this event\'s missing side last',
       r.nodes.map(n => n.id), ['event:R7', 'attr:x1', 'attr:x2', 'event:R8', 'attr:x3', 'attr:e1']);
    eq('a card holds nothing', r.nodes.filter(n => n.data.type === 'event').map(n => n.children), [undefined, undefined]);
    eq('a correlated attribute is drawn like any attribute, and says which event it is in',
       [byId(r.nodes, 'attr:x1').data.type, byId(r.nodes, 'attr:x1').data.event_id], ['attribute', '7']);
    eq('each joined to its card, and to this event by its correlation, with stable ids',
       r.edges.map(e => [e.id, e.from, e.to, e.data.kind]),
       [['in-event:attr:x1', 'attr:x1', 'event:R7', 'in-event'],
        ['corr:c1:x1', 'attr:c1', 'attr:x1', 'correlation'],
        ['in-event:attr:x2', 'attr:x2', 'event:R7', 'in-event'],
        ['corr:c1:x2', 'attr:c1', 'attr:x2', 'correlation'],
        ['in-event:attr:x3', 'attr:x3', 'event:R8', 'in-event'],
        ['corr:e1:x3', 'attr:e1', 'attr:x3', 'correlation']]);
});

// Two correlations into one domain-ip object of event 7, as
// /events/correlatedAttributes returns them once the object is readable.
const inObject = (src, uuid) => Object.assign(pair(src, uuid, '7', 'R7'), { Object: { id: '70', uuid: 'OB', name: 'domain-ip' } });
const OBJECT_PAIRS = {
    pairs: [inObject('c1', 'x1'), inObject('c1', 'x2')],
    events: PAIRS.events,
    objects: {
        OB: { id: '70', uuid: 'OB', name: 'domain-ip', 'meta-category': 'network', event_id: '7',
              template_uuid: 'T-DIP', template_version: '9', Attribute: [
                  attr({ uuid: 'x1', value: 'evil.example', type: 'domain', object_relation: 'domain' }),
                  attr({ uuid: 'x2', value: '10.0.0.x2', object_relation: 'ip' }),
                  attr({ uuid: 'x9', value: 'gone', deleted: true })] },
    },
    ui_priorities: { 'T-DIP.9': { ip: 5 } },
};

test('a correlated attribute inside an object lands in it, the object closed beside the card', async () => {
    const g = await withPivots([[/correlatedAttributes/, OBJECT_PAIRS]]);
    const r = await pivot(g, 'correlations').fetch([pnode({ type: 'object', uuid: 'A' })], {}, {});
    eq('the card and the object, once for both correlations', r.nodes.map(n => n.id), ['event:R7', 'obj:OB']);
    const o = byId(r.nodes, 'obj:OB');
    eq('the object is another event\'s', [o.data.type, o.data.label, o.data.scope, o.data.event_id],
       ['object', 'domain-ip', 'foreign', '7']);
    eq('with its live attributes, the correlated ones among them',
       o.children.map(c => [c.id, c.data.scope]), [['attr:x1', 'foreign'], ['attr:x2', 'foreign']]);
    eq('ranked by its own template', o.children.map(c => c.data.ui_priority), [undefined, 5]);
    eq('one in-event edge from the object, the correlations ending inside it',
       r.edges.map(e => [e.id, e.from, e.to]),
       [['in-event:obj:OB', 'obj:OB', 'event:R7'],
        ['corr:c1:x1', 'attr:c1', 'attr:x1'],
        ['corr:c1:x2', 'attr:c1', 'attr:x2']]);
});

test('an object the user cannot read leaves its correlated attribute free', async () => {
    const hidden = Object.assign({}, OBJECT_PAIRS, { objects: {} });
    const g = await withPivots([[/correlatedAttributes/, hidden]]);
    const r = await pivot(g, 'correlations').fetch([pnode({ type: 'object', uuid: 'A' })], {}, {});
    eq('no object, free attributes', r.nodes.map(n => n.id), ['event:R7', 'attr:x1', 'attr:x2']);
});

test('a correlated attribute is put inside its object even when the object\'s payload lacks it', async () => {
    const partial = JSON.parse(JSON.stringify(OBJECT_PAIRS));
    partial.objects.OB.Attribute = partial.objects.OB.Attribute.filter(a => a.uuid !== 'x2');
    const g = await withPivots([[/correlatedAttributes/, partial]]);
    const r = await pivot(g, 'correlations').fetch([pnode({ type: 'object', uuid: 'A' })], {}, {});
    eq('both inside', byId(r.nodes, 'obj:OB').children.map(c => c.id), ['attr:x1', 'attr:x2']);
});

test('a correlated event\'s container is drawn from its card, not from the pair', async () => {
    const g = await withPivots();
    const r = await pivot(g, 'correlations').fetch([pnode({ type: 'attribute', uuid: 'e1' })], {}, {});
    const d = r.nodes.find(n => n.id === 'event:R7').data;
    eq('the index row', [d.org, d.orgc, d.date, d.published, d.publish_timestamp, d.distribution],
       ['CIRCL', { name: 'CIRCL', uuid: 'O1' }, '2024-01-02', true, 1700000000, 3]);
    eq('its own counts, not the correlated children', [d.attribute_count, d.object_count], [36, 9]);
    eq('its tags', d.tags, [{ name: 'tlp:white', colour: '#ffffff' }]);
    eq('its galaxy clusters', d.context, [{ galaxy_type: 'tool', value: 'BabyShark' }]);
    const bare = r.nodes.find(n => n.id === 'event:R8').data;
    eq('without a card, the pair\'s event still draws its title', [bare.label, bare.tags], ['Event 8', undefined]);
});

test('this event\'s side of a pair comes along when it is not on the canvas', async () => {
    const g = await withPivots();
    const r = await pivot(g, 'correlations').fetch([pnode({ type: 'attribute', uuid: 'e1' })], {}, {});
    const own = r.nodes.filter(n => n.data.scope === 'self').map(n => n.id).sort();
    eq('only the one not drawn: c1 is already on the canvas, inside object A', own, ['attr:e1']);
    eq('and drawn from the event payload', r.nodes.find(n => n.id === 'attr:e1').data.uuid, 'e1');
});

/* ──────────────── task 10: what a drawn edge can be ─────────────── */

const VOCAB = [
    { name: 'related-to' }, { name: 'drops' }, { name: "<script>alert('name')</script>" },
    { name: '' }, { name: null },
];

function editorFixture() {
    return ev({
        Attribute: [attr({ uuid: 'e1' })],
        Object: [
            obj({ uuid: 'A', Attribute: [attr({ uuid: 'c1' })] }),
            obj({ uuid: 'B' }),
        ],
    });
}

// Boot as an editor, recording every POST to objectReferences/add.
function withEditor(extraRoutes) {
    const posts = [];
    return buildGraph(editorFixture(), {
        routes: (extraRoutes || []).concat([
            [/objectRelationships\/index\.json$/, VOCAB],
            [/objectReferences\/add\//, init => { posts.push(JSON.parse(init.body)); return {}; }],
            [/correlationCounts/, { attributes: {}, objects: {}, events: {} }],
        ]),
    }).then(g => { g.posts = posts; return g; });
}

// An EdgeCreateContext whose form answers `answer`, recording what it was asked.
function edgeCtx(source, target, answer) {
    const ctx = {
        kind: 'edge', source, target, origin: 'drag', asked: null,
        promptData: opts => { ctx.asked = opts; return Promise.resolve(answer); },
    };
    return ctx;
}

const own = {
    objA: pnode({ type: 'object', uuid: 'A' }),
    objB: pnode({ type: 'object', uuid: 'B' }),
    attrE1: pnode({ type: 'attribute', uuid: 'e1' }),
    childC1: pnode({ type: 'attribute', uuid: 'c1' }),
};
const foreign = {
    attr: pnode({ type: 'attribute', uuid: 'x1', event_id: '7' }),
    obj: pnode({ type: 'object', uuid: 'X' }),
    event: pnode({ type: 'event', uuid: 'R7', event_id: '7' }),
};

test('only drawing a reference reaches MISP, so it is the only write tool an editor keeps', async () => {
    const g = await withEditor();
    eq('editor', g.opts.UI.editors, {
        nodeEditor: { enabled: false }, nodeCreator: { enabled: false },
        edgeEditor: { enabled: false }, edgeCreator: { enabled: true }, deletion: { enabled: true },
    });
    const r = await buildGraph(editorFixture(), { canEdit: false });
    ok('a read-only viewer gets none of them',
       Object.keys(r.opts.UI.editors).every(k => r.opts.UI.editors[k].enabled === false));
    ok('and no edge hooks', !r.opts.callbacks.isValidConnection && !r.opts.callbacks.onBeforeEdgeCreate);
});

test('a reference runs from one of this event\'s objects to one of its attributes or objects', async () => {
    const g = await withEditor();
    const valid = g.opts.callbacks.isValidConnection;
    ok('object → object', valid(own.objA, own.objB));
    ok('object → event-level attribute', valid(own.objA, own.attrE1));
    ok('object → another object\'s attribute', valid(own.objB, own.childC1));
    ok('an attribute cannot own a reference', !valid(own.attrE1, own.objA));
    ok('an event node cannot own one', !valid(foreign.event, own.objA));
    ok('nor be referenced', !valid(own.objA, foreign.event));
    ok('a correlated attribute from another event cannot be referenced', !valid(own.objA, foreign.attr));
    ok('an object that is not this event\'s cannot own one', !valid(foreign.obj, own.objB));
    ok('a note linking itself is not ours to judge', valid({}, own.objA));
});

test('an invalid pair is refused without asking anything', async () => {
    const g = await withEditor();
    const ctx = edgeCtx(own.attrE1, own.objA, { relationship_type: 'drops' });
    eq('refused', await g.opts.callbacks.onBeforeEdgeCreate(ctx), false);
    ok('no form', ctx.asked === null);
    eq('no POST', g.posts.length, 0);
});

test('the form offers the object_relationships vocabulary, sorted, defaulting to related-to', async () => {
    const g = await withEditor();
    const ctx = edgeCtx(own.objA, own.objB, null);
    await g.opts.callbacks.onBeforeEdgeCreate(ctx);
    const select = ctx.asked.fields[0];
    eq('select of names, blanks dropped', [select.key, select.type, select.options.map(o => o.value)],
       ['relationship_type', 'select', ["<script>alert('name')</script>", 'drops', 'related-to']]);
    eq('a name is a label, handed over as text', select.options[0].label, "<script>alert('name')</script>");
    eq('defaults to related-to', select.defaultValue, 'related-to');
    eq('plus a free-text field', [ctx.asked.fields[1].key, ctx.asked.fields[1].type], ['custom', 'text']);
    ok('the vocabulary was asked for once, and only when needed',
       g.fetchLog.filter(f => /objectRelationships/.test(f.url)).length === 1);
});

test('saving: the chosen type is POSTed and the edge lands persisted', async () => {
    const g = await withEditor();
    const d = await g.opts.callbacks.onBeforeEdgeCreate(edgeCtx(own.objA, own.attrE1, { relationship_type: 'drops' }));
    eq('POST body', g.posts, [{ ObjectReference: { referenced_uuid: 'e1', relationship_type: 'drops', comment: '' } }]);
    eq('decision', d, { accept: true, data: { kind: 'object-reference', label: 'drops', relationship_type: 'drops' }, persisted: true });
    ok('to the source object', g.fetchLog.some(f => /\/misp\/objectReferences\/add\/A\.json$/.test(f.url)));
});

test('a typed relationship wins over the list; an empty answer saves nothing', async () => {
    const g = await withEditor();
    await g.opts.callbacks.onBeforeEdgeCreate(edgeCtx(own.objA, own.objB, { relationship_type: 'drops', custom: '  beacons-to ' }));
    eq('custom, trimmed', g.posts[0].ObjectReference.relationship_type, 'beacons-to');
    eq('blank', await g.opts.callbacks.onBeforeEdgeCreate(edgeCtx(own.objA, own.objB, { relationship_type: '', custom: ' ' })), false);
    eq('cancelled', await g.opts.callbacks.onBeforeEdgeCreate(edgeCtx(own.objA, own.objB, null)), false);
    eq('only the first was POSTed', g.posts.length, 1);
});

test('a refused save leaves no edge', async () => {
    const g = await withEditor([[/objectReferences\/add\//, { __status: 403, message: 'no' }]]);
    eq('refused', await g.opts.callbacks.onBeforeEdgeCreate(edgeCtx(own.objA, own.objB, { relationship_type: 'drops' })), false);
});

test('without the vocabulary the form is one free-text field, and asks again next time', async () => {
    const g = await withEditor([[/objectRelationships\/index\.json$/, { __status: 500 }]]);
    const asked = () => g.fetchLog.filter(f => /objectRelationships/.test(f.url)).length;
    await new Promise(r => setTimeout(r, 0));
    const before = asked();
    const ctx = edgeCtx(own.objA, own.objB, { custom: 'drops' });
    eq('saved', (await g.opts.callbacks.onBeforeEdgeCreate(ctx)).accept, true);
    eq('one text field', ctx.asked.fields.map(f => [f.key, f.type]), [['custom', 'text']]);
    await g.opts.callbacks.onBeforeEdgeCreate(edgeCtx(own.objA, own.objB, null));
    eq('asked again on each edge', asked() - before, 2);
});

test('the vocabulary is asked for when the editor attaches, once', async () => {
    const g = await withEditor();
    const asked = () => g.fetchLog.filter(f => /objectRelationships/.test(f.url)).length;
    eq('before any edge is drawn', asked(), 1);
    await g.opts.callbacks.onBeforeEdgeCreate(edgeCtx(own.objA, own.objB, { custom: 'x' }));
    eq('the first edge reuses it', asked(), 1);
});

test('nothing carries a pending flag any more (D2)', async () => {
    const g = await withEditor();
    ok('no styleCb', g.opts.render.defaultNodeStyle.styleCb === undefined);
    ok('no node data carries pending', JSON.stringify(g.nodes).indexOf('pending') === -1);
});

/* ─────────────── task 11: physics adapts after the first frame ─────────────── */

test('physics is auto, seeded by the hand-tuned link distance', async () => {
    const g = await buildGraph(ev({ Attribute: [attr({ uuid: 'e1' })] }));
    eq('both set: a d3 value alone would pin physics to manual',
       g.opts.simulation, { physics: 'auto', d3LinkDistance: 200 });
});

/* ──────────── task 10c: deleting an edge deletes the reference ──────────── */

function deleteFixture() {
    return ev({
        Attribute: [attr({ uuid: 'e1', value: '1.2.3.4' })],
        Object: [
            obj({ uuid: 'A', name: 'file', ObjectReference: [
                ref({ uuid: 'R1', referenced_uuid: 'e1', referenced_type: '0', relationship_type: 'drops' }),
            ] }),
            obj({ uuid: 'B', name: 'domain-ip' }),
        ],
    });
}

// Boot as an editor; every delete POST is logged and answered by `answer`.
function withDeletes(answer) {
    const deletes = [];
    return buildGraph(deleteFixture(), {
        routes: [
            [/objectReferences\/delete\//, init => {
                deletes.push(init);
                return answer ? answer(deletes.length) : { saved: true };
            }],
            [/objectReferences\/add\//, { ObjectReference: { uuid: 'R-NEW', id: '9' } }],
            [/objectRelationships\/index\.json$/, VOCAB],
            [/correlationCounts/, { attributes: {}, objects: {}, events: {} }],
        ],
    }).then(g => { g.deletes = deletes; return g; });
}

const pedge = (id, from, to, data) => ({ id, from, to, getData: () => data });
const refEdge = (uuid, label) => pedge('ref:' + uuid,
    pnode({ type: 'object', uuid: 'A', label: 'file' }),
    pnode({ type: 'attribute', uuid: 'e1', label: '1.2.3.4' }),
    { kind: 'object-reference', label: label || 'drops', uuid });
const corrEdge = pedge('corr:1', pnode({ label: 'a' }), pnode({ label: 'b' }), { kind: 'correlation', label: '' });
const arelEdge = pedge('arel:1', pnode({ label: 'a' }), pnode({ label: 'b' }), { kind: 'analyst-relationship', label: 'x' });

// A DeleteContext whose confirm answers `yes`, recording what it was shown.
function delCtx(parts, yes) {
    const ctx = Object.assign({ nodes: [], edges: [], notes: [], cascadingEdges: [], origin: 'bulk-action' }, parts);
    ctx.asked = null;
    ctx.confirm = opts => { ctx.asked = opts; return Promise.resolve(yes); };
    return ctx;
}

test('a seeded reference edge knows its reference, so it can be found again in MISP', async () => {
    const g = await withDeletes();
    eq('uuid on the edge', g.edges.filter(e => e.data.kind === 'object-reference').map(e => e.data.uuid), ['R1']);
});

test('a drawn reference takes the uuid MISP gave it', async () => {
    const g = await withDeletes();
    const d = await g.opts.callbacks.onBeforeEdgeCreate(edgeCtx(own.objA, own.objB, { relationship_type: 'drops' }));
    eq('decision', d, { accept: true, data: { kind: 'object-reference', label: 'drops', relationship_type: 'drops', uuid: 'R-NEW' }, persisted: true });
});

test('deleting a node is refused, and says where it is done instead', async () => {
    const g = await withDeletes();
    const ctx = delCtx({ nodes: [own.objA], edges: [refEdge('R1')] }, true);
    eq('vetoed', await g.opts.callbacks.onBeforeDelete(ctx), false);
    ok('nothing asked', ctx.asked === null);
    eq('nothing deleted', g.deletes.length, 0);
    eq('one warning naming Hide', g.graph.notices.map(n => [n.level, /Hide/.test(n.msg)]), [['warning', true]]);
});

test('an edge is deleted in MISP only after a danger confirm saying it cannot be undone', async () => {
    const g = await withDeletes();
    const ctx = delCtx({ edges: [refEdge('R1')] }, true);
    const d = await g.opts.callbacks.onBeforeDelete(ctx);
    eq('confirm', [ctx.asked.variant, ctx.asked.confirmLabel, ctx.asked.title], ['danger', 'Delete in MISP', 'Delete relationship']);
    eq('body names the relationship and the consequence', ctx.asked.body,
       'This deletes the relationship in MISP: file → drops → 1.2.3.4. It cannot be undone from the graph.');
    ok('a soft delete, by uuid, as a POST',
       g.fetchLog.some(f => /\/misp\/objectReferences\/delete\/R1\.json$/.test(f.url) && f.init.method === 'POST'));
    eq('the history row is sealed', [d.accept, d.edges.map(e => e.id), d.persisted], [true, ['ref:R1'], true]);
});

test('the confirm bounds a long element name itself; the label stays whole', async () => {
    const g = await withDeletes();
    const edge = pedge('ref:R1', pnode({ type: 'object', uuid: 'A', label: 'file' }),
        pnode({ type: 'attribute', uuid: 'e1', label: 'y'.repeat(80) }),
        { kind: 'object-reference', label: 'drops', uuid: 'R1' });
    const ctx = delCtx({ edges: [edge] }, false);
    await g.opts.callbacks.onBeforeDelete(ctx);
    eq('body', ctx.asked.body, 'This deletes the relationship in MISP: file → drops → '
       + 'y'.repeat(41) + '…. It cannot be undone from the graph.');
});

test('cancelling the confirm deletes nothing', async () => {
    const g = await withDeletes();
    eq('vetoed', await g.opts.callbacks.onBeforeDelete(delCtx({ edges: [refEdge('R1')] }, false)), false);
    eq('no POST', g.deletes.length, 0);
});

test('only what MISP deleted leaves the canvas', async () => {
    const g = await withDeletes(n => (n === 2 ? { __status: 403, saved: false, errors: 'no' } : { saved: true }));
    const edges = [refEdge('R1'), refEdge('R2', 'uses'), refEdge('R3', 'hosts'), refEdge('R4', 'x')];
    const ctx = delCtx({ edges }, true);
    const d = await g.opts.callbacks.onBeforeDelete(ctx);
    ok('the body lists three and counts the rest', /hosts → 1\.2\.3\.4; and 1 more\. /.test(ctx.asked.body), ctx.asked.body);
    eq('narrowed to the three that went', d.edges.length, 3);
    eq('the refusal is reported in MISP\'s words',
       g.graph.notices.filter(n => n.level === 'error').map(n => n.msg), ['file → uses → 1.2.3.4: no']);
    const none = await withDeletes(() => ({ __status: 500 }));
    eq('all refused: nothing leaves', await none.opts.callbacks.onBeforeDelete(delCtx({ edges: [refEdge('R1')] }, true)), false);
});

test('derived and analyst edges are spared, not deleted, and the rest goes ahead', async () => {
    const g = await withDeletes();
    const d = await g.opts.callbacks.onBeforeDelete(delCtx({ edges: [corrEdge, refEdge('R1'), arelEdge] }, true));
    eq('only the reference', d.edges.map(e => e.id), ['ref:R1']);
    eq('one POST', g.deletes.length, 1);
    ok('told why', g.graph.notices.some(n => n.level === 'info'));
    const ctx = delCtx({ edges: [corrEdge], notes: [{ id: 'n1' }] }, true);
    eq('nothing deletable: the note still goes, the edge stays', await g.opts.callbacks.onBeforeDelete(ctx), { accept: true, edges: [] });
    ok('without a confirm', ctx.asked === null);
    eq('a reference with no uuid is spared too',
       (await g.opts.callbacks.onBeforeDelete(delCtx({ edges: [refEdge(undefined)] }, true))).edges, []);
    const foreignRef = pedge('ref:RF', pnode({ type: 'object', uuid: 'OB', scope: 'foreign', label: 'domain-ip' }),
        pnode({ type: 'object', uuid: 'OB2', scope: 'foreign', label: 'file' }),
        { kind: 'object-reference', label: 'resolves-to', uuid: 'RF' });
    eq('another event\'s reference is spared',
       (await g.opts.callbacks.onBeforeDelete(delCtx({ edges: [foreignRef] }, true))).edges, []);
});

test('notes alone are canvas-only and go straight through', async () => {
    const g = await withDeletes();
    const ctx = delCtx({ notes: [{ id: 'n1' }] }, true);
    eq('accepted', await g.opts.callbacks.onBeforeDelete(ctx), true);
    ok('no confirm, no POST', ctx.asked === null && g.deletes.length === 0);
});

test('a read-only viewer has no delete hook', async () => {
    const r = await buildGraph(deleteFixture(), { canEdit: false });
    ok('none', !r.opts.callbacks.onBeforeDelete);
});

/* ──────── task 10b: analyst relationships, drawn and deleted ──────── */

// Boot with the given rights, recording every analyst-data POST.
function withAnalyst(options, answers) {
    const adds = [], deletes = [];
    answers = answers || {};
    return buildGraph(editorFixture(), Object.assign({
        routes: [
            [/analystData\/add\/Relationship\//, init => {
                adds.push(JSON.parse(init.body));
                return answers.add || { Relationship: { uuid: 'AR-NEW', orgc_uuid: 'ORG-ME', authors: 'me@x' } };
            }],
            [/analystData\/delete\/Relationship\//, init => { deletes.push(init); return answers.del || { saved: true }; }],
            [/objectReferences\/add\//, { ObjectReference: { uuid: 'R-NEW' } }],
            [/objectReferences\/delete\//, { saved: true }],
            [/objectRelationships\/index\.json$/, VOCAB],
            [/correlationCounts/, { attributes: {}, objects: {}, events: {} }],
        ],
    }, options)).then(g => { g.adds = adds; g.deletes = deletes; return g; });
}
const analystOnly = { canEdit: false, canAnalyst: true, orgUuid: 'ORG-ME' };
const both = { canAnalyst: true, orgUuid: 'ORG-ME' };

const arEdge = (uuid, orgc) => pedge('ar:' + uuid,
    pnode({ type: 'attribute', uuid: 'e1', label: '1.2.3.4' }),
    pnode({ type: 'object', uuid: 'A', label: 'file' }),
    { kind: 'analyst-relationship', label: 'seen-with', uuid, orgc });

test('a seeded analyst relationship edge knows its relationship', async () => {
    const g = await buildGraph(ev({
        Attribute: [attr({ uuid: 'e1', Relationship: [arel({ uuid: 'AR1', related_object_uuid: 'A' })] })],
        Object: [obj({ uuid: 'A' })],
    }));
    eq('uuid and creator org on the edge',
       g.edges.filter(e => e.data.kind === 'analyst-relationship').map(e => [e.data.uuid, e.data.orgc]),
       [['AR1', 'org-1']]);
});

test('analyst rights alone give back the edge tool and delete, and the hooks', async () => {
    const g = await withAnalyst(analystOnly);
    eq('edge tool and delete only', Object.keys(g.opts.UI.editors).filter(k => g.opts.UI.editors[k].enabled),
       ['edgeCreator', 'deletion']);
    ok('hooks', !!g.opts.callbacks.isValidConnection && !!g.opts.callbacks.onBeforeEdgeCreate
       && !!g.opts.callbacks.onBeforeDelete);
});

test('an analyst relationship joins any two nameable elements, this event\'s or not', async () => {
    const g = await withAnalyst(analystOnly);
    const valid = g.opts.callbacks.isValidConnection;
    ok('attribute → object', valid(own.attrE1, own.objA));
    ok('to another event\'s attribute', valid(own.objA, foreign.attr));
    ok('from another event\'s attribute', valid(foreign.attr, own.objB));
    ok('from and to an event node', valid(foreign.event, own.attrE1) && valid(own.objA, foreign.event));
    ok('not to itself', !valid(own.objA, pnode({ type: 'object', uuid: 'A' })));
    ok('not to an element MISP cannot name', !valid(own.objA, pnode({ type: 'feed', uuid: 'F' })));
    ok('not without a uuid', !valid(own.objA, pnode({ type: 'attribute' })));
    const e = await withEditor();
    ok('an editor without analyst rights still draws references only', !e.opts.callbacks.isValidConnection(own.attrE1, own.objA));
});

test('one possible kind asks no link type; two ask, defaulting to the reference', async () => {
    const a = await withAnalyst(analystOnly);
    const one = edgeCtx(own.objA, own.objB, null);
    await a.opts.callbacks.onBeforeEdgeCreate(one);
    eq('analyst only: no link type, and how it is shared in the same form', one.asked.fields.map(f => f.key),
       ['relationship_type', 'custom', 'distribution', 'authors']);
    const b = await withAnalyst(both);
    const two = edgeCtx(own.objA, own.objB, null);
    await b.opts.callbacks.onBeforeEdgeCreate(two);
    const kind = two.asked.fields[0];
    eq('link type first', [kind.key, kind.type, kind.defaultValue], ['kind', 'select', 'object-reference']);
    eq('both offered, worded', kind.options, [
        { label: 'Object reference', value: 'object-reference' },
        { label: 'Analyst relationship', value: 'analyst-relationship' },
    ]);
    const c = await withAnalyst(both);
    const across = edgeCtx(own.objA, foreign.attr, null);
    await c.opts.callbacks.onBeforeEdgeCreate(across);
    ok('across events only the analyst kind remains, so no question', across.asked.fields[0].key !== 'kind');
});

test('saving an analyst relationship: addressed by MISP type, landing with what MISP returned', async () => {
    const g = await withAnalyst(analystOnly);
    const d = await g.opts.callbacks.onBeforeEdgeCreate(edgeCtx(own.attrE1, foreign.attr, { custom: 'seen-with' }));
    ok('to the source, typed', g.fetchLog.some(f => /\/misp\/analystData\/add\/Relationship\/e1\/Attribute\.json$/.test(f.url)));
    eq('body', g.adds, [{ Relationship: { related_object_uuid: 'x1', related_object_type: 'Attribute',
                                          relationship_type: 'seen-with', distribution: '1' } }]);
    eq('decision', d, { accept: true,
        data: { kind: 'analyst-relationship', label: 'seen-with', relationship_type: 'seen-with',
                uuid: 'AR-NEW', orgc: 'ORG-ME', authors: 'me@x' },
        persisted: true });
    await g.opts.callbacks.onBeforeEdgeCreate(edgeCtx(foreign.event, own.objA, { custom: 'about' }));
    eq('an event source and an object target', g.adds[1].Relationship.related_object_type, 'Object');
    ok('event source path', g.fetchLog.some(f => /analystData\/add\/Relationship\/R7\/Event\.json$/.test(f.url)));
});

test('the chosen link type decides the write; an unoffered one falls back to the first', async () => {
    const g = await withAnalyst(both);
    await g.opts.callbacks.onBeforeEdgeCreate(edgeCtx(own.objA, own.objB, { kind: 'analyst-relationship', custom: 'x' }));
    eq('analyst chosen: analyst POST only', [g.adds.length, g.fetchLog.filter(f => /objectReferences\/add/.test(f.url)).length], [1, 0]);
    const d = await g.opts.callbacks.onBeforeEdgeCreate(edgeCtx(own.objA, own.objB, { kind: 'bogus', custom: 'y' }));
    eq('bogus: the reference', d.data.kind, 'object-reference');
});

/* ──── how an analyst relationship is shared: distribution, sharing group, authors ──── */

const SHARING = JSON.stringify({
    levels: [[0, 'Your organisation only'], [1, 'This community only'], [2, 'Connected communities'],
             [3, 'All communities'], [4, 'Sharing group']],
    sharingGroups: [[5, 'Alpha'], [3, 'Beta']],
    default: 2, authors: 'me@x',
});

// A context answering each form in turn, recording every one it was shown.
function edgeCtxSeq(source, target, answers) {
    const ctx = {
        kind: 'edge', source, target, origin: 'drag', asks: [],
        promptData: opts => { ctx.asks.push(opts); return Promise.resolve(answers[ctx.asks.length - 1]); },
    };
    return ctx;
}

test('sharing: the form offers MISP\'s levels, the user\'s sharing groups and the author', async () => {
    const g = await withAnalyst(Object.assign({ analystSharing: SHARING }, analystOnly));
    const ctx = edgeCtxSeq(own.objA, own.objB, [null]);
    await g.opts.callbacks.onBeforeEdgeCreate(ctx);
    eq('one form, saving', [ctx.asks.length, ctx.asks[0].submitLabel], [1, 'Save']);
    const f = {}; ctx.asks[0].fields.forEach(x => { f[x.key] = x; });
    eq('distribution: the five levels, the instance default', [f.distribution.type, f.distribution.options.map(o => o.value),
       f.distribution.defaultValue], ['select', ['0', '1', '2', '3', '4'], '2']);
    eq('named as MISP names them', f.distribution.options[4].label, 'Sharing group');
    eq('sharing groups in the order given, none picked', [f.sharing_group_id.options.map(o => o.label), f.sharing_group_id.defaultValue],
       [['—', 'Alpha', 'Beta'], '']);
    eq('authors, blank meaning the user', [f.authors.type, f.authors.placeholder], ['text', 'me@x']);
});

test('sharing: with no sharing group to offer, none is asked', async () => {
    const none = JSON.stringify(Object.assign(JSON.parse(SHARING), { sharingGroups: [] }));
    const g = await withAnalyst(Object.assign({ analystSharing: none }, analystOnly));
    const ctx = edgeCtxSeq(own.objA, own.objB, [null]);
    await g.opts.callbacks.onBeforeEdgeCreate(ctx);
    eq('fields', ctx.asks[0].fields.map(x => x.key), ['relationship_type', 'custom', 'distribution', 'authors']);
});

test('sharing: with two kinds it is asked second, and only for the analyst kind', async () => {
    const g = await withAnalyst(Object.assign({ analystSharing: SHARING }, both));
    const ref = edgeCtxSeq(own.objA, own.objB, [{ kind: 'object-reference', custom: 'r' }]);
    await g.opts.callbacks.onBeforeEdgeCreate(ref);
    eq('a reference asks once, with no sharing', [ref.asks.length, ref.asks[0].submitLabel,
       ref.asks[0].fields.some(x => x.key === 'distribution')], [1, 'Next', false]);
    const ar = edgeCtxSeq(own.objA, own.objB, [{ kind: 'analyst-relationship', custom: 'a' },
                                               { distribution: '3', authors: ' Alice ' }]);
    const d = await g.opts.callbacks.onBeforeEdgeCreate(ar);
    eq('the second form', [ar.asks.length, ar.asks[1].title, ar.asks[1].submitLabel, ar.asks[1].fields.map(x => x.key)],
       [2, 'Share the relationship', 'Save', ['distribution', 'sharing_group_id', 'authors']]);
    eq('saved as answered, authors trimmed', g.adds, [{ Relationship: { related_object_uuid: 'B', related_object_type: 'Object',
       relationship_type: 'a', distribution: '3', authors: 'Alice' } }]);
    eq('and it lands', d.accept, true);
    const cancelled = edgeCtxSeq(own.objA, own.objB, [{ kind: 'analyst-relationship', custom: 'a' }, null]);
    eq('cancelling the second form saves nothing', [await g.opts.callbacks.onBeforeEdgeCreate(cancelled), g.adds.length],
       [false, 1]);
});

test('sharing: a sharing group level needs its group; any other level drops one', async () => {
    const g = await withAnalyst(Object.assign({ analystSharing: SHARING }, analystOnly));
    const missing = edgeCtxSeq(own.objA, own.objB, [{ custom: 'x', distribution: '4' }]);
    eq('refused before any POST', [await g.opts.callbacks.onBeforeEdgeCreate(missing), g.adds.length], [false, 0]);
    eq('and says why', g.graph.notices.map(n => [n.level, n.title]), [['warning', 'No sharing group']]);
    await g.opts.callbacks.onBeforeEdgeCreate(edgeCtxSeq(own.objA, own.objB, [{ custom: 'x', distribution: '4', sharing_group_id: '5' }]));
    await g.opts.callbacks.onBeforeEdgeCreate(edgeCtxSeq(own.objA, own.objB, [{ custom: 'y', distribution: '0', sharing_group_id: '5' }]));
    eq('the group goes with level 4 only', g.adds.map(a => [a.Relationship.distribution, a.Relationship.sharing_group_id]),
       [['4', '5'], ['0', undefined]]);
});

test('sharing: unreadable options fall back to the defaults', async () => {
    const g = await withAnalyst(Object.assign({ analystSharing: '{not json' }, analystOnly));
    await g.opts.callbacks.onBeforeEdgeCreate(edgeCtxSeq(own.objA, own.objB, [{ custom: 'x' }]));
    eq('saved at level 1', g.adds.map(a => a.Relationship.distribution), ['1']);
    ok('and said so in the console', g.errors.some(e => /analyst sharing/.test(e)), JSON.stringify(g.errors));
});

test('a refused analyst save leaves no edge', async () => {
    const g = await withAnalyst(analystOnly, { add: { __status: 403, message: 'nope' } });
    eq('refused', await g.opts.callbacks.onBeforeEdgeCreate(edgeCtx(own.attrE1, own.objA, { custom: 'x' })), false);
    ok('reported', g.graph.notices.some(n => n.level === 'error' && n.msg === 'nope'));
});

test('an analyst relationship is deleted only where MISP would allow it', async () => {
    const g = await withAnalyst(analystOnly);
    const d = await g.opts.callbacks.onBeforeDelete(delCtx({ edges: [arEdge('AR1', 'ORG-ME'), arEdge('AR2', 'ORG-THEM')] }, true));
    eq('my org\'s goes, theirs stays', d.edges.map(e => e.id), ['ar:AR1']);
    ok('by uuid', g.fetchLog.some(f => /\/misp\/analystData\/delete\/Relationship\/AR1\.json$/.test(f.url)));
    eq('sealed', d.persisted, true);
    eq('an analyst-only user cannot delete a reference',
       await g.opts.callbacks.onBeforeDelete(delCtx({ edges: [refEdge('R1')] }, true)), { accept: true, edges: [] });
    const admin = await withAnalyst(Object.assign({ siteAdmin: true }, analystOnly));
    eq('a site admin deletes any org\'s',
       (await admin.opts.callbacks.onBeforeDelete(delCtx({ edges: [arEdge('AR2', 'ORG-THEM')] }, true))).edges.length, 1);
    const editor = await withAnalyst({ orgUuid: 'ORG-ME' });
    eq('an editor without analyst rights cannot delete one',
       await editor.opts.callbacks.onBeforeDelete(delCtx({ edges: [arEdge('AR1', 'ORG-ME')] }, true)), { accept: true, edges: [] });
    const noOrg = await withAnalyst({ canEdit: false, canAnalyst: true });
    eq('an unknown org matches nothing, not even a blank orgc',
       await noOrg.opts.callbacks.onBeforeDelete(delCtx({ edges: [arEdge('AR3', '')] }, true)), { accept: true, edges: [] });
});

test('a mixed selection deletes each kind at its own endpoint', async () => {
    const g = await withAnalyst(both);
    const d = await g.opts.callbacks.onBeforeDelete(delCtx({ edges: [refEdge('R1'), arEdge('AR1', 'ORG-ME')] }, true));
    eq('both', d.edges.map(e => e.id), ['ref:R1', 'ar:AR1']);
    ok('reference soft', g.fetchLog.some(f => /objectReferences\/delete\/R1\.json$/.test(f.url)));
    ok('relationship at analystData', g.fetchLog.some(f => /analystData\/delete\/Relationship\/AR1\.json$/.test(f.url)));
});

/* ─────────── task 9: the event's elements, as an origin-less pivot ─────────── */

const elementsOf = g => g.opts.pivots.find(p => p.id === 'event-elements');
const offered = (g, narrowing) => elementsOf(g).fetch([], narrowing || {}, {}).nodes.map(n => n.id).sort();

// Over the budget, so L2 is skipped and objects are on offer too.
function elementFixture() {
    return ev({
        Attribute: [
            attr({ uuid: 'a1', value: 'Evil.COM', type: 'domain', category: 'Network activity' }),
            attr({ uuid: 'a2', value: '10.0.0.1', type: 'ip-dst', category: 'Network activity', comment: 'the evil box' }),
            attr({ uuid: 'a3', value: 'deadbeef', type: 'md5', category: 'Payload delivery' }),
            attr({ uuid: 'a4', value: 'evil.com', deleted: true }),
        ],
        Object: fillers(1500).concat([
            obj({ uuid: 'O', name: 'domain-ip', 'meta-category': 'network', Attribute: [
                attr({ uuid: 'oc1', value: 'sub.evil.com', object_relation: 'domain' }),
                attr({ uuid: 'oc2', value: 'hidden', deleted: true }),
            ] }),
        ]),
    });
}

test('the element pivot needs no origin, refuses above the budget, and saves nothing', async () => {
    const g = await buildGraph(ev({}));
    const p = elementsOf(g);
    eq('shape', [p.origin, p.maxCandidates, p.save, typeof p.appliesTo], ['none', 1500, undefined, 'undefined']);
    eq('named for what it lists', p.label, 'Event elements');
});

test('it offers every live element the canvas lacks, objects whole', async () => {
    const g = await buildGraph(elementFixture());
    const ids = offered(g);
    ok('event-level attributes, deleted ones excluded',
       ['attr:a1', 'attr:a2', 'attr:a3'].every(i => ids.indexOf(i) !== -1) && ids.indexOf('attr:a4') === -1);
    ok('an object, not its attributes on their own',
       ids.indexOf('obj:O') !== -1 && ids.indexOf('attr:oc1') === -1);
    const o = elementsOf(g).fetch([], { q: 'domain-ip' }, {}).nodes[0];
    eq('the object arrives with its live children', o.children.map(c => c.id), ['attr:oc1']);
    eq('drawn like any object', o.data.type, 'object');
});

test('search is case-insensitive, and reaches values, types, categories and comments', async () => {
    const g = await buildGraph(elementFixture());
    eq('a value, either case', offered(g, { q: 'EVIL.com' }), ['attr:a1', 'obj:O']);
    eq('a comment', offered(g, { q: 'evil box' }), ['attr:a2']);
    eq('a type', offered(g, { q: 'md5' }), ['attr:a3']);
    eq('a category', offered(g, { q: 'payload' }), ['attr:a3']);
    eq('surrounding space ignored', offered(g, { q: '  deadbeef ' }), ['attr:a3']);
    eq('an object answers for its attributes', offered(g, { q: 'sub.evil' }), ['obj:O']);
    eq('but not for its deleted ones', offered(g, { q: 'hidden' }), []);
});

test('element and category narrow, and the summary counts what the fetch would bring', async () => {
    const g = await buildGraph(elementFixture());
    const p = elementsOf(g);
    eq('element', offered(g, { element: 'attribute' }), ['attr:a1', 'attr:a2', 'attr:a3']);
    eq('category', offered(g, { category: 'Network activity' }), ['attr:a1', 'attr:a2']);
    eq('together with search', offered(g, { q: 'evil', element: 'object' }), ['obj:O']);
    [{}, { q: 'evil' }, { element: 'object' }, { category: 'Payload delivery' }].forEach(n => {
        eq('summary = fetch for ' + JSON.stringify(n), p.summarize([], n).total, p.fetch([], n, {}).nodes.length);
    });
    eq('unnarrowed, the budget refuses it: 3 attributes and 1,501 objects', p.summarize([], {}).total, 1504);
});

test('the form: a search box, then element and category with their counts', async () => {
    const g = await buildGraph(elementFixture());
    const f = elementsOf(g).summarize([], {}).facets;
    eq('fields', f.map(x => [x.key, x.type]), [['q', 'text'], ['element', 'multiselect'], ['category', 'select']]);
    eq('element counts', f[1].options, [
        { label: 'Attributes', value: 'attribute', count: 3 },
        { label: 'Objects', value: 'object', count: 1501 },
    ]);
    eq('attributes and objects picked by default', f[1].default, ['attribute', 'object']);
    eq('category counts, objects by meta-category',
       f[2].options.map(o => [o.value, o.count]),
       [['Network activity', 2], ['Payload delivery', 1], ['file', 1500], ['network', 1]]);
});

// A tag on the event itself, a tag and a cluster on an event-level attribute,
// a tag on an object's attribute, and one on a deleted attribute.
function labelledElementFixture() {
    return ev({
        Tag: [{ name: 'tlp:white', colour: '#ffffff', is_galaxy: false }],
        Attribute: [
            attr({ uuid: 'a1', value: 'evil.com', type: 'domain', category: 'Network activity',
                   Tag: [{ name: 'osint:source-type="blog-post"', colour: '#00a' }, TAG_APT], Galaxy: [GAL_APT] }),
            attr({ uuid: 'a2', value: 'gone', deleted: true, Tag: [{ name: 'stale', colour: '#000' }] }),
        ],
        Object: [obj({ uuid: 'O', name: 'file', 'meta-category': 'file', Attribute: [
            attr({ uuid: 'oc1', value: 'x.exe', Tag: [{ name: 'admiralty-scale:source-reliability="f"' }] }),
        ] })],
    });
}

const TAG_KINDS = { element: ['tag', 'cluster'] };

test('elements: the event\'s tags and clusters are offered, but a plain browse leaves them out', async () => {
    const g = await buildGraph(labelledElementFixture());
    const p = elementsOf(g);
    eq('by default, the event\'s contents', offered(g).filter(i => !/^(attr|obj):/.test(i)), []);
    eq('asked for, every tag and cluster the event carries, on itself or a live attribute', offered(g, TAG_KINDS), [
        'cluster:misp-galaxy:threat-actor="APT28"',
        'tag:admiralty-scale:source-reliability="f"',
        'tag:osint:source-type="blog-post"',
        'tag:tlp:white',
    ]);
    eq('the picker offers them, unpicked', p.summarize([], {}).facets[1].options.map(o => [o.value, o.label, o.count]),
       [['attribute', 'Attributes', 1], ['object', 'Objects', 1], ['tag', 'Tags', 3], ['cluster', 'Galaxy clusters', 1]]);
    eq('category counts leave them out', p.summarize([], {}).facets[2].options.map(o => o.value),
       ['Network activity', 'file']);
    eq('a category pick leaves them out', offered(g, { element: ['attribute', 'tag'], category: 'Network activity' }),
       ['attr:a1']);
    eq('the one-kind string form still reads', offered(g, { element: 'tag' }).length, 3);
    eq('an empty pick is nothing', offered(g, { element: [] }), []);
    [{}, TAG_KINDS, { element: ['tag'], q: 'TLP' }].forEach(n => {
        eq('summary = fetch for ' + JSON.stringify(n), p.summarize([], n).total, p.fetch([], n, {}).nodes.length);
    });
});

test('elements: a tag lands as the tag pivot draws it, and by itself when nothing drawn carries it', async () => {
    const g = await buildGraph(labelledElementFixture());
    const r = elementsOf(g).fetch([], { element: ['tag', 'cluster'], q: 'tlp' }, {});
    eq('the event\'s own tag', r.nodes.map(n => [n.id, n.data.type, n.data.name]), [['tag:tlp:white', 'tag', 'tlp:white']]);
    eq('with no edge', r.edges, []);
    eq('search reaches a cluster by its value', offered(g, { element: ['cluster'], q: 'apt28' }),
       ['cluster:misp-galaxy:threat-actor="APT28"']);
});

test('elements: a tag already drawn is not offered, and one on a drawn attribute is joined to it', async () => {
    const g = await buildGraph(labelledElementFixture());
    g.graph.liveNode({ id: 'attr:a1', data: { type: 'attribute', uuid: 'a1',
                                              tags: [{ name: 'osint:source-type="blog-post"' }] } });
    g.graph.liveNode({ id: 'tag:tlp:white', data: { type: 'tag', name: 'tlp:white' } });
    ok('the drawn tag is left out', offered(g, TAG_KINDS).indexOf('tag:tlp:white') === -1);
    const r = elementsOf(g).fetch([], { element: ['tag'], q: 'blog-post' }, {});
    eq('the drawn carrier is joined', r.edges.map(e => [e.from, e.to]), [['attr:a1', 'tag:osint:source-type="blog-post"']]);
});

test('its summaries are dropped whenever a node comes or goes', async () => {
    const g = await buildGraph(ev({}));
    ['nodeAdd', 'nodeRemove'].forEach(evt => {
        ok(evt + ' is watched', (g.graph.listeners[evt] || []).length >= 1);
        g.graph.listeners[evt].forEach(f => f(pnode({})));
    });
    const once = ['event-elements', 'object-surroundings', 'card-attributes', 'card-ids', 'card-network', 'card-correlations'];
    eq('each drops this pivot\'s cache, and those of the pivots that leave out what is drawn',
       g.graph.pivots.invalidated, once.concat(once));
});

/* ─────────────── task 6: analyst-data badges and panel ─────────────── */

const note = o => Object.assign({ note_type_name: 'Note', note: 'n', authors: 'a@x', created: '2025-03-11 14:06:56', Orgc: { name: 'CIRCL' } }, o);
const opinion = o => Object.assign({ note_type_name: 'Opinion', opinion: '50', comment: '', authors: 'a@x', created: '2025-03-12 09:00:00', Orgc: { name: 'CIRCL' } }, o);

function analystFixture() {
    return ev({
        Note: [note({ note: 'about the event' })],
        // What puts the event node on the canvas for its note to sit on.
        Relationship: [arel({ object_uuid: 'EV-SELF', related_object_uuid: 'c2',
                              related_object_type: 'Attribute' })],
        Object: [
            // A's references are what put the other objects on the canvas.
            obj({ uuid: 'A', Opinion: [opinion({ opinion: '10', comment: 'Clearly a FP' })],
                  ObjectReference: ['B', 'C', 'at40', 'at41', 'at60', 'at61'].map(u => ref({ referenced_uuid: u })), Attribute: [
                attr({ uuid: 'c1', value: 'noted',
                       Note: [note({ note: '<b>first</b>', Opinion: [opinion({ opinion: '0' })] }), note({ note: 'second' })],
                       Opinion: [opinion({ opinion: '80' }), opinion({ opinion: '70' })],
                       Relationship: [arel({ related_object_uuid: 'c2', related_object_type: 'Attribute' })] }),
                attr({ uuid: 'c2', value: 'quiet' }),
            ] }),
            obj({ uuid: 'B', Opinion: [opinion({ opinion: '55' })] }),
            obj({ uuid: 'C', Note: [note()] }),
        ].concat(['40', '41', '60', '61'].map(v =>
            obj({ uuid: 'at' + v, Opinion: [opinion({ opinion: v })] }))),
    });
}

const nodeById = (nodes, id) => {
    for (const n of nodes || []) {
        if (n.id === id) return n;
        const c = nodeById(n.children, id);
        if (c) return c;
    }
    return null;
};
const badgesOf = (g, data) => g.opts.render.defaultNodeStyle.badges(pnode(data));

test('an element wears one badge: everything said about it, coloured by its own opinions', async () => {
    const g = await buildGraph(analystFixture());
    const c1 = nodeById(g.nodes, 'attr:c1').data;
    eq('two notes, two opinions, and an opinion on a note — not the relationship, which is an edge', c1.analyst_count, 5);
    eq('mean of its own opinions, 75: endorsed — the 0 on a note does not count', c1.analyst_mood, 'endorsed');
    eq('an object\'s 10 is disputed', nodeById(g.nodes, 'obj:A').data.analyst_mood, 'disputed');
    eq('55 is neutral', nodeById(g.nodes, 'obj:B').data.analyst_mood, 'neutral');
    eq('notes alone have no mood', nodeById(g.nodes, 'obj:C').data.analyst_mood, 'none');
    eq('the band edges: 40 | 41 … 60 | 61', ['40', '41', '60', '61'].map(v => nodeById(g.nodes, 'obj:at' + v).data.analyst_mood),
       ['disputed', 'neutral', 'neutral', 'endorsed']);
    eq('the event node carries its own', nodeById(g.nodes, 'event:EV-SELF').data.analyst_count, 1);
    const b = badgesOf(g, c1);
    eq('one badge, north-west, a bubble without a count',
       b.map(x => [x.position, x.text, x.color]), [['nw', null, '#6fbe80']]);
    eq('it says what it counts', b[0].title, '5 notes and opinions — endorsed');
    eq('colours', ['disputed', 'neutral', 'none'].map(m => badgesOf(g, { analyst_count: 1, analyst_mood: m })[0].color),
       ['#b94a48', '#999', '#999']);
    eq('singular', badgesOf(g, { analyst_count: 1, analyst_mood: 'none' })[0].title, '1 note or opinion');
});

test('an object does not add up its attributes\' badges', async () => {
    const g = await buildGraph(analystFixture());
    eq('A counts only its own opinion', nodeById(g.nodes, 'obj:A').data.analyst_count, 1);
});

test('nothing said, nothing changed: no fields, no badge', async () => {
    const g = await buildGraph(analystFixture());
    const c2 = nodeById(g.nodes, 'attr:c2').data;
    ok('no analyst fields at all', !('analyst_count' in c2) && !('analyst_mood' in c2));
    eq('an empty badge list', badgesOf(g, c2), []);
});

const analystPanelOf = g => g.opts.UI.extraPanels.find(p => p.id === 'analyst-data');

test('the panel exists only where there is analyst data to show', async () => {
    const quiet = await buildGraph(ev({ Object: [obj({ uuid: 'A' })] }));
    eq('an event without any gets only the shared-labels panel', quiet.opts.UI.extraPanels.map(p => p.id), ['pe-shared']);
    const deep = await buildGraph(ev({ Object: [obj({ uuid: 'A', Attribute: [attr({ uuid: 'c', Note: [note()] })] })] }));
    eq('one note on one object attribute is enough', deep.opts.UI.extraPanels.map(p => p.id), ['pe-shared', 'analyst-data']);
});

const panelText = el => (el.children || []).map(c => c.tagName === '#text' ? c._text : panelText(c)).join('|');

test('the panel lists what was said about the selected element, as text', async () => {
    const g = await buildGraph(analystFixture());
    const panel = analystPanelOf(g);
    ok('reactive by default, hidden with nothing selected', panel.reactive === undefined && !panel.alwaysVisible);
    const out = panel.render(pnode({ type: 'attribute', uuid: 'c1' }));
    eq('five cards', findByClass(out, 'pes-ad-card').length, 5);
    eq('grouped by kind, roots counted', findByClass(out, 'pes-ad-h').map(panelText), ['|Notes (2)', '|Opinions (2)']);
    const t = panelText(out);
    ok('a note\'s text, left as text', t.indexOf('<b>first</b>') !== -1, t);
    ok('an opinion names its band and value', t.indexOf('Agree · 80/100') !== -1 && t.indexOf('Strongly Disagree · 0/100') !== -1, t);
    ok('who and when', t.indexOf('a@x') !== -1 && t.indexOf('2025-03-11') !== -1, t);
    const first = findByClass(out, 'pes-ad-card').find(c => panelText(c).indexOf('<b>first</b>') !== -1);
    const replies = findByClass(first, 'pes-ad-replies');
    eq('the reply nests in what it answers', replies.map(r => findByClass(r, 'pes-ad-card').length), [1]);
    ok('and is the opinion on it', panelText(replies[0]).indexOf('Strongly Disagree · 0/100') !== -1);
});

test('the panel for anything else says so', async () => {
    const g = await buildGraph(analystFixture());
    const render = analystPanelOf(g).render;
    ok('an element nobody commented on', panelText(render(pnode({ type: 'attribute', uuid: 'c2' }))).indexOf('No notes or opinions') !== -1);
    ok('a correlated element from another event', panelText(render(pnode({ type: 'attribute', uuid: 'x1' }))).indexOf('No notes or opinions') !== -1);
    ok('a multi-selection', panelText(render([pnode({ uuid: 'c1' }), pnode({ uuid: 'A' })])).indexOf('single element') !== -1);
    ok('this event, through its node', findByClass(render(pnode({ type: 'event', uuid: 'EV-SELF' })), 'pes-ad-card').length === 1);
});

test('clicking the badge selects its node and opens the sidebar', async () => {
    const g = await buildGraph(analystFixture());
    const n = pnode(nodeById(g.nodes, 'attr:c1').data);
    badgesOf(g, n.getData())[0].onClick({}, n);
    eq('selected', g.graph.selected, [n]);
    eq('sidebar shown', g.graph.UIManager.sidebar.shown, 1);
});

test('17: the panel\'s title counts what was said about the selection', async () => {
    const g = await buildGraph(analystFixture());
    const title = analystPanelOf(g).title;
    eq('with a count', title(pnode(nodeById(g.nodes, 'attr:c1').data)), 'Notes & opinions (5)');
    eq('without', [title(pnode({ type: 'attribute', uuid: 'c2' })), title(null), title([pnode({ analyst_count: 2 })])],
       ['Notes & opinions', 'Notes & opinions', 'Notes & opinions']);
});

/* ─────────── the sidebar: hooks into pivotick's panels ─────────── */

const props = (g, data) => g.opts.UI.propertiesPanel.nodePropertiesMap(pnode(data))
    .map(p => p.name + ': ' + p.value);
const edgeProps = (g, data) => g.opts.UI.propertiesPanel.edgePropertiesMap({ getData: () => data })
    .map(p => p.name + ': ' + p.value);

test('sidebar: a node\'s rows are one per value, for the multi-selection table', async () => {
    const g = await buildGraph(ev({ Object: [obj({ uuid: 'A' })] }));
    eq('an attribute from another event, one row per tag', props(g, {
        type: 'attribute', uuid: 'x', 'attr-type': 'ip-dst', category: 'Network activity', scope: 'foreign',
        tags: [{ name: 'tlp:clear' }, { name: 'type:OSINT' }] }), [
        'Element: attribute', 'Attribute type: ip-dst', 'Category: Network activity',
        'Tag: tlp:clear', 'Tag: type:OSINT']);
    eq('an event, by its org', props(g, { type: 'event', uuid: 'E', org: 'CIRCL', scope: 'foreign' }),
       ['Element: event', 'Organisation: CIRCL']);
});

test('sidebar: several elements go back to pivotick\'s own table, one gets the detail', async () => {
    const g = await buildGraph(ev({ Object: [obj({ uuid: 'A' })] }));
    const render = g.opts.UI.propertiesPanel.render;
    ok('a multi-selection is handed back', render([pnode({ type: 'event' }), pnode({ type: 'event' })]) === undefined);
    ok('so is nothing selected', render(null) === undefined);
    ok('the header hook is set', typeof g.opts.UI.mainHeader.render === 'function');
    // undefined hands the header back to pivotick; null would paint the text "null".
    ok('nothing selected hands the header back', g.opts.UI.mainHeader.render(null) === undefined);
    const shared = g.opts.UI.extraPanels.find(p => p.id === 'pe-shared');
    ok('the shared-labels panel has nothing for one element', shared.render(pnode({ type: 'event' })) === undefined);
    ok('nor for several links', shared.render([{ from: {}, to: {}, getData: () => ({}) }]) === undefined);
});

test('sidebar: the neighbour graph draws small nodes and does not zoom in', async () => {
    const g = await buildGraph(ev({ Object: [obj({ uuid: 'A' })] }));
    const r = g.opts.UI.neighborsPanel.graph.render;
    eq('never past 1×', r.maxZoom, 1);
    const styles = Object.keys(r.nodeStyleMap).map(k => r.nodeStyleMap[k]);
    ok('no card tiers, no focus card', styles.every(s => !s.tiers && !s.focusTier));
    ok('the canvas has both, so this is its own map', !!g.opts.render.nodeStyleMap.attribute.tiers);
    // An event's own provenance mark is a badge of its drawing; the pivot badges are not.
    const pivotBadges = g.opts.render.defaultNodeStyle.badges;
    ok('no pivot badges', !r.defaultNodeStyle.badges && styles.every(s => s.badges !== pivotBadges));
    ok('labels kept', typeof r.defaultNodeStyle.text === 'function');
    ok('servers and images still drawn', !!r.nodeStyleMap.server && !!r.nodeStyleMap.image);
});

test('17: an edge reads by the kind of link and what it asserts', async () => {
    const g = await buildGraph(ev({ Object: [obj({ uuid: 'A' })] }));
    eq('an analyst relationship', edgeProps(g, { kind: 'analyst-relationship', relationship_type: 'seen-with',
                                                  authors: 'alice', uuid: 'U1', orgc: 'o' }),
       ['Link: Analyst relationship', 'Relationship: seen-with', 'Authors: alice', 'UUID: U1']);
    eq('every derived kind has a name', ['correlation', 'feed-correlation', 'server-correlation']
       .map(k => edgeProps(g, { kind: k, label: '' })[0]),
       ['Link: Correlation', 'Link: Seen in a feed', 'Link: Seen on a server']);
});

/* ─────────────────── task 18: the node context menu ─────────────────── */

const menuItem = (g, text) => g.opts.UI.contextMenu.menuNode.menu.find(i => i.text === text);
const shows = (g, text, data) => menuItem(g, text).visible(data === null ? null : pnode(data));

test('18: MISP adds six entries to the node menu, after the library\'s own', async () => {
    const g = await buildGraph(ev({ Object: [obj({ uuid: 'A' })] }));
    eq('in this order', g.opts.UI.contextMenu.menuNode.menu.map(i => [i.text, i.iconClass]), [
        ['Save this element', 'fas fa-save'], ['Add to active graph', 'fas fa-circle-nodes'],
        ['Open its event', 'fas fa-external-link-alt'], ['Browse feed', 'fas fa-rss'],
        ['Preview in feed', 'fas fa-rss'], ['Copy value', 'fas fa-copy']]);
    ok('no topbar of ours, and the edge and note menus left alone',
       !g.opts.UI.contextMenu.menuNode.topbar
       && JSON.stringify(Object.keys(g.opts.UI.contextMenu)) === JSON.stringify(['menuNode', 'menuSelection', 'menuCanvas']));
});

test('18: another event\'s page opens in a new tab, for whatever belongs to one', async () => {
    const g = await buildGraph(ev({ Object: [obj({ uuid: 'A' })] }), { baseurl: '/misp' });
    eq('a related event, a correlated attribute or object — never this event or a source', [
        shows(g, 'Open its event', { type: 'event', event_id: '7' }),
        shows(g, 'Open its event', { type: 'attribute', event_id: '7', scope: 'foreign' }),
        shows(g, 'Open its event', { type: 'object', event_id: '7', scope: 'foreign' }),
        shows(g, 'Open its event', { type: 'event', event_id: '1' }),
        shows(g, 'Open its event', { type: 'attribute', event_id: '1', scope: 'self' }),
        shows(g, 'Open its event', { type: 'feed', source_id: '3' }),
        shows(g, 'Open its event', null),
    ], [true, true, true, false, false, false, false]);
    menuItem(g, 'Open its event').onclick({}, pnode({ type: 'attribute', event_id: '7' }));
    eq('event page, in a new tab, without an opener', g.win.opened, [['/misp/events/view/7', '_blank', 'noopener']]);
    ok('the page itself stays', g.win.location.href === '');
    eq('a multi-selection is not one element', shows(g, 'Open its event', undefined) === false
       && menuItem(g, 'Open its event').visible([pnode({ type: 'event', event_id: '7' }), pnode({ type: 'event', event_id: '8' })]),
       false);
});

test('18: a feed opens on its preview, which every role may read', async () => {
    const g = await buildGraph(ev({ Object: [obj({ uuid: 'A' })] }), { baseurl: '/misp' });
    eq('feeds only', [shows(g, 'Browse feed', { type: 'feed', source_id: '3' }),
                      shows(g, 'Browse feed', { type: 'server', source_id: '3' }),
                      shows(g, 'Browse feed', { type: 'attribute' })], [true, false, false]);
    menuItem(g, 'Browse feed').onclick({}, pnode({ type: 'feed', source_id: '3' }));
    eq('previewIndex', g.win.opened, [['/misp/feeds/previewIndex/3', '_blank', 'noopener']]);
});

test('18: an attribute\'s value copies whole, and says so', async () => {
    const copied = [];
    const g = await buildGraph(ev({ Object: [obj({ uuid: 'A' })] }), {
        navigator: { clipboard: { writeText: v => { copied.push(v); return Promise.resolve(); } } },
    });
    eq('attributes with a value only', [shows(g, 'Copy value', { type: 'attribute', value: 'x' }),
                                        shows(g, 'Copy value', { type: 'attribute', value: '' }),
                                        shows(g, 'Copy value', { type: 'object', name: 'x' })], [true, false, false]);
    const long = 'z'.repeat(120);
    menuItem(g, 'Copy value').onclick({}, pnode({ type: 'attribute', value: long }));
    await new Promise(r => setTimeout(r, 0));
    eq('the whole value', copied, [long]);
    eq('a notice, shortened', g.graph.notices.map(n => [n.level, n.title, n.msg.length]), [['success', 'Copied', 80]]);
});

test('18: a refused or missing clipboard says so', async () => {
    const refused = await buildGraph(ev({ Object: [obj({ uuid: 'A' })] }), {
        navigator: { clipboard: { writeText: () => Promise.reject(new Error('no')) } },
    });
    menuItem(refused, 'Copy value').onclick({}, pnode({ type: 'attribute', value: 'v' }));
    await new Promise(r => setTimeout(r, 0));
    eq('refused', refused.graph.notices.map(n => [n.level, n.title]), [['error', 'Copy failed']]);
    const none = await buildGraph(ev({ Object: [obj({ uuid: 'A' })] }));
    menuItem(none, 'Copy value').onclick({}, pnode({ type: 'attribute', value: 'v' }));
    eq('absent', none.graph.notices.map(n => [n.level, n.title]), [['error', 'Copy failed']]);
});

/* ─────────── task 12: taking fetched correlations back off ─────────── */

const canvasItem = g => g.opts.UI.contextMenu.menuCanvas.menu[0];

// The pivot fixture, then one correlation run's worth of results, vouched as
// Pivotick vouches an ingest: by the pivot's id.
async function withFetched() {
    const g = await withPivots();
    const gr = g.graph;
    gr.liveNode({ id: 'attr:x1', data: { type: 'attribute', uuid: 'x1' } }, ['correlations']);
    gr.liveNode({ id: 'attr:x2', data: { type: 'attribute', uuid: 'x2' } }, ['correlations']);
    gr.liveNode({ id: 'attr:e1', data: { type: 'attribute', uuid: 'e1' } }, ['correlations', 'event-elements']);
    ['c1>x1', 'c1>x2'].forEach(id => gr.liveEdges.push({
        id, getData: () => ({ kind: 'correlation' }), vouched: new Set(['correlations']),
        hasSource(s) { return this.vouched.has(s); },
        dropSource(s) { this.vouched.delete(s); return this.vouched.size === 0; },
    }));
    return g;
}

test('12: the canvas menu offers it only while the correlation pivot has brought something', async () => {
    const seeded = await withPivots();
    eq('one entry', [canvasItem(seeded).text, canvasItem(seeded).iconClass],
       ['Remove fetched correlations', 'fas fa-eraser']);
    eq('nothing fetched, nothing offered', canvasItem(seeded).visible(null), false);
    const fetched = await withFetched();
    eq('after a run, offered', canvasItem(fetched).visible(null), true);
});

test('12: it removes what the correlation pivot brought, and only that', async () => {
    const g = await withFetched();
    const seedNodes = g.graph.getMutableNodes().length - 3, seedEdges = g.graph.getMutableEdges().length - 2;
    canvasItem(g).onclick({}, null);
    eq('through the library', g.graph.removedBy, ['correlations']);
    ok('the fetched elements are gone', !g.graph.getMutableNode('attr:x1') && !g.graph.getMutableNode('attr:x2'));
    ok('one the element pivot also put there stays', !!g.graph.getMutableNode('attr:e1'));
    eq('the seed is untouched', [g.graph.getMutableNodes().length - 1, g.graph.getMutableEdges().length],
       [seedNodes, seedEdges]);
    eq('the notice counts it and says Undo puts it back', g.graph.notices.map(n => [n.level, n.title, n.msg]), [[
        'success', 'Correlations removed',
        '2 elements and 2 links off the canvas. Undo puts them back.']]);
    eq('and then there is nothing left to offer', canvasItem(g).visible(null), false);
});

/* ─────────────────── task 4: the empty canvas (D11) ─────────────────── */
// Pivotick shows and hides the card (UI.emptyState); MISP owns what it says.

const emptyCard = (g, initial) => g.opts.UI.emptyState.render({ initial: initial !== false, graph: g.graph });
const emptyText = (g, initial) => panelText(emptyCard(g, initial));
const emptyButton = (g, initial) => findByClass(emptyCard(g, initial), 'btn')[0];

test('an empty seed says why, and where the contents are', async () => {
    const g = await buildGraph(ev({ Attribute: [attr({ uuid: 'a1' }), attr({ uuid: 'a2' }), attr({ uuid: 'gone', deleted: true })] }));
    eq('nothing drawn', g.nodes, []);
    const t = emptyText(g);
    ok('it names what is missing', t.indexOf('Nothing in this event is linked yet') !== -1
       && t.indexOf('No object references, analyst relationships or feed and server hits to draw') !== -1, t);
    ok('and where correlations come from', t.indexOf('Correlations are fetched from the elements on the canvas') !== -1, t);
    ok('and counts what is there, deleted ones aside', t.indexOf('Its 2 attributes are listed under Event elements') !== -1, t);
    eq('one action', emptyButton(g).textContent, 'Browse event elements');
});

test('the action opens the element pivot', async () => {
    const g = await buildGraph(ev({ Attribute: [attr({ uuid: 'a1' })] }));
    const calls = [];
    g.graph.UIManager.openPivotMode = (nodes, id) => calls.push([nodes, id]);
    emptyButton(g)._listeners.click[0]();
    eq('with no origin', calls, [[[], 'event-elements']]);
    ok('singular', emptyText(g).indexOf('Its 1 attribute is listed') !== -1, emptyText(g));
});

test('an event whose objects blow the budget says so too', async () => {
    const g = await buildGraph(ev({ Attribute: [attr({ uuid: 'a1' })], Object: fillers(1501) }));
    eq('nothing drawn', g.nodes, []);
    ok('both counted', emptyText(g).indexOf('Its 1 attribute and 1501 objects are listed') !== -1, emptyText(g));
});

test('an event with no content at all offers nothing to browse', async () => {
    const g = await buildGraph(ev({}));
    ok('says it', emptyText(g).indexOf('This event has no attributes or objects to draw.') !== -1, emptyText(g));
    ok('no button', !emptyButton(g));
});

test('a canvas emptied by hand is not told that nothing is related', async () => {
    const g = await buildGraph(ev({ Object: [obj({ uuid: 'A' })] }));
    const t = emptyText(g, false);
    ok('it says the canvas is empty', t.indexOf('The canvas is empty') !== -1 && t.indexOf('related') === -1, t);
    ok('and still points at the elements', t.indexOf("The event's 1 object is listed under Event elements") !== -1, t);
    ok('with the same action', !!emptyButton(g, false));
});

test('the statement is text, never markup', async () => {
    const g = await buildGraph(ev({ Attribute: [attr({ uuid: 'a1' })] }));
    const card = emptyCard(g);
    ok('no innerHTML anywhere in the card', (function noHtml(el) {
        return !el._html && (el.children || []).every(noHtml);
    })(card));
});

/* ─────────── provenance, the facets, the header ─────────── */

const flat = nodes => (nodes || []).reduce((out, n) => out.concat([n], flat(n.children)), []);
const prov = n => [n.data.scope, n.data.event_id, n.data.event_uuid];

test('every seeded node says which event it belongs to', async () => {
    const g = await buildGraph(ev({
        Relationship: [toEvent(otherEvent({ uuid: 'R7', id: '7' }), { object_uuid: 'EV-SELF' })],
        Attribute: [attr({ uuid: 'e1', event_id: '1' })],
        Object: [obj({ uuid: 'A', event_id: '1', Attribute: [attr({ uuid: 'c1', event_id: '1' })],
                       ObjectReference: [ref({ referenced_uuid: 'e1', referenced_type: '0' })] })],
    }));
    const all = flat(g.nodes);
    eq('this event', prov(byId(all, 'event:EV-SELF')), ['self', '1', 'EV-SELF']);
    eq('another event', prov(byId(all, 'event:R7')), ['foreign', '7', 'R7']);
    eq('an object', prov(byId(all, 'obj:A')), ['self', '1', 'EV-SELF']);
    eq('its child attribute', prov(byId(all, 'attr:c1')), ['self', '1', 'EV-SELF']);
    eq('an event-level attribute', prov(byId(all, 'attr:e1')), ['self', '1', 'EV-SELF']);
    ok('every node carries a scope', all.every(n => n.data.scope === 'self' || n.data.scope === 'foreign'));
});

test('an element merged in from an extension event is foreign, known by id alone', async () => {
    const g = await buildGraph(ev({ Object: [
        obj({ uuid: 'A', event_id: '1', ObjectReference: [ref({ referenced_uuid: 'X' })] }),
        obj({ uuid: 'X', event_id: '42', Attribute: [attr({ uuid: 'x1', event_id: '42' })] }),
    ] }));
    const all = flat(g.nodes);
    eq('the extension object', prov(byId(all, 'obj:X')), ['foreign', '42', undefined]);
    eq('and its attribute', prov(byId(all, 'attr:x1')), ['foreign', '42', undefined]);
    eq('this event\'s own object stays self', prov(byId(all, 'obj:A')), ['self', '1', 'EV-SELF']);
});

test('a record without an event_id belongs to the event it came in', async () => {
    const g = await buildGraph(ev({ Object: [fedObj({ uuid: 'A' })] }));
    eq('self', prov(byId(g.nodes, 'obj:A')), ['self', '1', 'EV-SELF']);
});

test('pivot results carry provenance: correlated elements foreign, this event\'s side self', async () => {
    const g = await withPivots();
    const r = await pivot(g, 'correlations').fetch([pnode({ type: 'attribute', uuid: 'e1' })], {}, {});
    const all = flat(r.nodes);
    eq('a correlated attribute', prov(all.find(n => n.id === 'attr:x1')), ['foreign', '7', 'R7']);
    eq('its container', prov(all.find(n => n.id === 'event:R7')), ['foreign', '7', 'R7']);
    eq('this event\'s side brought along', prov(all.find(n => n.id === 'attr:e1')), ['self', '1', 'EV-SELF']);
});

test('elements put on the canvas from the element pivot are this event\'s', async () => {
    const g = await buildGraph(ev({
        Attribute: [attr({ uuid: 'e1' })],
        Object: [obj({ uuid: 'A', Attribute: [attr({ uuid: 'c1' })] })],
    }), { routes: [[/correlationCounts/, { attributes: {}, objects: {}, events: {} }]] });
    // Push A past the canvas so the pivot offers it too.
    g.graph.getMutableNode = () => undefined;
    const r = pivot(g, 'event-elements').fetch([], {}, {});
    eq('each, children included', flat(r.nodes).map(n => n.id + '=' + n.data.scope).sort(),
       ['attr:c1=self', 'attr:e1=self', 'obj:A=self']);
});

test('the filter panel declares its facets, provenance first', async () => {
    const g = await buildGraph(ev({}));
    const facets = g.opts.UI.filter.facets;
    eq('the facet set', facets.map(f => [f.key, f.type]),
       [['scope', 'multiselect'], ['type', 'multiselect'], ['category', 'multiselect'],
        ['attr-type', 'multiselect'], ['name', 'multiselect'], ['to_ids', 'boolean'],
        ['warninglisted', 'boolean'], ['value', 'regex']]);
    eq('provenance names both sides in words', facets[0].options,
       [{ label: 'This event', value: 'self' }, { label: 'Other events', value: 'foreign' }]);
    eq('provenance is labelled as such', facets[0].label, 'Provenance');
    eq('the edge facets are unchanged', g.opts.UI.filter.edgeFacets.map(f => f.key),
       ['kind', 'relationship_type']);
});

test('the legend keys elements and relationships, the latter on the layer facet', async () => {
    const g = await buildGraph(ev({}));
    const sections = g.opts.UI.legend.sections;
    eq('three sections', sections.map(s => s.title), ['Element', 'Provenance', 'Relationship']);
    ok('Element is the nodeTypeAccessor dimension, its hues declared (drawn nodes have none)',
       sections[0].key === undefined && typeof sections[0].entries === 'function' && sections[0].scope === undefined);
    ok('Provenance declares its entries, and so its own swatches',
       sections[1].key === undefined && typeof sections[1].entries === 'function' && sections[1].scope === undefined);
    eq('Relationship keys on edges by kind', [sections[2].scope, sections[2].key], ['edge', 'kind']);
    ok('the same key the layer facet declares',
       g.opts.UI.filter.edgeFacets.some(f => f.key === sections[2].key));
});

test('the legend\'s This event entry holds what the event is made of, the tags it carries included', async () => {
    const payload = taggedEvent();
    payload.Event.Tag = [{ name: 'tlp:clear', colour: '#fff' }];
    const g = await buildGraph(payload);
    const node = (id, data) => Object.assign(pnode(data), { id });
    const nodes = [
        node('event:U1', { type: 'event', scope: 'self', event_id: '1' }),
        node('attr:e1', { type: 'attribute', uuid: 'e1', scope: 'self' }),
        node('obj:A', { type: 'object', uuid: 'A', scope: 'self' }),
        node('attr:c1', { type: 'attribute', uuid: 'c1', scope: 'self' }),
        node('tag:tlp:clear', { type: 'tag', name: 'tlp:clear' }),
        node('tag:' + TAG_TLP.name, { type: 'tag', name: TAG_TLP.name }),
        node('cluster:' + TAG_APT.name, { type: 'cluster', tag_name: TAG_APT.name }),
        node('event:R7', { type: 'event', scope: 'foreign', event_id: '7' }),
        node('attr:x1', { type: 'attribute', uuid: 'x1', scope: 'foreign', event_id: '7' }),
        node('tag:elsewhere', { type: 'tag', name: 'elsewhere' }),
        node('feed:1', { type: 'feed', source_id: '1' }),
    ];
    const entries = g.opts.UI.legend.sections[1].entries({ getMutableNodes: () => nodes });
    eq('both entries, labelled', entries.map(e => [e.id, e.label]), [['self', 'This event'], ['elsewhere', 'Elsewhere']]);
    eq('this event: its card, its elements, and the tags and clusters it carries on itself or an attribute',
       nodes.filter(entries[0].predicate).map(n => n.id),
       ['event:U1', 'attr:e1', 'obj:A', 'attr:c1', 'tag:tlp:clear', 'tag:' + TAG_TLP.name, 'cluster:' + TAG_APT.name]);
    eq('elsewhere: the rest', nodes.filter(entries[1].predicate).map(n => n.id),
       ['event:R7', 'attr:x1', 'tag:elsewhere', 'feed:1']);
    eq('an entry nothing matches is not listed',
       g.opts.UI.legend.sections[1].entries({ getMutableNodes: () => nodes.slice(0, 2) }).map(e => e.id), ['self']);
});

test('a facet\'s options are what the live graph holds, children included', async () => {
    const g = await buildGraph(ev({}));
    const cat = g.opts.UI.filter.facets.find(f => f.key === 'category');
    const graph = { getMutableNodes: () => [
        pnode({ category: 'Payload delivery' }), pnode({ category: 'Network activity' }),
        pnode({ category: 'Network activity' }), pnode({ type: 'object' }), pnode({ category: '' }),
    ] };
    eq('distinct, sorted, blanks dropped', cat.options(graph),
       [{ label: 'Network activity', value: 'Network activity' },
        { label: 'Payload delivery', value: 'Payload delivery' }]);
});

test('the canvas takes the window height below its top, down to its card\'s edge', async () => {
    const layout = { innerHeight: 1000, graphTop: 246, cardBorder: 1, cardMargin: 16 };
    const g = await buildGraph(ev({ Attribute: [attr({ uuid: 'a1', id: '1' })] }), { layout });
    eq('fitted when shown', g.graphEl.style.height, (1000 - 246 - 17) + 'px');
    g.win.innerHeight = 1400;
    g.resizers.forEach(f => f());
    eq('refitted on resize', g.graphEl.style.height, (1400 - 246 - 17) + 'px');
    g.win.innerHeight = 600;
    g.resizers.forEach(f => f());
    eq('never shorter than 480px', g.graphEl.style.height, '480px');
});

/* ────────────── task 5b: feed and server correlations ────────────── */

// A feed as Feed::attachFeedCorrelations() attaches it: the full record on the
// event's source map, and a copy on every attribute it was seen in. The map is
// keyed by feed id in PHP but reaches the browser as a list.
const FEED1 = { id: '1', name: 'CIRCL OSINT Feed', url: 'https://x/osint', provider: 'CIRCL',
                source_format: 'misp', lookup_visible: true, event_uuids: ['u1', 'u2'] };
const FEED9 = { id: '9', name: 'URLHaus', url: 'https://x/urlhaus', provider: 'abuse.ch',
                source_format: 'csv', lookup_visible: true };

function feedEvent(extra) {
    return ev(Object.assign({
        Feed: [FEED1, FEED9],   // FEED9 at index 1: position is not id
        // The first hit met is a trimmed copy, so the node must read the map.
        Attribute: [attr({ uuid: 'e1', value: 'linked', Feed: [{ id: '1', name: 'CIRCL OSINT Feed' }] }),
                    attr({ uuid: 'e2', value: 'loose', Feed: [FEED1, FEED9] })],
        Object: [
            obj({ uuid: 'A', ObjectReference: [ref({ referenced_uuid: 'e1', referenced_type: '0' })],
                  Attribute: [attr({ uuid: 'c1', Feed: [{ id: '1', name: 'CIRCL OSINT Feed' }, FEED9] }),
                              attr({ uuid: 'c2' })] }),
        ],
    }, extra));
}

test('5b: one node per feed, joined to every drawn attribute seen in it', async () => {
    const g = await buildGraph(feedEvent());
    eq('the two feeds join the canvas', ids(g.nodes), ['attr:e1', 'attr:e2', 'feed:1', 'feed:9', 'obj:A']);
    eq('edges into the referenced attribute, the hit one and the object\'s child — into, which pivotick draws for a child',
       g.edges.filter(e => e.data.kind === 'feed-correlation').map(e => e.from + '->' + e.to).sort(),
       ['feed:1->attr:c1', 'feed:1->attr:e1', 'feed:1->attr:e2', 'feed:9->attr:c1', 'feed:9->attr:e2']);
    eq('a correlation asserts nothing', g.edges.filter(e => e.data.kind === 'feed-correlation')
       .map(e => [e.data.label, 'relationship_type' in e.data]), Array(5).fill(['', false]));
    const f = byId(g.nodes, 'feed:1').data;
    eq('the node reads the event\'s full record, not the attribute\'s copy', f, {
        type: 'feed', label: 'CIRCL OSINT Feed', description: 'CIRCL · misp feed', source_id: '1',
        provider: 'CIRCL', url: 'https://x/osint', source_format: 'misp', feed_events: 2, scope: 'foreign' });
    ok('no name key — that is the Object facet', !('name' in f));
    ok('no feed_events without a MISP-format feed', byId(g.nodes, 'feed:9').data.feed_events == null);
});

test('5b: the source map is read by id, as a list or keyed', async () => {
    const list = await buildGraph(feedEvent());
    const keyed = await buildGraph(feedEvent({ Feed: { 1: FEED1, 9: FEED9 } }));
    [['list', list], ['keyed', keyed]].forEach(([shape, g]) => eq(shape + ': each node under its own name',
        ['feed:1', 'feed:9'].map(i => byId(g.nodes, i).data.label), ['CIRCL OSINT Feed', 'URLHaus']));
});

test('5b: a feed hit puts an event-level attribute on the canvas, through L2', async () => {
    const g = await buildGraph(feedEvent());
    ok('the attribute nothing references is drawn for its hits', !!byId(g.nodes, 'attr:e2'));
    eq('so the element pivot no longer offers it', trayLabels(g), []);
});

test('5b: a feed seen only by elements not drawn draws no node', async () => {
    // Over budget, L2 is skipped whole, the hit attribute with it.
    const g = await buildGraph(ev({
        Feed: [FEED9],
        Attribute: [attr({ uuid: 'e2', Feed: [FEED9] })],
        Object: [obj({ uuid: 'A', ObjectReference: [ref({ referenced_uuid: 'B' })] }), obj({ uuid: 'B' })]
            .concat(fillers(750)),
    }));
    eq('no feed node', ids(g.nodes), ['obj:A', 'obj:B']);
});

test('5b: deleted attributes carry no hits', async () => {
    const g = await buildGraph(ev({
        Feed: [FEED1],
        Object: [obj({ uuid: 'A', Attribute: [attr({ uuid: 'c1', deleted: true, Feed: [FEED1] })],
                       ObjectReference: [ref({ referenced_uuid: 'B' })] }), obj({ uuid: 'B' })],
    }));
    eq('no feed node', ids(g.nodes), ['obj:A', 'obj:B']);
});

test('5b: past 10,000 hits, a badge on each attribute', async () => {
    const g = await buildGraph(ev({
        FeedCount: 16246,
        Attribute: [attr({ uuid: 'e1', FeedHit: true })],
        Object: [obj({ uuid: 'A', ObjectReference: [ref({ referenced_uuid: 'e1', referenced_type: '0' })],
                       Attribute: [attr({ uuid: 'c1', FeedHit: true }), attr({ uuid: 'c2' })] })],
    }));
    ok('no source node — there is nothing to point at', !g.nodes.some(n => n.data.type === 'feed'));
    ok('no feed edge', !g.edges.some(e => e.data.kind === 'feed-correlation'));
    const c1 = byId(g.nodes, 'obj:A').children.find(c => c.id === 'attr:c1').data;
    const c2 = byId(g.nodes, 'obj:A').children.find(c => c.id === 'attr:c2').data;
    eq('the flag rides on the node', [byId(g.nodes, 'attr:e1').data.feed_hit, c1.feed_hit, c2.feed_hit == null],
       [true, true, true]);
    const b = badgesOf(g, c1);
    eq('one badge, bottom-left, off the analyst corner', b.map(x => [x.position, x.iconClass, x.color]),
       [['sw', 'fas fa-rss', '#5bc0de']]);
    ok('it says why no feed is named', /too many/.test(b[0].title), b[0].title);
    eq('no badge without the flag', badgesOf(g, c2), []);
    eq('both badges when there is analyst data too',
       badgesOf(g, { feed_hit: true, analyst_count: 2, analyst_mood: 'none' }).map(x => x.position), ['nw', 'sw']);
});

test('5b: a server is a source like a feed, on its own layer, even with only id and name', async () => {
    const SRV = { id: '3', name: 'Partner MISP' };
    const g = await buildGraph(ev({
        Server: [SRV],
        Attribute: [attr({ uuid: 'e1', Server: [SRV] })],
        Object: [obj({ uuid: 'A', ObjectReference: [ref({ referenced_uuid: 'e1', referenced_type: '0' })] })],
    }));
    eq('its node', byId(g.nodes, 'server:3').data,
       { type: 'server', label: 'Partner MISP', description: 'Server', source_id: '3', scope: 'foreign' });
    eq('its edge', g.edges.filter(e => e.from === 'server:3').map(e => [e.to, e.data.kind]),
       [['attr:e1', 'server-correlation']]);
});

test('5b: a feed and a server sharing an id are two nodes', async () => {
    const g = await buildGraph(ev({
        Feed: [FEED1], Server: [{ id: '1', name: 'S' }],
        Attribute: [attr({ uuid: 'e1', Feed: [FEED1], Server: [{ id: '1', name: 'S' }] })],
        Object: [obj({ uuid: 'A', ObjectReference: [ref({ referenced_uuid: 'e1', referenced_type: '0' })] })],
    }));
    eq('both', ids(g.nodes).filter(i => /^(feed|server):/.test(i)), ['feed:1', 'server:1']);
});

test('5b: sources are styled, iconed and keyed like the other elements', async () => {
    const g = await buildGraph(feedEvent());
    const r = g.opts.render;
    const feed = r.nodeStyleMap.feed;
    eq('a feed is drawn by misp-pivot-nodes: composed at rest, the authority card as its chip',
       [feed.shape, typeof feed.svgIcon, feed.tiers[0].width, feed.tiers[0].height,
        typeof feed.tiers[0].style.html],
       ['none', 'function', 140, 44, 'function']);
    const server = r.nodeStyleMap.server;
    eq('so is a server',
       [server.shape, typeof server.svgIcon, server.tiers[0].width, server.tiers[0].height,
        typeof server.tiers[0].style.html],
       ['none', 'function', 140, 44, 'function']);
    const srv = pnode({ type: 'server', label: 'Partner MISP', provider: 'CIRCL',
                        url: 'https://misp.example.org', scope: 'foreign' });
    const rest = server.svgIcon(srv);
    ok('at rest it is a hexagon in the server hue, in a dashed ring',
       /fill="#D0539F"/.test(rest) && /stroke-dasharray="3 3"/.test(rest));
    const chip = server.tiers[0].style.html(srv).innerHTML;
    ok('its chip names the server and its provider, in the server hue',
       /Partner MISP/.test(chip) && /CIRCL/.test(chip) && /#D0539F/.test(chip));
    eq('its edges take the same hue', r.edgeStyleMap['server-correlation'].strokeColor, '#D0539F');
    eq('a feed\'s edges take the feed\'s hue',
       [r.edgeStyleMap['feed-correlation'].strokeColor, r.edgeStyleMap['feed-event'].strokeColor],
       ['#D4A017', '#D4A017']);
    eq('the accessor reads the type', r.nodeTypeAccessor(pnode({ type: 'feed' })), 'feed');
    const styled = Object.keys(r.edgeStyleMap);
    g.edges.forEach(e => ok('kind ' + e.data.kind + ' is styled',
                            styled.indexOf(r.edgeTypeAccessor({ getData: () => e.data })) !== -1));
    eq('Provenance puts a source with the other events\' elements',
       g.nodes.filter(n => n.data.type === 'feed').map(n => n.data.scope), ['foreign', 'foreign']);
});

test('5b: no write reaches a source node, nor a pivot one that names no events', async () => {
    const g = await withEditor();
    const feed = pnode({ type: 'feed', source_id: '1', scope: 'foreign', label: 'F' });
    const offered = g.opts.pivots.filter(p => p.appliesTo && p.appliesTo([feed]).length);
    eq('no pivot applies', offered.map(p => p.id), []);
    ok('nothing draws from a feed', !g.opts.callbacks.isValidConnection(feed, own.objA));
    ok('nor to one', !g.opts.callbacks.isValidConnection(own.objA, feed));
    const fe = pedge('fc:1', own.attrE1, feed, { kind: 'feed-correlation', label: '' });
    const d = await g.opts.callbacks.onBeforeDelete({ nodes: [], edges: [fe], confirm: () => Promise.resolve(true) });
    eq('its edge is spared, not deleted', d, { accept: true, edges: [] });
});

/* ─────────────── feed events: the events of a MISP feed ─────────────── */

// Each hit names the feed events its value is in; the map holds them all.
function feedEventsEvent() {
    return ev({
        Feed: [FEED1, FEED9],
        Attribute: [attr({ uuid: 'e1', value: 'linked', Feed: [{ id: '1', name: 'CIRCL OSINT Feed', event_uuids: ['u1'] }] }),
                    attr({ uuid: 'e2', value: 'loose', Feed: [{ id: '1', name: 'CIRCL OSINT Feed', event_uuids: ['u2'] }] })],
        Object: [
            obj({ uuid: 'A', ObjectReference: [ref({ referenced_uuid: 'e1', referenced_type: '0' })],
                  Attribute: [attr({ uuid: 'c1', Feed: [{ id: '1', name: 'CIRCL OSINT Feed', event_uuids: ['u1', 'u2'] }, FEED9] })] }),
        ],
    });
}

const CARD_U1 = {
    uuid: 'u1', info: 'ThreatFox IOCs for 2026-09-03', date: '2026-09-03',
    Orgc: { name: 'abuse.ch', uuid: 'O2' },
    Tag: [{ name: 'tlp:white', colour: '#ffffff' }],
    Galaxy: [{ type: 'malpedia', GalaxyCluster: [{ value: 'Cobalt Strike' }] }],
};

function withFeedEvents(onPost) {
    return buildGraph(feedEventsEvent(), {
        routes: [[/feeds\/manifestEvents\.json$/, init => {
            if (onPost) onPost(JSON.parse(init.body));
            return { events: { '1': { u1: CARD_U1 } } };
        }]],
    }).then(g => new Promise(res => setTimeout(() => res(g), 0)));
}

test('feed events: a MISP feed wears the number of its events this event\'s values are in', async () => {
    const g = await withFeedEvents();
    eq('the MISP feed', potentials(g, 'feed:1'), [['feed-events', 2]]);
    eq('a CSV feed names no events', potentials(g, 'feed:9'), []);
    const p = pivot(g, 'feed-events');
    const nodes = [pnode(byId(g.nodes, 'feed:1').data), pnode(byId(g.nodes, 'feed:9').data),
                   pnode({ type: 'attribute', uuid: 'e1' })];
    eq('it applies to the MISP feed alone', p.appliesTo(nodes).map(n => n.getData().source_id), ['1']);
    eq('summarize is its events', p.summarize(p.appliesTo(nodes)), { total: 2 });
    eq('capped at the canvas budget, never saved', [p.maxCandidates, p.save], [1500, undefined]);
});

test('feed events: each lands as a cached event card, joined to its feed and its attributes', async () => {
    let body = null;
    const g = await withFeedEvents(b => { body = b; });
    const r = await pivot(g, 'feed-events').fetch([pnode(byId(g.nodes, 'feed:1').data)], {}, {});
    eq('it asks for the feed\'s events by uuid', body, { feeds: { '1': ['u1', 'u2'] } });
    eq('two feed events; every attribute they were seen with is already drawn',
       r.nodes.map(n => n.id), ['feed-event:1:u1', 'feed-event:1:u2']);
    const d = r.nodes[0].data;
    eq('the card is drawn from the manifest entry',
       [d.type, d.label, d.date, d.orgc, d.tags, d.context],
       ['event', 'ThreatFox IOCs for 2026-09-03', '2026-09-03', { name: 'abuse.ch', uuid: 'O2' },
        [{ name: 'tlp:white', colour: '#ffffff' }], [{ galaxy_type: 'malpedia', value: 'Cobalt Strike' }]]);
    eq('as a cached hit of that feed', [d._provenance, d.source.kind, d.source.name, d.feed_id, d.scope],
       ['feed', 'feed', 'CIRCL OSINT Feed', '1', 'foreign']);
    eq('without a manifest entry it is its uuid', [r.nodes[1].data.label, r.nodes[1].data.orgc], ['u2', undefined]);
    eq('the feed holds its events; each event holds the values it was seen with',
       r.edges.map(e => [e.from, e.to, e.data.kind]),
       [['feed:1', 'feed-event:1:u1', 'feed-event'], ['feed:1', 'feed-event:1:u2', 'feed-event'],
        ['feed-event:1:u1', 'attr:e1', 'feed-correlation'], ['feed-event:1:u2', 'attr:e2', 'feed-correlation'],
        ['feed-event:1:u1', 'attr:c1', 'feed-correlation'], ['feed-event:1:u2', 'attr:c1', 'feed-correlation']]);
});

test('feed events: a feed listed once per lookup batch is one feed with all their events', async () => {
    const payload = feedEventsEvent();
    payload.Event.Feed = [Object.assign({}, FEED1, { event_uuids: ['u1'] }), FEED9,
                          Object.assign({}, FEED1, { event_uuids: ['u2'] })];
    const g = await buildGraph(payload);
    eq('its node counts both batches', byId(g.nodes, 'feed:1').data.feed_events, 2);
    eq('and so does its badge', potentials(g, 'feed:1'), [['feed-events', 2]]);
});

test('feed events: one previews in its feed, in a new tab', async () => {
    const g = await buildGraph(ev({ Object: [obj({ uuid: 'A' })] }), { baseurl: '/misp' });
    eq('feed events only', [shows(g, 'Preview in feed', { type: 'event', feed_id: '1', uuid: 'u1' }),
                            shows(g, 'Preview in feed', { type: 'event', event_id: '7', uuid: 'R7' }),
                            shows(g, 'Preview in feed', { type: 'feed', source_id: '1' })], [true, false, false]);
    menuItem(g, 'Preview in feed').onclick({}, pnode({ type: 'event', feed_id: '1', uuid: 'u1' }));
    eq('previewEvent', g.win.opened, [['/misp/feeds/previewEvent/1/u1', '_blank', 'noopener']]);
});

/* ─────────────────────── tags and galaxy clusters ─────────────────────── */

const TAG_TLP = { id: '1', name: 'tlp:amber', colour: '#ffc000', is_galaxy: false, local: false };
const TAG_LUMMA = { id: '2', name: 'LummaC2', colour: '#5000fa', is_galaxy: false, local: true };
const TAG_APT = { id: '3', name: 'misp-galaxy:threat-actor="APT28"', colour: '#0088cc', is_galaxy: true };
const GAL_APT = { type: 'threat-actor', name: 'Threat Actor', GalaxyCluster: [
    { uuid: 'CL-APT28', value: 'APT28', tag_name: 'misp-galaxy:threat-actor="APT28"' }] };

function taggedEvent() {
    return ev({
        Attribute: [
            attr({ uuid: 'e1', value: 'lumma.example', Tag: [TAG_LUMMA, TAG_APT], Galaxy: [GAL_APT],
                   Relationship: [arel({ object_uuid: 'e1', related_object_uuid: 'A' })] }),
            attr({ uuid: 'e2', value: 'plain' }),
        ],
        Object: [obj({ uuid: 'A', Attribute: [
            attr({ uuid: 'c1', value: '1.2.3.4', Tag: [TAG_TLP, TAG_APT], Galaxy: [GAL_APT] }),
            attr({ uuid: 'c2', value: 'untagged' }),
        ] })],
    });
}

test('tags: an attribute carries its tags and its clusters, a cluster keyed by its tag', async () => {
    const g = await buildGraph(taggedEvent());
    const d = byId(g.nodes, 'attr:e1').data;
    eq('the plain tag, marked local', d.tags.map(t => [t.name, t.colour, !!t.local]), [['LummaC2', '#5000fa', true]]);
    eq('the galaxy tag is a cluster, not a tag',
       d.clusters.map(c => [c.tag_name, c.galaxy_type, c.galaxy_name, c.value, c.uuid]),
       [['misp-galaxy:threat-actor="APT28"', 'threat-actor', 'Threat Actor', 'APT28', 'CL-APT28']]);
    ok('an untagged attribute carries neither',
       ['tags', 'clusters'].every(k => byId(g.nodes, 'obj:A').children[1].data[k] === undefined));
});

test('warninglists: an attribute carries the lists its value is on, once each', async () => {
    const hit = (id, name, category) => ({ value: '8.8.8.8', match: '8.8.8.8/32', warninglist_id: id,
                                           warninglist_name: name, warninglist_category: category });
    const g = await buildGraph(ev({ Attribute: [
        attr({ uuid: 'e1', value: '8.8.8.8', warnings: [hit(60, 'Public DNS resolvers', 'false_positive'),
            hit(60, 'Public DNS resolvers', 'false_positive'), hit(7, 'Known hosting', 'known')],
            Relationship: [arel({ object_uuid: 'e1', related_object_uuid: 'EV-SELF', related_object_type: 'Event' })] }),
        attr({ uuid: 'e2', value: 'plain',
            Relationship: [arel({ object_uuid: 'e2', related_object_uuid: 'EV-SELF', related_object_type: 'Event' })] }),
    ] }));
    const d = byId(g.nodes, 'attr:e1').data;
    eq('deduplicated by list, in MISP\'s own field names, which the node drawing reads',
       d.warnings.map(w => [w.warninglist_id, w.warninglist_name, w.warninglist_category]),
       [['60', 'Public DNS resolvers', 'false_positive'], ['7', 'Known hosting', 'known']]);
    eq('flagged for the filter', [d.warninglisted, byId(g.nodes, 'attr:e2').data.warninglisted], [true, false]);
    eq('none, none', byId(g.nodes, 'attr:e2').data.warnings, undefined);
    ok('the multi-selection table counts each list',
       props(g, d).indexOf('Warninglist: Public DNS resolvers') !== -1
       && props(g, d).indexOf('Warninglist: Known hosting') !== -1, props(g, d));
});

test('tags: a cluster named only by its tag still reads its galaxy and value', async () => {
    const g = await buildGraph(ev({ Attribute: [attr({ uuid: 'e1', Tag: [TAG_APT],
        Relationship: [arel({ object_uuid: 'e1', related_object_uuid: 'EV-SELF', related_object_type: 'Event' })] })] }));
    eq('parsed off misp-galaxy:TYPE="VALUE"',
       byId(g.nodes, 'attr:e1').data.clusters.map(c => [c.galaxy_type, c.value, c.galaxy_name]),
       [['threat-actor', 'APT28', undefined]]);
});

test('tags: a hidden tag is left out', async () => {
    const g = await buildGraph(ev({ Attribute: [attr({ uuid: 'e1',
        Tag: [Object.assign({}, TAG_TLP, { hide_tag: true })],
        Relationship: [arel({ object_uuid: 'e1', related_object_uuid: 'EV-SELF', related_object_type: 'Event' })] })] }));
    eq('nothing', byId(g.nodes, 'attr:e1').data.tags, undefined);
});

test('tags: the table has a row per label, and a tagged attribute wears a tag badge', async () => {
    const g = await buildGraph(taggedEvent());
    const rows = props(g, byId(g.nodes, 'attr:e1').data);
    ok('a tag', rows.indexOf('Tag: LummaC2') !== -1, rows);
    ok('a cluster, by its galaxy', rows.filter(r => /^Galaxy cluster: .*APT28$/.test(r)).length === 1, rows);
    const b = badgesOf(g, byId(g.nodes, 'attr:e1').data);
    eq('one badge, bottom-right, in the first tag\'s colour', b.map(x => [x.position, x.iconClass, x.color]),
       [['se', 'fas fa-tag', '#5000fa']]);
    eq('its title names them all', b[0].title, 'LummaC2\nThreat Actor: APT28');
    eq('no badge without tags', badgesOf(g, { type: 'attribute', value: 'x' }), []);
    eq('an event card draws its own', badgesOf(g, { type: 'event', tags: [{ name: 'x' }] }), []);
    eq('a tag node counts as its tag', props(g, { type: 'tag', name: 'tlp:amber' }), ['Element: tag', 'Tag: tlp:amber']);
    eq('a cluster node as its cluster',
       props(g, { type: 'cluster', value: 'APT28', galaxy_name: 'Threat Actor', tag_name: 't', uuid: 'U' }),
       ['Element: cluster', 'Galaxy cluster: Threat Actor: APT28']);
});

test('tags: a tag draws as the taxonomy entity and the legend calls it a tag', async () => {
    const g = await buildGraph(taggedEvent());
    eq('style key', g.opts.render.nodeTypeAccessor(pnode({ type: 'tag' })), 'taxonomy');
    ok('drawn by misp-pivot-nodes', !!g.opts.render.nodeStyleMap.taxonomy && !!g.opts.render.nodeStyleMap.cluster);
    const legend = g.opts.UI.legend.sections[0].entries({ getMutableNodes: () => [
        pnode({ type: 'tag' }), pnode({ type: 'cluster' }), pnode({ type: 'attribute' })] });
    eq('labels', legend.map(e => [e.id, e.label]),
       [['taxonomy', 'tag'], ['cluster', 'galaxy cluster'], ['attribute', 'attribute']]);
});

test('tags: the pivot applies to what carries a tag, an object through its attributes', async () => {
    const g = await buildGraph(taggedEvent());
    const p = pivot(g, 'tags');
    const nodes = ['attr:e1', 'obj:A', 'attr:c2'].map(id => g.graph.getMutableNode(id));
    eq('the plain attribute is left out', p.appliesTo(nodes).map(n => n.id), ['attr:e1', 'obj:A']);
    eq('distinct tags and clusters: LummaC2, APT28, tlp:amber', p.summarize(p.appliesTo(nodes)), { total: 3 });
    eq('capped, never saved', [p.maxCandidates, p.save], [1500, undefined]);
    eq('no carrier wears a rim potential for it',
       [potentials(g, 'attr:e1'), potentials(g, 'obj:A'), potentials(g, 'attr:c2')],
       [[], [], []]);
});

test('tags: one node per tag or cluster, joined to every carrier on the canvas', async () => {
    const g = await buildGraph(taggedEvent());
    const r = pivot(g, 'tags').fetch([g.graph.getMutableNode('attr:e1')], {}, {});
    eq('the selection\'s tag and cluster', r.nodes.map(n => [n.id, n.data.type, n.data.label]),
       [['tag:LummaC2', 'tag', 'LummaC2'], ['cluster:misp-galaxy:threat-actor="APT28"', 'cluster', 'APT28']]);
    eq('the cluster node is what its drawing reads',
       [r.nodes[1].data.galaxy_type, r.nodes[1].data.galaxy_name, r.nodes[1].data.value],
       ['threat-actor', 'Threat Actor', 'APT28']);
    eq('the object\'s attribute already on the canvas shares the cluster, so it is joined too',
       r.edges.map(e => [e.from, e.to, e.data.kind]),
       [['attr:e1', 'tag:LummaC2', 'tag'], ['attr:e1', 'cluster:misp-galaxy:threat-actor="APT28"', 'tag'],
        ['attr:c1', 'cluster:misp-galaxy:threat-actor="APT28"', 'tag']]);
    ok('tlp:amber was not asked for', !r.nodes.some(n => n.id === 'tag:tlp:amber'));
});

test('tags: a tag\'s relationship type labels its edge', async () => {
    const g = await buildGraph(ev({ Attribute: [attr({ uuid: 'e1',
        Tag: [Object.assign({}, TAG_TLP, { relationship_type: 'classified-as' })],
        Relationship: [arel({ object_uuid: 'e1', related_object_uuid: 'EV-SELF', related_object_type: 'Event' })] })] }));
    const r = pivot(g, 'tags').fetch([g.graph.getMutableNode('attr:e1')], {}, {});
    eq('label', r.edges.map(e => e.data.label), ['classified-as']);
});

test('tags: another event\'s card is a carrier, its galaxy tags read as clusters', async () => {
    const g = await buildGraph(ev({ Object: [obj({ uuid: 'A' })] }));
    const card = pnode({ type: 'event', tags: [{ name: 'tlp:white' }],
                         clusters: [{ tag_name: 'misp-galaxy:threat-actor="APT28"', value: 'APT28' }] });
    card.id = 'event:R1';
    const r = pivot(g, 'tags').fetch([card], {}, {});
    eq('both', r.nodes.map(n => n.id), ['tag:tlp:white', 'cluster:misp-galaxy:threat-actor="APT28"']);
    eq('joined to the card', r.edges.map(e => e.from), ['event:R1', 'event:R1']);
});

test('tags: a tag edge is not deleted in MISP', async () => {
    const g = await buildGraph(taggedEvent());
    const del = g.opts.callbacks.onBeforeDelete;
    const res = await del({ nodes: [], edges: [{ getData: () => ({ kind: 'tag' }) }], confirm: () => true });
    eq('it stays, hide it instead', res, { accept: true, edges: [] });
});

/* ─────────────── from a tag or cluster to other events ─────────── */

const tagNode = (id, data) => Object.assign(pnode(data), { id });
const TLP_NODE = () => tagNode('tag:tlp:amber', { type: 'tag', name: 'tlp:amber' });
const APT_NODE = () => tagNode('cluster:' + TAG_APT.name,
    { type: 'cluster', tag_name: TAG_APT.name, value: 'APT28', uuid: 'CL-APT28' });

// As /events/taggedEvents shapes it: newest first, each card saying how it
// carries each asked-for tag.
const TAGGED = {
    total: 4812,
    events: [
        { id: '812', uuid: 'R812', info: 'Tagged on the event', date: '2026-01-02',
          Orgc: { name: 'CIRCL', uuid: 'O1' },
          Tag: [{ name: 'tlp:amber', colour: '#ffc000', is_galaxy: false }],
          Galaxy: [{ type: 'threat-actor', GalaxyCluster: [{ value: 'APT28', tag_name: TAG_APT.name }] }],
          matched: { 'tlp:amber': 'event', [TAG_APT.name]: 'event' } },
        { id: '813', uuid: 'R813', info: 'Tagged on an attribute', Tag: [], Galaxy: [],
          matched: { 'tlp:amber': 'attribute' } },
    ],
};

function withTagged(route) {
    let bodies = [];
    return buildGraph(taggedEvent(), { routes: [[/events\/taggedEvents\/1\.json$/, init => {
        bodies.push(JSON.parse(init.body));
        return route ? route(init) : TAGGED;
    }]] }).then(g => Object.assign(g, { bodies }));
}

test('tagged events: offered on tag and cluster nodes only', async () => {
    const g = await withTagged();
    const p = pivot(g, 'tagged-events');
    const nodes = [TLP_NODE(), APT_NODE(), tagNode('cluster:x', { type: 'cluster' }),
                   g.graph.getMutableNode('attr:e1'), tagNode('event:R1', { type: 'event', tags: [{ name: 'x' }] })];
    eq('a tag, a cluster with its tag; not a cluster without one, an element or an event',
       p.appliesTo(nodes).map(n => n.id), ['tag:tlp:amber', 'cluster:' + TAG_APT.name]);
    eq('capped at the canvas budget, never saved', [p.maxCandidates, p.save], [1500, undefined]);
});

test('tagged events: one tag asks by name, counts at most the newest 200, offers no mode', async () => {
    const g = await withTagged();
    const s = await pivot(g, 'tagged-events').summarize([TLP_NODE()], {}, {});
    eq('the request', g.bodies, [{ tags: ['tlp:amber'], mode: 'and' }]);
    eq('the count is what the fetch brings', s, { total: 200 });
});

test('tagged events: several tags intersect by default, union on request', async () => {
    const g = await withTagged();
    const p = pivot(g, 'tagged-events');
    const s = await p.summarize([TLP_NODE(), APT_NODE()], {}, {});
    eq('a cluster asks by its tag', g.bodies[0], { tags: ['tlp:amber', TAG_APT.name], mode: 'and' });
    eq('one narrowing control, all of them first',
       s.facets.map(f => [f.key, f.type, f.options.map(o => o.value)]), [['mode', 'select', ['and', 'or']]]);
    await p.summarize([TLP_NODE(), APT_NODE()], { mode: 'or' }, {});
    eq('any of them', g.bodies[1].mode, 'or');
});

test('tagged events: summarize then fetch is one request', async () => {
    const g = await withTagged();
    const p = pivot(g, 'tagged-events');
    await p.summarize([TLP_NODE()], {}, {});
    await p.fetch([TLP_NODE()], {}, {});
    eq('asked once', g.bodies.length, 1);
    await p.fetch([TLP_NODE()], { mode: 'or' }, {});
    eq('a different question is asked again', g.bodies.length, 2);
});

test('tagged events: each lands as an event card, joined to the tags it carries', async () => {
    const g = await withTagged();
    const r = await pivot(g, 'tagged-events').fetch([TLP_NODE(), APT_NODE()], { mode: 'or' }, {});
    eq('cards, keyed like every other event', r.nodes.map(n => [n.id, n.data.type, n.data.label, n.data.event_id]),
       [['event:R812', 'event', 'Tagged on the event', '812'], ['event:R813', 'event', 'Tagged on an attribute', '813']]);
    eq('a card reads its clusters by tag, so the Tags & clusters pivot finds them',
       r.nodes[0].data.clusters.map(c => c.tag_name), [TAG_APT.name]);
    eq('event-level unlabelled, attribute-level said, and only for what each carries',
       r.edges.map(e => [e.from, e.to, e.data.kind, e.data.label]),
       [['event:R812', 'tag:tlp:amber', 'tag', ''],
        ['event:R812', 'cluster:' + TAG_APT.name, 'tag', ''],
        ['event:R813', 'tag:tlp:amber', 'tag', 'via attribute']]);
    eq('an edge the Tags & clusters pivot would draw has the same id',
       r.edges[0].id, 'tagged:event:R812>tag:tlp:amber');
});

test('tagged events: a card is joined to the other tags already drawn, not only the selected one', async () => {
    const g = await withTagged();
    g.graph.liveNode({ id: 'tag:tlp:amber', data: { type: 'tag', name: 'tlp:amber' } });
    const r = await pivot(g, 'tagged-events').fetch([APT_NODE()], {}, {});
    eq('R812 carries tlp:amber too',
       r.edges.map(e => [e.from, e.to, e.data.label]),
       [['event:R812', 'cluster:' + TAG_APT.name, ''], ['event:R812', 'tag:tlp:amber', '']]);
});

test('tags: an element landing after its tag is joined to it', async () => {
    // Over the budget, so the object is not drawn and is on offer.
    const g = await buildGraph(ev({ Object: fillers(1500).concat([obj({ uuid: 'A', Attribute: [
        attr({ uuid: 'c1', value: '1.2.3.4', Tag: [TAG_TLP] }),
        attr({ uuid: 'c2', value: 'untagged', Tag: [TAG_LUMMA] })] })]) }));
    g.graph.liveNode({ id: 'tag:tlp:amber', data: { type: 'tag', name: 'tlp:amber' } });
    const r = pivot(g, 'event-elements').fetch([], { q: '1.2.3.4' }, {});
    eq('the object is offered', r.nodes.map(n => n.id), ['obj:A']);
    ok('the object\'s attribute rides in joined to the drawn tag',
       r.edges.some(e => e.from === 'attr:c1' && e.to === 'tag:tlp:amber' && e.data.kind === 'tag'),
       r.edges.map(e => e.id));
    ok('nothing to a tag not drawn', !r.edges.some(e => e.to === 'tag:LummaC2'));
});

test('tags: a cluster landing from another pivot is joined to the carriers already drawn', async () => {
    const g = await withRelations(() => ({ relations: [{ relation: 'similar',
        cluster: { uuid: 'CL-APT28', value: 'APT28', type: 'threat-actor', tag_name: TAG_APT.name } }] }));
    const src = tagNode('cluster:misp-galaxy:x="Y"', { type: 'cluster', tag_name: 'misp-galaxy:x="Y"', uuid: 'CL-Y' });
    const r = await pivot(g, 'related-clusters').fetch([src], {}, {});
    eq('APT28 lands with its carriers on the canvas',
       r.edges.filter(e => e.data.kind === 'tag').map(e => e.from).sort(), ['attr:c1', 'attr:e1']);
});

test('tagged events: a failed request is not kept', async () => {
    let fail = true;
    const g = await withTagged(() => (fail ? { __status: 500 } : TAGGED));
    const p = pivot(g, 'tagged-events');
    let threw = false;
    await p.summarize([TLP_NODE()], {}, {}).catch(() => { threw = true; });
    ok('the failure reaches the library', threw);
    fail = false;
    eq('asked again', (await p.summarize([TLP_NODE()], {}, {})).total, 200);
});

/* ─────────────────────── around another event's object ─────────────────── */

const SURROUNDINGS = {
    objects: [
        obj({ uuid: 'OB2', name: 'file', event_id: '7', template_uuid: 'T-FILE', template_version: '3', Attribute: [
            attr({ uuid: 'oc1', value: 'deadbeef', type: 'md5', object_relation: 'md5' })] }),
        obj({ uuid: 'OB3', name: 'url', 'meta-category': 'network', event_id: '7' }),
    ],
    references: [
        { uuid: 'REF1', object_uuid: 'OB', referenced_uuid: 'OB2', relationship_type: 'resolves-to' },
        { uuid: 'REF2', object_uuid: 'OB3', referenced_uuid: 'OB', relationship_type: null },
    ],
    event: { id: '7', uuid: 'R7', info: 'Event 7' },
    ui_priorities: { 'T-FILE.3': { md5: 8 } },
};

function withSurroundings(route) {
    let asked = 0;
    return buildGraph(taggedEvent(), { routes: [[/objects\/surroundings\/OB\.json$/, init => {
        asked++;
        return route ? route(init) : SURROUNDINGS;
    }]] }).then(g => Object.assign(g, { asked: () => asked }));
}

const FOREIGN_OBJ = () => tagNode('obj:OB', { type: 'object', uuid: 'OB', scope: 'foreign', event_id: '7' });

test('around this object: offered on another event\'s object only', async () => {
    const g = await withSurroundings();
    const p = pivot(g, 'object-surroundings');
    const nodes = [FOREIGN_OBJ(), g.graph.getMutableNode('obj:A'),
                   tagNode('attr:x1', { type: 'attribute', uuid: 'x1', scope: 'foreign' }),
                   tagNode('event:R7', { type: 'event', uuid: 'R7', scope: 'foreign' })];
    eq('not this event\'s object, not an attribute, not a card', p.appliesTo(nodes).map(n => n.id), ['obj:OB']);
    eq('capped, never saved', [p.maxCandidates, p.save], [1500, undefined]);
});

test('around this object: counts the objects it brings, read once', async () => {
    const g = await withSurroundings();
    const p = pivot(g, 'object-surroundings');
    eq('two objects', (await p.summarize([FOREIGN_OBJ()], {}, {})).total, 2);
    await p.fetch([FOREIGN_OBJ()], {}, {});
    eq('read once', g.asked(), 1);
});

test('around this object: its neighbours land with their references and their card', async () => {
    const g = await withSurroundings();
    const r = await pivot(g, 'object-surroundings').fetch([FOREIGN_OBJ()], {}, {});
    eq('the card, then each object', r.nodes.map(n => n.id), ['event:R7', 'obj:OB2', 'obj:OB3']);
    eq('an object brings its own, ranked by its template',
       byId(r.nodes, 'obj:OB2').children.map(c => [c.id, c.data.scope, c.data.event_id, c.data.ui_priority]),
       [['attr:oc1', 'foreign', '7', 8]]);
    eq('each object in its event, each reference as drawn in its own event',
       r.edges.map(e => [e.id, e.from, e.to, e.data.kind, e.data.label]),
       [['in-event:obj:OB2', 'obj:OB2', 'event:R7', 'in-event', ''],
        ['in-event:obj:OB3', 'obj:OB3', 'event:R7', 'in-event', ''],
        ['ref:REF1', 'obj:OB', 'obj:OB2', 'object-reference', 'resolves-to'],
        ['ref:REF2', 'obj:OB3', 'obj:OB', 'object-reference', 'related-to']]);
});

test('around this object: a failed request is not kept', async () => {
    let fail = true;
    const g = await withSurroundings(() => (fail ? { __status: 403 } : SURROUNDINGS));
    const p = pivot(g, 'object-surroundings');
    let threw = false;
    await p.summarize([FOREIGN_OBJ()], {}, {}).catch(() => { threw = true; });
    ok('the failure reaches the library', threw);
    fail = false;
    eq('asked again', (await p.summarize([FOREIGN_OBJ()], {}, {})).total, 2);
});

/* ─────────────────── a cluster's galaxy relations ───────────────── */

const RELATIONS = {
    relations: [
        { relation: 'similar', cluster: { id: '47753', uuid: 'CL-G0007', value: 'APT28 - G0007',
            type: 'mitre-intrusion-set', galaxy_name: 'MITRE ATT&CK Groups',
            tag_name: 'misp-galaxy:mitre-intrusion-set="APT28 - G0007"' } },
        { relation: 'uses', cluster: { id: '5', uuid: 'CL-X', value: 'X-Agent', type: 'tool',
            galaxy_name: 'Tool', tag_name: 'misp-galaxy:tool="X-Agent"' } },
        { relation: 'similar', cluster: { id: '72580', uuid: 'CL-APT28', value: 'APT28', type: 'threat-actor',
            tag_name: TAG_APT.name } },
    ],
};

function withRelations(route, inbound) {
    return buildGraph(taggedEvent(), { routes: [
        [/galaxy_clusters\/relatedClusters\/[^/]+\.json$/, route || (() => RELATIONS)],
        [/galaxy_clusters\/relatedClusters\/[^/]+\/inbound\.json$/, inbound || (() => ({ relations: [] }))]] });
}

test('related clusters: offered on a cluster node that has a uuid', async () => {
    const g = await withRelations();
    const p = pivot(g, 'related-clusters');
    const nodes = [APT_NODE(), tagNode('cluster:y', { type: 'cluster', tag_name: 'y' }), TLP_NODE()];
    eq('a cluster parsed from a bare tag has none', p.appliesTo(nodes).map(n => n.id), ['cluster:' + TAG_APT.name]);
    eq('the count is the relations', await p.summarize([APT_NODE()], {}, {}), { total: 3 });
    ok('asked by uuid', g.fetchLog.some(f => /\/galaxy_clusters\/relatedClusters\/CL-APT28\.json$/.test(f.url)));
});

test('related clusters: each target lands as a cluster node, the edge naming the relation', async () => {
    const g = await withRelations();
    const p = pivot(g, 'related-clusters');
    await p.summarize([APT_NODE()], {}, {});
    const r = await p.fetch([APT_NODE()], {}, {});
    eq('asked once per cluster', g.fetchLog.filter(f => /relatedClusters/.test(f.url)).length, 1);
    eq('keyed by tag, so a cluster already drawn merges',
       r.nodes.map(n => [n.id, n.data.type, n.data.label, n.data.galaxy_type, n.data.galaxy_name, n.data.uuid]),
       [['cluster:misp-galaxy:mitre-intrusion-set="APT28 - G0007"', 'cluster', 'APT28 - G0007',
         'mitre-intrusion-set', 'MITRE ATT&CK Groups', 'CL-G0007'],
        ['cluster:misp-galaxy:tool="X-Agent"', 'cluster', 'X-Agent', 'tool', 'Tool', 'CL-X']]);
    eq('away from the selected cluster; a relation to its own tag is left out',
       r.edges.map(e => [e.from, e.to, e.data.kind, e.data.label]),
       [['cluster:' + TAG_APT.name, 'cluster:misp-galaxy:mitre-intrusion-set="APT28 - G0007"', 'cluster-relation', 'similar'],
        ['cluster:' + TAG_APT.name, 'cluster:misp-galaxy:tool="X-Agent"', 'cluster-relation', 'uses']]);
});

test('relating clusters: asks for the relations held towards the cluster, drawn into it', async () => {
    const g = await withRelations(null, () => RELATIONS);
    const p = pivot(g, 'relating-clusters');
    eq('the count is the relations', await p.summarize([APT_NODE()], {}, {}), { total: 3 });
    ok('asked for the inbound side',
       g.fetchLog.some(f => /\/galaxy_clusters\/relatedClusters\/CL-APT28\/inbound\.json$/.test(f.url)));
    const r = await p.fetch([APT_NODE()], {}, {});
    eq('each source points at the selected cluster, under the id the outbound side gives it',
       r.edges.map(e => [e.id, e.from, e.to, e.data.label]),
       [['clrel:cluster:misp-galaxy:mitre-intrusion-set="APT28 - G0007">cluster:' + TAG_APT.name + ':similar',
         'cluster:misp-galaxy:mitre-intrusion-set="APT28 - G0007"', 'cluster:' + TAG_APT.name, 'similar'],
        ['clrel:cluster:misp-galaxy:tool="X-Agent">cluster:' + TAG_APT.name + ':uses',
         'cluster:misp-galaxy:tool="X-Agent"', 'cluster:' + TAG_APT.name, 'uses']]);
});

test('related clusters: a cluster whose id is known is asked for by id, as one uuid can name several', async () => {
    const g = await withRelations();
    const p = pivot(g, 'related-clusters');
    const r = await p.fetch([APT_NODE()], {}, {});
    eq('a landed cluster keeps its id', byId(r.nodes, 'cluster:misp-galaxy:tool="X-Agent"').data.cluster_id, '5');
    await p.summarize([tagNode('cluster:misp-galaxy:tool="X-Agent"',
        { type: 'cluster', tag_name: 'misp-galaxy:tool="X-Agent"', uuid: 'CL-X', cluster_id: '5' })], {}, {});
    ok('asked by id', g.fetchLog.some(f => /\/galaxy_clusters\/relatedClusters\/5\.json$/.test(f.url)));
});

test('related clusters: a galaxy relation is its own edge kind', async () => {
    const g = await withRelations();
    const style = g.opts.render.edgeStyleMap['cluster-relation'];
    eq('solid, in the galaxy hue', [style.dashed, style.strokeColor],
       [undefined, g.win.MispPivotNodes.palette().galaxy.core]);
    eq('the sidebar names it', g.opts.UI.propertiesPanel.edgePropertiesMap(
        { getData: () => ({ kind: 'cluster-relation', label: 'uses' }) }), [{ name: 'Link', value: 'Galaxy relation' }]);
});

test('a dashed edge holds still unless its kind asks to move', async () => {
    const g = await buildGraph(taggedEvent());
    eq('off by default', g.opts.render.defaultEdgeStyle.animateDash, false);
    eq('no kind opts in', Object.keys(g.opts.render.edgeStyleMap)
        .filter(k => g.opts.render.edgeStyleMap[k].animateDash), []);
});

test('related clusters: a failed request is not kept', async () => {
    let fail = true;
    const g = await withRelations(() => (fail ? { __status: 404 } : RELATIONS));
    const p = pivot(g, 'related-clusters');
    let threw = false;
    await p.summarize([APT_NODE()], {}, {}).catch(() => { threw = true; });
    ok('the failure reaches the library', threw);
    fail = false;
    eq('asked again', (await p.summarize([APT_NODE()], {}, {})).total, 3);
});

/* ─────────────────── part of another event, by kind ─────────────────── */

// As /events/cardElements shapes it, for event 7: counted, then fetched.
const CARD_COUNT = { total: 3, by_type: { 'ip-dst': 2, domain: 1 }, by_category: { 'Network activity': 3 } };
const CARD_ELEMENTS = {
    attributes: [attr({ uuid: 'f1', value: '10.9.9.9', to_ids: true, event_id: '7' })],
    objects: {
        OB: { id: '70', uuid: 'OB', name: 'domain-ip', 'meta-category': 'network', event_id: '7',
              template_uuid: 'T-DIP', template_version: '9', Attribute: [
                  attr({ uuid: 'x1', value: 'evil.example', type: 'domain', object_relation: 'domain', to_ids: true }),
                  attr({ uuid: 'x2', value: '10.0.0.2', object_relation: 'ip' })] },
    },
    matched: ['x1', 'f1'],
    event: { id: '7', uuid: 'R7', info: 'Event 7' },
    ui_priorities: { 'T-DIP.9': { domain: 4 } },
};

const CARD = (id, uuid) => tagNode('event:' + (uuid || 'R' + (id || '7')),
    { type: 'event', uuid: uuid || 'R' + (id || '7'), event_id: id || '7', scope: 'foreign' });

function withCard(route) {
    const asked = [];
    return withPivots([[/events\/cardElements\/(\d+)\.json$/, init => {
        const body = JSON.parse(init.body);
        asked.push(body);
        if (route) return route(body, asked.length);
        return body.count ? CARD_COUNT : CARD_ELEMENTS;
    }]]).then(g => Object.assign(g, { asked }));
}

const CARD_PIVOTS = ['card-attributes', 'card-ids', 'card-network'];

test('another event\'s card: offered on a MISP event\'s card only', async () => {
    const g = await withCard();
    const nodes = [CARD(), CARD('1', 'U1'),
                   tagNode('event:F', { type: 'event', uuid: 'F', event_id: '7', _provenance: 'feed' }),
                   tagNode('attr:x1', { type: 'attribute', uuid: 'x1', event_id: '7' }),
                   tagNode('obj:OB', { type: 'object', uuid: 'OB', event_id: '7' })];
    CARD_PIVOTS.concat('card-correlations').forEach(id => {
        eq(id + ': not this event, not a feed\'s card, not an element', pivot(g, id).appliesTo(nodes).map(n => n.id), ['event:R7']);
        eq(id + ': capped, never saved', [pivot(g, id).maxCandidates, pivot(g, id).save], [1500, undefined]);
    });
    eq('labels', CARD_PIVOTS.concat('card-correlations').map(id => pivot(g, id).label),
       ['Its attributes', 'Its IDS indicators', 'Its network indicators', 'More correlations with this event']);
    eq('more correlations: only where the counts say that event correlates',
       pivot(g, 'card-correlations').appliesTo([CARD(), CARD('9')]).map(n => n.id), ['event:R7']);
});

test('another event\'s card: the count names its slice and narrowing, and leaves out what is drawn', async () => {
    const g = await withCard();
    g.graph.liveNode({ id: 'obj:OB', data: { type: 'object', uuid: 'OB', event_id: '7' } });
    g.graph.liveNode({ id: 'attr:x1', data: { type: 'attribute', uuid: 'x1', event_id: '7' } });
    g.graph.liveNode({ id: 'attr:y', data: { type: 'attribute', uuid: 'y', event_id: '8' } });
    await pivot(g, 'card-network').summarize([CARD()], { q: 'evil', type: ['domain'], category: 'Network activity', ids: false }, {});
    eq('network', g.asked[0], { slice: 'network', q: 'evil', types: ['domain'], category: 'Network activity',
                                exclude: ['OB', 'x1'], count: true, ids: false });
    ok('asked of that event', g.fetchLog.some(f => /\/misp\/events\/cardElements\/7\.json$/.test(f.url)));
    await pivot(g, 'card-ids').summarize([CARD()], { ids: false }, {});
    eq('the IDS slice is always IDS', [g.asked[1].slice, 'ids' in g.asked[1]], ['ids', false]);
    await pivot(g, 'card-attributes').summarize([CARD()], {}, {});
    eq('unnarrowed', g.asked[2], { slice: 'all', q: '', types: [], category: '', exclude: ['OB', 'x1'], count: true });
});

test('another event\'s card: the form, with its options counting matching attributes', async () => {
    const g = await withCard();
    const s = await pivot(g, 'card-attributes').summarize([CARD()], {}, {});
    eq('the total is landing units', s.total, 3);
    eq('fields', s.facets.map(f => [f.key, f.type]),
       [['q', 'text'], ['ids', 'boolean'], ['type', 'multiselect'], ['category', 'select']]);
    eq('types, each with its count', s.facets[2].options,
       [{ label: 'domain', value: 'domain', count: 1 }, { label: 'ip-dst', value: 'ip-dst', count: 2 }]);
    eq('the IDS shortcut has no IDS field',
       (await pivot(g, 'card-ids').summarize([CARD()], {}, {})).facets.map(f => f.key), ['q', 'type', 'category']);
});

test('another event\'s card: several cards each answer for themselves, and the counts add up', async () => {
    const g = await withCard(body => (body.count
        ? { total: 2, by_type: { 'ip-dst': 2 }, by_category: { 'Network activity': 2 } } : CARD_ELEMENTS));
    const s = await pivot(g, 'card-ids').summarize([CARD(), CARD('9')], {}, {});
    eq('summed', [s.total, s.facets[1].options.map(o => o.count)], [4, [4]]);
    eq('one request per card', g.fetchLog.filter(f => /cardElements/.test(f.url)).map(f => f.url.split('/').pop()),
       ['7.json', '9.json']);
});

test('another event\'s card: a count is read once until the canvas changes', async () => {
    const g = await withCard();
    const p = pivot(g, 'card-ids');
    await p.summarize([CARD()], {}, {});
    await p.summarize([CARD()], {}, {});
    eq('once', g.asked.length, 1);
    await p.summarize([CARD()], { q: 'x' }, {});
    eq('another narrowing is another question', g.asked.length, 2);
    g.graph.listeners.nodeAdd.forEach(f => f(pnode({})));
    await p.summarize([CARD()], {}, {});
    eq('asked again once something landed', g.asked.length, 3);
});

test('another event\'s card: a failed request is not kept', async () => {
    let fail = true;
    const g = await withCard(() => (fail ? { __status: 500 } : CARD_COUNT));
    const p = pivot(g, 'card-ids');
    let threw = false;
    await p.summarize([CARD()], {}, {}).catch(() => { threw = true; });
    ok('the failure reaches the library', threw);
    fail = false;
    eq('asked again', (await p.summarize([CARD()], {}, {})).total, 3);
});

test('another event\'s card: an object lands closed with all its attributes, the matching ones marked', async () => {
    const g = await withCard();
    const r = await pivot(g, 'card-ids').fetch([CARD()], {}, {});
    eq('asked for records', [g.asked[0].count, g.asked[0].slice], [false, 'ids']);
    eq('the card, the object, the free attribute', r.nodes.map(n => n.id), ['event:R7', 'obj:OB', 'attr:f1']);
    const box = byId(r.nodes, 'obj:OB');
    eq('every child, only the matching one marked, ranked by its template',
       box.children.map(c => [c.id, c.data.matched, c.data.ui_priority]),
       [['attr:x1', ['ids'], 4], ['attr:x2', undefined, undefined]]);
    eq('in that event', [box.data.scope, box.data.event_id, byId(r.nodes, 'attr:f1').data.event_id], ['foreign', '7', '7']);
    eq('the free attribute is marked too', byId(r.nodes, 'attr:f1').data.matched, ['ids']);
    eq('each joined to its card',
       r.edges.map(e => [e.id, e.from, e.to, e.data.kind]),
       [['in-event:obj:OB', 'obj:OB', 'event:R7', 'in-event'], ['in-event:attr:f1', 'attr:f1', 'event:R7', 'in-event']]);
});

test('another event\'s card: several cards land each its own, joined to its own card', async () => {
    const other = { attributes: [attr({ uuid: 'g1', event_id: '9' })], objects: {}, matched: ['g1'],
                    event: { id: '9', uuid: 'R9', info: 'Event 9' } };
    const g = await withPivots([[/cardElements\/7\.json$/, CARD_ELEMENTS], [/cardElements\/9\.json$/, other]]);
    const r = await pivot(g, 'card-network').fetch([CARD(), CARD('9')], {}, {});
    eq('each card and its own', r.nodes.map(n => n.id), ['event:R7', 'obj:OB', 'attr:f1', 'event:R9', 'attr:g1']);
    eq('marked by the pivot that brought it', byId(r.nodes, 'attr:g1').data.matched, ['network']);
    eq('joined to its own card', r.edges.filter(e => e.from === 'attr:g1').map(e => e.to), ['event:R9']);
});

test('more correlations: counts what of that event it would draw, and lands it without asking again', async () => {
    let body = null, asked = 0;
    const g = await withPivots([[/correlatedAttributes/, init => {
        asked++;
        body = JSON.parse(init.body);
        return Object.assign({}, PAIRS, { pairs: PAIRS.pairs.filter(p => body.event_ids.indexOf(p.Event.id) !== -1) });
    }]]);
    const p = pivot(g, 'card-correlations');
    eq('two correlated attributes in 7',(await p.summarize([CARD()], {}, {})).total, 2);
    eq('every pair with that event', body, { event_ids: ['7'] });
    g.graph.liveNode({ id: 'attr:x1', data: { type: 'attribute', uuid: 'x1', event_id: '7' } });
    eq('less what is drawn', (await p.summarize([CARD()], {}, {})).total, 1);
    const r = await p.fetch([CARD()], {}, {});
    eq('asked once', asked, 1);
    eq('lands that event\'s side, joined to this event\'s',
       [r.nodes.map(n => n.id).filter(id => /R7|x1|x2/.test(id)), r.edges.filter(e => e.data.kind === 'correlation').map(e => e.id)],
       [['event:R7', 'attr:x1', 'attr:x2'], ['corr:c1:x1', 'corr:c1:x2']]);
});

test('more correlations: a failed request is not kept', async () => {
    let fail = true;
    const g = await withPivots([[/correlatedAttributes/, () => (fail ? { __status: 500 } : PAIRS)]]);
    const p = pivot(g, 'card-correlations');
    let threw = false;
    await p.summarize([CARD()], {}, {}).catch(() => { threw = true; });
    ok('the failure reaches the library', threw);
    fail = false;
    eq('asked again', (await p.summarize([CARD()], {}, {})).total, 2);
});

/* ──────────────────────── enrichment (Enrich) ─────────────────── */

const ENR_TYPES = {
    types: { 'ip-dst': ['ipasn', 'mmdb_lookup', 'whois', 'shodan'], domain: ['whois'] },
    modules: { ipasn: { format: 'misp_standard' }, mmdb_lookup: { format: 'misp_standard' },
               whois: { format: 'simplified' }, shodan: { format: 'misp_standard' } },
    profile: { ticked: { 'ip-dst': ['mmdb_lookup'] }, never: { 'ip-dst': ['shodan'] } },
};
const NOW = () => Math.floor(Date.now() / 1000);
const ENR_STORED = body => JSON.parse(body.body).items.map(i => ({
    value: i.value, type: i.type,
    modules: i.value === '8.8.8.8' ? {
        ipasn: { state: 'ok', ran_at: NOW() - 3 * 3600, total: 2, fresh: true },
        whois: { state: 'error', ran_at: NOW() - 30 * 3600, total: 0, fresh: false },
    } : {},
}));
const ASN = { name: 'asn', meta_category: 'network', description: 'An AS', attributes: [
    { relation: 'asn', type: 'AS', value: '15169', known: false },
    { relation: 'subnet-announced', type: 'ip-src', value: '8.8.8.0/24', known: true }] };
const ECHO = { type: 'ip-dst', value: '8.8.8.8', category: 'Network activity', known: false };
const answerOf = (module, o) => ({ run: Object.assign({ module, state: 'ok', attributes: [ECHO], objects: [],
    elements: [], total: 1, shown: 1, capped: false, from_store: false, age: null }, o) });
const ENR_RUN = init => {
    const b = JSON.parse(init.body);
    // A misp_standard module echoes the value it was asked about.
    const answer = (module, o) => answerOf(module, Object.assign({ attributes: [Object.assign({}, ECHO, { value: b.value })] }, o));
    if (b.module === 'ipasn') return answer('ipasn', { objects: [ASN], from_store: b.mode === 'stored', age: 10800 });
    if (b.module === 'mmdb_lookup') return answer('mmdb_lookup', { objects: [ASN], elements: [] });
    if (b.module === 'whois') return answer('whois', { state: 'error', message: 'Whois local instance address is missing',
                                                        attributes: [] });
    return answer(b.module, { state: 'silent', attributes: [] });
};
const ENR_ROUTES = [[/enrichmentTypes/, ENR_TYPES], [/enrichmentStored/, ENR_STORED], [/enrichmentRun/, ENR_RUN]];

const enrNode = (id, data) => ({ id, getData: () => data });
const IP = (value, id) => enrNode(id || 'attr:' + value, { type: 'attribute', value, 'attr-type': 'ip-dst', scope: 'self' });

async function enrichGraph(options) {
    const g = await buildGraph(ev({ Attribute: [attr({ uuid: 'A1', value: '8.8.8.8' })] }),
                               Object.assign({ canEnrich: true, routes: ENR_ROUTES }, options));
    await new Promise(r => setTimeout(r, 0));
    return g;
}

test('enrich: offered only to a reader who may run modules (E11)', async () => {
    const off = await buildGraph(ev({}), { routes: ENR_ROUTES });
    ok('no Enrich without canEnrich', !pivot(off, 'enrich'));
    ok('nothing asked either', !off.fetchLog.some(f => /enrichment/.test(f.url)));
    const on = await enrichGraph();
    ok('Enrich with canEnrich', !!pivot(on, 'enrich'));
    eq('the catalogue is read once', on.fetchLog.filter(f => /enrichmentTypes/.test(f.url)).length, 1);
});

test('enrich: applies to attributes and values whose type a module accepts', async () => {
    const p = pivot(await enrichGraph(), 'enrich');
    const kept = p.appliesTo([
        IP('8.8.8.8'),
        enrNode('attr:x', { type: 'attribute', value: 'x', 'attr-type': 'md5' }),
        enrNode('obj:o', { type: 'object', name: 'asn' }),
        enrNode('event:e', { type: 'event' }),
        enrNode('value:v', { type: 'value', value: 'a.example', types: ['domain', 'text'] }),
        enrNode('enr:ip-src:1.1.1.1', { type: 'attribute', value: '1.1.1.1', 'attr-type': 'ip-dst', scope: 'module' }),
    ]).map(n => n.id);
    eq('the ip-dst attribute and the domain value', kept, ['attr:8.8.8.8', 'value:v']);
});

test('enrich: the Module facet carries stored state, pre-ticks, and hides `never`', async () => {
    const p = pivot(await enrichGraph(), 'enrich');
    const s = await p.summarize([IP('8.8.8.8')], {}, {});
    const facet = s.facets[0];
    eq('one multiselect Module facet', [facet.key, facet.type], ['module', 'multiselect']);
    eq('never is not offered', facet.options.map(o => o.value), ['ipasn', 'mmdb_lookup', 'whois']);
    eq('stored state in the labels', facet.options.map(o => o.label),
       ['ipasn — 3 h ago', 'mmdb_lookup', 'whois — failed 30 h ago']);
    eq('the stored total is the count', facet.options[0].count, 2);
    eq('fresh and profile-ticked start ticked', facet.default.slice().sort(), ['ipasn', 'mmdb_lookup']);
    eq('a ticked module never asked leaves the total unknown', s.total, null);
    eq('every picked module stored: their totals, a failure counting 0',
       (await p.summarize([IP('8.8.8.8')], { module: ['ipasn', 'whois'] }, {})).total, 2);
    eq('nothing picked: nothing comes', (await p.summarize([IP('8.8.8.8')], { module: [] }, {})).total, 0);
});

test('enrich: fetch lands content-hashed objects, drops the echo, and toasts what failed', async () => {
    const g = await enrichGraph();
    const p = pivot(g, 'enrich');
    const r = await p.fetch([IP('8.8.8.8')], { module: ['ipasn', 'mmdb_lookup', 'whois'] }, { graph: g.graph });
    const runs = g.fetchLog.filter(f => /enrichmentRun/.test(f.url)).map(f => JSON.parse(f.init.body));
    eq('a fresh answer is read from the store, the rest pressed',
       runs.map(x => x.module + ':' + x.mode).sort(), ['ipasn:stored', 'mmdb_lookup:press', 'whois:press']);
    ok('the echoed origin is not landed', !r.nodes.some(n => n.id === 'enr:ip-dst:8.8.8.8'));
    eq('one object per module (E4)', r.nodes.map(n => n.id.split(':')[1]).sort(), ['ipasn', 'mmdb_lookup']);
    const o = r.nodes.find(n => n.data.module === 'ipasn');
    ok('its id is the module and a content hash', /^enr-obj:ipasn:[0-9a-f]{8}$/.test(o.id), o.id);
    eq('the same record hashes the same', o.id.split(':')[2],
       r.nodes.find(n => n.data.module === 'mmdb_lookup').id.split(':')[2]);
    eq('it is a module result, from the store', [o.data.type, o.data.scope, o.data.from_store], ['object', 'module', true]);
    eq('its attributes are its own children', o.children.map(c => c.id),
       [o.id + ':asn:15169', o.id + ':subnet-announced:8.8.8.0/24']);
    eq('known rides on the child', o.children.map(c => c.data.known), [false, true]);
    eq('two enrichment edges, one per module', r.edges.map(e => [e.data.kind, e.data.label]).sort(),
       [['enrichment', 'ipasn'], ['enrichment', 'mmdb_lookup']]);
    eq('one toast for what did not come back', g.graph.notices.map(n => [n.level, n.msg]),
       [['warning', 'whois: Whois local instance address is missing']]);
});

test('enrich: one module returning one record for two origins lands one node, two edges', async () => {
    const g = await enrichGraph();
    const r = await pivot(g, 'enrich').fetch([IP('8.8.8.8'), IP('8.8.4.4')], { module: ['mmdb_lookup'] }, { graph: g.graph });
    eq('one node', r.nodes.length, 1);
    eq('an edge from each origin', r.edges.map(e => e.from).sort(), ['attr:8.8.4.4', 'attr:8.8.8.8']);
});

const SOCKET = () => Object.assign(enrNode('obj:sock', { type: 'object', name: 'network-socket', scope: 'self' }), {
    children: [
        { getData: () => ({ type: 'attribute', value: '53', 'attr-type': 'port', object_relation: 'dst-port', ui_priority: 1 }) },
        { getData: () => ({ type: 'attribute', value: '8.8.4.4', 'attr-type': 'ip-dst', object_relation: 'ip-dst', ui_priority: 5 }) },
        { getData: () => ({ type: 'attribute', value: '8.8.8.8', 'attr-type': 'ip-dst', object_relation: 'ip-src', ui_priority: 2 }) },
    ] });

test('enrich: an object is enriched through its attributes, its lead one by default', async () => {
    const g = await enrichGraph();
    const p = pivot(g, 'enrich');
    eq('an object with an eligible attribute is offered', p.appliesTo([SOCKET()]).map(n => n.id), ['obj:sock']);
    const s = await p.summarize([SOCKET()], {}, {});
    const attrs = s.facets.find(f => f.key === 'attribute');
    eq('its eligible attributes, lead first', attrs.options.map(o => o.label), ['ip-dst: 8.8.4.4', 'ip-src: 8.8.8.8']);
    eq('the lead one starts picked', attrs.default, ['ip-dst|8.8.4.4']);
    const r = await p.fetch([SOCKET()], { module: ['mmdb_lookup'] }, { graph: g.graph });
    eq('only the lead attribute is asked',
       g.fetchLog.filter(f => /enrichmentRun/.test(f.url)).map(f => JSON.parse(f.init.body).value), ['8.8.4.4']);
    eq('the result joins the object, the edge names the attribute',
       r.edges.map(e => [e.from, e.data.label]), [['obj:sock', 'mmdb_lookup · ip-dst']]);
    ok('the asked value is not echoed back as a result', !r.nodes.some(n => n.id === 'enr:ip-dst:8.8.4.4'));
    await p.fetch([SOCKET()], { module: ['mmdb_lookup'], attribute: ['ip-dst|8.8.4.4', 'ip-dst|8.8.8.8'] }, { graph: g.graph });
    eq('a wider pick asks each picked attribute',
       g.fetchLog.filter(f => /enrichmentRun/.test(f.url)).map(f => JSON.parse(f.init.body).value), ['8.8.4.4', '8.8.4.4', '8.8.8.8']);
});

test('enrich: the context menu offers an object\'s attributes as choices', async () => {
    const p = pivot(await enrichGraph(), 'enrich');
    eq('one choice per eligible attribute', p.menuChoices([SOCKET()]),
       [{ label: 'ip-dst: 8.8.4.4', narrowing: { attribute: ['ip-dst|8.8.4.4'] } },
        { label: 'ip-src: 8.8.8.8', narrowing: { attribute: ['ip-dst|8.8.8.8'] } }]);
    eq('a loose attribute has none', p.menuChoices([IP('8.8.8.8')]), []);
});

test('enrich: a run drops the cached counts of what it asked', async () => {
    const g = await enrichGraph();
    const node = IP('8.8.8.8');
    await pivot(g, 'enrich').fetch([node], { module: ['ipasn'] }, { graph: g.graph });
    ok('the Enrich summary is invalidated', g.graph.pivots.invalidated.includes('enrich'));
    const before = g.fetchLog.filter(f => /enrichmentStored/.test(f.url)).length;
    await pivot(g, 'enrich').summarize([node], {}, {});
    eq('and the store is read again', g.fetchLog.filter(f => /enrichmentStored/.test(f.url)).length, before + 1);
});

test('enrich: a run where no module answered fails with their reasons', async () => {
    const g = await enrichGraph();
    let msg = null;
    await pivot(g, 'enrich').fetch([IP('8.8.8.8')], { module: ['whois'] }, { graph: g.graph })
        .catch(e => { msg = e.message; });
    eq('the reason is the error', msg, 'whois: Whois local instance address is missing');
});

test('enrich: over 25 asked pairs is refused before any call (E10)', async () => {
    const g = await enrichGraph();
    const nodes = [];
    for (let i = 0; i < 9; i++) nodes.push(IP('10.0.0.' + i));
    let msg = null;
    await pivot(g, 'enrich').fetch(nodes, { module: ['ipasn', 'mmdb_lookup', 'whois'] }, { graph: g.graph })
        .catch(e => { msg = e.message; });
    ok('refused with the count and the limit', /^27 module queries would be sent; 25 at most/.test(msg || ''), msg);
    ok('no module was asked', !g.fetchLog.some(f => /enrichmentRun/.test(f.url)));
});

test('enrich: a legacy element lands untyped, as its first type', async () => {
    const g = await enrichGraph({ routes: [[/enrichmentTypes/, ENR_TYPES], [/enrichmentStored/, ENR_STORED],
        [/enrichmentRun/, () => answerOf('whois', { attributes: [], elements: [{ types: ['domain', 'hostname'], value: 'dns.google', known: false }] })]] });
    const r = await pivot(g, 'enrich').fetch([IP('8.8.8.8')], { module: ['whois'] }, { graph: g.graph });
    eq('one attribute node', r.nodes.map(n => n.id), ['enr:domain:dns.google']);
    eq('flagged untyped, other types kept', [r.nodes[0].data.untyped, r.nodes[0].data.candidate_types], [true, ['hostname']]);
});

test('enrich: a result wears the mark, groups keep results apart, the legend has an entry', async () => {
    const g = await enrichGraph();
    const res = enrNode('enr-obj:ipasn:abc', { type: 'object', name: 'asn', scope: 'module', module: 'ipasn', modules: ['ipasn'] });
    const mine = enrNode('obj:1', { type: 'object', name: 'asn', scope: 'self' });
    const badges = g.opts.render.defaultNodeStyle.badges;
    eq('a result wears one ne mark', badges(res).map(b => b.position), ['ne']);
    ok('its title names the module', /From enrichment — ipasn/.test(badges(res)[0].title));
    eq('a MISP node does not', badges(mine), []);
    const typeOf = g.opts.UI.simplify.typeOf;
    ok('a result and a MISP object of one name group apart', typeOf(res) !== typeOf(mine), typeOf(res));
    g.graph.liveNode({ id: res.id, data: res.getData() });
    const prov = g.opts.UI.legend.sections.find(s => s && s.id === 'provenance');
    const entry = prov.entries(g.graph).find(e => e.id === 'module');
    ok('From enrichment is in the Provenance legend, with the mark', entry && entry.label === 'From enrichment' && !!entry.badge);
    ok('and it is not counted as elsewhere', !prov.entries(g.graph).some(e => e.id === 'elsewhere'));
});

/* ─────────────────────── enrichment: saving ────────────────────── */

// A landed result as pivotick hands it to `save`: live nodes and edges.
function liveResult(raw, byId) {
    const n = { id: raw.id, data: Object.assign({}, raw.data),
                getData() { return this.data; },
                updateData(p) { Object.assign(this.data, p); } };
    n.children = (raw.children || []).map(c => liveResult(c, byId));
    byId[raw.id] = n;
    return n;
}
function savePayload(result, origins) {
    const byId = {};
    origins.forEach(o => { byId[o.id] = o; });
    const nodes = result.nodes.map(r => liveResult(r, byId));
    const children = [].concat(...nodes.map(n => n.children));
    const edges = result.edges.map(e => ({ id: e.id, from: byId[e.from], to: byId[e.to], getData: () => e.data }));
    return { runId: 'enrich#1', pivotId: 'enrich', origin: origins, nodes, children, edges,
             vouched: { nodes: [], edges: [] }, attempt: 1 };
}
// Saved under the uuid sent, unless `answer` says otherwise for that uuid.
const saveRoute = (seen, answer) => init => {
    const body = JSON.parse(init.body);
    seen.push(body);
    const results = {};
    const all = body.Attribute.concat(body.Object, ...body.Object.map(o => o.Attribute));
    all.forEach((rec, i) => { results[rec.uuid] = (answer && answer(rec, i)) || { state: 'saved', uuid: rec.uuid }; });
    return { results, message: '' };
};
const saveGraph = (seen, answer, options) => buildGraph(ev({
    Attribute: [attr({ uuid: 'A1', value: '8.8.8.8' })],
    Object: [obj({ uuid: 'O1', name: 'network-socket', Attribute: [attr({ uuid: 'O1-a', value: '8.8.4.4' })] })],
}), Object.assign({ canEnrich: true, routes: ENR_ROUTES.concat([[/saveEnrichment/, saveRoute(seen, answer)], [/objectRelationships/, RELS]]) }, options))
    .then(g => new Promise(r => setTimeout(() => r(g), 0)));
const RELS = [{ name: 'resolves-to' }, { name: 'related-to' }, { name: 'characterizes' }];
// The library's save context; the prompt answers `answer` (default: as offered).
function saveCtx(g, answer) {
    const prompts = [];
    return { graph: g.graph, prompts, promptData(options) {
        prompts.push(options);
        if (answer === null) return Promise.resolve(null);
        const values = {};
        options.fields.forEach(f => { values[f.key] = f.defaultValue !== undefined ? f.defaultValue : ''; });
        return Promise.resolve(Object.assign(values, answer));
    } };
}
const OWN_IP = () => enrNode('attr:A1', { type: 'attribute', uuid: 'A1', value: '8.8.8.8', 'attr-type': 'ip-dst', scope: 'self' });
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;

test('enrich save: declared only where the viewer may modify the event', async () => {
    ok('savable with canEdit', typeof pivot(await saveGraph([]), 'enrich').save === 'function');
    ok('not savable without', pivot(await saveGraph([], null, { canEdit: false }), 'enrich').save === undefined);
});

test('enrich save: an object result becomes an object referencing its origin', async () => {
    const seen = [];
    const g = await saveGraph(seen);
    const p = pivot(g, 'enrich');
    const origin = OWN_IP();
    const payload = savePayload(await p.fetch([origin], { module: ['ipasn'] }, { graph: g.graph }), [origin]);
    const out = await p.save(payload, saveCtx(g));
    eq('one post, to this event', g.fetchLog.filter(f => /saveEnrichment/.test(f.url)).map(f => f.url),
       ['/misp/events/saveEnrichment/1.json']);
    const o = seen[0].Object[0];
    ok('a fresh uuid', UUID.test(o.uuid), o.uuid);
    eq('named, commented after the module and the value', [o.name, o.comment], ['asn', 'Enrichment: ipasn on 8.8.8.8']);
    eq('its attributes, with their relations', o.Attribute.map(a => [a.object_relation, a.type, a.value]),
       [['asn', 'AS', '15169'], ['subnet-announced', 'ip-src', '8.8.8.0/24']]);
    eq('tied to the origin, related-to', o.ObjectReference, [{ referenced_uuid: 'A1', relationship_type: 'related-to' }]);
    eq('no loose attribute, no reference from an object', [seen[0].Attribute, seen[0].ObjectReference], [[], []]);
    const node = payload.nodes[0];
    eq('the object and its children are saved', out.savedNodeIds.sort(),
       [node.id].concat(node.children.map(c => c.id)).sort());
    eq('under their MISP ids', out.canonicalIds[node.id], 'obj:' + o.uuid);
    eq('the edge is saved', out.savedEdgeIds, payload.edges.map(e => e.id));
    eq('it is this event\'s now', [node.data.scope, node.data.uuid, node.data.module], ['self', o.uuid, undefined]);
    eq('its children too', node.children.map(c => c.data.scope), ['self', 'self']);
    eq('the graph is told, so the legend recounts', g.graph.dataUpdates, [[node.id]]);
});

test('enrich save: from another event\'s origin a result goes in unattached', async () => {
    const seen = [];
    const g = await saveGraph(seen);
    const p = pivot(g, 'enrich');
    const origin = enrNode('attr:F1', { type: 'attribute', uuid: 'F1', value: '8.8.8.8', 'attr-type': 'ip-dst',
                                        scope: 'foreign', event_id: '7' });
    const payload = savePayload(await p.fetch([origin], { module: ['ipasn'] }, { graph: g.graph }), [origin]);
    await p.save(payload, saveCtx(g));
    eq('no reference', seen[0].Object[0].ObjectReference, []);
    eq('the comment names what was enriched', seen[0].Object[0].comment, 'Enrichment: ipasn on 8.8.8.8');
});

test('enrich save: a loose result of an object is referenced from that object', async () => {
    const seen = [];
    const g = await saveGraph(seen);
    const origin = enrNode('obj:O1', { type: 'object', uuid: 'O1', name: 'network-socket', scope: 'self' });
    const result = { nodes: [{ id: 'enr:domain:dns.google', data: { type: 'attribute', scope: 'module', module: 'whois',
                                     'attr-type': 'domain', value: 'dns.google', category: 'Network activity' } }],
                     edges: [{ id: 'e1', from: 'obj:O1', to: 'enr:domain:dns.google',
                               data: { kind: 'enrichment', module: 'whois', asked: '8.8.4.4' } }] };
    const out = await pivot(g, 'enrich').save(savePayload(result, [origin]), saveCtx(g));
    const a = seen[0].Attribute[0];
    eq('a loose attribute', [a.type, a.value, a.comment, 'object_relation' in a],
       ['domain', 'dns.google', 'Enrichment: whois on 8.8.4.4', false]);
    eq('referenced by the origin object', seen[0].ObjectReference,
       [{ object_uuid: 'O1', referenced_uuid: a.uuid, relationship_type: 'related-to' }]);
    eq('under its MISP id', out.canonicalIds['enr:domain:dns.google'], 'attr:' + a.uuid);
});

test('enrich save: the relationship is asked, related-to offered first', async () => {
    const seen = [];
    const g = await saveGraph(seen);
    const p = pivot(g, 'enrich');
    const origin = OWN_IP();
    const ctx = saveCtx(g, { relationship_type: 'resolves-to' });
    await p.save(savePayload(await p.fetch([origin], { module: ['ipasn'] }, { graph: g.graph }), [origin]), ctx);
    eq('one prompt', ctx.prompts.length, 1);
    const select = ctx.prompts[0].fields.find(f => f.key === 'relationship_type');
    eq('the vocabulary, sorted, related-to picked', [select.options.map(o => o.value), select.defaultValue],
       [['characterizes', 'related-to', 'resolves-to'], 'related-to']);
    eq('the answer is written', seen[0].Object[0].ObjectReference.map(r => r.relationship_type), ['resolves-to']);
});

test('enrich save: a custom relationship wins over the list', async () => {
    const seen = [];
    const g = await saveGraph(seen);
    const p = pivot(g, 'enrich');
    const origin = OWN_IP();
    await p.save(savePayload(await p.fetch([origin], { module: ['ipasn'] }, { graph: g.graph }), [origin]),
                 saveCtx(g, { custom: '  announced-by ' }));
    eq('trimmed and written', seen[0].Object[0].ObjectReference[0].relationship_type, 'announced-by');
});

test('enrich save: cancelling the prompt writes nothing and says so to the library', async () => {
    const seen = [];
    const g = await saveGraph(seen);
    const p = pivot(g, 'enrich');
    const origin = OWN_IP();
    const payload = savePayload(await p.fetch([origin], { module: ['ipasn'] }, { graph: g.graph }), [origin]);
    eq('a cancel', await p.save(payload, saveCtx(g, null)), { cancelled: true });
    eq('nothing posted', seen.length, 0);
    eq('still a result', payload.nodes[0].data.scope, 'module');
});

test('enrich save: nothing is asked when no reference would be written', async () => {
    const seen = [];
    const g = await saveGraph(seen);
    const p = pivot(g, 'enrich');
    const origin = enrNode('attr:F1', { type: 'attribute', uuid: 'F1', value: '8.8.8.8', 'attr-type': 'ip-dst',
                                        scope: 'foreign', event_id: '7' });
    const ctx = saveCtx(g);
    await p.save(savePayload(await p.fetch([origin], { module: ['ipasn'] }, { graph: g.graph }), [origin]), ctx);
    eq('no prompt', ctx.prompts.length, 0);
    eq('saved all the same', seen.length, 1);
});

test('enrich save: offered from the node menu and the selection menu', async () => {
    const g = await buildGraph(ev({}));
    eq('never from the pivot panel or a triage pane', g.opts.pivotSaveControls, false);
    const one = menuItem(g, 'Save this element');
    const many = g.opts.UI.contextMenu.menuSelection.menu.find(i => i.text === 'Save selection');
    eq('the selection menu holds that and the graph add', g.opts.UI.contextMenu.menuSelection.menu.map(i => [i.text, i.iconClass]),
       [['Save selection', 'fas fa-save'], ['Add selection to active graph', 'fas fa-circle-nodes']]);
    const n = id => ({ id, getData: () => ({ type: 'object', scope: 'module' }) });
    const ledger = g.graph.pivots;
    ['r1', 'r2', 'r3'].forEach(id => ledger.savable.add(id));
    ledger.saved.add('r3');
    eq('an unsaved result offers it', one.visible(n('r1')), true);
    eq('a saved one, or one no save covers, does not', [one.visible(n('r3')), one.visible(n('x'))], [false, false]);
    eq('a selection with something to write offers it', [many.visible([n('r1'), n('x')]), many.visible([n('r3'), n('x')])],
       [true, false]);
    many.onclick({}, [n('r1'), n('r2'), n('r3'), n('x')]);
    eq('only what waits is named, and the analyst is asked',
       [ledger.saves[0][0].elements.map(e => e.id), ledger.saves[0][1]], [['r1', 'r2'], { interactive: true }]);
    one.onclick({}, n('r2'));
    eq('the element alone', ledger.saves[1][0].elements.map(e => e.id), ['r2']);
});

test('enrich save: a duplicate aliases to what the event holds, a failure stays unsaved', async () => {
    const seen = [];
    const g = await saveGraph(seen, rec => rec.value === 'dup.example' ? { state: 'existing', uuid: 'HELD' }
                                         : rec.value === 'bad' ? { state: 'failed' } : null);
    const origin = OWN_IP();
    const loose = (value, id) => ({ id, data: { type: 'attribute', scope: 'module', module: 'm', 'attr-type': 'domain', value } });
    const result = { nodes: [loose('dup.example', 'enr:domain:dup.example'), loose('bad', 'enr:domain:bad')],
                     edges: [{ id: 'e1', from: 'attr:A1', to: 'enr:domain:dup.example', data: { kind: 'enrichment', module: 'm' } },
                             { id: 'e2', from: 'attr:A1', to: 'enr:domain:bad', data: { kind: 'enrichment', module: 'm' } }] };
    const payload = savePayload(result, [origin]);
    const out = await pivot(g, 'enrich').save(payload, saveCtx(g));
    eq('only the duplicate is saved', out.savedNodeIds, ['enr:domain:dup.example']);
    eq('as the attribute already there', out.canonicalIds, { 'enr:domain:dup.example': 'attr:HELD' });
    eq('the failed one\'s edge stays unsaved', out.savedEdgeIds, ['e1']);
    ok('and the toast says so', /could not be saved/.test(out.message || ''), out.message);
    eq('the failed one is still a result', payload.nodes[1].data.scope, 'module');
});

test('links: the canvas draws the links MISP holds between its records, once each', async () => {
    const asked = [];
    const g = await buildGraph(ev({ Object: [
        fedObj({ uuid: 'A', ObjectReference: [ref({ uuid: 'R1', referenced_uuid: 'B' })] }),
        fedObj({ uuid: 'B' }),
    ] }), { routes: [[/\/analyst_graphs\/edges\.json$/, init => {
        asked.push(JSON.parse(init.body));
        return { Value: [], edges: [
            { id: 'object-reference:R1', kind: 'object-reference', from: 'Object:a', to: 'Object:b', label: 'related-to', uuid: 'R1' },
            { id: 'relationship:REL1', kind: 'relationship', from: 'Object:b', to: 'Object:a', label: 'seen-with',
              uuid: 'REL1', authors: 'a@b', orgc_uuid: 'org-c' },
            { id: 'contains:a-hit', kind: 'contains', from: 'Object:a', to: 'Attribute:a-hit' },
            { id: 'in-event:x', kind: 'in-event', from: 'Object:a', to: 'Event:not-drawn' },
        ] };
    }]] });
    await new Promise(r => setTimeout(r, 400));
    eq('asked once, after the seed', asked.length, 1);
    ok('naming every record on the canvas',
       ['Object:A', 'Object:B'].every(k => asked[0].nodes.some(n => n.type + ':' + n.uuid === k)), JSON.stringify(asked[0]));
    eq('only the relationship was missing', g.graph.addedEdges.map(e => [e.id, e.from, e.to, e.data.kind, e.data.uuid]),
       [['relationship:REL1', 'obj:B', 'obj:A', 'analyst-relationship', 'REL1']]);
    eq('nothing failed', g.errors, []);
});

/* ───────────────────────────── runner ─────────────────────────── */

(async () => {
    for (const t of TESTS) {
        console.log('\n' + t.name);
        try {
            await t.fn();
        } catch (e) {
            failed++;
            failures.push(t.name + ' (threw)');
            console.log('  THREW ' + (e && e.stack || e));
        }
    }
    console.log('\n' + '─'.repeat(66));
    console.log((failed ? 'FAILED' : 'OK') + ' — ' + passed + ' passed, ' + failed + ' failed');
    if (failed) { console.log('\nFailing:\n  ' + failures.join('\n  ')); }
    process.exit(failed ? 1 : 0);
})();
