// Unit tests for the Pivot Explorer sidebar view-models.
//
//   node tests/js/pivot-sidebar-model.test.js
//
// Zero dependencies, like pivot-explorer-graph.test.js. The context-priority
// port is also checked against ValueLabelPriority.php itself when a PHP with
// mbstring is at hand:
//
//   PHP_BIN='docker exec -i misp-docker-25-misp-core-1 php' \
//   MISP_APP=/var/www/MISP/app node tests/js/pivot-sidebar-model.test.js
//
// Without one the parity suite says it was skipped rather than passing.

'use strict';

const path = require('path');
const { spawnSync } = require('child_process');

const M = require(path.join(__dirname, '..', '..', 'app', 'webroot', 'js', 'pivot-sidebar-model.js'));
const P = M.priority;

const suites = [];
function suite(name, fn) { suites.push({ name, fn }); }

let passed = 0, failed = 0;
const failing = [];

function eq(label, actual, expected) {
    const a = JSON.stringify(actual), e = JSON.stringify(expected);
    if (a === e) { passed++; return; }
    failed++;
    failing.push(label);
    console.log('  FAIL  ' + label + '\n          expected ' + e + '\n          actual   ' + a);
}

/* ── context priority ──────────────────────────────────────── */

const IR = { parameters: { context: {
    taxonomies: { pinned: ['tlp', 'PAP', 'admiralty-scale'], preferred: ['circl'], demoted: ['workflow'] },
    galaxies: { preferred: ['threat-actor', 'mitre-intrusion-set'] }
} } };

const TAX_GROUPS = [
    { key: 'workflow', tags: [{ name: 'workflow:state="draft"' }] },
    { key: 'misp', tags: [{ name: 'misp:tool="x"' }] },
    { key: 'tlp', tags: [{ name: 'tlp:green' }, { name: 'tlp:red' }, { name: 'tlp:amber' }] },
    { key: 'circl', tags: [{ name: 'circl:incident-classification="malware"' }] },
    { key: 'osint', tags: [{ name: 'osint:source-type="blog-post"' }] },
];

suite('a plan is a profile normalised: lower-cased, deduplicated, first tier wins', () => {
    const plan = P.planFor({ context: { taxonomies: { pinned: [' TLP ', 'tlp', 7, null, ''], demoted: ['tlp', 'x'] } } });
    eq('pinned', plan.taxonomies.pinned, ['tlp', '7']);
    eq('demoted keeps only what pinned did not take', plan.taxonomies.demoted, ['x']);
    eq('galaxies filled in', plan.galaxies, { pinned: [], preferred: [], demoted: [] });
    eq('a plan passes through', P.planFor(plan), plan);
});

suite('a profile declaring nothing leaves the groups exactly as they came', () => {
    eq('same order, no priority key', P.order(TAX_GROUPS, P.planFor(null), 'taxonomies'), TAX_GROUPS);
    eq('a dimension the profile leaves out', P.order([{ key: 'b' }, { key: 'a' }],
       { context: { taxonomies: { pinned: ['tlp'] } } }, 'galaxies'),
       [{ key: 'b' }, { key: 'a' }]);
});

suite('groups: pinned, preferred, unlisted in arrival order, demoted', () => {
    const out = P.order(TAX_GROUPS, IR, 'taxonomies');
    eq('order', out.map(g => g.key), ['tlp', 'circl', 'misp', 'osint', 'workflow']);
    eq('priority', out.map(g => g.priority), ['pinned', 'preferred', null, null, 'demoted']);
    eq('a pinned handling group leads with its most restrictive label', out[0].lead,
       { tag: { name: 'tlp:red' }, others: 2 });
    eq('no lead elsewhere', out.slice(1).some(g => 'lead' in g), false);
});

suite('labels: listed handling namespaces put the most restrictive first', () => {
    const list = [{ key: 'tlp', name: 'tlp:clear' }, { key: 'misp', name: 'misp:x' },
                  { key: 'tlp', name: 'tlp:red' }, { key: 'tlp', name: 'tlp:amber' }];
    eq('ranked', P.labels(list, IR, 'taxonomies').map(l => l.name),
       ['tlp:red', 'tlp:amber', 'tlp:clear', 'misp:x']);
    const unlisted = P.labels(list, { context: { taxonomies: { preferred: ['misp'] } } }, 'taxonomies');
    eq('an unlisted tlp keeps arrival order', unlisted.map(l => l.name),
       ['misp:x', 'tlp:clear', 'tlp:red', 'tlp:amber']);
});

suite('absent: pinned keys the groups lack, under the instance floor', () => {
    eq('missing pins', P.absent(TAX_GROUPS, IR, 'taxonomies'), [{ key: 'pap' }, { key: 'admiralty-scale' }]);
    eq('floored', P.absent(TAX_GROUPS, IR, 'taxonomies', ['TLP', 'pap']), [{ key: 'pap' }]);
});

suite('namespaceOf', () => {
    eq('namespaces', ['tlp:red', 'misp-galaxy:x="y"', 'plain', ':x', 'A:b'].map(P.namespaceOf),
       ['tlp', 'misp-galaxy', null, null, 'a']);
});

// The same inputs through the PHP class. Every case is data, so the two
// implementations are compared on one set of answers.
suite('parity with ValueLabelPriority.php', () => {
    const bin = process.env.PHP_BIN;
    if (!bin) { console.log('  SKIPPED  set PHP_BIN (and MISP_APP) to compare with PHP'); return; }
    const app = process.env.MISP_APP || path.join(__dirname, '..', '..', 'app');
    const cases = [
        ['order', TAX_GROUPS, IR, 'taxonomies'],
        ['order', TAX_GROUPS, null, 'taxonomies'],
        ['order', [{ key: 'threat-actor' }, { key: 'tool' }, { key: 'mitre-intrusion-set' }], IR, 'galaxies'],
        ['labels', [{ key: 'tlp', name: 'tlp:clear' }, { key: 'pap', name: 'PAP:RED' }, { key: 'tlp', name: 'tlp:amber+strict' },
                    { key: 'x' }, { key: 'pap', name: 'pap:green' }], IR, 'taxonomies'],
        ['absent', TAX_GROUPS, IR, 'taxonomies', null],
        ['absent', TAX_GROUPS, IR, 'taxonomies', ['pap']],
        ['planFor', { context: { taxonomies: { pinned: [' TLP ', 'tlp', 7], demoted: ['tlp', 'x'] } } }],
    ];
    const php = `
require '${app}/Lib/Tools/ValueIntelligence/ValueLabelPriority.php';
$out = [];
foreach (json_decode(stream_get_contents(STDIN), true) as $c) {
    $fn = array_shift($c);
    $out[] = call_user_func_array(['ValueLabelPriority', $fn], $c);
}
echo json_encode($out);`;
    const argv = bin.split(/\s+/);
    const run = spawnSync(argv[0], argv.slice(1).concat(['-r', php]), { input: JSON.stringify(cases) });
    if (run.status !== 0) throw new Error('php failed: ' + run.stderr);
    const res = JSON.parse(run.stdout.toString());
    cases.forEach((c, i) => {
        const [fn, ...args] = c;
        eq('parity: ' + fn + ' #' + i, P[fn].apply(null, args), res[i]);
    });
});

/* ── view-models ───────────────────────────────────────────── */

// A small payload in /events/view.json's shape.
function payload() {
    const hit = { uuid: 'a-ip', id: '11', type: 'ip-dst', category: 'Network activity', value: '8.8.8.8',
        to_ids: true, comment: 'resolver', distribution: '5', timestamp: '1700000000',
        first_seen: '2024-01-01T00:00:00.000000+00:00', last_seen: null,
        Tag: [{ name: 'osint:source-type="blog-post"', colour: '#00f' }, { name: 'tlp:clear' }, { name: 'tlp:red' },
              { name: 'misp-galaxy:threat-actor="APT28"', is_galaxy: true }, { name: 'hidden', hide_tag: true }],
        Galaxy: [{ type: 'threat-actor', name: 'Threat Actor', GalaxyCluster: [{
            uuid: 'c-apt28', id: '7', value: 'APT28', tag_name: 'misp-galaxy:threat-actor="APT28"', type: 'threat-actor',
            description: 'Russian actor', meta: { synonyms: ['Fancy Bear', 'Sofacy'], country: ['RU'] },
            GalaxyClusterRelation: [{}, {}], TargetingClusterRelation: [{}] }] }],
        warnings: [{ warninglist_id: 3, warninglist_name: 'Public DNS', warninglist_category: 'false_positive', match: '8.8.8.8' },
                   { warninglist_id: 3, warninglist_name: 'Public DNS' }],
        Sighting: [{ type: '0', date_sighting: '100', Organisation: { name: 'A' } },
                   { type: '0', date_sighting: '300', Organisation: { name: 'B' } },
                   { type: '1', date_sighting: '200', Organisation: { name: 'A' } }],
        Feed: [{ id: '1', name: 'CIRCL OSINT', provider: 'CIRCL', source_format: 'misp', event_uuids: ['e1', 'e2'] }],
        Opinion: [{ uuid: 'op1', opinion: '80', comment: 'agree', Note: [{ uuid: 'n2', note: 'why' }] }],
        Relationship: [{ uuid: 'r1' }] };
    const port = { uuid: 'a-port', type: 'port', object_relation: 'dst-port', value: '53',
                   Tag: [{ name: 'tlp:clear' }], warnings: [{ warninglist_id: 9, warninglist_name: 'Ports' }] };
    const ip = { uuid: 'a-obj-ip', type: 'ip-dst', object_relation: 'ip', value: '8.8.4.4', Tag: [{ name: 'tlp:clear' }] };
    return { Event: {
        id: '5', uuid: 'e-self', info: 'Resolvers', date: '2024-02-02', threat_level_id: '1', analysis: '2',
        distribution: '3', published: true, publish_timestamp: '1700000500', attribute_count: '3', timestamp: '1700000600',
        extends_uuid: 'e-parent', Orgc: { name: 'CIRCL' },
        Tag: [{ name: 'tlp:amber' }], RelatedEvent: [{}, {}],
        EventReport: [{ uuid: 'rep1', name: 'Write-up', timestamp: '1' }, { uuid: 'rep2', name: 'gone', deleted: true }],
        Attribute: [hit, { uuid: 'a-dead', value: 'x', deleted: '1' }],
        Object: [
            { uuid: 'o-sock', name: 'network-socket', 'meta-category': 'network', template_uuid: 't1', template_version: '2',
              distribution: '5', Attribute: [port, ip],
              ObjectReference: [{ uuid: 'ref1', referenced_uuid: 'a-ip', referenced_type: '0', relationship_type: 'connects-to' },
                                { uuid: 'ref2', referenced_uuid: 'o-file', referenced_type: '1', relationship_type: 'drops', deleted: true }] },
            { uuid: 'o-file', name: 'file', Attribute: [], ObjectReference: [
                { uuid: 'ref3', referenced_uuid: 'o-sock', referenced_type: '1', relationship_type: 'related-to', comment: 'same host' }] }
        ] } };
}

function env(extra) {
    return Object.assign({ event: payload(), eventId: '5', plan: P.planFor(IR),
                           permitted: { taxonomies: ['tlp', 'pap', 'osint'], galaxies: ['threat-actor'] },
                           uiPriorities: { 't1.2': { ip: 2, 'dst-port': 1 } },
                           correlations: (type, uuid) => ({ 'a-ip': 4, 'o-sock': 2 })[uuid] ?? 0, lazy: {} }, extra || {});
}

const node = data => ({ kind: 'node', id: data.type + ':' + data.uuid, data });

suite("this event's attribute: everything the payload knows, in the plan's order", () => {
    const vm = M.build(node({ type: 'attribute', uuid: 'a-ip', label: '8.8.8.8', scope: 'self', event_id: '5' }), env());
    eq('card', vm.card, { value: '8.8.8.8', type: 'ip-dst', category: 'Network activity', relation: null, to_ids: true,
        marks: { warninglisted: true, tagged: 4, analyst: true, feed: true } });
    eq('taxonomy groups, pinned first', vm.labels.taxonomies.map(g => [g.key, g.priority]),
       [['tlp', 'pinned'], ['osint', null]]);
    eq('tlp leads with its most restrictive', vm.labels.taxonomies[0].lead.tag.name, 'tlp:red');
    eq('a hidden tag stays hidden', JSON.stringify(vm.labels).includes('hidden'), false);
    eq('the cluster, in full, from the payload', vm.labels.galaxies[0].clusters[0].detail.synonyms, ['Fancy Bear', 'Sofacy']);
    eq('relations counted both ways', vm.labels.galaxies[0].clusters[0].detail.relations, 3);
    eq('missing pins, under the instance floor', vm.labels.missing.taxonomies, [{ key: 'pap' }]);
    eq('one warninglist per id', vm.warninglists.map(w => [w.name, w.false_positive]), [['Public DNS', true]]);
    eq('sightings folded', vm.sightings, { total: 3, sighting: 2, false_positive: 1, expiration: 0, first: 100, last: 300,
        orgs: [{ name: 'A', count: 2 }, { name: 'B', count: 1 }] });
    eq('feeds named', vm.sources, [{ type: 'feed', id: '1', name: 'CIRCL OSINT', provider: 'CIRCL', format: 'misp', events: 2 }]);
    eq('analyst: an opinion and the note on it', [vm.analyst.opinions, vm.analyst.notes, vm.analyst.relationships, vm.analyst.mood],
       [1, 1, 1, 'endorsed']);
    eq('the note sits under the opinion', vm.analyst.items.map(i => [i.kind, i.depth]), [['opinion', 0], ['note', 1]]);
    eq('facts', vm.facts.map(f => f.key), ['comment', 'first_seen', 'distribution', 'timestamp', 'uuid']);
    eq('distribution named', vm.facts.find(f => f.key === 'distribution').value, 'Inherit event');
    eq('correlations', vm.correlations, { count: 4 });
    eq('what reads it still needs', Object.keys(vm.lazy), ['taxonomies', 'warninglists']);
    eq('taxonomy text is asked for, namespaced tags only', vm.lazy.taxonomies.request,
       { method: 'POST', url: '/tags/search/0/1.json', body: { tag: ['tlp:clear', 'tlp:red', 'osint:source-type="blog-post"'] } });
    eq('warninglist text too', vm.lazy.warninglists.request.url, '/warninglists/index/id:3.json');
    eq('no link to the page it is on', vm.links, []);
});

suite('a lazy read: pending, then ready with its answer, or failed', () => {
    const input = node({ type: 'attribute', uuid: 'a-ip', scope: 'self' });
    eq('pending', M.build(input, env()).lazy.warninglists.state, 'pending');
    const rows = [{ Tag: { name: 'tlp:red' }, Taxonomy: { namespace: 'tlp', description: 'Traffic Light Protocol' },
                    TaxonomyPredicate: { value: 'red', expanded: '(TLP:RED) Not for disclosure', numerical_value: '0' } },
                  { Tag: { name: 'osint:source-type="blog-post"' } }];
    const vm = M.build(input, env({ lazy: { taxonomies: rows, warninglists: false } }));
    eq('ready', vm.lazy.taxonomies.state, 'ready');
    const tlp = vm.labels.taxonomies[0];
    eq('the group takes its taxonomy description', tlp.description, 'Traffic Light Protocol');
    eq('the tag its meaning', tlp.tags.find(t => t.name === 'tlp:red').meaning,
       { taxonomy: { namespace: 'tlp', description: 'Traffic Light Protocol', exclusive: false },
         predicate: { value: 'red', expanded: '(TLP:RED) Not for disclosure', description: null }, value: null, numerical_value: 0 });
    eq('no taxonomy installed: no meaning', vm.labels.taxonomies[1].tags[0].meaning, null);
    eq('failed', vm.lazy.warninglists.state, 'failed');
});

suite("another event's attribute arrives slim and asks for its record", () => {
    const d = { type: 'attribute', uuid: 'far', label: '1.1.1.1', value: '1.1.1.1', 'attr-type': 'ip-dst', scope: 'foreign',
                event_id: '16', tags: [{ name: 'tlp:clear' }] };
    const before = M.build(node(d), env({ correlations: () => null }));
    eq('drawn from node data', [before.card.value, before.labels.taxonomies[0].key], ['1.1.1.1', 'tlp']);
    eq('count not known yet', before.correlations, null);
    eq('the record read', before.lazy.record.request,
       { method: 'POST', url: '/attributes/restSearch',
         body: { returnFormat: 'json', uuid: 'far', includeSightings: 1, includeWarninglistHits: 1, includeEventTags: 0 } });
    eq('its event linked', before.links, [{ kind: 'event', label: 'Open its event', path: '/events/view/16' }]);
    const after = M.build(node(d), env({ lazy: { record: { response: { Attribute: [{
        uuid: 'far', value: '1.1.1.1', type: 'ip-dst', event_id: '16', Tag: [{ name: 'pap:green' }],
        Sighting: [{ Sighting: { type: '0', date_sighting: '9' }, Organisation: { name: 'X' } }] }] } } } }));
    eq('the record replaces the node data', after.labels.taxonomies.map(g => g.key), ['pap']);
    eq('with its sightings', after.sightings.total, 1);
});

suite('an object: attributes ranked by the template, what they carry rolled up', () => {
    const vm = M.build(node({ type: 'object', uuid: 'o-sock', name: 'network-socket', scope: 'self', event_id: '5' }), env());
    eq('ranked', vm.children.map(c => [c.relation, c.priority]), [['ip', 2], ['dst-port', 1]]);
    eq('card', vm.card.top.map(c => [c.relation, c.value]), [['ip', '8.8.4.4'], ['dst-port', '53']]);
    eq('with what marks a row', vm.card.top.map(c => [c.warninglisted, c.warninglists, c.false_positive]),
       [[false, [], false], [true, ['Ports'], false]]);
    eq('a tag on both attributes counts 2', vm.labels.taxonomies[0].tags.map(t => [t.name, t.count]), [['tlp:clear', 2]]);
    eq('warninglists rolled up', vm.warninglists.map(w => [w.name, w.count]), [['Ports', 1]]);
    eq('references out, deleted ones dropped', vm.relations.references.out.map(r => [r.relationship_type, r.target.label]),
       [['connects-to', 'ip-dst: 8.8.8.8']]);
    eq('references in, inverted from the payload', vm.relations.references.in.map(r => [r.relationship_type, r.source.label, r.comment]),
       [['related-to', 'file', 'same host']]);
    eq('correlations', vm.correlations, { count: 2 });
});

suite('this event: the card, then its context', () => {
    const vm = M.build(node({ type: 'event', uuid: 'e-self', label: 'Resolvers', scope: 'self', event_id: '5' }), env());
    eq('card', vm.card, { info: 'Resolvers', org: 'CIRCL', date: '2024-02-02', threat_level: 'High', analysis: 'Completed',
        distribution: 'All communities', sharing_group: null, published: true, published_at: 1700000500, attributes: 3,
        objects: 2, reports: 1 });
    eq('reports, deleted ones dropped', vm.relations.reports, [{ uuid: 'rep1', name: 'Write-up', timestamp: 1 }]);
    eq('extends', vm.relations.extends, { uuid: 'e-parent' });
    eq('who extends it is asked', vm.lazy.extended_by.request.body, { returnFormat: 'json', eventsExtendingUuid: 'e-self', metadata: 1 });
    eq('no record read for this event', 'record' in vm.lazy, false);
});

suite('tags, clusters, feeds and edges', () => {
    const tag = M.build(node({ type: 'tag', name: 'tlp:amber', label: 'tlp:amber' }), env());
    eq('a tag knows its tier', [tag.card.namespace, tag.card.predicate, tag.priority], ['tlp', 'amber', 'pinned']);
    const plain = M.build(node({ type: 'tag', name: 'Phishing' }), env());
    eq('a plain tag asks nothing', [plain.card.namespace, Object.keys(plain.lazy)], [null, []]);
    const known = M.build(node({ type: 'cluster', value: 'APT28', galaxy_type: 'threat-actor',
                                 tag_name: 'misp-galaxy:threat-actor="APT28"' }), env());
    eq('a cluster the payload holds, found by its tag', [known.detail.description, Object.keys(known.lazy)], ['Russian actor', []]);
    eq('linked', known.links[0].path, '/galaxy_clusters/view/7');
    const bare = M.build(node({ type: 'cluster', value: 'X', galaxy_type: 'g', tag_name: 'misp-galaxy:g="X"' }), env());
    eq('an unknown one is looked up by tag', bare.lazy.cluster_tag.request.body, { tag: ['misp-galaxy:g="X"'] });
    const found = M.build(node({ type: 'cluster', value: 'X', galaxy_type: 'g', tag_name: 'misp-galaxy:g="X"' }),
        env({ lazy: { cluster_tag: [{ Tag: {}, GalaxyCluster: { uuid: 'c-x' } }] } }));
    eq('then read in full', found.lazy.cluster.request.url, '/galaxy_clusters/view/c-x.json');
    const feed = M.build(node({ type: 'feed', label: 'CIRCL OSINT', source_id: '1', feed_events: 2 }), env());
    eq('a feed counts what it holds here', [feed.card.attributes_here, feed.links[0].path], [1, '/feeds/previewIndex/1']);
    const ref = M.build({ kind: 'edge', id: 'e1', data: { kind: 'object-reference', uuid: 'ref3', relationship_type: 'related-to' },
                          from: { id: 'obj:o-file', data: { type: 'object', label: 'file' } }, to: { id: 'obj:o-sock', data: { type: 'object' } } }, env());
    eq('an authored edge', [ref.card.authored, ref.card.derived, ref.facts[0]], [true, false,
       { key: 'comment', label: 'Comment', value: 'same host', kind: 'text' }]);
    const corr = M.build({ kind: 'edge', data: { kind: 'correlation' } }, env());
    eq('a derived one', [corr.card.authored, corr.card.derived, corr.title], [false, true, 'Correlation']);
});

suite('a multi-selection: what the nodes share, and one property row per value', () => {
    const items = [
        node({ type: 'event', uuid: 'x1', org: 'CIRCL', tags: [{ name: 'tlp:clear' }, { name: 'osint:a' }] }),
        node({ type: 'event', uuid: 'x2', org: 'CIRCL', tags: [{ name: 'osint:a' }, { name: 'tlp:red' }] }),
        node({ type: 'attribute', uuid: 'x3', tags: [{ name: 'osint:a' }] }),
    ];
    const vm = M.build({ kind: 'nodes', items }, env());
    eq('kinds', vm.card.kinds, [{ count: 2, entity: 'event' }, { count: 1, entity: 'attribute' }]);
    eq('shared tags: pinned first, most restrictive first', vm.shared.taxonomies.map(t => [t.name, t.count]),
       [['tlp:red', 1], ['tlp:clear', 1], ['osint:a', 3]]);
    eq('orgs', vm.shared.orgs, [{ count: 2, name: 'CIRCL' }]);
    eq('rows repeat the name, one per value', M.propertyRows(items[0], env()).filter(r => r.name === 'Tag').map(r => r.value),
       ['tlp:clear', 'osint:a']);
    eq('a tag node counts as its tag', M.propertyRows(node({ type: 'tag', name: 'tlp:amber' }), env()),
       [{ name: 'Element', value: 'tag' }, { name: 'Tag', value: 'tlp:amber' }]);
    eq('a cluster node as its cluster', M.propertyRows(node({ type: 'cluster', value: 'APT28', galaxy_type: 'threat-actor' }), env()),
       [{ name: 'Element', value: 'cluster' }, { name: 'Galaxy cluster', value: 'threat-actor: APT28' }]);
});

suite('an attribute another event\'s card brought says which of its slices matched', () => {
    const e = Object.assign(env(), { matchedLabels: { ids: 'IDS indicators' } });
    const vm = M.build(node({ type: 'attribute', uuid: 'far', scope: 'foreign', event_id: '7', matched: ['ids', 'x'] }), e);
    eq('named by the explorer, an unknown key as itself', vm.facts.filter(f => f.key === 'matched').map(f => f.value),
       ['IDS indicators, x']);
    eq('nothing when nothing matched', M.build(node({ type: 'attribute', uuid: 'far2', scope: 'foreign' }), e)
       .facts.filter(f => f.key === 'matched'), []);
});

suite('a value in the sidebar: keyed as ValueUrlTool::address(), opening its card where the instance has it on', () => {
    eq('url-safe alphabet, bytes not characters', ['\u00ff>?/', '\u00e9vil.example', 'http://x.y/?q=~~'].map(M.valueKey),
       ['w78-Py8=', 'w6l2aWwuZXhhbXBsZQ==', 'aHR0cDovL3gueS8_cT1-fg==']);
    const sha = v => 'sha256:' + require('crypto').createHash('sha256').update(v, 'utf8').digest('hex');
    eq('base64 that reads as an id goes by its sha256', M.valueKey('\u3374'), sha('\u3374'));
    eq('base64 up to 7800 characters', M.valueKey('x'.repeat(5850)).length, 7800);
    eq('then its sha256', M.valueKey('x'.repeat(5851)), sha('x'.repeat(5851)));
    const attr = node({ type: 'attribute', uuid: 'a-ip', scope: 'self', event_id: '5' });
    eq('an attribute: its own value', M.build(attr, env()).profile, { value: '8.8.8.8', b64: 'OC44LjguOA==' });
    eq('an attribute with no value: none', M.build(node({ type: 'attribute', uuid: 'nope' }), env()).profile, null);
    const sock = node({ type: 'object', uuid: 'o-sock', name: 'network-socket', scope: 'self', event_id: '5' });
    eq('each object attribute keyed', M.build(sock, env()).children.map(c => c.b64), ['OC44LjQuNA==', 'NTM=']);
    eq('the card follows the instance', [M.build(attr, env()).value_card, M.build(attr, env({ valueCard: true })).value_card,
        M.build(sock, env({ valueCard: true })).value_card], [false, true, true]);
});

suite('an enrichment result: said by a module, linked only where MISP holds it', () => {
    const res = { kind: 'node', id: 'enr-obj:ipasn:abc', data: { type: 'object', name: 'asn', scope: 'module',
        module: 'ipasn', modules: ['ipasn', 'mmdb_lookup'], from_store: true, age: 7200 },
        children: [{ type: 'AS', value: '15169', object_relation: 'asn', scope: 'module', known: false },
                   { type: 'ip-src', value: '8.8.8.0/24', object_relation: 'subnet-announced', scope: 'module', known: true }] };
    const vm = M.build(res, env());
    eq('its provenance', vm.provenance, { scope: 'module', event_id: null, label: 'From enrichment' });
    eq('what the modules said', vm.enrichment,
       { modules: ['ipasn', 'mmdb_lookup'], from_store: true, age: 7200, kept_by: null, untyped: false, candidate_types: [] });
    const kept = M.build(node({ type: 'attribute', uuid: undefined, value: '203.0.113.7', 'attr-type': 'ip-dst',
                                scope: 'module', module: 'dns', kept_by: 'CIRCL',
                                ran_at: Math.floor(Date.now() / 1000) - 3600 }), env()).enrichment;
    eq('a kept answer says who kept it and when it was asked', [kept.kept_by, kept.age >= 3600 && kept.age < 3700],
       ['CIRCL', true]);
    eq('only the known value is keyed', vm.children.filter(c => c.b64).map(c => c.value), ['8.8.8.0/24']);
    const loose = node({ type: 'attribute', uuid: undefined, value: 'dns.google', 'attr-type': 'domain',
                         scope: 'module', module: 'whois', untyped: true, candidate_types: ['hostname'] });
    eq('an unknown loose result has no profile', M.build(loose, env()).profile, null);
    eq('untyped, with its other types', [M.build(loose, env()).enrichment.untyped, M.build(loose, env()).enrichment.candidate_types],
       [true, ['hostname']]);
    eq('a MISP element has none', M.build(node({ type: 'attribute', uuid: 'a-ip', scope: 'self' }), env()).enrichment, null);
});

/* ── runner ────────────────────────────────────────────────── */

(async () => {
    for (const s of suites) {
        console.log(s.name);
        try { await s.fn(); }
        catch (e) { failed++; failing.push(s.name + ' (threw)'); console.log('  THREW ' + (e.stack || e)); }
        console.log('');
    }
    console.log('─'.repeat(66));
    console.log((failed ? 'FAILED' : 'OK') + ' — ' + passed + ' passed, ' + failed + ' failed');
    if (failed) { console.log('\nFailing:\n' + failing.map(f => '  ' + f).join('\n')); process.exit(1); }
})();
