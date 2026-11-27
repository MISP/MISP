import { test, describe, after } from 'node:test';
import assert from 'node:assert/strict';
import { createClient, failureMessage } from '../../webroot/js/mispql/client.mjs';
import { snippets } from '../../webroot/js/mispql/snippets.mjs';
import { cellLink, openSpec, columnField, filterEntries, tagEntries, sortNameOf, nextOrder, levelNames, tagLane, tagParts, asRan } from '../../webroot/js/mispql/results.mjs';

const f = (type, level, operators) => ({ type: type, level: [level], operators: operators });
const EQ = ['=', '!=', 'IN', 'NOT IN', 'LIKE', 'NOT LIKE'];
const CMP = ['=', '!=', '<', '>', '<=', '>=', 'IN', 'NOT IN'];
const PACK = {
    pages: {
        Attribute: '/attributes/view/%s', Event: '/events/view/%s', Object: '/objects/view/%s',
        Note: '/analystData/view/Note/%s', Value: '/values/view/%s',
    },
    tables: {
        attributes: {
            fields: {
                id: f('int', 'attribute', CMP), type: f('string', 'attribute', EQ), value: f('string', 'attribute', EQ),
                timestamp: f('timestamp', 'attribute', CMP), to_ids: f('bool', 'attribute', ['=', '!=']),
                eventinfo: f('string', 'event', EQ), org: f('string', 'event', EQ),
                tags: { type: 'string', level: ['attribute', 'event'], operators: EQ },
            },
            aliases: { eventinfo: 'Event.info', org: 'Event.Orgc.name', tags: 'Tag' },
            links: { id: 'Attribute', value: 'Value', event_id: 'Event', object_id: 'Object', 'Event.Orgc.id': 'Organisation' },
        },
        objects: {
            fields: { id: f('int', 'object', CMP), comment: f('string', 'attribute', EQ), event_id: f('int', 'event', CMP) },
            aliases: { object_name: 'name' },
            links: { id: 'Object' },
        },
        notes: {
            fields: { id: f('int', 'note', CMP), created: f('datetime', 'note', CMP) },
            aliases: {},
            links: {
                id: 'Note', object_uuid: { type_from: 'object_type' },
                object_sha256: { type: 'Value', by: 'sha256' },
            },
        },
    },
};
const ctx = (table) => ({ pack: PACK, tableName: table, baseurl: '/misp', address: (v) => 'b64:' + v });

describe('Cells', () => {
    test('a column reads the field of its name, or the alias printed as it', () => {
        const t = PACK.tables.attributes;
        assert.equal(columnField(t, 'attributes', 'type'), 'type');
        assert.equal(columnField(t, 'attributes', 'TYPE'), 'type');
        assert.equal(columnField(t, 'attributes', 'Event.info'), 'eventinfo');
        assert.equal(columnField(t, 'attributes', 'Event.Orgc.name'), 'org');
        assert.equal(columnField(t, 'attributes', 'Tag'), 'tags');
        assert.equal(columnField(t, 'attributes', 'Event.date'), null);
    });

    test('a field matched against the records inside is not the column', () => {
        const t = PACK.tables.objects;
        assert.equal(columnField(t, 'objects', 'comment'), null, "an object's comment is not its attributes' comment");
        assert.equal(columnField(t, 'objects', 'event_id'), 'event_id');
    });

    test('a value offers the conditions its field takes', () => {
        const t = PACK.tables.attributes;
        assert.deepEqual(filterEntries(t, 'attributes', 'type', 'domain').map((e) => e.condition),
            ["type = 'domain'", "type != 'domain'"]);
        assert.deepEqual(filterEntries(t, 'attributes', 'timestamp', '1731591425').map((e) => e.label + ': ' + e.condition), [
            'Keep only this: timestamp = 1731591425', 'Leave this out: timestamp != 1731591425',
            'From this on: timestamp >= 1731591425', 'Up to this: timestamp <= 1731591425',
        ]);
        assert.deepEqual(filterEntries(t, 'attributes', 'id', '30').map((e) => e.label),
            ['Keep only this', 'Leave this out', 'At least this', 'At most this']);
        assert.deepEqual(filterEntries(t, 'attributes', 'to_ids', true).map((e) => e.condition), ['to_ids = TRUE', 'to_ids != TRUE']);
        assert.deepEqual(filterEntries(t, 'attributes', 'Event.info', "Bob's"), [
            { label: 'Keep only this', icon: 'fa-filter', condition: "eventinfo = 'Bob''s'" },
            { label: 'Leave this out', icon: 'fa-filter-circle-xmark', condition: "eventinfo != 'Bob''s'" },
        ]);
    });

    test('no condition where = would refuse the value, or none reads the column', () => {
        const t = PACK.tables.attributes;
        assert.deepEqual(filterEntries(t, 'attributes', 'value', '%.example.com'), []);
        assert.deepEqual(filterEntries(t, 'attributes', 'value', ''), []);
        assert.deepEqual(filterEntries(t, 'attributes', 'Event.date', '2024-11-11'), []);
        assert.deepEqual(filterEntries(PACK.tables.notes, 'notes', 'created', '2024-11-12 09:11:15').map((e) => e.label),
            ['Keep only this', 'Leave this out', 'From this on', 'Up to this']);
    });

    test('a tag chip filters by its name, never its id', () => {
        const t = PACK.tables.attributes;
        assert.deepEqual(tagEntries(t, 'attributes', 'Tag', 'tlp:green').map((e) => e.condition),
            ["tags = 'tlp:green'", "tags != 'tlp:green'"]);
        assert.deepEqual(tagEntries(t, 'attributes', 'Tag', '42'), [], 'digits alone would name a tag id');
    });

    test('ids, uuids and values link to their page', () => {
        assert.deepEqual(cellLink(ctx('attributes'), 'id', '30', {}), { href: '/misp/attributes/view/30', type: 'Attribute', address: '30' });
        assert.deepEqual(cellLink(ctx('attributes'), 'EVENT_ID', 1, {}), { href: '/misp/events/view/1', type: 'Event', address: '1' });
        assert.deepEqual(cellLink(ctx('attributes'), 'value', 'circl.lu', {}), { href: '/misp/values/view/b64:circl.lu', type: 'Value', address: 'b64:circl.lu' });
        assert.deepEqual(cellLink(ctx('attributes'), 'object_id', '12', {}), { href: '/misp/objects/view/12', type: 'Object', address: '12' });
        assert.equal(cellLink(ctx('attributes'), 'object_id', '0', {}), null, 'no object');
        assert.equal(cellLink(ctx('attributes'), 'type', 'domain', {}), null, 'not a linked column');
        assert.equal(cellLink(ctx('attributes'), 'Event.Orgc.id', '1', {}), null, 'no page for organisations in this pack');
        assert.equal(cellLink(ctx('attributes'), 'id', 'x', {}), null);
    });

    test('analyst data link to the record their row names', () => {
        const uuid = '2192a382-792f-4108-a064-a17970a2de30';
        assert.equal(cellLink(ctx('notes'), 'object_uuid', uuid, { object_type: 'Attribute' }).href, '/misp/attributes/view/' + uuid);
        assert.equal(cellLink(ctx('notes'), 'object_uuid', uuid, { object_type: 'SharingGroup' }), null);
        assert.equal(cellLink(ctx('notes'), 'object_uuid', uuid, {}), null, 'without the type column');
        const sha = 'A'.repeat(64);
        assert.equal(cellLink(ctx('notes'), 'object_sha256', sha, {}).href, '/misp/values/view/sha256:' + 'a'.repeat(64));
    });

    test('a sharing group links to its page once the pack has it', () => {
        const withSg = { pages: Object.assign({ SharingGroup: '/sharing_groups/view/%s' }, PACK.pages),
            tables: { events: { links: { sharing_group_id: 'SharingGroup' } } } };
        const c = { pack: withSg, tableName: 'events', baseurl: '/misp' };
        assert.deepEqual(cellLink(c, 'sharing_group_id', '3', {}), { href: '/misp/sharing_groups/view/3', type: 'SharingGroup', address: '3' });
        assert.equal(cellLink(c, 'sharing_group_id', '0', {}), null, 'no sharing group');
    });
});

describe('Failures', () => {
    test('an expired page token asks for a reload', () => {
        assert.match(failureMessage(400, { name: 'csrf', message: 'csrf' }), /Reload the page/);
        assert.match(failureMessage(400, { name: 'The request has been black-holed' }), /Reload the page/);
    });

    test('a refusal carries what MISP said', () => {
        assert.equal(failureMessage(403, { message: 'You do not have permission to use this functionality.' }),
            'MISP refused this statement: You do not have permission to use this functionality.');
    });

    test('a server error names its status', () => {
        assert.match(failureMessage(500, null), /HTTP 500/);
    });
});

describe('Explain', () => {
    const realFetch = globalThis.fetch;
    const answer = (status, body) => async () => new Response(JSON.stringify(body), { status: status });
    const client = createClient({ csrfToken: () => 'token' });
    after(() => { globalThis.fetch = realFetch; });

    test('a plan is a result that ran nothing', async () => {
        const request = { method: 'POST', endpoint: '/events/restSearch', body: { returnFormat: 'json', query: { id: { '>': 1 } } } };
        globalThis.fetch = answer(200, {
            language: '1.0',
            statements: [{ kind: 'count', start: 0, end: 40, validated: true, table: 'events', request: request }],
        });
        const r = await client.plan('SELECT COUNT(*) FROM events WHERE id > 1');
        assert.equal(r.kind, 'plan');
        assert.equal(r.explained, true);
        assert.equal(r.table, 'events');
        assert.deepEqual(r.plan.request, request);
    });

    test('errors are placed on the statement in string indices', async () => {
        const text = "SELECT * FROM events WHERE eventinfo = '🙂' AND id = 'x' LIMIT 1";
        const at = text.indexOf("id = 'x'");
        globalThis.fetch = answer(400, {
            errors: [{ statement: 0, start: at - 1, end: at - 1 + 8, code: 'bad_type', message: 'this field expects an integer' }],
        });
        const r = await client.plan(text);
        assert.equal(r.kind, 'error');
        assert.equal(r.explained, true);
        assert.equal(text.slice(r.errors[0].from, r.errors[0].to), "id = 'x'");
    });

    test('no answer is a failure', async () => {
        globalThis.fetch = async () => { throw new TypeError('offline'); };
        const r = await client.plan('WHOAMI');
        assert.equal(r.kind, 'failure');
        assert.match(r.message, /did not answer/);
    });
});

describe('Lookups', () => {
    const realFetch = globalThis.fetch;
    after(() => { globalThis.fetch = realFetch; });
    const sources = {
        tags: [
            { url: '/tags/pickerSearch', insert: 'value', doc: 'taxonomy.expanded' },
            { url: '/galaxy_clusters/pickerSearch', insert: 'value', detail: 'style.galaxy' },
        ],
        galaxy_names: [{ url: '/galaxies/pickerScopes', insert: 'name', detail: 'type', whole: true }],
    };

    test('a source asks each picker with the prefix and keeps their order', async () => {
        const asked = [];
        globalThis.fetch = async (url) => {
            asked.push(url);
            const rows = url.indexOf('/tags/') !== -1
                ? [{ value: 'tlp:amber', label: 'tlp:amber', taxonomy: { expanded: 'Limited disclosure' } }]
                : [{ value: 'misp-galaxy:threat-actor="APT 28"', label: 'APT 28', style: { galaxy: 'Threat Actor' } }];
            return new Response(JSON.stringify(rows), { status: 200 });
        };
        const rows = await createClient({ baseurl: '/misp', csrfToken: () => '', sources }).lookup('tags', 'a b');
        assert.deepEqual(asked, ['/misp/tags/pickerSearch?q=a%20b', '/misp/galaxy_clusters/pickerSearch?q=a%20b']);
        assert.deepEqual(rows, [
            { value: 'tlp:amber', detail: '', doc: 'Limited disclosure' },
            { value: 'misp-galaxy:threat-actor="APT 28"', detail: 'Threat Actor', doc: '' },
        ]);
    });

    test('a whole list is asked once and matched here, prefixes first', async () => {
        let calls = 0;
        globalThis.fetch = async () => {
            calls++;
            return new Response(JSON.stringify([
                { name: 'Attack Pattern', type: 'mitre-attack-pattern' },
                { name: 'Threat Actor', type: 'threat-actor' },
                { name: 'Tool', type: 'tool' },
            ]), { status: 200 });
        };
        const client = createClient({ csrfToken: () => '', sources });
        assert.deepEqual((await client.lookup('galaxy_names', 'at')).map((r) => r.value), ['Attack Pattern', 'Threat Actor']);
        assert.deepEqual((await client.lookup('galaxy_names', '')).length, 3);
        assert.equal(calls, 1);
    });

    test('a picker that fails answers nothing; an aborted lookup rejects', async () => {
        globalThis.fetch = async (url) => (url.indexOf('/tags/') !== -1
            ? new Response('{}', { status: 500 })
            : new Response(JSON.stringify([{ value: 'misp-galaxy:tool="x"' }]), { status: 200 }));
        const client = createClient({ csrfToken: () => '', sources });
        assert.deepEqual((await client.lookup('tags', 'xx')).map((r) => r.value), ['misp-galaxy:tool="x"']);
        assert.deepEqual(await client.lookup('nothing', 'xx'), []);
        const ctrl = new AbortController();
        globalThis.fetch = async (url, init) => {
            ctrl.abort();
            throw Object.assign(new Error('aborted'), { name: 'AbortError', signal: init.signal });
        };
        await assert.rejects(client.lookup('tags', 'xx', ctrl.signal));
    });

    test('the galaxies come from the galaxy types picker, sharing its list with lookups', async () => {
        let calls = 0;
        globalThis.fetch = async () => {
            calls++;
            return new Response(JSON.stringify([{ name: 'Threat Actor', type: 'threat-actor', icon: 'fas fa-user-secret' }]), { status: 200 });
        };
        const types = [{ url: '/galaxies/pickerScopes', insert: 'type', detail: 'name', whole: true }];
        const client = createClient({ csrfToken: () => '', sources: { galaxy_types: types } });
        assert.deepEqual((await client.lookup('galaxy_types', 'thr')).map((r) => r.detail), ['Threat Actor']);
        assert.deepEqual(await client.galaxies(), [{ name: 'Threat Actor', type: 'threat-actor', icon: 'fas fa-user-secret' }]);
        assert.equal(calls, 1);
    });

    test('no galaxy types picker, or one that fails, gives no galaxies', async () => {
        assert.deepEqual(await createClient({ csrfToken: () => '', sources }).galaxies(), []);
        globalThis.fetch = async () => new Response('{}', { status: 500 });
        const types = [{ url: '/galaxies/pickerScopes', insert: 'type', whole: true }];
        assert.deepEqual(await createClient({ csrfToken: () => '', sources: { galaxy_types: types } }).galaxies(), []);
    });
});

describe('Tag cells', () => {
    test('a chip shows the predicate and the value, as the events index splits them', () => {
        assert.deepEqual(tagParts('osint:source-type="blog-post"'), { namespace: 'source-type', value: 'blog-post' });
        assert.deepEqual(tagParts('tlp:amber'), { namespace: 'tlp', value: 'amber' });
        assert.deepEqual(tagParts('Free text'), { namespace: null, value: 'Free text' });
    });

    test('clusters come first, named from the row, then from their type', () => {
        const rows = {
            'misp-galaxy:threat-actor="APT 28"': { galaxy: 'Threat Actor', icon: 'user-secret', value: 'APT 28' },
        };
        const lane = tagLane([
            { name: 'tlp:red', colour: null },
            { name: 'misp-galaxy:threat-actor="APT 28"', id: '9' },
            { name: 'misp-galaxy:tool="Mimikatz"' },
        ], rows);
        assert.deepEqual(lane.clusters.map((c) => [c.galaxy, c.value, c.iconClass]),
            [['Threat Actor', 'APT 28', 'fas fa-user-secret'], ['tool', 'Mimikatz', null]]);
        assert.deepEqual(lane.tags.map((t) => [t.name, t.colour]), [['tlp:red', '#CC0033']]);
    });

    test('a cluster tag holding a uuid is counted unless the row names it', () => {
        const custom = 'misp-galaxy:my-galaxy="fa5e7fb1-c3f3-47bc-91b6-67f8f0c2210a"';
        assert.equal(tagLane([{ name: custom }], {}).unresolved, 1);
        const named = tagLane([{ name: custom }], { [custom]: { galaxy: 'My galaxy', value: 'Custom Cluster' } });
        assert.equal(named.unresolved, 0);
        assert.equal(named.clusters[0].value, 'Custom Cluster');
    });
});

describe('Level names', () => {
    test('a numbered level reads its name from the pack', () => {
        const pack = {
            values: {
                threat_levels: [{ value: 1, label: 'Critical' }, { value: 2, label: 'Medium' }],
                attribute_types: [{ value: 'md5', label: 'Payload delivery' }],
            },
            tables: {
                events: {
                    fields: {
                        threat_level_id: { type: 'int', values: 'threat_levels' },
                        type: { type: 'string', values: 'attribute_types' },
                        id: { type: 'int' },
                    },
                },
            },
        };
        assert.deepEqual(levelNames(pack, 'events'), { threat_level_id: { 1: 'Critical', 2: 'Medium' } });
        assert.deepEqual(levelNames(pack, 'tags'), {});
    });
});

describe('API call', () => {
    const plan = { request: { method: 'GET', endpoint: '/events/queryDescribe' } };

    test('a plan offers the explain call first', () => {
        const list = snippets('DESCRIBE events ', plan, 'https://misp.example', { explain: true });
        assert.deepEqual(list.map((s) => s.id), ['explain', 'mispql', 'json', 'curl', 'pymisp']);
        assert.match(list[0].text, /^curl -X POST https:\/\/misp\.example\/mispql\/explain/);
        assert.match(list[0].text, /'\{"script":"DESCRIBE events"\}'$/);
    });

    test('a result offers the run call only', () => {
        assert.deepEqual(snippets('DESCRIBE events', plan, 'https://misp.example').map((s) => s.id), ['mispql', 'json', 'curl', 'pymisp']);
    });
});

describe('Header sort', () => {
    const attributes = {
        fields: { timestamp: f('timestamp', 'attribute', CMP), value: f('string', 'attribute', EQ) },
        aliases: { publish_timestamp: 'Event.publish_timestamp', eventinfo: 'Event.info' },
        order_by: { id: 'id', value: 'value', timestamp: 'timestamp', publish_timestamp: 'Event.publish_timestamp' },
    };
    const events = {
        fields: { date: f('date', 'event', CMP) },
        aliases: { event_id: 'id', eventinfo: 'info', org: 'Orgc.name' },
        order_by: { id: 'id', event_id: 'id', eventinfo: 'info', date: 'date' },
    };

    test('a column sorts by its sort name, the sort name of its field, or an alias', () => {
        assert.equal(sortNameOf(attributes, 'timestamp'), 'timestamp');
        assert.equal(sortNameOf(attributes, 'Event.publish_timestamp'), 'publish_timestamp');
        assert.equal(sortNameOf(events, 'info'), 'eventinfo');
        assert.equal(sortNameOf(events, 'ID'), 'id');
        assert.equal(sortNameOf(events, 'Orgc.name'), null);
        assert.equal(sortNameOf(attributes, 'Event.info'), null);
        assert.equal(sortNameOf({ order_by: {}, aliases: {}, fields: {} }, 'id'), null, 'objects sort by nothing');
    });

    test('a click sorts by the column alone, times newest first', () => {
        assert.deepEqual(nextOrder(attributes, [], 'value', false), [{ name: 'value', dir: 'ASC' }]);
        assert.deepEqual(nextOrder(attributes, [{ name: 'value', dir: null }], 'timestamp', false), [{ name: 'timestamp', dir: 'DESC' }]);
        assert.deepEqual(nextOrder(events, [], 'date', false), [{ name: 'date', dir: 'DESC' }]);
    });

    test('a click on the first key flips it, whatever name it was written with', () => {
        assert.deepEqual(nextOrder(attributes, [{ name: 'timestamp', dir: 'DESC' }, { name: 'id', dir: null }], 'timestamp', false),
            [{ name: 'timestamp', dir: 'ASC' }]);
        assert.deepEqual(nextOrder(events, [{ name: 'event_id', dir: null }], 'id', false), [{ name: 'event_id', dir: 'DESC' }]);
    });

    test('Shift adds the column as the next key, or flips it where it stands', () => {
        assert.deepEqual(nextOrder(attributes, [{ name: 'timestamp', dir: 'DESC' }], 'value', true),
            [{ name: 'timestamp', dir: 'DESC' }, { name: 'value', dir: 'ASC' }]);
        assert.deepEqual(nextOrder(attributes, [{ name: 'timestamp', dir: 'DESC' }, { name: 'value', dir: 'ASC' }], 'value', true),
            [{ name: 'timestamp', dir: 'DESC' }, { name: 'value', dir: 'DESC' }]);
    });
});

describe('Opened in place', () => {
    const link = (type, address) => ({ type: type, address: address, href: '/x' });

    test('a type mapped to true opens with a plain caret, named by its record', () => {
        assert.deepEqual(openSpec({ Object: true }, link('Object', '12')), { label: 'the object', cls: '', attrs: {} });
    });

    test("a view's label and caret: the class and attributes of its own trigger", () => {
        const opens = { Event: { label: 'the event', caret: (l) => (l.address === '1' ? { cls: 'ev-ref', attrs: { 'data-ev-peek': '1' } } : null) } };
        assert.deepEqual(openSpec(opens, link('Event', '1')), { label: 'the event', cls: 'ev-ref', attrs: { 'data-ev-peek': '1' } });
        assert.equal(openSpec(opens, link('Event', '2')), null, 'a cell the view cannot open');
    });

    test('nothing for a type the page does not open, nor without a link', () => {
        assert.equal(openSpec({ Object: true }, link('Event', '1')), null);
        assert.equal(openSpec({ Object: true }, null), null);
        assert.equal(openSpec(null, link('Object', '1')), null);
    });
});

describe('Download as it ran', () => {
    const model = (columns, raw) => ({ columns: columns, rows: [], raw: raw });
    test('table and flat are CSV, named by their FORMAT', () => {
        assert.deepEqual(asRan('table', model(['id', 'value'], null)), { file: 'csv', format: 'table', detail: 'CSV, 2 columns' });
        assert.deepEqual(asRan('flat', model(['id'], null)), { file: 'csv', format: 'flat', detail: 'CSV, 1 column' });
    });
    test('no FORMAT is JSON: the records for SELECT *, the columns for a column list', () => {
        assert.deepEqual(asRan('default', model(['id', 'value'], [{}])), { file: 'json', format: null, detail: 'JSON, the records as MISP returns them' });
        assert.deepEqual(asRan('default', model(['id', 'value', 'type'], null)), { file: 'json', format: null, detail: 'JSON, 3 columns' });
    });
});
