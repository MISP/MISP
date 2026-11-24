import { test, describe, after } from 'node:test';
import assert from 'node:assert/strict';
import { rewritePaging, pagingOf } from '../../webroot/js/mispql/results.mjs';
import { createClient, failureMessage } from '../../webroot/js/mispql/client.mjs';
import { snippets } from '../../webroot/js/mispql/snippets.mjs';

describe('Pager', () => {
    test('sets OFFSET after LIMIT, before FORMAT', () => {
        assert.equal(rewritePaging("SELECT * FROM events WHERE id > 1 LIMIT 20 FORMAT table", 20, 40),
            "SELECT * FROM events WHERE id > 1 LIMIT 20 OFFSET 40 FORMAT table");
        assert.equal(rewritePaging('SELECT * FROM events LIMIT 20 OFFSET 40', 50, 0), 'SELECT * FROM events LIMIT 50');
        assert.equal(rewritePaging("SELECT * FROM events WHERE id > 1", 20, 20), 'SELECT * FROM events WHERE id > 1 LIMIT 20 OFFSET 20');
    });

    test('keeps a trailing semicolon last', () => {
        assert.equal(rewritePaging('SELECT * FROM tags WHERE id > 1;', 10, 0), 'SELECT * FROM tags WHERE id > 1 LIMIT 10;');
    });

    test('leaves a LIMIT inside a string alone', () => {
        assert.equal(rewritePaging("SELECT * FROM events WHERE eventinfo = 'LIMIT 5' LIMIT 5", 5, 5),
            "SELECT * FROM events WHERE eventinfo = 'LIMIT 5' LIMIT 5 OFFSET 5");
    });

    test('reads LIMIT and OFFSET', () => {
        assert.deepEqual(pagingOf('SELECT * FROM events LIMIT 20 OFFSET 40'), { limit: 20, offset: 40 });
        assert.deepEqual(pagingOf("SELECT * FROM events WHERE eventinfo = 'LIMIT 3'"), { limit: null, offset: 0 });
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
