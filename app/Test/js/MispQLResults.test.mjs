import { test, describe } from 'node:test';
import assert from 'node:assert/strict';
import { rewritePaging, pagingOf } from '../../webroot/js/mispql/results.mjs';
import { failureMessage } from '../../webroot/js/mispql/client.mjs';

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
