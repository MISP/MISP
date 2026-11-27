import { test, describe } from 'node:test';
import assert from 'node:assert/strict';
import {
    addCondition, setOrder, orderOf, rewritePaging, pagingOf, fieldName, literal,
} from '../../webroot/js/mispql/rewrite.mjs';

describe('Adding a condition', () => {
    test('starts a WHERE after the table', () => {
        assert.equal(addCondition('SELECT * FROM attributes LIMIT 20', "type = 'domain'"),
            "SELECT * FROM attributes WHERE type = 'domain' LIMIT 20");
        assert.equal(addCondition('SELECT * FROM attributes\nLIMIT 20 FORMAT table', 'id = 3'),
            'SELECT * FROM attributes WHERE id = 3\nLIMIT 20 FORMAT table');
        assert.equal(addCondition('SELECT * FROM `events` LIMIT 5', 'id = 3'),
            'SELECT * FROM `events` WHERE id = 3 LIMIT 5');
    });

    test('appends to the condition, before ORDER BY, LIMIT, OFFSET and FORMAT', () => {
        assert.equal(addCondition("SELECT * FROM attributes WHERE type = 'domain' ORDER BY id LIMIT 5", 'to_ids = TRUE'),
            "SELECT * FROM attributes WHERE type = 'domain' AND to_ids = TRUE ORDER BY id LIMIT 5");
        assert.equal(addCondition("SELECT * FROM attributes WHERE type = 'domain'", 'to_ids = TRUE'),
            "SELECT * FROM attributes WHERE type = 'domain' AND to_ids = TRUE");
        assert.equal(addCondition('SELECT id FROM events WHERE id > 1 FORMAT flat', 'published = TRUE'),
            'SELECT id FROM events WHERE id > 1 AND published = TRUE FORMAT flat');
        assert.equal(addCondition('SELECT COUNT(*) FROM events WHERE id > 1', 'published = TRUE'),
            'SELECT COUNT(*) FROM events WHERE id > 1 AND published = TRUE');
    });

    test('wraps a condition whose top level holds an OR', () => {
        assert.equal(addCondition("SELECT * FROM attributes WHERE type = 'a' OR type = 'b' LIMIT 5", 'id = 1'),
            "SELECT * FROM attributes WHERE (type = 'a' OR type = 'b') AND id = 1 LIMIT 5");
        assert.equal(addCondition("SELECT * FROM attributes WHERE (type = 'a' OR type = 'b') AND id > 1 LIMIT 5", 'id < 9'),
            "SELECT * FROM attributes WHERE (type = 'a' OR type = 'b') AND id > 1 AND id < 9 LIMIT 5");
        assert.equal(addCondition("SELECT * FROM attributes WHERE NOT (type = 'a' OR type = 'b') LIMIT 5", 'id = 1'),
            "SELECT * FROM attributes WHERE NOT (type = 'a' OR type = 'b') AND id = 1 LIMIT 5");
    });

    test('keeps comments, strings and backticks as written', () => {
        assert.equal(addCondition("SELECT * FROM attributes -- the lot\nWHERE value = 'x LIMIT 3' -- why\nLIMIT 5", 'id = 1'),
            "SELECT * FROM attributes -- the lot\nWHERE value = 'x LIMIT 3' AND id = 1 -- why\nLIMIT 5");
        assert.equal(addCondition("SELECT * FROM galaxy_clusters WHERE meta.`cfr-target-category` = 'x' OR value = 'y'", 'id = 1'),
            "SELECT * FROM galaxy_clusters WHERE (meta.`cfr-target-category` = 'x' OR value = 'y') AND id = 1");
        assert.equal(addCondition("SELECT * FROM attributes WHERE comment = 'a -- b' LIMIT 5", 'id = 1'),
            "SELECT * FROM attributes WHERE comment = 'a -- b' AND id = 1 LIMIT 5");
    });

    test('stops at the end of the statement', () => {
        assert.equal(addCondition('SELECT * FROM tags LIMIT 5;', 'id = 1'), 'SELECT * FROM tags WHERE id = 1 LIMIT 5;');
        assert.equal(addCondition("SELECT * FROM tags WHERE name = 'a';\nSELECT * FROM events LIMIT 1", 'id = 1'),
            "SELECT * FROM tags WHERE name = 'a' AND id = 1;\nSELECT * FROM events LIMIT 1");
    });

    test('has nothing to add to without a table', () => {
        assert.equal(addCondition('SHOW TABLES', 'id = 1'), null);
        assert.equal(addCondition('SELECT * FROM', 'id = 1'), null);
    });
});

describe('Ordering', () => {
    test('reads the keys of ORDER BY', () => {
        assert.deepEqual(orderOf('SELECT * FROM events WHERE id > 1 ORDER BY publish_timestamp DESC, event_id LIMIT 5'),
            [{ name: 'publish_timestamp', dir: 'DESC' }, { name: 'event_id', dir: null }]);
        assert.deepEqual(orderOf('SELECT * FROM events WHERE id > 1 order by Event_ID asc'), [{ name: 'event_id', dir: 'ASC' }]);
        assert.deepEqual(orderOf("SELECT * FROM events WHERE eventinfo = 'ORDER BY id' LIMIT 5"), []);
    });

    test('replaces ORDER BY and goes back to the first page', () => {
        assert.equal(setOrder('SELECT * FROM events WHERE id > 1 ORDER BY id LIMIT 20 OFFSET 40 FORMAT table', [{ name: 'timestamp', dir: 'DESC' }]),
            'SELECT * FROM events WHERE id > 1 ORDER BY timestamp DESC LIMIT 20 FORMAT table');
        assert.equal(setOrder('SELECT * FROM events WHERE id > 1 ORDER BY id DESC, timestamp LIMIT 5', [{ name: 'id', dir: 'ASC' }, { name: 'timestamp', dir: null }]),
            'SELECT * FROM events WHERE id > 1 ORDER BY id ASC, timestamp LIMIT 5');
    });

    test('inserts ORDER BY after the condition', () => {
        assert.equal(setOrder("SELECT * FROM attributes WHERE type = 'domain'\nLIMIT 20", [{ name: 'value', dir: null }]),
            "SELECT * FROM attributes WHERE type = 'domain' ORDER BY value\nLIMIT 20");
        assert.equal(setOrder('SELECT * FROM tags LIMIT 20', [{ name: 'name', dir: null }]),
            'SELECT * FROM tags ORDER BY name LIMIT 20');
        assert.equal(setOrder('SELECT * FROM tags WHERE id > 1;', [{ name: 'name', dir: 'DESC' }]),
            'SELECT * FROM tags WHERE id > 1 ORDER BY name DESC;');
    });

    test('removes ORDER BY when given no key', () => {
        assert.equal(setOrder('SELECT * FROM tags WHERE id > 1 ORDER BY name DESC LIMIT 5', []),
            'SELECT * FROM tags WHERE id > 1 LIMIT 5');
    });
});

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

describe('Literals', () => {
    test('follow the field type, converting nothing', () => {
        assert.equal(literal('string', "O'Brien"), "'O''Brien'");
        assert.equal(literal('int', '42'), '42');
        assert.equal(literal('int', -3), '-3');
        assert.equal(literal('int', 'x'), null);
        assert.equal(literal('timestamp', '1731591425'), '1731591425');
        assert.equal(literal('bool', true), 'TRUE');
        assert.equal(literal('bool', false), 'FALSE');
        assert.equal(literal('bool', '1'), 'TRUE');
        assert.equal(literal('date', '2024-11-11'), "'2024-11-11'");
        assert.equal(literal('datetime', '2024-11-12 09:11:15'), "'2024-11-12 09:11:15'");
    });

    test('none where = would refuse the value or there is nothing to compare', () => {
        assert.equal(literal('string', '%evil'), null);
        assert.equal(literal('string', 'evil%'), null);
        assert.equal(literal('string', 'ev%il'), "'ev%il'");
        assert.equal(literal('string', ''), null);
        assert.equal(literal('string', null), null);
        assert.equal(literal('string', ['a']), null);
        assert.equal(literal('timestamp', '0'), null);
        assert.equal(literal('datetime', '0'), null);
    });

    test('field names get backticks where a part needs them', () => {
        assert.equal(fieldName('type'), 'type');
        assert.equal(fieldName('meta.synonyms'), 'meta.synonyms');
        assert.equal(fieldName('meta.cfr-target-category'), 'meta.`cfr-target-category`');
        assert.equal(fieldName('count'), '`count`');
    });
});
