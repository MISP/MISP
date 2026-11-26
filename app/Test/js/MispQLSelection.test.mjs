import { test, describe } from 'node:test';
import assert from 'node:assert/strict';
import { addableRecords, blockedReason, itemsOf } from '../../webroot/js/mispql/selection.mjs';

const attr = (id, value, extra) => Object.assign({ type: 'Attribute', id: String(id), uuid: 'a-' + id, label: value }, extra || {});

describe('addableRecords', () => {
    const reply = { rows: [{}, {}], records: [attr(1, 'x'), attr(2, 'y')] };

    test('the records of a table a collection holds', () => {
        for (const table of ['attributes', 'events', 'objects', 'galaxy_clusters']) {
            assert.equal(addableRecords(table, reply), reply.records);
        }
    });

    test('none for the other tables', () => {
        for (const table of ['tags', 'organisations', 'collections', 'event_reports', 'notes', 'opinions', 'relationships']) {
            assert.equal(addableRecords(table, reply), null);
        }
    });

    test('none when the reply has no records, or not one per row', () => {
        assert.equal(addableRecords('attributes', { rows: [{}] }), null);
        assert.equal(addableRecords('attributes', { rows: [{}], records: [] }), null);
        assert.equal(addableRecords('attributes', null), null);
    });
});

describe('blockedReason', () => {
    test('a record with a uuid can be added', () => {
        assert.equal(blockedReason(attr(1, 'x')), '');
    });

    test('a deleted record, or one without a uuid, cannot', () => {
        assert.match(blockedReason(attr(1, 'x', { deleted: true })), /Deleted/);
        assert.notEqual(blockedReason(attr(1, 'x', { uuid: null })), '');
        assert.notEqual(blockedReason(undefined), '');
    });
});

describe('itemsOf', () => {
    const records = [
        attr(1, 'circl.lu'),
        { type: 'Event', id: '7', uuid: 'e-7', label: 'Phishing' },
        attr(3, 'gone', { deleted: true }),
        { type: 'GalaxyCluster', id: '9', uuid: 'c-9', label: null },
    ];

    test('the selected rows, in order, as IntelGraph.add() takes them', () => {
        assert.deepEqual(itemsOf(records, [0, 1]), [
            { type: 'Attribute', uuid: 'a-1', label: 'circl.lu' },
            { type: 'Event', uuid: 'e-7', label: 'Phishing' },
        ]);
    });

    test('a row that cannot be added is left out; a missing label is empty', () => {
        assert.deepEqual(itemsOf(records, [2, 3]), [{ type: 'GalaxyCluster', uuid: 'c-9', label: '' }]);
    });
});
