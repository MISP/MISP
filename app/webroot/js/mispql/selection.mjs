/*
 * MispQL console: the grid's selected rows as the workspace's add control
 * takes them (intel-graph-actions.js), read from the reply's records.
 */

/** The tables whose rows a collection can hold. */
var ADDABLE = { attributes: true, events: true, objects: true, galaxy_clusters: true };

/**
 * The reply's records when its rows can be added: one per row, on a table a
 * collection holds; else null.
 */
function addableRecords(table, reply) {
    if (!ADDABLE[table] || !reply || !Array.isArray(reply.records) || !Array.isArray(reply.rows)) {
        return null;
    }
    return reply.records.length === reply.rows.length ? reply.records : null;
}

/** Why a row cannot be added, or '' when it can. */
function blockedReason(record) {
    if (!record || !record.uuid) {
        return 'No record to add';
    }
    if (record.deleted) {
        return 'Deleted: it cannot be added';
    }
    return '';
}

/** The records of the selected rows, as IntelGraph.add() takes them. */
function itemsOf(records, indices) {
    var items = [];
    indices.forEach(function (i) {
        var record = records[i];
        if (blockedReason(record) === '') {
            items.push({ type: record.type, uuid: record.uuid, label: record.label === null || record.label === undefined ? '' : String(record.label) });
        }
    });
    return items;
}

export { ADDABLE, addableRecords, blockedReason, itemsOf };
