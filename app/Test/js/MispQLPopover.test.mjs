import { test, describe } from 'node:test';
import assert from 'node:assert/strict';
import { objectView, inPlaceViews, membersPageSize } from '../../webroot/js/mispql/popover.mjs';

const attr = (relation, type, value, extra) => Object.assign({ object_relation: relation, type: type, value: value }, extra || {});

describe('objectView', () => {
    test("an object's record, as the workspace's popover reads it", () => {
        const v = objectView({ Object: {
            uuid: 'AB-12', name: 'domain-ip', template_uuid: 't-1', template_version: '9',
            Attribute: [attr('ip', 'ip-dst', '192.0.2.1'), attr('domain', 'domain', 'circl.lu')],
        } });
        assert.deepEqual(v, {
            key: 'Object:ab-12',
            value: 'circl.lu',
            record: {
                name: 'domain-ip', module: null, template_uuid: 't-1', template_version: '9',
                attributes: [
                    { relation: 'ip', type: 'ip-dst', value: '192.0.2.1' },
                    { relation: 'domain', type: 'domain', value: 'circl.lu' },
                ],
            },
        });
    });

    test('named by its first attribute without a headline relation, else by its name', () => {
        assert.equal(objectView({ Object: { uuid: 'u', name: 'file', Attribute: [attr('filename', 'filename', 'a.exe')] } }).value, 'a.exe');
        assert.equal(objectView({ Object: { uuid: 'u', name: 'file', Attribute: [] } }).value, 'file');
    });

    test('deleted attributes are left out', () => {
        const v = objectView({ Object: { uuid: 'u', name: 'file', Attribute: [attr('filename', 'filename', 'gone', { deleted: true }), attr('size-in-bytes', 'size-in-bytes', '12')] } });
        assert.deepEqual(v.record.attributes.map((a) => a.value), ['12']);
    });

    test('nothing without an object', () => {
        assert.equal(objectView(null), null);
        assert.equal(objectView({ Object: { name: 'x' } }), null);
    });
});

const UUID = '2192a382-792f-4108-a064-a17970a2de30';
const link = (type, address) => ({ type: type, address: address, href: '/x' });
const ALL = { object: true, peeks: true, valueCard: true, reportReader: true, baseurl: '/misp' };

describe('inPlaceViews: the event peek', () => {
    test("an event id's caret is the indexes' peek trigger, asking /events/peek", () => {
        const v = inPlaceViews(ALL).Event;
        assert.equal(v.label, 'the event');
        assert.deepEqual(v.caret(link('Event', '42')), {
            cls: 'ev-ref', attrs: { 'data-ev-peek': '42', 'data-ev-peek-url': '/misp/events/peek/42' },
        });
    });

    test('no caret on a uuid, which the peek would read as its leading digits', () => {
        assert.equal(inPlaceViews(ALL).Event.caret(link('Event', '5f3c2a10-0000-4000-8000-000000000000')), null);
    });

    test('only where the server draws the peeks', () => {
        assert.equal(inPlaceViews(Object.assign({}, ALL, { peeks: false })).Event, undefined);
    });
});

describe('inPlaceViews: the sharing group peek', () => {
    test("a sharing group's caret is the events index's badge trigger, by id or uuid", () => {
        const v = inPlaceViews(ALL).SharingGroup;
        assert.equal(v.label, 'the sharing group');
        assert.deepEqual(v.caret(link('SharingGroup', '3')), { cls: 'dk-dist', attrs: { 'data-sg-id': '3' } });
        assert.deepEqual(v.caret(link('SharingGroup', UUID)).attrs, { 'data-sg-id': UUID });
    });

    test('only where the server draws the peeks', () => {
        assert.equal(inPlaceViews(Object.assign({}, ALL, { peeks: false })).SharingGroup, undefined);
    });
});

describe('inPlaceViews: the value hover card', () => {
    test("a value's caret is the card's trigger, on the value's address", () => {
        const v = inPlaceViews(ALL).Value;
        assert.equal(v.label, 'the value card');
        assert.deepEqual(v.caret(link('Value', 'b64:Y2lyY2wubHU')), { cls: 'vp-hc-trigger', attrs: { 'data-vp-hc-value': 'b64:Y2lyY2wubHU' } });
        assert.deepEqual(v.caret(link('Value', 'sha256:' + 'a'.repeat(64))).attrs, { 'data-vp-hc-value': 'sha256:' + 'a'.repeat(64) });
    });

    test('only where the instance has the card on', () => {
        assert.equal(inPlaceViews(Object.assign({}, ALL, { valueCard: false })).Value, undefined);
    });
});

describe('inPlaceViews: the event report reader', () => {
    test("a report id gets a plain caret, the page opening the reader", () => {
        const v = inPlaceViews(ALL).EventReport;
        assert.equal(v.label, 'the event report');
        assert.deepEqual(v.caret(link('EventReport', '7')), {});
    });

    test('no caret on a uuid: the reader names the report by the id it is given', () => {
        assert.equal(inPlaceViews(ALL).EventReport.caret(link('EventReport', UUID)), null);
    });

    test('only where the reader is on the page', () => {
        assert.equal(inPlaceViews(Object.assign({}, ALL, { reportReader: false })).EventReport, undefined);
    });
});

describe("inPlaceViews: a collection's members", () => {
    test('read from /collections/peek, by id or uuid, with a plain caret', () => {
        const v = inPlaceViews(ALL).Collection;
        assert.equal(v.label, "the collection's members");
        assert.equal(v.caret, undefined);
        assert.equal(v.url(link('Collection', '134')), '/misp/collections/peek/134');
        assert.equal(v.url(link('Collection', UUID)), '/misp/collections/peek/' + UUID);
    });

    test('only where the server draws the peeks', () => {
        assert.equal(inPlaceViews(Object.assign({}, ALL, { peeks: false })).Collection, undefined);
    });

    test('as many rows as fit the window, so the popover never scrolls', () => {
        assert.equal(membersPageSize(984), 11);
        assert.equal(membersPageSize(700), 6);
        assert.equal(membersPageSize(400), 3, 'never fewer than 3');
        assert.equal(membersPageSize(10000), 50, "never more than the card's own page");
        assert.equal(membersPageSize(undefined), 3);
    });

    test('refitted from the heights measured on a first draw', () => {
        assert.equal(membersPageSize(984, 56, 190), 14);
        assert.equal(membersPageSize(984, 80, 400), 7, 'wrapped rows and type filters at a phone width');
        assert.equal(membersPageSize(984, 0, null), membersPageSize(984), 'nothing measured');
    });
});

describe('inPlaceViews: the object popover', () => {
    test('a plain caret, the page opening the popover', () => {
        assert.deepEqual(inPlaceViews({ object: true }), { Object: { label: 'the object' } });
    });

    test('nothing the page cannot open', () => {
        assert.deepEqual(inPlaceViews({}), {});
        assert.deepEqual(inPlaceViews(null), {});
    });
});
