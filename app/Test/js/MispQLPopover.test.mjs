import { test, describe } from 'node:test';
import assert from 'node:assert/strict';
import { objectView } from '../../webroot/js/mispql/popover.mjs';

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
