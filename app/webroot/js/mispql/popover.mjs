/*
 * MispQL console: records opened in place, in the workspace's popover
 * (intel-graph-working.js `IntelGraphWorking.openObject`), from what MISP
 * answers for them.
 */

/** The relations an object goes by, first found first, as the workspace names it. */
var HEADLINE = ['domain', 'hostname', 'url', 'ip', 'ip-dst', 'ip-src'];

function headline(name, attributes) {
    for (var i = 0; i < HEADLINE.length; i++) {
        var hit = attributes.filter(function (a) { return a.object_relation === HEADLINE[i]; })[0];
        if (hit) {
            return String(hit.value);
        }
    }
    return attributes.length ? String(attributes[0].value) : String(name || '');
}

/**
 * The popover's view of an object, from /objects/view/<id>.json's reply:
 * {key, value, record}, or null when the reply holds no object.
 */
function objectView(reply) {
    var o = reply && reply.Object;
    if (!o || !o.uuid) {
        return null;
    }
    var attributes = (Array.isArray(o.Attribute) ? o.Attribute : []).filter(function (a) {
        return a && !a.deleted;
    });
    return {
        key: 'Object:' + String(o.uuid).toLowerCase(),
        value: headline(o.name, attributes),
        record: {
            name: o.name,
            module: null,
            template_uuid: o.template_uuid || null,
            template_version: o.template_version || null,
            attributes: attributes.map(function (a) {
                return { relation: a.object_relation, type: a.type, value: a.value };
            }),
        },
    };
}

export { objectView };
