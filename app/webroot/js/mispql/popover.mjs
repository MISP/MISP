/*
 * MispQL console: records opened in place, each in the view MISP already
 * has for it: an object in the workspace's popover (intel-graph-working.js
 * `IntelGraphWorking.openObject`), an event in the indexes' peek, a sharing
 * group in the events index's badge popover, a value in its hover card, a
 * report in the event page's reader, a collection's members in its page's
 * elements card.
 */

var ID = /^[0-9]+$/;

/**
 * The views the page can open, by record type: `label` names what opens
 * (the caret's title, the funnel's "Open …" entry); `caret(link)` gives the
 * class and data attributes making the caret the view's own trigger, or
 * null when the cell cannot open it; `url(link)` where a fragment is read.
 * has: {object, peeks, valueCard, reportReader, baseurl}
 */
function inPlaceViews(has) {
    var base = (has && has.baseurl) || '';
    var views = {};
    if (!has) {
        return views;
    }
    if (has.object) {
        views.Object = { label: 'the object' };
    }
    if (has.peeks) {
        // /events/peek reads an id: a uuid would be cut to its leading digits
        views.Event = {
            label: 'the event',
            caret: function (link) {
                return ID.test(link.address)
                    ? { cls: 'ev-ref', attrs: { 'data-ev-peek': link.address, 'data-ev-peek-url': base + '/events/peek/' + link.address } }
                    : null;
            },
        };
        views.SharingGroup = {
            label: 'the sharing group',
            caret: function (link) {
                return { cls: 'dk-dist', attrs: { 'data-sg-id': link.address } };
            },
        };
        views.Collection = {
            label: 'the collection\'s members',
            url: function (link) {
                return base + '/collections/peek/' + encodeURIComponent(link.address);
            },
        };
    }
    if (has.valueCard) {
        views.Value = {
            label: 'the value card',
            caret: function (link) {
                return { cls: 'vp-hc-trigger', attrs: { 'data-vp-hc-value': link.address } };
            },
        };
    }
    if (has.reportReader) {
        // The reader names the report by the id it is given
        views.EventReport = {
            label: 'the event report',
            caret: function (link) {
                return ID.test(link.address) ? {} : null;
            },
        };
    }
    return views;
}

/** A member row's height and the card's around the rows, until measured. */
var MEMBER_ROW = 58;
var MEMBER_CHROME = 300;

/**
 * How many members a popover shows at once in `room` pixels of window, so
 * it never scrolls: at least 3, at most the card's own 50. `row` and
 * `chrome` are the heights measured on a first draw, when there was one.
 */
function membersPageSize(room, row, chrome) {
    row = Number(row) > 0 ? Number(row) : MEMBER_ROW;
    chrome = Number(chrome) >= 0 && chrome !== null && chrome !== undefined ? Number(chrome) : MEMBER_CHROME;
    var fit = Math.floor((Number(room) - chrome) / row);
    return Math.max(3, Math.min(50, isFinite(fit) ? fit : 3));
}

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

export { objectView, inPlaceViews, membersPageSize };
