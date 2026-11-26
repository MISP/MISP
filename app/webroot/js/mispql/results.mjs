/*
 * MispQL console: one view per kind of reply. Each takes the result and
 * its options and returns an element; none reads the page around it.
 */

import * as T from './tokens.mjs';
import { highlightHTML } from './writer.mjs';
import { addCondition, literal, fieldName, orderOf, setOrder, pagingOf, rewritePaging } from './rewrite.mjs';
import { columnField, valueRows } from './suggest.mjs';
import { el, esc, fmtInt, ago, bytes, download, jsonHTML, copyText } from './util.mjs';

var GRID_CAP = 500;

function summary(r) {
    switch (r.kind) {
        case 'rows':
            var n = r.reply.rows.length;
            return r.reply.total === null || n === r.reply.total ? fmtInt(n) + (n === 1 ? ' row' : ' rows')
                : fmtInt(n) + ' of ' + fmtInt(r.reply.total) + ' rows';
        case 'count':
            return 'count ' + fmtInt(r.reply.count);
        case 'describe':
            return Object.keys(r.reply.fields).length + ' fields';
        case 'tables':
            return r.reply.tables.length + ' tables';
        case 'whoami':
            return r.reply.email;
        case 'export':
            return r.format + ' · ' + bytes(r.size);
        case 'plan':
            return isClient(r) ? 'runs in mispql' : 'not run';
        case 'failure':
            return r.status ? 'HTTP ' + r.status : 'no answer';
        case 'error':
            if (isClient(r)) {
                return 'runs in mispql';
            }
            return r.errors.length === 1 ? '1 error' : r.errors.length + ' errors';
        default:
            return '';
    }
}

function isClient(r) {
    if (r.kind === 'plan') {
        return !!r.plan && (r.plan.kind === 'use' || r.plan.kind === 'show_databases');
    }
    return r.kind === 'error' && r.errors.length === 1 && r.errors[0].code === 'client_statement';
}

function kindIcon(r) {
    return isClient(r) ? 'fa-terminal' : KIND_ICON[r.kind];
}

var KIND_ICON = {
    rows: 'fa-table-cells', count: 'fa-hashtag', describe: 'fa-list-ul', tables: 'fa-layer-group',
    whoami: 'fa-id-badge', export: 'fa-file-arrow-down', error: 'fa-circle-exclamation',
    failure: 'fa-plug-circle-xmark', plan: 'fa-route'
};

function flatten(row, prefix, out) {
    out = out || {};
    prefix = prefix || '';
    Object.keys(row).forEach(function (k) {
        var v = row[k];
        if (k === 'Tag' && Array.isArray(v)) {
            out[prefix + k] = v;
        } else if (Array.isArray(v)) {
            return;
        } else if (v !== null && typeof v === 'object') {
            flatten(v, prefix + k + '.', out);
        } else {
            out[prefix + k] = v;
        }
    });
    return out;
}

/** Columns and flat rows for the grid: the reply's projection, or the table's default columns. */
function gridModel(r, pack) {
    var reply = r.reply;
    if (reply.columns) {
        return { columns: reply.columns, rows: reply.rows, raw: null };
    }
    var table = pack && pack.tables[r.table];
    var flat = reply.rows.map(function (row) { return flatten(row); });
    var defaults = table ? table.default_columns : (flat.length ? Object.keys(flat[0]) : []);
    var columns = defaults.map(function (c) {
        var lower = c.toLowerCase();
        for (var i = 0; i < flat.length; i++) {
            var hit = Object.keys(flat[i]).filter(function (k) { return k.toLowerCase() === lower; })[0];
            if (hit) {
                return hit;
            }
        }
        return c;
    });
    return { columns: columns, rows: flat, raw: reply.rows };
}

function splitTags(v) {
    if (Array.isArray(v)) {
        return v.filter(function (t) { return t !== null && t !== undefined; }).map(function (t) {
            return typeof t === 'object'
                ? {
                    id: t.id, name: String(t.name), colour: t.colour, local: t.local,
                    numerical_value: t.numerical_value, relationship_type: t.relationship_type
                }
                : { name: String(t), colour: null };
        });
    }
    if (!v) {
        return [];
    }
    var out = [];
    var cur = '';
    var quoted = false;
    String(v).split('').forEach(function (c) {
        if (c === '"') {
            quoted = !quoted;
        }
        if (c === ',' && !quoted) {
            out.push(cur);
            cur = '';
        } else {
            cur += c;
        }
    });
    if (cur) {
        out.push(cur);
    }
    return out.map(function (n) { return { name: n, colour: null }; });
}

// The declared colours of TLP, for rows that carry tag names only.
var TLP_COLOUR = {
    'tlp:red': '#CC0033', 'tlp:amber': '#FFC000', 'tlp:amber+strict': '#FFC000', 'tlp:green': '#339900',
    'tlp:clear': '#ffffff', 'tlp:white': '#ffffff'
};

var GALAXY_TAG = /^misp-galaxy:([^=]+)="?(.*?)"?$/;

// The galaxies the user can see, by type, once a grid has asked for them
var galaxyTypes = null;

function typesOf(list) {
    var out = {};
    list.forEach(function (g) {
        var type = String(g.type || '').toLowerCase();
        if (type && !out[type]) {
            out[type] = { galaxy: g.name, iconClass: g.icon || null };
        }
    });
    return out;
}

/** The galaxies MISP sends with event rows, by their clusters' tag names. */
function galaxiesOf(raw) {
    var out = {};
    (raw || []).forEach(function (row) {
        [row && row.Galaxy, row && row.Event && row.Event.Galaxy].forEach(function (list) {
            (Array.isArray(list) ? list : []).forEach(function (g) {
                (g.GalaxyCluster || []).forEach(function (c) {
                    if (c.tag_name) {
                        out[c.tag_name] = { galaxy: g.name, icon: g.icon, value: c.value, description: c.description };
                    }
                });
            });
        });
    });
    return out;
}

/** The predicate and value a tag chip shows, split as the events index does. */
function tagParts(name) {
    var m = /^([^:="]+):([^=]+)="(.*)"$/s.exec(name);
    if (m) {
        return { namespace: m[2], value: m[3] };
    }
    m = /^([^:]+):(.+)$/s.exec(name);
    return m ? { namespace: m[1], value: m[2] } : { namespace: null, value: name };
}

/**
 * A tag cell's tags as the events index sorts them: the clusters, named
 * from the row's galaxies or the ones the user can see, then the tags; a
 * cluster tag holding a uuid it cannot name is only counted.
 */
function tagLane(tags, galaxies) {
    var lane = { clusters: [], tags: [], unresolved: 0 };
    tags.forEach(function (t) {
        var m = GALAXY_TAG.exec(t.name);
        if (!m || !m[2]) {
            lane.tags.push(Object.assign({}, t, { colour: t.colour || TLP_COLOUR[t.name.toLowerCase()] || null }));
            return;
        }
        var known = (galaxies && galaxies[t.name]) || {};
        if (!known.value && /^[0-9a-f]{8}-[0-9a-f]{4}-/i.test(m[2])) {
            lane.unresolved++;
            return;
        }
        var byType = (galaxyTypes && galaxyTypes[m[1].toLowerCase()]) || {};
        lane.clusters.push({
            value: known.value || m[2],
            galaxy: known.galaxy || byType.galaxy || m[1],
            iconClass: byType.iconClass || (known.icon ? 'fas fa-' + known.icon : null),
            description: known.description,
            tag_id: t.id,
            local: t.local,
            relationship_type: t.relationship_type
        });
    });
    return lane;
}

function unresolvedNote(n) {
    return n + (n === 1 ? ' galaxy tag whose cluster is' : ' galaxy tags whose cluster is') + ' not available here';
}

function laneChips(lane) {
    var html = lane.clusters.map(function (c) {
        var title = (c.relationship_type ? c.relationship_type + ': ' : '') + c.galaxy + ' › ' + c.value;
        return '<span class="dk-chip is-gx" title="' + esc(title) + '"><i class="' + esc(c.iconClass || 'fas fa-circle-dot') +
            '"></i><span>' + esc(c.value) + '</span></span>';
    }).join('') + lane.tags.map(function (t) {
        var parts = tagParts(t.name);
        var colour = /^#[0-9a-f]{3,8}$/i.test(String(t.colour || '')) ? ' style="--tc:' + esc(t.colour) + '"' : '';
        return '<span class="dk-chip is-tag"' + colour + ' title="' + esc(t.name) + '"><span>' +
            (parts.namespace !== null ? '<small>' + esc(parts.namespace) + '</small> ' : '') + esc(parts.value) + '</span></span>';
    }).join('');
    if (lane.unresolved) {
        html += '<span class="dk-chip is-fold" title="' + esc(unresolvedNote(lane.unresolved)) + '">' +
            lane.unresolved + ' unresolved</span>';
    }
    return html;
}

/** What +N opens: every tag of the cell, one list per galaxy or namespace, as EventIndexHelper::lists() draws it. */
function laneTemplate(lane, head) {
    var chips = typeof window !== 'undefined' ? window.TagChips : null;
    if (!chips || !chips.lists) {
        return '';
    }
    var lists = chips.lists([], lane.clusters) + chips.lists(lane.tags, [], { ownColour: true });
    var cols = 1;
    if (lists.indexOf('data-cols="2"') === -1 && lists.indexOf('data-cols="3"') === -1) {
        var height = 45 * (lists.split('hg-card-head').length - 1) + 21 * (lists.split('class="hg-row').length - 1);
        cols = Math.max(1, Math.min(3, Math.ceil(height / 360)));
    }
    var count = lane.clusters.length + lane.tags.length + lane.unresolved;
    return '<template class="dk-ctx-tpl"><div class="dk-pop-in"><div class="dk-pop-head">' +
        (head.id ? '<span class="dk-pop-id">#' + esc(head.id) + '</span>' : '') +
        '<b title="' + esc(head.label) + '">' + esc(head.label) + '</b>' +
        '<button type="button" class="dk-pop-x" data-dk-close aria-label="Close"><i class="fas fa-xmark"></i></button></div>' +
        '<section class="dk-pop-sec" data-dk-lane="tags"><h4><i class="misp-icon misp-icon-tag misp-simple" aria-hidden="true"></i>Tags <small>' + count + '</small></h4>' +
        '<div class="dk-pop-body" data-cols="' + cols + '">' + lists + '</div>' +
        (lane.unresolved ? '<div class="dk-pop-note">' + esc(unresolvedNote(lane.unresolved)) + '</div>' : '') +
        '</section></div></template>';
}

/**
 * A tag cell as an events index lane: the chips that fit, then +N, which
 * events-index-cards.js reveals and opens onto every tag.
 */
function tagCell(tags, galaxies, head) {
    var lane = tagLane(tags, galaxies);
    return '<div class="te-ctx" data-dk-lane="tags" data-dk-root data-dk-label="' +
        esc('Tags' + (head.id ? ' of #' + head.id : '')) + '">' + laneChips(lane) +
        '<button type="button" class="dk-more" data-dk-lane="tags" tabindex="-1" aria-haspopup="dialog" ' +
        'aria-expanded="false" aria-label="Tags: show all" hidden></button>' + laneTemplate(lane, head) + '</div>';
}

var TIME_COLUMN = /(^|\.)(timestamp|publish_timestamp|event_timestamp)$/i;

var BOOL_TRUE = '<span class="cq-bool is-true"><i class="fa-solid fa-check"></i>true</span>';

var BOOL_FALSE = '<span class="cq-bool">false</span>';

/**
 * The names of a table's numbered levels (distribution, threat level,
 * analysis), from the pack's lists: field => {number: name}.
 */
function levelNames(pack, tableName) {
    var table = pack && pack.tables[tableName];
    var names = {};
    if (!table) {
        return names;
    }
    Object.keys(table.fields).forEach(function (f) {
        var def = table.fields[f];
        if (def.type !== 'int' || !def.values) {
            return;
        }
        var map = {};
        valueRows(pack, def).forEach(function (row) {
            if (row.label) {
                map[row.value] = row.label;
            }
        });
        names[f.toLowerCase()] = map;
    });
    return names;
}

function cell(column, value, levels, galaxies, head) {
    var base = column.split('.').pop().toLowerCase();
    var level = levels && levels[base] && !Array.isArray(value) ? levels[base][value] : undefined;
    if (value === null || value === undefined || value === '') {
        return '<span class="cq-null">—</span>';
    }
    if (base === 'tag') {
        var tags = splitTags(value);
        return tags.length ? tagCell(tags, galaxies, head || {}) : '<span class="cq-null">—</span>';
    }
    if (Array.isArray(value)) {
        return '<span class="cq-text">' + esc(value.join(', ')) + '</span>';
    }
    if (typeof value === 'boolean') {
        return value ? BOOL_TRUE : BOOL_FALSE;
    }
    if (TIME_COLUMN.test(column) && /^[0-9]+$/.test(String(value))) {
        if (String(value) === '0') {
            return '<span class="cq-null">—</span>';
        }
        var d = new Date(Number(value) * 1000).toISOString().replace('T', ' ');
        return '<span class="cq-time" title="' + esc(value) + ' · ' + esc(d.slice(0, 19)) + ' UTC · ' + esc(ago(Number(value))) + '">' + esc(d.slice(0, 16)) + '</span>';
    }
    if (level !== undefined && base === 'threat_level_id') {
        return '<span class="cq-threat cq-threat-' + esc(value) + '" title="' + esc(value) + ' · ' + esc(level) + '">' + esc(level) + '</span>';
    }
    if (level !== undefined) {
        return '<span class="cq-enum" title="' + esc(level) + '"><b>' + esc(value) + '</b>' + esc(level) + '</span>';
    }
    if (base === 'id' || base === 'event_id' || base === 'object_id') {
        return '<span class="cq-id">' + esc(value) + '</span>';
    }
    if (base === 'value' || base === 'uuid' || /_uuid$/.test(base) || base === 'object_uuid') {
        return '<span class="cq-mono" title="' + esc(value) + '">' + esc(value) + '</span>';
    }
    var s = String(value);
    return '<span class="cq-text" title="' + esc(s.length > 60 ? s : '') + '">' + esc(s.replace(/\n/g, ' ⏎ ')) + '</span>';
}

var UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

var RECORD_LABEL = {
    Attribute: 'the attribute', Event: 'the event', Object: 'the object', GalaxyCluster: 'the galaxy cluster',
    Galaxy: 'the galaxy', EventReport: 'the event report', Note: 'the note', Opinion: 'the opinion',
    Relationship: 'the relationship', Collection: 'the collection', Tag: 'the events carrying the tag',
    Organisation: 'the organisation', SharingGroup: 'the sharing group',
    Value: 'the value\'s page'
};

/** The key of `map` that is `name` in any case, or null. */
function keyOf(map, name) {
    if (!map) {
        return null;
    }
    if (Object.prototype.hasOwnProperty.call(map, name)) {
        return name;
    }
    var lower = String(name).toLowerCase();
    var keys = Object.keys(map);
    for (var i = 0; i < keys.length; i++) {
        if (keys[i].toLowerCase() === lower) {
            return keys[i];
        }
    }
    return null;
}

function rowValue(row, column) {
    var k = keyOf(row, column);
    return k === null ? undefined : row[k];
}

function isEmpty(v) {
    return v === null || v === undefined || v === '' || (Array.isArray(v) && !v.length);
}

/**
 * The page a cell names, from the pack's links and pages: {href, type}, or
 * null. ctx: {pack, tableName, baseurl, address(value)}.
 */
function cellLink(ctx, column, value, row) {
    var table = ctx.pack && ctx.pack.tables[ctx.tableName];
    var pages = ctx.pack && ctx.pack.pages;
    var key = table && table.links ? keyOf(table.links, column) : null;
    if (key === null || !pages || isEmpty(value) || typeof value === 'object') {
        return null;
    }
    var spec = table.links[key];
    var type = typeof spec === 'string' ? spec : spec.type;
    if (spec.type_from) {
        type = rowValue(row, spec.type_from);
    }
    if (typeof type !== 'string' || !Object.prototype.hasOwnProperty.call(pages, type)) {
        return null;
    }
    var s = String(value);
    var address = null;
    if (type === 'Value') {
        if (spec.by === 'sha256') {
            address = /^[0-9a-f]{64}$/i.test(s) ? 'sha256:' + s.toLowerCase() : null;
        } else {
            address = ctx.address ? ctx.address(s) : null;
        }
    } else if ((/^[0-9]+$/.test(s) && s !== '0') || UUID.test(s)) {
        address = s;
    }
    return address === null ? null : { href: (ctx.baseurl || '') + pages[type].replace('%s', address), type: type, address: address };
}

/**
 * How a linked record opens in place, from the page's `opens` (record type
 * => true, or {label, caret(link)}): {label, cls, attrs}, or null when it
 * does not. `cls` and `attrs` make the caret the trigger of a view MISP
 * opens itself (a hover card, a peek).
 */
function openSpec(opens, link) {
    var view = link && opens ? opens[link.type] : null;
    if (!view) {
        return null;
    }
    var caret = view === true || typeof view.caret !== 'function' ? {} : view.caret(link);
    if (!caret) {
        return null;
    }
    return {
        label: (view !== true && view.label) || RECORD_LABEL[link.type] || link.type,
        cls: caret.cls || '',
        attrs: caret.attrs || {},
    };
}

function caretHTML(open, value) {
    var attrs = Object.keys(open.attrs).map(function (k) {
        return ' ' + k + '="' + esc(String(open.attrs[k])) + '"';
    }).join('');
    // A trigger of MISP's own opens on hover: a native tooltip would cover it
    return '<button type="button" class="cq-open' + (open.cls ? ' ' + esc(open.cls) : '') + '" tabindex="-1" aria-haspopup="dialog"' +
        ' aria-label="Open ' + esc(open.label + ' ' + String(value)) + ' here"' +
        (open.cls ? '' : ' title="Open ' + esc(open.label) + ' here"') + attrs + '>' +
        '<i class="fa-solid fa-chevron-down" aria-hidden="true"></i></button>';
}

var TIMELIKE = { timestamp: 1, date: 1, datetime: 1 };

/** The conditions a cell's value can add: [{label, icon, condition}]. */
function filterEntries(table, tableName, column, value) {
    var field = columnField(table, tableName, column);
    if (field === null) {
        return [];
    }
    var def = table.fields[field];
    var lit = literal(def.type, value);
    if (lit === null) {
        return [];
    }
    var name = fieldName(field);
    var has = function (op) { return def.operators.indexOf(op) !== -1; };
    var out = [];
    if (has('=')) {
        out.push({ label: 'Keep only this', icon: 'fa-filter', condition: name + ' = ' + lit });
    }
    if (has('!=')) {
        out.push({ label: 'Leave this out', icon: 'fa-filter-circle-xmark', condition: name + ' != ' + lit });
    }
    if (def.type === 'int' || TIMELIKE[def.type]) {
        var time = TIMELIKE[def.type] === 1;
        if (has('>=')) {
            out.push({ label: time ? 'From this on' : 'At least this', icon: 'fa-greater-than-equal', condition: name + ' >= ' + lit });
        }
        if (has('<=')) {
            out.push({ label: time ? 'Up to this' : 'At most this', icon: 'fa-less-than-equal', condition: name + ' <= ' + lit });
        }
    }
    return out;
}

/**
 * The conditions a tag chip can add, always by the tag's name. A name of
 * digits only would be read as a tag id, so it gets none.
 */
function tagEntries(table, tableName, column, name) {
    if (/^[0-9]+$/.test(name)) {
        return [];
    }
    return filterEntries(table, tableName, column, name).filter(function (e) {
        return e.label === 'Keep only this' || e.label === 'Leave this out';
    });
}

/**
 * The name ORDER BY takes for a column: a sort name of the table, the sort
 * name whose server field the column is, or an alias printed as the column
 * that is a sort name. null when MISP cannot sort by it.
 */
function sortNameOf(table, column) {
    var order = table && table.order_by;
    if (!order) {
        return null;
    }
    var direct = keyOf(order, column);
    if (direct !== null) {
        return direct;
    }
    var lower = String(column).toLowerCase();
    var names = Object.keys(order);
    for (var i = 0; i < names.length; i++) {
        if (String(order[names[i]]).toLowerCase() === lower) {
            return names[i];
        }
    }
    var aliases = table.aliases || {};
    var alias = Object.keys(aliases).filter(function (a) {
        return String(aliases[a]).toLowerCase() === lower && keyOf(order, a) !== null;
    })[0];
    return alias ? keyOf(order, alias) : null;
}

/** Index in `keys` of the key sorting by the same server field as `name`, or -1. */
function keyIndex(table, keys, name) {
    var target = table.order_by[name];
    for (var i = 0; i < keys.length; i++) {
        var k = keyOf(table.order_by, keys[i].name);
        if (k !== null && table.order_by[k] === target) {
            return i;
        }
    }
    return -1;
}

/**
 * The ORDER BY keys after a click on a column's header: alone, ascending
 * (descending for times and dates), or flipped when it was the first key;
 * with `add` (Shift), appended, or flipped where it stands.
 */
function nextOrder(table, keys, name, add) {
    var def = table.fields && table.fields[name];
    var first = def && TIMELIKE[def.type] ? 'DESC' : 'ASC';
    var flip = function (k) { return { name: k.name, dir: k.dir === 'DESC' ? 'ASC' : 'DESC' }; };
    var at = keyIndex(table, keys, name);
    if (add) {
        if (at === -1) {
            return keys.concat([{ name: name, dir: first }]);
        }
        return keys.map(function (k, i) { return i === at ? flip(k) : k; });
    }
    return [at === 0 ? flip(keys[0]) : { name: name, dir: first }];
}

function copyable(v) {
    if (Array.isArray(v)) {
        return v.map(function (x) { return x !== null && typeof x === 'object' ? x.name : x; }).join(', ');
    }
    return String(v);
}

/**
 * The funnel's menu, in Bootstrap's dropdown look but opened and closed
 * here. While it is open its keys are taken at window capture, so
 * Bootstrap's delegated dropdown handler never sees them.
 * Items: {label | html, icon, detail, run() | copy | open() -> items},
 * {header: html}, {divider: true}.
 */
function cellMenu(host) {
    var menu = null;
    var cell = null;
    var button = null;
    var list = [];

    function render(items) {
        list = items;
        menu.innerHTML = items.map(function (it, k) {
            if (it.divider) {
                return '<hr class="dropdown-divider">';
            }
            if (it.header !== undefined) {
                return '<div class="dropdown-header cq-menu-head">' + it.header + '</div>';
            }
            var icon = '<i class="fa-solid ' + it.icon + ' fa-fw" aria-hidden="true"></i>';
            return '<button type="button" class="dropdown-item cq-menu-item' + (it.trailing ? ' is-trailing' : '') + '" role="menuitem" data-k="' + k + '">' +
                (it.trailing ? '' : icon) + '<span class="cq-menu-label">' + (it.html || esc(it.label)) +
                (it.detail ? '<code class="cq-menu-detail">' + esc(it.detail) + '</code>' : '') + '</span>' +
                (it.trailing ? icon : '') + '</button>';
        }).join('');
        var first = menu.querySelector('.dropdown-item');
        if (first) {
            first.focus({ preventScroll: true });
        }
    }

    function place() {
        var r = button.getBoundingClientRect();
        var w = menu.offsetWidth;
        var h = menu.offsetHeight;
        var left = Math.max(8, Math.min(r.right - w, window.innerWidth - w - 8));
        var top = r.bottom + 4;
        if (top + h > window.innerHeight - 8 && r.top - 4 - h >= 8) {
            top = r.top - 4 - h;
        }
        menu.style.left = left + 'px';
        menu.style.top = top + 'px';
    }

    function close(refocus) {
        if (!menu) {
            return;
        }
        menu.remove();
        menu = null;
        window.removeEventListener('keydown', onKey, true);
        document.removeEventListener('pointerdown', onPointer, true);
        window.removeEventListener('scroll', onScroll, true);
        window.removeEventListener('resize', onScroll);
        cell.classList.remove('is-open');
        button.setAttribute('aria-expanded', 'false');
        if (refocus) {
            cell.focus({ preventScroll: true });
        }
        cell = null;
        button = null;
    }

    function onKey(e) {
        if (e.key === 'Escape') {
            e.preventDefault();
            e.stopPropagation();
            close(true);
            return;
        }
        if (!menu.contains(e.target)) {
            return;
        }
        var items = Array.prototype.slice.call(menu.querySelectorAll('.dropdown-item'));
        var at = items.indexOf(document.activeElement);
        var n = items.length;
        var to = null;
        if (e.key === 'ArrowDown') {
            to = (at + 1) % n;
        } else if (e.key === 'ArrowUp') {
            to = at <= 0 ? n - 1 : at - 1;
        } else if (e.key === 'Home') {
            to = 0;
        } else if (e.key === 'End') {
            to = n - 1;
        } else if (e.key === 'Tab') {
            e.preventDefault();
            e.stopPropagation();
            close(true);
            return;
        } else {
            return;
        }
        e.preventDefault();
        e.stopPropagation();
        if (n) {
            items[to].focus({ preventScroll: true });
        }
    }

    function onPointer(e) {
        if (!menu.contains(e.target) && !button.contains(e.target)) {
            close(false);
        }
    }

    // Follows its cell while the cell stays in sight (the grid scrolls a
    // half-hidden cell into view as it takes the focus); closes once it leaves
    function onScroll(e) {
        if (e && e.target && e.target.nodeType === 1 && menu.contains(e.target)) {
            return;
        }
        if (inSight(cell)) {
            place();
        } else {
            close(false);
        }
    }

    function inSight(td) {
        var r = td.getBoundingClientRect();
        var wrap = td.closest('.cq-grid-wrap');
        var box = wrap ? wrap.getBoundingClientRect() : { top: 0, left: 0, right: window.innerWidth, bottom: window.innerHeight };
        var head = wrap ? wrap.querySelector('thead') : null;
        var top = Math.max(0, box.top + (head ? head.offsetHeight : 0));
        return r.bottom > top && r.top < Math.min(box.bottom, window.innerHeight) &&
            r.right > Math.max(0, box.left) && r.left < Math.min(box.right, window.innerWidth);
    }

    function choose(e) {
        var b = e.target.closest('[data-k]');
        if (!b) {
            return;
        }
        var it = list[Number(b.dataset.k)];
        if (it.open) {
            render(it.open());
            place();
        } else if (it.copy !== undefined) {
            var flash = button;
            close(true);
            copyText(it.copy, flash);
        } else if (it.run) {
            close(true);
            it.run();
        }
    }

    function toggle(td, btn, items, keyboard) {
        var same = menu && cell === td;
        close(same && keyboard);
        if (same) {
            return;
        }
        cell = td;
        button = btn;
        menu = el('div', 'dropdown-menu show cq-menu');
        menu.setAttribute('role', 'menu');
        menu.setAttribute('data-bs-popper', 'static');
        menu.addEventListener('click', choose);
        host.appendChild(menu);
        render(items);
        place();
        td.classList.add('is-open');
        btn.setAttribute('aria-expanded', 'true');
        window.addEventListener('keydown', onKey, true);
        document.addEventListener('pointerdown', onPointer, true);
        window.addEventListener('scroll', onScroll, true);
        window.addEventListener('resize', onScroll);
    }

    return { toggle: toggle, close: close };
}

/**
 * The page in the shape its FORMAT gave it: table and flat are rows written
 * as CSV, no FORMAT is JSON (the records as MISP returns them for SELECT *).
 */
function asRan(output, model) {
    var n = model.columns.length;
    var cols = n + (n === 1 ? ' column' : ' columns');
    if (output === 'table' || output === 'flat') {
        return { file: 'csv', format: output, detail: 'CSV, ' + cols };
    }
    return { file: 'json', format: null, detail: model.raw ? 'JSON, the records as MISP returns them' : 'JSON, ' + cols };
}

function csvOf(columns, rows) {
    function c(v) {
        if (Array.isArray(v)) {
            v = v.map(function (t) { return t !== null && typeof t === 'object' ? t.name : t; }).join(',');
        }
        v = v === null || v === undefined ? '' : String(v);
        return /[",\n]/.test(v) ? '"' + v.replace(/"/g, '""') + '"' : v;
    }
    return [columns.map(c).join(',')].concat(rows.map(function (r) {
        return columns.map(function (col) { return c(r[col]); }).join(',');
    })).join('\n') + '\n';
}

/**
 * Rows: grid (column list or default columns), JSON of the raw rows for
 * SELECT *, CSV text for FORMAT flat; pager driven by `total`.
 * opts: {pack, baseurl, valueAddress(value), onPage(statement), onFilter(statement),
 *        onSelect(indices, {drawn, returned, clear}), unselectable(index) → reason or '',
 *        opens: {RecordType: true | {label, caret(link)}}, onOpen(link, cell)}
 * With onSelect, the grid draws a checkbox column over the rows it draws. A
 * linked record of a type in `opens` gets a caret and a menu entry that hand
 * it to onOpen, for the page to open it in place (openSpec()).
 */
function renderRows(r, opts) {
    opts = opts || {};
    var reply = r.reply;
    var model = gridModel(r, opts.pack);
    var root_ = el('div', 'cq-rows dk-index');
    var views = [{ id: 'grid', label: 'Grid', icon: 'fa-table-cells' }];
    if (model.raw) {
        views.push({ id: 'json', label: 'JSON', icon: 'fa-code' });
    }
    if (reply.output === 'flat') {
        views.unshift({ id: 'csv', label: 'CSV', icon: 'fa-file-csv' });
    }
    var bar = el('div', 'cq-bar');
    var seg = el('div', 'cq-seg');
    views.forEach(function (v) {
        var b = el('button', '', '<i class="fa-solid ' + v.icon + '"></i>' + v.label);
        b.type = 'button';
        b.dataset.view = v.id;
        seg.appendChild(b);
    });
    if (views.length > 1) {
        bar.appendChild(seg);
    }
    var info = el('div', 'cq-bar-info');
    bar.appendChild(info);
    var dl = el('div', 'dropdown cq-dl');
    var ran = asRan(reply.output, model);
    dl.innerHTML = '<button class="btn btn-sm btn-outline-secondary dropdown-toggle" type="button" data-bs-toggle="dropdown" aria-expanded="false">' +
        '<i class="fa-solid fa-download"></i><span>Download</span></button>' +
        '<ul class="dropdown-menu dropdown-menu-end">' +
        '<li><button class="dropdown-item cq-dl-ran" type="button" data-dl="ran"><i class="fa-solid ' + (ran.file === 'csv' ? 'fa-file-csv' : 'fa-file-code') + ' fa-fw"></i>' +
        '<span><span class="d-block">This page as it ran</span><span class="cq-dl-detail">' +
        (ran.format ? '<code>FORMAT ' + ran.format + '</code>' : 'No FORMAT') + ' · ' + esc(ran.detail) + '</span></span></button></li>' +
        '<li><hr class="dropdown-divider"></li>' +
        '<li><button class="dropdown-item" type="button" data-dl="csv"><i class="fa-solid fa-file-csv fa-fw"></i>This page as CSV</button></li>' +
        '<li><button class="dropdown-item" type="button" data-dl="json"><i class="fa-solid fa-file-code fa-fw"></i>This page as JSON</button></li>' +
        '<li><hr class="dropdown-divider"></li>' +
        '<li><span class="dropdown-item-text small text-body-secondary">Every match in a MISP format:<br>add <code>FORMAT csv</code>, <code>stix2</code>, …</span></li></ul>';
    bar.appendChild(dl);
    root_.appendChild(bar);
    dl.addEventListener('click', function (e) {
        var b = e.target.closest('[data-dl]');
        if (!b) {
            return;
        }
        var base = (r.table || 'rows') + '-' + new Date().toISOString().slice(0, 10);
        if ((b.dataset.dl === 'ran' ? ran.file : b.dataset.dl) === 'csv') {
            download(base + '.csv', csvOf(model.columns, model.rows), 'text/csv');
        } else {
            download(base + '.json', JSON.stringify(model.raw || model.rows, null, 2), 'application/json');
        }
    });

    (reply.warnings || []).forEach(function (w) {
        root_.appendChild(el('div', 'cq-warn', '<i class="fa-solid fa-triangle-exclamation"></i><span>' + esc(w) + '</span>'));
    });

    var body = el('div', 'cq-view');
    root_.appendChild(body);

    var paging = pagingOf(r.statement);
    var shown = reply.rows.length;
    var cap = Math.min(shown, GRID_CAP);
    var first = shown ? paging.offset + 1 : 0;
    var selectable = typeof opts.onSelect === 'function' && shown > 0;
    var selected = new Set();
    var lastPick = null;
    var pickable = new Set();
    for (var k = 0; selectable && k < cap; k++) {
        if (!blocked(k)) {
            pickable.add(k);
        }
    }
    info.innerHTML = shown
        ? 'Rows <b>' + fmtInt(first) + '–' + fmtInt(paging.offset + shown) + '</b>' +
            (reply.total === null ? '' : ' of <b>' + fmtInt(reply.total) + '</b>')
        : 'No rows';

    function drawGrid() {
        if (!shown) {
            body.innerHTML = '<div class="cq-empty"><i class="fa-regular fa-folder-open"></i><div><b>No rows match.</b><br>' +
                (paging.offset > 0 ? 'This page is past the last match.' : 'Loosen a condition, or check the values against DESCRIBE.') + '</div></div>';
            return;
        }
        var head = (selectable ? selectAllCell() : '') + '<th class="cq-rn" scope="col">#</th>' + model.columns.map(headerCell).join('');
        var rowsHtml = '';
        for (var i = 0; i < cap; i++) {
            var row = model.rows[i];
            var on = selectable && selected.has(i);
            rowsHtml += '<tr data-r="' + i + '"' + (selectable ? ' aria-selected="' + on + '"' + (on ? ' class="is-selected"' : '') : '') + '>' +
                (selectable ? selectCell(i, on) : '') +
                '<td class="cq-rn">' + fmtInt(paging.offset + i + 1) + '</td>' + model.columns.map(function (c, j) {
                var v = rowValue(row, c);
                var content = cell(c, v, levels, galaxies, rowHead(row));
                var link = cellLink(ctx, c, v, row);
                if (link) {
                    content = '<a class="cq-link" href="' + esc(link.href) + '" target="_blank" rel="noopener" tabindex="-1" title="Open ' +
                        esc(RECORD_LABEL[link.type] || link.type) + ' in a new tab">' + content + '<i class="fa-solid fa-arrow-up-right-from-square cq-ext" aria-hidden="true"></i></a>';
                    var open = openOf(link);
                    if (open) {
                        content += caretHTML(open, v);
                    }
                }
                if (isEmpty(v)) {
                    return '<td data-c="' + j + '"' + (i === 0 && j === 0 ? ' tabindex="0"' : '') + '>' + content + '</td>';
                }
                return '<td data-c="' + j + '" class="has-funnel"' + (i === 0 && j === 0 ? ' tabindex="0"' : '') + '>' + content +
                    '<button type="button" class="cq-funnel" tabindex="-1" aria-haspopup="menu" aria-label="Filter or copy this value" title="Filter or copy">' +
                    '<i class="fa-solid fa-filter" aria-hidden="true"></i></button></td>';
            }).join('') + '</tr>';
        }
        body.innerHTML = '<div class="cq-grid-wrap"><table class="cq-grid" role="grid" aria-label="Rows" aria-rowcount="' + (cap + 1) + '">' +
            '<thead><tr>' + head + '</tr></thead><tbody>' + rowsHtml + '</tbody></table></div>' +
            (shown > cap ? '<div class="cq-capnote"><i class="fa-solid fa-circle-info"></i>The grid shows the first ' + fmtInt(cap) +
                ' of ' + fmtInt(shown) + ' rows returned. Add a <code>LIMIT</code> to page through them.</div>' : '');
        syncSelection();
        fitLanes();
        if (!galaxyTypes && opts.galaxies && body.querySelector('.te-ctx .dk-chip.is-gx')) {
            opts.galaxies().then(function (list) {
                galaxyTypes = typesOf(list);
                redrawTags();
            });
        }
    }

    // Drawn before the page attaches it, so fitted a frame later
    function fitLanes() {
        requestAnimationFrame(function () {
            if (window.eventIndexCards) {
                window.eventIndexCards.fitLanes(Array.prototype.slice.call(body.querySelectorAll('.te-ctx[data-dk-lane]')));
            }
        });
    }

    function redrawTags() {
        body.querySelectorAll('.cq-grid td > .te-ctx').forEach(function (lane) {
            var td = lane.parentNode;
            var row = model.rows[Number(td.parentNode.dataset.r)];
            var column = model.columns[Number(td.dataset.c)];
            lane.outerHTML = cell(column, rowValue(row, column), levels, galaxies, rowHead(row));
        });
        fitLanes();
    }

    /** How the page opens this record in place, beside its link, or null. */
    function openOf(link) {
        return typeof opts.onOpen === 'function' ? openSpec(opts.opens, link) : null;
    }

    function linkOf(td) {
        var row = model.rows[Number(td.parentNode.dataset.r)];
        var column = model.columns[Number(td.dataset.c)];
        return cellLink(ctx, column, rowValue(row, column), row);
    }

    /* The selection: over the rows drawn; a row the page cannot act on stays unticked, saying why. */
    function blocked(i) {
        return opts.unselectable ? (opts.unselectable(i) || '') : '';
    }

    function selectAllCell() {
        return '<th class="cq-sel" scope="col" data-c="-1"><input type="checkbox" class="form-check-input cq-sel-all" tabindex="-1"' +
            ' aria-label="Select every row shown" title="Select every row shown"></th>';
    }

    function selectCell(i, on) {
        var why = blocked(i);
        return '<td class="cq-sel" data-c="-1"><input type="checkbox" class="form-check-input cq-sel-box" tabindex="-1" aria-label="Select row ' +
            fmtInt(paging.offset + i + 1) + '"' + (on ? ' checked' : '') + (why ? ' disabled title="' + esc(why) + '"' : '') + '></td>';
    }

    function syncSelection() {
        if (!selectable) {
            return;
        }
        body.querySelectorAll('.cq-grid tbody tr').forEach(function (tr) {
            var on = selected.has(Number(tr.dataset.r));
            var box = tr.querySelector('.cq-sel-box');
            if (box) {
                box.checked = on;
            }
            tr.classList.toggle('is-selected', on);
            tr.setAttribute('aria-selected', String(on));
        });
        var all = body.querySelector('.cq-sel-all');
        if (all) {
            all.checked = pickable.size > 0 && selected.size === pickable.size;
            all.indeterminate = selected.size > 0 && selected.size < pickable.size;
            all.disabled = pickable.size === 0;
        }
    }

    function reportSelection() {
        syncSelection();
        opts.onSelect(Array.from(selected).sort(function (a, b) { return a - b; }), { drawn: cap, returned: shown, clear: clearSelection });
    }

    function clearSelection() {
        selected.clear();
        lastPick = null;
        reportSelection();
    }

    /** Ticks or unticks a row; with range, every row from the last one picked. */
    function pick(i, on, range) {
        var from = range && lastPick !== null ? Math.min(lastPick, i) : i;
        var to = range && lastPick !== null ? Math.max(lastPick, i) : i;
        for (var n = from; n <= to; n++) {
            if (!pickable.has(n)) {
                continue;
            }
            if (on) {
                selected.add(n);
            } else {
                selected.delete(n);
            }
        }
        lastPick = i;
        reportSelection();
    }

    function pickAll() {
        var every = selected.size === pickable.size;
        selected.clear();
        if (!every) {
            pickable.forEach(function (n) { selected.add(n); });
        }
        lastPick = null;
        reportSelection();
    }

    function toggleCell(cell, range) {
        if (cell.tagName === 'TH') {
            pickAll();
            return;
        }
        var i = Number(cell.parentNode.dataset.r);
        if (pickable.has(i)) {
            pick(i, !selected.has(i), range);
        } else {
            syncSelection();
        }
    }

    /** What a tag popover is headed with: the row's id and what names it. */
    function rowHead(row) {
        var label = ['info', 'Event.info', 'value', 'name'].map(function (c) { return rowValue(row, c); })
            .filter(function (v) { return v !== null && v !== undefined && v !== '' && typeof v !== 'object'; })[0];
        var id = rowValue(row, 'id');
        return { id: id === null || id === undefined ? '' : String(id), label: label === undefined ? 'Tags' : String(label) };
    }

    var ctx = {
        pack: opts.pack,
        tableName: r.table,
        baseurl: opts.baseurl || '',
        address: opts.valueAddress || null,
    };
    var tableDef = opts.pack && opts.pack.tables[r.table];
    var levels = levelNames(opts.pack, r.table);
    var galaxies = galaxiesOf(model.raw);
    var menu = cellMenu(root_);
    var order = orderOf(r.statement);
    var canSort = !!opts.onPage && !!tableDef;

    /** What the column's field means, above the header's sort state. */
    function headerTitle(c, state) {
        var field = columnField(tableDef, r.table, c);
        var sentence = field !== null ? tableDef.fields[field].description : '';
        return [sentence, state].filter(Boolean).join('\n');
    }

    /** A header sorts when MISP can sort the table by its column; its arrow reads the statement's ORDER BY. */
    function headerCell(c, j) {
        var name = canSort ? sortNameOf(tableDef, c) : null;
        var label = '<span>' + esc(c) + '</span>';
        if (name === null) {
            var why = '';
            if (canSort) {
                why = Object.keys(tableDef.order_by || {}).length ? r.table + ' cannot be sorted by this column' : r.table + ' cannot be sorted';
            }
            var plain = headerTitle(c, why);
            return '<th scope="col" data-c="' + j + '"' + (plain ? ' title="' + esc(plain) + '"' : '') + '>' + label + '</th>';
        }
        var at = keyIndex(tableDef, order, name);
        var dir = at === -1 ? null : (order[at].dir === 'DESC' ? 'DESC' : 'ASC');
        var title = headerTitle(c, dir === null
            ? 'Sort by ' + name + ' · Shift+click adds it to the order'
            : 'ORDER BY ' + name + ' ' + dir + ' · click to flip · Shift+click for another key');
        return '<th scope="col" data-c="' + j + '" class="cq-sortable' + (dir ? ' is-sorted' : '') + '" data-sort="' + esc(name) +
            '" aria-sort="' + (dir === null ? 'none' : dir === 'DESC' ? 'descending' : 'ascending') + '" title="' + esc(title) + '">' + label +
            '<i class="fa-solid ' + (dir === null ? 'fa-sort' : dir === 'DESC' ? 'fa-arrow-down-long' : 'fa-arrow-up-long') + ' cq-sort-icon" aria-hidden="true"></i>' +
            (dir && order.length > 1 ? '<span class="cq-sort-rank">' + (at + 1) + '</span>' : '') + '</th>';
    }

    function sortBy(th, add) {
        var next = setOrder(r.statement, nextOrder(tableDef, order, th.dataset.sort, add));
        if (next !== null) {
            opts.onPage(next);
        }
    }

    body.addEventListener('mousedown', function (e) {
        if (e.shiftKey && e.target.closest('th.cq-sortable, .cq-sel')) {
            e.preventDefault();
        }
    });

    /** What the funnel of a cell offers: filters (when the page takes them), then Copy. */
    function menuFor(td) {
        var i = Number(td.parentNode.dataset.r);
        var column = model.columns[Number(td.dataset.c)];
        var value = rowValue(model.rows[i], column);
        var canFilter = !!opts.onFilter && tableDef;
        if (column.split('.').pop().toLowerCase() === 'tag') {
            return tagMenu(splitTags(value), column, canFilter);
        }
        var items = (canFilter ? filterEntries(tableDef, r.table, column, value) : []).map(filterItem);
        if (items.length) {
            items.push({ divider: true });
        }
        items.push({ label: 'Copy value', icon: 'fa-copy', copy: copyable(value) });
        var link = linkOf(td);
        var open = openOf(link);
        if (open) {
            items.unshift({ label: 'Open ' + open.label, icon: 'fa-up-right-and-down-left-from-center', run: function () {
                opts.onOpen(link, td);
            } }, { divider: true });
        }
        return items;
    }

    function menuChip(t) {
        return laneChips(tagLane([t], galaxies)) || esc(t.name);
    }

    function tagMenu(tags, column, canFilter) {
        function entriesOf(t) {
            var items = [{ header: menuChip(t) }];
            (canFilter ? tagEntries(tableDef, r.table, column, t.name) : []).forEach(function (e) { items.push(filterItem(e)); });
            items.push({ label: 'Copy the tag name', icon: 'fa-copy', copy: t.name });
            return items;
        }
        if (tags.length === 1) {
            return entriesOf(tags[0]);
        }
        var items = [{ header: 'Tags' }];
        tags.forEach(function (t) {
            items.push({ html: menuChip(t), icon: 'fa-chevron-right', trailing: true, open: function () {
                return [{ label: 'All tags', icon: 'fa-chevron-left', open: function () { return tagMenu(tags, column, canFilter); } }]
                    .concat(entriesOf(t));
            } });
        });
        items.push({ divider: true });
        items.push({ label: 'Copy every tag name', icon: 'fa-copy', copy: tags.map(function (t) { return t.name; }).join(', ') });
        return items;
    }

    function filterItem(e) {
        return { label: e.label, icon: e.icon, detail: e.condition, run: function () {
            var next = addCondition(r.statement, e.condition);
            if (next === null) {
                return;
            }
            if (paging.limit && paging.offset > 0) {
                next = rewritePaging(next, paging.limit, 0);
            }
            opts.onFilter(next);
        } };
    }

    body.addEventListener('click', function (e) {
        var sel = selectable && e.target.closest('.cq-sel');
        if (sel && body.contains(sel)) {
            focusCell(sel, true);
            toggleCell(sel, e.shiftKey);
            return;
        }
        var open = e.target.closest('.cq-open');
        if (open && body.contains(open)) {
            var cellOf = open.closest('td');
            focusCell(cellOf, false);
            opts.onOpen(linkOf(cellOf), cellOf);
            return;
        }
        var b = e.target.closest('.cq-funnel');
        if (b && body.contains(b)) {
            var td = b.closest('td');
            focusCell(td, false);
            menu.toggle(td, b, menuFor(td), false);
            return;
        }
        var th = e.target.closest('th.cq-sortable');
        if (th && body.contains(th)) {
            sortBy(th, e.shiftKey);
        }
    });

    function rowAbove(tr) {
        return tr.previousElementSibling || (tr.parentNode.tagName === 'TBODY' ? tr.closest('table').tHead.rows[0] : null);
    }

    function rowBelow(tr) {
        return tr.nextElementSibling || (tr.parentNode.tagName === 'THEAD' ? tr.closest('table').tBodies[0].rows[0] : null);
    }

    function focusCell(td, focus) {
        var grid = body.querySelector('.cq-grid');
        var was = grid && grid.querySelector('[data-c][tabindex="0"]');
        if (was && was !== td) {
            was.removeAttribute('tabindex');
        }
        td.setAttribute('tabindex', '0');
        if (focus) {
            td.focus();
        }
    }

    body.addEventListener('keydown', function (e) {
        var td = e.target;
        // A view opened from a caret by keyboard leaves the focus on it: Escape
        // and the grid's moves take it back to the cell
        if (td.classList && td.classList.contains('cq-open') && body.contains(td)) {
            if (e.key !== 'Escape' && !/^(Arrow|Home$|End$)/.test(e.key)) {
                return;
            }
            td = td.closest('td[data-c]');
            focusCell(td, true);
            if (e.key === 'Escape') {
                return;
            }
        }
        if (!td.matches || !td.matches('.cq-grid td[data-c], .cq-grid th[data-c]')) {
            return;
        }
        var tr = td.parentNode;
        var c = Number(td.dataset.c);
        var next = null;
        var above = null;
        var below = null;
        if (c === -1 && (e.key === ' ' || e.key === 'Enter')) {
            e.preventDefault();
            toggleCell(td, e.shiftKey);
            return;
        }
        switch (e.key) {
            case 'ArrowLeft':
                next = tr.querySelector('[data-c="' + (c - 1) + '"]');
                break;
            case 'ArrowRight':
                next = tr.querySelector('[data-c="' + (c + 1) + '"]');
                break;
            case 'ArrowUp':
                above = rowAbove(tr);
                next = above && above.querySelector('[data-c="' + c + '"]');
                break;
            case 'ArrowDown':
                below = rowBelow(tr);
                next = below && below.querySelector('[data-c="' + c + '"]');
                break;
            case 'Home':
                next = tr.querySelector('[data-c="0"]');
                break;
            case 'End':
                next = tr.querySelector('[data-c="' + (model.columns.length - 1) + '"]');
                break;
            case 'Enter':
                e.preventDefault();
                if (td.tagName === 'TH') {
                    if (td.classList.contains('cq-sortable')) {
                        sortBy(td, e.shiftKey);
                    }
                    return;
                }
                var a = td.querySelector('.cq-link');
                if ((e.ctrlKey || e.metaKey) && a) {
                    window.open(a.href, '_blank', 'noopener');
                } else if (!e.ctrlKey && !e.metaKey && td.classList.contains('has-funnel')) {
                    menu.toggle(td, td.querySelector('.cq-funnel'), menuFor(td), true);
                }
                return;
            default:
                return;
        }
        e.preventDefault();
        if (next) {
            focusCell(next, true);
        }
    });
    function drawJson() {
        body.innerHTML = '<pre class="cq-json">' + jsonHTML(model.raw.slice(0, 50)) + '</pre>' +
            (model.raw.length > 50 ? '<div class="cq-capnote">First 50 rows of ' + fmtInt(model.raw.length) + '. Download the page for all of them.</div>' : '');
    }
    function drawCsv() {
        body.innerHTML = '<pre class="cq-csv">' + esc(csvOf(model.columns, model.rows.slice(0, 200))) + '</pre>';
    }
    function select(id) {
        seg.querySelectorAll('button').forEach(function (b) { b.classList.toggle('active', b.dataset.view === id); });
        if (id === 'grid') {
            drawGrid();
        } else if (id === 'json') {
            drawJson();
        } else {
            drawCsv();
        }
    }
    seg.addEventListener('click', function (e) {
        var b = e.target.closest('button');
        if (b) {
            select(b.dataset.view);
        }
    });
    select(views[0].id);

    if (paging.limit && opts.onPage) {
        root_.appendChild(pager(r, paging, reply.total, shown, opts.onPage));
    } else if (!paging.limit && reply.total !== null && reply.total > shown) {
        root_.appendChild(el('div', 'cq-pager cq-pager-note', '<i class="fa-solid fa-circle-info"></i>Without a LIMIT there is no pager.'));
    }
    return root_;
}

function pager(r, paging, total, shown, onPage) {
    var limit = paging.limit;
    var page = Math.floor(paging.offset / limit) + 1;
    var known = total !== null;
    var pages = known ? Math.max(1, Math.ceil(total / limit)) : null;
    var hasNext = known ? page < pages : shown >= limit;
    var wrap = el('div', 'cq-pager');
    var sizes = [10, 20, 50, 100];
    if (sizes.indexOf(limit) === -1) {
        sizes.push(limit);
        sizes.sort(function (a, b) { return a - b; });
    }
    wrap.innerHTML =
        '<label class="cq-size">Rows per page <select class="form-select form-select-sm">' +
        sizes.map(function (s) { return '<option' + (s === limit ? ' selected' : '') + '>' + s + '</option>'; }).join('') +
        '</select></label>' +
        '<span class="cq-page-of">Page <b>' + fmtInt(page) + '</b>' + (known ? ' of ' + fmtInt(pages) : '') + '</span>' +
        '<div class="btn-group btn-group-sm" role="group" aria-label="Pages">' +
        '<button type="button" class="btn btn-outline-secondary" data-go="first" title="First page"' + (page <= 1 ? ' disabled' : '') + '><i class="fa-solid fa-angles-left"></i></button>' +
        '<button type="button" class="btn btn-outline-secondary" data-go="prev" title="Previous page"' + (page <= 1 ? ' disabled' : '') + '><i class="fa-solid fa-angle-left"></i></button>' +
        '<button type="button" class="btn btn-outline-secondary" data-go="next" title="Next page"' + (hasNext ? '' : ' disabled') + '><i class="fa-solid fa-angle-right"></i></button>' +
        (known ? '<button type="button" class="btn btn-outline-secondary" data-go="last" title="Last page"' + (page >= pages ? ' disabled' : '') + '><i class="fa-solid fa-angles-right"></i></button>' : '') +
        '</div>' +
        '<span class="cq-pager-hint" title="The pager rewrites LIMIT and OFFSET in the statement">LIMIT ' + limit + (paging.offset ? ' OFFSET ' + fmtInt(paging.offset) : '') + '</span>';
    wrap.addEventListener('click', function (e) {
        var b = e.target.closest('[data-go]');
        if (!b || b.disabled) {
            return;
        }
        var target = { first: 1, prev: page - 1, next: page + 1, last: pages }[b.dataset.go];
        onPage(rewritePaging(r.statement, limit, (target - 1) * limit));
    });
    wrap.querySelector('select').addEventListener('change', function (e) {
        var size = Number(e.target.value);
        onPage(rewritePaging(r.statement, size, Math.floor(paging.offset / size) * size));
    });
    return wrap;
}

function renderCount(r) {
    var table = r.table || '';
    var wrap = el('div', 'cq-count');
    wrap.innerHTML = '<div class="cq-count-num">' + fmtInt(r.reply.count) + '</div>' +
        '<div class="cq-count-label">' + (r.reply.count === 1 ? 'match' : 'matches') + ' in <code>' + esc(table) + '</code>' +
        (table === 'events' ? '<span class="cq-count-note">counted as the events you can see</span>' : '') +
        '</div>';
    return wrap;
}

function renderDescribe(r, opts) {
    opts = opts || {};
    var name = r.reply.table;
    var t = r.reply;
    var lt = opts.pack && opts.pack.tables[name];
    var wrap = el('div', 'cq-describe');
    var head = el('div', 'cq-desc-head');
    head.innerHTML = '<div><code class="cq-desc-endpoint">POST ' + esc(lt ? lt.endpoint : '') + '</code><span class="cq-desc-text">' + esc(lt ? lt.description : '') + '</span></div>' +
        '<div class="cq-desc-filter"><i class="fa-solid fa-magnifying-glass"></i><input type="search" class="form-control form-control-sm" placeholder="Filter fields" aria-label="Filter fields"></div>';
    wrap.appendChild(head);
    var levels = {};
    Object.keys(t.fields).forEach(function (f) { t.fields[f].level.forEach(function (l) { levels[l] = 1; }); });
    var rows = Object.keys(t.fields).map(function (f) {
        var d = t.fields[f];
        var sentence = d.description || (lt && lt.fields[f] && lt.fields[f].description) || '';
        return '<tr data-f="' + esc(f.toLowerCase()) + '"><td><button type="button" class="cq-field" data-insert="' + esc(f.replace('<key>', '')) + '" title="Insert into the writer">' + esc(f) + '</button>' +
            (sentence ? '<div class="cq-desc-inline">' + esc(sentence) + '</div>' : '') + '</td>' +
            '<td><span class="mql-type mql-type-' + esc(d.type) + '">' + esc(d.type) + '</span></td>' +
            '<td class="cq-ops">' + d.operators.map(function (o) { return '<code>' + esc(o) + '</code>'; }).join('') + '</td>' +
            '<td>' + d.level.map(function (l) { return '<span class="cq-level">' + esc(l) + '</span>'; }).join('') + '</td>' +
            '<td class="cq-desc-cell">' + esc(sentence) + '</td></tr>';
    }).join('');
    var table = el('div', 'cq-grid-wrap cq-desc-grid');
    table.innerHTML = '<table class="cq-grid"><thead><tr><th>Field</th><th>Type</th><th>Operators</th><th>Level</th><th>Description</th></tr></thead><tbody>' + rows + '</tbody></table>';
    wrap.appendChild(table);
    var sortNames = t.order_by || [];
    var foot = el('div', 'cq-desc-foot');
    foot.innerHTML = '<div><span class="cq-foot-label">ORDER BY</span>' + (sortNames.length
        ? sortNames.map(function (s) { return '<code>' + esc(s) + '</code>'; }).join('')
        : '<span class="text-body-secondary">this table cannot be sorted</span>') + '</div>' +
        '<div><span class="cq-foot-label">Limits</span>' + Object.keys(r.reply.limits).map(function (k) {
            return '<span class="cq-limit">' + esc(k.replace('max_', '').replace('_', ' ')) + ' <b>' + esc(r.reply.limits[k]) + '</b></span>';
        }).join('') + '</div>';
    wrap.appendChild(foot);
    head.querySelector('input').addEventListener('input', function (e) {
        var q = e.target.value.toLowerCase();
        table.querySelectorAll('tbody tr').forEach(function (tr) {
            tr.hidden = q && tr.dataset.f.indexOf(q) === -1;
        });
    });
    table.addEventListener('click', function (e) {
        var b = e.target.closest('[data-insert]');
        if (b && opts.onInsert) {
            opts.onInsert(b.dataset.insert);
        }
    });
    return wrap;
}

function renderTables(r, opts) {
    opts = opts || {};
    var pack = opts.pack || { tables: {} };
    var wrap = el('div', 'cq-tables');
    wrap.innerHTML = r.reply.tables.map(function (name) {
        var t = pack.tables[name];
        return '<button type="button" class="cq-table" data-table="' + esc(name) + '"><span class="cq-table-name"><i class="fa-solid fa-table"></i>' + esc(name) + '</span>' +
            '<span class="cq-table-desc">' + esc(t ? t.description : '') + '</span><code>' + esc(t ? t.endpoint : '') + '</code></button>';
    }).join('');
    wrap.addEventListener('click', function (e) {
        var b = e.target.closest('[data-table]');
        if (b && opts.onPick) {
            opts.onPick(b.dataset.table);
        }
    });
    return wrap;
}

function renderWhoami(r) {
    var b = r.reply;
    return el('div', 'cq-whoami', '<span class="cq-avatar"><i class="fa-solid fa-user"></i></span>' +
        '<dl><dt>Email</dt><dd>' + esc(b.email) + '</dd><dt>Role</dt><dd>' + esc(b.role) + '</dd><dt>Organisation</dt><dd>' + esc(b.org) + '</dd></dl>');
}

function renderExport(r) {
    var wrap = el('div', 'cq-export');
    var lines = r.preview === null ? [] : r.preview.split('\n');
    var more = lines.length > 14 || r.size > r.previewSize;
    var count = r.total === null ? '' : ' · ' + fmtInt(r.total) + ' ' + (r.total === 1 ? 'match' : 'matches');
    wrap.innerHTML = '<div class="cq-export-head">' +
        '<span class="cq-file"><i class="fa-solid fa-file-lines"></i><span class="cq-file-ext">' + esc(r.format) + '</span></span>' +
        '<div class="cq-export-meta"><b>' + esc(r.filename) + '</b><span>' + esc(r.contentType) + ' · ' + bytes(r.size) + count +
        '</span><span class="cq-export-note">MISP\'s own export, as restSearch sends it.</span></div>' +
        '<button type="button" class="btn btn-primary btn-sm cq-export-dl"><i class="fa-solid fa-download"></i>Download</button></div>' +
        (r.preview === null ? '<div class="cq-capnote">Binary file: no preview.</div>'
            : '<pre class="cq-export-preview">' + esc(lines.slice(0, 14).join('\n')) + (more ? '\n…' : '') + '</pre>');
    wrap.querySelector('.cq-export-dl').addEventListener('click', function () {
        download(r.filename, r.blob);
    });
    return wrap;
}

var ANSWERED_BY_MISP = {
    show_tables: '<b>SHOW TABLES</b> is answered by MISP from the tables your role may query: no search is sent.',
    whoami: '<b>WHOAMI</b> is answered by MISP from your session: no search is sent.'
};

/** What a statement compiles to, from explain: nothing was run. */
function renderPlan(r, opts) {
    opts = opts || {};
    var p = r.plan;
    var wrap = el('div', 'cq-plan');
    if (!p) {
        wrap.innerHTML = '<div class="cq-client"><i class="fa-solid fa-circle-info"></i><span>No statement here, only comments.</span></div>';
        return wrap;
    }
    if (p.kind === 'use' || p.kind === 'show_databases') {
        wrap.innerHTML = '<div class="cq-client"><i class="fa-solid fa-terminal"></i><span><b>' + (p.kind === 'use' ? 'USE' : 'SHOW DATABASES') +
            '</b> switches between MISP servers: it runs in the mispql CLI. This console queries this MISP only.</span></div>';
        return wrap;
    }
    if (ANSWERED_BY_MISP[p.kind]) {
        wrap.innerHTML = '<div class="cq-client"><i class="fa-solid fa-circle-info"></i><span>' + ANSWERED_BY_MISP[p.kind] + '</span></div>';
        return wrap;
    }
    var facts = [];
    if (p.request) {
        facts.push(['Sends', '<span class="cq-method cq-method-' + esc(p.request.method.toLowerCase()) + '">' + esc(p.request.method) + '</span>' +
            '<code>' + esc(p.request.endpoint) + '</code>']);
    }
    if (p.kind === 'count') {
        facts.push(['Returns', 'the number of matches']);
    } else if (p.kind === 'describe') {
        facts.push(['Returns', 'the table\'s fields, sort names and limits']);
    } else if (p.kind === 'search') {
        var format = p.request && p.request.body ? p.request.body.returnFormat : '';
        facts.push(['Returns', p.output === 'verbatim'
            ? 'MISP\'s <code>' + esc(format) + '</code> export, as a file'
            : { table: 'rows, as a table', flat: 'rows, flattened' }[p.output] || 'rows']);
        var lt = opts.pack && opts.pack.tables[p.table];
        var columns = p.columns;
        var note = '';
        if (!columns && p.output === 'table' && lt && lt.default_columns) {
            columns = lt.default_columns;
            note = '<span class="cq-plan-note">the table\'s default:</span>';
        }
        if (p.output !== 'verbatim') {
            facts.push(['Columns', columns
                ? note + columns.map(function (c) { return '<code class="cq-chip">' + esc(c) + '</code>'; }).join('')
                : 'every field']);
        }
        if (p.skip > 0) {
            facts.push(['Skips', 'the first ' + fmtInt(p.skip) + (p.skip === 1 ? ' row' : ' rows') + ' of page ' + esc(p.request.body.page)]);
        }
    }
    wrap.innerHTML = '<dl class="cq-plan-facts">' + facts.map(function (f) {
        return '<div><dt>' + f[0] + '</dt><dd>' + f[1] + '</dd></div>';
    }).join('') + '</dl>';
    return wrap;
}

/** A request MISP refused before reading the statement, or no answer at all. */
function renderFailure(r) {
    return el('div', 'cq-error cq-failure', '<div class="cq-client"><i class="fa-solid fa-plug-circle-xmark"></i><span>' +
        esc(r.message) + '</span></div>');
}

var CODE_HELP = {
    syntax: 'The statement does not parse.',
    unknown_table: 'No such table.',
    wrong_table: 'A field qualified with another table.',
    not_sortable: 'Not a sort name of this table.',
    bad_clause: 'A clause this statement cannot take.',
    missing_clause: 'A clause this statement needs.',
    client_statement: 'Runs in the mispql CLI.',
    limit_exceeded: 'Past one of the limits.',
    unknown_field: 'Not a field of this table.',
    unknown_operator: 'An operator this field does not take.',
    bad_type: 'A value of the wrong type.',
    bad_shape: 'A condition MISP cannot evaluate in this place.'
};

function renderError(r, opts) {
    opts = opts || {};
    var wrap = el('div', 'cq-error');
    var client = r.errors.length === 1 && r.errors[0].code === 'client_statement';
    if (client) {
        wrap.classList.add('is-client');
        wrap.innerHTML = '<div class="cq-client"><i class="fa-solid fa-terminal"></i><span><b>' +
            esc(r.statement.trim().split(/\s+/)[0].toUpperCase() === 'USE' ? 'USE' : 'SHOW DATABASES') +
            '</b> switches between MISP servers: it runs in the mispql CLI. This console queries this MISP only.</span></div>';
        return wrap;
    }
    if (!opts.hideStatement) {
        var code = el('div', 'cq-err-stmt');
        code.innerHTML = highlight(r.statement, r.errors);
        wrap.appendChild(code);
    }
    var list = el('ol', 'cq-err-list');
    list.innerHTML = r.errors.map(function (e, i) {
        var lc = T.lineCol(r.statement, e.from);
        return '<li><button type="button" class="cq-err-item" data-i="' + i + '">' +
            '<span class="cq-err-code" title="' + esc(CODE_HELP[e.code] || '') + '">' + esc(e.code) + '</span>' +
            '<span class="cq-err-msg">' + esc(e.message) + '</span>' +
            '<span class="cq-err-pos">line ' + lc.line + ', col ' + lc.col + '</span>' +
            (e.path ? '<code class="cq-err-path">' + esc(e.path) + '</code>' : '') + '</button></li>';
    }).join('');
    wrap.appendChild(list);
    list.addEventListener('click', function (e) {
        var b = e.target.closest('[data-i]');
        if (b && opts.onLocate) {
            opts.onLocate(r.errors[Number(b.dataset.i)]);
        }
    });
    return wrap;
}

function highlight(text, errors) {
    return highlightHTML(text, (errors || []).map(function (e) {
        return { start: e.from, end: e.to, code: e.code, message: e.message };
    }));
}

function render(r, opts) {
    switch (r.kind) {
        case 'rows': return renderRows(r, opts);
        case 'count': return renderCount(r, opts);
        case 'describe': return renderDescribe(r, opts);
        case 'tables': return renderTables(r, opts);
        case 'whoami': return renderWhoami(r, opts);
        case 'export': return renderExport(r, opts);
        case 'plan': return renderPlan(r, opts);
        case 'failure': return renderFailure(r, opts);
        default: return renderError(r, opts);
    }
}

export {
    render,
    openSpec,
    highlight,
    summary,
    isClient,
    kindIcon,
    cellLink,
    columnField,
    filterEntries,
    tagEntries,
    sortNameOf,
    nextOrder,
    levelNames,
    tagLane,
    tagParts,
    asRan,
};
