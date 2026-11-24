/*
 * MispQL console: one view per kind of reply. Each takes the result and
 * its options and returns an element; none reads the page around it.
 */

import * as T from './tokens.mjs';
import { highlightHTML } from './writer.mjs';
import { el, esc, fmtInt, ago, bytes, download, jsonHTML } from './util.mjs';

var DISTRIBUTION = ['Your organisation only', 'This community only', 'Connected communities', 'All communities', 'Sharing group', 'Inherit event'];

var THREAT = { 1: 'High', 2: 'Medium', 3: 'Low', 4: 'Undefined' };

var ANALYSIS = { 0: 'Initial', 1: 'Ongoing', 2: 'Complete' };

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
            return typeof t === 'object' ? { name: String(t.name), colour: t.colour } : { name: String(t), colour: null };
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

function tagColour(name) {
    var fixed = {
        'tlp:red': '#CC0033', 'tlp:amber': '#FFC000', 'tlp:amber+strict': '#FFC000', 'tlp:green': '#339900',
        'tlp:clear': '#ffffff', 'tlp:white': '#ffffff'
    };
    if (fixed[name]) {
        return fixed[name];
    }
    return name.indexOf('misp-galaxy:') === 0 ? '#0088cc' : '#6c757d';
}

function textOn(hex) {
    var c = hex.replace('#', '');
    if (c.length === 3) {
        c = c.split('').map(function (x) { return x + x; }).join('');
    }
    var r = parseInt(c.slice(0, 2), 16);
    var g = parseInt(c.slice(2, 4), 16);
    var b = parseInt(c.slice(4, 6), 16);
    return (r * 299 + g * 587 + b * 114) / 1000 > 150 ? '#111' : '#fff';
}

function tagChip(t) {
    var colour = t.colour || tagColour(t.name);
    var galaxy = t.name.indexOf('misp-galaxy:') === 0;
    var label = galaxy ? t.name.replace(/^misp-galaxy:/, '') : t.name;
    return '<span class="cq-tag' + (galaxy ? ' is-galaxy' : '') + '" style="--tag:' + esc(colour) + ';--tag-fg:' + textOn(colour) +
        '" title="' + esc(t.name) + '">' + (galaxy ? '<i class="fa-solid fa-earth-europe"></i>' : '') + esc(label) + '</span>';
}

var TIME_COLUMN = /(^|\.)(timestamp|publish_timestamp|event_timestamp)$/i;

var BOOL_TRUE = '<span class="cq-bool is-true"><i class="fa-solid fa-check"></i>true</span>';

var BOOL_FALSE = '<span class="cq-bool">false</span>';

function cell(column, value) {
    var base = column.split('.').pop().toLowerCase();
    if (value === null || value === undefined || value === '') {
        return '<span class="cq-null">—</span>';
    }
    if (base === 'tag') {
        var tags = splitTags(value);
        return tags.length ? '<span class="cq-tags">' + tags.map(tagChip).join('') + '</span>' : '<span class="cq-null">—</span>';
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
    if (base === 'distribution' && DISTRIBUTION[value] !== undefined) {
        return '<span class="cq-enum" title="' + esc(DISTRIBUTION[value]) + '"><b>' + esc(value) + '</b>' + esc(DISTRIBUTION[value]) + '</span>';
    }
    if (base === 'threat_level_id' && THREAT[value]) {
        return '<span class="cq-threat cq-threat-' + esc(value) + '">' + esc(THREAT[value]) + '</span>';
    }
    if (base === 'analysis' && ANALYSIS[value] !== undefined) {
        return '<span class="cq-enum"><b>' + esc(value) + '</b>' + esc(ANALYSIS[value]) + '</span>';
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

/** The statement with its LIMIT and OFFSET set, rewritten through the tokens. */
function rewritePaging(statement, limit, offset) {
    var toks = T.significant(T.tokenize(statement));
    var limitTok = null;
    var offsetTok = null;
    var formatTok = null;
    for (var i = 0; i < toks.length; i++) {
        var t = toks[i];
        if (t.kind === 'keyword' && t.value === 'LIMIT' && toks[i + 1] && toks[i + 1].kind === 'number') {
            limitTok = { kw: t, num: toks[i + 1] };
        }
        if (t.kind === 'keyword' && t.value === 'OFFSET' && toks[i + 1] && toks[i + 1].kind === 'number') {
            offsetTok = { kw: t, num: toks[i + 1] };
        }
        if (t.kind === 'keyword' && t.value === 'FORMAT') {
            formatTok = t;
        }
    }
    var edits = [];
    var clause = offset > 0 ? ' OFFSET ' + offset : '';
    if (limitTok) {
        edits.push({ from: limitTok.num.start, to: limitTok.num.end, text: String(limit) });
        if (offsetTok) {
            edits.push(offset > 0
                ? { from: offsetTok.num.start, to: offsetTok.num.end, text: String(offset) }
                : { from: limitTok.num.end, to: offsetTok.num.end, text: '' });
        } else if (offset > 0) {
            edits.push({ from: limitTok.num.end, to: limitTok.num.end, text: clause });
        }
    } else {
        var at = formatTok ? formatTok.start : (toks.length ? toks[toks.length - 1].end : statement.length);
        if (!formatTok && toks.length && toks[toks.length - 1].value === ';') {
            at = toks[toks.length - 1].start;
        }
        edits.push({ from: at, to: at, text: (formatTok ? '' : ' ') + 'LIMIT ' + limit + clause + (formatTok ? ' ' : '') });
    }
    edits.sort(function (a, b) { return b.from - a.from; });
    var out = statement;
    edits.forEach(function (e) { out = out.slice(0, e.from) + e.text + out.slice(e.to); });
    return out;
}

function pagingOf(statement) {
    var toks = T.significant(T.tokenize(statement));
    var limit = null;
    var offset = 0;
    for (var i = 0; i < toks.length - 1; i++) {
        if (toks[i].kind === 'keyword' && toks[i + 1].kind === 'number') {
            if (toks[i].value === 'LIMIT') {
                limit = Number(toks[i + 1].value);
            }
            if (toks[i].value === 'OFFSET') {
                offset = Number(toks[i + 1].value);
            }
        }
    }
    return { limit: limit, offset: offset };
}

/**
 * Rows: grid (column list or default columns), JSON of the raw rows for
 * SELECT *, CSV text for FORMAT flat; pager driven by `total`.
 * opts: {onPage(statement), compact}
 */
function renderRows(r, opts) {
    opts = opts || {};
    var reply = r.reply;
    var model = gridModel(r, opts.pack);
    var root_ = el('div', 'cq-rows');
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
    dl.innerHTML = '<button class="btn btn-sm btn-outline-secondary dropdown-toggle" type="button" data-bs-toggle="dropdown" aria-expanded="false">' +
        '<i class="fa-solid fa-download"></i><span>Download</span></button>' +
        '<ul class="dropdown-menu dropdown-menu-end">' +
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
        if (b.dataset.dl === 'csv') {
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
    var first = shown ? paging.offset + 1 : 0;
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
        var cap = Math.min(shown, GRID_CAP);
        var head = '<th class="cq-rn" scope="col">#</th>' + model.columns.map(function (c) {
            return '<th scope="col"><span>' + esc(c) + '</span></th>';
        }).join('');
        var rowsHtml = '';
        for (var i = 0; i < cap; i++) {
            var row = model.rows[i];
            rowsHtml += '<tr><td class="cq-rn">' + fmtInt(paging.offset + i + 1) + '</td>' + model.columns.map(function (c) {
                var v = row[c];
                if (v === undefined) {
                    var lower = c.toLowerCase();
                    var k = Object.keys(row).filter(function (x) { return x.toLowerCase() === lower; })[0];
                    v = k ? row[k] : undefined;
                }
                return '<td>' + cell(c, v) + '</td>';
            }).join('') + '</tr>';
        }
        body.innerHTML = '<div class="cq-grid-wrap"><table class="cq-grid"><thead><tr>' + head + '</tr></thead><tbody>' + rowsHtml + '</tbody></table></div>' +
            (shown > cap ? '<div class="cq-capnote"><i class="fa-solid fa-circle-info"></i>The grid shows the first ' + fmtInt(cap) +
                ' of ' + fmtInt(shown) + ' rows returned. Add a <code>LIMIT</code> to page through them.</div>' : '');
    }
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
        return '<tr data-f="' + esc(f.toLowerCase()) + '"><td><button type="button" class="cq-field" data-insert="' + esc(f.replace('<key>', '')) + '" title="Insert into the writer">' + esc(f) + '</button></td>' +
            '<td><span class="mql-type mql-type-' + esc(d.type) + '">' + esc(d.type) + '</span></td>' +
            '<td class="cq-ops">' + d.operators.map(function (o) { return '<code>' + esc(o) + '</code>'; }).join('') + '</td>' +
            '<td>' + d.level.map(function (l) { return '<span class="cq-level">' + esc(l) + '</span>'; }).join('') + '</td></tr>';
    }).join('');
    var table = el('div', 'cq-grid-wrap cq-desc-grid');
    table.innerHTML = '<table class="cq-grid"><thead><tr><th>Field</th><th>Type</th><th>Operators</th><th>Level</th></tr></thead><tbody>' + rows + '</tbody></table>';
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
    highlight,
    summary,
    isClient,
    kindIcon,
    rewritePaging,
    pagingOf,
};
