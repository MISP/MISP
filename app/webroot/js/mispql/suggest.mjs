/*
 * MispQL console: suggestion context rules. They read the colouring tokens
 * and the language pack embedded in the page, and only ever suggest:
 * errors come from explain.
 *
 * suggest(text, cursor, pack) -> {from, to, prefix, state, table, items, hint,
 *     quoted, lookup}
 * Item: {label, insert, kind, detail, doc, chain}. `kind` drives the badge:
 * keyword, statement, client, table, column, field, operator, value, sort,
 * format, symbol.
 * Where a field's values are named rather than typed, they come from the
 * pack's lists (`values`), or `lookup` says which source to ask, for the
 * page to answer; lookupItems() turns its rows into items.
 */
import * as T from './tokens.mjs';
import { literal } from './rewrite.mjs';

var TYPE_DOC = {
    int: 'a whole number',
    timestamp: "Unix time, or relative: '7d', '12h', '30m'",
    date: "'YYYY-MM-DD', or a number of days: '30d'",
    datetime: "what timestamps take, or 'YYYY-MM-DD[ HH:MM:SS]'",
    bool: 'TRUE or FALSE',
    string: "a 'quoted' string; LIKE takes % at the start, the end or both"
};

var COMPARISONS = { '=': 1, '!=': 1, '<>': 1, '<': 1, '>': 1, '<=': 1, '>=': 1 };

/** Comparisons after which a field's named values are offered. */
var NAMING = { '=': 1, '!=': 1, '<>': 1 };

/** Characters a search picker needs before it answers. */
var LOOKUP_MIN = 2;

function kw(word, detail, chain) {
    return { label: word, insert: word, kind: 'keyword', detail: detail || '', chain: chain !== false };
}

function sym(label, detail, chain) {
    return { label: label, insert: label, kind: 'symbol', detail: detail || '', chain: !!chain, tight: true };
}

/** The field definition, including `meta.<key>` wildcards. */
function fieldDef(table, name) {
    if (!table || !name) {
        return null;
    }
    if (table.fields[name]) {
        return table.fields[name];
    }
    var dot = name.indexOf('.');
    if (dot > 0) {
        var wildcard = name.slice(0, dot + 1) + '<key>';
        if (table.fields[wildcard]) {
            return table.fields[wildcard];
        }
    }
    return null;
}

function elementOnly(tableName, def) {
    if (!def) {
        return false;
    }
    var native = tableName === 'events' ? ['event'] : tableName === 'objects' ? ['object', 'event'] : null;
    return native !== null && def.level.every(function (l) { return native.indexOf(l) === -1; });
}

function fieldItems(tableName, table) {
    return Object.keys(table.fields).map(function (name) {
        var def = table.fields[name];
        var isWildcard = name.slice(-5) === '<key>';
        var label = isWildcard ? name.slice(0, -5) : name;
        var notes = elementOnly(tableName, def)
            ? 'matched against the ' + def.level.join(' or ') + 's inside; positive operators only'
            : '';
        return {
            label: label,
            insert: isWildcard ? label : label + ' ',
            kind: 'field',
            detail: def.type,
            level: def.level,
            operators: def.operators,
            doc: (isWildcard ? 'any meta key: meta.synonyms, meta.`cfr-suspected-victims`. ' : '') + TYPE_DOC[def.type],
            note: notes,
            chain: true
        };
    });
}

function columnItems(table) {
    var seen = {};
    var items = [];
    function add(label, detail, doc) {
        if (seen[label.toLowerCase()] || label.slice(-5) === '<key>') {
            return;
        }
        seen[label.toLowerCase()] = true;
        items.push({ label: label, insert: label, kind: 'column', detail: detail, doc: doc || '', chain: false });
    }
    table.default_columns.forEach(function (c) { add(c, 'default column'); });
    Object.keys(table.aliases).forEach(function (a) { add(a, '→ ' + table.aliases[a], 'printed as ' + table.aliases[a]); });
    Object.keys(table.fields).forEach(function (f) { add(f, table.fields[f].type); });
    return items;
}

function tableItems(pack) {
    return Object.keys(pack.tables).map(function (name) {
        var t = pack.tables[name];
        return { label: name, insert: name + ' ', kind: 'table', detail: t.endpoint, doc: t.description, chain: true };
    });
}

function operatorItems(def, negatedOnly) {
    var ops = def ? def.operators : ['=', '!=', '<', '>', '<=', '>=', 'IN', 'NOT IN', 'LIKE', 'NOT LIKE'];
    var items = [];
    ops.forEach(function (op) {
        if (negatedOnly) {
            if (op === 'NOT IN' || op === 'NOT LIKE') {
                var bare = op.slice(4);
                items.push({ label: bare, insert: bare + ' ', kind: 'operator', detail: op, chain: true });
            }
            return;
        }
        items.push({
            label: op,
            insert: op + ' ',
            kind: 'operator',
            detail: { '=': 'equals', '!=': 'does not equal', '<': 'less than', '>': 'greater than',
                '<=': 'at most', '>=': 'at least', 'IN': 'one of a list', 'NOT IN': 'none of a list',
                'LIKE': 'pattern', 'NOT LIKE': 'not the pattern' }[op] || '',
            chain: true
        });
    });
    return items;
}

function today(offsetDays) {
    var d = new Date(Date.now() - (offsetDays || 0) * 86400000);
    return d.toISOString().slice(0, 10);
}

/** The rows of the list a field names, each as {value, label?, description?}. */
function valueRows(pack, def) {
    var rows = def && def.values && pack && pack.values ? pack.values[def.values] : null;
    if (!Array.isArray(rows)) {
        return [];
    }
    return rows.map(function (row) {
        return row !== null && typeof row === 'object' ? row : { value: row };
    });
}

/** A named value as an item; a level's name is matched as well as its number. */
function namedItem(def, value, detail, doc) {
    var written = literal(def.type, value);
    if (written === null) {
        return null;
    }
    return {
        label: String(value),
        insert: written + ' ',
        kind: 'value',
        detail: detail || '',
        doc: doc || '',
        alias: def.type === 'int' ? detail || '' : '',
        named: true,
        chain: true
    };
}

function listedItems(pack, def) {
    return valueRows(pack, def).map(function (row) {
        return namedItem(def, row.value, row.label, row.description);
    }).filter(Boolean);
}

/**
 * Items for the rows a lookup answered, [{value, detail?, doc?}], in the
 * order given; a value the statement cannot hold is left out.
 */
function lookupItems(rows) {
    var seen = {};
    var def = { type: 'string' };
    return (rows || []).map(function (row) {
        if (!row || typeof row.value !== 'string' || seen[row.value]) {
            return null;
        }
        seen[row.value] = true;
        return namedItem(def, row.value, row.detail, row.doc);
    }).filter(Boolean);
}

function valueItems(def, pack, op) {
    if (!def) {
        return [];
    }
    if (def.values && NAMING[op]) {
        return listedItems(pack, def);
    }
    function v(label, detail) {
        return { label: label, insert: label + ' ', kind: 'value', detail: detail, chain: true };
    }
    switch (def.type) {
        case 'bool':
            return [v('TRUE', 'boolean'), v('FALSE', 'boolean')];
        case 'timestamp':
            return [v("'24h'", 'the last day'), v("'7d'", 'the last week'), v("'30d'", 'the last month')];
        case 'date':
            return [v("'" + today(0) + "'", 'today'), v("'7d'", 'a week ago'), v("'30d'", 'a month ago')];
        case 'datetime':
            return [v("'" + today(0) + "'", 'today'), v("'7d'", 'a week ago'), v("'" + today(30) + " 00:00:00'", 'date and time')];
        default:
            return [];
    }
}

function clauseItems(state, ctx) {
    var items = [];
    if (state === 'cond_done') {
        items.push(kw('AND'), kw('OR'));
        if (ctx.parens > 0) {
            items.push(sym(')', 'close the group', true));
        }
    }
    if (state === 'after_table' || state === 'cond_done') {
        if (state === 'after_table') {
            items.push(kw('WHERE', 'conditions'));
        }
        items.push({ label: 'ORDER BY', insert: 'ORDER BY ', kind: 'keyword', detail: 'sort', chain: true });
    }
    if (state === 'order_after_field' || state === 'order_after_dir') {
        if (state === 'order_after_field') {
            items.push(kw('DESC', 'descending', false), kw('ASC', 'ascending (default)', false));
        }
        items.push(sym(',', 'another sort field', true));
    }
    if (['after_table', 'cond_done', 'order_after_field', 'order_after_dir'].indexOf(state) !== -1) {
        items.push(kw('LIMIT', 'rows per page'));
    }
    if (state === 'after_limit') {
        items.push(kw('OFFSET', 'rows to skip'));
    }
    if (['after_table', 'cond_done', 'order_after_field', 'order_after_dir', 'after_limit', 'after_offset'].indexOf(state) !== -1) {
        items.push(kw('FORMAT', 'output'));
    }
    return items;
}

function formatItems(pack, table) {
    var items = pack.renderings.map(function (f) {
        return { label: f, insert: f, kind: 'format', detail: 'rendered by the console', chain: false };
    });
    var formats = table ? table.formats : ['json', 'csv'];
    formats.forEach(function (f) {
        if (f === 'count') {
            return;
        }
        items.push({ label: f, insert: f, kind: 'format', detail: 'MISP export, downloaded', chain: false });
    });
    return items;
}

function sortItems(table) {
    return Object.keys(table.order_by).map(function (name) {
        var server = table.order_by[name];
        return { label: name, insert: name + ' ', kind: 'sort', detail: server === name ? '' : '→ ' + server, chain: true };
    });
}

/**
 * Walks the statement's significant tokens up to the cursor and returns
 * where in the grammar the cursor stands.
 */
function scan(tokens) {
    var state = 'start';
    var ctx = { parens: 0, table: null, field: null };
    for (var i = 0; i < tokens.length; i++) {
        var t = tokens[i];
        var v = t.kind === 'keyword' ? t.value : (t.kind === 'symbol' ? t.value : null);
        var isName = t.kind === 'name' || t.kind === 'qname';
        var isLiteral = t.kind === 'string' || t.kind === 'number' || v === 'TRUE' || v === 'FALSE';
        switch (state) {
            case 'start':
                state = v === 'SELECT' ? 'select_cols'
                    : (v === 'DESCRIBE' || v === 'DESC') ? 'describe_table'
                    : v === 'SHOW' ? 'show_what'
                    : v === 'USE' ? 'use_db'
                    : v === 'WHOAMI' ? 'done' : 'unknown';
                break;
            case 'select_cols':
            case 'select_cols_more':
                if (v === '*' && state === 'select_cols') {
                    state = 'after_cols';
                } else if (v === 'COUNT' && state === 'select_cols') {
                    state = 'count_open';
                } else if (isName) {
                    state = 'col_name';
                } else {
                    state = 'unknown';
                }
                break;
            case 'count_open':
                state = v === '(' ? 'count_star' : 'unknown';
                break;
            case 'count_star':
                state = v === '*' ? 'count_close' : 'unknown';
                break;
            case 'count_close':
                state = v === ')' ? 'after_cols' : 'unknown';
                break;
            case 'col_name':
                state = v === '.' ? 'col_dot' : v === ',' ? 'select_cols_more' : v === 'FROM' ? 'from_table' : 'unknown';
                break;
            case 'col_dot':
                state = isName ? 'col_name' : 'unknown';
                break;
            case 'after_cols':
                state = v === 'FROM' ? 'from_table' : 'unknown';
                break;
            case 'from_table':
                if (isName) {
                    ctx.table = t.kind === 'qname' ? t.value : t.value;
                    state = 'after_table';
                } else {
                    state = 'unknown';
                }
                break;
            case 'after_table':
            case 'cond_done':
            case 'order_after_field':
            case 'order_after_dir':
            case 'after_limit':
            case 'after_offset':
                if (state === 'after_table' && v === 'WHERE') {
                    state = 'cond_start';
                } else if (state === 'cond_done' && (v === 'AND' || v === 'OR')) {
                    state = 'cond_start';
                } else if (state === 'cond_done' && v === ')' && ctx.parens > 0) {
                    ctx.parens--;
                } else if ((state === 'order_after_field' || state === 'order_after_dir') && v === ',') {
                    state = 'order_field';
                } else if (state === 'order_after_field' && (v === 'ASC' || v === 'DESC')) {
                    state = 'order_after_dir';
                } else if ((state === 'after_table' || state === 'cond_done') && v === 'ORDER') {
                    state = 'order_by_kw';
                } else if (['after_limit', 'after_offset'].indexOf(state) === -1 && v === 'LIMIT') {
                    state = 'limit_n';
                } else if (state !== 'after_offset' && v === 'OFFSET') {
                    state = 'offset_n';
                } else if (v === 'FORMAT') {
                    state = 'format_name';
                } else {
                    state = 'unknown';
                }
                break;
            case 'cond_start':
                if (v === 'NOT') {
                    state = 'cond_start';
                } else if (v === '(') {
                    ctx.parens++;
                } else if (isName) {
                    ctx.field = t.value;
                    state = 'cond_field';
                } else {
                    state = 'unknown';
                }
                break;
            case 'cond_field':
                if (v === '.') {
                    state = 'cond_field_dot';
                } else if (v && COMPARISONS[v]) {
                    ctx.op = v;
                    state = 'cond_value';
                } else if (v === 'NOT') {
                    state = 'cond_not_op';
                } else if (v === 'IN') {
                    state = 'in_open';
                } else if (v === 'LIKE') {
                    state = 'like_value';
                } else {
                    state = 'unknown';
                }
                break;
            case 'cond_field_dot':
                if (isName) {
                    // `attributes.type` names the table; `meta.synonyms` is part of the name.
                    ctx.field = ctx.field === ctx.table ? t.value : ctx.field + '.' + t.value;
                    state = 'cond_field';
                } else {
                    state = 'unknown';
                }
                break;
            case 'cond_not_op':
                state = v === 'IN' ? 'in_open' : v === 'LIKE' ? 'like_value' : 'unknown';
                break;
            case 'cond_value':
                if (v === '-') {
                    state = 'cond_value';
                } else {
                    state = isLiteral ? 'cond_done' : 'unknown';
                }
                break;
            case 'in_open':
                state = v === '(' ? 'in_value' : 'unknown';
                break;
            case 'in_value':
                state = isLiteral ? 'in_after_value' : v === '-' ? 'in_value' : 'unknown';
                break;
            case 'in_after_value':
                state = v === ',' ? 'in_value' : v === ')' ? 'cond_done' : 'unknown';
                break;
            case 'like_value':
                state = t.kind === 'string' ? 'cond_done' : 'unknown';
                break;
            case 'order_by_kw':
                state = v === 'BY' ? 'order_field' : 'unknown';
                break;
            case 'order_field':
                state = isName ? 'order_after_field' : 'unknown';
                break;
            case 'limit_n':
                state = t.kind === 'number' ? 'after_limit' : 'unknown';
                break;
            case 'offset_n':
                state = t.kind === 'number' ? 'after_offset' : 'unknown';
                break;
            case 'format_name':
            case 'describe_table':
            case 'show_what':
            case 'use_db':
                state = 'done';
                break;
            default:
                state = 'unknown';
        }
        if (state === 'unknown') {
            break;
        }
    }
    return { state: state, ctx: ctx };
}

/** The table named after FROM anywhere in the statement, for columns typed before it. */
function lookAheadTable(tokens) {
    for (var i = 0; i < tokens.length - 1; i++) {
        if (tokens[i].kind === 'keyword' && tokens[i].value === 'FROM' &&
            (tokens[i + 1].kind === 'name' || tokens[i + 1].kind === 'qname')) {
            return tokens[i + 1].value;
        }
    }
    return null;
}

function matchScore(label, prefix) {
    if (!prefix) {
        return 1;
    }
    var l = label.toLowerCase().replace(/^'/, '');
    var p = prefix.toLowerCase();
    if (l.indexOf(p) === 0) {
        return 3;
    }
    if (l.indexOf('_' + p) !== -1 || l.indexOf('.' + p) !== -1) {
        return 2;
    }
    return l.indexOf(p) !== -1 ? 1.5 : 0;
}

/**
 * Where a value written over a string token at the caret ends: the rest of
 * the word after the caret, and the closing quote when the word reaches it.
 * A quote typed before other text pairs with the next one, so the token
 * can hold more of the statement than the value; that part is kept.
 */
function valueEnd(text, t, cursor) {
    var inner = t.closed ? t.end - 1 : t.end;
    var word = /^[^\s']*/.exec(text.slice(cursor, inner))[0];
    var end = cursor + word.length;
    return t.closed && end === inner ? t.end : end;
}

/**
 * The field a value at the end of these tokens is written for, when it is
 * one a name can stand for (after =, != or in an IN list), or null.
 */
function valueSlot(sig, pack) {
    var scanned = scan(sig);
    if (scanned.state !== 'cond_value' && scanned.state !== 'in_value') {
        return null;
    }
    if (scanned.state === 'cond_value' && !NAMING[scanned.ctx.op]) {
        return null;
    }
    var name = scanned.ctx.table || lookAheadTable(sig);
    var def = fieldDef(name && pack.tables[name] ? pack.tables[name] : null, scanned.ctx.field);
    return def ? { state: scanned.state, def: def } : null;
}

/** The line under the items: the type's sentence, unless values are named. */
function valueHint(def, listed, lookup) {
    if (!def) {
        return '';
    }
    if (lookup) {
        return lookup.prefix.length < lookup.min ? 'Type ' + lookup.min + ' characters to look names up.' : '';
    }
    return listed ? '' : TYPE_DOC[def.type];
}

function lookupOf(pack, def, prefix) {
    var pickers = def && def.lookup && pack.sources ? pack.sources[def.lookup] : null;
    if (!Array.isArray(pickers) || !pickers.length) {
        return null;
    }
    var whole = pickers.every(function (p) { return p.whole; });
    return { source: def.lookup, prefix: prefix, min: whole ? 0 : LOOKUP_MIN };
}

function suggest(text, cursor, pack) {
    var all = T.tokenize(text);
    var from = cursor;
    var to = cursor;
    var prefix = '';
    var stmtStart = 0;
    var stmtTokens = [];
    var after = [];
    var openString = null;
    for (var i = 0; i < all.length; i++) {
        var t = all[i];
        if (t.kind === 'string' && t.start < cursor && (cursor < t.end || (!t.closed && cursor === t.end))) {
            openString = t;
            continue;
        }
        if (t.start < cursor && cursor < t.end && (t.kind === 'comment' || t.kind === 'qname')) {
            if (t.kind !== 'qname' || t.closed) {
                return nothing(cursor, 'inside');
            }
        }
        if (t.end <= cursor || (t.start < cursor && t.end >= cursor && (t.kind === 'name' || t.kind === 'keyword'))) {
            if (t.kind === 'symbol' && t.value === ';' && t.end <= cursor) {
                stmtTokens = [];
                stmtStart = t.end;
                continue;
            }
            stmtTokens.push(t);
        } else if (t.start >= cursor) {
            if (t.kind === 'symbol' && t.value === ';') {
                break;
            }
            after.push(t);
        }
    }
    var sig = T.significant(stmtTokens);
    if (openString) {
        return quotedValue(text, cursor, openString, sig, pack, stmtStart);
    }
    var last = sig[sig.length - 1];
    if (last && last.end >= cursor && last.kind === 'number') {
        var numbered = valueSlot(sig.slice(0, -1), pack);
        if (numbered && numbered.def.values) {
            return finish(listedItems(pack, numbered.def), text.slice(last.start, cursor), {
                from: last.start, to: last.end, state: numbered.state, statementStart: stmtStart
            });
        }
    }
    if (last && last.end >= cursor && (last.kind === 'number' || last.kind === 'string' ||
        (last.kind === 'qname' && last.closed))) {
        return nothing(cursor, 'touching');
    }
    if (last && last.end >= cursor && (last.kind === 'name' || last.kind === 'keyword')) {
        prefix = text.slice(last.start, cursor);
        from = last.start;
        to = last.end;
        sig = sig.slice(0, -1);
    }
    // The name being written after a dot keeps the qualifier out of the prefix.
    var scanned = scan(sig);
    var state = scanned.state;
    var ctx = scanned.ctx;
    var tableName = ctx.table || lookAheadTable(T.significant(after.concat(stmtTokens)));
    var table = tableName && pack.tables[tableName] ? pack.tables[tableName] : null;
    var items = [];
    var hint = '';
    var lookup = null;

    switch (state) {
        case 'start':
            items = [
                { label: 'SELECT', insert: 'SELECT ', kind: 'statement', detail: 'search a table', chain: true },
                { label: 'DESCRIBE', insert: 'DESCRIBE ', kind: 'statement', detail: "a table's fields", chain: true },
                { label: 'SHOW TABLES', insert: 'SHOW TABLES', kind: 'statement', detail: 'the tables you may query', chain: false },
                { label: 'WHOAMI', insert: 'WHOAMI', kind: 'statement', detail: 'your account', chain: false },
                { label: 'USE', insert: 'USE ', kind: 'client', detail: 'mispql CLI only', chain: false },
                { label: 'SHOW DATABASES', insert: 'SHOW DATABASES', kind: 'client', detail: 'mispql CLI only', chain: false }
            ];
            break;
        case 'select_cols':
            items = [
                { label: '*', insert: '* ', kind: 'symbol', detail: 'whole rows', chain: true },
                { label: 'COUNT(*)', insert: 'COUNT(*) ', kind: 'keyword', detail: 'count the matches', chain: true }
            ];
            if (table) {
                items = items.concat(columnItems(table));
            } else {
                hint = 'Write FROM and a table to get its columns.';
            }
            break;
        case 'select_cols_more':
        case 'col_dot':
            if (table) {
                items = columnItems(table);
            }
            break;
        case 'col_name':
            items = [sym(',', 'another column', true), kw('FROM')];
            break;
        case 'after_cols':
            items = [kw('FROM')];
            break;
        case 'count_open':
        case 'count_star':
        case 'count_close':
            items = [{ label: 'COUNT(*)', insert: 'COUNT(*) ', kind: 'keyword', detail: '', chain: true }];
            break;
        case 'from_table':
        case 'describe_table':
            items = tableItems(pack);
            if (state === 'describe_table') {
                items.forEach(function (it) { it.insert = it.label; it.chain = false; });
            }
            break;
        case 'show_what':
            items = [kw('TABLES', 'the tables you may query', false),
                { label: 'DATABASES', insert: 'DATABASES', kind: 'client', detail: 'mispql CLI only', chain: false }];
            break;
        case 'cond_start':
            if (table) {
                items = fieldItems(tableName, table);
            } else {
                hint = 'Unknown table: no fields to offer.';
            }
            items.push(kw('NOT', 'negate the next condition'), sym('(', 'group conditions', true));
            break;
        case 'cond_field_dot':
            if (table) {
                var base = ctx.field === tableName ? '' : ctx.field + '.';
                items = fieldItems(tableName, table).filter(function (it) {
                    return base === '' ? it.label.indexOf('.') === -1 : it.label.indexOf(base) === 0;
                }).map(function (it) {
                    var copy = Object.assign({}, it);
                    copy.label = it.label.slice(base.length);
                    copy.insert = copy.label + ' ';
                    return copy;
                }).filter(function (it) {
                    return it.label !== '';
                });
                if (base) {
                    hint = 'Any key: write it, in backticks if it holds other characters than letters, digits and _.';
                }
            }
            break;
        case 'cond_field':
            var def = fieldDef(table, ctx.field);
            items = operatorItems(def, false);
            if (table && !def) {
                hint = 'Not a field of ' + tableName + '; explain will say so.';
            }
            break;
        case 'cond_not_op':
            items = operatorItems(fieldDef(table, ctx.field), true);
            break;
        case 'cond_value':
            var vdef = fieldDef(table, ctx.field);
            items = valueItems(vdef, pack, ctx.op);
            lookup = NAMING[ctx.op] ? lookupOf(pack, vdef, prefix) : null;
            hint = valueHint(vdef, vdef && vdef.values && NAMING[ctx.op], lookup);
            break;
        case 'in_open':
            items = [sym('(', 'the list of values', false)];
            break;
        case 'in_value':
        case 'like_value':
            var ldef = fieldDef(table, ctx.field);
            hint = state === 'like_value' ? "A 'pattern' with % at the start, the end or both."
                : (ldef ? TYPE_DOC[ldef.type] : '');
            if (state === 'in_value' && ldef) {
                items = ldef.values ? listedItems(pack, ldef) : [];
                lookup = lookupOf(pack, ldef, prefix);
                hint = valueHint(ldef, ldef.values, lookup);
            }
            break;
        case 'in_after_value':
            items = [sym(',', 'another value', false), sym(')', 'close the list', true)];
            break;
        case 'order_by_kw':
            items = [kw('BY')];
            break;
        case 'order_field':
            if (table && Object.keys(table.order_by).length) {
                items = sortItems(table);
            } else if (table) {
                hint = tableName + ' cannot be sorted.';
            }
            break;
        case 'limit_n':
        case 'offset_n':
            items = (state === 'limit_n' ? ['20', '50', '100'] : ['20', '100']).map(function (n) {
                return { label: n, insert: n + ' ', kind: 'value', detail: 'rows', chain: true };
            });
            break;
        case 'format_name':
            items = formatItems(pack, table);
            break;
        case 'after_table':
        case 'cond_done':
        case 'order_after_field':
        case 'order_after_dir':
        case 'after_limit':
        case 'after_offset':
            items = clauseItems(state, ctx);
            break;
        default:
            items = [];
    }

    return finish(items, prefix, {
        from: from,
        to: to,
        state: state,
        table: tableName,
        hint: hint,
        lookup: lookup,
        statementStart: stmtStart
    });
}

/** A value written in quotes: the field's named values, or what to look up. */
function quotedValue(text, cursor, t, sig, pack, stmtStart) {
    var slot = valueSlot(sig, pack);
    if (!slot || slot.def.type !== 'string') {
        return nothing(cursor, 'inside');
    }
    var prefix = text.slice(t.start + 1, cursor).split("''").join("'");
    var lookup = lookupOf(pack, slot.def, prefix);
    return finish(slot.def.values ? listedItems(pack, slot.def) : [], prefix, {
        from: t.start,
        to: valueEnd(text, t, cursor),
        state: slot.state,
        hint: valueHint(slot.def, slot.def.values, lookup),
        quoted: true,
        lookup: lookup,
        statementStart: stmtStart
    });
}

/** Inside a comment, a quoted name or a string, or right after a literal. */
function nothing(cursor, state) {
    return finish([], '', { from: cursor, to: cursor, state: state });
}

/** Scores and orders the items against the prefix; a value named in full stays offered. */
function finish(items, prefix, reply) {
    var upper = !/[a-z]/.test(prefix) || /[A-Z]/.test(prefix);
    items = rank(items, prefix).map(function (it) {
        if (!upper && (it.kind === 'keyword' || it.kind === 'statement' || it.kind === 'client') && /^[A-Z(*) ]+$/.test(it.label)) {
            it.insert = it.insert.toLowerCase();
        }
        return it;
    }).filter(function (it) {
        return !(prefix && !it.named && it.label.toLowerCase() === prefix.toLowerCase() && it.kind !== 'table' && it.kind !== 'field');
    });
    return Object.assign({ prefix: prefix, table: null, items: items, hint: '', quoted: false, lookup: null }, reply);
}

function rank(items, prefix) {
    return items.map(function (it, idx) {
        var copy = Object.assign({}, it);
        copy.score = Math.max(matchScore(it.label, prefix), it.alias && matchScore(it.alias, prefix) ? 1 : 0);
        copy.order = idx;
        return copy;
    }).filter(function (it) {
        return it.score > 0;
    }).sort(function (a, b) {
        return b.score - a.score || a.order - b.order;
    });
}

export {
    suggest,
    fieldDef,
    elementOnly,
    valueRows,
    lookupItems,
    TYPE_DOC,
};
