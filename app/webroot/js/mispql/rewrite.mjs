/*
 * MispQL console: rewrites of one statement's text, made through its tokens
 * so comments, quotes and backticked names stay as written. DOM-free.
 */
import * as T from './tokens.mjs';

/**
 * The significant tokens up to the statement's first top-level ';', and the
 * index among them of each clause keyword found at parenthesis depth 0.
 */
function clauses(statement) {
    var all = T.significant(T.tokenize(statement));
    var c = { toks: [], from: null, where: null, order: null, limit: null, offset: null, format: null };
    var depth = 0;
    for (var i = 0; i < all.length; i++) {
        var t = all[i];
        if (t.kind === 'symbol') {
            if (t.value === ';' && depth === 0) {
                break;
            }
            depth += t.value === '(' ? 1 : t.value === ')' ? -1 : 0;
        }
        var at = c.toks.length;
        c.toks.push(t);
        if (depth !== 0 || t.kind !== 'keyword') {
            continue;
        }
        if (t.value === 'FROM' && c.from === null) {
            c.from = at;
        } else if (t.value === 'WHERE' && c.where === null) {
            c.where = at;
        } else if (t.value === 'ORDER' && all[i + 1] && all[i + 1].value === 'BY' && c.order === null) {
            c.order = at;
        } else if (t.value === 'LIMIT' && c.limit === null) {
            c.limit = at;
        } else if (t.value === 'OFFSET' && c.offset === null) {
            c.offset = at;
        } else if (t.value === 'FORMAT' && c.format === null) {
            c.format = at;
        }
    }
    return c;
}

/** Index of the first clause keyword after `after`, among those named. */
function nextClause(c, after, names) {
    var next = null;
    names.forEach(function (name) {
        if (c[name] !== null && c[name] > after && (next === null || c[name] < next)) {
            next = c[name];
        }
    });
    return next;
}

function apply(statement, edits) {
    edits.sort(function (a, b) { return b.from - a.from; });
    var out = statement;
    edits.forEach(function (e) { out = out.slice(0, e.from) + e.text + out.slice(e.to); });
    return out;
}

function hasTopLevelOr(toks, from, to) {
    var depth = 0;
    for (var i = from; i <= to; i++) {
        var t = toks[i];
        if (t.kind === 'symbol') {
            depth += t.value === '(' ? 1 : t.value === ')' ? -1 : 0;
        } else if (depth === 0 && t.kind === 'keyword' && t.value === 'OR') {
            return true;
        }
    }
    return false;
}

/**
 * The statement with `condition` added with AND: after `FROM table` as a new
 * WHERE, else after the existing condition, parenthesised when its top
 * level holds an OR. null when the statement searches no table.
 */
function addCondition(statement, condition) {
    var c = clauses(statement);
    if (c.from === null || !c.toks[c.from + 1]) {
        return null;
    }
    if (c.where === null) {
        var table = c.toks[c.from + 1];
        return apply(statement, [{ from: table.end, to: table.end, text: ' WHERE ' + condition }]);
    }
    var stop = nextClause(c, c.where, ['order', 'limit', 'offset', 'format']);
    var first = c.where + 1;
    var last = (stop === null ? c.toks.length : stop) - 1;
    if (last < first) {
        var where = c.toks[c.where];
        return apply(statement, [{ from: where.end, to: where.end, text: ' ' + condition }]);
    }
    var from = c.toks[first].start;
    var to = c.toks[last].end;
    if (hasTopLevelOr(c.toks, first, last)) {
        return apply(statement, [
            { from: from, to: from, text: '(' },
            { from: to, to: to, text: ') AND ' + condition },
        ]);
    }
    return apply(statement, [{ from: to, to: to, text: ' AND ' + condition }]);
}

/** The keys of the statement's ORDER BY: [{name, dir}], dir 'ASC', 'DESC' or null. */
function orderOf(statement) {
    var c = clauses(statement);
    if (c.order === null) {
        return [];
    }
    var stop = nextClause(c, c.order, ['limit', 'offset', 'format']);
    var keys = [];
    var name = '';
    var dir = null;
    function flush() {
        if (name) {
            keys.push({ name: name, dir: dir });
        }
        name = '';
        dir = null;
    }
    for (var i = c.order + 2; i < (stop === null ? c.toks.length : stop); i++) {
        var t = c.toks[i];
        if (t.kind === 'symbol' && t.value === ',') {
            flush();
        } else if (t.kind === 'keyword' && (t.value === 'ASC' || t.value === 'DESC')) {
            dir = t.value;
        } else if (t.kind === 'name' || t.kind === 'qname') {
            name += t.value;
        } else if (t.kind === 'symbol' && t.value === '.') {
            name += '.';
        }
    }
    flush();
    return keys;
}

/**
 * The statement with its ORDER BY set to `keys` ([{name, dir}]; none
 * removes the clause) and its OFFSET dropped: a new order starts again from
 * the first page.
 */
function setOrder(statement, keys) {
    var c = clauses(statement);
    if (c.from === null) {
        return null;
    }
    var text = keys.length ? 'ORDER BY ' + keys.map(function (k) {
        return k.name + (k.dir ? ' ' + k.dir : '');
    }).join(', ') : '';
    var edits = [];
    var after = c.order !== null ? c.order : (c.where !== null ? c.where : c.from);
    var stop = nextClause(c, after, ['limit', 'offset', 'format']);
    var lastBefore = (stop === null ? c.toks.length : stop) - 1;
    if (c.order !== null) {
        var orderFrom = c.toks[c.order].start;
        var orderTo = c.toks[lastBefore].end;
        if (text) {
            edits.push({ from: orderFrom, to: orderTo, text: text });
        } else {
            edits.push({ from: c.toks[c.order - 1].end, to: orderTo, text: '' });
        }
    } else if (text) {
        var at = c.toks[lastBefore].end;
        edits.push({ from: at, to: at, text: ' ' + text });
    }
    if (c.offset !== null) {
        var number = c.toks[c.offset + 1];
        edits.push({
            from: c.toks[c.offset - 1].end,
            to: number && number.kind === 'number' ? number.end : c.toks[c.offset].end,
            text: '',
        });
    }
    return apply(statement, edits);
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
    return apply(statement, edits);
}

// Keywords a complete statement can end with
var FINAL_KEYWORDS = { TRUE: true, FALSE: true, NULL: true, ASC: true, DESC: true };

/**
 * ` FORMAT <word>` added to a SELECT on a table that names no FORMAT:
 * {text, at, insert}, the statement with it, where and what was inserted.
 * null for COUNT(*), which takes no FORMAT, for other statements, and for
 * one that stops mid-clause.
 */
function defaultFormat(statement, word) {
    var c = clauses(statement);
    var toks = c.toks;
    if (!toks.length || toks[0].kind !== 'keyword' || toks[0].value !== 'SELECT' || c.from === null || c.format !== null) {
        return null;
    }
    if (toks[1] && toks[1].kind === 'keyword' && toks[1].value === 'COUNT') {
        return null;
    }
    var last = toks[toks.length - 1];
    var complete = last.kind === 'number' || last.kind === 'name' || last.kind === 'qname'
        || (last.kind === 'string' && last.closed)
        || (last.kind === 'symbol' && last.value === ')')
        || (last.kind === 'keyword' && FINAL_KEYWORDS[last.value] === true);
    if (!complete) {
        return null;
    }
    var insert = ' FORMAT ' + word;
    return {
        text: apply(statement, [{ from: last.end, to: last.end, text: insert }]),
        at: last.end,
        insert: insert,
    };
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

var PLAIN_NAME = /^[A-Za-z_][A-Za-z0-9_]*$/;

/** A field name as a statement spells it: backticks where a part needs them. */
function fieldName(name) {
    return name.split('.').map(function (part) {
        return PLAIN_NAME.test(part) && !T.isKeyword(part) ? part : '`' + part.replace(/`/g, '``') + '`';
    }).join('.');
}

function quote(s) {
    return "'" + s.replace(/'/g, "''") + "'";
}

/**
 * A cell's value as a literal of the field's type, or null when no
 * condition can be written with it: nothing is converted, so a string
 * starting or ending with % (which = refuses) or an empty cell gets none.
 */
function literal(type, value) {
    if (value === null || value === undefined || typeof value === 'object') {
        return null;
    }
    var s = String(value);
    if (s === '') {
        return null;
    }
    switch (type) {
        case 'int':
            return /^-?[0-9]+$/.test(s) ? s : null;
        case 'timestamp':
            return /^[0-9]+$/.test(s) && s !== '0' ? s : null;
        case 'bool':
            if (value === true || s === '1' || s.toLowerCase() === 'true') {
                return 'TRUE';
            }
            return value === false || s === '0' || s.toLowerCase() === 'false' ? 'FALSE' : null;
        case 'date':
            return /^[0-9]{4}-[0-9]{2}-[0-9]{2}$/.test(s) ? quote(s) : null;
        case 'datetime':
            return /^[0-9]{4}-[0-9]{2}-[0-9]{2}( [0-9]{2}:[0-9]{2}(:[0-9]{2})?)?$/.test(s) ? quote(s) : null;
        default:
            return s.charAt(0) === '%' || s.charAt(s.length - 1) === '%' ? null : quote(s);
    }
}

export {
    addCondition,
    setOrder,
    orderOf,
    rewritePaging,
    pagingOf,
    defaultFormat,
    fieldName,
    literal,
};
