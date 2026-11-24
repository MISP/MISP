/*
 * MispQL console: the colouring tokenizer and the offset helpers.
 * DOM-free.
 *
 * Token offsets are JavaScript string indices (UTF-16 code units), the unit
 * the textarea uses. Offsets coming from the server are Unicode code points;
 * they go through cpRangeToIndex() and nothing else.
 */

// Unicode White_Space, as the server's lexer: U+001C-U+001F, ZWSP and BOM are not in it.
var WHITE_SPACE = [
    0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x20, 0x85, 0xA0, 0x1680,
    0x2000, 0x2001, 0x2002, 0x2003, 0x2004, 0x2005, 0x2006, 0x2007, 0x2008, 0x2009, 0x200A,
    0x2028, 0x2029, 0x202F, 0x205F, 0x3000
];
var WS = {};
WHITE_SPACE.forEach(function (cp) { WS[cp] = true; });

var KEYWORDS = [
    'AND', 'ASC', 'BY', 'COUNT', 'DATABASES', 'DESC', 'DESCRIBE', 'FALSE', 'FORMAT', 'FROM',
    'IN', 'LIKE', 'LIMIT', 'NOT', 'OFFSET', 'OR', 'ORDER', 'SELECT', 'SHOW', 'TABLES', 'TRUE',
    'USE', 'WHERE', 'WHOAMI'
];
var IS_KEYWORD = {};
KEYWORDS.forEach(function (k) { IS_KEYWORD[k] = true; });

var SYMBOLS = ['!=', '<>', '<=', '>=', '=', '<', '>', '(', ')', ',', '.', '*', ';', '-'];

function isWhiteSpace(cp) {
    return WS[cp] === true;
}

function isWordChar(c) {
    return (c >= 48 && c <= 57) || (c >= 65 && c <= 90) || (c >= 97 && c <= 122) || c === 95;
}

function isHighSurrogate(c) {
    return c >= 0xD800 && c <= 0xDBFF;
}

function isLowSurrogate(c) {
    return c >= 0xDC00 && c <= 0xDFFF;
}

// Width in code units of the code point starting at index i.
function unitsAt(text, i) {
    return isHighSurrogate(text.charCodeAt(i)) && isLowSurrogate(text.charCodeAt(i + 1)) ? 2 : 1;
}

/** Code point offset -> string index. Past the end clamps to text.length. */
function cpToIndex(text, cp) {
    var i = 0;
    var n = 0;
    while (n < cp && i < text.length) {
        i += unitsAt(text, i);
        n++;
    }
    return i;
}

/** String index -> code point offset. */
function indexToCp(text, index) {
    var i = 0;
    var n = 0;
    while (i < index && i < text.length) {
        i += unitsAt(text, i);
        n++;
    }
    return n;
}

function cpLength(text) {
    return indexToCp(text, text.length);
}

/** The one conversion for server offsets: {start, end} in code points -> string indices. */
function cpRangeToIndex(text, start, end) {
    var s = cpToIndex(text, start);
    return { start: s, end: s + (cpToIndex(text.slice(s), end - start)) };
}

/**
 * Tokens for colour and suggestions. Never throws: text the server would
 * refuse still gets tokens (kind 'bad', or a flag), and explain says why.
 * Kinds: space, comment, keyword, name, qname, string, number, symbol, bad.
 */
function tokenize(text) {
    var tokens = [];
    var n = text.length;
    var i = 0;
    while (i < n) {
        var c = text.charCodeAt(i);
        var start = i;
        var cp = text.codePointAt(i);
        if (isWhiteSpace(cp)) {
            var unicode = false;
            while (i < n && isWhiteSpace(text.codePointAt(i))) {
                if (text.charCodeAt(i) > 0x7F) {
                    unicode = true;
                }
                i += unitsAt(text, i);
            }
            tokens.push({ kind: 'space', start: start, end: i, unicode: unicode });
        } else if (c === 45 && text.charCodeAt(i + 1) === 45) {
            var nl = text.indexOf('\n', i);
            i = nl === -1 ? n : nl;
            tokens.push({ kind: 'comment', start: start, end: i });
        } else if (c === 39 || c === 34 || c === 96) {
            var quote = text[i];
            var closed = false;
            i++;
            while (i < n) {
                if (text[i] === quote) {
                    if (text[i + 1] === quote) {
                        i += 2;
                        continue;
                    }
                    i++;
                    closed = true;
                    break;
                }
                i++;
            }
            var raw = text.slice(start + 1, closed ? i - 1 : i);
            tokens.push({
                kind: quote === '`' ? 'qname' : 'string',
                start: start,
                end: i,
                value: raw.split(quote + quote).join(quote),
                closed: closed
            });
        } else if (isWordChar(c)) {
            while (i < n && isWordChar(text.charCodeAt(i))) {
                i++;
            }
            var word = text.slice(start, i);
            if (c >= 48 && c <= 57) {
                tokens.push({ kind: /^[0-9]+$/.test(word) ? 'number' : 'name', start: start, end: i,
                    value: word, digitWord: !/^[0-9]+$/.test(word) });
            } else if (IS_KEYWORD[word.toUpperCase()]) {
                tokens.push({ kind: 'keyword', start: start, end: i, value: word.toUpperCase() });
            } else {
                tokens.push({ kind: 'name', start: start, end: i, value: word.toLowerCase() });
            }
        } else {
            var symbol = null;
            for (var s = 0; s < SYMBOLS.length; s++) {
                if (text.startsWith(SYMBOLS[s], i)) {
                    symbol = SYMBOLS[s];
                    break;
                }
            }
            if (symbol) {
                i += symbol.length;
                tokens.push({ kind: 'symbol', start: start, end: i, value: symbol });
            } else {
                i += unitsAt(text, i);
                tokens.push({ kind: 'bad', start: start, end: i, value: text.slice(start, i) });
            }
        }
    }
    return tokens;
}

function significant(tokens) {
    return tokens.filter(function (t) {
        return t.kind !== 'space' && t.kind !== 'comment';
    });
}

/**
 * Statement ranges from the ';' tokens. The console prefers explain's
 * boundaries; this is the fallback while explain reports errors.
 */
function splitStatements(text, tokens) {
    tokens = tokens || tokenize(text);
    var ranges = [];
    var cur = null;
    tokens.forEach(function (t) {
        if (t.kind === 'symbol' && t.value === ';') {
            if (cur) {
                ranges.push(cur);
            }
            cur = null;
            return;
        }
        if (t.kind === 'space' || t.kind === 'comment') {
            return;
        }
        if (!cur) {
            cur = { start: t.start, end: t.end };
        }
        cur.end = t.end;
    });
    if (cur) {
        ranges.push(cur);
    }
    return ranges;
}

/** Line and column (1-based, in code points) of a string index. */
function lineCol(text, index) {
    var before = text.slice(0, index);
    var line = before.split('\n').length;
    var col = cpLength(before.slice(before.lastIndexOf('\n') + 1)) + 1;
    return { line: line, col: col };
}

function isKeyword(w) { return IS_KEYWORD[String(w).toUpperCase()] === true; }

export {
    WHITE_SPACE,
    KEYWORDS,
    isWhiteSpace,
    isKeyword,
    cpToIndex,
    indexToCp,
    cpLength,
    cpRangeToIndex,
    tokenize,
    significant,
    splitStatements,
    lineCol,
};
