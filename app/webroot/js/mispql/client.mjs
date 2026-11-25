/*
 * MispQL console: the calls to MISP. Neither call rejects: a refusal, a
 * failure or no answer at all comes back as a reply the console can show.
 *
 * createClient({baseurl, csrfToken() -> string, sources}) -> {
 *     explain(script) -> Promise<{status, body, failure?}>,
 *     run(statement, {remember}) -> Promise<result>,
 *     plan(statement) -> Promise<result>,
 *     lookup(source, prefix, signal) -> Promise<[{value, detail, doc}]>
 * }
 * `sources` are the language pack's: lookup() asks their pickers and never
 * rejects, except when aborted; a picker that fails answers nothing.
 * A result has a `kind`: rows, count, describe, tables, whoami (MISP's reply
 * in `reply`), export (MISP's own format, kept as a Blob), plan (explain's
 * entry for the statement, in `plan`), error (located errors, offsets
 * converted to string indices) or failure (`message`).
 */
import * as T from './tokens.mjs';

const PREVIEW_BYTES = 65536;

const KINDS = { search: 'rows', count: 'count', describe: 'describe', show_tables: 'tables', whoami: 'whoami' };

const EXTENSIONS = { csv: 'csv', json: 'json', 'yara-json': 'json', stix2: 'json', stix: 'xml', xml: 'xml', xlsx: 'xlsx' };

const TEXT_TYPE = /^text\/|[/+](json|xml|csv|javascript)$/;

function createClient(options) {
    const base = options.baseurl || '';

    function post(path, body) {
        return fetch(base + path, {
            method: 'POST',
            credentials: 'same-origin',
            headers: {
                'Accept': 'application/json',
                'Content-Type': 'application/json',
                'X-Requested-With': 'XMLHttpRequest',
                'X-CSRF-Token': options.csrfToken() || '',
            },
            body: JSON.stringify(body),
        });
    }

    async function explain(script) {
        let response;
        try {
            response = await post('/mispql/explain', { script: script });
        } catch (e) {
            return { status: 0, body: { errors: [] }, failure: NO_ANSWER };
        }
        const body = await readJson(response);
        if (response.ok && body && Array.isArray(body.statements)) {
            return { status: 200, body: body };
        }
        if (body && Array.isArray(body.errors)) {
            return { status: response.status, body: body };
        }
        return { status: response.status, body: { errors: [] }, failure: failureMessage(response.status, body) };
    }

    async function run(statement, opts) {
        const started = Date.now();
        const r = { statement: statement, ranAt: Math.floor(started / 1000), status: 0 };
        const done = function () {
            r.elapsed = Date.now() - started;
            return r;
        };
        let response;
        try {
            response = await post('/mispql/run', { statement: statement, remember: !!(opts && opts.remember) });
        } catch (e) {
            return done(Object.assign(r, { kind: 'failure', message: NO_ANSWER }));
        }
        r.status = response.status;
        if (response.ok && response.headers.has('X-Export-Module-Used')) {
            await readExport(r, response);
            return done();
        }
        const body = await readJson(response);
        if (response.ok && body && KINDS[body.kind]) {
            r.kind = KINDS[body.kind];
            r.reply = body;
            r.table = body.table || null;
            return done();
        }
        if (body && Array.isArray(body.errors)) {
            r.kind = 'error';
            r.envelope = body;
            r.errors = located(statement, body.errors);
            return done();
        }
        r.kind = 'failure';
        r.message = failureMessage(response.status, body);
        return done();
    }

    /** Explains one statement, as a result: its plan, its errors or a failure. Reads no data. */
    async function plan(statement) {
        const started = Date.now();
        const reply = await explain(statement);
        const r = {
            statement: statement,
            ranAt: Math.floor(started / 1000),
            status: reply.status,
            elapsed: Date.now() - started,
            explained: true,
        };
        if (reply.status === 200) {
            r.kind = 'plan';
            r.plan = reply.body.statements[0] || null;
            r.table = (r.plan && r.plan.table) || null;
        } else if (reply.failure) {
            r.kind = 'failure';
            r.message = reply.failure;
        } else {
            r.kind = 'error';
            r.envelope = reply.body;
            r.errors = located(statement, reply.body.errors);
        }
        return r;
    }

    const sources = options.sources || {};
    const wholeLists = {};

    function getJson(path, signal) {
        return fetch(base + path, {
            credentials: 'same-origin',
            headers: { 'Accept': 'application/json' },
            signal: signal,
        }).then(function (response) {
            if (!response.ok) {
                throw new Error('HTTP ' + response.status);
            }
            return response.json();
        });
    }

    /** A picker answering its whole list is asked once per page; its rows are matched here. */
    function pickerRows(picker, prefix, signal) {
        if (!picker.whole) {
            return getJson(picker.url + '?q=' + encodeURIComponent(prefix), signal);
        }
        if (!wholeLists[picker.url]) {
            wholeLists[picker.url] = getJson(picker.url).catch(function (e) {
                delete wholeLists[picker.url];
                throw e;
            });
        }
        return wholeLists[picker.url].then(function (rows) {
            return matching(rows, picker.insert, prefix);
        });
    }

    async function lookup(source, prefix, signal) {
        const found = await Promise.all((sources[source] || []).map(function (picker) {
            return pickerRows(picker, prefix, signal).then(function (rows) {
                return (Array.isArray(rows) ? rows : []).map(function (row) {
                    return {
                        value: textAt(row, picker.insert),
                        detail: textAt(row, picker.detail),
                        doc: textAt(row, picker.doc),
                    };
                }).filter(function (row) { return row.value !== ''; });
            }).catch(function (e) {
                if (signal && signal.aborted) {
                    throw e;
                }
                return [];
            });
        }));
        return [].concat.apply([], found);
    }

    return { explain: explain, run: run, plan: plan, lookup: lookup };
}

/** The text at a dotted key of a picker row, or ''. */
function textAt(row, path) {
    if (!path) {
        return '';
    }
    const v = path.split('.').reduce(function (o, k) {
        return o !== null && typeof o === 'object' ? o[k] : undefined;
    }, row);
    return typeof v === 'string' || typeof v === 'number' ? String(v) : '';
}

/** Rows whose key holds the prefix, those starting with it first. */
function matching(rows, key, prefix) {
    const p = prefix.toLowerCase();
    return (Array.isArray(rows) ? rows : []).map(function (row, i) {
        const v = textAt(row, key).toLowerCase();
        return { row: row, at: p ? v.indexOf(p) : 0, i: i };
    }).filter(function (m) {
        return m.at !== -1;
    }).sort(function (a, b) {
        return (a.at === 0 ? 0 : 1) - (b.at === 0 ? 0 : 1) || a.i - b.i;
    }).map(function (m) { return m.row; });
}

/** Errors with their code-point offsets converted to string indices of the text. */
function located(text, errors) {
    return errors.map(function (e) {
        const span = T.cpRangeToIndex(text, e.start, e.end);
        return Object.assign({}, e, { from: span.start, to: span.end });
    });
}

const NO_ANSWER = 'MISP did not answer. Check the connection, then try again.';

function failureMessage(status, body) {
    const said = body && (body.message || body.name) ? String(body.message || body.name) : '';
    if (status === 400 && /csrf|black-?holed/i.test(said)) {
        return 'This page\'s security token has expired. Reload the page: the writer keeps your text.';
    }
    if (status === 401 || (status === 403 && /authenticat|log ?in/i.test(said))) {
        return 'Your session has ended. Log in again, then reload this page.';
    }
    if (status === 403) {
        return 'MISP refused this statement' + (said ? ': ' + said : '.');
    }
    if (status >= 500) {
        return 'MISP failed while running this statement (HTTP ' + status + ').' + (said ? ' ' + said : '');
    }
    return 'MISP answered HTTP ' + status + (said ? ': ' + said : '.');
}

async function readJson(response) {
    try {
        return JSON.parse(await response.text());
    } catch (e) {
        return null;
    }
}

async function readExport(r, response) {
    const blob = await response.blob();
    const type = (response.headers.get('Content-Type') || 'application/octet-stream').split(';')[0].trim();
    r.kind = 'export';
    r.format = response.headers.get('X-Export-Module-Used') || '';
    r.blob = blob;
    r.size = blob.size;
    r.contentType = type;
    r.total = null;
    r.filename = filenameOf(response.headers.get('Content-Disposition'))
        || 'misp.' + (r.format || 'export') + '.' + (EXTENSIONS[r.format] || 'txt');
    r.previewSize = PREVIEW_BYTES;
    r.preview = TEXT_TYPE.test(type) ? await blob.slice(0, PREVIEW_BYTES).text() : null;
}

function filenameOf(disposition) {
    const m = /filename\*?=(?:UTF-8'')?"?([^";]+)"?/i.exec(disposition || '');
    return m ? decodeURIComponent(m[1]) : null;
}

export { createClient, failureMessage };
