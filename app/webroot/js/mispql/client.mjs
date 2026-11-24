/*
 * MispQL console: the calls to MISP. Neither call rejects: a refusal, a
 * failure or no answer at all comes back as a reply the console can show.
 *
 * createClient({baseurl, csrfToken() -> string}) -> {
 *     explain(script) -> Promise<{status, body, failure?}>,
 *     run(statement, {remember}) -> Promise<result>
 * }
 * A result has a `kind`: rows, count, describe, tables, whoami (MISP's reply
 * in `reply`), export (MISP's own format, kept as a Blob), error (located
 * errors, offsets converted to string indices) or failure (`message`).
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
            r.errors = body.errors.map(function (e) {
                const span = T.cpRangeToIndex(statement, e.start, e.end);
                return Object.assign({}, e, { from: span.start, to: span.end });
            });
            return done();
        }
        r.kind = 'failure';
        r.message = failureMessage(response.status, body);
        return done();
    }

    return { explain: explain, run: run };
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
