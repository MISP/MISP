/*
 * The query console page: the writer on top, the latest result below,
 * History and Tables beside them. The next run replaces the result; the
 * results of this page's last runs stay in memory and come back from
 * History without asking MISP again.
 */
import * as T from './tokens.mjs';
import { MispQLWriter } from './writer.mjs';
import { createClient } from './client.mjs';
import * as R from './results.mjs';
import { apiCallPanel } from './snippets.mjs';
import { addableRecords, blockedReason, itemsOf } from './selection.mjs';
import { createInPlace } from './inplace.mjs';
import { el, esc, fmtInt, ago, clock } from './util.mjs';

const SESSION_KEEP = 20;
const HISTORY_KEEP = 50;
const DRAFT_KEY = 'mispql-console-draft';
const NARROW = 900;

const EXAMPLES = [
    { label: 'Domains seen this month', icon: 'fa-table-cells', tables: ['attributes'], text: "SELECT * FROM attributes\nWHERE type IN ('domain', 'hostname') AND to_ids = TRUE AND timestamp >= '30d'\nORDER BY timestamp DESC\nLIMIT 20" },
    { label: 'Phishing events', icon: 'fa-table-cells', tables: ['events'], text: "SELECT id, date, eventinfo, org, tags FROM events\nWHERE eventinfo LIKE '%phishing%'\nORDER BY event_id DESC LIMIT 10 FORMAT table" },
    { label: 'Count C2 addresses', icon: 'fa-hashtag', tables: ['attributes'], text: "SELECT COUNT(*) FROM attributes WHERE type IN ('ip-src', 'ip-dst') AND to_ids = TRUE" },
    { label: 'Threat actors maintained by MISP', icon: 'fa-table-cells', tables: ['galaxy_clusters'], text: "SELECT id, value, Galaxy.name FROM galaxy_clusters\nWHERE galaxy_name = 'Threat Actor' AND org = 'MISP'\nORDER BY value LIMIT 25" },
    { label: 'Fields of objects', icon: 'fa-list-ul', tables: ['objects'], text: 'DESCRIBE objects' },
    { label: 'IDS rules (Suricata export)', icon: 'fa-file-arrow-down', tables: ['attributes'], text: "SELECT * FROM attributes WHERE type IN ('domain', 'ip-dst') AND to_ids = TRUE LIMIT 100 FORMAT suricata" },
    { label: 'Tables you may query', icon: 'fa-layer-group', tables: [], text: 'SHOW TABLES' },
];

function readJsonScript(id, fallback) {
    const node = document.getElementById(id);
    try {
        return node ? JSON.parse(node.textContent) : fallback;
    } catch (e) {
        return fallback;
    }
}

function storage(action, value) {
    try {
        if (action === 'get') {
            return window.localStorage.getItem(DRAFT_KEY);
        }
        if (value) {
            window.localStorage.setItem(DRAFT_KEY, value);
        } else {
            window.localStorage.removeItem(DRAFT_KEY);
        }
    } catch (e) {
        // storage refused: the draft lasts as long as the page
    }
    return null;
}

/** Where this MISP answers, as an API client reaches it. */
function publicBase(baseurl) {
    if (/^https?:\/\//i.test(baseurl || '')) {
        return baseurl.replace(/\/+$/, '');
    }
    return window.location.origin + (baseurl || '');
}

/** Status line under the writer, fed by explain. */
function statusLine(target, writer, reply) {
    const text = writer.value;
    if (!text.trim()) {
        target.innerHTML = '<span class="mql-diag is-idle"><i class="fa-regular fa-keyboard"></i><span>Write a statement' +
            '<span class="mql-idle-keys">; <kbd>Ctrl</kbd><kbd>Space</kbd> suggests</span>.</span></span>';
        return;
    }
    if (!reply) {
        target.innerHTML = '<span class="mql-diag is-idle"><span class="mql-pulse"></span>Checking…</span>';
        return;
    }
    if (reply.failure) {
        target.innerHTML = '<span class="mql-diag is-error"><i class="fa-solid fa-plug-circle-xmark"></i><span class="mql-diag-msg">' +
            esc(reply.failure) + '</span></span>';
        return;
    }
    const e = reply.status !== 200 ? writer.focusError() : null;
    if (reply.status !== 200 && !e) {
        target.innerHTML = '<span class="mql-diag is-idle"><i class="fa-solid fa-pen-nib"></i>Writing…</span>';
        return;
    }
    if (e) {
        const lc = T.lineCol(text, e.from);
        const more = writer.visibleErrors().length - 1;
        target.innerHTML = '<button type="button" class="mql-diag is-error">' +
            '<i class="fa-solid fa-circle-xmark"></i><span class="mql-diag-code">' + esc(e.code) + '</span>' +
            '<span class="mql-diag-msg">' + esc(e.message) + '</span><span class="mql-diag-pos">' + lc.line + ':' + lc.col + '</span>' +
            (more > 0 ? '<span class="mql-diag-more">+' + more + ' more</span>' : '') + '</button>';
        target.querySelector('button').addEventListener('click', function () {
            writer.selectRange(e.from, e.to);
        });
        return;
    }
    const st = writer.statementAtCursor();
    const plan = st && st.plan;
    let what = '';
    if (plan) {
        what = '<code>' + esc(plan.request ? plan.request.method + ' ' + plan.request.endpoint : plan.kind.replace('_', ' ')) + '</code>';
    }
    const count = reply.body.statements.length;
    const notValidated = reply.body.statements.some(function (s) { return s.validated === false; });
    target.innerHTML = '<span class="mql-diag is-ok"><i class="fa-solid fa-circle-check"></i>' +
        (count > 1 ? count + ' statements, valid' : 'Valid') + (what ? '<span class="mql-diag-sep">·</span>compiles to ' + what : '') +
        (notValidated ? '<span class="mql-diag-sep">·</span><span class="text-warning-emphasis">statements after USE are not checked</span>' : '') +
        '</span>';
}

function group(seconds) {
    const d = new Date(seconds * 1000);
    const today = new Date();
    today.setHours(0, 0, 0, 0);
    if (d >= today) {
        return 'Today';
    }
    if (d >= new Date(today.getTime() - 86400000)) {
        return 'Yesterday';
    }
    return 'Earlier';
}

function tableOf(statement) {
    const toks = T.significant(T.tokenize(statement));
    for (let i = 0; i < toks.length - 1; i++) {
        if (toks[i].kind === 'keyword' && (toks[i].value === 'FROM' || toks[i].value === 'DESCRIBE' || toks[i].value === 'DESC')) {
            return toks[i + 1].value;
        }
    }
    return '';
}

/** A template's %s, in order. */
function fill(template, values) {
    let i = 0;
    return String(template || '').replace(/%s/g, function () {
        return i < values.length ? String(values[i++]) : '';
    });
}

/**
 * The floating bar of the grid's selection (the index pages' bulk bar): the
 * count and the workspace's add control, fed with the selected records.
 */
function selectionBar(bar) {
    const count = bar.querySelector('#mql-sel-count');
    const note = bar.querySelector('#mql-sel-note');
    const main = bar.querySelector('[data-intel-graph-add]');
    let clear = null;
    bar.querySelector('#mql-sel-clear').addEventListener('click', function () {
        if (clear) {
            clear();
        }
    });

    function relayout() {
        if (typeof window.syncMultiSelectFloat === 'function') {
            window.syncMultiSelectFloat();
        }
    }

    function hide() {
        clear = null;
        if (!bar.classList.contains('d-none')) {
            bar.classList.add('d-none');
            relayout();
        }
    }

    function show(records, indices, info) {
        const items = itemsOf(records, indices);
        if (!items.length) {
            hide();
            return;
        }
        clear = info.clear;
        main.setAttribute('data-intel-graph-add', JSON.stringify(items));
        const parts = String(count.dataset.template || '%s').split('%s');
        const b = document.createElement('b');
        b.textContent = fmtInt(items.length);
        count.replaceChildren(parts[0], b, parts.slice(1).join('%s'));
        note.hidden = info.returned <= info.drawn;
        note.textContent = note.hidden ? '' : fill(bar.dataset.note, [fmtInt(info.drawn), fmtInt(info.returned)]);
        const opening = bar.classList.contains('d-none');
        bar.classList.remove('d-none');
        if (opening || !note.hidden) {
            relayout();
        }
    }

    /** The grid's selection options for a result, or null when its rows cannot be added here. */
    function optionsFor(r) {
        const records = window.IntelGraphActions ? addableRecords(r.table, r.reply) : null;
        if (!records) {
            return null;
        }
        return {
            unselectable: function (i) { return blockedReason(records[i]); },
            onSelect: function (indices, info) { show(records, indices, info); },
        };
    }

    return { hide: hide, optionsFor: optionsFor };
}

function boot() {
    const page = document.getElementById('mql-console');
    if (!page) {
        return;
    }
    const pack = readJsonScript('mispql-language-pack', { tables: {} });
    let history = readJsonScript('mispql-history', []);
    const baseurl = typeof window.baseurl === 'string' ? window.baseurl : '';
    const client = createClient({
        baseurl: baseurl,
        csrfToken: function () {
            return typeof window.getCsrfToken === 'function' ? window.getCsrfToken() : window.csrfToken;
        },
        sources: pack.sources,
    });
    const apiBase = publicBase(baseurl);

    const statusEl = document.getElementById('wb-status');
    const resultEl = document.getElementById('wb-result');
    const listEl = document.getElementById('wb-list');
    const filterEl = document.getElementById('wb-filter');
    const stmtCountEl = document.getElementById('wb-statements');
    const runBtn = document.getElementById('wb-run');
    const explainBtn = document.getElementById('wb-explain');
    const examples = EXAMPLES.filter(function (ex) {
        return ex.tables.every(function (t) { return pack.tables[t]; });
    });
    const sessionResults = new Map();
    const inPlace = createInPlace({ baseurl: baseurl, client: client, config: readJsonScript('mispql-in-place', {}) });
    const selBarEl = document.getElementById('mql-selbar');
    const selection = selBarEl ? selectionBar(selBarEl) : null;
    let tab = 'history';
    let running = false;
    let current = null;
    let draftTimer = 0;
    let listItems = [];

    const writer = new MispQLWriter(document.getElementById('wb-writer'), {
        pack: pack,
        explain: client.explain,
        lookup: client.lookup,
        minRows: 6,
        maxRows: 18,
        gutter: true,
        placeholder: "SELECT * FROM attributes WHERE type = 'domain' LIMIT 20",
        recall: function () {
            return history.map(function (h) { return h.statement; });
        },
        onRun: function (st) { run(st); },
        onPlan: function (st) { explainStatement(st); },
        onExplain: function (reply, w) {
            statusLine(statusEl, w, reply);
            const n = reply && reply.status === 200 ? reply.body.statements.length : T.splitStatements(w.value).length;
            stmtCountEl.innerHTML = n > 1 ? n + ' statements · <kbd>Ctrl</kbd><kbd>↵</kbd> runs the one under the caret' : '';
        },
        onChange: function (text) {
            if (!text.trim()) {
                statusLine(statusEl, writer, null);
                stmtCountEl.textContent = '';
            }
            clearTimeout(draftTimer);
            draftTimer = setTimeout(function () { storage('set', text); }, 400);
        },
    });

    runBtn.addEventListener('click', function () {
        const st = writer.statementAtCursor();
        if (st) {
            run(st);
        } else {
            writer.focus();
        }
    });
    explainBtn.addEventListener('click', function () {
        const st = writer.statementAtCursor();
        if (st) {
            explainStatement(st);
        } else {
            writer.focus();
        }
    });
    document.getElementById('wb-clear').addEventListener('click', function () {
        writer.setValue('');
        writer.focus();
    });
    const examplesEl = document.getElementById('wb-examples');
    examplesEl.querySelector('.dropdown-menu').innerHTML = examples.map(function (ex, i) {
        return '<li><button type="button" class="dropdown-item d-flex align-items-center gap-2" data-example="' + i + '">' +
            '<i class="fa-solid ' + ex.icon + ' fa-fw text-body-secondary"></i>' + esc(ex.label) + '</button></li>';
    }).join('');
    examplesEl.addEventListener('click', function (e) {
        const b = e.target.closest('[data-example]');
        if (b) {
            writer.setValue(examples[Number(b.dataset.example)].text);
            run(writer.statementAtCursor());
        }
    });

    // ------------------------------------------------------------- run

    function run(st, opts) {
        if (running || !st || !st.text.trim()) {
            return;
        }
        const remember = !opts || opts.remember !== false;
        const source = writer.value;
        const plan = st.plan || null;
        busy(true);
        waiting('fa-play', 'Running…', st.text);
        client.run(st.text, { remember: remember }).then(function (r) {
            busy(false);
            r.plan = plan;
            r.table = r.table || (plan && plan.table) || null;
            r.range = { from: st.from, to: st.to, source: source };
            current = r;
            keep(r);
            if (remember && r.kind !== 'error' && r.kind !== 'failure') {
                remembered(r.statement, r.ranAt);
            }
            showResult(r);
            drawList();
            if (opts && opts.then) {
                opts.then();
            }
        });
    }

    /** What the statement compiles to, from explain: nothing runs, nothing is remembered. */
    function explainStatement(st) {
        if (running || !st || !st.text.trim()) {
            return;
        }
        const source = writer.value;
        busy(true);
        // Explain answers fast: the waiting card only shows if it does not.
        const slow = setTimeout(function () { waiting('fa-route', 'Explaining…', st.text); }, 150);
        client.plan(st.text).then(function (r) {
            clearTimeout(slow);
            busy(false);
            r.range = { from: st.from, to: st.to, source: source };
            current = null;
            showResult(r);
            drawList();
        });
    }

    function busy(on) {
        running = on;
        runBtn.disabled = on;
        explainBtn.disabled = on;
    }

    function waiting(icon, title, text) {
        resultEl.classList.add('is-running');
        resultEl.innerHTML = '<div class="wb-result-head"><span class="cq-kind-icon"><i class="fa-solid ' + icon + '"></i></span>' +
            '<h2 class="wb-result-title">' + title + '</h2></div>' +
            '<div class="wb-ran">' + R.highlight(text, []) + '</div>' +
            '<div class="cq-loading"><div class="misp-loader" role="status"><span class="visually-hidden">Loading…</span></div>Asking MISP…</div>';
    }

    /** The server's history rule, applied to the page's copy. */
    function remembered(statement, ranAt) {
        const text = statement.trim();
        history = [{ statement: text, ran_at: ranAt }].concat(history.filter(function (h) {
            return h.statement !== text;
        })).slice(0, HISTORY_KEEP);
    }

    /** This page's results, in memory only: the last SESSION_KEEP runs. */
    function keep(r) {
        const key = r.statement.trim();
        sessionResults.delete(key);
        sessionResults.set(key, r);
        while (sessionResults.size > SESSION_KEEP) {
            sessionResults.delete(sessionResults.keys().next().value);
        }
    }

    /** A History entry: its statement into the writer, and its result if it ran on this page. */
    function recall(statement) {
        writer.setValue(statement);
        const kept = sessionResults.get(statement.trim());
        if (kept && !running) {
            kept.range = { from: 0, to: statement.length, source: statement };
            current = kept;
            showResult(kept, { recalled: true });
            drawList();
        }
    }

    function showResult(r, opts) {
        resultEl.classList.remove('is-running');
        resultEl.innerHTML = '';
        if (selection) {
            selection.hide();
        }
        inPlace.reset();
        const head = el('div', 'wb-result-head');
        const meta = [];
        if (r.table) {
            meta.push('<code>' + esc(r.table) + '</code>');
        }
        meta.push('<span>' + esc(R.summary(r)) + '</span>');
        meta.push('<span>' + fmtInt(r.elapsed) + ' ms</span>');
        const client_ = R.isClient(r);
        const failed = r.kind === 'error' || r.kind === 'failure';
        const isPlan = r.kind === 'plan';
        const runnable = isPlan && r.plan && !client_;
        let title = 'Result';
        if (client_) {
            title = 'Not run here';
        } else if (failed) {
            title = r.explained && r.kind === 'error' ? 'Not valid' : 'Not run';
        } else if (isPlan) {
            title = 'Plan';
        }
        head.innerHTML = '<span class="cq-kind-icon' + (failed && !client_ ? ' is-error' : '') + '"><i class="fa-solid ' + R.kindIcon(r) + '"></i></span>' +
            '<h2 class="wb-result-title">' + title + '</h2>' +
            '<div class="wb-result-meta">' + meta.join('<span class="mql-diag-sep">·</span>') + '</div>' +
            '<div class="wb-result-actions"></div>';
        const actions = head.querySelector('.wb-result-actions');
        const apiBtn = el('button', 'btn btn-sm btn-outline-secondary', '<i class="fa-solid fa-code"></i>API call');
        apiBtn.type = 'button';
        apiBtn.setAttribute('aria-expanded', 'false');
        if (!failed && !isPlan) {
            actions.appendChild(apiBtn);
        }
        if (runnable) {
            const runIt = el('button', 'btn btn-sm btn-outline-primary', '<i class="fa-solid fa-play"></i>Run');
            runIt.type = 'button';
            runIt.addEventListener('click', function () {
                run({ text: r.statement, from: r.range.from, to: r.range.to, plan: r.plan });
            });
            actions.appendChild(runIt);
        }
        resultEl.appendChild(head);

        if (opts && opts.recalled) {
            const note = el('div', 'wb-recalled', '<i class="fa-regular fa-clock"></i><span>Result from <b>' + clock(r.ranAt) +
                '</b>, earlier on this page. It is not refreshed.</span>');
            const again = el('button', 'btn btn-sm btn-outline-secondary', '<i class="fa-solid fa-rotate-right"></i>Run again');
            again.type = 'button';
            again.addEventListener('click', function () {
                run({ text: r.statement, from: r.range.from, to: r.range.to, plan: r.plan });
            });
            note.appendChild(again);
            resultEl.appendChild(note);
        }

        const ran = el('div', 'wb-ran');
        ran.innerHTML = R.highlight(r.statement, r.kind === 'error' && !client_ ? r.errors : []);
        resultEl.appendChild(ran);

        let api = null;
        apiBtn.addEventListener('click', function () {
            if (api) {
                api.remove();
                api = null;
                apiBtn.classList.remove('active');
                apiBtn.setAttribute('aria-expanded', 'false');
                return;
            }
            api = apiCallPanel(r.statement, planOf(r), apiBase);
            ran.after(api);
            apiBtn.classList.add('active');
            apiBtn.setAttribute('aria-expanded', 'true');
        });

        const selecting = selection && r.kind === 'rows' ? selection.optionsFor(r) : null;
        resultEl.appendChild(R.render(r, Object.assign({
            pack: pack,
            baseurl: baseurl,
            valueAddress: window.MispValueAddress ? window.MispValueAddress.address : null,
            galaxies: client.galaxies,
            hideStatement: true,
            onPage: function (next) { pageTo(r, next); },
            onFilter: function (next) { pageTo(r, next, { remember: true }); },
            onInsert: function (text) { writer.insert(text + ' '); },
            onPick: function (table) { writer.setValue('DESCRIBE ' + table); run(writer.statementAtCursor()); },
            onLocate: function (e) { locate(r, e); },
            opens: inPlace.views,
            onOpen: inPlace.open,
        }, selecting)));
        if (runnable) {
            resultEl.appendChild(apiCallPanel(r.statement, r.plan, apiBase, { explain: true }));
        }
    }

    /** The request behind a result: explain's plan, else what run sent back. */
    function planOf(r) {
        if (r.plan && r.plan.request) {
            return r.plan;
        }
        return r.reply && r.reply.request ? { request: r.reply.request } : r.plan;
    }

    /**
     * A rewrite of the result's statement (a page, a filter) goes into the
     * writer where the statement still is, else replaces it, then runs. Only
     * a filter, a new question, is remembered.
     */
    function pageTo(r, next, opts) {
        const remember = !!(opts && opts.remember);
        const back = focusInResult();
        const range = r.range;
        const text = writer.value;
        if (range && text.slice(range.from, range.to) === r.statement) {
            writer.setValue(text.slice(0, range.from) + next + text.slice(range.to), range.from + next.length);
            run({ text: next, from: range.from, to: range.from + next.length }, { remember: remember, then: back });
        } else {
            writer.setValue(next);
            run({ text: next, from: 0, to: next.length }, { remember: remember, then: back });
        }
    }

    /**
     * Where in the result the focus was when a rewrite started from it (a
     * header, a cell's menu, the pager): setting the writer's text takes the
     * focus, this gives it back to the same place in the next result.
     */
    function focusInResult() {
        const a = document.activeElement;
        if (!a || !resultEl.contains(a)) {
            return null;
        }
        const cell = a.closest('.cq-grid [data-c]');
        let sel = null;
        if (cell) {
            sel = (cell.tagName === 'TH' ? '.cq-grid thead' : '.cq-grid tbody tr:first-child') + ' [data-c="' + cell.dataset.c + '"]';
        } else if (a.matches('[data-go]')) {
            sel = '[data-go="' + a.dataset.go + '"]';
        } else if (a.matches('.cq-size select')) {
            sel = '.cq-size select';
        }
        return function () {
            let to = sel && resultEl.querySelector(sel);
            if (!to || to.disabled) {
                to = resultEl.querySelector('.cq-grid [data-c][tabindex="0"]');
            }
            if (!to) {
                return;
            }
            if (to.matches('[data-c]')) {
                const was = resultEl.querySelector('.cq-grid [data-c][tabindex="0"]');
                if (was && was !== to) {
                    was.removeAttribute('tabindex');
                }
                to.setAttribute('tabindex', '0');
            }
            to.focus();
        };
    }

    function locate(r, e) {
        const range = r.range;
        if (range && writer.value.slice(range.from, range.to) === r.statement) {
            writer.selectRange(range.from + e.from, range.from + e.to);
        } else {
            writer.setValue(r.statement);
            writer.selectRange(e.from, e.to);
        }
    }

    function emptyResult() {
        resultEl.innerHTML = '<div class="wb-empty"><i class="fa-solid fa-magnifying-glass-chart"></i>' +
            '<div><b class="text-body-emphasis">Results show here.</b><br>Write a statement and press <kbd>Ctrl</kbd><kbd>↵</kbd>, or start from an example.</div>' +
            '<div class="wb-examples">' + examples.map(function (ex, i) {
                return '<button type="button" class="cq-example" data-ex="' + i + '">' + esc(ex.label) + '</button>';
            }).join('') + '</div></div>';
    }

    resultEl.addEventListener('click', function (e) {
        const b = e.target.closest('[data-ex]');
        if (b) {
            writer.setValue(examples[Number(b.dataset.ex)].text);
            run(writer.statementAtCursor());
        }
    });

    // ------------------------------------------------------- side list

    function drawList() {
        const q = filterEl.value.trim().toLowerCase();
        const tables = Object.keys(pack.tables);
        document.getElementById('wb-hist-count').textContent = history.length;
        document.getElementById('wb-table-count').textContent = tables.length;
        if (tab === 'history') {
            listItems = history.filter(function (h) { return !q || h.statement.toLowerCase().indexOf(q) !== -1; });
            if (!listItems.length) {
                listEl.innerHTML = '<div class="cq-empty"><i class="fa-regular fa-clock"></i><div>' +
                    (q ? 'No statement matches.' : 'Statements you run show here, on any device you log in from.') + '</div></div>';
                return;
            }
            let html = '';
            let last = '';
            listItems.forEach(function (h, i) {
                const g = group(h.ran_at);
                if (g !== last) {
                    html += '<div class="wb-group-label">' + g + '</div>';
                    last = g;
                }
                const r = sessionResults.get(h.statement.trim());
                const failed = r && (r.kind === 'error' || r.kind === 'failure') && !R.isClient(r);
                const icon = r ? '<span class="cq-kind-icon ' + (failed ? 'is-error' : 'is-done') + '"><i class="fa-solid ' + R.kindIcon(r) + '"></i></span>'
                    : '<span class="cq-kind-icon"><i class="fa-regular fa-clock"></i></span>';
                const isCurrent = current && current.statement.trim() === h.statement.trim();
                const table = tableOf(h.statement);
                html += '<div class="wb-hist' + (isCurrent ? ' is-current' : '') + '" role="button" tabindex="0" data-h="' + i + '" title="' +
                    (r ? 'Load into the writer and show its result from this page' : 'Load into the writer') + '">' + icon +
                    '<span class="wb-hist-stmt">' + R.highlight(h.statement, []) + '</span>' +
                    '<span class="wb-hist-meta">' + (table ? '<span class="wb-table">' + esc(table) + '</span>' : '') + '<span>' + esc(ago(h.ran_at)) + '</span>' +
                    (r ? '<span>· ' + esc(R.summary(r)) + '</span>' : '') + '</span>' +
                    '<button type="button" class="wb-hist-run" data-run="' + i + '" title="Run again" aria-label="Run again"><i class="fa-solid fa-play"></i></button></div>';
            });
            listEl.innerHTML = html;
            return;
        }
        listEl.innerHTML = tables.filter(function (name) {
            return !q || name.indexOf(q) !== -1 || Object.keys(pack.tables[name].fields).some(function (f) { return f.toLowerCase().indexOf(q) !== -1; });
        }).map(function (name) {
            const t = pack.tables[name];
            const fields = Object.keys(t.fields).filter(function (f) { return !q || name.indexOf(q) !== -1 || f.toLowerCase().indexOf(q) !== -1; });
            return '<details class="wb-schema-table"' + (q ? ' open' : '') + '><summary><i class="fa-solid fa-chevron-right"></i>' + esc(name) +
                '<span class="wb-count">' + Object.keys(t.fields).length + ' fields</span></summary><div class="wb-fields">' +
                fields.map(function (f) {
                    const d = t.fields[f];
                    const tip = (d.description ? d.description + '\n' : '') + d.operators.join(' ');
                    return '<button type="button" class="wb-field" data-insert="' + esc(f.replace('<key>', '')) + '" title="' + esc(tip) + '">' +
                        '<span class="wb-field-name">' + esc(f) + '</span><span class="mql-type mql-type-' + esc(d.type) + '">' + esc(d.type) + '</span>' +
                        (d.description ? '<span class="wb-field-doc">' + esc(d.description) + '</span>' : '') + '</button>';
                }).join('') + '</div></details>';
        }).join('') || '<div class="cq-empty"><i class="fa-solid fa-table"></i><div>' +
            (q ? 'No table or field matches.' : 'Your role may query no table.') + '</div></div>';
    }

    listEl.addEventListener('click', function (e) {
        const again = e.target.closest('[data-run]');
        const item = e.target.closest('[data-h]');
        const field = e.target.closest('[data-insert]');
        if (again) {
            e.stopPropagation();
            writer.setValue(listItems[Number(again.dataset.run)].statement);
            run(writer.statementAtCursor());
        } else if (item) {
            recall(listItems[Number(item.dataset.h)].statement);
        } else if (field) {
            writer.insert(field.dataset.insert + ' ');
        }
    });
    listEl.addEventListener('keydown', function (e) {
        const item = e.target.closest('[data-h]');
        if (item && e.target === item && (e.key === 'Enter' || e.key === ' ')) {
            e.preventDefault();
            recall(listItems[Number(item.dataset.h)].statement);
        }
    });
    filterEl.addEventListener('input', drawList);
    const libTabs = Array.prototype.slice.call(page.querySelectorAll('[data-lib-tab]'));
    libTabs.forEach(function (b) {
        b.setAttribute('tabindex', b.classList.contains('active') ? '0' : '-1');
        b.addEventListener('click', function () {
            tab = b.dataset.libTab;
            libTabs.forEach(function (o) {
                o.classList.toggle('active', o === b);
                o.setAttribute('aria-selected', o === b ? 'true' : 'false');
                o.setAttribute('tabindex', o === b ? '0' : '-1');
            });
            filterEl.placeholder = tab === 'history' ? 'Filter history' : 'Filter tables and fields';
            drawList();
        });
        b.addEventListener('keydown', function (e) {
            const at = libTabs.indexOf(b);
            const to = { ArrowLeft: at - 1, ArrowRight: at + 1, Home: 0, End: libTabs.length - 1 }[e.key];
            if (to === undefined) {
                return;
            }
            e.preventDefault();
            const next = libTabs[(to + libTabs.length) % libTabs.length];
            next.focus();
            next.click();
        });
    });

    // ----------------------------------------------------------- start

    drawList();
    emptyResult();
    const asked = new URLSearchParams(window.location.search).get('q');
    const start = asked !== null ? asked : (storage('get') || '');
    if (start) {
        writer.setValue(start);
    }
    statusLine(statusEl, writer, null);
    writer.focus();

    // Beside the workspace dock the page can be narrower than its two columns need
    const wide = window.matchMedia('(min-width: 992px)');
    if (window.ResizeObserver) {
        new ResizeObserver(function (entries) {
            page.classList.toggle('is-narrow', wide.matches && entries[0].contentRect.width < NARROW);
        }).observe(page);
    }
}

if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', boot);
} else {
    boot();
}
