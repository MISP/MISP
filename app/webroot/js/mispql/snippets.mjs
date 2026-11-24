/*
 * MispQL console: the API call behind a result, as the /mispql/run call
 * (and /mispql/explain for a plan), the compiled restSearch request, curl
 * and PyMISP.
 */

import { el, esc, jsonHTML, copyText } from './util.mjs';

function pyLiteral(v, indent) {
    indent = indent || '';
    if (v === true) {
        return 'True';
    }
    if (v === false) {
        return 'False';
    }
    if (v === null) {
        return 'None';
    }
    if (Array.isArray(v)) {
        return '[' + v.map(function (x) { return pyLiteral(x, indent); }).join(', ') + ']';
    }
    if (typeof v === 'object') {
        var inner = indent + '    ';
        return '{\n' + Object.keys(v).map(function (k) {
            return inner + JSON.stringify(k) + ': ' + pyLiteral(v[k], inner);
        }).join(',\n') + '\n' + indent + '}';
    }
    return JSON.stringify(v);
}

function shellQuote(s) {
    return "'" + s.replace(/'/g, "'\\''") + "'";
}

function mispqlCall(baseUrl, action, body) {
    return 'curl -X POST ' + baseUrl + '/mispql/' + action + ' \\\n  -H "Authorization: $MISP_KEY" \\\n  -H "Accept: application/json" \\\n' +
        '  -H "Content-Type: application/json" \\\n  -d ' + shellQuote(JSON.stringify(body));
}

/** opts.explain: the /mispql/explain call comes first. */
function snippets(statement, plan, baseUrl, opts) {
    var out = [];
    if (opts && opts.explain) {
        out.push({ id: 'explain', label: '/mispql/explain', text: mispqlCall(baseUrl, 'explain', { script: statement.trim() }) });
    }
    out.push({ id: 'mispql', label: '/mispql/run', text: mispqlCall(baseUrl, 'run', { statement: statement.trim() }) });
    if (plan && plan.request) {
        var req = plan.request;
        var url = baseUrl + req.endpoint;
        out.push({ id: 'json', label: 'Request', text: req.method + ' ' + req.endpoint + (req.body ? '\n' + JSON.stringify(req.body, null, 2) : ''), json: true });
        out.push({
            id: 'curl', label: 'curl',
            text: 'curl -X ' + req.method + ' ' + url + ' \\\n  -H "Authorization: $MISP_KEY" \\\n  -H "Accept: application/json"' +
                (req.body ? ' \\\n  -H "Content-Type: application/json" \\\n  -d ' + shellQuote(JSON.stringify(req.body)) : '')
        });
        out.push({
            id: 'pymisp', label: 'PyMISP',
            text: 'from pymisp import PyMISP\n\nmisp = PyMISP("' + baseUrl + '", MISP_KEY)\n' +
                (req.body
                    ? 'body = ' + pyLiteral(req.body) + '\nresult = misp.direct_call("' + req.endpoint.slice(1) + '", body)'
                    : 'result = misp.direct_call("' + req.endpoint.slice(1) + '")')
        });
    }
    return out;
}

/** baseUrl: where this MISP answers, as an API client reaches it. opts as snippets() takes them. */
function apiCallPanel(statement, plan, baseUrl, opts) {
    var list = snippets(statement, plan, baseUrl, opts);
    var wrap = el('div', 'cq-api');
    var tabs = el('div', 'cq-api-tabs');
    var pre = el('pre', 'cq-api-code');
    var copy = el('button', 'btn btn-sm btn-outline-secondary cq-copy', '<i class="fa-regular fa-copy"></i><span>Copy</span>');
    copy.type = 'button';
    var current = list.filter(function (item) { return item.id === 'json'; })[0] || list[0];
    function show(item) {
        current = item;
        tabs.querySelectorAll('button').forEach(function (b) { b.classList.toggle('active', b.dataset.id === item.id); });
        pre.innerHTML = item.json ? esc(item.text.split('\n')[0]) + '\n' + jsonHTML(JSON.parse(item.text.split('\n').slice(1).join('\n') || 'null')) : esc(item.text);
    }
    list.forEach(function (item) {
        var b = el('button', 'cq-api-tab', esc(item.label));
        b.type = 'button';
        b.dataset.id = item.id;
        b.addEventListener('click', function () { show(item); });
        tabs.appendChild(b);
    });
    tabs.appendChild(copy);
    copy.addEventListener('click', function () {
        copyText(current.text, copy);
    });
    if (plan && plan.next_page) {
        var note = el('div', 'cq-api-note', '<i class="fa-solid fa-circle-info"></i>The offset is not a multiple of the limit: a second page (' +
            esc(plan.next_page.endpoint) + ', page ' + esc(plan.next_page.body.page) + ') is read when the first one is full.');
        wrap.appendChild(tabs);
        wrap.appendChild(pre);
        wrap.appendChild(note);
    } else {
        wrap.appendChild(tabs);
        wrap.appendChild(pre);
    }
    show(current);
    return wrap;
}

export {
    snippets,
    apiCallPanel,
};
