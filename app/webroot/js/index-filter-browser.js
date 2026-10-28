/*
 * Column browser for a filter bar picker whose config carries `browser`
 * (`{kind: 'tag'|'galaxy', scopes, tree}`): scopes · sub-groups · values,
 * side by side. index-filters.js hands such pickers over through
 * window.IndexFilterBrowser; selection, serialisation and applying on close
 * follow its rules. Nothing scrolls: long lists reflow into columns.
 *
 * mount() draws the same browser inside a host element instead (the tag and
 * galaxy picker modals): a pick is either global or local rather than
 * included or excluded, and the host owns the selection, handing it back with
 * select(). A tag host may add its tag collections as one more scope.
 */
(function () {
    'use strict';

    // A modal loads this on demand, so a page can bring it twice.
    if (window.IndexFilterBrowser) { return; }

    var ROW = 28;
    var RICH = 46;
    var SIDE_W = 212;
    var SPINE_W = 40;
    var MID_W = 196;
    var VAL_W = 236;
    var VAL_ID_W = 300;
    var RICH_W = 360;
    var LETTER_W = 54;
    var MIN_ROWS = 12;
    var MIN_BELOW = 8;
    var MIN_W = 800;
    var MAX_W = 1400;
    var DEBOUNCE = 200;
    var BROWSE = 200;
    var GLOBAL = 80;
    var EMBED_ROWS = [8, 14];

    var st = null;
    // Height of everything but the lists (search bar, column heads, tray),
    // measured after each render; this is the first guess.
    var chrome = 156;
    var models = {};
    var trees = {};
    var strings = {};

    /* ── small helpers ────────────────────────────────────────────────── */

    // T('key') or T('key', a, b): the bar's translated string, each %s filled in turn.
    function T(key) {
        var text = strings[key] || key;
        var args = Array.prototype.slice.call(arguments, 1);
        return text.replace(/%s/g, function () { return args.length ? String(args.shift()) : ''; });
    }

    function lc(s) { return String(s == null ? '' : s).toLowerCase(); }

    function esc(text) {
        return String(text == null ? '' : text).replace(/[&<>"']/g, function (c) {
            return { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c];
        });
    }

    function num(n) { return Number(n || 0).toLocaleString('en-US'); }

    function has(text, term) { return !term || lc(text).indexOf(term) !== -1; }

    function hl(text, term) {
        text = String(text == null ? '' : text);
        var i = term ? lc(text).indexOf(term) : -1;
        if (i === -1) { return esc(text); }
        return esc(text.slice(0, i)) + '<mark class="ifb-hl">' + esc(text.slice(i, i + term.length))
            + '</mark>' + esc(text.slice(i + term.length));
    }

    function iconClass(icon) { return icon || 'fas fa-circle-nodes'; }

    function api(url, params, signal) {
        var qs = params ? (url.indexOf('?') === -1 ? '?' : '&') + new URLSearchParams(params).toString() : '';
        return fetch(url + qs, {
            credentials: 'same-origin',
            headers: { Accept: 'application/json' },
            signal: signal,
        }).then(function (r) {
            if (!r.ok) { throw new Error('HTTP ' + r.status); }
            return r.json();
        });
    }

    function humanize(s) {
        s = String(s || '').replace(/-/g, ' ');
        return s.charAt(0).toUpperCase() + s.slice(1);
    }

    // "(TLP:RED) For the eyes…" → value + the sentence; a short code reads
    // better as a badge in front of its expansion.
    function describe(value, expanded) {
        var ex = String(expanded || '').trim();
        var m = /^\(([^)]{1,40})\)\s*(.*)$/.exec(ex);
        if (m) { return { label: value, sub: m[2] }; }
        if (!ex || lc(ex) === lc(value)) { return { label: value }; }
        if (String(value).length <= 4) { return { badge: value, label: ex }; }
        return { label: value, sub: ex };
    }

    // "Phishing - T1566" → name + id, so the id lines up at the right.
    function splitId(label) {
        var m = /^(.*\S)\s+-\s+((?:[A-Z]{1,2}\d{3,4}(?:\.\d{3})?)|(?:[A-Z]{2,4}-[A-Z]{2,5}-\d{2,4}))$/.exec(label);
        return m ? { name: m[1], id: m[2] } : { name: label, id: null };
    }

    function tagNs(value) {
        var i = String(value).indexOf(':');
        return i > 0 ? lc(value.slice(0, i)) : '-';
    }

    function clusterType(value) {
        var m = /^misp-galaxy:([^=]+)=/.exec(String(value));
        return m ? lc(m[1]) : null;
    }

    /* ── scope models ─────────────────────────────────────────────────── */

    function loadModel(kind, url) {
        if (!models[kind]) {
            models[kind] = api(url).then(kind === 'tag' ? tagModel : galaxyModel);
            models[kind].catch(function () { delete models[kind]; });
        }
        return models[kind];
    }

    // Profile scopes in the profile's own order, pinned before preferred.
    function byProfile(a, b) {
        return ((a.pinned || 1e3) - (b.pinned || 1e3)) || ((a.preferred || 1e3) - (b.preferred || 1e3));
    }

    function bySize(a, b) { return (b.size - a.size) || a.label.localeCompare(b.label); }

    function tagModel(d) {
        var byId = {};
        var add = function (s) { byId[s.id] = s; return s; };
        var tax = d.taxonomies.map(function (t) {
            return add({
                id: 'tax:' + lc(t.namespace), kind: 'tax', ns: t.namespace, label: t.namespace,
                desc: t.description || '', enabled: !!t.enabled, size: t.tags || 0,
                pinned: t.pinned, preferred: t.preferred, icon: 'fas fa-tags', group: 'g:tax',
            });
        });
        tax.sort(function (a, b) { return (b.enabled - a.enabled) || bySize(a, b); });
        var nss = d.namespaces.filter(function (n) {
            return lc(n.namespace).trim() !== 'misp-galaxy';
        }).map(function (n) {
            return add({
                id: 'ns:' + lc(n.namespace), kind: 'ns', ns: n.namespace, label: n.namespace.trim(),
                size: n.tags, icon: 'fas fa-tag', group: 'g:ns',
                desc: T('nsDesc', n.namespace.trim()),
            });
        });
        nss.sort(bySize);
        var none = add({
            id: 'none', kind: 'none', ns: '-', label: T('noNamespace'), size: d.no_namespace,
            icon: 'fas fa-hashtag', direct: true, group: null,
            desc: T('noNamespaceDesc'),
        });
        var pinned = tax.filter(function (t) { return t.pinned || t.preferred; }).sort(byProfile);
        pinned.forEach(function (t) { t.direct = true; });
        var groups = {
            'g:tax': {
                id: 'g:tax', label: T('taxonomies'), icon: 'fas fa-folder', scopes: tax,
                sections: [
                    { head: T('enabled'), items: tax.filter(function (t) { return t.enabled; }) },
                    { head: T('notEnabled'), items: tax.filter(function (t) { return !t.enabled; }) },
                ],
            },
            'g:ns': {
                id: 'g:ns', label: T('namespaces'), hint: T('noTaxonomy'), icon: 'fas fa-folder', scopes: nss,
                sections: [{ head: null, items: nss }],
            },
        };
        return {
            kind: 'tag', root: T('allTags'), rootIcon: 'fas fa-tag',
            byId: byId, groups: groups, defaultGroup: 'g:tax',
            side: [
                { head: T('pinnedInProfile'), icon: 'fas fa-thumbtack', items: pinned },
                { head: T('browse'), icon: 'fas fa-folder-tree', items: [groups['g:tax'], groups['g:ns'], none] },
            ],
            all: tax.concat(nss, [none]),
        };
    }

    var GAL_NAMES = {
        mitre: 'MITRE', misp: 'MISP', tidal: 'Tidal', disarm: 'DISARM', 'nist-nice': 'NIST NICE',
    };
    var GAL_ORDER = ['mitre', 'misp', 'tidal', 'disarm', 'nist-nice'];

    function galaxyModel(list) {
        var byId = {};
        var add = function (s) { byId[s.id] = s; return s; };
        var scopes = list.map(function (g) {
            return add({
                id: 'gal:' + lc(g.type), kind: 'galaxy', type: g.type, label: g.name, ns: lc(g.namespace),
                icon: iconClass(g.icon), desc: g.description || '', size: g.clusters, inUse: g.in_use || 0,
                tactics: g.kill_chain && g.kill_chain.length > 1 ? g.kill_chain : null,
                pinned: g.pinned, preferred: g.preferred, direct: !!(g.pinned || g.preferred),
            });
        });
        var count = {};
        scopes.forEach(function (s) { count[s.ns] = (count[s.ns] || 0) + 1; });
        var keyOf = function (s) {
            if (GAL_ORDER.indexOf(s.ns) !== -1 || s.ns === 'deprecated' || count[s.ns] >= 3) { return s.ns; }
            return 'other';
        };
        var groups = {};
        scopes.forEach(function (s) {
            var k = keyOf(s);
            s.group = 'g:' + k;
            if (!groups[s.group]) {
                var label = k === 'deprecated' ? T('deprecated') : (k === 'other' ? T('otherNamespaces') : GAL_NAMES[k]);
                groups[s.group] = {
                    id: s.group, key: k, label: label || k.toUpperCase(), scopes: [],
                    icon: k === 'deprecated' ? 'fas fa-box-archive' : 'fas fa-folder',
                };
            }
            groups[s.group].scopes.push(s);
        });
        var keys = Object.keys(groups).map(function (id) { return groups[id].key; });
        var rank = function (k) {
            var i = GAL_ORDER.indexOf(k);
            if (i !== -1) { return i; }
            return k === 'deprecated' ? 300 : (k === 'other' ? 200 : 100);
        };
        keys.sort(function (a, b) { return (rank(a) - rank(b)) || a.localeCompare(b); });
        var ordered = keys.map(function (k) {
            var g = groups['g:' + k];
            g.scopes.sort(function (a, b) { return a.label.localeCompare(b.label); });
            g.sections = [{ head: null, items: g.scopes }];
            return g;
        });
        return {
            kind: 'galaxy', root: T('allGalaxies'), rootIcon: 'fas fa-earth-europe',
            byId: byId, groups: groups, defaultGroup: groups['g:misp'] ? 'g:misp' : (ordered.length ? ordered[0].id : null),
            side: [
                {
                    head: T('preferredInProfile'), icon: 'fas fa-star',
                    items: scopes.filter(function (s) { return s.direct; }).sort(byProfile),
                },
                { head: T('byNamespace'), icon: 'fas fa-folder-tree', items: ordered },
            ],
            all: scopes,
        };
    }

    function loadTree(ns) {
        var key = lc(ns);
        if (!trees[key]) {
            trees[key] = api(st.urls.tree, { namespace: ns }).then(treeModel);
            trees[key].catch(function () { delete trees[key]; });
        }
        return trees[key];
    }

    function treeModel(tree) {
        var tags = {};
        var preds = tree.predicates.map(function (p) {
            var entries = p.entries.filter(function (e) { return e.tag_exists; }).map(function (e) {
                tags[lc(e.tag)] = true;
                return {
                    tag: e.tag, value: e.value, expanded: e.expanded, colour: e.colour || p.colour,
                    nv: e.numerical_value, id: e.tag_id, localOnly: e.local_only,
                };
            });
            var self = null;
            if (!p.entries.length && p.tag && p.tag_exists) {
                self = {
                    tag: p.tag, value: p.value, expanded: p.expanded, colour: p.colour,
                    id: p.tag_id, localOnly: p.local_only,
                };
                tags[lc(p.tag)] = true;
            }
            var path = String(p.value).split(':');
            return { id: p.value, label: p.value, expanded: p.expanded, entries: entries, self: self, path: path };
        });
        var existing = 0;
        var withEntries = 0;
        preds.forEach(function (p) {
            existing += p.entries.length + (p.self ? 1 : 0);
            if (p.entries.length) { withEntries++; }
        });
        return {
            namespace: tree.namespace, desc: tree.description, preds: preds, tags: tags,
            existing: existing, big: withEntries > 1 && existing > 48,
        };
    }

    /* ── selection ────────────────────────────────────────────────────── */

    // `a&b` asks for all of them, which only means something with two or more included.
    function serialize(selection, pc, allOf) {
        if (!selection.length) { return null; }
        var sep = allOf && includedCount(selection) > 1 ? '&' : (pc.sep || '|');
        return selection.map(function (s) { return (s.exclude ? '!' : '') + s.value; }).join(sep);
    }

    function includedCount(selection) {
        return selection.filter(function (s) { return !s.exclude; }).length;
    }

    function stateOf(value) {
        var hit = st.selection.find(function (s) { return s.value === value; });
        if (!hit) { return 'none'; }
        if (st.embedded) { return hit.local ? 'local' : 'include'; }
        return hit.exclude ? 'exclude' : 'include';
    }

    // A tag collection counts as picked once every one of its tags is.
    function collState(c) {
        return c.tags.length && c.tags.every(function (t) { return stateOf(t.name) !== 'none'; }) ? 'include' : 'none';
    }

    function rowState(row) { return row.collection ? collState(row.collection) : stateOf(row.value); }

    function toggle(row, exclude) {
        if (st.embedded) {
            st.onToggle(row, rowState(row) === 'none');
            return;
        }
        var i = st.selection.findIndex(function (s) { return s.value === row.value; });
        var current = i === -1 ? 'none' : (st.selection[i].exclude ? 'exclude' : 'include');
        var next = exclude
            ? (current === 'exclude' ? 'none' : 'exclude')
            : (current === 'none' ? 'include' : 'none');
        if (next === 'none') {
            st.selection.splice(i, 1);
        } else if (i !== -1) {
            st.selection[i].exclude = next === 'exclude';
        } else {
            st.selection.push({
                value: row.value, label: row.label, style: row.style || null,
                exclude: next === 'exclude', unresolved: false,
            });
        }
        st.dirty = true;
        render();
    }

    function scopeHasSelection(scope) {
        if (scope.kind === 'coll') {
            return scope.items.some(function (c) { return collState(c) !== 'none'; });
        }
        return st.selection.some(function (s) {
            if (scope.kind === 'galaxy') { return clusterType(s.value) === lc(scope.type); }
            if (scope.kind === 'none') { return tagNs(s.value) === '-'; }
            return tagNs(s.value) === lc(scope.ns);
        });
    }

    function scopeOfValue(value) {
        var m = st.model;
        if (m.kind === 'galaxy') { return m.byId['gal:' + clusterType(value)] || null; }
        var ns = tagNs(value);
        if (ns === '-') { return m.byId.none; }
        return m.byId['tax:' + ns] || m.byId['ns:' + ns] || null;
    }

    /* ── navigation ───────────────────────────────────────────────────── */

    // The collections scope belongs to one mounted browser, not to the shared model.
    function scopeById(id) { return st.coll && id === st.coll.id ? st.coll : st.model.byId[id]; }

    function currentScope() {
        var step = st.path.find(function (s) { return s.k === 'scope'; });
        return step ? scopeById(step.id) : null;
    }

    function currentSub() { return st.path.find(function (s) { return s.k === 'sub'; }) || null; }

    function openGroup(id) {
        st.path = [{ k: 'group', id: id }];
        st.wide = false;
        st.term = '';
        syncInput();
        refresh();
    }

    function openScope(scope, opts) {
        opts = opts || {};
        if (opts.fromGroup || (!scope.direct && scope.group)) {
            st.path = [{ k: 'group', id: scope.group }, { k: 'scope', id: scope.id }];
        } else {
            st.path = [{ k: 'scope', id: scope.id }];
        }
        st.wide = false;
        if (!opts.keepTerm) { st.term = ''; syncInput(); }
        // A filter wants what is in use; a picker attaches new clusters as often.
        st.inUse = scope.kind === 'galaxy' && !st.embedded ? scope.inUse > 0 : false;
        refresh();
    }

    function openSub(id, label) {
        var i = st.path.findIndex(function (s) { return s.k === 'scope'; });
        st.path = st.path.slice(0, i + 1);
        if (id !== null) { st.path.push({ k: 'sub', id: id, label: label }); }
        refresh();
    }

    function popTo(i) {
        st.wide = false;
        st.path = st.path.slice(0, i + 1);
        if (!st.path.length) { st.path = [{ k: 'group', id: st.model.defaultGroup }]; }
        refresh();
    }

    function back() {
        var last = st.path[st.path.length - 1];
        if (!last || last.k === 'group') { return false; }
        st.wide = false;
        if (last.k === 'scope' && st.path.length === 1) {
            var scope = scopeById(last.id);
            st.path = [{ k: 'group', id: (scope && scope.group) || st.model.defaultGroup }];
        } else {
            st.path = st.path.slice(0, -1);
        }
        refresh();
        return true;
    }

    /* ── data for the current view ────────────────────────────────────── */

    function wantKey() {
        var scope = currentScope();
        var sub = currentSub();
        var term = st.term.trim();
        if (!scope) { return term.length >= 2 ? 'g|' + lc(term) : null; }
        if (scope.kind === 'coll') { return 'coll'; }
        if (scope.kind === 'tax') { return 'tax|' + scope.id + '|' + lc(term); }
        if (scope.kind === 'ns') { return 'ns|' + scope.id + '|' + lc(term); }
        if (scope.kind === 'none') { return 'none|' + lc(term || (sub ? sub.id : '')); }
        return 'gal|' + scope.id + '|' + (sub ? sub.id : '') + '|' + (st.inUse ? 1 : 0) + '|' + lc(term);
    }

    function fetchFor(scope, sub, term, signal) {
        var search = st.pc.source;
        if (!scope) {
            return api(search, { q: term, limit: GLOBAL }, signal).then(function (rows) { return { rows: rows }; });
        }
        if (scope.kind === 'coll') { return Promise.resolve({}); }
        if (scope.kind === 'tax') {
            var extras = term || scope.size <= BROWSE
                ? api(search, { q: term, scope: scope.ns, limit: BROWSE }, signal)
                : Promise.resolve([]);
            return Promise.all([loadTree(scope.ns), extras]).then(function (r) { return { tree: r[0], rows: r[1] }; });
        }
        if (scope.kind === 'ns' || scope.kind === 'none') {
            var q = term || (scope.kind === 'none' && sub ? sub.id : '');
            return api(search, { q: q, scope: scope.ns, limit: BROWSE }, signal)
                .then(function (rows) { return { rows: rows }; });
        }
        var params = { q: term, galaxy: scope.type, limit: BROWSE };
        if (sub) { params.kill_chain = sub.id; }
        if (st.inUse) { params.in_use = 1; }
        return api(search, params, signal).then(function (rows) { return { rows: rows }; });
    }

    function refresh(typed) {
        var key = wantKey();
        if (st.timer) { clearTimeout(st.timer); st.timer = null; }
        if (st.req) { st.req.abort(); st.req = null; }
        if (key === st.dataKey && !st.error) { st.loading = false; render(); return; }
        st.error = false;
        if (key === null) { st.loading = false; st.dataKey = null; render(); return; }
        st.loading = true;
        render();
        var state = st;
        var scope = currentScope();
        var sub = currentSub();
        var term = st.term.trim();
        state.timer = setTimeout(function () {
            state.timer = null;
            var ctrl = new AbortController();
            state.req = ctrl;
            fetchFor(scope, sub, term, ctrl.signal).then(function (data) {
                if (st !== state || state.req !== ctrl) { return; }
                state.req = null;
                state.data = data;
                state.data.scopeId = scope ? scope.id : null;
                state.dataKey = key;
                state.loading = false;
                render();
            }, function (err) {
                if (err && err.name === 'AbortError') { return; }
                if (st !== state || state.req !== ctrl) { return; }
                state.req = null;
                state.loading = false;
                state.error = true;
                render();
            });
        }, typed ? DEBOUNCE : 0);
    }

    // Data still describing the current scope, even while a newer request runs.
    function dataFor(scope) {
        var d = st.data;
        if (!d) { return null; }
        if ((scope ? scope.id : null) !== d.scopeId) { return null; }
        return d;
    }

    /* ── columns ──────────────────────────────────────────────────────── */

    function act(fn) { st.acts.push(fn); return st.acts.length - 1; }

    function navItem(target, opts) {
        opts = opts || {};
        var isGroup = !!target.sections;
        return {
            t: 'item',
            key: target.id,
            label: target.label,
            hint: null,
            icon: isGroup ? (opts.open && target.icon === 'fas fa-folder' ? 'fas fa-folder-open' : target.icon) : target.icon,
            count: opts.count === false ? null : (isGroup ? target.scopes.length : (opts.count ? target.size : null)),
            open: !!opts.open,
            mark: isGroup ? target.scopes.some(scopeHasSelection) : scopeHasSelection(target),
            dim: target.ns === 'deprecated',
            title: target.desc || '',
            go: opts.go,
        };
    }

    function sideCol() {
        var m = st.model;
        var first = st.path[0];
        var searching = !!st.term.trim() && !currentScope();
        var lines = [];
        var side = m.side;
        if (st.coll) {
            var last = side[side.length - 1];
            side = side.slice(0, -1).concat([{ head: last.head, icon: last.icon, items: last.items.concat([st.coll]) }]);
        }
        side.forEach(function (sec) {
            if (!sec.items.length) { return; }
            lines.push({ t: 'head', text: sec.head, icon: sec.icon });
            sec.items.forEach(function (it) {
                var open = !searching && !!first && first.id === it.id;
                lines.push(navItem(it, {
                    open: open,
                    count: !it.sections && it.kind !== 'tax' && it.kind !== 'galaxy',
                    go: it.sections ? function () { openGroup(it.id); } : function () { openScope(it); },
                }));
            });
        });
        return {
            key: 'side', title: st.kind === 'tag' ? T('tags') : T('galaxies'), lines: lines,
            titleIcon: st.kind === 'tag' ? 'fas fa-tags' : 'misp-icon misp-icon-galaxy misp-simple',
        };
    }

    function groupCol(group, scope) {
        var lines = [];
        group.sections.forEach(function (sec) {
            if (!sec.items.length) { return; }
            if (sec.head) { lines.push({ t: 'head', text: sec.head }); }
            sec.items.forEach(function (s) {
                var line = navItem(s, {
                    open: !!scope && scope.id === s.id,
                    count: true,
                    go: function () { openScope(s, { fromGroup: true }); },
                });
                if (s.tactics) { line.matrix = true; }
                lines.push(line);
            });
        });
        return {
            key: 'group', title: group.label, meta: group.scopes.length + (group.hint ? ' · ' + group.hint : ''), lines: lines, subW: MID_W,
            maxSubs: 4, spineText: scope ? scope.label : group.label, spineIcon: group.icon,
            popTo: 0,
        };
    }

    function predLabel(p) { return p.path.length > 1 ? p.path.slice(1).join(' › ') : p.label; }

    function predMatches(p, term) {
        if (!term) { return { name: false, n: p.entries.length + (p.self ? 1 : 0) }; }
        var name = has(p.label, term) || has(p.expanded, term);
        var n = 0;
        p.entries.forEach(function (e) { if (name || has(e.value, term) || has(e.expanded, term)) { n++; } });
        if (p.self && (name || has(p.self.value, term) || has(p.self.expanded, term))) { n++; }
        return { name: name, n: n };
    }

    function subCol(scope, sub, term) {
        var lines = [];
        var stepIndex = st.path.findIndex(function (s) { return s.k === 'scope'; });
        if (scope.kind === 'tax') {
            var tm = (dataFor(scope) || {}).tree;
            var groups = [];
            var byKey = {};
            if (term) {
                lines.push({
                    t: 'item', key: '*', label: T('allOf', scope.label), icon: 'fas fa-layer-group',
                    open: !sub, go: function () { openSub(null); },
                });
            }
            tm.preds.forEach(function (p) {
                if (!p.entries.length && !p.self) { return; }
                var m = predMatches(p, term);
                if (term && !m.n) { return; }
                var k = p.path.length > 1 ? p.path[0] : '';
                if (!byKey[k]) { byKey[k] = { key: k, preds: [] }; groups.push(byKey[k]); }
                byKey[k].preds.push({ p: p, n: m.n });
            });
            groups.sort(function (a, b) { return (a.key === '' ? 0 : 1) - (b.key === '' ? 0 : 1); });
            groups.forEach(function (g) {
                if (g.key) { lines.push({ t: 'head', text: g.key }); }
                g.preds.forEach(function (x) {
                    lines.push({
                        t: 'item', key: x.p.id, label: predLabel(x.p), labelTerm: term,
                        title: x.p.label, open: !!sub && sub.id === x.p.id,
                        count: term ? x.n : null, mark: false,
                        go: function () { openSub(x.p.id, x.p.label); },
                    });
                });
            });
            if (term && lines.length === 1) {
                lines.push({ t: 'msg', h: 56, html: '<p class="ifb-msg-s">' + esc(T('noPredicateMatch')) + '</p>' });
            }
            return {
                key: 'sub', title: T('predicates'), meta: term ? null : tm.preds.length + '', lines: lines,
                subW: MID_W, maxSubs: 4, spineText: sub ? sub.label : scope.label, spineIcon: 'fas fa-list',
                popTo: stepIndex,
            };
        }
        if (scope.kind === 'none') {
            lines.push({
                t: 'item', key: '*', label: T('all'), open: !sub, go: function () { openSub(null); }, compact: true,
            });
            'ABCDEFGHIJKLMNOPQRSTUVWXYZ'.split('').forEach(function (L) {
                lines.push({
                    t: 'item', key: L, label: L, open: !!sub && sub.id === L, compact: true,
                    go: function () { openSub(L, T('startsWith', L)); },
                });
            });
            return {
                key: 'sub', title: T('az'), lines: lines, subW: LETTER_W, maxSubs: 2,
                spineText: sub ? sub.label : T('all'), spineIcon: 'fas fa-font', popTo: stepIndex,
                dimmed: !!term,
            };
        }
        lines.push({
            t: 'item', key: '*', label: T('allTactics'), icon: 'fas fa-layer-group', open: !sub,
            go: function () { openSub(null); },
        });
        scope.tactics.forEach(function (t) {
            lines.push({
                t: 'item', key: t, label: humanize(t), title: t, open: !!sub && sub.id === t,
                go: function () { openSub(t, humanize(t)); },
            });
        });
        return {
            key: 'sub', title: T('tactics'), meta: scope.tactics.length + '', lines: lines, subW: MID_W,
            maxSubs: 3, spineText: sub ? sub.label : T('allTactics'), spineIcon: 'fas fa-table-columns',
            popTo: stepIndex,
        };
    }

    // `row` is a picker row: {value, style: {colour}, id, local_only}.
    function tagVal(row, d, extra) {
        var colour = (row.style && row.style.colour) || null;
        var line = {
            t: 'val', value: row.value, swatch: colour, label: d.label, badge: d.badge || null,
            sub: d.sub || null, pre: d.pre || null,
            row: { value: row.value, label: row.value, style: { colour: colour }, id: row.id, local_only: !!row.local_only },
        };
        if (extra) { Object.keys(extra).forEach(function (k) { line[k] = extra[k]; }); }
        return line;
    }

    function entryVal(e) {
        var d = describe(e.value, e.expanded);
        return tagVal({ value: e.tag, style: { colour: e.colour }, id: e.id, local_only: e.localOnly }, d, { nv: e.nv });
    }

    function collValues(term, col) {
        var lines = st.coll.items.filter(function (c) { return has(c.name, term); }).map(function (c) {
            return {
                t: 'val', value: 'collection:' + c.id, icon: 'fas fa-layer-group', label: c.name,
                sub: c.tags.length === 1 ? T('oneTag') : T('nTags', c.tags.length),
                title: c.tags.map(function (t) { return t.name; }).join('\n'),
                row: { value: 'collection:' + c.id, label: c.name, collection: c },
            };
        });
        if (!lines.length) {
            col.empty = true;
            lines.push({ t: 'msg', h: 120, html: '<div class="ifb-empty"><i class="fas fa-magnifying-glass" aria-hidden="true"></i>'
                + '<b>' + esc(T('noCollectionMatches', term)) + '</b></div>' });
        }
        return lines;
    }

    function taxValues(scope, sub, term, col) {
        var d = dataFor(scope);
        var tm = d.tree;
        var lines = [];
        var push = function (p, all) {
            var name = all || has(p.label, term) || has(p.expanded, term);
            var hits = p.entries.filter(function (e) { return name || has(e.value, term) || has(e.expanded, term); });
            var self = p.self && (name || has(p.self.value, term) || has(p.self.expanded, term));
            return { hits: hits, self: self };
        };
        if (tm.big && !sub && !term) {
            col.prompt = true;
            lines.push({
                t: 'msg', h: 168, html: '<div class="ifb-prompt"><i class="fas fa-arrow-left" aria-hidden="true"></i>'
                    + '<b>' + esc(T('pickPredicate')) + '</b><span>' + esc(T('orTypeToSearchAll', num(tm.existing), scope.label))
                    + '</span></div>',
            });
            return lines;
        }
        var preds = tm.preds.filter(function (p) { return !sub || p.id === sub.id; });
        preds.forEach(function (p) {
            var r = push(p, !term);
            if (r.self) { lines.push(entryVal(p.self)); }
            if (!r.hits.length) { return; }
            if (!sub) {
                var headText = p.expanded && p.expanded !== p.label && p.expanded.length <= 48
                    ? p.expanded : p.path.join(' › ');
                var head = { t: 'head', text: headText, title: p.label };
                if (tm.big) {
                    head.go = function () { openSub(p.id, p.label); };
                    head.whole = true;
                    head.title = T('open', p.label);
                }
                lines.push(head);
            }
            r.hits.forEach(function (e) { lines.push(entryVal(e)); });
        });
        var extras = (d.rows || []).filter(function (row) { return !tm.tags[lc(row.value)]; });
        if (extras.length && !sub) {
            lines.push({ t: 'head', text: T('otherTags', scope.label), title: T('otherTagsTitle') });
            extras.forEach(function (row) {
                lines.push(tagVal(row, { label: row.value.slice(scope.ns.length + 1) }));
            });
        }
        if (!lines.length) {
            col.empty = true;
            var html = '<div class="ifb-empty"><i class="fas fa-magnifying-glass" aria-hidden="true"></i>'
                + '<b>' + esc(T('noValueMatches', sub ? sub.label : scope.label, term)) + '</b>';
            if (sub) {
                html += '<button type="button" class="ifb-link" data-ifb-go="' + act(function () { openSub(null); }) + '">'
                    + esc(T('searchAllOf', scope.label)) + '</button>';
            }
            lines.push({ t: 'msg', h: 120, html: html + '</div>' });
        }
        return lines;
    }

    function nsParts(name, ns) {
        var rest = name.slice(ns.length + 1);
        var eq = rest.indexOf('=');
        if (eq > 0) {
            return { pred: rest.slice(0, eq).trim(), val: rest.slice(eq + 1).trim().replace(/^"+|"+$/g, '') };
        }
        var c = rest.indexOf(':');
        if (c > 0) { return { pred: rest.slice(0, c), val: rest.slice(c + 1) }; }
        return { pred: '', val: rest };
    }

    function nsValues(scope, rows) {
        var groups = [];
        var byKey = {};
        rows.forEach(function (row) {
            var parts = nsParts(row.value, scope.ns);
            if (!byKey[parts.pred]) { byKey[parts.pred] = { pred: parts.pred, rows: [] }; groups.push(byKey[parts.pred]); }
            byKey[parts.pred].rows.push({ row: row, parts: parts });
        });
        var loose = [];
        var lines = [];
        groups.forEach(function (g) { if (g.rows.length < 2 || !g.pred) { loose = loose.concat(g.rows); } });
        loose.forEach(function (x) {
            lines.push(tagVal(x.row, { label: x.parts.val, pre: x.parts.pred || null }));
        });
        groups.forEach(function (g) {
            if (g.rows.length < 2 || !g.pred) { return; }
            lines.push({ t: 'head', text: g.pred });
            g.rows.forEach(function (x) {
                lines.push(tagVal(x.row, { label: x.parts.val }));
            });
        });
        return lines;
    }

    function clusterVal(row, term) {
        var split = splitId(row.label);
        return {
            t: 'val', value: row.value, icon: row.style && row.style.icon ? iconClass(row.style.icon) : null,
            label: split.name, idb: split.id,
            sub: row.matched_synonym ? T('aka', row.matched_synonym) : null,
            desc: row.description || null,
            dim: !row.in_use && !st.embedded,
            title: (row.style && row.style.galaxy ? row.style.galaxy + ' › ' : '') + row.label
                + (row.in_use ? '' : '\n' + T('notAttached')),
            row: { value: row.value, label: row.label, style: row.style, id: row.id },
        };
    }

    function valCol(scope, sub, term) {
        var col = { key: 'val', isVal: true, lines: [], subW: VAL_W, canRich: true };
        var d = dataFor(scope);
        col.title = scope.label + (sub ? ' › ' + sub.label : '');
        col.titleIcon = scope.kind === 'galaxy' ? scope.icon : scope.icon;
        col.about = !term && scope.desc ? scope.desc : null;
        if (scope.kind === 'galaxy') {
            col.ctrl = '<span class="ifb-seg" role="group" aria-label="' + esc(T('whichClusters')) + '">'
                + '<button type="button" class="ifb-seg-b' + (st.inUse ? ' is-on' : '') + '" data-ifb-go="'
                + act(function () { st.inUse = true; refresh(); }) + '" aria-pressed="' + st.inUse + '"'
                + (scope.inUse ? '' : ' disabled') + ' title="' + esc(T('inUseTitle')) + '">' + esc(T('inUse')) + ' <span>'
                + num(scope.inUse) + '</span></button>'
                + '<button type="button" class="ifb-seg-b' + (st.inUse ? '' : ' is-on') + '" data-ifb-go="'
                + act(function () { st.inUse = false; refresh(); }) + '" aria-pressed="' + !st.inUse + '">' + esc(T('all')) + ' <span>'
                + num(scope.size) + '</span></button></span>';
        }
        if (st.error) {
            col.lines = [{ t: 'msg', h: 110, html: '<div class="ifb-empty"><i class="fas fa-triangle-exclamation"></i>'
                + '<b>' + esc(T('loadValuesFailed')) + '</b><button type="button" class="ifb-link" data-ifb-go="'
                + act(function () { st.dataKey = null; refresh(); }) + '">' + esc(T('tryAgain')) + '</button></div>' }];
            return col;
        }
        if (scope.kind === 'coll') {
            col.lines = collValues(term, col);
            return col;
        }
        if (!d) {
            col.lines = skeleton(8);
            col.loading = true;
            return col;
        }
        col.loading = st.loading;
        if (scope.kind === 'tax') {
            col.lines = taxValues(scope, sub, term, col);
            return col;
        }
        var rows = d.rows || [];
        if (scope.kind === 'galaxy') {
            col.lines = rows.map(function (r) { return clusterVal(r, term); });
            // ATT&CK-style ids take a column of their own; keep room for the name.
            if (col.lines.some(function (l) { return l.idb; })) { col.baseW = VAL_ID_W; }
            if (!term && !sub && rows.length) {
                var total = st.inUse ? scope.inUse : scope.size;
                if (total > rows.length) { col.lines.push({ t: 'more', n: total - rows.length }); }
            } else if (rows.length >= BROWSE) {
                col.lines.push({ t: 'more', n: -1 });
            }
        } else if (scope.kind === 'ns') {
            col.lines = nsValues(scope, rows);
            if (!term && scope.size > rows.length) { col.lines.push({ t: 'more', n: scope.size - rows.length }); }
        } else {
            col.lines = rows.map(function (r) {
                return tagVal(r, { label: r.value.trim() || r.value });
            });
            if (!term && !sub && scope.size > rows.length) {
                col.lines.push({ t: 'more', n: scope.size - rows.length });
            } else if (rows.length >= BROWSE) {
                col.lines.push({ t: 'more', n: -1 });
            }
        }
        if (!rows.length) {
            var html = '<div class="ifb-empty"><i class="fas fa-magnifying-glass" aria-hidden="true"></i><b>';
            if (scope.kind === 'galaxy' && st.inUse) {
                html += esc(term ? T('noClusterInUseMatches', term) : (sub ? T('noClusterInUseTactic') : T('noClusterInUse')))
                    + '</b><button type="button" class="ifb-link" data-ifb-go="'
                    + act(function () { st.inUse = false; refresh(); }) + '">' + esc(T('showAllClusters')) + '</button>';
            } else {
                html += esc(term ? T('nothingInMatches', scope.label, term) : T('nothingHere'));
                html += '</b>';
            }
            col.lines = [{ t: 'msg', h: 120, html: html + '</div>' }];
            col.empty = true;
        }
        return col;
    }

    function skeleton(n) {
        var out = [];
        for (var i = 0; i < n; i++) { out.push({ t: 'skel', w: 40 + ((i * 37) % 45) }); }
        return out;
    }

    function matchCol(term) {
        var m = st.model;
        var hits = m.all.filter(function (s) {
            return has(s.label, term) || (s.kind === 'galaxy' && (has(s.type, term) || has(s.ns, term)));
        });
        if (!hits.length) { return null; }
        var lines = [];
        var sections = st.kind === 'tag'
            ? [[T('taxonomies'), 'tax'], [T('namespaces'), 'ns'], [T('tags'), 'none']]
            : [[T('galaxies'), 'galaxy']];
        sections.forEach(function (sec) {
            var list = hits.filter(function (s) { return s.kind === sec[1]; });
            if (!list.length) { return; }
            lines.push({ t: 'head', text: sec[0] });
            list.forEach(function (s) {
                var line = navItem(s, { count: true, go: function () { openScope(s, { fromGroup: !s.direct }); } });
                line.labelTerm = term;
                lines.push(line);
            });
        });
        return { key: 'match', title: T('narrowTo'), meta: null, lines: lines, subW: MID_W, maxSubs: 2 };
    }

    function resultsCol(term) {
        var col = { key: 'val', isVal: true, lines: [], subW: VAL_W, canRich: false };
        col.title = T('everywhere');
        col.meta = T('pickHeading');
        col.titleIcon = st.model.rootIcon;
        if (term.length < 2) {
            col.lines = [{ t: 'msg', h: 120, html: '<div class="ifb-empty"><i class="fas fa-keyboard"></i>'
                + '<b>' + esc(T('keepTyping')) + '</b><span>' + esc(st.kind === 'tag' ? T('twoCharsTags') : T('twoCharsClusters'))
                + '</span></div>' }];
            return col;
        }
        var d = dataFor(null);
        if (st.error) {
            col.lines = [{ t: 'msg', h: 100, html: '<div class="ifb-empty"><b>' + esc(T('searchFailed')) + '</b></div>' }];
            return col;
        }
        if (!d) { col.lines = skeleton(8); col.loading = true; return col; }
        col.loading = st.loading;
        var rows = d.rows || [];
        var groups = [];
        var byKey = {};
        rows.forEach(function (row) {
            var k;
            if (st.kind === 'tag') {
                k = tagNs(row.value);
                if (k === 'misp-galaxy') { return; }
            } else {
                k = lc(row.galaxy_type);
            }
            if (!byKey[k]) { byKey[k] = { key: k, rows: [] }; groups.push(byKey[k]); }
            byKey[k].rows.push(row);
        });
        groups.forEach(function (g) {
            var scope;
            var head = { t: 'head' };
            if (st.kind === 'tag') {
                scope = g.key === '-' ? st.model.byId.none : (st.model.byId['tax:' + g.key] || st.model.byId['ns:' + g.key]);
                var first = g.rows[0].value;
                head.text = scope ? scope.label : first.slice(0, first.indexOf(':')).trim();
                head.icon = scope ? scope.icon : 'fas fa-tag';
                head.note = scope && scope.kind === 'tax' ? T('taxonomy') : null;
            } else {
                scope = st.model.byId['gal:' + g.key];
                head.text = g.rows[0].style && g.rows[0].style.galaxy;
                head.icon = scope ? scope.icon : iconClass(g.rows[0].style && g.rows[0].style.icon);
            }
            if (scope) {
                head.go = function () { openScope(scope, { keepTerm: true }); };
                head.whole = true;
                head.title = T('narrowKeeping', scope.label, term);
            }
            lines(head);
            g.rows.forEach(function (row) {
                if (st.kind === 'galaxy') { lines(clusterVal(row, term)); return; }
                var ns = g.key === '-' ? '' : row.value.slice(0, row.value.indexOf(':') + 1);
                var tx = row.taxonomy;
                var dsc = tx ? describe(tx.entry || tx.predicate, tx.expanded) : { label: row.value.slice(ns.length) };
                if (tx && tx.entry) { dsc.pre = tx.predicate; }
                lines(tagVal(row, dsc));
            });
        });
        function lines(l) { col.lines.push(l); }
        if (rows.length >= GLOBAL) { col.lines.push({ t: 'more', n: -2 }); }
        if (!col.lines.length) {
            col.empty = true;
            col.lines = [{ t: 'msg', h: 120, html: '<div class="ifb-empty"><i class="fas fa-magnifying-glass"></i><b>'
                + esc(T('nothingMatches', term)) + '</b><span>' + esc(T('checkSpelling')) + '</span></div>' }];
        }
        return col;
    }

    function buildCols() {
        var cols = [sideCol()];
        var term = st.term.trim();
        var tl = lc(term);
        var scope = currentScope();
        var sub = currentSub();
        if (!scope && term) {
            var mc = tl.length >= 2 ? matchCol(tl) : null;
            if (mc) { cols.push(mc); }
            cols.push(resultsCol(tl));
            return cols;
        }
        var first = st.path[0];
        if (first && first.k === 'group' && st.model.groups[first.id]) {
            var gc = groupCol(st.model.groups[first.id], scope);
            if (scope) {
                gc.maxSubs = 1;
                gc.moreGo = function () { popTo(0); };
                gc.moreText = T('showAll');
            }
            cols.push(gc);
        }
        if (scope) {
            var d = dataFor(scope);
            var wantsSub = scope.kind === 'none' || (scope.kind === 'galaxy' && scope.tactics)
                || (scope.kind === 'tax' && d && d.tree && d.tree.big);
            if (wantsSub) { cols.push(subCol(scope, sub, tl)); }
            cols.push(valCol(scope, sub, tl));
        }
        var mids = cols.filter(function (c) { return c.key !== 'side' && !c.isVal; });
        if (scope && mids.length > 1) {
            mids.slice(0, -1).forEach(function (c) { c.spine = true; });
        }
        return cols;
    }

    /* ── layout: columns reflow, never scroll ─────────────────────────── */

    function lineH(l, rich) {
        if (l.t === 'msg') { return l.h; }
        if (l.t === 'val' && rich && (l.sub || l.desc)) { return RICH; }
        return ROW;
    }

    function pack(lines, H, maxSubs, rich, keepKey, more) {
        var subs = [[]];
        var used = 0;
        var cut = -1;
        for (var i = 0; i < lines.length; i++) {
            var l = lines[i];
            var h = lineH(l, rich);
            var cur = subs[subs.length - 1];
            var orphan = l.t === 'head' && i + 1 < lines.length && used + h + lineH(lines[i + 1], rich) > H;
            if (cur.length && (used + h > H || orphan)) {
                if (subs.length >= maxSubs) { cut = i; break; }
                subs.push([]);
                used = 0;
            }
            subs[subs.length - 1].push(l);
            used += h;
        }
        if (cut !== -1) {
            var rest = lines.slice(cut);
            var last = subs[subs.length - 1];
            while (last.length && used + ROW > H) { var p = last.pop(); used -= lineH(p, rich); rest.unshift(p); }
            while (last.length && last[last.length - 1].t === 'head') {
                var hd = last.pop();
                used -= lineH(hd, rich);
                rest.unshift(hd);
            }
            var hidden = 0;
            var unknown = false;
            rest.forEach(function (x) {
                if (x.t === 'val' || x.t === 'item') { hidden++; }
                if (x.t === 'more') { if (x.n < 0) { unknown = true; } else { hidden += x.n; } }
            });
            var keep = keepKey ? rest.find(function (x) { return x.t === 'item' && x.open; }) : null;
            if (keep) {
                for (var j = last.length - 1; j >= 0; j--) {
                    if (last[j].t === 'item') { last[j] = keep; break; }
                }
            }
            last.push({ t: 'more', n: unknown ? -1 : hidden, go: more ? more.go : null, text: more ? more.text : null });
            used += ROW;
        }
        return { subs: subs, n: subs.length, cut: cut !== -1, usedLast: used };
    }

    // Bottom of a navbar that stays on screen; the panel never goes under it.
    function navBottom() {
        var nav = document.querySelector('.rc-nav');
        if (!nav) { return 0; }
        var pos = getComputedStyle(nav).position;
        return pos === 'fixed' || pos === 'sticky' ? Math.max(0, nav.getBoundingClientRect().bottom) : 0;
    }

    function geometry(cols) {
        var vw = document.documentElement.clientWidth;
        var vh = window.innerHeight;
        var Wmax = st.embedded ? st.panel.clientWidth : Math.min(vw - 24, MAX_W);
        var fixed = 0;
        var full = [];
        cols.forEach(function (c) {
            if (c.key === 'side') { c.w = SIDE_W; fixed += SIDE_W; } else if (c.spine) { c.w = SPINE_W; fixed += SPINE_W; } else { full.push(c); }
        });
        var sideH = cols[0].lines.reduce(function (n, l) { return n + lineH(l, false); }, 0);
        // Stay under the button and grow wider rather than taller; only a
        // window too short for that lets the panel rise over the bar.
        var rows = function (room) { return Math.floor((room - chrome) / ROW) * ROW; };
        var Hcap;
        var Hmin;
        if (st.embedded) {
            // A steady height, whatever the columns hold, sized to the window
            // minus what the host draws around the browser.
            Hcap = Hmin = Math.max(EMBED_ROWS[0], Math.min(EMBED_ROWS[1], Math.floor((vh - st.reserve) / ROW))) * ROW;
        } else {
            var below = rows(vh - 12 - (st.btn.getBoundingClientRect().bottom + 6));
            Hcap = below >= Math.max(MIN_BELOW * ROW, sideH) ? below : rows(vh - 12 - navBottom() - 8);
            Hmin = Math.min(Hcap, Math.max(MIN_ROWS * ROW, sideH));
        }
        var prev = st.geo || { H: 0, W: 0 };
        var val = full.filter(function (c) { return c.isVal; })[0];
        var others = full.filter(function (c) { return !c.isVal; });
        var plan = function (H) {
            var avail = Wmax - fixed;
            var used = 0;
            var ok = true;
            if (val) {
                val.rich = false;
                val.subW = val.baseW || VAL_W;
                if (val.canRich && val.lines.some(function (l) { return l.sub || l.desc; })) {
                    var nr = pack(val.lines, H, Infinity, true).n;
                    if (nr === 1 || (nr === 2 && val.lines.length <= 24)) { val.rich = true; val.subW = RICH_W; }
                }
                val.need = pack(val.lines, H, Infinity, val.rich).n;
            }
            var reserve = val ? Math.min(val.need, st.wide ? 1 : 2) * val.subW : 0;
            others.forEach(function (c) {
                c.need = pack(c.lines, H, Infinity, false).n;
                var room = Math.max(1, Math.floor((avail - reserve - used) / c.subW));
                c.subs = Math.min(c.need, room, st.wide && c.key === 'sub' ? 6 : (c.maxSubs || 4));
                used += c.subs * c.subW;
                if (c.subs < c.need && !c.moreGo) { ok = false; }
            });
            if (val) {
                var room = Math.max(1, Math.floor((avail - used) / val.subW));
                val.subs = Math.min(val.need, room);
                used += val.subs * val.subW;
                if (val.subs < val.need) { ok = false; }
            }
            return { ok: ok, W: fixed + used };
        };
        var H = Math.min(Hcap, Math.max(Hmin, prev.H));
        var p;
        for (;;) {
            p = plan(H);
            if (p.ok || H >= Hcap) { break; }
            H = Math.min(Hcap, H + ROW);
        }
        var W = st.embedded ? Wmax : Math.min(Wmax, Math.max(p.W, MIN_W, prev.W));
        full.forEach(function (c) { c.w = c.subs * c.subW; });
        var grow = full.length ? full[full.length - 1] : cols[0];
        grow.w += W - p.W;
        st.geo = { H: H, W: W };
        return { H: H, W: W };
    }

    // Under the button when it fits, otherwise as low as it fits; never
    // under the navbar. Follows the button when the page scrolls.
    function place() {
        var p = st.panel;
        var rect = st.btn.getBoundingClientRect();
        var top = rect.bottom + 6;
        var bottom = window.innerHeight - 12;
        if (top + p.offsetHeight > bottom) { top = bottom - p.offsetHeight; }
        p.style.top = Math.max(navBottom() + 8, top) + 'px';
        p.style.left = Math.max(12, Math.min(rect.left, document.documentElement.clientWidth - 12 - p.offsetWidth)) + 'px';
    }

    /* ── rendering ────────────────────────────────────────────────────── */

    function rowId(c, key) { return 'ifb-o-' + c + '-' + String(key).replace(/[^a-z0-9_-]/gi, '_').slice(0, 60); }

    function lineHtml(l, ci, rich, term) {
        if (l.t === 'head') {
            var go = l.go ? act(l.go) : null;
            if (l.whole) {
                return '<div class="ifb-head is-go" data-ifb-go="' + go + '"' + (l.title ? ' title="' + esc(l.title) + '"' : '') + '>'
                    + (l.icon ? '<i class="' + esc(l.icon) + ' ifb-head-i" aria-hidden="true"></i>' : '')
                    + '<span class="ifb-head-t">' + esc(l.text) + '</span>'
                    + (l.note ? '<span class="ifb-head-note">' + esc(l.note) + '</span>' : '')
                    + '<i class="fas fa-arrow-right ifb-head-arrow" aria-hidden="true"></i></div>';
            }
            return '<div class="ifb-head"' + (l.title ? ' title="' + esc(l.title) + '"' : '') + '>'
                + (l.icon ? '<i class="' + esc(l.icon) + ' ifb-head-i" aria-hidden="true"></i>' : '')
                + '<span class="ifb-head-t">' + esc(l.text) + '</span>'
                + (l.note ? '<span class="ifb-head-note">' + esc(l.note) + '</span>' : '')
                + (go !== null ? '<button type="button" class="ifb-head-go" tabindex="-1" data-ifb-go="' + go + '">'
                    + esc(l.goLabel || T('openShort')) + '<i class="fas fa-chevron-right" aria-hidden="true"></i></button>' : '')
                + '</div>';
        }
        if (l.t === 'more') {
            if (l.go) {
                return '<button type="button" class="ifb-more is-go" tabindex="-1" data-ifb-go="' + act(l.go) + '">'
                    + '<i class="fas fa-ellipsis" aria-hidden="true"></i>' + esc(T('moreN', num(Math.max(0, l.n)))) + ' · '
                    + '<u>' + esc(l.text || T('showAll')) + '</u></button>';
            }
            var text = l.n === -2 ? T('firstMatches', GLOBAL)
                : (l.n < 0 ? T('moreNotShown') : T('moreTypeToNarrow', num(l.n)));
            return '<div class="ifb-more"><i class="fas fa-ellipsis" aria-hidden="true"></i><span>' + esc(text) + '</span></div>';
        }
        if (l.t === 'msg') { return '<div class="ifb-msg" style="height:' + l.h + 'px">' + l.html + '</div>'; }
        if (l.t === 'skel') { return '<div class="ifb-skel"><i style="width:' + l.w + '%"></i></div>'; }
        if (l.t === 'item') {
            var n = act(l.go);
            var id = rowId(ci, 'n' + l.key);
            st.grid[ci].push({ id: id, go: n, key: 'n' + l.key, open: l.open });
            return '<div class="ifb-row ifb-nav' + (l.open ? ' is-open' : '') + (l.dim ? ' is-dim' : '')
                + (l.compact ? ' is-compact' : '') + '" id="' + id + '" role="option" aria-selected="' + !!l.open
                + '" data-ifb-go="' + n + '"' + (l.title ? ' title="' + esc(l.title) + '"' : '') + '>'
                + (l.icon ? '<i class="' + esc(l.icon) + ' ifb-ico" aria-hidden="true"></i>' : '')
                + '<span class="ifb-label">' + hl(l.label, l.labelTerm || '') + '</span>'
                + (l.hint ? '<span class="ifb-hint">' + esc(l.hint) + '</span>' : '')
                + (l.mark ? '<span class="ifb-dot" title="' + esc(T('hasSelected')) + '"></span>' : '')
                + (l.matrix ? '<i class="fas fa-table-cells ifb-matrix" title="' + esc(T('matrixTitle')) + '" aria-label="' + esc(T('matrix')) + '"></i>' : '')
                + (l.count !== null && l.count !== undefined ? '<span class="ifb-count">' + num(l.count) + '</span>' : '')
                + (l.compact ? '' : '<i class="fas fa-chevron-right ifb-chev" aria-hidden="true"></i>')
                + '</div>';
        }
        // value
        var state = rowState(l.row);
        st.vals.push(l);
        var vi = st.vals.length - 1;
        var vid = rowId(ci, 'v' + vi);
        st.grid[ci].push({ id: vid, val: vi, key: 'v' + l.value });
        var isRich = rich && (l.sub || l.desc);
        var mark = l.swatch
            ? '<span class="ifb-sw" style="--ifb-sw:' + esc(l.swatch) + '"></span>'
            : (l.icon ? '<i class="' + esc(l.icon) + ' ifb-gi" aria-hidden="true"></i>' : '<span class="ifb-sw is-none"></span>');
        var label = (l.badge ? '<span class="ifb-badge">' + hl(l.badge, term) + '</span>' : '')
            + (l.pre ? '<span class="ifb-pre">' + hl(l.pre, term) + '</span>' : '')
            + hl(l.label, term);
        var second = isRich ? (l.desc ? esc(l.desc) : hl(l.sub, term)) : '';
        var inline = l.sub && (!isRich || l.desc) ? ' <small>' + hl(l.sub, term) + '</small>' : '';
        var checkIcon = { exclude: 'fa-ban', local: 'fa-user' }[state] || 'fa-check';
        var ex = st.embedded ? ''
            : '<button type="button" class="ifb-ex" tabindex="-1" data-ifb-ex="' + vi + '" aria-pressed="' + (state === 'exclude') + '"'
                + ' title="' + esc(state === 'exclude' ? T('stopExcluding') : T('exclude')) + '" aria-label="'
                + esc((state === 'exclude' ? T('stopExcluding') : T('exclude')) + ' ' + l.row.label) + '">'
                + '<i class="fas fa-ban" aria-hidden="true"></i></button>';
        return '<div class="ifb-row ifb-val' + (isRich ? ' is-rich' : '') + (l.dim ? ' is-dim' : '') + '" id="' + vid
            + '" role="option" data-state="' + state + '" aria-selected="' + (state === 'include' || state === 'local') + '"'
            + ' data-ifb-val="' + vi + '" title="' + esc(l.title || l.value) + '">'
            + '<span class="ifb-check" aria-hidden="true"><i class="fas ' + checkIcon + '"></i></span>'
            + mark
            + '<span class="ifb-text"><span class="ifb-label">' + label + inline + '</span>'
            + (isRich ? '<span class="ifb-sub">' + second + '</span>' : '') + '</span>'
            + (l.nv !== null && l.nv !== undefined && l.nv !== '' ? '<span class="ifb-nv" title="' + esc(T('numericalValue')) + '">' + esc(l.nv) + '</span>' : '')
            + (l.idb ? '<span class="ifb-idb">' + hl(l.idb, term) + '</span>' : '')
            + ex
            + '</div>';
    }

    function colHtml(c, ci, g, term) {
        if (c.spine) {
            var go = act(function () { popTo(c.popTo); });
            return '<button type="button" class="ifb-spine" data-ifb-go="' + go + '" title="' + esc(T('backTo', c.title)) + '">'
                + '<i class="' + esc(c.spineIcon || 'fas fa-folder') + '" aria-hidden="true"></i>'
                + '<span class="ifb-spine-t"><small>' + esc(c.title) + '</small> ' + esc(c.spineText) + '</span>'
                + '<i class="fas fa-chevron-left ifb-spine-back" aria-hidden="true"></i></button>';
        }
        st.grid[ci] = [];
        var subs = c.key === 'side' ? 1 : c.subs;
        var more = c.moreGo ? { go: c.moreGo, text: c.moreText } : null;
        if (!more && c.key === 'sub' && !st.wide) {
            more = { go: function () { st.wide = true; render(); }, text: T('showAll') };
        }
        var packed = pack(c.lines, g.H, subs, !!c.rich, true, more);
        if (c.isVal && !packed.cut) {
            var cap = Math.max(1, Math.floor((c.w - 6) / (Math.max(c.subW, 300) + 6)));
            var items = c.lines.filter(function (l) { return l.t === 'val'; }).length;
            var k = Math.min(cap, Math.max(1, Math.ceil(items / 6)));
            if (k > packed.n) {
                var total = c.lines.reduce(function (n, l) { return n + lineH(l, !!c.rich); }, 0);
                for (var Hb = Math.ceil(total / k); Hb <= g.H; Hb += 14) {
                    var pk = pack(c.lines, Hb, k, !!c.rich, true);
                    if (!pk.cut) { packed = pk; packed.usedLast = Math.max(pk.usedLast, 0); break; }
                }
            }
        }
        var head = '<div class="ifb-colhead">'
            + (c.titleIcon ? '<i class="' + esc(c.titleIcon) + '" aria-hidden="true"></i>' : '')
            + '<span class="ifb-colhead-t">' + esc(c.title) + '</span>'
            + (c.meta ? '<span class="ifb-colhead-m">' + esc(c.meta) + '</span>' : '')
            + (c.loading ? '<span class="ifb-spin" role="status" aria-label="' + esc(T('loading')) + '"></span>' : '')
            + (c.ctrl || '') + '</div>';
        var body = '';
        packed.subs.forEach(function (sub, si) {
            var isLast = si === packed.subs.length - 1;
            var inner = sub.map(function (l) { return lineHtml(l, ci, !!c.rich, term); }).join('');
            var room = g.H - packed.usedLast;
            if (isLast && c.about && !packed.cut && room >= 80) {
                // sized to the room left, so the note never clips
                var stackW = (c.w - 12) / packed.subs.length - 6;
                var perLine = Math.max(20, Math.floor((stackW - 52) / 6.8));
                var lines = Math.min(5, Math.floor((room - 30) / 18));
                var max = perLine * lines - 4;
                var text = c.about.length > max ? c.about.slice(0, max).replace(/\s+\S*$/, '') + '…' : c.about;
                inner += '<div class="ifb-about"><i class="fas fa-circle-info" aria-hidden="true"></i><p>' + esc(text) + '</p></div>';
            }
            body += '<div class="ifb-stack" style="' + (c.key === 'side' ? '' : 'flex-basis:' + c.subW + 'px') + '">' + inner + '</div>';
        });
        return '<section class="ifb-col ifb-col-' + c.key + (c.loading && !c.lines.some(function (l) { return l.t === 'skel'; }) ? ' is-stale' : '')
            + (c.dimmed ? ' is-dimmed' : '') + '" style="width:' + c.w + 'px" data-ifb-col="' + ci + '">'
            + head + '<div class="ifb-list" role="listbox" aria-label="' + esc(c.title) + '" style="height:' + g.H + 'px">'
            + body + '</div></section>';
    }

    function render() {
        if (!st || !st.model) { return; }
        // Embedded in a dialog that is not shown yet: the observer renders it once it has a width.
        if (st.embedded && !st.panel.clientWidth) { return; }
        var activeKey = st.active ? { col: st.active.colKey, key: st.active.key } : null;
        st.acts = [];
        st.vals = [];
        st.grid = [];
        var term = lc(st.term.trim());
        var cols = buildCols();
        var g = geometry(cols);
        var html = '';
        st.colKeys = [];
        cols.forEach(function (c, ci) {
            st.colKeys[ci] = c.spine ? null : c.key;
            html += colHtml(c, ci, g, term);
        });
        st.cols.innerHTML = html;
        renderTop();
        if (!st.embedded) {
            st.panel.style.width = g.W + 'px';
            renderTray();
            var measured = st.panel.offsetHeight - g.H;
            if (measured !== chrome && !st.remeasured) {
                chrome = measured;
                st.remeasured = true;
                render();
                st.remeasured = false;
                return;
            }
            place();
        }
        // put the keyboard cursor back where it was
        st.active = null;
        if (activeKey) {
            st.grid.forEach(function (list, ci) {
                if (!list || st.colKeys[ci] !== activeKey.col) { return; }
                var i = list.findIndex(function (r) { return r.key === activeKey.key; });
                if (i !== -1) { setActive(ci, i); }
            });
        }
        if (st.enterNext && st.active) {
            var from = st.active.ci;
            var to = navigable().find(function (ci) { return ci > from; });
            if (to !== undefined) {
                st.enterNext = false;
                var open = st.grid[to].findIndex(function (x) { return x.open; });
                setActive(to, open === -1 ? 0 : open);
            }
        }
    }

    function crumbs() {
        var m = st.model;
        var out = [{ text: m.root, icon: m.rootIcon, pop: -1 }];
        st.path.forEach(function (s, i) {
            if (s.k === 'group') {
                if (st.term.trim() && !currentScope()) { return; }
                out.push({ text: m.groups[s.id].label, pop: i });
            } else if (s.k === 'scope') {
                out.push({ text: scopeById(s.id).label, pop: i });
            } else {
                out.push({ text: s.label, pop: i });
            }
        });
        if (st.term.trim() && !currentScope()) { out.push({ text: T('search'), pop: null }); }
        return out;
    }

    function renderTop() {
        var scope = currentScope();
        var sub = currentSub();
        st.input.placeholder = scope
            ? T('searchIn', scope.label + (sub ? ' › ' + sub.label : ''))
            : (st.kind === 'tag' ? T('searchAllTags') : T('searchAllClusters'));
        var list = crumbs();
        st.crumbs.innerHTML = list.map(function (c, i) {
            var last = i === list.length - 1;
            var inner = (c.icon ? '<i class="' + esc(c.icon) + '" aria-hidden="true"></i>' : '') + esc(c.text);
            var html = last || c.pop === null
                ? '<span class="ifb-crumb is-here">' + inner + '</span>'
                : '<button type="button" class="ifb-crumb" tabindex="-1" data-ifb-go="'
                    + act((function (pop) { return function () { if (pop < 0) { goRoot(); } else { st.term = ''; syncInput(); popTo(pop); } }; }(c.pop)))
                    + '">' + inner + '</button>';
            return (i ? '<i class="fas fa-chevron-right ifb-crumb-sep" aria-hidden="true"></i>' : '') + html;
        }).join('');
        st.backHint.hidden = !scope || st.input.value !== '';
    }

    function goRoot() {
        st.path = [{ k: 'group', id: st.model.defaultGroup }];
        st.term = '';
        syncInput();
        refresh();
    }

    // A cluster the server could not resolve still never shows its raw tag.
    function pickName(s) {
        if (st.kind === 'galaxy' && /^misp-galaxy:/.test(s.label || '')) {
            var m = /="?(.*?)"?$/.exec(s.label);
            return m ? m[1] : s.label.slice(12);
        }
        return s.label;
    }

    function pickGalaxy(s) {
        if (s.style && s.style.galaxy) { return s.style.galaxy; }
        var scope = st.model && st.model.byId['gal:' + clusterType(s.value)];
        return scope ? scope.label : humanize(clusterType(s.value) || '');
    }

    function chipHtml(s) {
        if (window.TagChips) {
            if (st.kind === 'tag') {
                return TagChips.chip({ name: s.value, colour: s.style && s.style.colour }, { searchUrl: '', inline: true });
            }
            return TagChips.cluster({
                value: pickName(s), galaxy: pickGalaxy(s),
                iconClass: s.style && s.style.icon ? iconClass(s.style.icon) : null,
            }, { searchUrl: '', inline: true });
        }
        return '<span>' + esc(pickName(s)) + '</span>';
    }

    function renderTray() {
        var sel = st.selection;
        var html = '';
        if (!sel.length) {
            html = '<span class="ifb-tray-empty"><i class="fas fa-hand-pointer" aria-hidden="true"></i>'
                + esc(T('trayEmpty')) + ' <i class="fas fa-ban" aria-hidden="true"></i> ' + esc(T('trayEmptyExclude')) + '</span>';
        } else {
            html = '<span class="ifb-tray-label">' + esc(T('selected')) + '</span>' + modeHtml() + '<div class="ifb-tray-items">'
                + sel.map(function (s, i) {
                    return '<span class="ifb-pick' + (s.exclude ? ' is-ex' : '') + (s.unresolved ? ' is-unres' : '') + '">'
                        + (s.exclude ? '<span class="ifb-not">' + esc(T('not')) + '</span>' : '')
                        + '<button type="button" class="ifb-pick-go" tabindex="-1" data-ifb-reveal="' + i + '" title="' + esc(T('showWhere')) + '">'
                        + chipHtml(s) + '</button>'
                        + '<button type="button" class="ifb-pick-x" data-ifb-rm="' + i + '" aria-label="' + esc(T('remove') + ' ' + pickName(s)) + '">'
                        + '<i class="fas fa-xmark" aria-hidden="true"></i></button></span>';
                }).join('')
                + '</div><span class="ifb-tray-more" hidden></span>'
                + '<button type="button" class="ifb-tray-clear" data-ifb-clear>' + esc(T('clear')) + '</button>';
        }
        html += '<span class="ifb-keys"><kbd>↵</kbd> ' + esc(T('keyInclude')) + ' <kbd>⇧↵</kbd> ' + esc(T('keyExclude'))
            + ' <kbd>⌫</kbd> ' + esc(T('keyBack')) + ' <kbd>Esc</kbd> ' + esc(T('keyApply')) + '</span>';
        st.tray.innerHTML = html;
        fitTray();
    }

    function modeHtml() {
        if (!st.pc.allOfMode || includedCount(st.selection) < 2) { return ''; }
        return '<span class="ifb-mode" role="group" aria-label="' + esc(T('matchLabel')) + '">'
            + [['any', false], ['all', true]].map(function (m) {
                var key = m[1] ? 'matchAll' : 'matchAny';
                return '<button type="button" class="ifb-mode-btn" data-ifb-mode="' + m[0] + '" aria-pressed="' + (st.allOf === m[1]) + '"'
                    + ' title="' + esc(T(key + 'Title')) + '">' + esc(T(key)) + '</button>';
            }).join('')
            + '</span>';
    }

    // One row of picks: the ones that do not fit fold into "+N".
    function fitTray() {
        var box = st.tray.querySelector('.ifb-tray-items');
        if (!box) { return; }
        var more = st.tray.querySelector('.ifb-tray-more');
        var items = Array.prototype.slice.call(box.querySelectorAll(':scope > .ifb-pick'));
        if (!items.length) { return; }
        var right = box.getBoundingClientRect().right;
        if (items[items.length - 1].getBoundingClientRect().right <= right + 1) { return; }
        var limit = right - 48;
        var cut = items.findIndex(function (el) { return el.getBoundingClientRect().right > limit; });
        var hidden = items.slice(Math.max(0, cut));
        hidden.forEach(function (el) { el.hidden = true; });
        more.hidden = false;
        more.textContent = '+' + hidden.length;
        more.title = hidden.map(function (el) { return el.textContent.replace(/\s+/g, ' ').trim(); }).join('\n');
    }

    /* ── keyboard cursor ──────────────────────────────────────────────── */

    function setActive(ci, i) {
        var prev = st.panel.querySelector('.ifb-row.is-active');
        if (prev) { prev.classList.remove('is-active'); }
        var list = st.grid[ci];
        if (!list || !list[i]) { st.active = null; st.input.removeAttribute('aria-activedescendant'); return; }
        var r = list[i];
        st.active = { ci: ci, i: i, colKey: st.colKeys[ci], key: r.key };
        var el = document.getElementById(r.id);
        if (el) { el.classList.add('is-active'); }
        st.input.setAttribute('aria-activedescendant', r.id);
    }

    function navigable() {
        var out = [];
        st.grid.forEach(function (list, ci) { if (list && list.length) { out.push(ci); } });
        return out;
    }

    function moveRow(delta) {
        var cols = navigable();
        if (!cols.length) { return; }
        if (!st.active) {
            var ci = cols[cols.length - 1];
            setActive(ci, delta > 0 ? 0 : st.grid[ci].length - 1);
            return;
        }
        var list = st.grid[st.active.ci];
        setActive(st.active.ci, Math.max(0, Math.min(list.length - 1, st.active.i + delta)));
    }

    function moveCol(delta) {
        var cols = navigable();
        if (!cols.length) { return; }
        var at = st.active ? cols.indexOf(st.active.ci) : cols.length - 1;
        if (st.active && delta > 0) {
            var r = st.grid[st.active.ci][st.active.i];
            if (r && r.go !== undefined && !r.open) {
                st.acts[r.go]();
                cols = navigable();
                at = cols.indexOf(st.active ? st.active.ci : -1);
                // the next column may still be loading: step into it once it renders
                if (at === cols.length - 1) { st.enterNext = true; return; }
            }
        }
        var next = cols[Math.max(0, Math.min(cols.length - 1, at + delta))];
        if (next === undefined) { return; }
        var list = st.grid[next];
        var open = list.findIndex(function (x) { return x.open; });
        setActive(next, open === -1 ? 0 : open);
    }

    function activate(exclude) {
        if (!st.active) { return; }
        var r = st.grid[st.active.ci][st.active.i];
        if (!r) { return; }
        if (r.val !== undefined) {
            toggle(st.vals[r.val].row, exclude);
        } else if (!exclude) {
            st.acts[r.go]();
        }
    }

    /* ── open / close ─────────────────────────────────────────────────── */

    function syncInput() {
        if (st && st.input.value !== st.term) { st.input.value = st.term; }
    }

    function build(host) {
        var p = document.createElement('div');
        p.className = 'ifb-panel' + (host ? ' is-embedded' : '');
        p.setAttribute('role', host ? 'group' : 'dialog');
        p.setAttribute('aria-label', st.pc.label);
        p.innerHTML = '<div class="ifb-top">'
            + '<label class="ifb-search"><i class="fas fa-magnifying-glass" aria-hidden="true"></i>'
            + '<input type="search" autocomplete="off" spellcheck="false" role="combobox" aria-expanded="true"'
            + ' aria-label="' + esc(T('search') + ' ' + st.pc.label) + '">'
            + '<span class="ifb-back-hint" hidden><kbd>⌫</kbd> ' + esc(T('keyBack')) + '</span></label>'
            + '<nav class="ifb-crumbs" aria-label="' + esc(T('whereYouAre')) + '"></nav>'
            + '</div>'
            + '<div class="ifb-cols"><div class="ifb-loading"><span class="ifb-spin"></span>' + esc(T('loadingScopes')) + '</div></div>'
            + (host ? '' : '<div class="ifb-tray"></div>');
        (host || document.body).appendChild(p);
        st.panel = p;
        st.input = p.querySelector('input');
        st.cols = p.querySelector('.ifb-cols');
        st.crumbs = p.querySelector('.ifb-crumbs');
        st.tray = p.querySelector('.ifb-tray');
        st.backHint = p.querySelector('.ifb-back-hint');
        if (!host) {
            var rect = st.btn.getBoundingClientRect();
            p.style.top = (rect.bottom + 6) + 'px';
            p.style.left = Math.max(12, Math.min(rect.left, document.documentElement.clientWidth - 12 - MIN_W)) + 'px';
            p.style.width = MIN_W + 'px';
        }
        p.addEventListener('mousedown', function (e) {
            if (e.target !== st.input) { e.preventDefault(); }
        });
        p.addEventListener('click', onPanelClick);
        st.input.addEventListener('input', function () {
            st.term = st.input.value;
            st.active = null;
            refresh(true);
        });
    }

    function openPicker(picker) {
        if (st) { closePicker(true); }
        var pc = JSON.parse(picker.getAttribute('data-ifp-picker'));
        var bar = picker.closest('[data-ifp-bar]');
        strings = (bar ? JSON.parse(bar.getAttribute('data-ifp-bar')).browser : null) || {};
        var btn = picker.querySelector('.ifp-btn');
        st = {
            kind: pc.browser.kind, picker: picker, bar: bar, btn: btn, pc: pc, urls: pc.browser, model: null,
            selection: pc.selected.map(function (s) { return Object.assign({}, s); }),
            allOf: !!pc.allOf,
            initial: null,
            dirty: false, path: [], term: '', inUse: false,
            data: null, dataKey: null, loading: false, error: false, timer: null, req: null,
            acts: [], vals: [], grid: [], colKeys: [], active: null, geo: null,
        };
        st.initial = serialize(st.selection, pc, st.allOf);
        btn.setAttribute('aria-expanded', 'true');
        build();
        st.input.focus();
        start();
    }

    /*
     * The embedded browser. cfg: kind, scopes, source (the search URL), tree
     * (a taxonomy's entries, for tags), label, strings, selection
     * ([{value, local}]), onToggle(row, on) when a value is clicked, and
     * reserve, the height in pixels the host keeps around the browser.
     * For tags, also collections ([{id, name, tags: [{name, …}]}], a row
     * then carries `collection`) and open, a namespace to start on.
     */
    function mountIn(host, cfg) {
        if (st) { closePicker(true); }
        strings = cfg.strings || {};
        var collections = cfg.collections || [];
        st = {
            kind: cfg.kind, embedded: true, picker: null, bar: null, btn: null,
            pc: { label: cfg.label || '', source: cfg.source }, urls: { scopes: cfg.scopes, tree: cfg.tree },
            model: null, selection: (cfg.selection || []).slice(), allOf: false,
            coll: collections.length ? {
                id: 'coll', kind: 'coll', label: T('tagCollections'), icon: 'fas fa-layer-group',
                desc: T('tagCollectionsDesc'), size: collections.length, direct: true, group: null, items: collections,
            } : null,
            open: cfg.open || null,
            onToggle: cfg.onToggle, reserve: cfg.reserve || 0, width: 0,
            dirty: false, path: [], term: '', inUse: false,
            data: null, dataKey: null, loading: false, error: false, timer: null, req: null,
            acts: [], vals: [], grid: [], colKeys: [], active: null, geo: null,
        };
        build(host);
        var state = st;
        if (window.ResizeObserver) {
            state.observer = new ResizeObserver(function () {
                var w = state.panel.clientWidth;
                if (st !== state || w === state.width) { return; }
                state.width = w;
                st.geo = null;
                render();
            });
            state.observer.observe(state.panel);
        }
        start();
        return {
            select: function (selection) {
                if (st !== state) { return; }
                st.selection = selection.slice();
                render();
            },
            reveal: function (value) {
                var scope = st === state && st.model ? scopeOfValue(value) : null;
                if (scope) { openScope(scope); }
            },
            focus: function () {
                if (st === state) { st.input.focus(); }
            },
            destroy: function () {
                if (st === state) { closePicker(false); }
            },
        };
    }

    function start() {
        var state = st;
        loadModel(st.kind, st.urls.scopes).then(function (model) {
            if (st !== state) { return; }
            st.model = model;
            var open = st.open ? model.byId['tax:' + lc(st.open)] || model.byId['ns:' + lc(st.open)] : null;
            if (open) { openScope(open); return; }
            st.path = model.defaultGroup ? [{ k: 'group', id: model.defaultGroup }] : [];
            refresh();
        }, function () {
            if (st !== state) { return; }
            st.cols.innerHTML = '<div class="ifb-loading">' + esc(T('loadScopesFailed')) + '</div>';
        });
    }

    function closePicker(apply) {
        if (!st) { return; }
        var state = st;
        st = null;
        if (state.timer) { clearTimeout(state.timer); }
        if (state.req) { state.req.abort(); }
        state.panel.remove();
        if (state.embedded) {
            if (state.observer) { state.observer.disconnect(); }
            return;
        }
        state.btn.setAttribute('aria-expanded', 'false');
        if (!apply || !state.dirty) { return; }
        var next = serialize(state.selection, state.pc, state.allOf);
        if (next === state.initial) { return; }
        // The bar may have re-rendered the picker while the panel was open.
        var btn = state.btn.isConnected ? state.btn
            : (state.bar && state.bar.querySelector('[data-ifp-swap="picker-' + state.pc.name + '"] .ifp-btn'));
        if (!btn) { return; }
        var changes = {};
        changes[state.pc.name] = next;
        IndexFilters.load(btn, IndexFilters.urlWith(btn, changes), true);
    }

    function onPanelClick(e) {
        var t = e.target;
        var ex = t.closest('[data-ifb-ex]');
        if (ex) { toggle(st.vals[+ex.getAttribute('data-ifb-ex')].row, true); st.input.focus(); return; }
        var val = t.closest('[data-ifb-val]');
        if (val) { toggle(st.vals[+val.getAttribute('data-ifb-val')].row, false); st.input.focus(); return; }
        var mode = t.closest('[data-ifb-mode]');
        if (mode) {
            st.allOf = mode.getAttribute('data-ifb-mode') === 'all';
            st.dirty = true;
            renderTray();
            st.input.focus();
            return;
        }
        var rm = t.closest('[data-ifb-rm]');
        if (rm) {
            st.selection.splice(+rm.getAttribute('data-ifb-rm'), 1);
            st.dirty = true;
            render();
            st.input.focus();
            return;
        }
        var rv = t.closest('[data-ifb-reveal]');
        if (rv) {
            var s = st.selection[+rv.getAttribute('data-ifb-reveal')];
            var scope = s && scopeOfValue(s.value);
            if (scope) { openScope(scope); }
            st.input.focus();
            return;
        }
        if (t.closest('[data-ifb-clear]')) {
            st.selection = [];
            st.dirty = true;
            render();
            st.input.focus();
            return;
        }
        var go = t.closest('[data-ifb-go]');
        if (go) {
            var fn = st.acts[+go.getAttribute('data-ifb-go')];
            st.active = null;
            if (fn) { fn(); }
            if (st) { st.input.focus(); }
        }
    }

    // Capture phase: a click inside the panel re-renders it, so by the time
    // the click bubbles its target may no longer be in the panel. The
    // picker's own button is index-filters.js's to handle.
    document.addEventListener('click', function (e) {
        if (st && !st.embedded && !st.panel.contains(e.target) && !st.btn.contains(e.target)) { closePicker(true); }
    }, true);

    // Embedded, Escape and Tab stay the host's: they close or leave the dialog.
    window.addEventListener('keydown', function (e) {
        if (!st) { return; }
        if (e.key === 'Escape' && !st.embedded) {
            e.preventDefault();
            e.stopImmediatePropagation();
            var btn = st.btn;
            closePicker(true);
            btn.focus();
            return;
        }
        if (!st.panel.contains(e.target)) { return; }
        var inInput = e.target === st.input;
        var empty = st.input.value === '';
        if (e.key === 'ArrowDown' || e.key === 'ArrowUp') {
            e.preventDefault();
            moveRow(e.key === 'ArrowDown' ? 1 : -1);
        } else if ((e.key === 'ArrowRight' || e.key === 'ArrowLeft') && st.active
            && (!inInput || empty || (e.key === 'ArrowRight' ? st.input.selectionStart === st.input.value.length : st.input.selectionStart === 0))) {
            e.preventDefault();
            moveCol(e.key === 'ArrowRight' ? 1 : -1);
        } else if (e.key === 'Enter' && inInput) {
            e.preventDefault();
            activate(e.shiftKey);
        } else if (e.key === 'Backspace' && inInput && empty) {
            if (st.model && back()) { e.preventDefault(); }
        } else if (e.key === 'Tab' && !st.embedded) {
            var focusables = Array.prototype.slice.call(st.panel.querySelectorAll('input, button:not([tabindex="-1"]):not([disabled])'));
            var i = focusables.indexOf(document.activeElement);
            e.preventDefault();
            var next = focusables[(i + (e.shiftKey ? -1 : 1) + focusables.length) % focusables.length];
            if (next) { next.focus(); }
        }
    }, true);

    window.addEventListener('resize', function () {
        if (st && st.model) { st.geo = null; render(); }
    });

    var placing = false;
    window.addEventListener('scroll', function () {
        if (!st || st.embedded || placing) { return; }
        placing = true;
        requestAnimationFrame(function () { placing = false; if (st && !st.embedded) { place(); } });
    }, true);

    window.addEventListener('popstate', function () {
        if (st && !st.embedded) { closePicker(false); }
    });

    window.IndexFilterBrowser = {
        toggle: function (picker) {
            if (st && st.picker === picker) { closePicker(true); } else { openPicker(picker); }
        },
        open: function (picker) {
            if (!st || st.picker !== picker) { openPicker(picker); }
        },
        close: function (apply) { closePicker(apply); },
        mount: mountIn,
    };
}());
