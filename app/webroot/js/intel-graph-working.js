// The working view: a collection drawn by the graph laying it out, with a
// list beside the canvas holding every member, finding and extra it draws,
// and what a pivot brought. One selection is shared by the list and the
// canvas; the menus of both offer what fits each node.
//
// Two frames: the dock (intel-graph-dock.js builds it around its stage) and
// the collection page's Pivot Explorer tab (started here, from
// Collections/View/collection_pivot_explorer.ctp). The dock draws the
// workspace; the page draws it for whoever has the collection as workspace,
// and every member with an automatic layout for anyone else.
//
//   IntelGraphWorking.frame(where, { body, stage })  → frame
//   frame.mountOptions(ui)  { ui, badges } laid into IntelGraph.mount's options
//   frame.bind(handle)      as soon as the mount resolves, for the first badges
//   frame.attach(handle)    once it is ready; frame.detach(), frame.none(on)
//   IntelGraphWorking.t(key, …), .tn(key, n, …)  the words, from
//                           Elements/intel_graph_working_text.ctp
//
// Graph edits (hide, show, remove from the graph, keep as a finding) are
// written at once; only moves wait for Save layout.
(function () {
    'use strict';
    if (window.IntelGraphWorking) return;

    function IG() { return window.IntelGraph; }
    function baseurl() { return (window.IntelGraphConfig && window.IntelGraphConfig.baseurl) || ''; }

    /* ── the words ─────────────────────────────────────────── */
    var words = null;
    function text() {
        if (words) return words;
        var block = document.getElementById('ig-working-text');
        try { words = block ? JSON.parse(block.textContent) : {}; } catch (e) { words = {}; }
        return words;
    }
    function fill(s, args) {
        var i = 0;
        return String(s == null ? '' : s).replace(/%s/g, function () { var v = args[i++]; return v == null ? '' : String(v); });
    }
    function t(key) {
        var s = text()[key];
        if (Array.isArray(s)) s = s[0];
        return fill(s == null ? key : s, Array.prototype.slice.call(arguments, 1));
    }
    function tn(key, n) {
        var pair = text()[key];
        var s = Array.isArray(pair) ? pair[n === 1 ? 0 : 1] : pair;
        return fill(s == null ? key : s, [n].concat(Array.prototype.slice.call(arguments, 2)));
    }

    var TYPES = {
        Event:         { icon: 'misp-icon misp-icon-event misp-simple', color: 'var(--bs-event)' },
        Attribute:     { icon: 'misp-icon misp-icon-attribute misp-simple', color: 'var(--bs-attribute)' },
        Object:        { icon: 'misp-icon misp-icon-object misp-simple', color: 'var(--bs-object)' },
        GalaxyCluster: { icon: 'misp-icon misp-icon-galaxy misp-simple', color: 'var(--bs-galaxy)' },
        Value:         { icon: 'misp-icon misp-icon-value-intelligence misp-simple', color: 'var(--bs-valueIntelligence)' }
    };
    function typeName(kind, plural) {
        var pair = (text().types || {})[kind];
        return pair ? pair[plural ? 1 : 0] : kind;
    }
    var GROUPS = [
        { role: 'member', key: 'groupMember' },
        { role: 'finding', key: 'groupFinding' },
        { role: 'extra', key: 'groupExtra', icon: 'fas fa-folder-minus' },
        { role: 'pivot', key: 'groupPivot' }
    ];

    var frames = {};

    function esc(s) {
        return String(s == null ? '' : s).replace(/[&<>"']/g, function (c) {
            return { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c];
        });
    }
    function lower(s) { return String(s == null ? '' : s).toLowerCase(); }
    var PREFS = 'misp.intelGraph.working';
    function load(where) {
        try { var v = JSON.parse(window.localStorage.getItem(PREFS) || '{}'); return (v && v[where]) || {}; } catch (e) { return {}; }
    }
    function store(where, prefs) {
        try {
            var v = JSON.parse(window.localStorage.getItem(PREFS) || '{}') || {};
            v[where] = prefs;
            window.localStorage.setItem(PREFS, JSON.stringify(v));
        } catch (e) { /* kept for this page only */ }
    }
    function dark() { return document.documentElement.getAttribute('data-bs-theme') === 'dark'; }
    function day(when) { return String(when || '').slice(0, 10); }
    function minute(when) { return String(when || '').slice(0, 16); }
    function toast(message, kind) { if (typeof window.showToast === 'function') window.showToast(message, kind || 'info'); }
    function sel(rid) { return '[data-rid="' + (window.CSS && CSS.escape ? CSS.escape(rid) : rid) + '"]'; }

    /* ── what the frame draws, and what the user may do there ── */
    function payload(F) { var h = F.h || F.bound; try { return (h && h.payload()) || {}; } catch (e) { return {}; } }
    function collectionOf(F) { return payload(F).Collection || {}; }
    function canEditCollection(F) { return !!collectionOf(F)._canEdit; }
    function graphWritable(F) { try { return !!F.h.uuid() && F.h.canEdit(); } catch (e) { return false; } }
    // The dock always draws the workspace; the page, when the collection is it.
    function isWorkspace(F) {
        if (F.where === 'dock') return true;
        var a = IG() && IG().active();
        return !!a && lower(a.Collection.uuid) === lower(collectionOf(F).uuid);
    }
    function where(F) { return { collection: collectionOf(F).uuid }; }

    /* ── the marks: one quiet rim badge, in one corner ── */
    function badge(kind) {
        var d = dark();
        var B = {
            finding: { iconClass: 'fas fa-lightbulb', color: d ? 'var(--bs-warning-border-subtle)' : 'var(--bs-warning-text-emphasis)', title: t('badgeFinding') },
            known:   { iconClass: 'fas fa-circle-check', color: 'var(--bs-success)', title: t('badgeKnown') },
            extra:   { iconClass: 'fas fa-folder-minus', color: 'var(--bs-secondary)', title: t('badgeExtra') }
        }[kind];
        return Object.assign({ position: 'sw' }, B, { title: B.title + '\n' + t('badgeFind') });
    }
    function badgesOf(F) {
        return function (key, data, node) {
            var W = payload(F).working || {};
            var mark = key ? W[key] || null : null;
            var out = null;
            if (mark) {
                if (mark.role === 'member' && mark.missing) out = badge('finding');
                else if (mark.role === 'extra') out = badge('extra');
            } else if (node && F.kept[node.id]) {
                out = badge(data && data.known ? 'known' : 'finding');
            }
            if (!out) return [];
            out.onClick = function (e, clicked) { badgeClicked(F, clicked || node); };
            return [out];
        };
    }
    function badgeClicked(F, node) {
        if (!F.h || !node) return;
        refreshRows(F, true);
        var rid = ridOfNode(F, node);
        if (!rid) return;
        showList(F);
        find(F, rid, { reveal: false });
    }

    /* ── the rows: what the working view draws, as the payload says it ── */
    function recordIndex(p) {
        var idx = { attr: {}, obj: {}, ev: {}, doc: {} };
        (p.Attribute || []).forEach(function (a) { idx.attr[lower(a.uuid)] = a; });
        (p.Object || []).forEach(function (o) {
            idx.obj[lower(o.uuid)] = o;
            (o.Attribute || []).forEach(function (a) { idx.attr[lower(a.uuid)] = a; });
        });
        Object.keys(p.events || {}).forEach(function (id) { idx.ev[lower(p.events[id].uuid)] = p.events[id]; });
        ((p.document && p.document.nodes) || []).forEach(function (n) {
            if (n.type === 'ModuleAnswer') idx.doc[lower(n.uuid)] = n;
        });
        idx.sobj = {};
        (p.StandaloneObject || []).forEach(function (o) { idx.sobj[lower(o.uuid)] = o; });
        return idx;
    }
    function objectValue(o) {
        var attrs = o.Attribute || [];
        var order = ['domain', 'hostname', 'url', 'ip', 'ip-dst', 'ip-src'];
        for (var i = 0; i < order.length; i++) {
            var hit = attrs.filter(function (a) { return a.object_relation === order[i]; })[0];
            if (hit) return hit.value;
        }
        return attrs.length ? attrs[0].value : o.name;
    }
    function keyedRow(F, p, idx, key, data, mark) {
        var at = key.indexOf(':');
        var type = key.slice(0, at), addr = lower(key.slice(at + 1));
        var d = data || {};
        var r = {
            rid: key, key: key, type: type,
            kind: type === 'ModuleAnswer' ? 'Attribute' : type === 'StandaloneObject' ? 'Object' : (TYPES[type] ? type : 'Attribute'),
            role: mark.role, known: !!mark.known, missing: !!mark.missing, el: mark.element || null, data: d,
            value: d.value || d.label || addr, typeLabel: '', eventId: null,
            from: mark.origin ? { module: mark.origin.module, value: mark.origin.value } : null
        };
        if (type === 'Event') {
            var ev = idx.ev[addr];
            r.value = (ev && ev.info) || d.info || d.label;
            r.eventId = ev ? String(ev.id) : (d.id ? String(d.id) : null);
            r.typeLabel = r.eventId ? t('eventN', r.eventId) : typeName('Event');
        } else if (type === 'Attribute') {
            var a = idx.attr[addr];
            r.value = a ? a.value : d.value;
            r.typeLabel = (a && a.type) || d['attr-type'] || typeName('Attribute');
            r.eventId = a ? String(a.event_id) : (d.event_id || null);
        } else if (type === 'Object') {
            var o = idx.obj[addr];
            r.value = o ? objectValue(o) : d.label;
            r.typeLabel = (o && o.name) || d.name ? t('objectOf', (o && o.name) || d.name) : typeName('Object');
            r.eventId = o ? String(o.event_id) : (d.event_id || null);
        } else if (type === 'GalaxyCluster') {
            r.value = d.value || d.label;
            r.typeLabel = d.galaxy_name ? t('clusterOf', d.galaxy_name) : typeName('GalaxyCluster');
        } else if (type === 'Value') {
            r.value = d.value || d.label;
            r.typeLabel = typeName('Value');
        } else if (type === 'StandaloneObject') {
            var so = idx.sobj[addr];
            r.value = so ? objectValue({ name: so.name, Attribute: (so.attributes || []).map(function (a) {
                return { object_relation: a.relation, value: a.value };
            }) }) : d.label;
            r.typeLabel = t('objectOf', (so && so.name) || d.name || typeName('Object'));
        } else if (type === 'ModuleAnswer') {
            var n = idx.doc[addr], c = (n && n.content) || {};
            r.value = c.value || d.value;
            r.typeLabel = c.type || d['attr-type'] || typeName('Value');
            var origin = n && n.origins && n.origins[0];
            if (origin) {
                r.from = { module: origin.module, value: origin.value };
                var oa = idx.attr[lower(String(origin.node || '').split(':')[1])];
                if (oa) r.eventId = String(oa.event_id);
            } else if (d.module) {
                r.from = { module: d.module, value: null };
            }
        }
        if (r.eventId && p.events && p.events[r.eventId]) r.eventInfo = p.events[r.eventId].info;
        if (r.el) {
            r.who = r.el.user ? r.el.user.email : null;
            r.when = r.el.created || null;
        }
        r.why = Object.prototype.hasOwnProperty.call(F.why, key) ? F.why[key] : (r.el ? r.el.description || '' : '');
        if (mark.item) r.item = mark.item;
        else if (type === 'Value') r.item = r.value ? { type: 'Value', value: r.value } : { type: 'Value', sha256: key.slice(at + 1) };
        else r.item = type === 'ModuleAnswer' ? null : { type: type, uuid: key.slice(at + 1) };
        r.canAdd = r.role === 'extra' && !!r.item;
        r.canKeep = false;
        return r;
    }
    function enrichEdge(F, id) {
        try {
            var e = F.h.graph().getMutableEdges().filter(function (x) { return x.to && x.to.id === id; })[0];
            return e ? e.getData() : null;
        } catch (err) { return null; }
    }
    // A node a pivot brought, or one being kept: no document key yet.
    function looseRow(F, p, node, kept) {
        var d = node.getData() || {};
        var target = F.h.targetOf(node)[0] || {};
        var answer = d.scope === 'module';
        var kind = { event: 'Event', object: 'Object', cluster: 'GalaxyCluster', value: 'Value' }[d.type] || 'Attribute';
        var r = {
            rid: node.id, key: null, type: answer ? 'ModuleAnswer' : kind, kind: kind, node: node,
            role: kept ? 'finding' : 'pivot', pivot: !kept, kept: !!kept, known: !!d.known, data: d,
            value: d.value || d.label,
            typeLabel: d['attr-type'] || (kind === 'Object' ? (d.name ? t('objectOf', d.name) : typeName('Object')) : typeName(kind)),
            eventId: d.event_id ? String(d.event_id) : null, from: null, why: '',
            item: target.item || (answer && d.known ? { type: 'Value', value: d.value } : null)
        };
        if (answer) {
            var e = enrichEdge(F, node.id);
            r.from = { module: d.module || (d.modules || [])[0], value: e ? (e.asked || (e.origin && e.origin.value)) : null };
        }
        if (r.eventId && p.events && p.events[r.eventId]) r.eventInfo = p.events[r.eventId].info;
        r.canAdd = !kept && !!r.item;
        r.canKeep = false;
        return r;
    }
    function collect(F) {
        var h = F.h, p = h.payload() || {}, W = p.working || {}, idx = recordIndex(p);
        var hidden = {};
        h.hiddenNodes().forEach(function (x) { hidden[x.key] = x.data; });
        var rows = [];
        Object.keys(W).forEach(function (key) {
            var node = h.nodeOf(key);
            var isHidden = Object.prototype.hasOwnProperty.call(hidden, key);
            if (!node && !isHidden) return;
            var r = keyedRow(F, p, idx, key, node ? node.getData() : hidden[key], W[key]);
            r.hidden = isHidden;
            r.node = isHidden ? null : node;
            rows.push(r);
        });
        var pivoted = {};
        h.pivoted().forEach(function (id) { pivoted[id] = true; });
        var g = h.graph();
        Object.keys(pivoted).concat(Object.keys(F.kept)).forEach(function (id) {
            var n = g.getMutableNode(id);
            if (!n) { delete F.kept[id]; return; }
            var target = h.targetOf(n)[0];
            if (target && target.key) { delete F.kept[id]; return; }
            if (!pivoted[id] && !F.kept[id]) return;
            rows.push(looseRow(F, p, n, !pivoted[id]));
        });
        return rows;
    }
    function refreshRows(F, force) {
        if (!F.h) return;
        if (!force && Date.now() - F.rowsAt < 60) return;
        F.rows = collect(F);
        F.byRid = {};
        F.rows.forEach(function (r) { F.byRid[r.rid] = r; });
        F.rowsAt = Date.now();
    }
    function ridOfNode(F, n) {
        if (!n) return null;
        var target = F.h.targetOf(n)[0];
        if (target && target.key && F.byRid[target.key]) return target.key;
        return F.byRid[n.id] ? n.id : null;
    }

    /* ── filters and order ── */
    function matches(F, r) {
        var f = F.f;
        if (f.role !== 'all') {
            if (f.role === 'member' && r.role !== 'member') return false;
            if (f.role === 'finding' && !r.missing && r.role !== 'finding') return false;
            if (f.role === 'extra' && r.role !== 'extra') return false;
            if (f.role === 'hidden' && !r.hidden) return false;
        }
        if (f.kind !== 'all' && r.kind !== f.kind) return false;
        if (f.q) {
            var hay = lower([r.value, r.typeLabel, r.data && r.data.comment, r.eventId ? '#' + r.eventId : '', r.eventInfo, r.who, r.when, r.why,
                             r.from && r.from.module, r.from && r.from.value].join(' '));
            if (hay.indexOf(lower(f.q.trim())) === -1) return false;
        }
        return true;
    }
    function sorter(F) {
        var s = F.sort;
        function cmp(x, y) { return x < y ? -1 : x > y ? 1 : 0; }
        return function (a, b) {
            var c;
            if (s.by === 'value') c = cmp(lower(a.value), lower(b.value));
            else if (s.by === 'event') c = cmp(Number(a.eventId || 1e12), Number(b.eventId || 1e12));
            else c = cmp(a.when || '', b.when || '');
            return c * s.dir || cmp(lower(a.value), lower(b.value));
        };
    }

    /* ── drawing the list ── */
    function chip(cls, icon, label) {
        return '<span class="igw-chip ' + cls + '"><i class="' + icon + '" aria-hidden="true"></i>' + esc(label) + '</span>';
    }
    function chipOf(r) {
        if (r.missing || r.role === 'finding') return chip('is-finding', 'fas fa-lightbulb', t('chipFinding'));
        if (r.hidden) return chip('is-hidden', 'fas fa-eye-slash', t('chipHidden'));
        return '';
    }
    function fromText(r) {
        if (!r.from) return '';
        var module = r.from.module || t('aModule');
        return r.from.value ? t('fromModuleOn', module, r.from.value) : t('fromModule', module);
    }
    function whyForm(F) {
        var id = 'igw-why-' + F.where;
        return '<form class="igw-why-form" data-igw-why-form novalidate>'
            + '<label class="igw-why-l" for="' + id + '">' + esc(t('why')) + '</label>'
            + '<input id="' + id + '" type="text" class="form-control form-control-sm" maxlength="255" autocomplete="off"'
            + ' value="' + esc(F.draft) + '" placeholder="' + esc(t(F.ws ? 'whyPlaceholderWs' : 'whyPlaceholder')) + '"' + (F.saving ? ' disabled' : '') + '>'
            + '<button type="submit" class="btn btn-primary btn-sm"' + (F.saving ? ' disabled' : '') + '>' + esc(t('save')) + '</button>'
            + '<button type="button" class="btn btn-link btn-sm" data-igw-why-cancel>' + esc(t('cancel')) + '</button>'
            + (F.whyError ? '<span class="igw-why-err" role="alert">' + esc(F.whyError) + '</span>'
                          : '<span class="igw-why-hint">' + esc(t('whyHint')) + '</span>')
            + '</form>';
    }
    function rowHtml(F, r) {
        var picked = !!F.picks[r.rid];
        var cls = 'igw-row' + (picked ? ' is-picked' : '') + (F.current === r.rid ? ' is-current' : '')
            + (r.hidden ? ' is-hidden' : '') + (r.key && F.fresh[r.key] ? ' is-fresh' : '') + (F.busy[r.rid] ? ' is-busy' : '');
        var a = ' data-rid="' + esc(r.rid) + '" data-role="' + r.role + '"';
        a += r.role === 'pivot' ? ' data-igw-pivot="' + esc(r.rid) + '"' : ' data-igw-row="' + esc(r.key || r.rid) + '"';
        if (r.hidden) a += ' data-igw-hidden="' + esc(r.key) + '"';
        if (F.current === r.rid) a += ' aria-current="true"';
        var T = TYPES[r.kind] || TYPES.Attribute;
        var html = '<li class="' + cls + '"' + a + ' tabindex="-1">';
        html += '<input type="checkbox" class="form-check-input igw-pick" data-igw-pick aria-label="' + esc(t('selectRow', r.value)) + '"' + (picked ? ' checked' : '') + '>';
        html += '<span class="igw-ico" style="color:' + T.color + '" title="' + esc(typeName(r.kind)) + '"><i class="' + T.icon + '" aria-hidden="true"></i></span>';
        var chipHtml = chipOf(r);
        html += '<span class="igw-val"><span class="igw-v" title="' + esc(r.value) + '">' + esc(r.value) + '</span>' + chipHtml + '</span>';
        var meta = '<span>' + esc(r.typeLabel) + '</span>';
        if (r.from) meta += '<span class="igw-from" title="' + esc(fromText(r)) + '">' + esc(fromText(r)) + '</span>';
        if (r.eventId && r.type !== 'Event') meta += '<span class="igw-n" title="' + esc(r.eventInfo || '') + '">' + esc(t('eventN', r.eventId)) + '</span>';
        if (r.who) meta += '<span class="igw-n">' + esc(r.who) + '</span>';
        if (r.when) meta += '<span class="igw-n" title="' + esc(r.when) + '">' + esc(day(r.when)) + '</span>';
        if (chipHtml) meta += '<span class="igw-w">' + chipHtml + '</span>';
        html += '<span class="igw-meta">' + meta + '</span>';
        html += '<span class="igw-c-ev">' + (r.eventId
            ? '<span class="igw-cell1">#' + esc(r.eventId) + '</span>' + (r.eventInfo && r.type !== 'Event' ? '<span class="igw-cell2" title="' + esc(r.eventInfo) + '">' + esc(r.eventInfo) + '</span>' : '')
            : '') + '</span>';
        html += '<span class="igw-c-add">' + (r.who ? '<span class="igw-cell1" title="' + esc(r.who) + '">' + esc(r.who) + '</span>' : '')
            + (r.when ? '<span class="igw-cell2" title="' + esc(r.when) + '">' + esc(minute(r.when)) + '</span>' : '') + '</span>';
        var why = '';
        if (r.hidden && graphWritable(F)) {
            why += '<button type="button" class="btn btn-link btn-sm" data-igw-show><i class="fas fa-eye me-1" aria-hidden="true"></i>' + esc(tn('showOn', 1)) + '</button>';
        }
        if (r.role === 'member' && F.editing !== r.rid) {
            if (r.why) {
                why += '<span class="igw-why-l">' + esc(t('why')) + '</span><span class="igw-why-t" title="' + esc(r.why) + '">' + esc(r.why) + '</span>';
                if (canEditCollection(F)) {
                    why += '<button type="button" class="igw-ibtn igw-why-edit" data-igw-why title="' + esc(t('editWhy')) + '" aria-label="' + esc(t('editWhy')) + '">'
                        + '<i class="fas fa-pen" aria-hidden="true"></i></button>';
                }
            } else if (canEditCollection(F)) {
                why += '<button type="button" class="btn btn-link btn-sm igw-say" data-igw-why>' + esc(t('sayWhy')) + '</button>';
            }
        } else if (r.role === 'pivot') {
            if (r.canAdd && canEditCollection(F)) {
                why += '<button type="button" class="btn btn-outline-primary btn-sm igw-do" data-igw-do="add"><i class="fas fa-plus me-1" aria-hidden="true"></i>'
                    + esc(tn(F.ws ? 'addWs' : 'addColl', 1)) + '</button>';
            } else if (r.canKeep && graphWritable(F)) {
                why += '<button type="button" class="btn btn-outline-primary btn-sm igw-do" data-igw-do="keep"><i class="fas fa-thumbtack me-1" aria-hidden="true"></i>'
                    + esc(tn('keep', 1)) + '</button>';
            }
        }
        html += '<span class="igw-why">' + why + '</span>';
        if (F.editing === r.rid) html += '<div class="igw-edit">' + whyForm(F) + '</div>';
        html += '<span class="igw-act"><button type="button" class="igw-ibtn" data-igw-more aria-haspopup="menu" aria-expanded="false"'
            + ' aria-label="' + esc(t('actionsFor', r.value)) + '" title="' + esc(t('actions')) + '"><i class="fas fa-ellipsis-vertical" aria-hidden="true"></i></button></span>';
        return html + '</li>';
    }
    function render(F) {
        clearTimeout(F.renderTimer);
        if (!F.h) {
            F.loadEl.hidden = false;
            F.list.hidden = true;
            F.bulk.hidden = true;
            F.countEl.textContent = '';
            return;
        }
        try {
            refreshRows(F, true);
        } catch (e) {
            // The handle went with a remount: the next one draws the list
            F.h = null;
            render(F);
            return;
        }
        F.ws = isWorkspace(F);
        F.loadEl.hidden = true;
        F.list.hidden = false;
        Object.keys(F.picks).forEach(function (rid) { if (!F.byRid[rid]) delete F.picks[rid]; });
        if (F.current && !F.byRid[F.current]) F.current = null;
        if (F.editing && !F.byRid[F.editing]) F.editing = null;
        var shown = F.rows.filter(function (r) { return matches(F, r); });
        var sort = sorter(F);
        var html = '';
        F.shown = [];
        GROUPS.forEach(function (g) {
            var rows = shown.filter(function (r) { return r.role === g.role; }).sort(sort);
            if (!rows.length) return;
            var n = rows.filter(function (r) { return F.picks[r.rid]; }).length;
            html += '<li class="igw-group" data-igw-group="' + g.role + '">'
                + '<input type="checkbox" class="form-check-input" data-igw-gpick="' + g.role + '"' + (n && n === rows.length ? ' checked' : '')
                + (n && n < rows.length ? ' data-igw-mixed' : '') + ' aria-label="' + esc(t('selectGroup', t(g.key))) + '">'
                + (g.icon ? '<i class="' + g.icon + '" aria-hidden="true"></i>' : '')
                + '<span>' + esc(t(g.key)) + '</span><span class="igw-group-n">' + rows.length + '</span></li>';
            rows.forEach(function (r) { html += rowHtml(F, r); F.shown.push(r); });
        });
        if (!shown.length) {
            html = '<li class="igw-empty">' + (F.rows.length
                ? esc(t('noMatch')) + '<br><button type="button" class="btn btn-outline-secondary btn-sm" data-igw-unfilter>' + esc(t('clearFilters')) + '</button>'
                : esc(t('nothing'))) + '</li>';
        }
        var focus = rememberFocus(F);
        var top = F.list.scrollTop;
        F.list.innerHTML = html;
        F.list.scrollTop = top;
        Array.prototype.forEach.call(F.list.querySelectorAll('[data-igw-mixed]'), function (c) { c.indeterminate = true; });
        var tab = F.list.querySelector('.igw-row.is-current') || F.list.querySelector('.igw-row');
        if (tab) tab.tabIndex = 0;
        restoreFocus(F, focus);
        var total = F.rows.length;
        var picked = Object.keys(F.picks).length;
        F.countEl.textContent = (shown.length === total ? String(total) : t('countOf', shown.length, total))
            + (F.mode === 'graph' && picked ? ' · ' + t('selectedN', picked) : '');
        renderBulk(F);
        renderCols(F);
        if (F.scrollTo) {
            var to = F.scrollTo;
            F.scrollTo = null;
            scrollToRow(F, to);
        }
    }
    function renderSoon(F) {
        clearTimeout(F.renderTimer);
        F.renderTimer = setTimeout(function () { render(F); }, 40);
    }
    function rememberFocus(F) {
        var a = document.activeElement;
        if (!a || !F.list.contains(a)) return null;
        var row = a.closest('[data-rid]');
        if (!row) return null;
        var what = a.matches('input[type="text"]') ? 'input' : a.matches('[data-igw-pick]') ? 'pick' : a.matches('[data-igw-more]') ? 'more' : 'row';
        return { rid: row.getAttribute('data-rid'), what: what, start: a.selectionStart, end: a.selectionEnd };
    }
    function restoreFocus(F, f) {
        if (!f) return;
        var row = F.list.querySelector(sel(f.rid));
        if (!row) return;
        var target = f.what === 'input' ? row.querySelector('.igw-why-form input') : f.what === 'pick' ? row.querySelector('[data-igw-pick]')
            : f.what === 'more' ? row.querySelector('[data-igw-more]') : row;
        if (!target) return;
        target.focus({ preventScroll: true });
        if (f.what === 'input' && typeof f.start === 'number') { try { target.setSelectionRange(f.start, f.end); } catch (e) { /* not text */ } }
    }
    function renderCols(F) {
        var s = F.sort;
        Array.prototype.forEach.call(F.pane.querySelectorAll('[data-igw-sort]'), function (b) {
            var on = b.getAttribute('data-igw-sort') === s.by;
            b.setAttribute('aria-sort', on ? (s.dir > 0 ? 'ascending' : 'descending') : 'none');
            b.querySelector('i').className = on ? (s.dir > 0 ? 'fas fa-arrow-up' : 'fas fa-arrow-down') : '';
        });
        var all = F.pane.querySelector('[data-igw-all]');
        if (all) {
            var n = (F.shown || []).filter(function (r) { return F.picks[r.rid]; }).length;
            all.checked = !!n && n === F.shown.length;
            all.indeterminate = !!n && n < F.shown.length;
        }
    }
    // What a bulk removal takes: members out of the collection, findings and
    // extras off the graph, pivots off the canvas.
    function removable(F, r) {
        if (r.role === 'member') return canEditCollection(F);
        if (r.role === 'pivot') return true;
        return graphWritable(F) || !r.key;
    }
    function renderBulk(F) {
        var picked = F.rows.filter(function (r) { return F.picks[r.rid]; });
        var n = picked.length;
        if (!n) {
            F.confirming = false;
            F.bulk.hidden = true;
            F.bulk.innerHTML = '';
            return;
        }
        F.bulk.hidden = false;
        var out = picked.filter(function (r) { return removable(F, r); });
        if (F.confirming && out.length) {
            var mem = out.filter(function (r) { return r.role === 'member'; }).length;
            var other = out.length - mem;
            var parts = [];
            if (mem) parts.push(tn(F.ws ? 'leaveWs' : 'leaveColl', mem));
            if (other) parts.push(tn('leaveGraph', other));
            F.bulk.className = 'igw-bulk is-confirming';
            F.bulk.setAttribute('role', 'alertdialog');
            F.bulk.innerHTML = '<span class="igw-confirm-text"><strong>' + esc(t('removeQ', out.length)) + '</strong> ' + esc(parts.join('; ')) + '.</span>'
                + '<span class="igw-bulk-acts"><button type="button" class="btn btn-link btn-sm" data-igw-cancel>' + esc(t('cancel')) + '</button>'
                + '<button type="button" class="btn btn-danger btn-sm" data-igw-confirm><i class="fas fa-trash-can me-1" aria-hidden="true"></i>'
                + esc(t('removeN', out.length)) + '</button></span>';
            return;
        }
        F.confirming = false;
        F.bulk.className = 'igw-bulk';
        F.bulk.removeAttribute('role');
        F.bulk.innerHTML = '<span class="igw-bulk-n">' + esc(t('selectedN', n)) + '</span>'
            + '<button type="button" class="btn btn-link btn-sm" data-igw-clear>' + esc(t('clear')) + '</button>'
            + '<span class="igw-bulk-acts">'
            + '<button type="button" class="btn btn-outline-primary btn-sm" data-igw-bulk-more aria-haspopup="menu" aria-expanded="false">'
            + esc(t('actions')) + '<i class="fas fa-caret-down ms-1" aria-hidden="true"></i></button>'
            + (out.length ? '<button type="button" class="btn btn-outline-danger btn-sm" data-igw-bulk-remove><i class="fas fa-trash-can me-1" aria-hidden="true"></i>'
                + esc(t('removeNAsk', out.length)) + '</button>' : '')
            + '</span>';
    }
    function scrollToRow(F, rid) {
        var li = F.list.querySelector(sel(rid));
        if (!li) return;
        var L = F.list, head = 30;
        var top = li.offsetTop, bottom = top + li.offsetHeight;
        if (top - head >= L.scrollTop && bottom <= L.scrollTop + L.clientHeight) return;
        L.scrollTop = Math.max(0, top - Math.max(head, (L.clientHeight - li.offsetHeight) / 2));
    }

    /* ── one selection, two views ── */
    function graphOf(F) { try { return F.h.graph(); } catch (e) { return null; } }
    function drawnPicks(F) {
        var g = graphOf(F);
        return Object.keys(F.picks).map(function (rid) {
            var r = F.byRid[rid];
            return r && r.node && g && g.getMutableNode(r.node.id) ? r.node : null;
        }).filter(Boolean);
    }
    function syncCanvas(F) {
        var g = graphOf(F);
        if (!g) return;
        var nodes = drawnPicks(F);
        try { if (nodes.length) g.selectElements(nodes); else g.deselectAll(); } catch (e) { /* no canvas */ }
    }
    function selectedNodes(F) {
        try {
            var bus = F.h.graph().renderer.getGraphInteraction();
            return (bus.getSelectedNodes() || []).map(function (x) { return x && x.node ? x.node : x; }).filter(Boolean);
        } catch (e) { return []; }
    }
    function fromCanvas(F) {
        if (!F.h) return;
        refreshRows(F, true);
        var rids = selectedNodes(F).map(function (n) { return ridOfNode(F, n); }).filter(Boolean);
        var mine = drawnPicks(F).map(function (n) { return ridOfNode(F, n); });
        var same = rids.length === mine.length && rids.every(function (r) { return mine.indexOf(r) !== -1; });
        if (same) return;
        F.picks = {};
        rids.forEach(function (rid) { F.picks[rid] = true; });
        F.confirming = false;
        if (rids.length) {
            var order = (F.shown || []).map(function (r) { return r.rid; });
            var at = function (rid) { var i = order.indexOf(rid); return i === -1 ? 1e9 : i; };
            F.current = rids.slice().sort(function (a, b) { return at(a) - at(b); })[0];
            F.scrollTo = F.current;
        }
        render(F);
    }
    // Pans to a node out of view without zooming.
    function reveal(F, node) {
        try {
            var g = F.h.graph(), rr = g.renderer, n = g.getMutableNode(node.id) || node;
            var p = rr.graphToScreenCoordinates(n.x, n.y);
            var box = F.stage.getBoundingClientRect();
            var m = 48;
            if (p.x > box.left + m && p.x < box.right - m && p.y > box.top + m && p.y < box.bottom - m) return;
            rr.setViewport({ x: n.x, y: n.y, animate: true });
        } catch (e) { /* no canvas */ }
    }
    // Picking a row finds its node; the node is the selection, as a click on it would make it.
    function find(F, rid, opts) {
        var r = F.byRid[rid];
        if (!r) return;
        F.current = rid;
        F.picks = {};
        F.picks[rid] = true;
        F.confirming = false;
        F.scrollTo = rid;
        render(F);
        syncCanvas(F);
        if (r.node && !(opts && opts.reveal === false)) reveal(F, r.node);
    }
    function togglePick(F, rid, on) {
        if (on) F.picks[rid] = true; else delete F.picks[rid];
        F.current = rid;
        F.confirming = false;
        render(F);
        syncCanvas(F);
    }
    function pickMany(F, rids, on) {
        rids.forEach(function (rid) { if (on) F.picks[rid] = true; else delete F.picks[rid]; });
        F.confirming = false;
        render(F);
        syncCanvas(F);
    }
    function clearPicks(F) {
        F.picks = {};
        F.confirming = false;
        render(F);
        syncCanvas(F);
    }

    /* ── what each node offers, on the canvas and in the list alike ── */
    var ENTRIES = [
        { id: 'add', icon: 'fas fa-plus', key: function (F) { return F.ws ? 'addWs' : 'addColl'; },
          fits: function (r, T, F) { return !!r.canAdd && canEditCollection(F); }, run: addToCollection },
        { id: 'keep', icon: 'fas fa-thumbtack', key: 'keep',
          fits: function (r, T, F) { return !!r.canKeep && graphWritable(F); }, run: keepAsFinding },
        { id: 'event', icon: 'fas fa-calendar-plus', key: 'createEvent',
          fits: function (r) { return r.role === 'finding' && !r.known; }, run: function () { toast(t('eventLater'), 'info'); } },
        { id: 'remove', icon: 'fas fa-folder-minus', danger: true, key: function (F) { return F.ws ? 'removeWs' : 'removeColl'; },
          fits: function (r, T, F) { return r.role === 'member' && canEditCollection(F); }, run: removeFromCollection },
        { id: 'hide', icon: 'fas fa-eye-slash', key: 'hide',
          fits: function (r, T, F) { return r.role === 'member' && !r.hidden && !!r.node && graphWritable(F); }, run: hideOnGraph },
        { id: 'show', icon: 'fas fa-eye', key: 'showOn',
          fits: function (r, T, F) { return !!r.hidden && graphWritable(F); }, run: showOnGraph },
        { id: 'why', icon: 'fas fa-pen', key: function (F, fit) { return fit[0].why ? 'editWhy' : 'sayWhy'; },
          fits: function (r, T, F) { return T.length === 1 && r.role === 'member' && canEditCollection(F); },
          run: function (F, fit) { openWhy(F, fit[0].rid); } },
        { id: 'drop', icon: 'fas fa-trash-can', danger: true, divider: true, key: 'drop',
          fits: function (r, T, F) { return (r.role === 'finding' || r.role === 'extra') && (graphWritable(F) || !r.key); }, run: removeFromGraph },
        { id: 'open', icon: 'fas fa-up-right-from-square', divider: true, key: 'openEvent', single: true,
          fits: function (r, T) { return T.length === 1 && !!r.eventId && ['Attribute', 'Object', 'Event'].indexOf(r.type) !== -1; },
          run: function (F, fit) { openEvent(fit[0]); } },
        { id: 'copy', icon: 'fas fa-copy', key: 'copy', single: true,
          fits: function (r, T) { return T.length === 1 && !!r.value && r.type !== 'Event'; }, run: function (F, fit) { copyValue(fit[0]); } }
    ];
    function labelOf(F, E, fit, T) {
        var key = typeof E.key === 'function' ? E.key(F, fit) : E.key;
        if (E.single || !Array.isArray(text()[key])) return t(key);
        return T.length > 1 ? tn(key, fit.length) : tn(key, 1);
    }
    function fitting(F, T) {
        var out = [];
        ENTRIES.forEach(function (E) {
            var fit = T.filter(function (r) { return E.fits(r, T, F); });
            if (fit.length) out.push({ E: E, fit: fit, text: labelOf(F, E, fit, T) });
        });
        return out;
    }
    function targetsOf(F, el) {
        refreshRows(F, false);
        var seen = {};
        return F.h.targetOf(el).map(function (target) {
            var r = F.byRid[target.key || target.id] || null;
            if (!r || seen[r.rid]) return null;
            seen[r.rid] = true;
            return r;
        }).filter(Boolean);
    }
    // The canvas menus: the same entries, each shown where it fits.
    function canvasMenu(F) {
        return ENTRIES.map(function (E) {
            // Pivotick copies the entries it is given: the label is a node kept by reference
            var label = document.createElement('span');
            var item = { text: label, iconClass: E.icon, dividerBefore: !!E.divider };
            if (E.danger) item.variant = 'outline-danger';
            item.visible = function (el) {
                if (!F.h) return false;
                F.ws = isWorkspace(F);
                var T = targetsOf(F, el);
                var fit = T.filter(function (r) { return E.fits(r, T, F); });
                if (!fit.length) return false;
                label.textContent = labelOf(F, E, fit, T);
                return true;
            };
            item.onclick = function (ev, el) {
                if (!F.h) return;
                var T = targetsOf(F, el);
                var fit = T.filter(function (r) { return E.fits(r, T, F); });
                if (fit.length) E.run(F, fit, T);
            };
            return item;
        });
    }

    /* ── the list's own menu, built from the same entries ── */
    var menu = null;
    function closeMenu(refocus) {
        if (!menu) return;
        var m = menu;
        menu = null;
        m.el.remove();
        if (m.anchor) m.anchor.setAttribute('aria-expanded', 'false');
        document.removeEventListener('pointerdown', m.outside, true);
        document.removeEventListener('keydown', m.keys, true);
        window.removeEventListener('resize', m.close);
        if (refocus && m.anchor && document.contains(m.anchor)) m.anchor.focus();
    }
    function openListMenu(F, rows, anchor, point, title) {
        closeMenu(false);
        var entries = fitting(F, rows);
        if (!entries.length) return;
        var el = document.createElement('div');
        el.className = 'dropdown-menu show igw-menu shadow';
        el.setAttribute('role', 'menu');
        if (title) {
            var h = document.createElement('h6');
            h.className = 'dropdown-header';
            h.textContent = title;
            el.appendChild(h);
        }
        entries.forEach(function (x, i) {
            if (x.E.divider && i > 0) {
                var hr = document.createElement('div');
                hr.className = 'dropdown-divider';
                el.appendChild(hr);
            }
            var b = document.createElement('button');
            b.type = 'button';
            b.className = 'dropdown-item' + (x.E.danger ? ' is-danger' : '');
            b.setAttribute('role', 'menuitem');
            b.innerHTML = '<i class="' + x.E.icon + '" aria-hidden="true"></i><span>' + esc(x.text) + '</span>';
            b.addEventListener('click', function () {
                closeMenu(false);
                x.E.run(F, x.fit, rows);
            });
            el.appendChild(b);
        });
        el.style.visibility = 'hidden';
        document.body.appendChild(el);
        var w = el.offsetWidth, hgt = el.offsetHeight, vw = document.documentElement.clientWidth, vh = window.innerHeight;
        var x, y;
        if (point) { x = point.x; y = point.y; }
        else { var r = anchor.getBoundingClientRect(); x = r.right - w; y = r.bottom + 2; if (y + hgt > vh - 8) y = r.top - hgt - 2; }
        el.style.left = Math.max(8, Math.min(x, vw - w - 8)) + 'px';
        el.style.top = Math.max(8, Math.min(y, vh - hgt - 8)) + 'px';
        el.style.visibility = '';
        var m = { el: el, anchor: anchor };
        m.close = function () { closeMenu(false); };
        m.outside = function (e) { if (!el.contains(e.target) && e.target !== anchor && !(anchor && anchor.contains(e.target))) closeMenu(false); };
        // Ahead of the dock's own Escape, which would close the panel
        m.keys = function (e) {
            var items = Array.prototype.slice.call(el.querySelectorAll('[role="menuitem"]'));
            var at = items.indexOf(document.activeElement);
            if (e.key === 'Escape') { e.preventDefault(); e.stopPropagation(); closeMenu(true); }
            else if (e.key === 'ArrowDown') { e.preventDefault(); items[(at + 1) % items.length].focus(); }
            else if (e.key === 'ArrowUp') { e.preventDefault(); items[(at - 1 + items.length) % items.length].focus(); }
            else if (e.key === 'Tab') { closeMenu(false); }
        };
        document.addEventListener('pointerdown', m.outside, true);
        document.addEventListener('keydown', m.keys, true);
        window.addEventListener('resize', m.close);
        if (anchor) anchor.setAttribute('aria-expanded', 'true');
        menu = m;
        var first = el.querySelector('[role="menuitem"]');
        if (first) first.focus({ preventScroll: true });
    }

    /* ── the actions ── */
    function failed(F, err, what) {
        toast(t(what) + ': ' + ((err && err.message) || t('didNotGo')) + '.', 'danger');
        render(F);
    }
    function settle(F, rows) {
        rows.forEach(function (r) { delete F.busy[r.rid]; delete F.picks[r.rid]; });
    }
    // A finding MISP now holds gives its place on the graph to the member
    // holding it; a pivot's answer leaves the canvas once its value is in.
    function addToCollection(F, fit) {
        var rows = fit.filter(function (r) { return r.item; });
        if (!rows.length) return Promise.resolve();
        var h = F.h;
        // A value answer gives its place to the member; an object answer the
        // collection holds is drawn as its member where it sits
        var swaps = rows.filter(function (r) {
            return r.key && r.type === 'ModuleAnswer' && r.item.type === 'Value' && graphWritable(F);
        });
        var drops = rows.filter(function (r) { return !r.key && r.type === 'ModuleAnswer'; }).map(function (r) { return r.rid; });
        rows.forEach(function (r) { F.busy[r.rid] = true; });
        render(F);
        var swapped = swaps.reduce(function (p, r) {
            return p.then(function () { return h.replaceNode(r.key, { type: 'Value', value: r.item.value }); });
        }, Promise.resolve());
        return swapped.then(function () {
            return IG().add(rows.map(function (r) { return r.item; }), where(F));
        }).then(function () {
            settle(F, rows);
            if (drops.length && F.h === h) h.remove(drops);
            render(F);
        }, function (err) {
            rows.forEach(function (r) { delete F.busy[r.rid]; });
            failed(F, err, 'notAdded');
        });
    }
    function keepAsFinding(F, fit) {
        var ids = fit.map(function (r) { return r.rid; });
        var h = F.h;
        ids.forEach(function (id) { F.kept[id] = true; });
        F.current = ids[ids.length - 1];
        F.scrollTo = F.current;
        var kept = h.keepNow(ids);
        h.redraw();
        render(F);
        return kept.then(function () { if (F.h === h) render(F); }, function (err) {
            ids.forEach(function (id) { delete F.kept[id]; });
            failed(F, err, 'notKept');
        });
    }
    // Out of the collection, and off the graph laying it out (C14: one click).
    function removeFromCollection(F, fit) {
        var rows = fit.filter(function (r) { return r.role === 'member' && r.key; });
        if (!rows.length) return Promise.resolve();
        var h = F.h;
        var keys = rows.map(function (r) { return r.key; });
        rows.forEach(function (r) { F.busy[r.rid] = true; });
        render(F);
        return IG().remove(keys, where(F)).then(function () {
            settle(F, rows);
            if (F.editing && keys.indexOf(F.editing) !== -1) F.editing = null;
            if (F.h === h && graphWritable(F)) {
                return h.removeNow(keys).then(function () { render(F); }, function (err) { failed(F, err, 'notDropped'); });
            }
            render(F);
        }, function (err) {
            rows.forEach(function (r) { delete F.busy[r.rid]; });
            failed(F, err, 'notRemoved');
        });
    }
    function removeFromGraph(F, fit) {
        var keys = fit.filter(function (r) { return r.key; }).map(function (r) { return r.key; });
        var ids = fit.filter(function (r) { return !r.key; }).map(function (r) { return r.rid; });
        fit.forEach(function (r) { delete F.picks[r.rid]; });
        if (ids.length) {
            ids.forEach(function (id) { delete F.kept[id]; });
            F.h.remove(ids);
        }
        render(F);
        syncCanvas(F);
        if (!keys.length) return Promise.resolve();
        return F.h.removeNow(keys).then(function () { render(F); }, function (err) { failed(F, err, 'notDropped'); });
    }
    function hideOnGraph(F, fit) {
        var keys = fit.map(function (r) { return r.key; });
        var h = F.h;
        var hidden = h.hideNow(keys);
        render(F);
        return hidden.then(function () { render(F); }, function (err) {
            if (F.h === h) h.showNodes(keys);
            failed(F, err, 'notHidden');
        });
    }
    function showOnGraph(F, fit) {
        var keys = fit.map(function (r) { return r.key; });
        var h = F.h;
        var shown = h.showNow(keys);
        refreshRows(F, true);
        if (fit.length === 1) find(F, fit[0].rid);
        else { render(F); syncCanvas(F); }
        return shown.then(function () { render(F); }, function (err) {
            if (F.h === h) h.hideNodes(keys);
            failed(F, err, 'notShown');
        });
    }
    function bulkRemove(F) {
        var picked = F.rows.filter(function (r) { return F.picks[r.rid] && removable(F, r); });
        F.confirming = false;
        var members = picked.filter(function (r) { return r.role === 'member'; });
        var others = picked.filter(function (r) { return r.role !== 'member'; });
        var done = [];
        if (others.length) done.push(removeFromGraph(F, others));
        if (members.length) done.push(removeFromCollection(F, members));
        render(F);
        return Promise.all(done);
    }
    function openEvent(r) {
        window.open(baseurl() + '/events/view/' + encodeURIComponent(r.eventId), '_blank', 'noopener');
    }
    function copyValue(r) {
        var nope = function () { toast(t('notCopied'), 'danger'); };
        try {
            navigator.clipboard.writeText(String(r.value)).then(function () { toast(t('copied', r.value), 'success'); }, nope);
        } catch (e) { nope(); }
    }

    /* ── why ── */
    function openWhy(F, rid) {
        var r = F.byRid[rid];
        if (!r || r.role !== 'member') return;
        F.editing = rid;
        F.draft = r.why || '';
        F.whyError = null;
        F.current = rid;
        F.scrollTo = rid;
        showList(F);
        render(F);
        var input = F.list.querySelector('.igw-why-form input');
        if (input) { input.focus({ preventScroll: true }); input.select(); }
    }
    function cancelWhy(F) {
        var rid = F.editing;
        F.editing = null;
        F.whyError = null;
        render(F);
        var row = rid && F.list.querySelector(sel(rid));
        if (row) row.focus({ preventScroll: true });
    }
    function saveWhy(F) {
        var r = F.byRid[F.editing];
        if (!r || F.saving) return;
        var said = F.draft.replace(/\s+/g, ' ').trim();
        F.saving = true;
        render(F);
        IG().describe(r.key, said, where(F)).then(function (rep) {
            F.saving = false;
            F.why[r.key] = rep && typeof rep.description === 'string' ? rep.description : said;
            F.editing = null;
            render(F);
            var row = F.list.querySelector(sel(r.rid));
            if (row) row.focus({ preventScroll: true });
        }, function (err) {
            F.saving = false;
            F.whyError = (err && err.message) || t('whyFailed');
            render(F);
        });
    }

    /* ── writes made here, on the page, in the dock or in another tab ── */
    function framesOf(collection) {
        return Object.keys(frames).map(function (w) { return frames[w]; }).filter(function (F) {
            return F.h && lower(collectionOf(F).uuid) === lower(collection);
        });
    }
    // The dock follows its own collection's adds and removals; the page reads
    // its working view again.
    function follow(F) {
        if (F.where === 'dock') return;
        F.h.refresh().then(function () { render(F); }, function () { /* drawn on the next write */ });
    }
    document.addEventListener('intel-graph:added', function (e) {
        var d = e.detail || {};
        var keys = ((d.report && d.report.added) || []).slice();
        framesOf(d.collection).forEach(function (F) {
            var now = Date.now();
            keys.forEach(function (k) { F.fresh[k] = now; });
            if (keys.length) {
                F.scrollTo = keys[0];
                setTimeout(function () {
                    keys.forEach(function (k) { if (F.fresh[k] === now) delete F.fresh[k]; });
                    renderSoon(F);
                }, 8000);
            }
            follow(F);
        });
    });
    document.addEventListener('intel-graph:removed', function (e) {
        framesOf((e.detail || {}).collection).forEach(follow);
    });
    document.addEventListener('intel-graph:described', function (e) {
        var d = e.detail || {};
        if (!d.key) return;
        framesOf(d.collection).forEach(function (F) {
            F.why[d.key] = d.description || '';
            renderSoon(F);
        });
    });

    // Members the layout placed are written where they settled, so they open
    // there next time; only where that write does not hold a published
    // collection back from partners.
    function keepPlacedSoon(F) {
        clearTimeout(F.placeTimer);
        F.placeTimer = setTimeout(function () { keepPlaced(F); }, 300);
    }
    function keepPlaced(F) {
        var h = F.h;
        if (!h || F.placing || !graphWritable(F)) return;
        var c = collectionOf(F);
        if (!(c.distribution === 0 || c.withheld)) return;
        var fresh = h.placed().filter(function (k) { return !F.placedTried[k]; });
        if (!fresh.length) return;
        fresh.forEach(function (k) { F.placedTried[k] = true; });
        F.placing = true;
        h.keepPlaced().then(function () { F.placing = false; }, function () { F.placing = false; });
    }

    /* ── the frames ── */
    function paneHtml(F) {
        var id = 'igw-title-' + F.where;
        return '<div class="igw-bar">'
            + '<span class="igw-title" id="' + id + '">' + esc(t('title')) + '</span><span class="igw-count" data-igw-count aria-live="polite"></span>'
            + '<div class="btn-group igw-views" role="group" aria-label="' + esc(t('views')) + '" data-igw-views>'
            + '<button type="button" class="btn btn-outline-secondary" data-igw-view="graph" aria-pressed="false">' + esc(t('viewGraph')) + '</button>'
            + '<button type="button" class="btn btn-outline-secondary" data-igw-view="both" aria-pressed="true">' + esc(t('viewBoth')) + '</button>'
            + '<button type="button" class="btn btn-outline-secondary" data-igw-view="list" aria-pressed="false">' + esc(t('viewList')) + '</button>'
            + '</div></div>'
            + '<div class="igw-tools">'
            + '<div class="igw-search"><i class="fas fa-magnifying-glass" aria-hidden="true"></i>'
            + '<input type="search" class="form-control form-control-sm" data-igw-q placeholder="' + esc(t('filter')) + '" title="' + esc(t('filterTitle')) + '"'
            + ' aria-label="' + esc(t('filterLabel')) + '"></div>'
            + '<select class="form-select form-select-sm" data-igw-role aria-label="' + esc(t('show')) + '">'
            + '<option value="all">' + esc(t('showAll')) + '</option><option value="member">' + esc(t('showMembers')) + '</option>'
            + '<option value="finding">' + esc(t('showFindings')) + '</option><option value="extra">' + esc(t('showExtras')) + '</option>'
            + '<option value="hidden">' + esc(t('showHidden')) + '</option>'
            + '</select>'
            + '<select class="form-select form-select-sm" data-igw-kind aria-label="' + esc(t('type')) + '">'
            + '<option value="all">' + esc(t('typeAll')) + '</option>'
            + Object.keys(TYPES).map(function (k) { return '<option value="' + k + '">' + esc(typeName(k, true)) + '</option>'; }).join('')
            + '</select></div>'
            + '<div class="igw-bulk" data-igw-bulk hidden></div>'
            + '<div class="igw-cols" data-igw-cols>'
            + '<input type="checkbox" class="form-check-input" data-igw-all aria-label="' + esc(t('selectShown')) + '">'
            + '<button type="button" class="igw-sort igw-col-val" data-igw-sort="value">' + esc(t('colRecord')) + '<i aria-hidden="true"></i></button>'
            + '<button type="button" class="igw-sort igw-col-ev" data-igw-sort="event">' + esc(t('colEvent')) + '<i aria-hidden="true"></i></button>'
            + '<button type="button" class="igw-sort igw-col-add" data-igw-sort="when">' + esc(t('colAdded')) + '<i aria-hidden="true"></i></button>'
            + '<span class="igw-col-why">' + esc(t('colWhy')) + '</span></div>'
            + '<div class="igw-loading" data-igw-loading><div class="misp-loader" role="status"></div></div>'
            + '<ul class="igw-list" data-igw-list aria-labelledby="' + id + '" hidden></ul>';
    }
    function buildFrame(where, body, stage) {
        var split = document.createElement('div');
        split.className = 'igw-split';
        split.tabIndex = 0;
        split.setAttribute('role', 'separator');
        split.setAttribute('aria-label', t('splitLabel'));
        split.title = t('splitTitle');
        split.innerHTML = '<span class="igw-split-knob" aria-hidden="true"></span>';
        var pane = document.createElement('section');
        pane.className = 'igw-pane';
        pane.setAttribute('data-igw-pane', where);
        pane.setAttribute('aria-labelledby', 'igw-title-' + where);
        var prefs = load(where);
        var F = {
            where: where, body: body, stage: stage, pane: pane, split: split,
            h: null, bound: null, rows: [], byRid: {}, shown: [], rowsAt: 0, ws: where === 'dock',
            f: { q: '', role: 'all', kind: 'all' }, sort: { by: 'when', dir: -1 },
            picks: {}, current: null, editing: null, draft: '', saving: false, whyError: null, confirming: false,
            fresh: {}, kept: {}, why: {}, busy: {}, placedTried: {}, placing: false, stops: [],
            view: ['graph', 'both', 'list'].indexOf(prefs.view) !== -1 ? prefs.view : 'both',
            ratio: typeof prefs.ratio === 'number' ? prefs.ratio : 0.5
        };
        pane.innerHTML = paneHtml(F);
        body.appendChild(split);
        body.appendChild(pane);
        F.list = pane.querySelector('[data-igw-list]');
        F.bulk = pane.querySelector('[data-igw-bulk]');
        F.countEl = pane.querySelector('[data-igw-count]');
        F.loadEl = pane.querySelector('[data-igw-loading]');
        frames[where] = F;
        wire(F);
        layout(F);
        if (window.ResizeObserver) new ResizeObserver(function () { layout(F); }).observe(body);
        render(F);
        return F;
    }
    function attach(F, h) {
        detach(F);
        F.h = h;
        F.bound = h;
        F.rowsAt = 0;
        F.kept = {};
        F.placedTried = {};
        F.ws = isWorkspace(F);
        var g = h.graph();
        try {
            var bus = g.renderer.getGraphInteraction();
            ['selectNode', 'selectNodes', 'unselectNode', 'unselectNodes'].forEach(function (name) {
                bus.on(name, function () { setTimeout(function () { if (F.h === h) fromCanvas(F); }, 0); });
            });
            bus.on('nodeContextmenu', function () {
                var args = Array.prototype.slice.call(arguments);
                setTimeout(function () {
                    if (F.h !== h) return;
                    var node = args.filter(function (x) { return x && typeof x.getData === 'function'; })[0];
                    refreshRows(F, true);
                    var rid = ridOfNode(F, node);
                    if (rid) markCurrent(F, rid);
                }, 0);
            });
        } catch (e) { /* no interaction bus: the list follows writes only */ }
        try {
            g.on('nodeAdd', function () { if (F.h === h) renderSoon(F); });
            g.on('nodeRemove', function () { if (F.h === h) renderSoon(F); });
        } catch (e) { /* no graph events */ }
        F.stops.push(h.onChange(function (handle, reason) {
            if (F.h !== h) return;
            renderSoon(F);
            if (reason === 'refreshed') keepPlacedSoon(F);
        }));
        h.redraw();
        render(F);
        keepPlacedSoon(F);
    }
    function detach(F) {
        clearTimeout(F.placeTimer);
        F.stops.forEach(function (stop) { try { stop(); } catch (e) { /* gone */ } });
        F.stops = [];
        F.h = null;
        F.bound = null;
        F.placing = false;
        closeMenu(false);
        render(F);
    }
    function markCurrent(F, rid) {
        F.current = rid;
        F.scrollTo = rid;
        render(F);
    }

    /* ── the room: split, or Graph / List when the panel is short ── */
    function layout(F) {
        var b = F.body.getBoundingClientRect();
        if (!b.width || !b.height) return;
        var row = F.where === 'page' || b.width >= 820;
        var short = !row && b.height < 460;
        var mode = row ? 'both' : F.view;
        if (short && mode === 'both') mode = 'graph';
        var was = F.mode;
        F.row = row;
        F.short = short;
        F.mode = mode;
        if (was && was !== mode && F.h) renderSoon(F);
        F.body.classList.toggle('is-row', row);
        F.body.classList.toggle('is-graph', mode === 'graph');
        F.body.classList.toggle('is-list', mode === 'list');
        F.split.setAttribute('aria-orientation', row ? 'vertical' : 'horizontal');
        setRatio(F, F.ratio, b);
        var views = F.pane.querySelector('[data-igw-views]');
        views.hidden = row;
        Array.prototype.forEach.call(views.querySelectorAll('[data-igw-view]'), function (btn) {
            var v = btn.getAttribute('data-igw-view');
            btn.hidden = short && v === 'both';
            btn.setAttribute('aria-pressed', String(v === mode));
            btn.classList.toggle('active', v === mode);
        });
    }
    function setRatio(F, r, rect) {
        var b = rect || F.body.getBoundingClientRect();
        var size = F.row ? b.width : b.height;
        if (!size) return;
        var lo = (F.row ? 420 : 220) / size, hi = 1 - (F.row ? (F.where === 'page' ? 440 : 380) : 170) / size;
        F.ratio = lo > hi ? 0.5 : Math.min(hi, Math.max(lo, r));
        F.body.style.setProperty('--igw-a', F.ratio.toFixed(4));
        F.body.style.setProperty('--igw-b', (1 - F.ratio).toFixed(4));
        F.split.setAttribute('aria-valuenow', String(Math.round(F.ratio * 100)));
        F.split.setAttribute('aria-valuemin', String(Math.round(lo * 100)));
        F.split.setAttribute('aria-valuemax', String(Math.round(hi * 100)));
    }
    function remember(F) { store(F.where, { view: F.view, ratio: F.ratio }); }
    function setView(F, v) {
        F.view = v;
        remember(F);
        layout(F);
        if (v !== 'graph' && F.current) scrollToRow(F, F.current);
    }
    function showList(F) {
        if (F.mode === 'graph') { F.view = F.short ? 'list' : 'both'; layout(F); }
    }

    /* ── wiring ── */
    function wire(F) {
        var s = F.split;
        s.addEventListener('pointerdown', function (e) {
            if (e.button !== 0) return;
            e.preventDefault();
            s.setPointerCapture(e.pointerId);
            s.classList.add('is-dragging');
            var move = function (ev) {
                var b = F.body.getBoundingClientRect();
                setRatio(F, F.row ? (ev.clientX - b.left) / b.width : (ev.clientY - b.top) / b.height, b);
            };
            var up = function () {
                s.classList.remove('is-dragging');
                s.removeEventListener('pointermove', move);
                s.removeEventListener('pointerup', up);
                s.removeEventListener('pointercancel', up);
                remember(F);
            };
            s.addEventListener('pointermove', move);
            s.addEventListener('pointerup', up);
            s.addEventListener('pointercancel', up);
        });
        s.addEventListener('dblclick', function () { setRatio(F, 0.5); remember(F); });
        s.addEventListener('keydown', function (e) {
            var step = { ArrowUp: -0.04, ArrowLeft: -0.04, ArrowDown: 0.04, ArrowRight: 0.04 }[e.key];
            if (e.key === 'Home') step = -1;
            if (e.key === 'End') step = 1;
            if (!step) return;
            e.preventDefault();
            setRatio(F, F.ratio + step);
            remember(F);
        });

        F.pane.querySelector('[data-igw-views]').addEventListener('click', function (e) {
            var b = e.target.closest('[data-igw-view]');
            if (b) setView(F, b.getAttribute('data-igw-view'));
        });
        var q = F.pane.querySelector('[data-igw-q]'), qTimer = 0;
        q.addEventListener('input', function () {
            clearTimeout(qTimer);
            qTimer = setTimeout(function () { F.f.q = q.value; render(F); }, 120);
        });
        F.pane.querySelector('[data-igw-role]').addEventListener('change', function (e) { F.f.role = e.target.value; render(F); });
        F.pane.querySelector('[data-igw-kind]').addEventListener('change', function (e) { F.f.kind = e.target.value; render(F); });

        F.pane.querySelector('[data-igw-cols]').addEventListener('click', function (e) {
            var b = e.target.closest('[data-igw-sort]');
            if (!b) return;
            var by = b.getAttribute('data-igw-sort');
            F.sort = { by: by, dir: F.sort.by === by ? -F.sort.dir : (by === 'when' ? -1 : 1) };
            render(F);
        });
        F.pane.querySelector('[data-igw-all]').addEventListener('change', function (e) {
            pickMany(F, (F.shown || []).map(function (r) { return r.rid; }), e.target.checked);
        });

        F.bulk.addEventListener('click', function (e) {
            var target = e.target;
            if (target.closest('[data-igw-clear]')) { clearPicks(F); return; }
            if (target.closest('[data-igw-bulk-remove]')) {
                F.confirming = true;
                renderBulk(F);
                var c = F.bulk.querySelector('[data-igw-confirm]');
                if (c) c.focus({ preventScroll: true });
                return;
            }
            if (target.closest('[data-igw-cancel]')) {
                F.confirming = false;
                renderBulk(F);
                var back = F.bulk.querySelector('[data-igw-bulk-remove]');
                if (back) back.focus({ preventScroll: true });
                return;
            }
            if (target.closest('[data-igw-confirm]')) { bulkRemove(F); return; }
            var more = target.closest('[data-igw-bulk-more]');
            if (more) {
                var rows = F.rows.filter(function (r) { return F.picks[r.rid]; });
                openListMenu(F, rows, more, null, t('selectedN', rows.length));
            }
        });
        F.bulk.addEventListener('keydown', function (e) {
            if (e.key === 'Escape' && F.confirming) { e.stopPropagation(); F.confirming = false; renderBulk(F); }
        });

        var L = F.list;
        L.addEventListener('change', function (e) {
            var target = e.target;
            var row = target.closest('[data-rid]');
            if (target.matches('[data-igw-pick]') && row) { togglePick(F, row.getAttribute('data-rid'), target.checked); return; }
            if (target.matches('[data-igw-gpick]')) {
                var role = target.getAttribute('data-igw-gpick');
                pickMany(F, (F.shown || []).filter(function (r) { return r.role === role; }).map(function (r) { return r.rid; }), target.checked);
            }
        });
        L.addEventListener('input', function (e) {
            if (e.target.closest('[data-igw-why-form]')) F.draft = e.target.value;
        });
        L.addEventListener('submit', function (e) {
            if (!e.target.matches('[data-igw-why-form]')) return;
            e.preventDefault();
            saveWhy(F);
        });
        L.addEventListener('click', function (e) {
            var target = e.target;
            if (target.closest('[data-igw-unfilter]')) { clearFilters(F); return; }
            var row = target.closest('[data-rid]');
            if (!row) return;
            var rid = row.getAttribute('data-rid');
            var r = F.byRid[rid];
            if (target.closest('[data-igw-why-cancel]')) { cancelWhy(F); return; }
            if (!r || target.closest('[data-igw-pick]') || target.closest('.igw-edit')) return;
            if (target.closest('[data-igw-show]')) { showOnGraph(F, [r]); return; }
            if (target.closest('[data-igw-why]')) { openWhy(F, rid); return; }
            if (target.closest('[data-igw-more]')) {
                markCurrent(F, rid);
                openListMenu(F, [F.byRid[rid]], F.list.querySelector(sel(rid) + ' [data-igw-more]'));
                return;
            }
            var act = target.closest('[data-igw-do]');
            if (act) {
                var E = ENTRIES.filter(function (x) { return x.id === act.getAttribute('data-igw-do'); })[0];
                if (E) E.run(F, [r], [r]);
                return;
            }
            if (target.closest('a, button, input, select, textarea')) return;
            if (e.shiftKey || e.ctrlKey || e.metaKey) togglePick(F, rid, !F.picks[rid]);
            else find(F, rid);
        });
        L.addEventListener('contextmenu', function (e) {
            var row = e.target.closest('[data-rid]');
            if (!row || e.target.closest('input, [data-igw-why-form]')) return;
            e.preventDefault();
            var rid = row.getAttribute('data-rid');
            var rows = F.picks[rid] && Object.keys(F.picks).length > 1
                ? F.rows.filter(function (r) { return F.picks[r.rid]; }) : [F.byRid[rid]];
            if (rows.length === 1) markCurrent(F, rid);
            openListMenu(F, rows.filter(Boolean), null, { x: e.clientX, y: e.clientY }, rows.length > 1 ? t('selectedN', rows.length) : null);
        });
        L.addEventListener('keydown', function (e) {
            var target = e.target;
            if (target.closest('[data-igw-why-form]')) {
                if (e.key === 'Escape') { e.preventDefault(); e.stopPropagation(); cancelWhy(F); }
                return;
            }
            var row = target.closest('[data-rid]');
            if (!row || target !== row) return;
            var rows = Array.prototype.slice.call(L.querySelectorAll('.igw-row'));
            var at = rows.indexOf(row);
            var rid = row.getAttribute('data-rid');
            if (e.key === 'ArrowDown' || e.key === 'ArrowUp') {
                e.preventDefault();
                var next = rows[at + (e.key === 'ArrowDown' ? 1 : -1)];
                if (next) { row.tabIndex = -1; next.tabIndex = 0; next.focus(); }
            } else if (e.key === 'Enter') {
                e.preventDefault();
                find(F, rid);
            } else if (e.key === ' ') {
                e.preventDefault();
                togglePick(F, rid, !F.picks[rid]);
            } else if (e.key === 'ContextMenu' || (e.shiftKey && e.key === 'F10')) {
                e.preventDefault();
                openListMenu(F, [F.byRid[rid]], row.querySelector('[data-igw-more]'));
            }
        });
    }
    function clearFilters(F) {
        F.f = { q: '', role: 'all', kind: 'all' };
        F.pane.querySelector('[data-igw-q]').value = '';
        F.pane.querySelector('[data-igw-role]').value = 'all';
        F.pane.querySelector('[data-igw-kind]').value = 'all';
        render(F);
    }

    new MutationObserver(function () {
        Object.keys(frames).forEach(function (w) { if (frames[w].h) frames[w].h.redraw(); });
    }).observe(document.documentElement, { attributes: true, attributeFilter: ['data-bs-theme'] });

    function api(F) {
        return {
            where: F.where,
            mountOptions: function (ui) {
                return {
                    ui: Object.assign({}, ui || {}, { contextMenu: { enabled: true, menuNode: { menu: canvasMenu(F) }, menuSelection: { menu: canvasMenu(F) } } }),
                    badges: badgesOf(F)
                };
            },
            bind: function (h) { F.bound = h; },
            attach: function (h) { attach(F, h); },
            detach: function () { detach(F); },
            none: function (on) { F.body.classList.toggle('is-none', !!on); },
            layout: function () { layout(F); },
            find: function (rid) { if (F.h) { refreshRows(F, true); find(F, rid); } },
            rows: function () { if (F.h) refreshRows(F, true); return F.rows.slice(); }
        };
    }

    /* ── the collection page's Pivot Explorer tab ── */
    function startPage() {
        var root = document.querySelector('[data-igw-page]');
        if (!root || !IG()) return;
        var uuid = lower(root.getAttribute('data-igw-collection'));
        var extra = {};
        try { extra = JSON.parse(root.getAttribute('data-igw-explorer') || '{}') || {}; } catch (e) { extra = {}; }
        var slot = root.querySelector('[data-igw-slot]');
        var whatEl = root.querySelector('[data-igw-what]');
        var stateEl = root.querySelector('[data-igw-state]');
        var headEl = root.querySelector('[data-igw-head]');
        var body = document.createElement('div');
        body.className = 'igw-body igw-page is-row';
        var stage = document.createElement('div');
        stage.className = 'igw-stage';
        var wait = document.createElement('div');
        wait.className = 'igw-stage-wait';
        wait.innerHTML = '<div class="misp-loader" role="status"></div>';
        stage.appendChild(wait);
        body.appendChild(stage);
        slot.appendChild(body);
        var F = buildFrame('page', body, stage);
        var frame = api(F);
        var canEdit = root.getAttribute('data-igw-can-edit') === '1';
        var self = { uuid: uuid, name: root.getAttribute('data-igw-name') || '', type: root.getAttribute('data-igw-type') || 'research' };
        // choice: what the head's picker asked for, {kind: 'structure'} or
        // {kind: 'graph', graph}; null draws the default
        var P = { h: null, key: null, token: 0, layout: 'clean', why: '', choice: null, saveAs: null };

        // The working view when the collection is the workspace, else every
        // member; or a saved graph picked from the head, drawn as saved.
        function drawn() {
            var a = IG().active();
            var ws = !!a && lower(a.Collection.uuid) === uuid;
            var choice = P.choice || {};
            if (choice.kind === 'graph') return { kind: 'graph', ws: ws, graph: choice.graph };
            if (ws && choice.kind !== 'structure') return { kind: 'working', ws: true, graph: a.Graph || null };
            return { kind: 'structure', ws: ws, graph: null };
        }
        function keyOf(d) { return d.kind + '/' + lower(d.graph ? d.graph.uuid : ''); }
        function canSaveGraph() { return !!(window.IntelGraphConfig && window.IntelGraphConfig.canSaveGraph); }
        function el(tag, cls, label) {
            var e = document.createElement(tag);
            if (cls) e.className = cls;
            if (label != null) e.textContent = label;
            return e;
        }
        function button(cls, label, fn, icon) {
            var b = el('button', cls);
            b.type = 'button';
            if (icon) {
                var i = el('i', icon + ' me-1');
                i.setAttribute('aria-hidden', 'true');
                b.appendChild(i);
            }
            b.appendChild(document.createTextNode(label));
            b.addEventListener('click', fn);
            return b;
        }
        function graphLink(g, text) {
            var a = el('a', null, text);
            a.href = baseurl() + '/analyst_graphs/view/' + encodeURIComponent(g.uuid);
            return a;
        }
        // "laid out by ‹graph›", the graph a link
        function withGraph(key, g) {
            var span = el('span');
            var parts = t(key, '\u0000').split('\u0000');
            span.appendChild(document.createTextNode(parts[0]));
            var a = graphLink(g);
            a.title = t('pageOpenGraph');
            a.appendChild(el('strong', null, g.name));
            span.appendChild(a);
            span.appendChild(document.createTextNode(parts[1] || ''));
            return span;
        }
        function renderHead() {
            var d = drawn();
            whatEl.textContent = '';
            var icon = el('i', d.kind === 'structure' ? 'fas fa-circle-nodes' : 'misp-icon misp-icon-analyst-graph misp-simple');
            icon.setAttribute('aria-hidden', 'true');
            whatEl.appendChild(icon);
            whatEl.appendChild(picker(d));
            var say = el('span', 'igw-page-say');
            if (d.kind === 'working') {
                say.appendChild(d.graph ? withGraph('pageWsSubGraph', d.graph) : document.createTextNode(t('pageWsSubAuto')));
            } else if (d.kind === 'structure') {
                say.textContent = t('pageStructureSub');
            } else {
                var payload = P.h && P.h.payload && P.h.payload();
                var g = Object.assign({}, d.graph, (payload && payload.Graph) || {});
                say.appendChild(document.createTextNode(t('pagePicture', (g.Orgc && g.Orgc.name) || '', tn('layoutNodes', g.node_count || 0)) + ' · '));
                say.appendChild(graphLink(g, t('pageOpenGraph')));
                var joined = payload && payload.meta && payload.meta.joined_since;
                if (joined) say.appendChild(el('span', 'igw-page-joined', tn('pageJoinedSince', joined)));
            }
            whatEl.appendChild(say);
            renderState();
        }

        // The head's picker: the working view, Structure, and the saved graphs
        // on the collection, any organisation's.
        function picker(d) {
            var wrap = el('div', 'dropdown igw-pick');
            var b = el('button', 'btn btn-sm igw-pick-btn');
            b.type = 'button';
            b.title = t('pageDraw');
            b.setAttribute('data-bs-toggle', 'dropdown');
            b.setAttribute('aria-expanded', 'false');
            b.setAttribute('data-igw-pick', '');
            b.appendChild(el('strong', null, d.kind === 'working' ? t('pageYourWs') : d.kind === 'structure' ? t('pageStructureName') : d.graph.name));
            var caret = el('i', 'fas fa-chevron-down');
            caret.setAttribute('aria-hidden', 'true');
            b.appendChild(caret);
            var menu = el('div', 'dropdown-menu igw-pick-menu');
            menu.setAttribute('data-igw-pick-menu', '');
            b.addEventListener('show.bs.dropdown', function () { fillPick(menu); });
            wrap.appendChild(b);
            wrap.appendChild(menu);
            return wrap;
        }
        function pickRow(name, sub, current, iconCls, onPick) {
            var b = el('button', 'dropdown-item igw-pick-row');
            b.type = 'button';
            if (current) b.setAttribute('aria-current', 'true');
            var mark = el('i', (current ? 'fas fa-check' : iconCls) + ' igw-pick-mark');
            mark.setAttribute('aria-hidden', 'true');
            var text = el('span', 'igw-pick-body');
            text.appendChild(el('span', 'igw-pick-name', name));
            if (sub) text.appendChild(el('span', 'igw-pick-sub', sub));
            b.appendChild(mark);
            b.appendChild(text);
            b.addEventListener('click', onPick);
            return b;
        }
        function choose(choice) {
            P.choice = choice;
            P.saveAs = null;
            mount(true);
        }
        function fillPick(menu) {
            var d = drawn(), a = IG().active();
            menu.textContent = '';
            if (P.layout === 'dirty') menu.appendChild(el('p', 'dropdown-item-text igw-pick-note', t('layoutUnsaved')));
            if (d.ws) {
                menu.appendChild(pickRow(t('pageYourWs'), a.Graph ? t('pageWsSubGraph', a.Graph.name) : t('pageWsSubAuto'),
                    d.kind === 'working', 'misp-icon misp-icon-analyst-graph misp-simple', function () { choose(null); }));
            }
            menu.appendChild(pickRow(t('pageStructureName'), t('pageStructureSub'), d.kind === 'structure', 'fas fa-circle-nodes',
                function () { choose({ kind: 'structure' }); }));
            menu.appendChild(el('div', 'dropdown-divider'));
            menu.appendChild(el('h6', 'dropdown-header', t('pageGraphsHead')));
            var list = el('div');
            list.appendChild(el('p', 'dropdown-item-text igw-pick-note', t('layoutLoading')));
            menu.appendChild(list);
            IG().forTarget('Collection', uuid).then(function (out) {
                list.textContent = '';
                var graphs = (out && out.Graph) || [];
                if (!graphs.length) list.appendChild(el('p', 'dropdown-item-text igw-pick-note', t('pageGraphsNone')));
                graphs.forEach(function (g) {
                    var laysOut = d.ws && a.Graph && lower(a.Graph.uuid) === lower(g.uuid);
                    var sub = ((g.Orgc && g.Orgc.name) || '') + ' · ' + tn('layoutNodes', g.node_count || 0) + (laysOut ? ' · ' + t('pageLaysOut') : '');
                    list.appendChild(pickRow(g.name, sub, d.kind === 'graph' && lower(d.graph.uuid) === lower(g.uuid),
                        'misp-icon misp-icon-analyst-graph misp-simple', function () { choose({ kind: 'graph', graph: g }); }));
                });
            }, function () {
                list.textContent = '';
                list.appendChild(el('p', 'dropdown-item-text igw-pick-note text-danger-emphasis', t('layoutListFailed')));
            });
        }

        // What can be made of what is drawn: a graph, a new one, a copy.
        function actions(d) {
            var h = P.h;
            if (!h || d.kind === 'graph') return;
            var copies = !canEdit && !!window.IntelGraphActions && !!h.collect;
            if (canSaveGraph()) {
                var again = d.kind === 'working' && !!d.graph;
                var tone = P.layout === 'moved-ro' && !again ? 'btn-primary' : (again || copies ? 'btn-outline-secondary' : 'btn-outline-primary');
                var go = button('btn ' + tone, t(again ? 'saveAsNewGraph' : 'saveAsGraph'), openSaveAs, again ? 'fas fa-plus' : 'fas fa-floppy-disk');
                go.title = t(again ? 'saveAsNewTitle' : 'saveAsTitle');
                go.setAttribute('data-igw-save-as', '');
                stateEl.appendChild(go);
            }
            if (copies) {
                var copy = button('btn btn-outline-primary', t('copyAsMine'), function () { h.collect(); }, 'fas fa-copy');
                copy.title = t('copyTitle');
                copy.setAttribute('data-igw-copy', '');
                stateEl.appendChild(copy);
            }
        }
        function openSaveAs() {
            P.saveAs = { name: '', busy: false, error: null };
            renderState();
            var input = stateEl.querySelector('.igw-saveas input');
            if (input) input.focus();
        }
        function renderSaveAs() {
            var s = P.saveAs;
            var f = el('form', 'igw-saveas');
            f.noValidate = true;
            var input = el('input', 'form-control form-control-sm');
            input.type = 'text';
            input.maxLength = 191;
            input.autocomplete = 'off';
            input.placeholder = t('graphNamePlaceholder');
            input.setAttribute('aria-label', t('graphName'));
            input.value = s.name;
            input.disabled = s.busy;
            if (s.error) input.setAttribute('aria-invalid', 'true');
            input.addEventListener('input', function () { s.name = input.value; });
            input.addEventListener('keydown', function (e) {
                if (e.key !== 'Escape') return;
                e.preventDefault();
                e.stopPropagation();
                P.saveAs = null;
                renderState();
            });
            var go = el('button', 'btn btn-primary', s.busy ? t('creating') : t('save'));
            go.type = 'submit';
            go.disabled = s.busy;
            f.appendChild(input);
            f.appendChild(go);
            f.appendChild(button('btn btn-outline-secondary', t('cancel'), function () { P.saveAs = null; renderState(); }));
            var note = el('span', 'igw-saveas-note' + (s.error ? ' is-error' : ''), s.error || t('sharedLikeCollection'));
            if (s.error) note.setAttribute('role', 'alert');
            f.appendChild(note);
            f.addEventListener('submit', function (e) {
                e.preventDefault();
                createGraph();
            });
            stateEl.appendChild(f);
        }
        function createGraph() {
            var d = drawn(), h = P.h, s = P.saveAs;
            if (!h || !s || s.busy) return;
            var name = s.name.trim();
            if (!name) {
                s.error = t('nameNeeded');
                renderState();
                var input = stateEl.querySelector('.igw-saveas input');
                if (input) input.focus();
                return;
            }
            var c = (h.payload() || {}).Collection || {};
            s.busy = true;
            s.error = null;
            renderState();
            var working = d.kind === 'working';
            // The canvas, moves and all, becomes the graph laying the workspace out
            if (working) P.layout = 'clean';
            IG().create({
                name: name,
                target: { type: 'Collection', uuid: uuid },
                distribution: c.distribution,
                sharing_group_id: c.sharing_group_id || null,
                content: h.documentOf()
            }, { activate: working }).then(function (created) {
                P.saveAs = null;
                if (!working) choose({ kind: 'graph', graph: created });
                else renderHead();
            }, function (err) {
                if (P.saveAs !== s) return;
                s.busy = false;
                s.error = t('createFailed', (err && err.message) || '');
                renderState();
            });
        }

        function renderState() {
            headEl.classList.remove('is-dirty', 'is-conflict');
            stateEl.textContent = '';
            var h = P.h;
            if (!h) return;
            if (P.saveAs) {
                renderSaveAs();
                return;
            }
            if (P.layout === 'dirty') {
                headEl.classList.add('is-dirty');
                stateEl.appendChild(el('span', null, t('layoutDirty') + ' ' + t('layoutDirtySub')));
                stateEl.appendChild(button('btn btn-outline-secondary', t('discard'), function () { mount(true); }));
                stateEl.appendChild(button('btn btn-primary', t('saveLayout'), save, 'fas fa-floppy-disk'));
            } else if (P.layout === 'saving') {
                stateEl.appendChild(el('span', 'spinner-border spinner-border-sm'));
                stateEl.appendChild(el('span', null, t('saving')));
            } else if (P.layout === 'saved') {
                stateEl.appendChild(el('span', null, t('saved')));
            } else if (P.layout === 'conflict') {
                headEl.classList.add('is-conflict');
                stateEl.appendChild(el('span', null, t('conflict')));
                stateEl.appendChild(button('btn btn-danger', t('saveOver'), saveOver, 'fas fa-code-merge'));
                stateEl.appendChild(button('btn btn-outline-danger', t('reload'), function () { mount(true); }, 'fas fa-rotate'));
            } else if (P.layout === 'failed') {
                headEl.classList.add('is-conflict');
                stateEl.appendChild(el('span', null, t('failed', P.why)));
                stateEl.appendChild(button('btn btn-outline-secondary', t('tryAgain'), save));
            } else if (P.layout === 'moved-ro') {
                stateEl.appendChild(el('span', null, t(h.uuid() ? 'movesReadonly' : 'movesAuto')));
            }
            if (['clean', 'saved', 'moved-ro'].indexOf(P.layout) !== -1) actions(drawn());
        }
        function save() {
            var h = P.h;
            if (!h) return;
            P.layout = 'saving';
            renderState();
            h.save().then(function () {
                if (h !== P.h) return;
                P.layout = 'saved';
                renderState();
            }, function (err) {
                if (h !== P.h) return;
                if (err && err.status === 409) P.layout = 'conflict';
                else { P.layout = 'failed'; P.why = (err && err.message) || t('didNotGo'); }
                renderState();
            });
        }
        function saveOver() {
            var h = P.h;
            if (!h) return;
            P.layout = 'saving';
            renderState();
            h.rebase().then(save, function (err) {
                if (h !== P.h) return;
                P.layout = 'failed';
                P.why = (err && err.message) || t('didNotGo');
                renderState();
            });
        }
        function mount(force) {
            var d = drawn();
            var key = keyOf(d);
            if (!force && P.key === key && (P.h || P.mounting)) return;
            var mine = ++P.token;
            P.key = key;
            P.layout = 'clean';
            if (P.h) { try { P.h.destroy(); } catch (e) { /* gone */ } }
            P.h = null;
            frame.detach();
            Array.prototype.forEach.call(stage.querySelectorAll('.igw-mount'), function (m) { m.remove(); });
            var box = el('div', 'igw-mount');
            stage.insertBefore(box, wait);
            wait.hidden = false;
            wait.textContent = '';
            wait.appendChild(el('div', 'misp-loader'));
            renderHead();
            P.mounting = true;
            // A saved graph picked here is drawn as saved, without the list
            var picture = d.kind === 'graph';
            frame.none(picture);
            var options = picture ? {} : frame.mountOptions({});
            IG().mount(box, Object.assign({}, extra, picture ? {
                graph: d.graph.uuid,
                ui: { mode: 'viewer' }
            } : {
                graph: d.graph ? d.graph.uuid : null,
                source: IG().workingPath(uuid, d.graph && d.graph.uuid),
                ui: options.ui,
                badges: options.badges,
                copyOf: canEdit ? null : self
            })).then(function (h) {
                if (mine !== P.token) { try { h.destroy(); } catch (e) { /* gone */ } return null; }
                if (!picture) frame.bind(h);
                return h.ready;
            }).then(function (h) {
                if (!h || mine !== P.token) return;
                P.mounting = false;
                P.h = h;
                wait.hidden = true;
                if (picture) {
                    renderHead();
                    return;
                }
                frame.attach(h);
                h.onChange(function (handle, reason) {
                    if (handle !== P.h || ['moved', 'grouped', 'noted'].indexOf(reason) === -1) return;
                    if (!handle.uuid() || !handle.canEdit()) P.layout = 'moved-ro';
                    else if (P.layout !== 'conflict') P.layout = 'dirty';
                    renderState();
                });
                renderHead();
            }).catch(function (err) {
                if (mine !== P.token) return;
                P.mounting = false;
                wait.hidden = false;
                wait.textContent = '';
                var i = el('i', 'fas fa-triangle-exclamation text-danger');
                i.setAttribute('aria-hidden', 'true');
                wait.appendChild(i);
                wait.appendChild(el('span', null, t('drawFailed') + (err && err.status ? ' (' + err.status + ')' : '') + '.'));
                wait.appendChild(button('btn btn-sm btn-outline-secondary', t('tryAgain'), function () { mount(true); }));
            });
        }
        function tabShown() {
            var pane = document.getElementById('tab-pivot-explorer');
            return !!pane && pane.classList.contains('active');
        }
        renderHead();
        document.addEventListener('shown.bs.tab', function (e) {
            if (e.target && e.target.getAttribute && e.target.getAttribute('href') === '#tab-pivot-explorer') {
                mount(false);
                frame.layout();
            }
        });
        if (tabShown()) mount(false);
        // The workspace moved to or from this collection, or to another graph
        IG().on('active', function () {
            if (P.key === null) { renderHead(); return; }
            if (keyOf(drawn()) !== P.key && P.layout !== 'dirty') mount(true);
            else renderHead();
        });
        window.addEventListener('beforeunload', function (e) {
            if (P.layout !== 'dirty') return;
            e.preventDefault();
            e.returnValue = '';
        });
        window.IntelGraphWorkingPage = { handle: function () { return P.h; }, frame: frame, mount: mount };
    }

    window.IntelGraphWorking = {
        t: t,
        tn: tn,
        frame: function (where, opts) {
            if (frames[where]) return api(frames[where]);
            return api(buildFrame(where, opts.body, opts.stage));
        },
        get: function (where) { return frames[where] ? api(frames[where]) : null; }
    };

    if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', startPage);
    else startPage();
}());
