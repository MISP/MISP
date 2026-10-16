// Value Neighbourhood — the peek in the Relationships tab's rail.
//
// A light, static picture of what opening the graph will show, read from the
// same seed: the graph itself drawn small, what is worth following (the far
// ends a reference or an analyst relationship reaches, the feeds and servers
// that know the value, the values near it), then the events it sits in, and
// everything else counted. No pivots and no interaction; its one action opens
// the full graph.
//
//   MispValueNeighbourhoodPeek(el, seed, { kit, theme, onOpen })
//
// Requires value-neighbourhood.js (the model) and misp-pivot-nodes.js.

(function () {
    'use strict';

    // The model, read when the peek is drawn: the page's loader runs its
    // scripts in whatever order they arrive.
    var V = null;
    var FAR_ROWS = 4;
    var STORY_ROWS = 3;
    var GRAPH_HEIGHT = 190;
    var GRAPH_HEIGHT_WIDE = 120;

    var KIND = {
        reference: { edge: 'reference', dash: 'solid' },
        claim:     { edge: 'analyst',   dash: 'dashed' },
        near:      { edge: 'link',      dash: 'dashed' }
    };
    function kindColour(kind) { return P().edge[kind.edge]; }

    function N() { return window.MispPivotNodes; }
    function P() { return N().palette(); }
    function H() { return N().helpers; }

    function el(tag, cls, text) {
        var e = document.createElement(tag);
        if (cls) e.className = cls;
        if (text != null) e.textContent = text;
        return e;
    }

    function fmt(n) { return Number(n || 0).toLocaleString('en'); }
    function plural(n, one, many) { return fmt(n) + ' ' + (n === 1 ? one : (many || one + 's')); }

    function svgSpan(cls, markup) {
        var s = el('span', cls);
        s.innerHTML = markup;
        return s;
    }

    /* ── the graph, small ──────────────────────────────────── */
    // The full graph's own opening — rows by event, leads free — at the small
    // node size, with nothing to click and no labels: a picture of its shape.
    // The tree stands upright, so a value in many events runs across the
    // rail rather than down it. Shown once laid out and fitted.
    function drawGraph(box, seed, kit, theme) {
        if (typeof window.Pivotick !== 'function') return;
        var data = V.byEventOrder(seed, V.graphData(seed, kit));
        if (data.nodes.length < 2) return;
        var styles = N().options({ size: 'S', theme: theme, fontUrl: kit.baseurl + '/webfonts/misp-iconify.woff2' }).nodeStyleMap;
        var layout = V.openingLayout(seed, GRAPH_HEIGHT * 4);
        layout.horizontal = false;
        // A wide tree fits the rail by width; the box then need not be tall.
        var columns = data.edges.filter(function (e) { return e.from === data.nodes[0].id; }).length;
        box.style.height = (columns > 14 ? GRAPH_HEIGHT_WIDE : GRAPH_HEIGHT) + 'px';
        // The graph is laid out out of sight, with a note in its place.
        var loading = el('div', 'vn-graph-loading');
        var loader = el('div', 'misp-loader misp-loader-sm');
        loader.setAttribute('role', 'status');
        loading.appendChild(loader);
        loading.appendChild(el('span', null, 'Drawing the graph…'));
        var canvas = el('div', 'vn-graph-canvas');
        canvas.style.visibility = 'hidden';
        box.appendChild(loading);
        box.appendChild(canvas);
        try {
            var graph = new window.Pivotick(canvas, data, {
                isDirected: true,
                render: {
                    type: 'svg',
                    nodeTypeAccessor: function (n) { return (n.getData() || {}).type; },
                    nodeStyleMap: styles,
                    defaultNodeStyle: { text: '' },
                    defaultEdgeStyle: { animateDash: false, markerEnd: 'none' },
                    edgeTypeAccessor: function (e) { var d = e.getData ? e.getData() : null; return d ? d.kind : undefined; },
                    edgeStyleMap: {
                        'object-reference':     { strokeColor: kindColour(KIND.reference) },
                        'analyst-relationship': { strokeColor: kindColour(KIND.claim), dashed: true },
                        'feed-correlation':     { strokeColor: P().feed.core, dashed: true },
                        'server-correlation':   { strokeColor: P().server.core, dashed: true },
                        near:                   { strokeColor: kindColour(KIND.near), dashed: true },
                        'in-event':             { strokeColor: P().edge.link, strokeWidth: 1 },
                        occurrence:             { strokeColor: P().edge.link, strokeWidth: 1 }
                    },
                    defaultLabelStyle: { labelAccessor: function () { return ''; } },
                    enableNodeExpansion: false,
                    interactionEnabled: false,
                    dragEnabled: false,
                    zoomEnabled: false,
                    minLabelFontSize: 1000,
                    maxZoom: 1
                },
                layout: layout,
                simulation: { cooldownTime: 600 },
                UI: {
                    mode: 'viewer',
                    theme: theme,
                    navigation: { enabled: false },
                    tooltip: { enabled: false },
                    contextMenu: { enabled: false },
                    simplify: { rules: [V.byEventRule()] }
                }
            });
            graph.on('ready', function () {
                loading.remove();
                canvas.style.visibility = '';
            });
        } catch (e) {
            console.error('[value-neighbourhood] peek graph failed:', e);
            box.remove();
        }
    }

    /* ── marks, in the canvas's small vocabulary ───────────── */
    function nested(inner, x, size) {
        return inner.replace('<svg ', '<svg x="' + x + '" y="' + x + '" width="' + size + '" height="' + size + '" ');
    }

    function mark(entity, d) {
        var p = P();
        if (entity === 'object') {
            return H().svg(32, 32, '<rect x="1.25" y="1.25" width="29.5" height="29.5" rx="8" fill="' + p.object.wash +
                '" stroke="' + p.object.core + '" stroke-width="1.5"/>' +
                nested(N().markup('object', 'S', { name: d.name }), 4.8, 22.4));
        }
        if (entity === 'attribute') {
            return H().svg(32, 32, '<circle cx="16" cy="16" r="15.25" fill="' +
                (d.to_ids ? p.attribute.core : p.attribute.wash) + '" stroke="' + p.attribute.core +
                '" stroke-width="1.5"/>' +
                nested(N().markup('attribute', 'S', { type: d.name, to_ids: d.to_ids }), 4.8, 22.4));
        }
        return N().markup(entity, 'S', d || {});
    }

    function endMark(end) {
        if (end.type === 'object') return mark('object', { name: end.name });
        if (end.type === 'attribute') return mark('attribute', { name: end.name, to_ids: end.to_ids });
        if (end.type === 'cluster') return mark('cluster', { galaxy_type: end.galaxy_type, value: end.label });
        return mark('event', { _provenance: 'local', uuid: 'event' });
    }

    /* ── rows ──────────────────────────────────────────────── */
    // One line: parts side by side, the growing one taking the ellipsis, so
    // nothing is wider than the column.
    function line(cls, parts) {
        var l = el('span', cls);
        parts.filter(function (x) { return x && x.text; }).forEach(function (x) {
            var s = el('span', (x.grow ? 'vn-ell' : 'vn-fix') + (x.cls ? ' ' + x.cls : ''), x.text);
            if (x.color) s.style.color = x.color;
            if (x.title) s.title = x.title;
            l.appendChild(s);
        });
        return l;
    }

    function row(tree, kind, markup, l1, l2, count, cls) {
        var r = el('div', 'vn-row' + (cls ? ' ' + cls : ''));
        var br = el('span', 'vn-branch');
        if (kind) {
            br.style.borderTopColor = kindColour(kind);
            br.style.borderTopStyle = kind.dash;
        }
        r.appendChild(br);
        var m = svgSpan('vn-mark', markup || '');
        r.appendChild(m);
        var t = el('span', 'vn-text');
        t.appendChild(line('vn-l1', l1));
        if (l2) t.appendChild(l2.nodeType ? l2 : line('vn-l2', l2));
        r.appendChild(t);
        if (count) r.appendChild(el('span', 'vn-count', count));
        tree.appendChild(r);
        return r;
    }

    function caption(tree, text, sub) {
        var r = el('div', 'vn-row vn-caption');
        r.appendChild(el('span', 'vn-cap', text));
        if (sub) r.appendChild(el('span', 'vn-cap-sub', sub));
        tree.appendChild(r);
    }

    function short(s, n) {
        s = String(s || '');
        return s.length > n ? s.slice(0, n - 1) + '…' : s;
    }

    // How the far end links to the occurrences: its first relationship, the way
    // it runs ("← connect": it points at the occurrence), then how many others.
    function viaParts(end) {
        var seen = {}, list = [];
        end.via.forEach(function (v) {
            var k = v.kind + v.rel + v.dir;
            if (!seen[k]) { seen[k] = true; list.push(v); }
        });
        list.sort(function (a, b) { return a.kind === b.kind ? 0 : (a.kind === 'reference' ? -1 : 1); });
        var v = list[0];
        var parts = [{ text: v.dir === 'in' ? '← ' + short(v.rel, 18) : short(v.rel, 18) + ' →',
                       cls: 'vn-rel', color: kindColour(KIND[v.kind]) }];
        if (list.length > 1) parts.push({ text: '+' + (list.length - 1), cls: 'vn-plus' });
        return parts;
    }

    function endParts(end) {
        if (end.type === 'object') {
            return [{ text: end.name, cls: 'vn-kicker' },
                    end.label ? { text: end.label, cls: 'vn-mono', grow: true, title: end.label } : null];
        }
        if (end.type === 'attribute') return [{ text: end.label, cls: 'vn-mono', grow: true, title: end.label }];
        if (end.type === 'cluster') {
            return [{ text: end.name, cls: 'vn-kicker' }, { text: end.label, grow: true, title: end.label }];
        }
        return [{ text: end.label || 'event', grow: true }];
    }

    function eventInfo(seed, end) {
        if (end.event) return end.event.info;
        var c = (seed.events || {})[end.event_id];
        return c ? c.info : '';
    }

    /* ── the head ──────────────────────────────────────────── */
    function yearSpan(years) {
        var ks = Object.keys(years || {}).sort();
        if (!ks.length) return '';
        return ks[0] === ks[ks.length - 1] ? ks[0] : ks[0] + '–' + ks[ks.length - 1];
    }

    function orgLine(orgs) {
        orgs = orgs || [];
        if (!orgs.length) return '';
        var total = orgs.reduce(function (s, o) { return s + o.count; }, 0);
        var top = orgs.slice().sort(function (a, b) { return b.count - a.count; })[0];
        if (orgs.length === 1) return 'all ' + top.name;
        var share = Math.floor(top.count / total * 1000) / 10;
        return share >= 60 ? share + '% ' + top.name : plural(orgs.length, 'org');
    }

    // The value's warninglist hits, off the attributes that hold it.
    function warningsOf(seed) {
        var lists = {};
        function take(a) {
            (a.warnings || []).forEach(function (w) {
                var k = w.warninglist_name || String(w.warninglist_id);
                lists[k] = lists[k] || { name: k, fp: w.warninglist_category === 'false_positive' };
            });
        }
        (seed.Attribute || []).forEach(take);
        (seed.Object || []).forEach(function (o) {
            var held = {};
            (o.holds || []).forEach(function (u) { held[u] = true; });
            (o.Attribute || []).forEach(function (a) { if (held[a.uuid]) take(a); });
        });
        return Object.keys(lists).map(function (k) { return lists[k]; });
    }

    function head(root, seed) {
        var v = seed.value || {}, meta = seed.meta || {}, occ = meta.occurrences || {}, facets = meta.facets || {};
        var h = el('div', 'vn-head');
        h.appendChild(svgSpan('vn-vnode', N().markup('value', 'S', { centre: true, types: v.types, value: v.value })));
        var t = el('div', 'vn-htext');
        t.appendChild(el('div', 'vn-value', v.value));
        var sub = el('div', 'vn-sub');
        [plural(occ.units || 0, 'occurrence'), orgLine(facets.org), yearSpan(facets.year)].filter(Boolean)
            .forEach(function (x, i) {
                if (i) sub.appendChild(document.createTextNode(' · '));
                sub.appendChild(el('span', 'vn-nw', x));
            });
        t.appendChild(sub);
        var warnings = warningsOf(seed);
        if (warnings.length) {
            var w = warnings[0];
            var wl = el('div', 'vn-warnline');
            wl.appendChild(svgSpan('vn-tri', H().svg(24, 24, H().use('warning-triangle', { x: 0, y: 0, size: 24,
                color: w.fp ? P().warn.fp : P().warn.known }))));
            wl.appendChild(el('span', 'vn-ell', w.name));
            wl.appendChild(el('span', 'vn-fix vn-wcat', (w.fp ? 'false positive' : 'known') +
                (warnings.length > 1 ? ' · +' + (warnings.length - 1) : '')));
            t.appendChild(wl);
        }
        h.appendChild(t);
        root.appendChild(h);
    }

    /* ── worth following ───────────────────────────────────── */
    function sourcesOf(seed, kit) {
        return kit.sources.map(function (s) {
            var known = kit.sourceMap(seed, s.scope);
            var list = Object.keys(known).map(function (id) { return known[id]; });
            var evs = {};
            list.forEach(function (src) { (src.event_uuids || []).forEach(function (u) { evs[u] = true; }); });
            return { type: s.type, list: list, events: Object.keys(evs).length };
        }).filter(function (s) { return s.list.length; });
    }

    function following(tree, seed, kit, model) {
        var sources = sourcesOf(seed, kit), near = seed.near || [];
        if (!model.ends.length && !sources.length && !near.length) return;
        caption(tree, 'Worth following', model.leadUnits.length
            ? 'from ' + plural(model.leadUnits.length, 'occurrence') : 'on the value itself');

        model.ends.slice(0, FAR_ROWS).forEach(function (end) {
            var via = end.via.some(function (x) { return x.kind === 'reference'; }) ? KIND.reference : KIND.claim;
            var where = end.occurrence ? 'another occurrence of it' : eventInfo(seed, end);
            var l2 = viaParts(end);
            if (where) l2.push({ text: '·', cls: 'vn-sep' }, { text: where, grow: true, title: where });
            row(tree, via, endMark(end), endParts(end), l2, end.count > 1 ? end.count + ' occ.' : '');
        });
        var hidden = model.ends.slice(FAR_ROWS);
        if (hidden.length) {
            row(tree, null, '', [{ text: '+' + plural(hidden.length, 'more far end'), grow: true }],
                [{ text: 'in the full graph', grow: true }], '', 'vn-more');
        }

        sources.forEach(function (s) {
            var names = s.list.map(function (x) { return x.name || s.type + ' ' + x.id; }).join(', ');
            row(tree, { color: P()[s.type].core, dash: 'dotted' }, mark(s.type, {}),
                [{ text: names, grow: true, title: names }],
                [{ text: plural(s.list.length, s.type) + (s.events ? ' · ' + plural(s.events, 'event') : ''), grow: true }], '');
        });

        if (near.length) {
            var first = near[0];
            var byEngine = {};
            near.forEach(function (n) { byEngine[n.engine] = (byEngine[n.engine] || 0) + 1; });
            var rest = near.length > 1 ? ' · ' + Object.keys(byEngine).map(function (k) {
                return byEngine[k] + ' ' + (k === 'cidr' ? 'CIDR blocks' : k);
            }).join(', ') : '';
            row(tree, KIND.near, N().markup('value', 'S', { value: first.value, types: [] }),
                [{ text: first.value, cls: 'vn-mono', grow: true },
                 near.length > 1 ? { text: '+' + (near.length - 1), cls: 'vn-plus' } : null],
                [{ text: V.nearLabel(first) + rest, grow: true }], '');
        }
    }

    /* ── the events ────────────────────────────────────────── */
    function storyRow(list, st) {
        var c = st.card || {};
        var r = el('li', 'vn-story');
        var m = el('span', 'vn-story-mark');
        m.appendChild(el('span', 'vn-story-count', st.count > 1 ? fmt(st.count) : ''));
        r.appendChild(m);
        var body = el('div', 'vn-story-body');
        var top = el('div', 'vn-story-head');
        var title = el('span', 'vn-story-title', c.info || ('Event ' + st.id));
        title.title = c.info || '';
        top.appendChild(title);
        var marks = el('span', 'vn-story-marks');
        if (st.claims) {
            var claim = el('span', 'vn-story-lead vn-claim');
            claim.title = plural(st.claims, 'analyst relationship');
            claim.appendChild(el('i', 'fas fa-comment-dots'));
            claim.appendChild(el('span', null, String(st.claims)));
            marks.appendChild(claim);
        }
        if (st.feeds.length) {
            var feed = el('span', 'vn-story-lead vn-feed');
            feed.title = 'Also in ' + st.feeds.join(', ');
            feed.appendChild(el('i', 'fas fa-rss'));
            marks.appendChild(feed);
        }
        if (st.servers.length) {
            var server = el('span', 'vn-story-lead vn-server');
            server.title = 'Also on ' + st.servers.join(', ');
            server.appendChild(el('i', 'fas fa-server'));
            marks.appendChild(server);
        }
        if (marks.childNodes.length) top.appendChild(marks);
        body.appendChild(top);

        var roles = el('div', 'vn-roles');
        roles.appendChild(el('span', 'vn-date', c.date || ''));
        if (c.Orgc && c.Orgc.name) roles.appendChild(el('span', 'vn-org', c.Orgc.name));
        st.roleOrder.slice(0, 2).forEach(function (k) {
            var role = st.roles[k];
            var chip = el('span', 'vn-role');
            chip.appendChild(el('span', 'vn-role-rel', role.label.rel || '—'));
            if (role.label.holder) chip.appendChild(el('span', 'vn-role-in', 'in ' + role.label.holder));
            if (role.n > 1) chip.appendChild(el('span', 'vn-role-n', '×' + fmt(role.n)));
            roles.appendChild(chip);
        });
        if (st.roleOrder.length > 2) roles.appendChild(el('span', 'vn-role-more', '+' + (st.roleOrder.length - 2)));
        body.appendChild(roles);

        var clusters = [];
        var firstCluster = null;
        (c.Galaxy || []).forEach(function (g) {
            (g.GalaxyCluster || []).forEach(function (cl) {
                if (!firstCluster) firstCluster = { id: cl.id, value: cl.value, galaxy: g.name };
                clusters.push(cl.value);
            });
        });
        var context = st.notes.length ? st.notes : clusters;
        if (context.length) {
            var more = context.length > 1 ? ' · +' + (context.length - 1) : '';
            var ctx;
            if (!st.notes.length && window.TagChips) {
                ctx = el('div', 'vn-context');
                ctx.innerHTML = window.TagChips.cluster(firstCluster, { display: 'leaf' });
                if (more) ctx.appendChild(document.createTextNode(more));
            } else {
                ctx = el('div', 'vn-context', context[0] + more);
            }
            ctx.title = context.join('\n');
            body.appendChild(ctx);
        }
        r.appendChild(body);
        list.appendChild(r);
    }

    // What the seed leaves out, by template, from the facets less what it drew.
    function undrawnByTemplate(seed) {
        var facets = ((seed.meta || {}).facets || {}).template || {};
        var drawn = {};
        (seed.Object || []).forEach(function (o) { drawn[o.name] = (drawn[o.name] || 0) + 1; });
        drawn[''] = (seed.Attribute || []).length;
        return Object.keys(facets).map(function (k) {
            return { name: k === '' ? 'not in an object' : k, n: facets[k] - (drawn[k] || 0) };
        }).filter(function (r) { return r.n > 0; }).sort(function (a, b) { return b.n - a.n; });
    }

    function events(root, seed) {
        var list = V.stories(seed);
        if (!list.length) return;
        var box = el('div', 'vn-events');
        var cap = el('div', 'vn-row vn-caption vn-events-caption');
        cap.appendChild(el('span', 'vn-cap', 'In these events'));
        box.appendChild(cap);
        var ol = el('ol', 'vn-stories');
        list.slice(0, STORY_ROWS).forEach(function (st) { storyRow(ol, st); });
        box.appendChild(ol);

        var rest = el('div', 'vn-rest');
        var more = list.slice(STORY_ROWS);
        if (more.length) {
            var occ = more.reduce(function (s, st) { return s + st.count; }, 0);
            rest.appendChild(el('div', 'vn-rest-line', '+ ' + plural(more.length, 'more event') +
                ' holding it ' + plural(occ, 'time')));
        }
        var m = (seed.meta || {}).occurrences || {};
        var undrawn = (m.units || 0) - (m.seeded || 0);
        if (undrawn > 0) {
            var parts = undrawnByTemplate(seed);
            var names = parts.slice(0, 2).map(function (x) { return fmt(x.n) + ' ' + x.name; });
            var other = parts.slice(2).reduce(function (s, x) { return s + x.n; }, 0);
            if (other) names.push(fmt(other) + ' other');
            rest.appendChild(el('div', 'vn-rest-line', '+ ' + fmt(undrawn) + ' more not drawn yet: ' + names.join(', ')));
        }
        if (rest.childNodes.length) box.appendChild(rest);
        root.appendChild(box);
    }

    function peek(el0, seed, opts) {
        V = window.MispValueNeighbourhood;
        var kit = opts.kit;
        // Declares the icon font the node drawings are set in.
        N().options({ size: 'S', theme: opts.theme, fontUrl: kit.baseurl + '/webfonts/misp-iconify.woff2' });
        var root = el('div', 'vn-peek');
        el0.appendChild(root);
        var graph = el('div', 'vn-graph');
        root.appendChild(graph);
        head(root, seed);
        var model = V.leads(seed, kit);
        var tree = el('div', 'vn-tree');
        following(tree, seed, kit, model);
        if (tree.childNodes.length) root.appendChild(tree);
        events(root, seed);

        var btn = el('button', 'btn btn-sm btn-outline-secondary vn-open');
        btn.type = 'button';
        btn.appendChild(el('i', 'fas fa-maximize me-1'));
        btn.appendChild(document.createTextNode('Open the full graph'));
        btn.addEventListener('click', opts.onOpen);
        root.appendChild(btn);

        drawGraph(graph, seed, kit, opts.theme);
        return N().ready ? N().ready() : undefined;
    }

    window.MispValueNeighbourhoodPeek = peek;
}());
