// IntelGraphThumbs — a graph's picture where graphs are listed: a small
// drawing in the row, and a larger preview on hovering, focusing or clicking
// it (PRD §11.10.3).
//
// A row marks where its picture goes:
//
//   <span data-intel-graph-thumb="<uuid>" data-revision="<n>"
//         data-surface="card|index|switcher" data-name="<graph name>"></span>
//
// Every such element is mounted once, when the page has it: on load, and as
// rows are drawn later (the Graphs card, the dock's switcher, an index reload).
// Its picture comes from IntelGraph.thumbnail() where the page has the client,
// from analyst_graphs/thumbnail otherwise; four requests at a time, once per
// revision, what is on screen first. IntelGraphThumb.layout() places it.
//
// The tile says data-thumb-state="loading|ready|empty|error". On the card and
// the index it is a button: hovering it opens the preview after a moment,
// focusing it opens it at once, clicking it keeps it open. In the switcher
// the row is the button: hovering the tile, focusing the row or a long press
// opens it. Escape closes it.
//
// data-surface="peek" draws nothing in place: the element itself (a link or a
// badge) is the trigger, and its graph is asked for only when the preview
// opens — for lists where most graphs are never looked at. data-note adds a
// line under the preview.

(function () {
    'use strict';

    if (window.IntelGraphThumbs) return;

    var SVGNS = 'http://www.w3.org/2000/svg';
    var SIZES = {
        card: { w: 120, h: 72 },
        index: { w: 68, h: 48 },
        // 38 + its border is the item's two text lines: the menu does not grow
        switcher: { w: 56, h: 38 }
    };
    var POP_W = 420;
    var DRAW_W = 396;
    var DRAW_H = 228;
    var GAP = 10;
    var EDGE = 8;
    var OPEN_DELAY = 350;
    var CLOSE_GRACE = 120;
    var WARM_FOR = 400;
    var LONG_PRESS = 450;
    var AT_ONCE = 4;
    // Drawn bottom to top: the hubs (events, clusters) stay visible on a crowd
    var ORDER = { Attribute: 0, Value: 1, ModuleAnswer: 1, Object: 2, GalaxyCluster: 3, Event: 4 };
    var TYPES = [
        { type: 'Event', one: 'event', many: 'events' },
        { type: 'Object', one: 'object', many: 'objects' },
        { type: 'Attribute', one: 'attribute', many: 'attributes' },
        { type: 'GalaxyCluster', one: 'cluster', many: 'clusters' },
        { type: 'Value', one: 'value', many: 'values' },
        { type: 'ModuleAnswer', one: 'module answer', many: 'module answers' }
    ];
    // Never over the row the preview belongs to
    var SIDES = {
        card: ['left', 'below', 'above'],
        switcher: ['left', 'below', 'above'],
        index: ['below', 'above'],
        peek: ['above', 'below']
    };

    /* ── loading ───────────────────────────────────────────── */
    var cache = {};
    var waiting = [];
    var running = 0;

    function source(uuid, revision) {
        if (window.IntelGraph && typeof window.IntelGraph.thumbnail === 'function') {
            return window.IntelGraph.thumbnail(uuid, revision);
        }
        var base = typeof window.baseurl === 'string' ? window.baseurl : '';
        return fetch(base + '/analyst_graphs/thumbnail/' + encodeURIComponent(uuid) + '.json', {
            credentials: 'same-origin',
            headers: { 'Accept': 'application/json', 'X-Requested-With': 'XMLHttpRequest' }
        }).then(function (r) {
            if (!r.ok) throw new Error('HTTP ' + r.status);
            return r.json();
        });
    }

    function pump() {
        while (running < AT_ONCE && waiting.length) {
            var job = waiting.shift();
            running++;
            source(job.uuid, job.revision).then(job.resolve, job.reject).then(done, done);
        }
    }

    function done() {
        running--;
        pump();
        if (!running && !waiting.length) idle(trickle);
    }

    function request(uuid, revision) {
        var key = uuid + '@' + revision;
        if (!cache[key]) {
            cache[key] = new Promise(function (resolve, reject) {
                waiting.push({ uuid: uuid, revision: revision, resolve: resolve, reject: reject });
                pump();
            });
            cache[key].catch(function () { delete cache[key]; });
        }
        return cache[key];
    }

    var idle = window.requestIdleCallback
        ? function (fn) { window.requestIdleCallback(fn, { timeout: 500 }); }
        : function (fn) { setTimeout(fn, 50); };

    // What is on screen goes first; the rest follow one at a time once the
    // queue is quiet, so a long list never asks for everything at once
    var later = [];
    function trickle() {
        if (running || waiting.length) return;
        while (later.length) {
            var tile = later.shift();
            if (!tile.started && tile.el.isConnected) {
                draw(tile);
                return;
            }
        }
    }

    /* ── drawing ───────────────────────────────────────────── */
    function svgEl(name, attrs, parent) {
        var node = document.createElementNS(SVGNS, name);
        Object.keys(attrs || {}).forEach(function (k) { node.setAttribute(k, attrs[k]); });
        if (parent) parent.appendChild(node);
        return node;
    }

    function htmlEl(tag, cls, text) {
        var node = document.createElement(tag);
        if (cls) node.className = cls;
        if (text !== undefined) node.textContent = text;
        return node;
    }

    function canvas(w, h) {
        return svgEl('svg', { width: w, height: h, viewBox: '0 0 ' + w + ' ' + h, focusable: 'false', 'aria-hidden': 'true' });
    }

    function clamp(v, lo, hi) {
        return Math.max(lo, Math.min(hi, v));
    }

    function round(v) {
        return Math.round(v * 10) / 10;
    }

    // Events and clusters are the hubs a reader finds the shape by: they stay
    // larger than the crowd, within a share of the box
    function hubRadius(r, side) {
        return clamp(r * 1.7, 2.2, side / 10);
    }

    function mark(parent, type, x, y, r, side) {
        x = round(x);
        y = round(y);
        var cls = 'igt-n igt-' + type;
        if (type === 'Event') {
            return svgEl('circle', { cx: x, cy: y, r: round(hubRadius(r, side)), class: cls }, parent);
        }
        if (type === 'Object') {
            var s = round(r * 1.75);
            return svgEl('rect', { x: round(x - s / 2), y: round(y - s / 2), width: s, height: s, class: cls }, parent);
        }
        if (type === 'ModuleAnswer') {
            var t = round(r * 1.25);
            return svgEl('path', { d: 'M' + x + ' ' + (y - t) + 'L' + (x + t) + ' ' + (y + t * 0.8) + 'L' + (x - t) + ' ' + (y + t * 0.8) + 'Z', class: cls }, parent);
        }
        if (type === 'GalaxyCluster') {
            var d = round(hubRadius(r, side) * 0.95);
            return svgEl('path', { d: 'M' + x + ' ' + (y - d) + 'L' + (x + d) + ' ' + y + 'L' + x + ' ' + (y + d) + 'L' + (x - d) + ' ' + y + 'Z', class: cls }, parent);
        }
        return svgEl('circle', { cx: x, cy: y, r: round(r), class: cls }, parent);
    }

    function drawGraph(thumb, w, h, opts) {
        var count = thumb.nodes.length;
        var side = Math.min(w, h);
        // Room per node on the drawn square; the marks shrink before they merge
        var r = clamp(0.16 * Math.sqrt(side * side / count), 0.85, Math.min(opts.maxMark, side / 18));
        var box = window.IntelGraphThumb.layout(thumb, { width: w, height: h, padding: Math.ceil(hubRadius(r, side)) + opts.padding });
        var svg = canvas(w, h);
        var busy = count > 60;
        var d = box.edges.map(function (e) {
            var a = box.nodes[e.from];
            var b = box.nodes[e.to];
            return 'M' + round(a.x) + ' ' + round(a.y) + 'L' + round(b.x) + ' ' + round(b.y);
        }).join('');
        if (d) svgEl('path', { d: d, class: 'igt-edges' + (busy ? ' igt-edges--busy' : '') }, svg);
        var g = svgEl('g', { class: 'igt-nodes' + (busy ? ' igt-nodes--busy' : '') }, svg);
        box.nodes.slice().sort(function (a, b) {
            return (ORDER[a.type] || 0) - (ORDER[b.type] || 0);
        }).forEach(function (n) {
            mark(g, n.type, n.x, n.y, r, side);
            if (opts.pins && n.pinned) {
                svgEl('circle', { cx: round(n.x), cy: round(n.y), r: round(hubRadius(r, side) + 3), class: 'igt-pin' }, svg);
            }
        });
        return { svg: svg, box: box };
    }

    // A broken link: two marks whose line did not arrive
    function drawError(w, h) {
        var svg = canvas(w, h);
        var cx = w / 2;
        var cy = h / 2;
        var half = Math.min(14, w / 4);
        var g = svgEl('g', { class: 'igt-broken' }, svg);
        svgEl('path', {
            d: 'M' + (cx - half) + ' ' + cy + 'L' + (cx - 3) + ' ' + cy + 'M' + (cx + 3) + ' ' + cy + 'L' + (cx + half) + ' ' + cy +
                'M' + (cx - 2) + ' ' + (cy + 4) + 'L' + (cx + 2) + ' ' + (cy - 4),
            class: 'igt-broken-line'
        }, g);
        svgEl('circle', { cx: cx - half, cy: cy, r: 2.6, class: 'igt-broken-node' }, g);
        svgEl('circle', { cx: cx + half, cy: cy, r: 2.6, class: 'igt-broken-node' }, g);
        return svg;
    }

    function settle(tile, state, svg) {
        tile.el.textContent = '';
        tile.el.appendChild(svg);
        tile.el.setAttribute('data-thumb-state', state);
        tile.state = state;
    }

    function draw(tile) {
        if (tile.started || tile.peek) return;
        tile.started = true;
        var size = SIZES[tile.surface];
        request(tile.uuid, tile.revision).then(function (thumb) {
            tile.thumb = thumb;
            if (!thumb || !thumb.nodes || !thumb.nodes.length) {
                settle(tile, 'empty', canvas(size.w, size.h));
                return;
            }
            settle(tile, 'ready', drawGraph(thumb, size.w, size.h, { padding: 1.5, maxMark: 2.6 }).svg);
        }, function () {
            settle(tile, 'error', drawError(size.w, size.h));
            // Asked again when its preview opens
            tile.started = false;
        }).then(function () {
            // A cached answer frees no request, so the trickle moves on here
            idle(trickle);
        });
    }

    /* ── the preview ───────────────────────────────────────── */
    var open = null;
    var lastClosed = 0;
    var timers = { open: 0, close: 0, press: 0 };
    var seq = 0;

    function plural(n, spec) {
        return n + ' ' + (n === 1 ? spec.one : spec.many);
    }

    function swatch(type) {
        var svg = svgEl('svg', { width: 12, height: 12, viewBox: '0 0 12 12', 'aria-hidden': 'true', class: 'igt-swatch' });
        mark(svg, type, 6, 6, type === 'Object' ? 3 : 3.6, 60);
        return svg;
    }

    function message(kind, line1, line2) {
        var svg = canvas(DRAW_W, DRAW_H);
        var g = svgEl('g', { class: 'igt-msg igt-msg--' + kind }, svg);
        var cx = DRAW_W / 2;
        var cy = DRAW_H / 2 - 22;
        if (kind === 'empty') {
            [[-22, 6], [0, -10], [22, 6]].forEach(function (p) {
                svgEl('circle', { cx: cx + p[0], cy: cy + p[1], r: 6, class: 'igt-msg-glyph' }, g);
            });
            svgEl('path', { d: 'M' + (cx - 22) + ' ' + (cy + 6) + 'L' + cx + ' ' + (cy - 10) + 'L' + (cx + 22) + ' ' + (cy + 6), class: 'igt-msg-glyph' }, g);
        } else if (kind === 'error') {
            svgEl('circle', { cx: cx, cy: cy, r: 14, class: 'igt-msg-glyph' }, g);
            svgEl('path', { d: 'M' + cx + ' ' + (cy - 7) + 'L' + cx + ' ' + (cy + 2), class: 'igt-msg-glyph igt-msg-bang' }, g);
            svgEl('circle', { cx: cx, cy: cy + 7, r: 1.4, class: 'igt-msg-dot' }, g);
        } else {
            [-16, 0, 16].forEach(function (dx, i) {
                svgEl('circle', { cx: cx + dx, cy: cy, r: 4.5, class: 'igt-msg-pulse', style: 'animation-delay:' + (i * 160) + 'ms' }, g);
            });
        }
        var t1 = svgEl('text', { x: cx, y: cy + 38, class: 'igt-msg-text' }, g);
        t1.textContent = line1;
        if (line2) {
            var t2 = svgEl('text', { x: cx, y: cy + 56, class: 'igt-msg-sub' }, g);
            t2.textContent = line2;
        }
        return svg;
    }

    function buildPreview(tile) {
        var pop = htmlEl('div', 'igt-pop');
        pop.id = 'igt-pop-' + (++seq);
        pop.hidden = true;
        pop.setAttribute('role', 'tooltip');
        var head = htmlEl('div', 'igt-pop-head');
        head.appendChild(htmlEl('span', 'igt-pop-name', tile.name));
        tile.countEl = htmlEl('span', 'igt-pop-count', '');
        head.appendChild(tile.countEl);
        pop.appendChild(head);
        tile.stage = htmlEl('div', 'igt-pop-stage');
        pop.appendChild(tile.stage);
        tile.legend = htmlEl('div', 'igt-pop-legend');
        pop.appendChild(tile.legend);
        if (tile.note) pop.appendChild(htmlEl('div', 'igt-pop-note', tile.note));
        tile.caret = htmlEl('span', 'igt-pop-caret');
        pop.appendChild(tile.caret);
        document.body.appendChild(pop);
        tile.pop = pop;
    }

    function stage(tile, svg, label) {
        tile.stage.textContent = '';
        svg.setAttribute('role', 'img');
        svg.removeAttribute('aria-hidden');
        svg.setAttribute('aria-label', label);
        tile.stage.appendChild(svg);
    }

    function fill(tile) {
        if (tile.filled) return Promise.resolve();
        if (tile.filling) return tile.filling;
        stage(tile, message('loading', 'Drawing the graph…'), 'Loading the preview');
        tile.countEl.textContent = '';
        tile.legend.textContent = '';
        tile.filling = request(tile.uuid, tile.revision).then(function (thumb) {
            tile.filling = null;
            tile.filled = true;
            var nodes = (thumb && thumb.nodes) || [];
            var total = typeof thumb.total === 'number' ? thumb.total : nodes.length;
            tile.legend.textContent = '';
            if (!nodes.length) {
                stage(tile, message('empty', 'No nodes yet', 'Records sent with “Add to graph” appear here.'), 'This graph has no nodes yet');
                tile.countEl.textContent = '0 nodes';
                return;
            }
            var drawn = drawGraph(thumb, DRAW_W, DRAW_H, { padding: 14, maxMark: 5.5, pins: true });
            var count = total === 1 ? '1 node' : total + ' nodes';
            tile.countEl.textContent = count + (nodes.length < total ? ' · ' + nodes.length + ' drawn' : '');
            var tally = {};
            nodes.forEach(function (n) { tally[n.type] = (tally[n.type] || 0) + 1; });
            var said = [];
            TYPES.forEach(function (spec) {
                if (!tally[spec.type]) return;
                var key = htmlEl('span', 'igt-pop-key');
                key.appendChild(swatch(spec.type));
                key.appendChild(document.createTextNode(plural(tally[spec.type], spec)));
                tile.legend.appendChild(key);
                said.push(plural(tally[spec.type], spec));
            });
            var saved = nodes.some(function (n) { return typeof n.x === 'number' && typeof n.y === 'number'; });
            var pinned = drawn.box.nodes.filter(function (n) { return n.pinned; }).length;
            var meta = htmlEl('span', 'igt-pop-meta', (pinned ? pinned + ' pinned · ' : '') + (saved ? 'saved layout' : 'automatic layout'));
            tile.legend.appendChild(meta);
            stage(tile, drawn.svg, 'Graph preview: ' + count + ', ' + said.join(', ') + '; ' + (saved ? 'saved layout' : 'automatic layout'));
        }, function () {
            tile.filling = null;
            stage(tile, message('error', 'The preview could not be loaded', 'It is tried again the next time you open it.'), 'The preview could not be loaded');
            tile.countEl.textContent = '';
            tile.legend.textContent = '';
            if (tile.state !== 'ready') draw(tile);
        });
        return tile.filling;
    }

    function topBound() {
        var nav = document.querySelector('nav.fixed-top, .navbar.fixed-top, nav.navbar');
        var b = nav ? nav.getBoundingClientRect().bottom : 0;
        return Math.max(EDGE, b + EDGE);
    }

    function place(tile, sticky) {
        var pop = tile.pop;
        var R = tile.row.getBoundingClientRect();
        var A = tile.el.getBoundingClientRect();
        var vw = document.documentElement.clientWidth;
        var vh = window.innerHeight;
        var W = Math.min(POP_W, vw - 2 * EDGE);
        pop.style.width = W + 'px';
        var H = pop.offsetHeight;
        var top = topBound();
        var ax = A.left + A.width / 2;
        var ay = A.top + A.height / 2;
        var hangX = ax - W / 2;
        var order = (SIDES[tile.surface] || SIDES.index).slice();
        // Sliding from row to row keeps the side the preview was on
        if (sticky && order.indexOf(sticky) > 0) {
            order.splice(order.indexOf(sticky), 1);
            order.unshift(sticky);
        }
        var best = null;
        order.some(function (side) {
            var x, y, room;
            if (side === 'left') {
                x = R.left - GAP - W;
                y = Math.min(Math.max(ay - H / 2, top), vh - EDGE - H);
                if (x >= EDGE) { best = { side: side, x: x, y: y }; return true; }
                room = (R.left - GAP - EDGE) / W * H;
            } else {
                x = Math.min(Math.max(hangX, EDGE), vw - EDGE - W);
                y = side === 'below' ? R.bottom + GAP : R.top - GAP - H;
                room = side === 'below' ? vh - EDGE - R.bottom - GAP : R.top - GAP - top;
                if (room >= H) { best = { side: side, x: x, y: y }; return true; }
            }
            if (!best || room > best.room) best = { side: side, x: x, y: y, room: room };
            return false;
        });
        if (best.side === 'left' && best.x < EDGE) {
            best = { side: 'below', x: Math.min(Math.max(hangX, EDGE), vw - EDGE - W), y: R.bottom + GAP };
        }
        tile.side = best.side;
        pop.style.left = Math.round(best.x) + 'px';
        pop.style.top = Math.round(best.y) + 'px';
        pop.setAttribute('data-side', best.side);
        if (best.side === 'left') {
            tile.caret.style.top = Math.round(Math.min(Math.max(ay - best.y, 18), H - 18)) + 'px';
            tile.caret.style.left = '';
        } else {
            tile.caret.style.left = Math.round(Math.min(Math.max(ax - best.x, 18), W - 18)) + 'px';
            tile.caret.style.top = '';
        }
    }

    function clearTimers() {
        clearTimeout(timers.open);
        clearTimeout(timers.close);
    }

    function describer(tile) {
        return tile.el.matches('button') ? tile.el : tile.row.matches('button, a') ? tile.row : null;
    }

    function show(tile, mode) {
        clearTimers();
        var sticky = open ? open.side : null;
        if (open && open !== tile) hide(open);
        if (!tile.pop) buildPreview(tile);
        var p = fill(tile);
        tile.mode = mode;
        if (open !== tile) {
            tile.pop.hidden = false;
            tile.pop.classList.remove('igt-pop--in');
            void tile.pop.offsetWidth;
            tile.pop.classList.add('igt-pop--in');
            open = tile;
            if (tile.el.matches('button')) tile.el.setAttribute('aria-expanded', 'true');
            var d = describer(tile);
            if (d) d.setAttribute('aria-describedby', tile.pop.id);
        }
        place(tile, sticky);
        return p.then(function () {
            // Its legend has arrived and may have made it taller
            if (open === tile) place(tile, tile.side);
            return tile.pop;
        });
    }

    function hide(tile) {
        if (!tile || !tile.pop || tile.pop.hidden) return;
        tile.pop.hidden = true;
        if (tile.el.matches('button')) tile.el.setAttribute('aria-expanded', 'false');
        var d = describer(tile);
        if (d) d.removeAttribute('aria-describedby');
        tile.mode = null;
        if (open === tile) {
            open = null;
            lastClosed = Date.now();
        }
    }

    function warm() {
        return !!open || Date.now() - lastClosed < WARM_FOR;
    }

    function onEnter(tile, e) {
        if (e.pointerType === 'touch') return;
        clearTimeout(timers.close);
        if (open === tile || tile.dismissed) return;
        if (open && open.mode === 'pinned') return;
        clearTimeout(timers.open);
        if (warm()) {
            show(tile, 'hover');
            return;
        }
        if (!tile.peek) request(tile.uuid, tile.revision);
        timers.open = setTimeout(function () { show(tile, 'hover'); }, OPEN_DELAY);
    }

    function onLeave(tile, e) {
        if (e.pointerType === 'touch') return;
        tile.dismissed = false;
        clearTimeout(timers.open);
        if (open === tile && tile.mode === 'hover') {
            timers.close = setTimeout(function () { hide(tile); }, CLOSE_GRACE);
        }
    }

    function focusable(tile) {
        return tile.el.matches('button') ? tile.el : tile.row;
    }

    function onFocusIn(tile, e) {
        if (e.target !== focusable(tile) || !e.target.matches(':focus-visible')) return;
        if (open === tile) return;
        tile.dismissed = false;
        show(tile, 'focus');
    }

    function onFocusOut(tile, e) {
        if (e.relatedTarget && tile.row.contains(e.relatedTarget)) return;
        if (open === tile && tile.mode === 'focus') hide(tile);
    }

    // In the switcher the row is the button that picks the graph: touch peeks
    // by a long press, which then does not pick
    function wireLongPress(tile) {
        var start = null;
        var swallow = false;
        tile.row.addEventListener('pointerdown', function (e) {
            if (e.pointerType !== 'touch') return;
            start = [e.clientX, e.clientY];
            clearTimeout(timers.press);
            timers.press = setTimeout(function () {
                swallow = true;
                show(tile, 'pinned');
            }, LONG_PRESS);
        });
        tile.row.addEventListener('pointermove', function (e) {
            if (!start) return;
            if (Math.abs(e.clientX - start[0]) > 8 || Math.abs(e.clientY - start[1]) > 8) {
                clearTimeout(timers.press);
                start = null;
            }
        });
        ['pointerup', 'pointercancel'].forEach(function (type) {
            tile.row.addEventListener(type, function () {
                clearTimeout(timers.press);
                start = null;
            });
        });
        tile.row.addEventListener('contextmenu', function (e) {
            if (swallow || start) e.preventDefault();
        });
        tile.row.addEventListener('click', function (e) {
            if (!swallow) return;
            swallow = false;
            e.preventDefault();
            e.stopImmediatePropagation();
        }, true);
    }

    /* ── mounting ──────────────────────────────────────────── */
    var tiles = [];
    var seen = 'IntersectionObserver' in window
        ? new IntersectionObserver(function (entries) {
            entries.forEach(function (entry) {
                if (!entry.isIntersecting) return;
                seen.unobserve(entry.target);
                var tile = byEl(entry.target);
                if (tile) draw(tile);
            });
        }, { rootMargin: '200px 0px' })
        : null;

    function byEl(node) {
        for (var i = 0; i < tiles.length; i++) {
            if (tiles[i].el === node || tiles[i].row === node) return tiles[i];
        }
        return null;
    }

    function mountPeek(holder, uuid) {
        holder.removeAttribute('data-intel-graph-thumb');
        holder.setAttribute('data-thumb-for', uuid);
        var tile = {
            el: holder, row: holder, uuid: uuid, surface: 'peek', peek: true,
            name: holder.getAttribute('data-name') || '',
            note: holder.getAttribute('data-note') || '',
            revision: holder.getAttribute('data-revision') || undefined
        };
        tiles.push(tile);
        holder.addEventListener('pointerenter', function (e) { onEnter(tile, e); });
        holder.addEventListener('pointerleave', function (e) { onLeave(tile, e); });
        holder.addEventListener('focusin', function (e) { onFocusIn(tile, e); });
        holder.addEventListener('focusout', function (e) { onFocusOut(tile, e); });
    }

    function mount(holder) {
        var surface = holder.getAttribute('data-surface');
        if (surface === 'peek') {
            var peekUuid = (holder.getAttribute('data-intel-graph-thumb') || '').toLowerCase();
            if (peekUuid) mountPeek(holder, peekUuid);
            return;
        }
        var size = SIZES[surface];
        var uuid = (holder.getAttribute('data-intel-graph-thumb') || '').toLowerCase();
        if (!size || !uuid) return;
        var row = holder.closest('[data-intel-graph-row], tr') || holder.parentElement;
        var name = holder.getAttribute('data-name') || '';
        var el;
        if (surface === 'switcher') {
            el = htmlEl('span', 'igt igt--' + surface);
            el.setAttribute('aria-hidden', 'true');
        } else {
            el = htmlEl('button', 'igt igt--' + surface);
            el.type = 'button';
            el.setAttribute('aria-label', 'Preview the graph “' + name + '”');
            el.setAttribute('aria-expanded', 'false');
        }
        el.setAttribute('data-thumb-for', uuid);
        el.setAttribute('data-thumb-state', 'loading');
        el.style.width = size.w + 'px';
        el.style.height = size.h + 'px';
        holder.replaceWith(el);
        var tile = {
            el: el, row: row, uuid: uuid, surface: surface, name: name,
            revision: holder.getAttribute('data-revision') || undefined
        };
        tiles.push(tile);
        el.addEventListener('pointerenter', function (e) { onEnter(tile, e); });
        el.addEventListener('pointerleave', function (e) { onLeave(tile, e); });
        row.addEventListener('focusin', function (e) { onFocusIn(tile, e); });
        row.addEventListener('focusout', function (e) { onFocusOut(tile, e); });
        if (surface === 'switcher') {
            wireLongPress(tile);
        } else {
            el.addEventListener('click', function (e) {
                // The index row opens the graph on click; the tile does not
                e.preventDefault();
                e.stopPropagation();
                if (open === tile && tile.mode === 'pinned') {
                    hide(tile);
                } else {
                    tile.dismissed = false;
                    show(tile, 'pinned');
                }
            });
        }
        later.push(tile);
        if (seen) seen.observe(el);
        else draw(tile);
    }

    function scan(root) {
        var scope = root || document;
        var holders = scope.querySelectorAll ? scope.querySelectorAll('[data-intel-graph-thumb]') : [];
        Array.prototype.forEach.call(holders, mount);
        if (scope.matches && scope.matches('[data-intel-graph-thumb]')) mount(scope);
        // After the observer's first pass has queued what is on screen
        setTimeout(function () { idle(trickle); }, 250);
    }

    function prune() {
        tiles = tiles.filter(function (t) {
            if (t.el.isConnected) return true;
            if (open === t) hide(t);
            if (t.pop) t.pop.remove();
            return false;
        });
    }

    function start() {
        scan(document);
        new MutationObserver(function (records) {
            var added = false;
            var removed = false;
            records.forEach(function (rec) {
                Array.prototype.forEach.call(rec.addedNodes, function (n) {
                    if (n.nodeType === 1 && (n.matches('[data-intel-graph-thumb]') || n.querySelector('[data-intel-graph-thumb]'))) added = true;
                });
                if (rec.removedNodes.length) removed = true;
            });
            if (removed) prune();
            if (added) scan(document);
        }).observe(document.body, { childList: true, subtree: true });

        // On window: Bootstrap's dropdown takes Escape on document, in capture.
        // Escape closes the preview only, and a menu under it stays open
        window.addEventListener('keydown', function (e) {
            if (e.key !== 'Escape' || !open) return;
            e.preventDefault();
            e.stopPropagation();
            open.dismissed = true;
            hide(open);
        }, true);
        document.addEventListener('pointerdown', function (e) {
            if (!open || open.mode !== 'pinned') return;
            if (open.el.contains(e.target)) return;
            if (open.surface === 'switcher' && open.row.contains(e.target)) return;
            hide(open);
        }, true);
        var queued = false;
        function follow() {
            if (queued || !open) return;
            queued = true;
            requestAnimationFrame(function () {
                queued = false;
                if (!open) return;
                var R = open.row.getBoundingClientRect();
                if (!open.el.isConnected || R.bottom < topBound() || R.top > window.innerHeight || (!R.width && !R.height)) {
                    hide(open);
                    return;
                }
                place(open, open.side);
            });
        }
        window.addEventListener('scroll', follow, true);
        window.addEventListener('resize', follow);
    }

    window.IntelGraphThumbs = {
        scan: scan,
        // The preview of a tile, open; for tests and for a page that wants to show it
        reveal: function (node) {
            var tile = byEl(node) || byEl(node.querySelector && node.querySelector('[data-thumb-for]'));
            if (!tile) return Promise.reject(new Error('No graph thumbnail there.'));
            tile.dismissed = false;
            return show(tile, 'pinned');
        },
        conceal: function () {
            if (open) hide(open);
        }
    };

    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', start);
    } else {
        start();
    }
}());
