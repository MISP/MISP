// The workspace dock: the active workspace, over whatever page the analyst is
// on (phase 6's pick, mockups/dock.html in the PRD). Docked, it is a drawer
// against the right edge, full height under the navbar, as wide as the
// analyst drags it; it covers the page's right edge and never reflows the
// page. Undocked, it is a window moved by its head and resized from its
// edges, kept as the corner it is nearest to so it stays put when the browser
// window changes size. Closing is the only way out of the way.
//
// Opened by the navbar slot (IntelGraph.registerDock). It mounts the graph in
// Pivotick's viewer mode on first open only, keeps the adds made on the page
// underneath as they land, and saves layout only when asked. Open or closed,
// docked or floating, the drawer's width and the window's rectangle are
// remembered per viewer in localStorage, as is a short log of arrivals.
//
// Markup: Elements/intel_graph_dock.ctp. Needs intel-graph.js.
(function () {
    'use strict';

    var KEY = 'misp.intelGraph.dock';
    var LOG_KEY = 'misp.intelGraph.dock.arrivals';
    var LOG_MAX = 12;
    var MIN_W = 360;
    var PAGE_MIN = 480;
    var STEP = 24;

    var panel = document.getElementById('ig-so');
    var html = document.documentElement;
    var find = function (sel) { return panel.querySelector(sel); };
    var grip = find('[data-ig-grip]');
    var switchBtn = find('[data-ig-switch]');
    var menu = find('[data-ig-menu]');
    var nameEl = find('[data-ig-name]');
    var widenBtn = find('[data-ig-widen]');
    var undockBtn = find('[data-ig-undock]');
    var dockBtn = find('[data-ig-dock]');
    var moveHandle = find('[data-ig-move]');
    var head = find('.ig-so-head');
    var edges = Array.prototype.slice.call(panel.querySelectorAll('[data-ig-edge]'));
    var seEdge = find('[data-ig-edge="se"]');
    var fullLink = find('[data-ig-full]');
    var metaEl = find('[data-ig-meta]');
    var bannerEl = find('[data-ig-banner]');
    var stage = find('[data-ig-stage]');
    var canvas = find('[data-ig-canvas]');
    var calloutsEl = find('[data-ig-callouts]');
    var loadingEl = find('[data-ig-loading]');
    var noneEl = find('[data-ig-none]');
    var trayEl = find('[data-ig-tray]');
    var trayToggle = find('[data-ig-tray-toggle]');
    var trayList = find('[data-ig-tray-list]');
    var trayNew = find('[data-ig-tray-new]');
    var trayClear = find('[data-ig-tray-clear]');
    var footEl = find('[data-ig-foot]');
    var sayEl = find('[data-ig-say]');

    function IG() { return window.IntelGraph; }
    function baseurl() { return (window.IntelGraphConfig && window.IntelGraphConfig.baseurl) || ''; }
    function pageRecord() { return IG().page(); }
    function pageShowsActive() {
        var shown = window.IntelGraphConfig && window.IntelGraphConfig.shown;
        var a = IG().active();
        return !!shown && !!a && lower(a.uuid) === lower(shown);
    }
    function lower(s) { return String(s || '').toLowerCase(); }

    function el(tag, cls, text) {
        var e = document.createElement(tag);
        if (cls) e.className = cls;
        if (text != null) e.textContent = text;
        return e;
    }
    function icon(cls) {
        var i = el('i', cls);
        i.setAttribute('aria-hidden', 'true');
        return i;
    }
    function button(cls, label, onClick, iconCls) {
        var b = el('button', cls);
        b.type = 'button';
        if (iconCls) { b.appendChild(icon(iconCls)); b.appendChild(document.createTextNode(' ')); }
        b.appendChild(document.createTextNode(label));
        b.addEventListener('click', onClick);
        return b;
    }

    /* ── what is remembered, per viewer ───────────────────── */
    function read(key, fallback) {
        try {
            var raw = window.localStorage.getItem(key);
            var v = raw ? JSON.parse(raw) : null;
            return v && typeof v === 'object' ? v : fallback;
        } catch (e) { return fallback; }
    }
    function write(key, value) {
        try { window.localStorage.setItem(key, JSON.stringify(value)); } catch (e) { /* kept for this page only */ }
    }
    var prefs = Object.assign({ open: false, width: 0, wide: false, tray: true, mode: 'docked', win: null, scope: 'org' }, read(KEY, {}));
    if (prefs.mode !== 'floating') prefs.mode = 'docked';
    if (prefs.scope !== 'mine') prefs.scope = 'org';
    if (!validWin(prefs.win)) prefs.win = null;
    function validWin(w) {
        return !!w && /^[tb][lr]$/.test(w.corner) && ['dx', 'dy', 'w', 'h'].every(function (k) {
            return typeof w[k] === 'number' && isFinite(w[k]) && w[k] >= 0;
        });
    }
    function remember() {
        write(KEY, { open: prefs.open, width: prefs.width, wide: prefs.wide, tray: prefs.tray, mode: prefs.mode, win: prefs.win, scope: prefs.scope });
    }

    // Recent arrivals, per graph: what the analyst sent while browsing,
    // kept across page loads. Undo is a function and stays with the page
    // the add was made on.
    var LOG_DAYS = 7;
    var log = read(LOG_KEY, {});
    Object.keys(log).forEach(function (uuid) {
        var keep = Array.isArray(log[uuid]) ? log[uuid].filter(function (e) {
            return e && typeof e.at === 'number' && Date.now() - e.at < LOG_DAYS * 864e5 && e.labels;
        }) : [];
        if (keep.length) log[uuid] = keep; else delete log[uuid];
    });
    var undos = {};
    var seq = Date.now();
    function saveLog() {
        var out = {};
        Object.keys(log).forEach(function (uuid) {
            out[uuid] = log[uuid].slice(0, LOG_MAX).map(function (e) {
                return { id: e.id, kind: e.kind, keys: e.keys, present: e.present, labels: e.labels,
                         count: e.count, refused: e.refused, message: e.message, at: e.at };
            });
        });
        write(LOG_KEY, out);
    }
    function entriesOf(uuid) { return (uuid && log[lower(uuid)]) || []; }
    function push(uuid, entry) {
        log[lower(uuid)] = [entry].concat(entriesOf(uuid)).slice(0, LOG_MAX);
        saveLog();
    }

    /* ── width, and where the page goes ───────────────────── */
    function viewport() { return document.documentElement.clientWidth || window.innerWidth; }
    function defaultWidth(vw) { return Math.round(Math.min(560, Math.max(380, vw * 0.3))); }
    // Docked, the drawer lies over the page; at its widest it leaves the
    // page PAGE_MIN uncovered.
    function bounds() {
        var vw = viewport();
        var max = Math.max(Math.min(MIN_W, vw - 16), vw - PAGE_MIN);
        return { vw: vw, min: Math.min(MIN_W, max), max: max };
    }
    function width() {
        var b = bounds();
        var want = prefs.wide ? b.max : (prefs.width || defaultWidth(b.vw));
        return Math.round(Math.min(b.max, Math.max(b.min, want)));
    }
    var navTop = 58;
    function measureNav() {
        var nav = document.querySelector('header .navbar.fixed-top, .navbar.fixed-top, .rail-nav');
        if (!nav || nav.querySelector('.navbar-collapse.show, .navbar-collapse.collapsing')) return navTop;
        navTop = Math.max(0, Math.round(nav.getBoundingClientRect().bottom));
        return navTop;
    }
    /* ── undocked: one rectangle ──────────────────────────── */
    // Kept as the corner it is nearest to and its distance from that corner,
    // so a window parked bottom-right stays bottom-right when the browser
    // window changes size. Always inside the viewport, under the navbar.
    var GUTTER = 12, MIN_FW = 360, MIN_FH = 300, SNAP = 16;
    var drag = null;  // the rectangle while it is being moved or resized
    function floating() { return prefs.mode === 'floating'; }
    function room() {
        var top = measureNav();
        return { left: GUTTER, top: top + GUTTER, right: viewport() - GUTTER, bottom: window.innerHeight - GUTTER };
    }
    function defaultWin() {
        var r = room();
        return { corner: 'br', dx: 0, dy: 0, w: Math.min(Math.max(width(), 520), r.right - r.left),
                 h: Math.min(Math.round((r.bottom - r.top) * 0.72), 640) };
    }
    function winRect() {
        var r = room(), win = prefs.win || defaultWin();
        var w = Math.round(Math.min(Math.max(win.w, MIN_FW), r.right - r.left));
        var h = Math.round(Math.min(Math.max(win.h, MIN_FH), r.bottom - r.top));
        var left = win.corner.charAt(1) === 'r' ? r.right - win.dx - w : r.left + win.dx;
        var top = win.corner.charAt(0) === 'b' ? r.bottom - win.dy - h : r.top + win.dy;
        return { left: Math.round(Math.min(Math.max(left, r.left), r.right - w)),
                 top: Math.round(Math.min(Math.max(top, r.top), r.bottom - h)), w: w, h: h };
    }
    // The corner a rectangle is nearest to; within SNAP of an edge it sits on it.
    function anchor(rect) {
        var r = room();
        var right = rect.left + rect.w / 2 > (r.left + r.right) / 2;
        var bottom = rect.top + rect.h / 2 > (r.top + r.bottom) / 2;
        var dx = right ? r.right - rect.left - rect.w : rect.left - r.left;
        var dy = bottom ? r.bottom - rect.top - rect.h : rect.top - r.top;
        return { corner: (bottom ? 'b' : 't') + (right ? 'r' : 'l'),
                 dx: dx < SNAP ? 0 : Math.round(dx), dy: dy < SNAP ? 0 : Math.round(dy),
                 w: Math.round(rect.w), h: Math.round(rect.h) };
    }
    function clampMove(start, ex, ey) {
        var r = room();
        return { w: start.w, h: start.h,
                 left: Math.min(Math.max(start.left + ex, r.left), r.right - start.w),
                 top: Math.min(Math.max(start.top + ey, r.top), r.bottom - start.h) };
    }
    function clampResize(start, edge, ex, ey) {
        var r = room();
        var left = start.left, top = start.top, right = start.left + start.w, bottom = start.top + start.h;
        if (edge.indexOf('w') !== -1) left = Math.min(Math.max(left + ex, r.left), right - MIN_FW);
        if (edge.indexOf('e') !== -1) right = Math.max(Math.min(right + ex, r.right), left + MIN_FW);
        if (edge.indexOf('n') !== -1) top = Math.min(Math.max(top + ey, r.top), bottom - MIN_FH);
        if (edge.indexOf('s') !== -1) bottom = Math.max(Math.min(bottom + ey, r.bottom), top + MIN_FH);
        return { left: left, top: top, w: right - left, h: bottom - top };
    }

    function place() {
        var b = bounds(), w = width(), float = floating();
        html.style.setProperty('--ig-so-w', w + 'px');
        html.style.setProperty('--ig-so-top', measureNav() + 'px');
        panel.classList.toggle('is-floating', float);
        html.classList.toggle('ig-so-docked', opened && !float);
        if (float) {
            var rect = drag || winRect();
            panel.style.setProperty('--ig-fw-left', rect.left + 'px');
            panel.style.setProperty('--ig-fw-top', rect.top + 'px');
            panel.style.setProperty('--ig-fw-w', rect.w + 'px');
            panel.style.setProperty('--ig-fw-h', rect.h + 'px');
        }
        grip.hidden = float;
        widenBtn.hidden = float;
        undockBtn.hidden = float;
        dockBtn.hidden = !float;
        moveHandle.hidden = !float;
        edges.forEach(function (e) { e.hidden = !float; });
        grip.setAttribute('aria-valuemin', String(b.min));
        grip.setAttribute('aria-valuemax', String(b.max));
        grip.setAttribute('aria-valuenow', String(w));
        grip.setAttribute('aria-valuetext', w + ' pixels; ' + Math.max(0, b.vw - w) + ' pixels of the page left uncovered');
        widenBtn.setAttribute('aria-pressed', prefs.wide ? 'true' : 'false');
        widenBtn.title = prefs.wide ? 'Back to your width' : 'Widen the panel';
        widenBtn.setAttribute('aria-label', widenBtn.title);
    }
    var placing = 0;
    function placeSoon() {
        if (placing) return;
        placing = window.requestAnimationFrame(function () { placing = 0; place(); });
    }

    /* ── the slot ──────────────────────────────────────────── */
    var unseen = { added: 0, refused: false };
    function slotButtons() { return document.querySelectorAll('[data-intel-graph-toggle]'); }
    function decorateSlot() {
        slotButtons().forEach(function (b) {
            b.setAttribute('aria-controls', 'ig-so');
            if (!b.querySelector('.ig-slot-new')) {
                var n = el('span', 'ig-slot-new');
                n.hidden = true;
                n.setAttribute('data-ig-unseen', '');
                b.appendChild(n);
                var side = icon('fas fa-angles-left ig-slot-side');
                b.appendChild(side);
            }
        });
        syncSlot();
    }
    function syncSlot() {
        slotButtons().forEach(function (b) {
            b.setAttribute('aria-expanded', opened ? 'true' : 'false');
            var side = b.querySelector('.ig-slot-side');
            if (side) side.className = 'fas ' + (floating() ? 'fa-window-restore' : 'fa-angles-left') + ' ig-slot-side';
            var n = b.querySelector('[data-ig-unseen]');
            if (!n) return;
            var show = !opened && (unseen.added > 0 || unseen.refused);
            n.hidden = !show;
            n.classList.toggle('is-refused', unseen.refused && !unseen.added);
            n.textContent = unseen.added ? '+' + unseen.added : '!';
            var count = unseen.added ? unseen.added + ' added since you closed the panel' : 'an add was refused';
            n.title = show ? count : '';
        });
    }
    function pulseSlot() {
        slotButtons().forEach(function (b) {
            var li = b.closest('[data-intel-graph-slot]') || b;
            li.classList.remove('ig-slot-pulse');
            void li.offsetWidth;
            li.classList.add('ig-slot-pulse');
        });
    }

    // An add on its way from where it was made to where it went: the
    // navbar slot, or the open panel. Resolves on arrival.
    function flightTarget() {
        var box = null;
        if (opened) {
            box = (stage.offsetParent ? stage : panel).getBoundingClientRect();
        } else {
            Array.prototype.some.call(slotButtons(), function (b) {
                var r = (b.firstElementChild || b).getBoundingClientRect();
                if (!r.width || r.bottom < 0 || r.top > window.innerHeight) return false;
                box = r;
                return true;
            });
        }
        return box && box.width ? { x: box.left + box.width / 2, y: box.top + box.height / 2 } : null;
    }
    function fly(from) {
        var to = from && !reducedMotion() && flightTarget();
        var dx = to ? to.x - from.x : 0, dy = to ? to.y - from.y : 0;
        var dist = Math.sqrt(dx * dx + dy * dy);
        if (!to || dist < 32 || !panel.animate) return Promise.resolve();
        var token = el('span', 'ig-flight');
        token.appendChild(icon('misp-icon misp-icon-analyst-graph misp-simple'));
        token.style.left = from.x + 'px';
        token.style.top = from.y + 'px';
        document.body.appendChild(token);
        // A quadratic arc bowed upwards, kept below the top of the window.
        var cx = from.x + dx * 0.3;
        var cy = Math.max(12, Math.min(from.y, to.y) - Math.min(60, dist * 0.15));
        var frames = [];
        for (var i = 0; i <= 16; i++) {
            var t = i / 16, u = 1 - t;
            var x = u * u * from.x + 2 * u * t * cx + t * t * to.x;
            var y = u * u * from.y + 2 * u * t * cy + t * t * to.y;
            frames.push({
                offset: t,
                opacity: t < 0.8 ? 1 : 1 - (t - 0.8) * 3,
                transform: 'translate(' + (x - from.x) + 'px,' + (y - from.y) + 'px) scale(' + (1 - 0.45 * t) + ')'
            });
        }
        var flight = token.animate(frames, {
            duration: Math.min(850, 350 + dist * 0.4),
            easing: 'cubic-bezier(.5, 0, .3, 1)'
        });
        return flight.finished.catch(function () { /* cut short */ }).then(function () { token.remove(); });
    }

    /* ── open, close ───────────────────────────────────────── */
    var opened = false;
    var closeTimer = 0;
    function reducedMotion() {
        return window.matchMedia && window.matchMedia('(prefers-reduced-motion: reduce)').matches;
    }
    function openDock(opts) {
        opts = opts || {};
        if (opened) { if (opts.focus) focusInto(); return; }
        opened = true;
        prefs.open = true;
        remember();
        clearTimeout(closeTimer);
        // Off before it shows: place() measures the navbar, and a panel first
        // styled on screen would slide out and straight back instead.
        var slide = !opts.instant && !reducedMotion();
        if (slide) panel.classList.add('is-off');
        panel.hidden = false;
        place();
        if (slide) void panel.offsetWidth;
        panel.classList.remove('is-off');
        announceDocked();
        unseen = { added: 0, refused: false };
        syncSlot();
        if (!opts.deferMount) ensureMounted();
        if (opts.focus) focusInto();
    }
    // Side panels (side-panel.js) share the right edge and give way.
    function announceDocked() {
        if (opened && !floating()) document.dispatchEvent(new CustomEvent('intel-graph:docked'));
    }
    function closeDock(opts) {
        if (!opened) return;
        opened = false;
        prefs.open = false;
        remember();
        hideMenu();
        place();
        syncSlot();
        clearCallouts();
        if (reducedMotion()) panel.hidden = true;
        else {
            panel.classList.add('is-off');
            closeTimer = setTimeout(function () { if (!opened) panel.hidden = true; }, 200);
        }
        if (opts && opts.focusSlot) {
            var b = slotButtons()[0];
            if (b) b.focus();
        }
    }
    function toggle() {
        if (opened) { closeDock({ focusSlot: panel.contains(document.activeElement) }); return; }
        var collapse = document.querySelector('.navbar .navbar-collapse.show');
        if (collapse && window.bootstrap && window.bootstrap.Collapse) {
            window.bootstrap.Collapse.getOrCreateInstance(collapse, { toggle: false }).hide();
        }
        // Focus moves in only when the slot was worked from the keyboard: a
        // click leaves it where the analyst is reading.
        openDock({ focus: keyboardIntent });
        keyboardIntent = false;
    }
    var keyboardIntent = false;
    document.addEventListener('keydown', function (e) {
        if ((e.key === 'Enter' || e.key === ' ') && e.target.closest && e.target.closest('[data-intel-graph-toggle]')) keyboardIntent = true;
    }, true);
    function focusInto() {
        var target = !switchBtn.disabled ? switchBtn
            : noneEl.querySelector('.ig-so-pick, input') || find('[data-ig-close]');
        target.focus({ preventScroll: true });
    }

    /* ── the mount ─────────────────────────────────────────── */
    var UI = {
        mode: 'viewer',
        contextMenu: { enabled: false },
        emptyState: { render: emptyCard }
    };
    var current = null;     // the handle drawn in the panel
    var mountingUuid = null;
    var currentReady = false;
    var mountStarted = 0;
    var token = 0;         // the latest mount; an older one that resolves is dropped
    var layout = 'clean';   // clean | dirty | saving | saved | conflict | failed
    var layoutWhy = '';
    var conflictRevision = null;
    var notice = null;      // { kind, text } shown in the banner once
    var pending = null;     // items an add with no graph left waiting (intel-graph:pick)

    function drawnUuid() { return current ? current.uuid() : null; }
    // The summary says so, or the graph as mounted does.
    function readOnly(a) {
        return !a._canEdit || (currentReady && current.uuid() === lower(a.uuid) && !current.canEdit());
    }
    function teardown() {
        token++;
        var h = current;
        current = null;
        layout = 'clean';
        conflictRevision = null;
        clearCallouts();
        mountingUuid = null;
        currentReady = false;
        if (h) { try { h.destroy(); } catch (e) { /* already gone */ } }
        canvas.innerHTML = '';
    }
    function ensureMounted() {
        var a = IG().active();
        if (a && current && current.uuid() === lower(a.uuid)) { fitSoon(); return; }
        if (a && !current && mountingUuid === lower(a.uuid)) return;
        if (!a && !current && !noneEl.hidden) return;
        mountActive();
    }
    function mountActive() {
        teardown();
        var mine = token;
        var a = IG().active();
        render();
        if (!a) { showNone(); return Promise.resolve(null); }
        mountingUuid = lower(a.uuid);
        mountStarted = Date.now();
        noneEl.hidden = true;
        showLoading('Loading the graph tools…');
        var box = el('div', 'ig-so-mount');
        canvas.appendChild(box);
        // The page's boot summary carries no target (AppController asks
        // activeFor() for none, to save a query on every page): one GET
        // labels it.
        var labelled = a.target ? Promise.resolve(a) : IG().refreshActive().catch(function () { return a; });
        return Promise.all([IG().load(), labelled]).then(function () {
            if (mine !== token) return null;
            var b = IG().active();
            if (!b || lower(b.uuid) !== mountingUuid) return null;
            render();
            showLoading('Loading “' + b.name + '”…');
            return window.IntelGraph.mount(box, { graph: b.uuid, ui: UI });
        }).then(function (h) {
            if (!h) return null;
            if (mine !== token) { dispose(h); return null; }
            current = h;
            return h.ready;
        }).then(function (h) {
            if (!h || mine !== token) return null;
            loadingEl.hidden = true;
            currentReady = true;
            watch(h);
            describeKnown();
            render();
            var waiting = entriesOf(h.uuid()).filter(function (e) { return e.unlanded; });
            waiting.forEach(function (e) { delete e.unlanded; });
            if (waiting.length) landAll(waiting, h.uuid());
            return h;
        }).catch(function (err) {
            if (mine !== token) return;
            mountingUuid = null;
            showFailure(err);
        });
    }
    function dispose(h) {
        try { h.destroy(); } catch (e) { /* not drawn yet */ }
        if (h.ready) h.ready.then(function () { try { h.destroy(); } catch (e) { /* gone */ } }, function () {});
    }
    function showLoading(text) {
        loadingEl.hidden = false;
        loadingEl.querySelector('.misp-loader').hidden = false;
        loadingEl.querySelector('.ig-so-skeleton').hidden = false;
        find('[data-ig-loading-text]').textContent = text;
    }
    function showFailure(err) {
        loadingEl.hidden = false;
        var box = find('[data-ig-loading-text]');
        box.textContent = '';
        box.appendChild(icon('fas fa-triangle-exclamation text-danger me-1'));
        box.appendChild(document.createTextNode('The graph could not be drawn' + (err && err.status ? ' (' + err.status + ')' : '') + '. '));
        box.appendChild(button('btn btn-sm btn-outline-secondary ms-1', 'Try again', function () { mountActive(); }));
        loadingEl.querySelector('.misp-loader').hidden = true;
        loadingEl.querySelector('.ig-so-skeleton').hidden = true;
    }

    // The graph as the viewer sees it: never the stored node_count.
    function drawnCount() {
        var p = current && current.payload();
        return p && p.document ? p.document.nodes.length : null;
    }

    function watch(h) {
        var g = h.graph();
        try {
            var bus = g.renderer.getGraphInteraction();
            // A click ends a drag too; only one that moved the node counts.
            var dragged = false;
            bus.on('dragging', function () { dragged = true; });
            bus.on('dragended', function () {
                var moved = dragged;
                dragged = false;
                if (h !== current || !moved) return;
                if (!h.canEdit()) { layout = 'moved-ro'; renderFoot(); return; }
                if (layout !== 'conflict') { layout = 'dirty'; layoutWhy = 'moved'; renderFoot(); }
            });
            bus.on('canvasZoom', function () { if (h === current) clearCallouts(); });
        } catch (e) { /* no interaction bus: moves go unnoticed */ }
    }

    var fitTimer = 0;
    function fitSoon() {
        clearTimeout(fitTimer);
        fitTimer = setTimeout(function () {
            if (!opened || !current) return;
            try { current.graph().renderer.fitAndCenter(); } catch (e) { /* no canvas yet */ }
        }, 160);
    }
    if (window.ResizeObserver) {
        var lastW = 0, lastH = 0;
        new ResizeObserver(function (entries) {
            var r = entries[0].contentRect;
            if (!r.width || !r.height) return;
            if (Math.abs(r.width - lastW) < 2 && Math.abs(r.height - lastH) < 2) return;
            var first = !lastW;
            lastW = r.width; lastH = r.height;
            if (!first) fitSoon();
        }).observe(stage);
    }

    /* ── the head ──────────────────────────────────────────── */
    var TYPE = {
        Collection:    { label: 'Collection', icon: 'fas fa-folder' },
        Event:         { label: 'Event', icon: 'misp-icon misp-icon-event misp-simple', color: 'var(--bs-event)' },
        Attribute:     { label: 'Attribute', icon: 'misp-icon misp-icon-attribute misp-simple', color: 'var(--bs-attribute)' },
        Object:        { label: 'Object', icon: 'misp-icon misp-icon-object misp-simple', color: 'var(--bs-object)' },
        GalaxyCluster: { label: 'Galaxy cluster', icon: 'misp-icon misp-icon-galaxy misp-simple', color: 'var(--bs-galaxy)' },
        Value:         { label: 'Value', icon: 'misp-icon misp-icon-value-intelligence misp-simple', color: 'var(--bs-valueIntelligence)' }
    };
    function typeOf(t) { return TYPE[t] || { label: t || 'Record', icon: 'fas fa-circle' }; }
    var TARGET_PAGE = { Event: '/events/view/', Collection: '/collections/view/', GalaxyCluster: '/galaxy_clusters/view/' };

    // A target as type and label; a target the reader cannot read is its
    // type alone. A summary with no target at all is not labelled yet.
    function targetFact(target, typeHint) {
        var t = typeOf((target && target.type) || typeHint);
        var f = el('span', 'ig-so-fact');
        f.title = 'Target';
        f.appendChild(icon(t.icon));
        var s = el('span');
        s.appendChild(document.createTextNode(t.label));
        if (!target) s.appendChild(document.createTextNode(' · …'));
        else if (target.label) {
            s.appendChild(document.createTextNode(' · '));
            var href = TARGET_PAGE[target.type] && target.id != null
                ? baseurl() + TARGET_PAGE[target.type] + encodeURIComponent(target.id) : null;
            var name = el('strong', null, target.label);
            if (href) {
                var a = link('ig-so-target', '', href);
                a.title = 'Open the ' + t.label.toLowerCase();
                a.appendChild(name);
                s.appendChild(a);
            } else s.appendChild(name);
        }
        f.appendChild(s);
        return f;
    }
    function distributionBadge(level) {
        var d = IG().distribution(level);
        if (!d) return null;
        var b = el('span', 'badge d-inline-flex align-items-center px-2 py-1');
        var tone = function (role, value) {
            return d.token ? 'var(--misp-' + d.token + '-' + role + ', ' + value + ')' : value;
        };
        b.style.backgroundColor = tone('bg', d.bg);
        b.style.color = tone('fg', d.color);
        b.style.border = '1px solid ' + tone('border', d.color + '20');
        b.style.fontWeight = '500';
        b.title = d.label;
        b.appendChild(icon(d.icon));
        b.appendChild(el('span', 'ms-1', d.label));
        return b;
    }
    function render() {
        renderHead();
        renderBanner();
        renderTray();
        renderFoot();
    }
    function renderHead() {
        var a = IG().active();
        nameEl.textContent = a ? a.name : 'Pick a workspace';
        switchBtn.title = a ? 'Switch workspace' + (a.description ? ' — ' + a.description : '') : '';
        switchBtn.disabled = !a;
        switchBtn.querySelector('.ig-so-caret').hidden = !a;
        fullLink.hidden = !a;
        fullLink.href = a ? baseurl() + '/workspaces/view/' + encodeURIComponent(a.uuid) : '#';
        metaEl.textContent = '';
        if (!a) return;
        metaEl.appendChild(targetFact(a.target, a.object_type));
        var org = el('span', 'ig-so-fact');
        org.title = 'Creator organisation';
        org.appendChild(icon('misp-icon misp-icon-organisation misp-simple'));
        org.appendChild(el('span', null, (a.Orgc && a.Orgc.name) || ''));
        metaEl.appendChild(org);
        var badge = distributionBadge(a.distribution);
        if (badge) metaEl.appendChild(badge);
        var n = current && current.uuid() === lower(a.uuid) ? drawnCount() : null;
        var count = el('span', 'ig-so-fact ig-so-count');
        count.appendChild(icon('fas fa-circle-nodes'));
        count.appendChild(el('span', null, n == null ? '…' : n + (n === 1 ? ' node' : ' nodes')));
        count.setAttribute('data-ig-count', n == null ? '' : String(n));
        metaEl.appendChild(count);
        if (readOnly(a)) {
            var ro = el('span', 'ig-so-ro-chip');
            ro.appendChild(icon('fas fa-lock me-1'));
            ro.appendChild(document.createTextNode('Read-only'));
            metaEl.appendChild(ro);
        }
    }

    /* ── the banner: read-only, a conflict, what just happened ─ */
    function renderBanner() {
        var a = IG().active();
        bannerEl.className = 'ig-so-banner';
        bannerEl.textContent = '';
        var kind = null, iconCls = null, body = el('div');
        if (a && readOnly(a)) {
            kind = 'readonly'; iconCls = 'fas fa-lock';
            var org = (a.Orgc && a.Orgc.name) || 'another organisation';
            var p = el('p');
            p.appendChild(el('strong', null, org + '’s workspace. '));
            p.appendChild(document.createTextNode('Only ' + org + ' can change it, so “Add to workspace” is refused here. Fork it to keep working on your own copy.'));
            body.appendChild(p);
            var acts = el('div', 'ig-so-actions');
            forkButtons(null).forEach(function (b) { acts.appendChild(b); });
            body.appendChild(acts);
        } else if (layout === 'conflict') {
            kind = 'conflict'; iconCls = 'fas fa-code-compare';
            body.appendChild(el('p', null, 'Layout not saved: this workspace was saved somewhere else since it opened here'
                + (conflictRevision != null ? ' (it is now at revision ' + conflictRevision + ')' : '') + '.'));
            body.appendChild(el('p', 'mt-1', 'Save your layout over that version — what it added is kept, and placed — or reload it and drop your moves. Adds were never at risk: they were saved as they landed.'));
            var acts2 = el('div', 'ig-so-actions');
            acts2.appendChild(button('btn btn-sm btn-danger', 'Save my layout over it', rebaseAndSave, 'fas fa-code-merge'));
            acts2.appendChild(button('btn btn-sm btn-outline-danger', 'Reload the workspace', function () { notice = null; mountActive(); }, 'fas fa-rotate'));
            body.appendChild(acts2);
        } else if (pending) {
            kind = 'pending'; iconCls = 'fas fa-inbox';
            body.appendChild(el('p', null, describeItems(pending) + ' waiting: pick the workspace it goes to, or start one.'));
        } else if (notice) {
            kind = notice.kind; iconCls = notice.kind === 'error' ? 'fas fa-triangle-exclamation' : 'fas fa-check';
            body.appendChild(el('p', null, notice.text));
            if (notice.kind === 'done' && !notice.timer) {
                var shown = notice;
                shown.timer = setTimeout(function () { if (notice === shown) { notice = null; renderBanner(); } }, 12000);
            }
        }
        bannerEl.hidden = !kind;
        if (!kind) return;
        bannerEl.classList.add('is-' + kind);
        bannerEl.appendChild(icon(iconCls));
        bannerEl.appendChild(body);
    }
    function shakeBanner() {
        bannerEl.classList.remove('is-shaking');
        void bannerEl.offsetWidth;
        bannerEl.classList.add('is-shaking');
    }
    // Where a fork can land: the original's target when the analyst can read
    // it, and the record on screen when that is another one (Q8).
    function forkTargets() {
        var a = IG().active();
        var out = [];
        if (a && a.target && a.target.label != null) {
            out.push({ type: a.target.type, uuid: a.target.uuid, label: a.target.label, same: true });
        }
        var page = pageRecord();
        if (page && !(a && a.target && lower(a.target.uuid) === lower(page.uuid))) {
            out.push({ type: page.type, uuid: page.uuid, label: page.label, same: false });
        }
        return out;
    }
    function forkButtons(thenAdd) {
        var targets = forkTargets();
        if (!targets.length) {
            return [el('span', 'small', 'To fork it, open the collection, event or galaxy cluster your copy should hang off.')];
        }
        return targets.map(function (t, i) {
            var label = (thenAdd ? 'Fork, then add it' : 'Fork') + (t.same ? '' : ' onto ' + typeOf(t.type).label + ' · ' + t.label);
            var b = button(i ? 'btn btn-sm btn-outline-primary' : (thenAdd ? 'btn btn-sm btn-outline-primary' : 'btn btn-sm btn-primary'), label, function () {
                b.disabled = true;
                forkActive(thenAdd, t);
            }, 'fas fa-code-fork');
            return b;
        });
    }
    function deliver(items, uuid) {
        return IG().add(items, { graph: uuid }).catch(function () { /* the refusal lands in the tray */ });
    }
    function forkActive(thenAdd, target) {
        var a = IG().active();
        if (!a) return;
        IG().fork(a.uuid, { target: { type: target.type, uuid: target.uuid } }).then(function (fork) {
            notice = { kind: 'done', text: 'Forked onto ' + typeOf(target.type).label + ' · ' + target.label
                + '. This copy is your organisation’s: adds go to it now.' };
            return IG().setActive(fork.uuid);
        }).then(function (fork) {
            if (thenAdd && fork) return deliver(thenAdd, fork.uuid);
        }).catch(function (err) {
            notice = { kind: 'error', text: 'Could not fork: ' + ((err && err.message) || 'unknown error') };
            renderBanner();
        });
    }

    /* ── the switcher ──────────────────────────────────────── */
    function hideMenu() {
        if (!window.bootstrap || !window.bootstrap.Dropdown) return;
        var dd = window.bootstrap.Dropdown.getInstance(switchBtn);
        if (dd) dd.hide();
    }
    switchBtn.addEventListener('show.bs.dropdown', function () { fillSwitcher(menu, true); });
    switchBtn.addEventListener('shown.bs.dropdown', function () {
        var mark = menu.querySelector('[aria-current="true"]') || menu.querySelector('.ig-so-pick');
        if (mark) mark.focus();
    });

    function graphRow(g, isActive, asDropdown, onPick) {
        var b = el('button', asDropdown ? 'dropdown-item ig-so-pick' : 'list-group-item list-group-item-action ig-so-pick');
        b.type = 'button';
        if (isActive) b.setAttribute('aria-current', 'true');
        var mark = el('span', 'ig-so-pick-mark');
        if (isActive) mark.appendChild(icon('fas fa-check'));
        b.appendChild(mark);
        // Where the graph's picture goes (intel-graph-thumbs.js)
        b.setAttribute('data-intel-graph-row', '');
        var thumb = el('span');
        thumb.setAttribute('data-intel-graph-thumb', g.uuid);
        thumb.setAttribute('data-revision', String(g.revision));
        thumb.setAttribute('data-surface', 'switcher');
        thumb.setAttribute('data-name', g.name);
        b.appendChild(thumb);
        var bodyEl = el('span', 'ig-so-pick-body');
        bodyEl.appendChild(el('span', 'ig-so-pick-name', g.name));
        var sub = el('span', 'ig-so-pick-sub');
        var t = typeOf(g.target && g.target.type);
        sub.appendChild(icon(t.icon));
        sub.appendChild(el('span', null, t.label + (g.target && g.target.label ? ' · ' + g.target.label : '')));
        bodyEl.appendChild(sub);
        b.appendChild(bodyEl);
        var n = isActive && drawnUuid() === lower(g.uuid) ? drawnCount() : g.node_count;
        var c = el('span', 'badge rounded-pill text-bg-secondary', String(n == null ? '' : n));
        c.title = n + (n === 1 ? ' node' : ' nodes');
        b.appendChild(c);
        b.addEventListener('click', function () { onPick(g); });
        return b;
    }
    function pick(g) {
        hideMenu();
        var a = IG().active();
        notice = null;
        var items = pending;
        pending = null;
        if (a && lower(a.uuid) === lower(g.uuid)) {
            closeChooser();
            ensureMounted();
            if (items) deliver(items, g.uuid);
            return;
        }
        IG().setActive(g.uuid).then(function () {
            if (items) return deliver(items, g.uuid);
        }).catch(function (err) {
            notice = { kind: 'error', text: 'Could not switch: ' + ((err && err.message) || 'unknown error') };
            renderBanner();
        });
    }
    function noneRow() {
        var b = el('button', 'dropdown-item ig-so-pick ig-so-pick-none');
        b.type = 'button';
        var mark = el('span', 'ig-so-pick-mark');
        mark.appendChild(icon('fas fa-ban'));
        b.appendChild(mark);
        var bodyEl = el('span', 'ig-so-pick-body');
        bodyEl.appendChild(el('span', 'ig-so-pick-name', 'No active workspace'));
        bodyEl.appendChild(el('span', 'ig-so-pick-sub', '“Add to workspace” asks which workspace next time'));
        b.appendChild(bodyEl);
        b.addEventListener('click', clearActive);
        return b;
    }
    function clearActive() {
        hideMenu();
        notice = null;
        IG().setActive(null).catch(function (err) {
            notice = { kind: 'error', text: 'Could not clear the active workspace: ' + ((err && err.message) || 'unknown error') };
            renderBanner();
        });
    }
    var SCOPES = [
        { key: 'mine', label: 'Mine', head: 'Your workspaces', empty: 'No workspace names you among its authors yet.' },
        { key: 'org', label: 'Organisation', head: 'Your organisation’s workspaces', empty: 'Your organisation has no workspace yet.' }
    ];
    function scopeOf(key) {
        return SCOPES.filter(function (s) { return s.key === key; })[0] || SCOPES[1];
    }
    var listSeq = 0;
    function fillSwitcher(into, asDropdown) {
        into.textContent = '';
        var head = el('div', 'ig-so-scope' + (asDropdown ? ' dropdown-header' : ''));
        var title = el(asDropdown ? 'h6' : 'p', asDropdown ? 'mb-0' : 'small text-body-secondary mb-0');
        head.appendChild(title);
        var toggle = el('div', 'btn-group btn-group-sm');
        toggle.setAttribute('role', 'group');
        toggle.setAttribute('aria-label', 'Whose workspaces');
        head.appendChild(toggle);
        into.appendChild(head);
        var holder = el('div', asDropdown ? 'ig-so-list' : 'list-group');
        into.appendChild(holder);
        var buttons = SCOPES.map(function (s) {
            var b = el('button', 'btn btn-outline-primary', s.label);
            b.type = 'button';
            b.addEventListener('click', function () {
                if (prefs.scope === s.key) return;
                prefs.scope = s.key;
                remember();
                load();
            });
            toggle.appendChild(b);
            return b;
        });
        function load() {
            var scope = scopeOf(prefs.scope);
            title.textContent = scope.head;
            SCOPES.forEach(function (s, i) {
                buttons[i].classList.toggle('active', s.key === scope.key);
                buttons[i].setAttribute('aria-pressed', s.key === scope.key ? 'true' : 'false');
            });
            var seq = ++listSeq;
            holder.textContent = '';
            holder.appendChild(el('div', 'px-3 py-2 text-body-secondary small', 'Loading…'));
            IG().list(scope.key).then(function (out) {
                if (seq !== listSeq) return;
                holder.textContent = '';
                var a = IG().active();
                var activeUuid = lower((a && a.uuid) || out.active);
                var listed = out.graphs.some(function (g) { return lower(g.uuid) === activeUuid; });
                if (a && !listed) {
                    if (scope.key === 'mine' && lower(out.active) === lower(a.uuid)) {
                        holder.appendChild(graphRow(a, true, asDropdown, pick));
                    } else {
                        var cur = graphRow(a, true, asDropdown, function () { hideMenu(); });
                        cur.disabled = true;
                        cur.querySelector('.ig-so-pick-name').textContent = a.name + ' — read-only';
                        holder.appendChild(cur);
                    }
                }
                out.graphs.forEach(function (g) { holder.appendChild(graphRow(g, lower(g.uuid) === activeUuid, asDropdown, pick)); });
                if (!out.graphs.length) holder.appendChild(el('div', 'px-3 py-2 text-body-secondary small', scope.empty));
                if (asDropdown && a) holder.appendChild(noneRow());
            }, function (err) {
                if (seq !== listSeq) return;
                holder.textContent = '';
                holder.appendChild(el('div', 'px-3 py-2 text-danger small', 'Could not list the workspaces: ' + ((err && err.message) || 'error')));
            });
        }
        load();
        if (asDropdown) into.appendChild(el('div', 'dropdown-divider'));
        into.appendChild(newGraphForm(asDropdown));
    }
    var formSeq = 0;
    function newGraphForm(asDropdown) {
        var page = pageRecord();
        var id = 'ig-so-new-' + (++formSeq);
        var form = el('form', 'ig-so-new');
        form.noValidate = true;
        var label = el('label', 'form-label', 'New workspace');
        label.htmlFor = id;
        form.appendChild(label);
        var group = el('div', 'input-group input-group-sm');
        var input = el('input', 'form-control');
        input.id = id;
        input.name = 'name';
        input.placeholder = 'Name it';
        input.autocomplete = 'off';
        input.required = true;
        group.appendChild(input);
        var submit = el('button', 'btn btn-primary', 'Create');
        submit.type = 'submit';
        group.appendChild(submit);
        form.appendChild(group);
        var feedback = el('div', 'invalid-feedback');
        form.appendChild(feedback);
        var help = el('div', 'form-text');
        if (page) {
            help.appendChild(document.createTextNode('On '));
            help.appendChild(el('strong', null, typeOf(page.type).label + ' · ' + page.label));
            help.appendChild(document.createTextNode(', the page you are on. It becomes your active workspace.'));
        } else {
            help.textContent = 'Open an event, a collection or a cluster to start a workspace on it.';
            input.disabled = submit.disabled = true;
        }
        form.appendChild(help);
        form.addEventListener('submit', function (e) {
            e.preventDefault();
            var name = input.value.trim();
            input.classList.remove('is-invalid');
            if (!name) { input.classList.add('is-invalid'); feedback.textContent = 'A workspace needs a name.'; input.focus(); return; }
            if (!page) { input.classList.add('is-invalid'); feedback.textContent = 'This page is not a record a workspace can hang off.'; return; }
            submit.disabled = true;
            IG().create({ name: name, target: { type: page.type, uuid: page.uuid } }).then(function (created) {
                hideMenu();
                notice = { kind: 'done', text: '“' + name + '” created on ' + typeOf(page.type).label + ' · ' + page.label + ', and active.' };
                if (pending && created) { var items = pending; pending = null; closeChooser(); return deliver(items, created.uuid); }
            }).catch(function (err) {
                submit.disabled = false;
                input.classList.add('is-invalid');
                var errs = err && err.body && err.body.errors;
                feedback.textContent = (errs && errs.name && errs.name[0]) || (err && err.message) || 'Could not create the workspace.';
            });
        });
        return form;
    }

    /* ── no active graph ───────────────────────────────────── */
    function showNone() {
        loadingEl.hidden = true;
        noneEl.hidden = false;
        noneEl.textContent = '';
        if (pending) {
            noneEl.appendChild(el('h2', null, 'Add to which workspace?'));
            noneEl.appendChild(el('p', null, 'The one you pick becomes your active workspace: later adds go to it too.'));
        } else {
            noneEl.appendChild(el('h2', null, 'No active workspace'));
            noneEl.appendChild(el('p', null, '“Add to workspace” on the pages you browse feeds one workspace at a time. Pick the one you are working on, or start one; nothing loads until you do.'));
        }
        var choices = el('div', 'd-flex flex-column gap-3');
        noneEl.appendChild(choices);
        fillSwitcher(choices, false);
        if (pending) {
            noneEl.appendChild(button('btn btn-sm btn-outline-secondary align-self-start', 'Cancel', function () {
                pending = null;
                closeChooser();
            }));
        }
        render();
    }
    // Back to the graph, or to "no active graph".
    function closeChooser() {
        if (!IG().active()) { showNone(); return; }
        noneEl.hidden = true;
        ensureMounted();
        render();
    }

    /* ── the empty graph ───────────────────────────────────── */
    function emptyCard() {
        var box = el('div', 'ig-so-empty');
        box.appendChild(icon('fas fa-circle-plus'));
        box.appendChild(el('strong', null, 'Nothing in this workspace yet'));
        var p = el('p');
        p.appendChild(document.createTextNode('Use '));
        p.appendChild(el('kbd', null, 'Add to workspace'));
        p.appendChild(document.createTextNode(' on the pages you browse — an event, an attribute, an object, a value. Each one lands here as you add it, and stays.'));
        box.appendChild(p);
        return box;
    }

    /* ── arrivals ──────────────────────────────────────────── */
    // A report key (Type:uuid) on the canvas.
    function nodeFor(key) {
        return current ? current.nodeOf(key) : null;
    }
    function describe(key) {
        var p = (current && current.payload()) || {};
        var at = key.indexOf(':'), type = key.slice(0, at), uuid = lower(key.slice(at + 1));
        var hit = null;
        if (type === 'Attribute') {
            (p.Attribute || []).forEach(function (r) { if (lower(r.uuid) === uuid) hit = r; });
            (p.Object || []).forEach(function (o) { (o.Attribute || []).forEach(function (r) { if (lower(r.uuid) === uuid) hit = r; }); });
            return hit && { type: type, title: hit.value, sub: hit.type };
        }
        if (type === 'Object') {
            (p.Object || []).forEach(function (r) { if (lower(r.uuid) === uuid) hit = r; });
            return hit && { type: type, title: hit.name + ' object', sub: (hit.Attribute || []).length + ' attributes inside' };
        }
        if (type === 'Value') {
            (p.Value || []).forEach(function (r) { if (lower(r.sha256) === uuid) hit = r; });
            return hit && { type: type, title: hit.value, sub: 'value', value: hit.value };
        }
        if (type === 'Event') {
            Object.keys(p.events || {}).forEach(function (id) { if (lower(p.events[id].uuid) === uuid) hit = p.events[id]; });
            return hit && { type: type, title: hit.info, sub: 'event' };
        }
        if (type === 'GalaxyCluster') {
            (p.GalaxyCluster || []).forEach(function (r) { if (lower(r.uuid) === uuid) hit = r; });
            return hit && { type: type, title: hit.value, sub: hit.type ? hit.type + ' cluster' : 'galaxy cluster' };
        }
        return null;
    }
    function describeItems(items) {
        var values = (items || []).filter(function (i) { return i.type === 'Value'; }).map(function (i) { return i.value; });
        if (items && items.length === 1 && values.length === 1) return 'The value ' + values[0];
        if (items && items.length === 1 && items[0].label) return 'The ' + typeOf(items[0].type).label.toLowerCase() + ' ' + items[0].label;
        return (items ? items.length : 0) + ((items && items.length === 1) ? ' item' : ' items');
    }
    // On a mount: name what the log only knew by key, and mark what the
    // graph no longer holds (removed since, on this page or another).
    function describeKnown() {
        var a = drawnUuid();
        var p = (current && current.payload()) || {};
        var held = {};
        ((p.document && p.document.nodes) || []).forEach(function (n) {
            held[n.type + ':' + lower(n.type === 'Value' ? n.sha256 : n.uuid)] = true;
        });
        var changed = false;
        entriesOf(a).forEach(function (e) {
            var keys = (e.keys || []).concat(e.present || []);
            keys.forEach(function (k) {
                if (e.labels[k]) return;
                var d = describe(k);
                if (d) { e.labels[k] = d; changed = true; }
            });
            if ((e.kind === 'added' || e.kind === 'present') && e.at < mountStarted && keys.length
                && !keys.some(function (k) { return held[k]; })) {
                e.kind = 'gone';
                delete undos[e.id];
                changed = true;
            }
        });
        if (changed) saveLog();
    }

    function waitFor(test, ms) {
        return new Promise(function (resolve) {
            var t0 = Date.now();
            (function poll() {
                var v = null;
                try { v = test(); } catch (e) { v = null; }
                if (v || Date.now() - t0 > ms) { resolve(v || null); return; }
                setTimeout(poll, 100);
            }());
        });
    }

    IG().on('added', function (d) {
        var r = d.report || {};
        var entry = {
            id: String(++seq), keys: (r.added || []).slice(), present: (r.present || []).slice(),
            count: (r.added || []).length, refused: (r.refused || []).length, labels: {}, at: Date.now(), fresh: true
        };
        entry.kind = entry.keys.length ? 'added' : 'present';
        var only = (d.items || []).length === 1 ? d.items[0] : null;
        var onlyKey = entry.keys[0] || entry.present[0];
        if (only && only.type === 'Value' && onlyKey) entry.labels[onlyKey] = { type: 'Value', title: only.label || only.value, sub: 'value', value: only.value };
        (d.items || []).forEach(function (item) {
            if (item.label && item.uuid) {
                entry.labels[item.type + ':' + lower(item.uuid)] = { type: item.type, title: item.label, sub: typeOf(item.type).label.toLowerCase() };
            }
        });
        if (d.undo) undos[entry.id] = d.undo;
        push(d.graph, entry);
        if (!opened) unseen.added += entry.count;
        fly(d.origin).then(function () {
            if (opened) return;
            syncSlot();
            pulseSlot();
        });
        var a = IG().active();
        if (a && lower(a.uuid) === lower(d.graph)) {
            renderTray();
            // Not drawn yet (closed, or never opened on this page): it is
            // pointed at when the graph next mounts.
            if (current && current.uuid() === lower(d.graph)) land(entry, lower(d.graph));
            else entry.unlanded = true;
        }
    });

    IG().on('removed', function (d) {
        var gone = (d.report && d.report.removed) || [];
        entriesOf(d.graph).forEach(function (e) {
            if (e.kind === 'added' && e.keys.length && e.keys.every(function (k) { return gone.indexOf(k) !== -1; })) {
                e.kind = 'undone';
                delete undos[e.id];
            }
        });
        saveLog();
        if (drawnUuid() === lower(d.graph)) {
            waitFor(function () { return gone.every(function (k) { return !nodeFor(k); }); }, 4000).then(function () { renderHead(); });
        }
        renderTray();
    });

    document.addEventListener('intel-graph:refused', function (e) {
        var d = e.detail || {};
        if (!d.graph) return;
        var entry = { id: String(++seq), kind: 'refused', keys: [], present: [], labels: {}, at: Date.now(),
                      count: 0, items: d.items, message: d.message || ('HTTP ' + d.status), status: d.status, fresh: true };
        var one = (d.items || []).length === 1 ? d.items[0] : null;
        entry.labels._ = { title: 'Not added: ' + describeItems(d.items).replace(/^The value /, ''), sub: entry.message,
                           href: one ? hrefOf(one.type, one.uuid, one.value) : null };
        push(d.graph, entry);
        if (!opened) { unseen.refused = true; syncSlot(); pulseSlot(); return; }
        flash('is-refusing');
        renderTray();
        shakeBanner();
        say('Not added. ' + entry.message);
    });

    IG().on('pick', function (d) {
        pending = d.items || null;
        if (!opened) openDock({ focus: false, deferMount: true });
        showNone();
    });

    // A save made elsewhere on the page, now drawn here: the count moved.
    IG().on('drawn', function (d) {
        if (d && drawnUuid() === lower(d.graph)) renderHead();
    });

    IG().on('active', function (d) {
        var g = d && d.graph;
        if (!opened) {
            if (current && (!g || current.uuid() !== lower(g.uuid))) teardown();
            render();
            return;
        }
        if (!g) { teardown(); showNone(); return; }
        var showing = current ? current.uuid() : mountingUuid;
        if (showing !== lower(g.uuid)) mountActive();
        else render();
    });

    function flash(cls) {
        panel.classList.remove('is-landing', 'is-refusing');
        void panel.offsetWidth;
        panel.classList.add(cls);
        setTimeout(function () { panel.classList.remove(cls); }, 1500);
    }
    function say(text) {
        sayEl.textContent = '';
        setTimeout(function () { sayEl.textContent = text; }, 30);
    }

    function land(entry, uuid) {
        var keys = entry.keys.length ? entry.keys : entry.present;
        if (!keys.length) return;
        waitFor(function () {
            if (!current || current.uuid() !== uuid) return null;
            var nodes = keys.map(nodeFor);
            return nodes.every(Boolean) ? nodes : null;
        }, 8000).then(function (nodes) {
            if (!nodes) { renderTray(); return; }
            keys.forEach(function (k) { if (!entry.labels[k]) { var dsc = describe(k); if (dsc) entry.labels[k] = dsc; } });
            saveLog();
            if (entry.kind === 'added' && current.canEdit() && layout !== 'conflict') {
                layout = 'dirty';
                layoutWhy = 'placed';
            }
            render();
            if (!opened) return;
            flash('is-landing');
            say((entry.kind === 'added' ? 'Added ' : 'Already in the workspace: ') + titleOf(entry));
            pointAt(nodes, entry);
        });
    }

    // What arrived while the graph was not drawn, pointed at together.
    function landAll(entries, uuid) {
        var keys = [], labels = {};
        entries.forEach(function (e) {
            if (e.kind !== 'added') return;
            e.keys.forEach(function (k) {
                if (keys.indexOf(k) !== -1) return;
                keys.push(k);
                if (!e.labels[k]) { var d = describe(k); if (d) e.labels[k] = d; }
                if (e.labels[k]) labels[k] = e.labels[k];
            });
        });
        saveLog();
        if (keys.length) land({ kind: 'added', keys: keys, present: [], labels: labels, at: Date.now() }, uuid);
    }

    var emphasis = 0;
    function onScreen(g, nodes) {
        var svg = svgOf(g);
        if (!svg) return false;
        var t = g.renderer.getZoomTransform();
        var w = svg.clientWidth, h = svg.clientHeight, m = 24;
        return nodes.every(function (n) {
            if (typeof n.x !== 'number') return false;
            var p = t.apply([n.x, n.y]);
            return p[0] > m && p[1] > m && p[0] < w - m && p[1] < h - m;
        });
    }
    function svgOf(g) {
        try { return g.renderer.getCanvasSelection().node(); } catch (e) { return stage.querySelector('svg'); }
    }
    function pointAt(nodes, entry) {
        var g = current.graph();
        var settle = new Promise(function (r) { setTimeout(r, 650); });
        settle.then(function () {
            if (!current || current.graph() !== g) return null;
            if (!onScreen(g, nodes)) return g.renderer.fitAndCenterWhenSettled();
        }).then(function () {
            if (!current || current.graph() !== g) return;
            setTimeout(function () {
                try { g.emphasiseElements(nodes); } catch (e) { /* no emphasis */ }
                callouts(g, nodes, entry);
                clearTimeout(emphasis);
                emphasis = setTimeout(function () {
                    try { g.clearEmphasis(); } catch (e) { /* gone */ }
                }, 4200);
            }, 350);
        });
    }
    var calloutTimer = 0;
    function clearCallouts() { clearTimeout(calloutTimer); calloutsEl.textContent = ''; }
    function callouts(g, nodes, entry) {
        clearCallouts();
        var svg = svgOf(g);
        if (!svg) return;
        var t = g.renderer.getZoomTransform();
        var sr = svg.getBoundingClientRect(), cr = stage.getBoundingClientRect();
        var keys = entry.keys.length ? entry.keys : entry.present;
        // Beside the node's drawing rather than on it; chips that would
        // overlap are moved apart.
        var spots = [];
        nodes.slice(0, 4).forEach(function (n, i) {
            if (typeof n.x !== 'number') return;
            var p = t.apply([n.x, n.y]);
            var x = sr.left - cr.left + p[0], y = sr.top - cr.top + p[1], half = 6;
            var drawn = n.getGraphElement && n.getGraphElement();
            if (drawn && drawn.getBoundingClientRect) {
                var b = drawn.getBoundingClientRect();
                if (b.width && b.width < cr.width) { half = b.width / 2; x = b.left - cr.left + half; y = b.top - cr.top + b.height / 2; }
            }
            var lab = entry.labels[keys[i]];
            spots.push({ x: x, y: y, half: half, label: lab ? lab.title : 'added' });
        });
        spots.sort(function (a, b) { return a.y - b.y; });
        spots.forEach(function (s, i) {
            if (i && s.y - spots[i - 1].y < 24) s.y = spots[i - 1].y + 24;
            var chip = el('span', 'ig-so-callout' + (entry.kind === 'present' ? ' is-present' : ''));
            chip.appendChild(icon(entry.kind === 'present' ? 'fas fa-check' : 'fas fa-plus'));
            chip.appendChild(el('span', null, s.label));
            var left = s.x + s.half + 6 > cr.width - 140;
            chip.style.left = Math.round(left ? s.x - s.half - 6 : s.x + s.half + 6) + 'px';
            chip.style.top = Math.round(s.y) + 'px';
            if (left) chip.classList.add('is-left');
            calloutsEl.appendChild(chip);
        });
        calloutTimer = setTimeout(clearCallouts, 4300);
    }
    function locate(entry) {
        var keys = entry.keys.length ? entry.keys : entry.present;
        var nodes = keys.map(nodeFor).filter(Boolean);
        if (!nodes.length || !current) return;
        var g = current.graph();
        var n = nodes[0];
        if (nodes.length === 1 && typeof n.x === 'number') {
            var k = Math.max(g.renderer.getZoomTransform().k, 1);
            try { g.renderer.setViewport({ x: n.x, y: n.y, scale: k, animate: true }); } catch (e) { /* stays */ }
            setTimeout(function () { finishLocate(g, nodes, entry); }, 450);
        } else {
            g.renderer.fitAndCenterWhenSettled().then(function () { finishLocate(g, nodes, entry); });
        }
    }
    function finishLocate(g, nodes, entry) {
        try { g.emphasiseElements(nodes); } catch (e) { /* none */ }
        callouts(g, nodes, entry);
        clearTimeout(emphasis);
        emphasis = setTimeout(function () { try { g.clearEmphasis(); } catch (e) { /* gone */ } }, 3200);
    }

    function titleOf(e) {
        var keys = e.keys.length ? e.keys : e.present;
        if (e.kind === 'refused') return e.labels._ ? e.labels._.title : 'Not added';
        var labs = keys.map(function (k) { return e.labels[k]; });
        if (keys.length === 1) return labs[0] ? labs[0].title : keys[0].split(':')[0];
        var types = {};
        keys.forEach(function (k) { var t = k.split(':')[0]; types[t] = (types[t] || 0) + 1; });
        return Object.keys(types).map(function (t) { return types[t] + ' ' + typeOf(t).label.toLowerCase() + (types[t] > 1 ? 's' : ''); }).join(', ');
    }
    // A record's own page; an attribute's and an object's redirect to their
    // event's tab.
    var PAGE = { Event: '/events/view/', Attribute: '/attributes/view/', Object: '/objects/view/', GalaxyCluster: '/galaxy_clusters/view/' };
    function hrefOf(type, uuid, value) {
        if (PAGE[type] && uuid) return baseurl() + PAGE[type] + encodeURIComponent(uuid);
        if (type === 'Value' && value != null) return baseurl() + '/values/view/' + window.MispValueAddress.address(value);
        return null;
    }
    // A Value's key is a digest of the literal, which its label carries.
    function keyHref(key, lab) {
        var at = key.indexOf(':'), type = key.slice(0, at);
        var value = type === 'Value' && lab ? (lab.value != null ? lab.value : lab.title) : null;
        return hrefOf(type, key.slice(at + 1), value);
    }
    function entryHref(e) {
        if (e.kind === 'refused') return (e.labels._ && e.labels._.href) || null;
        var keys = e.keys.length ? e.keys : e.present;
        return keys.length === 1 ? keyHref(keys[0], e.labels[keys[0]]) : null;
    }
    function link(cls, text, href) {
        var a = el(href ? 'a' : 'span', cls, text);
        if (href) a.href = href;
        return a;
    }
    // An entry of several records names each one, leading to its page.
    function subEl(e) {
        var s = el('span', 'ig-so-arr-sub');
        if (e.kind === 'refused') { s.textContent = e.message; return s; }
        var keys = e.keys.length ? e.keys : e.present;
        var parts = [];
        if (keys.length === 1) {
            var lab = e.labels[keys[0]];
            parts.push(lab ? lab.sub : typeOf(keys[0].split(':')[0]).label.toLowerCase());
        } else {
            var names = el('span');
            keys.forEach(function (k) {
                if (!e.labels[k]) return;
                if (names.childNodes.length) names.appendChild(document.createTextNode(' · '));
                names.appendChild(link('ig-so-arr-link', e.labels[k].title, keyHref(k, e.labels[k])));
            });
            if (names.childNodes.length) parts.push(names);
        }
        parts.push(e.kind === 'present' ? 'already in this workspace' : e.kind === 'undone' ? 'undone'
            : e.kind === 'gone' ? 'no longer in this workspace' : 'added');
        if (e.refused) parts.push(e.refused + ' not added');
        parts.push(ago(e.at));
        parts.forEach(function (p, i) {
            if (i) s.appendChild(document.createTextNode(' — '));
            s.appendChild(typeof p === 'string' ? document.createTextNode(p) : p);
        });
        return s;
    }
    function ago(t) {
        var s = Math.round((Date.now() - t) / 1000);
        if (s < 45) return 'just now';
        var m = Math.round(s / 60);
        if (m < 60) return m + ' min ago';
        var h = Math.round(m / 60);
        if (h < 24) return h + ' h ago';
        return new Date(t).toLocaleDateString();
    }
    function arrivalIcon(e) {
        var keys = e.keys.length ? e.keys : e.present;
        var wrap = el('span', 'ig-so-arr-icon');
        if (e.kind === 'refused') { wrap.style.background = 'var(--bs-danger)'; wrap.appendChild(icon('fas fa-ban')); return wrap; }
        var t = typeOf(keys.length ? keys[0].split(':')[0] : null);
        if (t.color) wrap.style.background = t.color;
        if (e.kind !== 'added') wrap.style.opacity = '.55';
        wrap.appendChild(icon(t.icon));
        return wrap;
    }

    trayToggle.addEventListener('click', function () {
        prefs.tray = !prefs.tray;
        remember();
        renderTray();
    });
    trayClear.addEventListener('click', function () {
        var a = IG().active();
        if (!a) return;
        entriesOf(a.uuid).forEach(function (e) { delete undos[e.id]; });
        delete log[lower(a.uuid)];
        saveLog();
        renderTray();
        trayToggle.focus({ preventScroll: true });
    });
    function renderTray() {
        var a = IG().active();
        trayEl.hidden = !a;
        if (!a) return;
        var list = entriesOf(a.uuid);
        var fresh = list.filter(function (e) { return e.fresh; }).length;
        trayClear.hidden = !list.length;
        trayToggle.setAttribute('aria-expanded', prefs.tray ? 'true' : 'false');
        trayList.hidden = !prefs.tray;
        trayNew.className = fresh && !prefs.tray ? 'ig-so-tray-new' : '';
        trayNew.textContent = list.length ? (fresh && !prefs.tray ? fresh + ' new' : '· ' + list.length) : '';
        trayList.textContent = '';
        if (!list.length) {
            var hint = el('li', 'ig-so-arr-hint');
            hint.textContent = !readOnly(a)
                ? 'What you send with “Add to workspace” lands here, page after page.'
                : 'Nothing can be added to this workspace.';
            trayList.appendChild(hint);
            return;
        }
        var mounted = drawnUuid() === lower(a.uuid);
        list.forEach(function (e) {
            var li = el('li', 'ig-so-arr' + (e.fresh && prefs.tray ? ' is-fresh' : ''));
            li.setAttribute('data-kind', e.kind);
            li.appendChild(arrivalIcon(e));
            var bodyEl = el('div', 'ig-so-arr-body');
            bodyEl.appendChild(link('ig-so-arr-title', titleOf(e), entryHref(e)));
            bodyEl.appendChild(subEl(e));
            li.appendChild(bodyEl);
            var acts = el('div', 'ig-so-arr-acts');
            if (mounted && (e.kind === 'added' || e.kind === 'present')) {
                var loc = button('btn btn-link', '', function () { locate(e); }, 'fas fa-location-crosshairs');
                loc.title = 'Show it on the graph';
                loc.setAttribute('aria-label', 'Show ' + titleOf(e) + ' on the graph');
                acts.appendChild(loc);
            }
            if (e.kind === 'added' && undos[e.id]) {
                var un = button('btn btn-outline-secondary', 'Undo', function () {
                    un.disabled = true;
                    undos[e.id]().catch(function (err) {
                        un.disabled = false;
                        notice = { kind: 'error', text: 'Undo failed: ' + ((err && err.message) || 'error') };
                        renderBanner();
                    });
                });
                un.setAttribute('aria-label', 'Undo adding ' + titleOf(e));
                acts.appendChild(un);
            }
            if (e.kind === 'refused' && e.items && readOnly(a) && e.status === 403) {
                forkButtons(e.items).forEach(function (b) { if (b.tagName === 'BUTTON') acts.appendChild(b); });
            }
            li.appendChild(acts);
            trayList.appendChild(li);
            e.fresh = false;
        });
    }
    setInterval(function () { if (opened) renderTray(); }, 30000);

    /* ── the foot: what is kept ────────────────────────────── */
    function renderFoot() {
        var a = IG().active();
        footEl.hidden = !a;
        if (!a) return;
        footEl.className = 'ig-so-foot';
        footEl.textContent = '';
        var text = el('div', 'ig-so-foot-text');
        footEl.appendChild(text);
        var mounted = current && current.uuid() === lower(a.uuid);
        if (readOnly(a)) {
            text.appendChild(icon('fas fa-lock me-1'));
            text.appendChild(document.createTextNode(layout === 'moved-ro'
                ? 'Moves here are not kept: this workspace is read-only.'
                : 'Read-only: nothing you add or move here is kept.'));
            return;
        }
        if (layout === 'dirty' && mounted) {
            footEl.classList.add('is-dirty');
            text.appendChild(icon('fas fa-up-down-left-right me-1'));
            text.appendChild(el('strong', null, layoutWhy === 'placed' ? 'New nodes placed here. ' : 'Layout changed here. '));
            text.appendChild(document.createTextNode('Positions are not saved until you save them.'));
            footEl.appendChild(button('btn btn-outline-secondary', 'Discard', function () { mountActive(); }));
            footEl.appendChild(button('btn btn-primary', 'Save layout', saveLayout, 'fas fa-floppy-disk'));
            return;
        }
        if (layout === 'saving') {
            text.appendChild(el('span', 'spinner-border spinner-border-sm me-1'));
            text.appendChild(document.createTextNode('Saving the layout…'));
            return;
        }
        if (layout === 'conflict') {
            footEl.classList.add('is-conflict');
            text.appendChild(icon('fas fa-code-compare me-1'));
            text.appendChild(document.createTextNode('Layout not saved: saved elsewhere since it opened.'));
            return;
        }
        if (layout === 'failed') {
            footEl.classList.add('is-conflict');
            text.appendChild(icon('fas fa-triangle-exclamation me-1'));
            text.appendChild(document.createTextNode('Layout not saved: ' + layoutWhy));
            footEl.appendChild(button('btn btn-outline-secondary', 'Try again', saveLayout));
            return;
        }
        text.appendChild(icon((layout === 'saved' ? 'fas fa-check' : 'fas fa-cloud') + ' me-1'));
        text.appendChild(el('strong', null, layout === 'saved' ? 'Layout saved. ' : 'Adds are saved as they land. '));
        text.appendChild(document.createTextNode(layout === 'saved' ? 'It opens like this on every page.' : 'Moves are kept once you save the layout.'));
    }
    function rebaseAndSave() {
        var h = current;
        if (!h) return;
        layout = 'saving';
        render();
        h.rebase().then(function () {
            if (h !== current) return;
            conflictRevision = null;
            saveLayout();
        }, function (err) {
            if (h !== current) return;
            layout = 'failed';
            layoutWhy = (err && err.message) || 'error';
            render();
        });
    }
    function saveLayout() {
        var h = current;
        if (!h) return;
        layout = 'saving';
        renderFoot();
        h.save().then(function () {
            if (h !== current) return;
            layout = 'saved';
            render();
        }, function (err) {
            if (h !== current) return;
            if (err && err.status === 409) {
                layout = 'conflict';
                conflictRevision = err.body && err.body.revision != null ? err.body.revision : null;
                shakeBanner();
            } else {
                layout = 'failed';
                layoutWhy = (err && err.message) || 'error';
            }
            render();
            if (layout === 'conflict') shakeBanner();
        });
    }

    /* ── resizing ──────────────────────────────────────────── */
    grip.addEventListener('pointerdown', function (e) {
        if (e.button !== 0) return;
        e.preventDefault();
        grip.setPointerCapture(e.pointerId);
        panel.classList.add('is-resizing');
        var startX = e.clientX, startW = width();
        function move(ev) {
            prefs.wide = false;
            var b = bounds();
            prefs.width = Math.min(b.max, Math.max(b.min, startW + (startX - ev.clientX)));
            placeSoon();
        }
        function up() {
            grip.removeEventListener('pointermove', move);
            grip.removeEventListener('pointerup', up);
            grip.removeEventListener('pointercancel', up);
            panel.classList.remove('is-resizing');
            prefs.width = width();
            remember();
            place();
        }
        grip.addEventListener('pointermove', move);
        grip.addEventListener('pointerup', up);
        grip.addEventListener('pointercancel', up);
    });
    grip.addEventListener('dblclick', toggleWide);
    grip.addEventListener('keydown', function (e) {
        var b = bounds(), w = width(), step = e.shiftKey ? STEP * 4 : STEP;
        if (e.key === 'ArrowLeft') w += step;
        else if (e.key === 'ArrowRight') w -= step;
        else if (e.key === 'Home') w = b.min;
        else if (e.key === 'End') w = b.max;
        else return;
        e.preventDefault();
        prefs.wide = false;
        prefs.width = Math.min(b.max, Math.max(b.min, w));
        remember();
        place();
    });
    function toggleWide() {
        if (!prefs.wide) prefs.width = width();
        prefs.wide = !prefs.wide;
        remember();
        place();
    }
    widenBtn.addEventListener('click', toggleWide);
    window.addEventListener('resize', placeSoon);

    /* ── undocking ─────────────────────────────────────────── */
    // The graph stays mounted: only its container changes, and the stage's
    // resize observer refits it.
    function setMode(mode) {
        if (prefs.mode === mode) return;
        prefs.mode = mode;
        if (mode === 'floating' && !prefs.win) prefs.win = defaultWin();
        hideMenu();
        clearCallouts();
        remember();
        place();
        announceDocked();
        syncSlot();
        say(mode === 'floating' ? 'Undocked into a window.' : 'Docked to the right.');
        (mode === 'floating' ? moveHandle : undockBtn).focus({ preventScroll: true });
    }
    undockBtn.addEventListener('click', function () { setMode('floating'); });
    dockBtn.addEventListener('click', function () { setMode('docked'); });

    // Track a pointer from pointerdown to pointerup; fn gets the distance moved.
    function track(e, target, cls, fn) {
        e.preventDefault();
        target.setPointerCapture(e.pointerId);
        panel.classList.add(cls);
        var sx = e.clientX, sy = e.clientY;
        function move(ev) { drag = fn(ev.clientX - sx, ev.clientY - sy); placeSoon(); }
        function up() {
            target.removeEventListener('pointermove', move);
            target.removeEventListener('pointerup', up);
            target.removeEventListener('pointercancel', up);
            panel.classList.remove(cls);
            if (drag) { prefs.win = anchor(drag); drag = null; remember(); }
            place();
        }
        target.addEventListener('pointermove', move);
        target.addEventListener('pointerup', up);
        target.addEventListener('pointercancel', up);
    }
    head.addEventListener('pointerdown', function (e) {
        if (!floating() || e.button !== 0) return;
        var t = e.target;
        if (!t.closest('[data-ig-move]') && t.closest('button, a, input, select, textarea, .dropdown-menu, .ig-so-banner')) return;
        var start = winRect();
        track(e, head, 'is-moving', function (ex, ey) { return clampMove(start, ex, ey); });
    });
    edges.forEach(function (edge) {
        edge.addEventListener('pointerdown', function (e) {
            if (e.button !== 0) return;
            e.stopPropagation();
            var start = winRect(), which = edge.getAttribute('data-ig-edge');
            track(e, edge, 'is-resizing', function (ex, ey) { return clampResize(start, which, ex, ey); });
        });
    });
    function arrows(fn) {
        return function (e) {
            var step = e.shiftKey ? STEP * 4 : STEP;
            var by = { ArrowLeft: [-step, 0], ArrowRight: [step, 0], ArrowUp: [0, -step], ArrowDown: [0, step] }[e.key];
            if (!by) return;
            e.preventDefault();
            prefs.win = anchor(fn(winRect(), by[0], by[1]));
            remember();
            place();
        };
    }
    moveHandle.addEventListener('keydown', arrows(clampMove));
    seEdge.addEventListener('keydown', arrows(function (s, ex, ey) { return clampResize(s, 'se', ex, ey); }));

    // A page dropdown opening beside the dock shows over it, until it closes.
    document.addEventListener('show.bs.dropdown', function (e) {
        if (!panel.contains(e.target)) panel.classList.add('is-under');
    });
    document.addEventListener('hidden.bs.dropdown', function (e) {
        if (panel.contains(e.target)) return;
        if (!document.querySelector('.dropdown-menu.show')) panel.classList.remove('is-under');
    });

    /* ── keyboard ──────────────────────────────────────────── */
    // Bootstrap's dropdown takes an Escape that closes its menu (stopped in
    // capture) and prevents the default of any other on its toggle, so
    // defaultPrevented says nothing here.
    panel.addEventListener('keydown', function (e) {
        if (e.key !== 'Escape') return;
        if (menu.classList.contains('show')) return;
        e.preventDefault();
        closeDock({ focusSlot: true });
    });
    find('[data-ig-close]').addEventListener('click', function () { closeDock({ focusSlot: true }); });

    // G shows or hides the dock, unless the key is typed into a field, taken
    // by the control it was pressed on, or pressed behind a modal.
    var SHORTCUT = 'g';
    function typing(t) {
        return !!t && (t.isContentEditable || /^(INPUT|TEXTAREA|SELECT)$/.test(t.tagName));
    }
    document.addEventListener('keydown', function (e) {
        if (e.defaultPrevented || e.repeat || e.isComposing || e.ctrlKey || e.metaKey || e.altKey) return;
        if (String(e.key).toLowerCase() !== SHORTCUT || typing(e.target)) return;
        if (document.querySelector('.modal.show')) return;
        e.preventDefault();
        toggle();
    });

    /* ── boot ──────────────────────────────────────────────── */
    IG().registerDock({ toggle: toggle, shortcut: SHORTCUT });
    decorateSlot();
    render();
    // The active graph's own page draws it in full: the dock stays shut
    // there, and is still remembered open for the next page.
    if (prefs.open && !pageShowsActive()) {
        // The dock is drawn at once where it was left; the graph once the
        // page itself has loaded.
        openDock({ instant: true, deferMount: true });
        showLoading('Loading the workspace…');
        var go = function () {
            var idle = window.requestIdleCallback || function (fn) { return setTimeout(fn, 200); };
            idle(function () { if (opened) ensureMounted(); }, { timeout: 1200 });
        };
        if (document.readyState === 'complete') go();
        else window.addEventListener('load', go, { once: true });
    } else {
        place();
    }

    window.IntelGraphDock = {
        open: openDock, close: closeDock, toggle: toggle, handle: function () { return current; },
        isOpen: function () { return opened; },
        prefs: function () { return Object.assign({}, prefs); }, width: width, bounds: bounds,
        mode: function () { return prefs.mode; }, setMode: setMode, rect: winRect
    };
}());
