// The news panel: the instance's news, over whatever page the user is on.
// It behaves like the analyst graph dock (intel-graph-dock.js). Docked, it is
// a drawer against the right edge, full height under the navbar, as wide as
// the user drags it; undocked, a window moved by its head and resized from
// its edges, kept as the corner it is nearest to. The two share the right
// edge: docking one closes the other.
//
// Opened by the navbar's News button or N. The news load on open, which marks
// them read on the server, so the button's unread count goes with them. Open
// or closed, docked or floating, the width and the window are remembered per
// viewer in localStorage.
(function () {
    'use strict';

    var KEY = 'misp.news.panel';
    var MIN_W = 320;
    var PAGE_MIN = 480;
    var STEP = 24;
    var SHORTCUT = 'n';

    var panel = document.getElementById('nw-so');
    if (!panel) return;
    var html = document.documentElement;
    var find = function (sel) { return panel.querySelector(sel); };
    var body = find('[data-news-body]');
    var grip = find('[data-news-grip]');
    var head = find('.nw-so-head');
    var moveHandle = find('[data-news-move]');
    var widenBtn = find('[data-news-widen]');
    var undockBtn = find('[data-news-undock]');
    var dockBtn = find('[data-news-dock]');
    var edges = Array.prototype.slice.call(panel.querySelectorAll('[data-news-edge]'));
    var seEdge = find('[data-news-edge="se"]');
    var sayEl = find('[data-news-say]');
    var text = {};
    try { text = JSON.parse(find('[data-news-text]').textContent); } catch (e) { /* English below */ }
    text = Object.assign({
        failed: 'Failed to load the news.', retry: 'Try again', olderFailed: 'Failed to load older news.',
        shortcut: 'N shows or hides it', widen: 'Widen the panel', narrow: 'Back to your width',
        undocked: 'Undocked into a window.', docked: 'Docked to the right.',
        added: 'News item added.', saved: 'News item saved.', deleted: 'News item deleted.',
        saveFailed: 'The news item could not be saved.'
    }, text);

    function say(message) {
        sayEl.textContent = '';
        setTimeout(function () { sayEl.textContent = message; }, 50);
    }

    /* ── what is remembered, per viewer ───────────────────── */
    var prefs = { open: false, width: 0, wide: false, mode: 'docked', win: null };
    try {
        var saved = JSON.parse(window.localStorage.getItem(KEY));
        if (saved && typeof saved === 'object') prefs = Object.assign(prefs, saved);
    } catch (e) { /* defaults */ }
    if (prefs.mode !== 'floating') prefs.mode = 'docked';
    if (!validWin(prefs.win)) prefs.win = null;
    function validWin(w) {
        return !!w && /^[tb][lr]$/.test(w.corner) && ['dx', 'dy', 'w', 'h'].every(function (k) {
            return typeof w[k] === 'number' && isFinite(w[k]) && w[k] >= 0;
        });
    }
    function remember() {
        try {
            window.localStorage.setItem(KEY, JSON.stringify({
                open: prefs.open, width: prefs.width, wide: prefs.wide, mode: prefs.mode, win: prefs.win
            }));
        } catch (e) { /* kept for this page only */ }
    }

    /* ── docked: the width ─────────────────────────────────── */
    function viewport() { return html.clientWidth || window.innerWidth; }
    // It lies over the page; at its widest it leaves the page PAGE_MIN uncovered.
    function bounds() {
        var vw = viewport();
        var max = Math.max(Math.min(MIN_W, vw - 16), vw - PAGE_MIN);
        return { vw: vw, min: Math.min(MIN_W, max), max: max };
    }
    function width() {
        var b = bounds();
        var want = prefs.wide ? b.max : (prefs.width || Math.round(Math.min(480, Math.max(360, b.vw * 0.28))));
        return Math.round(Math.min(b.max, Math.max(b.min, want)));
    }
    var navTop = 58;
    function measureNav() {
        var bar = document.querySelector('.rc-bar, .rail-bar');
        if (bar) navTop = Math.max(0, Math.round(bar.getBoundingClientRect().bottom));
        return navTop;
    }

    /* ── undocked: one rectangle ──────────────────────────── */
    // Kept as the corner it is nearest to and its distance from that corner,
    // always inside the viewport, under the navbar.
    var GUTTER = 12, MIN_FW = 340, MIN_FH = 280, SNAP = 16;
    var drag = null;  // the rectangle while it is being moved or resized
    function floating() { return prefs.mode === 'floating'; }
    function room() {
        var top = measureNav();
        return { left: GUTTER, top: top + GUTTER, right: viewport() - GUTTER, bottom: window.innerHeight - GUTTER };
    }
    function defaultWin() {
        var r = room();
        return { corner: 'br', dx: 0, dy: 0, w: Math.min(Math.max(width(), 440), r.right - r.left),
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
        html.style.setProperty('--nw-so-w', w + 'px');
        html.style.setProperty('--nw-so-top', measureNav() + 'px');
        html.classList.toggle('nw-so-docked', opened && !float);
        panel.classList.toggle('is-floating', float);
        if (float) {
            var rect = drag || winRect();
            panel.style.setProperty('--nw-fw-left', rect.left + 'px');
            panel.style.setProperty('--nw-fw-top', rect.top + 'px');
            panel.style.setProperty('--nw-fw-w', rect.w + 'px');
            panel.style.setProperty('--nw-fw-h', rect.h + 'px');
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
        widenBtn.setAttribute('aria-pressed', prefs.wide ? 'true' : 'false');
        widenBtn.title = prefs.wide ? text.narrow : text.widen;
        widenBtn.setAttribute('aria-label', widenBtn.title);
    }
    var placing = 0;
    function placeSoon() {
        if (placing) return;
        placing = window.requestAnimationFrame(function () { placing = 0; place(); });
    }

    /* ── the button ────────────────────────────────────────── */
    function buttons() { return document.querySelectorAll('[data-news-toggle]'); }
    function syncButtons() {
        buttons().forEach(function (b) {
            b.setAttribute('aria-expanded', opened ? 'true' : 'false');
            var side = b.querySelector('.nw-slot-side');
            if (side) side.className = 'fas ' + (floating() ? 'fa-window-restore' : 'fa-angles-left') + ' nw-slot-side';
        });
    }
    function titleSlots(read) {
        document.querySelectorAll('[data-news-slot]').forEach(function (slot) {
            var b = slot.querySelector('[data-news-toggle]');
            var name = slot.querySelector('.rc-chip-name, .rail-graph-name');
            var label = read || !b ? (name ? name.textContent.trim() : 'News') : b.getAttribute('aria-label');
            slot.title = label + ' — ' + text.shortcut;
            if (b) {
                b.setAttribute('aria-label', label);
                b.setAttribute('aria-keyshortcuts', SHORTCUT.toUpperCase());
            }
        });
    }
    // The server marked the news read when it sent them.
    function markRead() {
        document.querySelectorAll('[data-news-slot]').forEach(function (slot) {
            slot.setAttribute('data-state', 'read');
            var count = slot.querySelector('[data-news-count]');
            if (count) count.hidden = true;
        });
        titleSlots(true);
    }

    /* ── the list ──────────────────────────────────────────── */
    var loaded = false;
    var loading = null;
    function fetchPage(page) {
        var url = panel.getAttribute('data-url') + (page > 1 ? '/page:' + page : '');
        return fetch(url, {
            credentials: 'same-origin',
            headers: { 'X-Requested-With': 'XMLHttpRequest' }
        }).then(function (r) {
            // A session that ran out answers with the login page.
            if (!r.ok || r.redirected) throw new Error('HTTP ' + r.status);
            return r.text();
        });
    }
    function load() {
        if (loading) return loading;
        loading = fetchPage(1).then(function (out) {
            disposeTips();
            body.innerHTML = out;
            loaded = true;
            markRead();
            renderMarkdown(body);
        }).catch(function () {
            disposeTips();
            body.innerHTML = '';
            var box = document.createElement('div');
            box.className = 'nw-so-error';
            box.setAttribute('role', 'alert');
            var p = document.createElement('p');
            p.textContent = text.failed;
            var retry = document.createElement('button');
            retry.type = 'button';
            retry.className = 'btn btn-sm btn-outline-secondary';
            retry.textContent = text.retry;
            retry.addEventListener('click', function () { showLoading(); load(); });
            box.appendChild(p);
            box.appendChild(retry);
            body.appendChild(box);
        }).then(function () { loading = null; });
        return loading;
    }
    function showLoading() {
        body.innerHTML = '<div class="nw-so-loading" role="status"><div class="misp-loader" aria-hidden="true"></div></div>';
    }
    function loadOlder(button) {
        var page = parseInt(button.getAttribute('data-news-more'), 10) || 2;
        button.disabled = true;
        fetchPage(page).then(function (out) {
            var holder = document.createElement('div');
            holder.innerHTML = out;
            // The last day on screen may go on in this page.
            var days = body.querySelectorAll('[data-news-day]');
            var last = days.length ? days[days.length - 1].getAttribute('data-news-day') : null;
            var firstDay = holder.querySelector('[data-news-day]');
            if (firstDay && firstDay.getAttribute('data-news-day') === last) firstDay.remove();
            var first = holder.querySelector('.nw-msg');
            var frag = document.createDocumentFragment();
            while (holder.firstChild) frag.appendChild(holder.firstChild);
            button.replaceWith(frag);
            renderMarkdown(body);
            if (first) first.focus({ preventScroll: true });
        }).catch(function () {
            button.disabled = false;
            if (typeof showToast === 'function') showToast(text.olderFailed, 'danger');
        });
    }

    // markdown-it is large and only the panel needs it, so it loads with the news.
    var md = null;
    var mdLoading = null;
    function markdownit() {
        if (window.markdownit) return Promise.resolve(window.markdownit);
        if (!mdLoading) {
            mdLoading = new Promise(function (resolve, reject) {
                var s = document.createElement('script');
                s.src = panel.getAttribute('data-markdown');
                s.onload = function () {
                    if (window.markdownit) resolve(window.markdownit); else reject(new Error('markdown-it'));
                };
                s.onerror = function () { mdLoading = null; reject(new Error('markdown-it')); };
                document.head.appendChild(s);
            });
        }
        return mdLoading;
    }
    function renderMarkdown(root) {
        if (!root.querySelector('[data-news-markdown]')) return;
        markdownit().then(function (factory) {
            if (!md) {
                md = factory('default');
                md.disable(['image']);
            }
            root.querySelectorAll('[data-news-markdown]').forEach(function (el) {
                el.innerHTML = md.render(el.textContent);
                el.removeAttribute('data-news-markdown');
            });
        }).catch(function () { /* the plain text stays */ });
    }

    // The exact date sits on the clock icon, as a tooltip made on first hover.
    function showTip(e) {
        var when = e.target.closest && e.target.closest('[data-news-when]');
        if (!when || !window.bootstrap) return;
        if (!window.bootstrap.Tooltip.getInstance(when)) {
            window.bootstrap.Tooltip.getOrCreateInstance(when, { placement: 'top', container: 'body' }).show();
        }
    }
    function disposeTips() {
        if (!window.bootstrap) return;
        body.querySelectorAll('[data-news-when]').forEach(function (el) {
            var tip = window.bootstrap.Tooltip.getInstance(el);
            if (tip) tip.dispose();
        });
    }
    panel.addEventListener('mouseover', showTip);
    panel.addEventListener('focusin', showTip);

    /* ── open, close ───────────────────────────────────────── */
    var opened = false;
    var closeTimer = 0;
    function reducedMotion() {
        return window.matchMedia && window.matchMedia('(prefers-reduced-motion: reduce)').matches;
    }
    // A docked graph takes the same edge.
    function yieldEdge() {
        var dock = window.IntelGraphDock;
        if (!floating() && dock && dock.isOpen() && dock.mode() === 'docked') dock.close();
    }
    function openPanel(opts) {
        opts = opts || {};
        if (opened) { if (opts.focus) focusInto(); return; }
        yieldEdge();
        opened = true;
        prefs.open = true;
        remember();
        clearTimeout(closeTimer);
        // Off before it shows, so it slides in rather than out and back.
        var slide = !opts.instant && !reducedMotion();
        if (slide) panel.classList.add('is-off');
        panel.hidden = false;
        place();
        if (slide) void panel.offsetWidth;
        panel.classList.remove('is-off');
        syncButtons();
        // Each open shows the news as they are now, and reads them.
        if (loaded) load(); else if (!loading) { showLoading(); load(); }
        if (opts.focus) focusInto();
    }
    function closePanel(opts) {
        if (!opened) return;
        opened = false;
        prefs.open = false;
        remember();
        disposeTips();
        place();
        syncButtons();
        if (reducedMotion()) panel.hidden = true;
        else {
            panel.classList.add('is-off');
            closeTimer = setTimeout(function () { if (!opened) panel.hidden = true; }, 200);
        }
        if (opts && opts.focusButton) {
            var b = Array.prototype.find.call(buttons(), function (el) { return el.offsetParent !== null; });
            if (b) b.focus();
        }
    }
    function toggle() {
        if (opened) { closePanel({ focusButton: panel.contains(document.activeElement) }); return; }
        // The rail's phone drawer would stay over the panel.
        var railToggle = document.querySelector('.rail-nav.is-drawer .rail-toggle');
        if (railToggle) railToggle.click();
        // Focus moves in only when the button was worked from the keyboard.
        openPanel({ focus: keyboardIntent });
        keyboardIntent = false;
    }
    var keyboardIntent = false;
    document.addEventListener('keydown', function (e) {
        if ((e.key === 'Enter' || e.key === ' ') && e.target.closest && e.target.closest('[data-news-toggle]')) keyboardIntent = true;
    }, true);
    function focusInto() {
        var target = floating() ? moveHandle : find('.nw-so-tools .nw-so-tool:not([hidden])') || find('[data-news-close]');
        target.focus({ preventScroll: true });
    }

    buttons().forEach(function (b) {
        b.addEventListener('click', function (e) {
            e.preventDefault();
            toggle();
        });
    });
    find('[data-news-close]').addEventListener('click', function () { closePanel({ focusButton: true }); });
    panel.addEventListener('keydown', function (e) {
        if (e.key !== 'Escape') return;
        e.preventDefault();
        closePanel({ focusButton: true });
    });
    panel.addEventListener('click', function (e) {
        var modal = e.target.closest('[data-news-modal]');
        if (modal && typeof openModal === 'function') {
            modalUrl = modal.getAttribute('data-news-modal');
            openModal(modalUrl, modal.getAttribute('data-news-modal-size') || 'lg');
            return;
        }
        var more = e.target.closest('[data-news-more]');
        if (more) loadOlder(more);
    });

    /* ── the forms it opens ────────────────────────────────── */
    // Sent from here rather than posted, so the page underneath stays as it
    // is: the modal closes and the list reloads.
    var modalUrl = null;
    var modalEl = document.getElementById('mainModal');
    if (modalEl) modalEl.addEventListener('hidden.bs.modal', function () { modalUrl = null; });
    document.addEventListener('submit', function (e) {
        var form = e.target;
        if (!modalUrl || !modalEl || !modalEl.contains(form)) return;
        var kind = (/\/news\/(add|edit|deleteSelection)\b/.exec(form.getAttribute('action') || '') || [])[1];
        if (!kind) return;
        e.preventDefault();
        sendForm(form, kind);
    });
    function sendForm(form, kind) {
        var submit = form.querySelector('[type="submit"]');
        if (submit) submit.disabled = true;
        // Accept: application/json takes the controller's REST branch, which
        // answers with the outcome instead of a redirect; the form's own
        // tokens still go with it.
        fetch(form.action, {
            method: 'POST',
            credentials: 'same-origin',
            headers: { 'X-Requested-With': 'XMLHttpRequest', 'Accept': 'application/json' },
            body: new URLSearchParams(new FormData(form))
        }).then(function (r) {
            return r.json().catch(function () { return {}; }).then(function (data) {
                if (!r.ok || data.saved === false) throw data;
                return data;
            });
        }).then(function (data) {
            var shown = bootstrap.Modal.getInstance(modalEl);
            if (shown) shown.hide();
            var done = { add: text.added, edit: text.saved, deleteSelection: data.message || text.deleted }[kind];
            if (typeof showToast === 'function') showToast(done, 'success');
            load();
        }).catch(function (data) {
            if (submit) submit.disabled = false;
            if (typeof showToast === 'function') showToast(errorText(data), 'danger');
            renewToken(form);
        });
    }
    function errorText(data) {
        var errors = data && data.errors;
        var list = [];
        (function walk(v) {
            if (Array.isArray(v)) v.forEach(walk);
            else if (v && typeof v === 'object') Object.keys(v).forEach(function (k) { walk(v[k]); });
            else if (v) list.push(String(v));
        })(errors);
        return list.length ? list.join(' ') : ((data && data.message) || text.saveFailed);
    }
    // The tokens a refused post carried are spent; the form stays up for
    // another try, so it takes the ones of a freshly rendered copy.
    function renewToken(form) {
        if (!modalUrl) return;
        fetch(modalUrl, { credentials: 'same-origin', headers: { 'X-Requested-With': 'XMLHttpRequest' } })
            .then(function (r) { return r.text(); })
            .then(function (out) {
                var fresh = new DOMParser().parseFromString(out, 'text/html');
                fresh.querySelectorAll('input[name^="data[_Token]"]').forEach(function (input) {
                    var mine = form.querySelector('input[name="' + input.name + '"]');
                    if (mine) mine.value = input.value;
                });
            })
            .catch(function () { /* the next try reports it */ });
    }
    document.addEventListener('intel-graph:docked', function () {
        if (!floating()) closePanel();
    });

    // N shows or hides the panel, unless the key is typed into a field, taken
    // by the control it was pressed on, or pressed behind a modal or the game.
    function typing(t) {
        return !!t && (t.isContentEditable || /^(INPUT|TEXTAREA|SELECT)$/.test(t.tagName));
    }
    document.addEventListener('keydown', function (e) {
        if (e.defaultPrevented || e.repeat || e.isComposing || e.ctrlKey || e.metaKey || e.altKey) return;
        if (String(e.key).toLowerCase() !== SHORTCUT || typing(e.target)) return;
        if (document.querySelector('.modal.show, .mi-overlay')) return;
        e.preventDefault();
        toggle();
    });

    /* ── docked: resizing ──────────────────────────────────── */
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
    function setMode(mode) {
        if (prefs.mode === mode) return;
        prefs.mode = mode;
        if (mode === 'floating' && !prefs.win) prefs.win = defaultWin();
        if (opened) yieldEdge();
        remember();
        place();
        syncButtons();
        say(mode === 'floating' ? text.undocked : text.docked);
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
        if (!t.closest('[data-news-move]') && t.closest('button, a, input')) return;
        var start = winRect();
        track(e, head, 'is-moving', function (ex, ey) { return clampMove(start, ex, ey); });
    });
    edges.forEach(function (edge) {
        edge.addEventListener('pointerdown', function (e) {
            if (e.button !== 0) return;
            e.stopPropagation();
            var start = winRect(), which = edge.getAttribute('data-news-edge');
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

    // A page dropdown opening beside the panel shows over it, until it closes.
    document.addEventListener('show.bs.dropdown', function (e) {
        if (!panel.contains(e.target)) panel.classList.add('is-under');
    });
    document.addEventListener('hidden.bs.dropdown', function () {
        if (!document.querySelector('.dropdown-menu.show')) panel.classList.remove('is-under');
    });

    /* ── boot ──────────────────────────────────────────────── */
    titleSlots(false);
    syncButtons();
    if (prefs.open) openPanel({ instant: true });
    else place();

    window.NewsPanel = {
        open: openPanel, close: closePanel, toggle: toggle,
        isOpen: function () { return opened; },
        mode: function () { return prefs.mode; }, setMode: setMode
    };
}());
