// Side panels: drawers over an Overmind page that a navbar button or a key
// shows and hides (the news, the bookmarks). They behave like the analyst
// graph dock (intel-graph-dock.js). Docked, a panel lies against the right
// edge, full height under the navbar, as wide as the user drags it; undocked,
// it is a window moved by its head and resized from its edges, kept as the
// corner it is nearest to. One thing docks at a time: a panel docking closes
// the other docked panels and the graph dock, whose docking closes them.
// Open or closed, docked or floating, the width and the window are remembered
// per viewer in localStorage.
//
// Markup: Elements/side_panel.ctp. A panel's own script calls
// MispSidePanel.create(id, options) and gets the panel's controller back:
//   options.key       localStorage key
//   options.shortcut  the key that shows or hides it
//   options.onLoad    (body) after the body is filled from the aside's data-url
//   options.beforeLoad  () before the body is replaced
//   options.onClose   ()
//   options.focus     selector of what takes the focus when it is opened
//                     from the keyboard, while that is on screen
//   options.forms     { match: RegExp whose group 1 is add|edit|deleteSelection,
//                       messages: { add, edit, deleteSelection } } for the forms
//                       the panel opens in #mainModal: they are sent from here,
//                       so the page underneath stays as it is
(function () {
    'use strict';

    var MIN_W = 320;
    var PAGE_MIN = 480;
    var STEP = 24;
    var GUTTER = 12, MIN_FW = 340, MIN_FH = 280, SNAP = 16;

    var html = document.documentElement;
    var panels = [];

    function viewport() { return html.clientWidth || window.innerWidth; }
    var navTop = 58;
    function measureNav() {
        var bar = document.querySelector('.rc-bar, .rail-bar');
        if (bar) navTop = Math.max(0, Math.round(bar.getBoundingClientRect().bottom));
        return navTop;
    }
    function reducedMotion() {
        return window.matchMedia && window.matchMedia('(prefers-reduced-motion: reduce)').matches;
    }
    function typing(t) {
        return !!t && (t.isContentEditable || /^(INPUT|TEXTAREA|SELECT)$/.test(t.tagName));
    }

    // The right edge holds one docked thing at a time.
    function yieldEdge(except) {
        panels.forEach(function (p) {
            if (p !== except && p.isOpen() && p.mode() === 'docked') p.close();
        });
        var dock = window.IntelGraphDock;
        if (dock && dock.isOpen() && dock.mode() === 'docked') dock.close();
    }
    document.addEventListener('intel-graph:docked', function () {
        panels.forEach(function (p) { if (p.isOpen() && p.mode() === 'docked') p.close(); });
    });
    // Toasts stay clear of whichever panel is docked.
    function syncDocked() {
        var docked = panels.filter(function (p) { return p.isOpen() && p.mode() === 'docked'; })[0];
        html.classList.toggle('sp-docked', !!docked);
        if (docked) html.style.setProperty('--sp-docked-w', docked.width() + 'px');
    }

    /* ── the forms a panel opens ───────────────────────────── */
    var formOwner = null;   // { panel, url } while a panel's modal is up
    var modalEl = document.getElementById('mainModal');
    if (modalEl) modalEl.addEventListener('hidden.bs.modal', function () { formOwner = null; });
    document.addEventListener('submit', function (e) {
        var form = e.target;
        if (!formOwner || !modalEl || !modalEl.contains(form)) return;
        var forms = formOwner.panel.options.forms;
        var kind = forms && (forms.match.exec(form.getAttribute('action') || '') || [])[1];
        if (!kind) return;
        e.preventDefault();
        sendForm(formOwner, form, kind);
    });
    function sendForm(owner, form, kind) {
        var panel = owner.panel;
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
            var shown = window.bootstrap && window.bootstrap.Modal.getInstance(modalEl);
            if (shown) shown.hide();
            var messages = panel.options.forms.messages || {};
            var done = kind === 'deleteSelection' ? (data.message || messages.deleteSelection) : messages[kind];
            if (done && typeof showToast === 'function') showToast(done, 'success');
            panel.load();
        }).catch(function (data) {
            if (submit) submit.disabled = false;
            if (typeof showToast === 'function') showToast(errorText(data, panel.text.saveFailed), 'danger');
            renewToken(owner.url, form);
        });
    }
    function errorText(data, fallback) {
        var list = [];
        (function walk(v) {
            if (Array.isArray(v)) v.forEach(walk);
            else if (v && typeof v === 'object') Object.keys(v).forEach(function (k) { walk(v[k]); });
            else if (v) list.push(String(v));
        })(data && data.errors);
        return list.length ? list.join(' ') : ((data && data.message) || fallback);
    }
    // The tokens a refused post carried are spent; the form stays up for
    // another try, so it takes the ones of a freshly rendered copy.
    function renewToken(url, form) {
        fetch(url, { credentials: 'same-origin', headers: { 'X-Requested-With': 'XMLHttpRequest' } })
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

    /* ── one panel ─────────────────────────────────────────── */
    function create(id, options) {
        var panel = document.getElementById(id);
        if (!panel) return null;
        options = options || {};
        var find = function (sel) { return panel.querySelector(sel); };
        var body = find('[data-sp-body]');
        var grip = find('[data-sp-grip]');
        var head = find('.sp-head');
        var moveHandle = find('[data-sp-move]');
        var widenBtn = find('[data-sp-widen]');
        var undockBtn = find('[data-sp-undock]');
        var dockBtn = find('[data-sp-dock]');
        var edges = Array.prototype.slice.call(panel.querySelectorAll('[data-sp-edge]'));
        var seEdge = find('[data-sp-edge="se"]');
        var sayEl = find('[data-sp-say]');
        var shortcut = options.shortcut || '';
        var text = {};
        try { text = JSON.parse(find('[data-sp-text]').textContent); } catch (e) { /* English below */ }
        text = Object.assign({
            shortcut: shortcut.toUpperCase() + ' shows or hides it', widen: 'Widen the panel', narrow: 'Back to your width',
            undocked: 'Undocked into a window.', docked: 'Docked to the right.',
            failed: 'Failed to load.', retry: 'Try again', saveFailed: 'It could not be saved.'
        }, text);

        function say(message) {
            sayEl.textContent = '';
            setTimeout(function () { sayEl.textContent = message; }, 50);
        }

        /* what is remembered, per viewer */
        var prefs = { open: false, width: 0, wide: false, mode: 'docked', win: null };
        try {
            var saved = JSON.parse(window.localStorage.getItem(options.key));
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
                window.localStorage.setItem(options.key, JSON.stringify({
                    open: prefs.open, width: prefs.width, wide: prefs.wide, mode: prefs.mode, win: prefs.win
                }));
            } catch (e) { /* kept for this page only */ }
        }

        /* docked: the width */
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

        /* undocked: one rectangle, kept as the corner it is nearest to and its
           distance from that corner, always inside the viewport, under the navbar */
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
            panel.style.setProperty('--sp-w', w + 'px');
            html.style.setProperty('--sp-top', measureNav() + 'px');
            panel.classList.toggle('is-floating', float);
            if (float) {
                var rect = drag || winRect();
                panel.style.setProperty('--sp-fw-left', rect.left + 'px');
                panel.style.setProperty('--sp-fw-top', rect.top + 'px');
                panel.style.setProperty('--sp-fw-w', rect.w + 'px');
                panel.style.setProperty('--sp-fw-h', rect.h + 'px');
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
            syncDocked();
        }
        var placing = 0;
        function placeSoon() {
            if (placing) return;
            placing = window.requestAnimationFrame(function () { placing = 0; place(); });
        }

        /* the navbar button */
        function slots() { return document.querySelectorAll('[data-side-panel-slot="' + id + '"]'); }
        function buttons() { return document.querySelectorAll('[data-side-panel-toggle="' + id + '"]'); }
        function syncButtons() {
            buttons().forEach(function (b) {
                b.setAttribute('aria-expanded', opened ? 'true' : 'false');
                var side = b.querySelector('.sp-slot-side');
                if (side) side.className = 'fas ' + (floating() ? 'fa-window-restore' : 'fa-angles-left') + ' sp-slot-side';
            });
        }
        function titleSlots() {
            slots().forEach(function (slot) {
                var b = slot.querySelector('[data-side-panel-toggle]');
                var label = b ? b.getAttribute('aria-label') : '';
                slot.title = label + (shortcut ? ' — ' + text.shortcut : '');
                if (b && shortcut) b.setAttribute('aria-keyshortcuts', shortcut.toUpperCase());
            });
        }
        // The badge on the button; without one it is called by its name.
        function setCount(n) {
            slots().forEach(function (slot) {
                var count = slot.querySelector('[data-side-panel-count]');
                if (count) {
                    count.textContent = n ? String(n) : '';
                    count.hidden = !n;
                }
                slot.toggleAttribute('data-has-count', !!n);
                var b = slot.querySelector('[data-side-panel-toggle]');
                var name = slot.querySelector('.rc-chip-name, .rail-graph-name');
                if (!n && b && name) b.setAttribute('aria-label', name.textContent.trim());
            });
            titleSlots();
        }

        /* the body, from the aside's data-url */
        var loaded = false;
        var loading = null;
        function fetchHtml(url) {
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
            var url = panel.getAttribute('data-url');
            if (!url) return Promise.resolve();
            if (loading) return loading;
            if (!loaded) showLoading();
            loading = fetchHtml(url).then(function (out) {
                if (options.beforeLoad) options.beforeLoad();
                body.innerHTML = out;
                loaded = true;
                if (options.onLoad) options.onLoad(body);
            }).catch(function () {
                if (options.beforeLoad) options.beforeLoad();
                showError(text.failed, function () { loaded = false; load(); });
            }).then(function () { loading = null; });
            return loading;
        }
        function showLoading() {
            body.innerHTML = '<div class="sp-loading" role="status"><div class="misp-loader" aria-hidden="true"></div></div>';
        }
        function showError(message, retry) {
            body.innerHTML = '';
            var box = document.createElement('div');
            box.className = 'sp-error';
            box.setAttribute('role', 'alert');
            var p = document.createElement('p');
            p.textContent = message;
            box.appendChild(p);
            if (retry) {
                var again = document.createElement('button');
                again.type = 'button';
                again.className = 'btn btn-sm btn-outline-secondary';
                again.textContent = text.retry;
                again.addEventListener('click', retry);
                box.appendChild(again);
            }
            body.appendChild(box);
        }
        function openModalFor(url, size) {
            if (typeof openModal !== 'function') return;
            formOwner = { panel: api, url: url };
            openModal(url, size || 'lg');
        }

        /* open, close */
        var opened = false;
        var closeTimer = 0;
        function openPanel(opts) {
            opts = opts || {};
            if (opened) { if (opts.focus) focusInto(); return; }
            if (!floating()) yieldEdge(api);
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
            // Each open shows the content as it is now.
            load();
            if (opts.focus) focusInto();
        }
        function closePanel(opts) {
            if (!opened) return;
            opened = false;
            prefs.open = false;
            remember();
            if (options.onClose) options.onClose();
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
        function toggle(byShortcut) {
            if (opened) { closePanel({ focusButton: panel.contains(document.activeElement) }); return; }
            // The rail's phone drawer would stay over the panel.
            var railToggle = document.querySelector('.rail-nav.is-drawer .rail-toggle');
            if (railToggle) railToggle.click();
            // Focus moves in only when the button was worked from the keyboard,
            // or the shortcut opened a panel with somewhere to type.
            openPanel({ focus: keyboardIntent || (byShortcut === true && !!options.focus) });
            keyboardIntent = false;
        }
        var keyboardIntent = false;
        document.addEventListener('keydown', function (e) {
            if ((e.key === 'Enter' || e.key === ' ') && e.target.closest
                && e.target.closest('[data-side-panel-toggle="' + id + '"]')) keyboardIntent = true;
        }, true);
        function focusInto() {
            var own = options.focus && find(options.focus);
            var target = own && own.offsetParent !== null ? own
                : floating() ? moveHandle : find('.sp-tools .sp-tool:not([hidden])') || find('[data-sp-close]');
            target.focus({ preventScroll: true });
        }

        buttons().forEach(function (b) {
            b.addEventListener('click', function (e) {
                e.preventDefault();
                toggle();
            });
        });
        find('[data-sp-close]').addEventListener('click', function () { closePanel({ focusButton: true }); });
        panel.addEventListener('keydown', function (e) {
            if (e.key !== 'Escape') return;
            e.preventDefault();
            closePanel({ focusButton: true });
        });
        panel.addEventListener('click', function (e) {
            var modal = e.target.closest('[data-sp-modal]');
            if (modal) openModalFor(modal.getAttribute('data-sp-modal'), modal.getAttribute('data-sp-modal-size'));
        });

        // The shortcut shows or hides the panel, unless the key is typed into a
        // field, taken by the control it was pressed on, or pressed behind a
        // modal or the game.
        if (shortcut) {
            document.addEventListener('keydown', function (e) {
                if (e.defaultPrevented || e.repeat || e.isComposing || e.ctrlKey || e.metaKey || e.altKey) return;
                if (String(e.key).toLowerCase() !== shortcut || typing(e.target)) return;
                if (document.querySelector('.modal.show, .mi-overlay')) return;
                e.preventDefault();
                toggle(true);
            });
        }

        /* docked: resizing */
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

        /* undocking */
        function setMode(mode) {
            if (prefs.mode === mode) return;
            prefs.mode = mode;
            if (mode === 'floating' && !prefs.win) prefs.win = defaultWin();
            if (opened && mode === 'docked') yieldEdge(api);
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
            if (!t.closest('[data-sp-move]') && t.closest('button, a, input')) return;
            var start = winRect();
            track(e, head, 'is-moving', function (ex, ey) { return clampMove(start, ex, ey); });
        });
        edges.forEach(function (edge) {
            edge.addEventListener('pointerdown', function (e) {
                if (e.button !== 0) return;
                e.stopPropagation();
                var start = winRect(), which = edge.getAttribute('data-sp-edge');
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

        var api = {
            id: id, el: panel, body: body, text: text, options: options,
            open: openPanel, close: closePanel, toggle: toggle, setMode: setMode,
            isOpen: function () { return opened; },
            mode: function () { return prefs.mode; },
            width: width,
            load: load, fetch: fetchHtml, showLoading: showLoading, showError: showError,
            openModal: openModalFor, setCount: setCount
        };
        panels.push(api);

        /* boot */
        titleSlots();
        syncButtons();
        // A panel left open comes back, unless one booted before it holds the edge.
        var edgeTaken = !floating() && panels.some(function (p) {
            return p !== api && p.isOpen() && p.mode() === 'docked';
        });
        if (prefs.open && !edgeTaken) openPanel({ instant: true });
        else {
            if (prefs.open) { prefs.open = false; remember(); }
            place();
        }
        return api;
    }

    window.MispSidePanel = { create: create };
}());
