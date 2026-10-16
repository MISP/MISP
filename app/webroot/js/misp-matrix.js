// The Overmind galaxy matrix of the event and value pages: the rail card (a
// pane that caps and scrolls, tactic ticks, folds, galaxy switcher), the
// technique tooltip and popover, and the full matrix modal. A slot with a
// data-url is fetched; one arriving in a lazy panel is mounted as it is.
// The galaxy page draws the full matrix inline, in a [data-mx-inline] host.
(function () {
    'use strict';

    var slot = null;
    var texts = {};
    var cellCache = new WeakMap();
    var tip = null;
    var pop = null;
    var popCell = null;

    function base() {
        return typeof window.baseurl === 'string' ? window.baseurl : '';
    }

    function esc(s) {
        return String(s == null ? '' : s).replace(/[&<>"']/g, function (c) {
            return { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c];
        });
    }

    function say(one, many, n) {
        return (n === 1 ? texts[one] : texts[many] || '').replace('%s', n);
    }

    function el(html) {
        var t = document.createElement('template');
        t.innerHTML = html.trim();
        return t.content.firstElementChild;
    }

    function fetchText(url) {
        return fetch(url, { credentials: 'same-origin', headers: { 'X-Requested-With': 'XMLHttpRequest' } })
            .then(function (r) {
                if (!r.ok) throw new Error('HTTP ' + r.status);
                return r.text();
            });
    }

    function loader() {
        return '<div class="d-flex justify-content-center py-5"><div class="misp-loader" role="status"></div></div>';
    }

    /* ── card ───────────────────────────────────────────────── */
    function card() {
        return slot ? slot.querySelector('[data-matrix-card]') : null;
    }

    function load(url) {
        return fetchText(url).then(function (html) {
            closePop();
            hideTip();
            slot.innerHTML = html;
            ready();
        }, function () {
            if (card()) {
                slot.querySelector('[data-matrix-card]').insertAdjacentHTML('beforeend',
                    '<div class="mx-gate">' + esc(texts.failed || '') + '</div>');
            }
        });
    }

    function ready() {
        var c = card();
        if (!c) return;
        texts = readJson(c.getAttribute('data-mx-text'), {});
        fitPane();
    }

    function readJson(raw, fallback) {
        try {
            return JSON.parse(raw);
        } catch (e) {
            return fallback;
        }
    }

    function visibleGalaxy() {
        var c = card();
        return c ? c.querySelector('.mx-galaxy:not([hidden])') : null;
    }

    // The pane caps only when its natural height clearly exceeds the cap.
    function fitPane() {
        var galaxy = visibleGalaxy();
        if (!galaxy) return;
        var pane = galaxy.querySelector('.mx-pane');
        var strip = galaxy.querySelector('.mx-strip');
        pane.classList.remove('is-capped');
        pane.style.maxHeight = '';
        var cap = Math.round(Math.max(300, Math.min(460, window.innerHeight * 0.5)));
        var capped = pane.scrollHeight > cap + 60;
        if (capped) {
            pane.classList.add('is-capped');
            pane.style.maxHeight = cap + 'px';
        }
        strip.hidden = false;
        spy();
    }

    function spy() {
        var galaxy = visibleGalaxy();
        if (!galaxy) return;
        var pane = galaxy.querySelector('.mx-pane');
        var wrap = galaxy.querySelector('.mx-pane-wrap');
        if (!pane.classList.contains('is-capped')) {
            wrap.classList.remove('has-more');
            galaxy.querySelectorAll('.mx-tick').forEach(function (t) {
                t.removeAttribute('aria-current');
            });
            return;
        }
        var top = pane.scrollTop;
        var atEnd = top + pane.clientHeight >= pane.scrollHeight - 2;
        wrap.classList.toggle('has-more', !atEnd);
        var sections = pane.querySelectorAll('.mx-tactic');
        var active = 0;
        sections.forEach(function (s, i) {
            if (s.offsetTop - pane.offsetTop <= top + 4) active = i;
        });
        if (atEnd && top > 0) active = sections.length - 1;
        galaxy.querySelectorAll('.mx-tick').forEach(function (t, i) {
            t.setAttribute('aria-current', i === active ? 'true' : 'false');
        });
    }

    function pickGalaxy(id) {
        var c = card();
        c.querySelectorAll('.mx-galaxy').forEach(function (g) {
            g.hidden = g.getAttribute('data-mx-galaxy') !== id;
        });
        c.querySelectorAll('[data-mx-galaxy-pick]').forEach(function (b) {
            b.setAttribute('aria-pressed', b.getAttribute('data-mx-galaxy-pick') === id ? 'true' : 'false');
        });
        var galaxy = visibleGalaxy();
        c.querySelector('[data-mx-sub]').textContent = galaxy.getAttribute('data-mx-sub-text');
        c.querySelector('[data-mx-icon]').className = 'fas fa-' + galaxy.getAttribute('data-mx-icon-name');
        fitPane();
    }

    /* ── cell facts ─────────────────────────────────────────── */
    function scopeOf(cell) {
        return cell.closest('[data-matrix-card], .mx-full');
    }

    function factsOf(cell) {
        var scope = scopeOf(cell);
        if (!cellCache.has(scope)) {
            var script = scope.querySelector('script[data-mx-cells]');
            cellCache.set(scope, script ? readJson(script.textContent, []) : []);
        }
        return cellCache.get(scope)[+cell.getAttribute('data-i')] || {};
    }

    function originsOf() {
        var c = card();
        var origins = {};
        if (!c) return origins;
        c.querySelectorAll('.mx-badge').forEach(function (b) {
            origins[b.textContent.replace('#', '').trim()] = b.outerHTML;
        });
        return origins;
    }

    function badge(id) {
        return originsOf()[String(id)] || '<span class="badge mx-badge text-bg-secondary">#' + esc(id) + '</span>';
    }

    function stateLines(f) {
        var out = '';
        if (f.e) {
            out += '<li class="mx-tip-l"><span class="mx-sw"></span>'
                + esc(f.k > 0 ? say('eventOne', 'eventMany', f.k) : texts.onEvent) + '</li>';
        }
        if (f.n > 0) {
            out += '<li class="mx-tip-l"><span class="mx-sw is-ind"></span>'
                + esc(f.e ? say('onOne', 'onMany', f.n) : say('onlyOne', 'onlyMany', f.n)) + '</li>';
        }
        if (f.u > 0 && !f.c) out += '<li class="text-muted">' + esc(say('throughOne', 'throughMany', f.u)) + '</li>';
        (f.f || []).forEach(function (id) {
            out += '<li class="mx-tip-l">' + badge(id) + '</li>';
        });
        return out;
    }

    /* ── tooltip ────────────────────────────────────────────── */
    function tipHtml(f) {
        return '<b>' + esc(f.l) + '</b>'
            + (f.t ? '<span class="mx-tid">' + esc(f.t) + '</span>' : '')
            + (f.p ? '<div>' + esc((texts.subOf || '').replace('%s', f.p)) + '</div>' : '')
            + '<ul class="list-unstyled m-0">' + stateLines(f) + '</ul>';
    }

    function place(box, anchor, gap) {
        var r = anchor.getBoundingClientRect();
        var w = box.offsetWidth;
        var h = box.offsetHeight;
        var vw = document.documentElement.clientWidth;
        var left = Math.max(8, Math.min(r.right - w, vw - w - 8));
        var top = r.bottom + gap;
        if (top + h > window.innerHeight - 8 && r.top - gap - h > 8) top = r.top - gap - h;
        box.style.left = (left + window.scrollX) + 'px';
        box.style.top = (top + window.scrollY) + 'px';
    }

    function showTip(target, html) {
        hideTip();
        tip = el('<div class="mx-tip" role="tooltip"></div>');
        tip.innerHTML = html;
        document.body.appendChild(tip);
        var c = target.closest('[data-matrix-card]');
        var r = target.getBoundingClientRect();
        var cr = c ? c.getBoundingClientRect() : null;
        if (cr && cr.left - tip.offsetWidth - 10 > 8) {
            var top = Math.min(Math.max(8, r.top + r.height / 2 - tip.offsetHeight / 2), window.innerHeight - tip.offsetHeight - 8);
            tip.style.left = (cr.left - tip.offsetWidth - 10 + window.scrollX) + 'px';
            tip.style.top = (top + window.scrollY) + 'px';
        } else {
            place(tip, target, 6);
        }
    }

    function hideTip() {
        if (tip) {
            tip.remove();
            tip = null;
        }
    }

    /* ── popover ────────────────────────────────────────────── */
    function closePop() {
        if (pop) {
            pop.remove();
            pop = null;
        }
        if (popCell) {
            popCell.classList.remove('is-open');
            popCell.setAttribute('aria-expanded', 'false');
            popCell = null;
        }
    }

    function clusterUrl(id) {
        return base() + '/galaxy_clusters/view/' + encodeURIComponent(id);
    }

    function openPop(cell) {
        var f = factsOf(cell);
        closePop();
        hideTip();
        var acts = '';
        if (f.n > 0 && f.g && texts.showOne) {
            acts += '<button type="button" class="mx-pop-act" data-mx-show><i class="misp-icon misp-icon-attribute misp-simple"></i>'
                + esc(say('showOne', 'showMany', f.n)) + '</button>';
        }
        if (f.c) {
            acts += '<a class="mx-pop-act" href="' + esc(clusterUrl(f.c)) + '"><i class="fas fa-arrow-up-right-from-square"></i>'
                + esc(texts.open) + '</a>';
        } else {
            (f.s || []).forEach(function (sub) {
                acts += '<a class="mx-pop-act" href="' + esc(clusterUrl(sub[2])) + '"><i class="fas fa-arrow-up-right-from-square"></i><span>'
                    + esc((texts.openSub || '').replace('%s', sub[0])) + ' <span class="mx-tid">' + esc(sub[1]) + '</span></span></a>';
            });
        }
        pop = el('<div class="mx-pop" data-matrix-popover role="dialog"></div>');
        pop.setAttribute('aria-label', f.l || '');
        pop.innerHTML = '<div class="mx-pop-h"><div class="mx-pop-t">' + esc(f.l)
            + (f.t ? '<span class="mx-tid">' + esc(f.t) + (f.p ? ' · ' + esc((texts.subOf || '').replace('%s', f.p)) : '') + '</span>' : '')
            + '</div><button type="button" class="mx-pop-x" aria-label="' + esc(texts.close) + '"><i class="fas fa-xmark"></i></button></div>'
            + '<ul class="mx-pop-facts">' + stateLines(f) + '</ul>'
            + (acts ? '<div class="mx-pop-acts">' + acts + '</div>' : '');
        pop._facts = f;
        document.body.appendChild(pop);
        place(pop, cell, 6);
        popCell = cell;
        cell.classList.add('is-open');
        cell.setAttribute('aria-expanded', 'true');
        var first = pop.querySelector('.mx-pop-act');
        if (first) first.focus({ preventScroll: true });
    }

    function showIndicators(f) {
        var overview = window.MispEventOverview;
        if (!overview || !f.g) return;
        var modal = document.getElementById('mx-modal');
        if (modal && modal.classList.contains('show') && window.bootstrap) {
            window.bootstrap.Modal.getOrCreateInstance(modal).hide();
        }
        overview.openFiltered(f.o * 2 >= f.n ? 'attributes' : 'objects', { tags: f.g });
    }

    /* ── full matrix modal ──────────────────────────────────── */
    function modal() {
        return document.getElementById('mx-modal');
    }

    function loadFull(galaxyId, tab) {
        var c = card();
        var m = modal();
        if (!c || !m) return;
        var body = m.querySelector('[data-mx-modal-body]');
        var pane = c.querySelector('.mx-galaxy[data-mx-galaxy="' + galaxyId + '"]');
        if (pane) {
            m.querySelector('[data-mx-modal-title]').textContent = pane.getAttribute('data-mx-name');
            m.querySelector('[data-mx-modal-icon]').className = 'fas fa-' + pane.getAttribute('data-mx-icon-name');
        }
        m.querySelectorAll('[data-mx-full-pick]').forEach(function (b) {
            b.setAttribute('aria-pressed', b.getAttribute('data-mx-full-pick') === galaxyId ? 'true' : 'false');
        });
        closePop();
        body.innerHTML = loader();
        var url = c.getAttribute('data-mx-full-url').replace('%s', encodeURIComponent(galaxyId))
            + (tab ? '?tab=' + encodeURIComponent(tab) : '');
        fetchText(url).then(function (html) {
            body.innerHTML = html;
        }, function () {
            body.innerHTML = '<div class="mx-full-empty">' + esc(texts.failed) + '</div>';
        });
    }

    function loadInline(host, tab) {
        var body = host.querySelector('[data-mx-inline-body]');
        closePop();
        hideTip();
        body.innerHTML = loader();
        var url = host.getAttribute('data-url') + (tab ? '?tab=' + encodeURIComponent(tab) : '');
        fetchText(url).then(function (html) {
            var fresh = el(html).querySelector('[data-mx-inline-body]');
            if (fresh) body.replaceWith(fresh);
        }, function () {
            body.innerHTML = '<div class="mx-full-empty">' + esc(texts.failed) + '</div>';
        });
    }

    function openFull() {
        var c = card();
        var m = modal();
        if (!c || !m || !window.bootstrap) return;
        var galaxies = Array.prototype.map.call(c.querySelectorAll('.mx-galaxy'), function (g) {
            return { id: g.getAttribute('data-mx-galaxy'), name: g.getAttribute('data-mx-name') };
        });
        var picks = m.querySelector('[data-mx-modal-galaxies]');
        picks.hidden = galaxies.length < 2;
        picks.innerHTML = galaxies.length < 2 ? '' : galaxies.map(function (g) {
            return '<button type="button" class="mx-full-tab" data-mx-full-pick="' + esc(g.id) + '">' + esc(g.name) + '</button>';
        }).join('');
        loadFull(visibleGalaxy().getAttribute('data-mx-galaxy'), null);
        window.bootstrap.Modal.getOrCreateInstance(m).show();
    }

    var HIDE_UNUSED = 'misp-matrix-hide-unused';
    var HIDE_UNUSED_INLINE = 'misp-matrix-inline-hide-unused';

    function hideUnused(m, on) {
        m.classList.toggle('mx-hide-unused', on);
        var box = m.querySelector('[data-mx-hide-unused]');
        if (box) box.checked = on;
    }

    function savedHideUnused(key, fallback) {
        try {
            var saved = window.localStorage.getItem(key);
            return saved === null ? fallback : saved === '1';
        } catch (e) {
            return fallback;
        }
    }

    /* ── events ─────────────────────────────────────────────── */
    function onClick(e) {
        var t = e.target;
        if (pop && t.closest('.mx-pop-x')) {
            var back = popCell;
            closePop();
            if (back) back.focus();
            return;
        }
        if (pop && t.closest('[data-mx-show]')) {
            var facts = pop._facts;
            closePop();
            showIndicators(facts);
            return;
        }
        if (pop && !pop.contains(t) && !t.closest('[data-matrix-cell]')) closePop();

        var hit;
        if ((hit = t.closest('.mx-fold'))) {
            var open = hit.getAttribute('aria-expanded') !== 'true';
            hit.setAttribute('aria-expanded', String(open));
            hit.closest('.mx-row').nextElementSibling.hidden = !open;
            closePop();
            spy();
        } else if ((hit = t.closest('[data-matrix-cell]'))) {
            if (popCell === hit) closePop();
            else openPop(hit);
        } else if ((hit = t.closest('[data-matrix-full]'))) {
            openFull();
        } else if ((hit = t.closest('[data-mx-galaxy-pick]'))) {
            pickGalaxy(hit.getAttribute('data-mx-galaxy-pick'));
        } else if ((hit = t.closest('.mx-tick'))) {
            var galaxy = hit.closest('.mx-galaxy');
            var pane = galaxy.querySelector('.mx-pane');
            var section = pane.querySelector('.mx-tactic[data-t="' + hit.getAttribute('data-t') + '"]');
            var smooth = window.matchMedia('(prefers-reduced-motion: reduce)').matches ? 'auto' : 'smooth';
            if (pane.classList.contains('is-capped')) {
                pane.scrollTo({ top: section.offsetTop - pane.offsetTop, behavior: smooth });
            } else {
                section.scrollIntoView({ block: 'nearest', behavior: smooth });
            }
        } else if ((hit = t.closest('[data-mx-rollup]'))) {
            hit.disabled = true;
            load(hit.getAttribute('data-mx-rollup')).then(function () {
                document.dispatchEvent(new CustomEvent('misp:overview-rolled-up', { detail: { source: 'matrix' } }));
            });
        } else if ((hit = t.closest('[data-mx-tab-pick]'))) {
            var inline = hit.closest('[data-mx-inline]');
            var full = hit.closest('.mx-full');
            if (inline) loadInline(inline, hit.getAttribute('data-mx-tab-pick'));
            else loadFull(full.getAttribute('data-mx-full-galaxy'), hit.getAttribute('data-mx-tab-pick'));
        } else if ((hit = t.closest('[data-mx-full-pick]'))) {
            loadFull(hit.getAttribute('data-mx-full-pick'), null);
        }
    }

    function onChange(e) {
        var box = e.target.closest && e.target.closest('[data-mx-hide-unused]');
        if (!box) return;
        closePop();
        var container = box.closest('.mx-modal, [data-mx-inline]');
        hideUnused(container, box.checked);
        try {
            window.localStorage.setItem(container.hasAttribute('data-mx-inline') ? HIDE_UNUSED_INLINE : HIDE_UNUSED,
                box.checked ? '1' : '0');
        } catch (err) {
            // Not remembered, still applied
        }
    }

    function onOver(e) {
        if (pop) return;
        var t = e.target.closest && e.target.closest('[data-matrix-cell], .mx-tick');
        if (!t || !t.closest('[data-matrix-card], #mx-modal, [data-mx-inline]')) return;
        if (t.classList.contains('mx-tick')) {
            var n = +t.getAttribute('data-n');
            showTip(t, '<b>' + esc(t.getAttribute('aria-label')) + '</b>' + esc(say('tickOne', 'tickMany', n)));
        } else {
            showTip(t, tipHtml(factsOf(t)));
        }
    }

    function onOut(e) {
        var t = e.target.closest && e.target.closest('[data-matrix-cell], .mx-tick');
        if (t && !t.contains(e.relatedTarget)) hideTip();
    }

    function onKey(e) {
        if (e.key !== 'Escape') return;
        hideTip();
        if (pop) {
            // Ahead of the modal's own Escape, which would close it under the popover
            e.stopPropagation();
            e.preventDefault();
            var back = popCell;
            closePop();
            if (back) back.focus();
        }
    }

    function onScroll(e) {
        if (!e.target.closest) return;
        if (e.target.closest('[data-matrix-card], #mx-modal, [data-mx-inline]')) {
            hideTip();
            closePop();
            if (e.target.classList && e.target.classList.contains('mx-pane')) spy();
        }
    }

    function reload() {
        if (slot && slot.hasAttribute('data-url')) load(slot.getAttribute('data-url'));
    }

    var wired = false;

    function mount(target) {
        slot = target;
        var m = slot.parentElement.querySelector('.mx-modal') || modal();
        if (m && m.parentElement !== document.body) {
            var old = modal();
            if (old && old !== m) old.remove();
            document.body.appendChild(m);
            m.addEventListener('hidden.bs.modal', closePop);
            hideUnused(m, savedHideUnused(HIDE_UNUSED, true));
        }
        wire();
        if (slot.hasAttribute('data-url')) reload();
        else ready();
    }

    function mountInline(host) {
        texts = readJson(host.getAttribute('data-mx-text'), {});
        hideUnused(host, savedHideUnused(HIDE_UNUSED_INLINE, false));
        wire();
    }

    function wire() {
        if (wired) return;
        wired = true;
        document.addEventListener('click', onClick);
        document.addEventListener('change', onChange);
        document.addEventListener('mouseover', onOver);
        document.addEventListener('mouseout', onOut);
        document.addEventListener('keydown', onKey, true);
        document.addEventListener('scroll', onScroll, true);
        window.addEventListener('resize', function () {
            closePop();
            fitPane();
        });
        document.addEventListener('misp:attributes-changed', reload);
        document.addEventListener('misp:overview-rolled-up', function (e) {
            if (!e.detail || e.detail.source !== 'matrix') reload();
        });
        // A card that arrived in a hidden tab measured nothing
        document.addEventListener('shown.bs.tab', fitPane);
    }

    function boot() {
        var target = document.querySelector('[data-mx-slot]');
        if (target) mount(target);
        var inline = document.querySelector('[data-mx-inline]');
        if (inline) mountInline(inline);
        document.addEventListener('misp:container-loaded', function (e) {
            var arrived = e.target.querySelector && e.target.querySelector('[data-mx-slot]');
            if (arrived) mount(arrived);
            var arrivedInline = e.target.querySelector && e.target.querySelector('[data-mx-inline]');
            if (arrivedInline) mountInline(arrivedInline);
        });
    }

    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', boot);
    } else {
        boot();
    }
})();
