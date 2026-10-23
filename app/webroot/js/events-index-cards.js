/* Overmind events index — the +N on each one-line context lane, the context
   popover it opens (card and table alike), the sharing group badges and
   their popover, and the selection state of the cards. */
(function () {
    'use strict';

    if (window.eventIndexCards) {
        window.eventIndexCards.scan();
        return;
    }

    var GAP = 4;

    function $$(s, r) { return Array.prototype.slice.call((r || document).querySelectorAll(s)); }

    /* ---------- a lane's chips to its width, the rest behind +N ---------- */
    // Every lane is reset, then every lane measured: interleaving the two
    // forces a layout of the whole page per lane.
    function fitLanes(lanes) {
        var todo = [];
        lanes.forEach(function (lane) {
            var more = lane.querySelector('.dk-more');
            if (!more) {
                return;
            }
            var chips = $$('.dk-chip', lane);
            chips.forEach(function (c) { c.hidden = false; c.style.maxWidth = ''; });
            more.hidden = true;
            todo.push({ lane: lane, more: more, chips: chips });
        });
        todo = todo.filter(function (t) {
            t.width = t.lane.clientWidth;
            if (!t.width || t.lane.scrollWidth <= t.width) {
                return false;
            }
            var lead = t.lane.querySelector('.te-tn');
            t.leadWidth = lead ? lead.offsetWidth + GAP : 0;
            t.widths = t.chips.map(function (c) { return c.offsetWidth; });
            return true;
        });
        todo.forEach(function (t) {
            t.more.textContent = '+' + t.chips.length;
            t.more.hidden = false;
        });
        todo.forEach(function (t) { t.reserve = t.more.offsetWidth + GAP; });
        todo.forEach(function (t) {
            t.more.hidden = true;
            placeChips(t.more, t.chips, t.widths, t.width, t.leadWidth, t.reserve);
        });
    }

    function placeChips(more, chips, widths, width, leadWidth, reserve) {
        var used = leadWidth, keep = 0;
        for (var i = 0; i < chips.length; i++) {
            var w = widths[i];
            if (i > 0 && used + w + reserve > width) {
                break;
            }
            used += w + GAP;
            keep++;
        }
        var rest = chips.length - keep;
        chips.forEach(function (c, j) { if (j >= keep) c.hidden = true; });
        if (!rest) {
            if (used - GAP > width) chips[0].style.maxWidth = Math.max(24, width - leadWidth) + 'px';
            return;
        }
        if (keep === 1 && used + reserve - GAP > width) {
            // A technique id is never clipped: it moves into +N.
            if (chips[0].classList.contains('is-tid')) {
                chips[0].hidden = true;
                rest++;
            } else {
                chips[0].style.maxWidth = Math.max(24, width - leadWidth - reserve) + 'px';
            }
        }
        more.hidden = false;
        more.textContent = '+' + rest;
    }

    /* ---------- a sharing group's name to the room its badge has ---------- */
    var NAME_MIN = 40, DIST_CAP = 176;
    var measure = document.createElement('canvas').getContext('2d');

    function fontOf(el) {
        var cs = getComputedStyle(el);
        return cs.fontStyle + ' ' + cs.fontWeight + ' ' + cs.fontSize + ' ' + cs.fontFamily;
    }
    function textWidth(s, font) {
        measure.font = font;
        return measure.measureText(s).width;
    }
    // The head and the tail survive: sibling groups tend to differ at the end.
    function midTrunc(s, max, font) {
        if (textWidth(s, font) <= max) return s;
        for (var n = s.length - 1; n >= 3; n--) {
            var head = Math.ceil(n * 0.58);
            var t = s.slice(0, head).replace(/\s+$/, '') + '…' + s.slice(s.length - (n - head)).replace(/^\s+/, '');
            if (textWidth(t, font) <= max) return t;
        }
        return '';
    }
    function hpad(el) {
        var cs = getComputedStyle(el);
        return parseFloat(cs.paddingLeft) + parseFloat(cs.paddingRight);
    }
    // Everything in the named badge but its name.
    function chromeOf(chip) {
        var icon = chip.classList.contains('is-icon');
        chip.classList.remove('is-icon');
        var cs = getComputedStyle(chip);
        var w = hpad(chip) + parseFloat(cs.borderLeftWidth) + parseFloat(cs.borderRightWidth)
            + (parseFloat(getComputedStyle(chip.firstElementChild).width) || 14) + (parseFloat(cs.columnGap) || 0);
        chip.classList.toggle('is-icon', icon);
        return w;
    }
    // A card footer's auto margins are its free room, so only the siblings'
    // own widths count against the badge (and the 10px it keeps from them).
    function roomIn(chip, chrome) {
        var box = chip.parentElement;
        if (!box.clientWidth) return null;
        var room = box.clientWidth - hpad(box);
        if (box.classList.contains('dk-foot')) {
            Array.prototype.forEach.call(box.children, function (c) {
                if (c !== chip) room -= c.offsetWidth;
            });
            room -= 10;
        }
        return room - chrome;
    }

    // Measured with every badge at its smallest, then written: one layout for the lot.
    function fitDist(chips) {
        if (!chips.length) return;
        var chrome = chromeOf(chips[0]);
        var font = fontOf(chips[0].lastElementChild);
        chips.forEach(function (chip) { chip.classList.add('is-icon'); });
        var memo = {};
        chips.map(function (chip) {
            var room = roomIn(chip, chrome);
            if (room === null) return null;
            var name = chip.getAttribute('data-sg-name');
            var key = name + '\u0000' + Math.floor(room);
            if (!(key in memo)) memo[key] = room < NAME_MIN ? '' : midTrunc(name, room, font);
            return memo[key];
        }).forEach(function (text, i) {
            var chip = chips[i];
            chip.lastElementChild.textContent = text || chip.getAttribute('data-sg-name');
            chip.classList.toggle('is-icon', text === '');
        });
    }

    // The width a table's distribution column needs to name its groups in full.
    function distWidth(table) {
        var chips = $$('td.te-c-dist .dk-dist[data-sg-name]', table);
        if (!chips.length) return 0;
        var font = fontOf(chips[0].lastElementChild);
        var longest = 0, seen = {};
        chips.forEach(function (chip) {
            var name = chip.getAttribute('data-sg-name');
            if (seen[name]) return;
            seen[name] = true;
            longest = Math.max(longest, textWidth(name, font));
        });
        var extra = chromeOf(chips[0]) + hpad(chips[0].closest('td'));
        return { want: Math.min(DIST_CAP, Math.ceil(longest + extra) + 1), least: Math.ceil(NAME_MIN + extra) };
    }

    function fitAll(scope) {
        fitLanes($$('.dk-ctx[data-dk-lane]', scope));
        fitDist($$('.dk-card .dk-foot .dk-dist[data-sg-name]', scope));
    }

    function syncSelection(root) {
        var any = false;
        $$('.dk-card', root).forEach(function (card) {
            var box = card.querySelector('.item-checkbox');
            var on = !!(box && box.checked);
            card.classList.toggle('is-selected', on);
            any = any || on;
        });
        $$('.idx-card-grid', root).forEach(function (grid) {
            grid.classList.toggle('dk-selecting', any);
        });
    }

    /* ---------- the popover: a context lane or a sharing group, on hover, pinned on click ---------- */
    var OPEN_MORE = 250, OPEN_LANE = 450, CLOSE = 220;
    var popEl = null, pop = null, openT = null, closeT = null, refocused = null;

    function popElement() {
        if (!popEl) {
            popEl = document.createElement('div');
            popEl.className = 'dk-index dk-pop-float';
            popEl.setAttribute('role', 'dialog');
            popEl.tabIndex = -1;
            popEl.hidden = true;
            document.body.appendChild(popEl);
            popEl.addEventListener('mouseenter', function () { clearTimeout(closeT); });
            popEl.addEventListener('mouseleave', function (e) {
                if (pop && e.relatedTarget && pop.zone.contains(e.relatedTarget)) return;
                scheduleClose();
            });
            popEl.addEventListener('click', function (e) {
                if (e.target.closest('[data-dk-close]')) {
                    closePop(true);
                    return;
                }
                var v = e.target.closest('[data-dk-view]');
                if (v && pop) {
                    if (!pop.pinned) pin();
                    fill(v.getAttribute('data-dk-view'));
                    var b = popEl.querySelector('[data-dk-view]');
                    if (b) b.focus({ preventScroll: true });
                }
            });
            popEl.addEventListener('focusout', function (e) {
                if (pop && pop.pinned && e.relatedTarget && !popEl.contains(e.relatedTarget) && !pop.zone.contains(e.relatedTarget)) {
                    closePop();
                }
            });
        }
        return popEl;
    }

    // Where hovering opens a lane: the table cell, or the card's +N alone.
    // A sharing group opens from its badge.
    function zoneOf(el) {
        if (!el || !el.closest('.dk-index') || el.closest('.dk-pop-float')) return null;
        var sg = el.closest('.dk-dist[data-sg-id]');
        if (sg) return sg;
        var cell = el.closest('td.te-lane');
        if (cell && cell.querySelector('.te-ctx[data-dk-lane]')) return cell;
        var more = el.closest('.dk-more');
        return more ? more.closest('.dk-ctx[data-dk-lane], .te-ctx[data-dk-lane]') : null;
    }
    function laneOf(zone) {
        return zone.matches('.dk-ctx, .te-ctx') ? zone : zone.querySelector('.te-ctx[data-dk-lane]');
    }
    function isSg(zone) {
        return zone.matches('.dk-dist[data-sg-id]');
    }
    function hasMore(zone) {
        if (isSg(zone)) return true;
        var lane = laneOf(zone);
        var more = lane.querySelector('.dk-more');
        if (more && !more.hidden) return true;
        return $$('.dk-chip', lane).some(function (c) {
            var s = c.lastElementChild || c;
            return s.scrollWidth > s.clientWidth + 1 || c.scrollWidth > c.clientWidth + 1;
        });
    }
    function cancelTimers() {
        clearTimeout(openT);
        clearTimeout(closeT);
        openT = closeT = null;
        sgWanted = null;
    }

    function fill(view) {
        var el = popElement();
        var tpl = pop.root.querySelector('template.dk-ctx-tpl');
        el.innerHTML = '';
        if (!tpl) return;
        var body = tpl.content.firstElementChild.cloneNode(true);
        var label = '';
        $$('.dk-pop-sec', body).forEach(function (sec) {
            var mine = sec.getAttribute('data-dk-lane') === pop.lane;
            if (mine) label = sec.querySelector('h4').textContent.replace(/\s*\d+$/, '').trim();
            if (view === 'all') sec.classList.toggle('is-focus', mine);
            else if (!mine) sec.remove();
        });
        var foot = document.createElement('div');
        foot.className = 'dk-pop-foot';
        foot.innerHTML = view === 'all'
            ? '<button type="button" data-dk-view="lane"><i class="fas fa-arrow-left"></i></button>'
            : '<button type="button" data-dk-view="all"><i class="fas fa-layer-group"></i></button>';
        foot.firstChild.appendChild(document.createTextNode(view === 'all' ? 'Only ' + label.toLowerCase() : 'All context'));
        body.appendChild(foot);
        el.appendChild(body);
        el.classList.toggle('is-all', view === 'all');
        pop.view = view;
        var id = pop.root.getAttribute('data-event-id');
        el.setAttribute('aria-label', (view === 'all' ? 'Context' : label) + ' of event #' + id);
        place();
    }

    // Drawn by the server (SharingGroupsController::peek), once per group per page.
    var sgPeeks = {};
    function loadSg(id) {
        if (!sgPeeks[id]) {
            sgPeeks[id] = fetch((window.baseurl || '') + '/sharing_groups/peek/' + encodeURIComponent(id), {
                credentials: 'same-origin',
                headers: { 'X-Requested-With': 'XMLHttpRequest', 'Accept': 'text/html' }
            }).then(function (r) {
                return r.ok && !r.redirected ? r.text() : null;
            }).then(function (html) {
                return html && html.indexOf('dk-sg-pop') >= 0 ? html : null;
            }, function () {
                return null;
            });
        }
        return sgPeeks[id];
    }

    function place() {
        var el = popEl;
        var r = pop.zone.getBoundingClientRect();
        var vw = document.documentElement.clientWidth;
        var head = pop.root.closest('table') && pop.root.closest('table').querySelector('thead');
        var headBottom = head ? head.getBoundingClientRect().bottom : 0;
        var below = window.innerHeight - r.bottom - 12, above = r.top - Math.max(headBottom, 0) - 12;
        el.style.left = '0px';
        el.style.top = '0px';
        var sg = pop.kind === 'sg';
        var beside = widen(Math.max(below, above), vw - 32);
        var pw, ph, top;
        if (beside) {
            ph = el.offsetHeight;
            top = ph <= below || below >= above ? r.bottom + 2 : r.top - ph - 2;
        } else {
            // Too tall for either side: over the row rather than cut short
            var nav = document.querySelector('nav.fixed-top, .navbar.fixed-top');
            var ceiling = Math.max(8, nav ? nav.getBoundingClientRect().bottom + 8 : 8);
            // A sharing group lists few enough members to need no cut.
            if (!sg) truncate(window.innerHeight - ceiling - 8);
            ph = el.offsetHeight;
            top = Math.max(ceiling, Math.min(r.bottom + 2, window.innerHeight - ph - 8));
        }
        pw = el.offsetWidth;
        // A badge sits at the right of its row or card: its popover hangs from that edge.
        var left = Math.min(Math.max(16, sg ? r.right - pw : r.left), vw - pw - 16);
        el.style.left = (left + window.scrollX) + 'px';
        el.style.top = (top + window.scrollY) + 'px';
    }

    // A popover never scrolls: it takes more columns while the screen has the
    // width; then, failing that, its last groups and their last rows give way
    // to a note.
    function widen(height, width) {
        var el = popEl;
        var bodies = $$('.dk-pop-body', el);
        var tooTall = function () { return el.offsetHeight > height; };
        var grow = function () {
            if (el.offsetWidth >= width) return false;
            var grew = false;
            bodies.forEach(function (b) {
                var cards = $$('.hg-card', b);
                // One long list spreads its own rows instead
                var target = cards.length === 1 ? cards[0].querySelector('.hg-list') : b;
                var cap = cards.length === 1 ? 4 : cards.length;
                var n = parseInt(getComputedStyle(target).columnCount, 10) || 1;
                if (n < cap) {
                    target.style.columnCount = n + 1;
                    grew = true;
                }
            });
            return grew;
        };
        while (tooTall() && grow()) { /* widen */ }
        return !tooTall();
    }

    function truncate(height) {
        var el = popEl;
        var tooTall = function () { return el.offsetHeight > height; };
        if (!tooTall()) return;
        var focus = el.querySelector('.dk-pop-sec.is-focus');
        var cards = $$('.dk-pop-body .hg-card', el);
        // Popped from the end: the other lanes give way before the one asked for
        cards = cards.filter(function (c) { return focus && focus.contains(c); })
            .concat(cards.filter(function (c) { return !focus || !focus.contains(c); }));
        var hidden = 0;
        var hide = function (node) { node.style.display = 'none'; };
        while (tooTall() && cards.length > 1) {
            var card = cards.pop();
            hidden += card.querySelectorAll('.hg-row').length;
            hide(card);
        }
        var note = document.createElement('a');
        note.className = 'dk-pop-more';
        note.href = (window.baseurl || '') + '/events/view/' + pop.root.getAttribute('data-event-id');
        var foot = el.querySelector('.dk-pop-foot');
        foot.insertBefore(note, foot.firstChild);
        var say = function (n) { note.textContent = '+' + n + ' not shown · open the event'; };
        say(hidden || 1);
        if (tooTall() && cards.length) {
            var last = cards[cards.length - 1];
            var rows = $$('.hg-row', last);
            var lo = 0, hi = rows.length;
            var show = function (k) {
                rows.forEach(function (row, i) { row.style.display = i < k ? '' : 'none'; });
                $$('.hg-fam', last).forEach(function (fam) {
                    fam.style.display = fam.querySelector('.hg-row:not([style*="none"])') ? '' : 'none';
                });
                say(hidden + rows.length - k);
            };
            while (lo < hi) {
                var mid = Math.ceil((lo + hi) / 2);
                show(mid);
                if (tooTall()) hi = mid - 1; else lo = mid;
            }
            show(lo);
        }
        $$('.dk-pop-sec', el).forEach(function (sec) {
            if (!sec.querySelector('.hg-card:not([style*="none"])') && sec.querySelector('.hg-card')) hide(sec);
        });
    }

    // A sharing group opens once its popover has arrived; when it cannot
    // arrive, its badge falls back to a plain tooltip.
    var sgWanted = null;
    function openPop(zone, pinned) {
        cancelTimers();
        if (pop && pop.zone === zone) {
            if (pinned && !pop.pinned) pin();
            return;
        }
        if (isSg(zone)) {
            sgWanted = zone;
            loadSg(zone.getAttribute('data-sg-id')).then(function (html) {
                if (sgWanted !== zone) return;
                if (!html) {
                    sgWanted = null;
                    zone.title = zone.getAttribute('aria-label');
                    return;
                }
                begin({ kind: 'sg', zone: zone, root: zone.closest('[data-event-id]') || zone, trigger: zone, pinned: false });
                popEl.innerHTML = html;
                popEl.setAttribute('aria-label', zone.getAttribute('aria-label'));
                place();
                if (pinned) pin();
            });
            return;
        }
        closePop();
        var lane = laneOf(zone);
        var root = zone.closest('[data-event-id]');
        if (!root || !root.querySelector('template.dk-ctx-tpl')) return;
        begin({ kind: 'lane', zone: zone, root: root, lane: lane.getAttribute('data-dk-lane'), trigger: lane.querySelector('.dk-more'), pinned: false });
        fill('lane');
        if (pinned) pin();
    }
    function begin(p) {
        closePop();
        pop = p;
        p.zone.classList.add('is-popped');
        popElement().hidden = false;
        popEl.classList.remove('is-pinned');
        popEl.classList.toggle('is-sg', p.kind === 'sg');
        if (p.trigger) p.trigger.setAttribute('aria-expanded', 'true');
    }
    function pin() {
        pop.pinned = true;
        popEl.classList.add('is-pinned');
        popEl.focus({ preventScroll: true });
    }
    function closePop(restore) {
        cancelTimers();
        if (!pop) return;
        var p = pop;
        pop = null;
        popEl.hidden = true;
        p.zone.classList.remove('is-popped');
        var t = p.trigger;
        if (t) {
            t.setAttribute('aria-expanded', 'false');
            if (restore && document.contains(t) && !t.hidden) {
                refocused = t;
                t.focus();
            }
        }
    }
    function scheduleClose() {
        if (!pop || pop.pinned) return;
        clearTimeout(closeT);
        closeT = setTimeout(function () { if (pop && !pop.pinned) closePop(); }, CLOSE);
    }

    document.addEventListener('mouseover', function (e) {
        var zone = zoneOf(e.target);
        if (!zone) return;
        if (pop && pop.zone === zone) {
            clearTimeout(closeT);
            return;
        }
        if (pop && pop.pinned) return;
        if (!hasMore(zone)) return;
        clearTimeout(openT);
        var sg = isSg(zone);
        if (sg) loadSg(zone.getAttribute('data-sg-id'));
        openT = setTimeout(function () { openPop(zone, false); }, sg || e.target.closest('.dk-more') ? OPEN_MORE : OPEN_LANE);
    });
    document.addEventListener('mouseout', function (e) {
        var zone = zoneOf(e.target);
        if (!zone || (e.relatedTarget && (zone.contains(e.relatedTarget) || (popEl && popEl.contains(e.relatedTarget))))) return;
        clearTimeout(openT);
        if (sgWanted === zone) sgWanted = null;
        if (pop && pop.zone === zone) scheduleClose();
    });
    var TRIGGERS = '.dk-index .dk-more, .dk-index .dk-dist[data-sg-id]';
    document.addEventListener('focusin', function (e) {
        var more = e.target.closest && e.target.closest(TRIGGERS);
        if (more && more === refocused) {
            refocused = null;
            return;
        }
        if (!more || (pop && pop.pinned)) return;
        clearTimeout(openT);
        openT = setTimeout(function () {
            if (document.activeElement === more) openPop(zoneOf(more), false);
        }, OPEN_MORE);
    });
    document.addEventListener('focusout', function (e) {
        if (!e.target.closest || !e.target.closest(TRIGGERS) || !pop || pop.pinned) return;
        if (e.relatedTarget && popEl.contains(e.relatedTarget)) return;
        closePop();
    });
    document.addEventListener('click', function (e) {
        var more = e.target.closest && e.target.closest(TRIGGERS);
        if (!more) return;
        e.preventDefault();
        e.stopPropagation();
        var zone = zoneOf(more);
        if (pop && pop.zone === zone && pop.pinned) closePop(true);
        else openPop(zone, true);
    }, true);
    document.addEventListener('keydown', function (e) {
        if (e.key === 'Escape') sgWanted = null;
        if (e.key === 'Escape' && pop) {
            e.stopPropagation();
            closePop(pop.pinned || (pop.trigger && document.activeElement === pop.trigger));
        }
    }, true);
    // Two clicks on a badge pin and unpin it; they do not open the event.
    document.addEventListener('dblclick', function (e) {
        if (e.target.closest && e.target.closest('.dk-index .dk-dist[data-sg-id]')) e.stopPropagation();
    }, true);
    document.addEventListener('mousedown', function (e) {
        if (!pop || popEl.contains(e.target) || pop.zone.contains(e.target)) return;
        closePop();
    });
    window.addEventListener('resize', function () { closePop(); });

    /* ---------- binding ---------- */
    // The card view starts hidden behind the table toggle, so a grid is
    // measured whenever it gets a size, not only on load.
    var pending = new Set();
    var frame = 0;
    var resizes = new ResizeObserver(function (entries) {
        entries.forEach(function (entry) {
            if (entry.contentRect.width) {
                pending.add(entry.target);
            }
        });
        if (!frame) {
            frame = requestAnimationFrame(function () {
                frame = 0;
                pending.forEach(fitAll);
                pending.clear();
            });
        }
    });

    function observeGrids(root) {
        $$('.idx-card-grid', root).forEach(function (grid) {
            if (!grid.dataset.dkObserved) {
                grid.dataset.dkObserved = '1';
                resizes.observe(grid);
            }
        });
    }

    function bind(root) {
        if (root.dataset.dkBound) {
            return;
        }
        root.dataset.dkBound = '1';
        observeGrids(root);
        root.addEventListener('change', function (e) {
            if (e.target.classList && e.target.classList.contains('item-checkbox')) {
                syncSelection(root);
            }
        });
        // The filter bar and the pager swap the children of #index-results.
        var results = root.querySelector('#index-results');
        if (results) {
            new MutationObserver(function () {
                closePop();
                observeGrids(root);
                fitAll(root);
                syncSelection(root);
            }).observe(results, { childList: true });
        }
    }

    function scan() {
        $$('.dk-index').forEach(function (root) {
            if (!root.classList.contains('dk-pop-float')) bind(root);
        });
    }

    window.eventIndexCards = {
        scan: scan, fit: fitAll, fitLanes: fitLanes, fitDist: fitDist, distWidth: distWidth,
        closePop: function () { closePop(); }
    };

    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', scan);
    } else {
        scan();
    }
    if (document.fonts && document.fonts.ready) {
        document.fonts.ready.then(function () {
            $$('.dk-index').forEach(fitAll);
        });
    }
})();
