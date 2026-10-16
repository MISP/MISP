/*
 * The rail navbar (Elements/navbar_rail*.ctp): mega-panels opened by hover
 * intent or click, keyboard navigation along the rail and inside a panel,
 * and the phone drawer. The theme, dark-mode, homepage, tutorial and
 * analyst-graph entries keep their own handlers (navbar_actions.ctp,
 * mispOvermind.js, onboarding.js, intel-graph.js).
 */
(function () {
    'use strict';

    var DRAWER = window.matchMedia('(max-width: 1099.98px)');
    var HOVER = window.matchMedia('(hover: hover) and (pointer: fine)');

    function init() {
        var nav = document.querySelector('.rail-nav');
        if (!nav) return;
        // The open panel is tracked here rather than read from the DOM or from
        // event.defaultPrevented: Bootstrap's dropdowns preventDefault every
        // Escape that passes over one of their toggles.
        var ui = { open: null, pinned: false };
        var timers = { open: 0, close: 0 };
        var hoverAt = 0;

        function groupEl(id) {
            return id ? nav.querySelector('.rail-group[data-group="' + id + '"]') : null;
        }
        function items(id) {
            var li = groupEl(id);
            return li ? Array.prototype.slice.call(li.querySelectorAll('.rail-panel a[href], .rail-panel button')) : [];
        }
        function place() {
            var li = groupEl(ui.open);
            if (!li) return;
            var p = li.querySelector('.rail-panel');
            if (DRAWER.matches) {
                p.style.left = '';
                return;
            }
            p.style.left = '0px';
            var t = li.querySelector('.rail-trigger').getBoundingClientRect();
            var vw = document.documentElement.clientWidth;
            var w = p.offsetWidth;
            var x = li.hasAttribute('data-end') ? t.right - w : t.left;
            p.style.left = Math.round(Math.max(12, Math.min(x, vw - w - 12))) + 'px';
        }
        function setOpen(id, pinned) {
            clearTimeout(timers.open);
            clearTimeout(timers.close);
            ui.open = id || null;
            ui.pinned = !!(id && pinned);
            nav.querySelectorAll('.rail-group[data-group]').forEach(function (li) {
                var on = li.getAttribute('data-group') === ui.open;
                li.classList.toggle('is-open', on);
                li.querySelector('.rail-trigger').setAttribute('aria-expanded', on ? 'true' : 'false');
            });
            place();
        }
        function setDrawer(on) {
            nav.classList.toggle('is-drawer', on);
            var tg = nav.querySelector('.rail-toggle');
            tg.setAttribute('aria-expanded', on ? 'true' : 'false');
            tg.querySelector('i').className = 'fas ' + (on ? 'fa-xmark' : 'fa-bars');
        }
        function isDrawerOpen() {
            return nav.classList.contains('is-drawer');
        }
        function focusTrigger(id) {
            var li = groupEl(id);
            if (li) li.querySelector('.rail-trigger').focus();
        }
        // Arrow keys along the rail: triggers and the graph launcher.
        function step(from, dir, intoPanel) {
            var all = Array.prototype.slice.call(nav.querySelectorAll('.rail-trigger, .rail-graph'));
            var next = all[(all.indexOf(from) + dir + all.length) % all.length];
            var wasOpen = !!ui.open;
            next.focus();
            if (!wasOpen) return;
            var li = next.closest('.rail-group[data-group]');
            if (li && next.classList.contains('rail-trigger')) {
                var id = li.getAttribute('data-group');
                setOpen(id, true);
                if (intoPanel) {
                    var list = items(id);
                    if (list.length) list[0].focus();
                }
            } else {
                setOpen(null);
            }
        }

        function onEnter(id) {
            if (!HOVER.matches || DRAWER.matches) return;
            clearTimeout(timers.close);
            if (ui.open === id) return;
            clearTimeout(timers.open);
            if (ui.open) {
                setOpen(id, false);
                hoverAt = Date.now();
                return;
            }
            timers.open = setTimeout(function () {
                setOpen(id, false);
                hoverAt = Date.now();
            }, 110);
        }
        function onLeave(id) {
            if (!HOVER.matches || DRAWER.matches) return;
            clearTimeout(timers.open);
            if (ui.open !== id || ui.pinned) return;
            timers.close = setTimeout(function () {
                if (ui.open === id && !ui.pinned) setOpen(null);
            }, 320);
        }

        nav.querySelectorAll('.rail-group[data-group]').forEach(function (li) {
            var id = li.getAttribute('data-group');
            li.addEventListener('mouseenter', function () { onEnter(id); });
            li.addEventListener('mouseleave', function () { onLeave(id); });
            li.addEventListener('focusout', function (e) {
                if (DRAWER.matches || ui.open !== id) return;
                if (e.relatedTarget && !li.contains(e.relatedTarget)) setOpen(null);
            });
        });

        nav.addEventListener('click', function (e) {
            var t = e.target.closest('.rail-trigger, .rail-toggle, a.rail-item, .onboarding-launch');
            if (!t || !nav.contains(t)) return;
            if (t.classList.contains('rail-toggle')) {
                setDrawer(!isDrawerOpen());
                return;
            }
            if (t.classList.contains('rail-trigger') && t.tagName === 'BUTTON') {
                var id = t.parentElement.getAttribute('data-group');
                if (ui.open !== id) setOpen(id, true);
                else if (!ui.pinned && e.detail !== 0 && Date.now() - hoverAt < 1000) ui.pinned = true;
                else setOpen(null);
                return;
            }
            setOpen(null);
            setDrawer(false);
        });

        nav.addEventListener('keydown', function (e) {
            var t = e.target;
            var k = e.key;
            if (k === 'Escape') {
                if (ui.open) {
                    var was = ui.open;
                    setOpen(null);
                    focusTrigger(was);
                    e.preventDefault();
                } else if (isDrawerOpen()) {
                    setDrawer(false);
                    nav.querySelector('.rail-toggle').focus();
                    e.preventDefault();
                }
                return;
            }
            var rail = t.closest('.rail-trigger, .rail-graph');
            if (rail) {
                if ((k === 'ArrowRight' || k === 'ArrowLeft') && !DRAWER.matches) {
                    e.preventDefault();
                    step(rail, k === 'ArrowRight' ? 1 : -1, false);
                } else if ((k === 'ArrowDown' || k === 'ArrowUp') && rail.tagName === 'BUTTON'
                        && rail.classList.contains('rail-trigger')) {
                    e.preventDefault();
                    var gid = rail.parentElement.getAttribute('data-group');
                    setOpen(gid, true);
                    var l = items(gid);
                    if (l.length) l[k === 'ArrowDown' ? 0 : l.length - 1].focus();
                }
                return;
            }
            var panel = t.closest('.rail-panel');
            if (!panel) return;
            var li = panel.parentElement;
            var list = items(li.getAttribute('data-group'));
            var i = list.indexOf(t);
            if (i < 0) return;
            var to = null;
            if (k === 'ArrowDown') to = list[(i + 1) % list.length];
            else if (k === 'ArrowUp') to = list[(i - 1 + list.length) % list.length];
            else if (k === 'Home') to = list[0];
            else if (k === 'End') to = list[list.length - 1];
            else if ((k === 'ArrowRight' || k === 'ArrowLeft') && !DRAWER.matches) {
                e.preventDefault();
                var dir = k === 'ArrowRight' ? 1 : -1;
                if (panel.classList.contains('rail-panel--mega')) {
                    var cols = Array.prototype.slice.call(panel.querySelectorAll('.rail-col'));
                    var nc = cols[cols.indexOf(t.closest('.rail-col')) + dir];
                    var f = nc && nc.querySelector('a[href], button');
                    if (f) {
                        f.focus();
                        return;
                    }
                }
                step(li.querySelector('.rail-trigger'), dir, true);
                return;
            }
            if (to) {
                e.preventDefault();
                to.focus();
            }
        });

        document.addEventListener('pointerdown', function (e) {
            if (!ui.open || DRAWER.matches) return;
            if (!e.target.closest || !nav.contains(e.target)) setOpen(null);
        });
        document.addEventListener('keydown', function (e) {
            if (e.key !== 'Escape' || nav.contains(e.target)) return;
            if (ui.open) setOpen(null);
            if (isDrawerOpen()) setDrawer(false);
        }, true);
        // Crossing the drawer breakpoint leaves nothing half-open.
        DRAWER.addEventListener('change', function () {
            setOpen(null);
            setDrawer(false);
        });
        window.addEventListener('resize', place);
    }

    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', init);
    } else {
        init();
    }
})();
