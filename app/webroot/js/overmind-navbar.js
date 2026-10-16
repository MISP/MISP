/*
 * Overmind top navbar (Elements/navbar*.ctp): hover or click dropdowns,
 * flyout submenus, keyboard navigation, the phone drawer and the lift once
 * the page scrolls under the bar. The theme, dark-mode, homepage, tutorial
 * and analyst-graph entries keep their own handlers (navbar.ctp,
 * mispOvermind.js, onboarding.js, intel-graph.js).
 */
(function () {
    'use strict';

    var DESK = window.matchMedia('(min-width: 1200px)');
    var ui = { open: null, how: null };
    var timers = { group: 0, sub: 0 };

    function openGroup(li, how) {
        var nav = li.closest('.rc-nav');
        nav.querySelectorAll('.rc-group.is-open').forEach(function (g) {
            if (g !== li) closeGroup(g);
        });
        clearTimeout(timers.group);
        li.classList.add('is-open');
        li.firstElementChild.setAttribute('aria-expanded', 'true');
        ui.open = li;
        ui.how = how;
        place(li, li.querySelector('.rc-panel'));
    }

    function closeGroup(li) {
        li.classList.remove('is-open', 'rc-flip');
        li.firstElementChild.setAttribute('aria-expanded', 'false');
        li.querySelectorAll('.rc-sub.is-open').forEach(closeSub);
        if (ui.open === li) {
            ui.open = null;
            ui.how = null;
        }
    }

    function closeAll(nav) {
        clearTimeout(timers.group);
        clearTimeout(timers.sub);
        nav.querySelectorAll('.rc-group.is-open').forEach(closeGroup);
    }

    function openSub(s) {
        Array.prototype.forEach.call(s.parentElement.children, function (o) {
            if (o !== s && o.classList.contains('is-open')) closeSub(o);
        });
        s.classList.add('is-open');
        s.firstElementChild.setAttribute('aria-expanded', 'true');
        place(s, s.querySelector('.rc-flyout'));
    }

    function closeSub(s) {
        s.classList.remove('is-open', 'rc-flip');
        s.firstElementChild.setAttribute('aria-expanded', 'false');
    }

    // Flip a panel or flyout to the other side when it would leave the viewport.
    function place(host, panel) {
        host.classList.remove('rc-flip');
        if (!DESK.matches || !panel || host.classList.contains('rc-end')) return;
        if (panel.getBoundingClientRect().right > window.innerWidth - 8) {
            host.classList.add('rc-flip');
        }
    }

    function setDrawer(nav, on) {
        nav.classList.toggle('is-drawer', on);
        nav.querySelector('.rc-toggler').setAttribute('aria-expanded', String(on));
    }

    /* ---------- pointer ---------- */
    function onRowEnter(li) {
        clearTimeout(timers.sub);
        var openOne = null;
        Array.prototype.forEach.call(li.parentElement.children, function (o) {
            if (o.classList.contains('is-open')) openOne = o;
        });
        if (li === openOne) return;
        // A short delay lets the pointer cut across a sibling row on its way
        // into an open flyout without the flyout snapping shut.
        timers.sub = setTimeout(function () {
            if (li.classList.contains('rc-sub')) openSub(li);
            else if (openOne) closeSub(openOne);
        }, openOne ? 120 : 30);
    }

    function wirePointer(nav) {
        nav.querySelectorAll('.rc-group').forEach(function (li) {
            if (!li.querySelector('.rc-panel')) return;
            li.addEventListener('pointerenter', function (e) {
                if (e.pointerType !== 'mouse' || !DESK.matches) return;
                clearTimeout(timers.group);
                if (!li.classList.contains('is-open')) openGroup(li, 'hover');
            });
            li.addEventListener('pointerleave', function (e) {
                if (e.pointerType !== 'mouse' || !DESK.matches || ui.how !== 'hover') return;
                timers.group = setTimeout(function () { closeGroup(li); }, 180);
            });
        });
        nav.querySelectorAll('.rc-group > .rc-panel > li').forEach(function (li) {
            li.addEventListener('pointerenter', function (e) {
                if (e.pointerType !== 'mouse' || !DESK.matches) return;
                onRowEnter(li);
            });
        });
    }

    /* ---------- click ---------- */
    function onClick(e) {
        var nav = e.currentTarget;
        var t = e.target.closest('button, a');
        if (!t || !nav.contains(t)) return;
        var byKey = e.detail === 0;
        if (t.classList.contains('rc-toggler')) {
            setDrawer(nav, !nav.classList.contains('is-drawer'));
            return;
        }
        if (t.classList.contains('rc-trigger') && t.tagName === 'BUTTON') {
            var li = t.parentElement;
            if (!li.classList.contains('is-open')) openGroup(li, 'click');
            else if (ui.how === 'hover' && !byKey) ui.how = 'click';
            else closeGroup(li);
            return;
        }
        if (t.classList.contains('rc-subtrigger')) {
            var s = t.parentElement;
            clearTimeout(timers.sub);
            if (!s.classList.contains('is-open')) openSub(s);
            else if (byKey || !DESK.matches) closeSub(s);
            return;
        }
        if (t.classList.contains('rc-item') || t.classList.contains('rc-chip')) {
            closeAll(nav);
            setDrawer(nav, false);
        }
    }

    /* ---------- keyboard ---------- */
    function rows(ul) {
        var out = [];
        Array.prototype.forEach.call(ul.children, function (li) {
            var el = li.firstElementChild;
            if (el && el.classList.contains('rc-item')) out.push(el);
        });
        return out;
    }

    function tops(nav) {
        return Array.prototype.slice.call(nav.querySelectorAll('.rc-trigger, .rc-chip'));
    }

    function onKey(e) {
        var nav = e.currentTarget;
        var t = e.target;
        var k = e.key;
        var li, list, i;

        if (t.classList.contains('rc-trigger') || t.classList.contains('rc-chip')) {
            li = t.parentElement;
            var isGroup = !!li.querySelector('.rc-panel');
            if (isGroup && (k === 'ArrowDown' || k === 'ArrowUp')) {
                e.preventDefault();
                openGroup(li, 'key');
                list = rows(li.querySelector('.rc-panel'));
                if (list.length) list[k === 'ArrowDown' ? 0 : list.length - 1].focus();
            } else if ((k === 'ArrowRight' || k === 'ArrowLeft') && DESK.matches) {
                e.preventDefault();
                list = tops(nav);
                i = list.indexOf(t) + (k === 'ArrowRight' ? 1 : -1);
                var next = list[(i + list.length) % list.length];
                var wasOpen = isGroup && li.classList.contains('is-open');
                if (wasOpen) closeGroup(li);
                next.focus();
                if (wasOpen && next.parentElement.querySelector('.rc-panel')) {
                    openGroup(next.parentElement, 'key');
                }
            } else if (k === 'Escape') {
                if (isGroup && li.classList.contains('is-open')) {
                    e.preventDefault();
                    closeGroup(li);
                } else if (nav.classList.contains('is-drawer')) {
                    e.preventDefault();
                    setDrawer(nav, false);
                    nav.querySelector('.rc-toggler').focus();
                }
            }
            return;
        }

        if (t.classList.contains('rc-item')) {
            var ul = t.parentElement.parentElement;
            var inFly = ul.classList.contains('rc-flyout');
            list = rows(ul);
            i = list.indexOf(t);
            if (k === 'ArrowDown' || k === 'ArrowUp') {
                e.preventDefault();
                i += k === 'ArrowDown' ? 1 : -1;
                list[(i + list.length) % list.length].focus();
            } else if (k === 'Home' || k === 'End') {
                e.preventDefault();
                list[k === 'Home' ? 0 : list.length - 1].focus();
            } else if (k === 'ArrowRight' && t.classList.contains('rc-subtrigger')) {
                e.preventDefault();
                openSub(t.parentElement);
                var inner = rows(t.nextElementSibling);
                if (inner.length) inner[0].focus();
            } else if (inFly && (k === 'ArrowLeft' || k === 'Escape')) {
                e.preventDefault();
                var s = ul.parentElement;
                closeSub(s);
                s.firstElementChild.focus();
            } else if (k === 'Escape') {
                e.preventDefault();
                li = t.closest('.rc-group');
                closeGroup(li);
                li.firstElementChild.focus();
            }
            return;
        }

        if (k === 'Escape' && nav.classList.contains('is-drawer')) {
            setDrawer(nav, false);
            nav.querySelector('.rc-toggler').focus();
        }
    }

    function onFocusOut(e) {
        if (!DESK.matches) return;
        var li = e.target.closest('.rc-group');
        var to = e.relatedTarget;
        if (!li || !li.classList.contains('is-open') || !to || li.contains(to)) return;
        closeGroup(li);
    }

    function init() {
        var nav = document.querySelector('.rc-nav');
        if (!nav) return;
        nav.addEventListener('click', onClick);
        nav.addEventListener('keydown', onKey);
        nav.addEventListener('focusout', onFocusOut);
        wirePointer(nav);

        document.addEventListener('pointerdown', function (e) {
            if (e.target.closest && e.target.closest('.rc-scrim')) {
                setDrawer(nav, false);
                return;
            }
            if (!nav.contains(e.target) && DESK.matches) closeAll(nav);
        });
        document.addEventListener('keydown', function (e) {
            if (e.key !== 'Escape' || nav.contains(e.target)) return;
            closeAll(nav);
            if (nav.classList.contains('is-drawer')) setDrawer(nav, false);
        });
        // Crossing the drawer breakpoint leaves no group half-open.
        DESK.addEventListener('change', function () {
            closeAll(nav);
            setDrawer(nav, false);
        });

        function onScroll() {
            nav.classList.toggle('is-scrolled', window.scrollY > 0);
        }
        window.addEventListener('scroll', onScroll, { passive: true });
        onScroll();
    }

    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', init);
    } else {
        init();
    }
})();
