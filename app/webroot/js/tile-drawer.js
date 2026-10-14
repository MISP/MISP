/*
 * Tiles that open in place: a panel inserted after the last item on the
 * open tile's line, its notch pointing back at the tile, stepping between
 * tiles, long tables folded. The event overview's object views and the
 * value page's enrichment strip.
 *
 * A tile carries `data-td-tile`, `data-td-name`, `data-td-pos` and its
 * panel in a `<template data-td-panel>`. In the panel, `[data-td-stepper]`
 * becomes ‹ › across the tiles and `[data-td-close]` closes it. The root
 * carries the strings as `data-td-strings` (Elements/TileDrawer/strings).
 */
(function () {
    'use strict';

    var ROWS_SHOWN = 12;    // table rows of a full drawing before "show all"
    var drawers = [];

    function fmt(template, values) {
        var i = 0;
        return String(template || '').replace(/%(\d+\$)?s/g, function (m, pos) {
            var at = pos ? parseInt(pos, 10) - 1 : i++;
            return values[at] === undefined ? '' : values[at];
        });
    }

    function n(x) {
        return Number(x).toLocaleString('en-US');
    }

    function h(tag, attrs, kids) {
        var el = document.createElement(tag);
        Object.keys(attrs || {}).forEach(function (k) {
            var v = attrs[k];
            if (v === null || v === undefined || v === false) return;
            if (k === 'class') el.className = v;
            else if (k === 'text') el.textContent = v;
            else el.setAttribute(k, v === true ? '' : v);
        });
        (kids || []).forEach(function (kid) {
            if (kid === null || kid === undefined || kid === false) return;
            el.appendChild(typeof kid === 'string' ? document.createTextNode(kid) : kid);
        });
        return el;
    }

    function icon(cls) {
        return h('i', { class: cls, 'aria-hidden': 'true' });
    }

    // What the fixed top bar and the sticky tab strip cover.
    function topInset() {
        var nav = document.querySelector('nav.rc-nav');
        return (nav ? nav.getBoundingClientRect().height : 0) + 52;
    }

    /**
     * @param {Element} root holds the tiles and gets their clicks and keys
     * @param {Object} opts
     *   panelId    the panel's id, which the tiles' aria-controls name
     *   anchor     tile => the element whose line the panel goes under
     *   reveal     tile => show a hidden tile before it opens
     *   onClick    event => true when the page handled the click
     *   onFill     (panel, tile) after the panel's content is in
     *   onOpen     (panel, tile) once the panel is placed
     *   onPlace    (panel, tile) whenever it is placed again
     *   onClose    (panel, tile) when its tile closes or another opens
     *   keepArrows selector inside the panel where ←/→ do not step
     */
    function TileDrawer(root, opts) {
        var self = this;
        this.root = root;
        this.opts = opts || {};
        this.strings = JSON.parse(root.getAttribute('data-td-strings') || '{}');
        this.panel = null;
        this.opened = null;
        root.addEventListener('click', function (e) { self.onClick(e); });
        root.addEventListener('keydown', function (e) { self.onKey(e); });
        drawers.push(this);
    }

    TileDrawer.prototype.tiles = function () {
        return Array.prototype.slice.call(this.root.querySelectorAll('[data-td-tile]'));
    };

    TileDrawer.prototype.tileOf = function (el) {
        var tile = el && el.closest && el.closest('[data-td-tile]');
        return tile && this.root.contains(tile) ? tile : null;
    };

    TileDrawer.prototype.name = function (tile) {
        return tile ? tile.getAttribute('data-td-name') || '' : '';
    };

    TileDrawer.prototype.isOpen = function () {
        return this.opened !== null;
    };

    // how: force (reopen the open tile), focus: 'title', stay (no scrolling)
    TileDrawer.prototype.open = function (tile, how) {
        how = how || {};
        if (this.opened === tile && !how.force) {
            this.close(true);
            return;
        }
        // Stepping redraws the panel: keep the reader's focus on the same control.
        var had = this.panel && this.panel.contains(document.activeElement)
            ? document.activeElement : null;
        var focusSel = how.focus === 'title' ? '.td-title'
            : had && had.hasAttribute('data-td-step') ? '[data-td-step="' + had.getAttribute('data-td-step') + '"]'
                : had ? '.td-title' : null;
        this.release();
        if (tile.hidden && this.opts.reveal) this.opts.reveal(tile);
        this.opened = tile;
        tile.setAttribute('aria-expanded', 'true');
        if (!this.panel) {
            this.panel = h('div', { class: 'td-panel', id: this.opts.panelId || null, role: 'region' });
        }
        this.fill(tile);
        this.place();
        if (this.opts.onOpen) this.opts.onOpen(this.panel, tile);
        if (focusSel) {
            var target = this.panel.querySelector(focusSel);
            if (!target || target.disabled) target = this.panel.querySelector('.td-title');
            if (target) target.focus({ preventScroll: true });
        }
        if (!how.stay) this.keepInView(tile);
    };

    TileDrawer.prototype.release = function () {
        var tile = this.opened;
        if (!tile) return null;
        this.opened = null;
        tile.setAttribute('aria-expanded', 'false');
        if (this.opts.onClose) this.opts.onClose(this.panel, tile);
        return tile;
    };

    TileDrawer.prototype.close = function (focusTile) {
        var tile = this.release();
        if (this.panel && this.panel.parentNode) this.panel.parentNode.removeChild(this.panel);
        if (tile && focusTile && document.contains(tile)) tile.focus({ preventScroll: true });
    };

    // After the last item on the anchor's line, among the anchor's siblings.
    TileDrawer.prototype.place = function () {
        var panel = this.panel;
        var tile = this.opened;
        if (!panel || !tile) return;
        var focusWas = panel.contains(document.activeElement) ? document.activeElement : null;
        if (panel.parentNode) panel.parentNode.removeChild(panel);
        var anchor = this.opts.anchor ? this.opts.anchor(tile) : tile;
        var top = anchor.offsetTop;
        var last = anchor;
        Array.prototype.forEach.call(anchor.parentNode.children, function (el) {
            if (el.hidden || !el.getClientRects().length) return;
            if (Math.abs(el.offsetTop - top) < 2) last = el;
        });
        anchor.parentNode.insertBefore(panel, last.nextSibling);
        this.fitBody();
        this.notch();
        if (focusWas && document.contains(focusWas)) focusWas.focus({ preventScroll: true });
        if (this.opts.onPlace) this.opts.onPlace(panel, tile);
    };

    // A drawing too wide for its column beside the aside takes the panel's
    // whole width, and the aside moves under it.
    TileDrawer.prototype.fitBody = function () {
        var body = this.panel.querySelector('.td-body');
        if (!body) return;
        body.classList.remove('is-wide');
        var wide = Array.prototype.some.call(body.querySelectorAll('.td-draw table'), function (t) {
            return t.scrollWidth > t.clientWidth + 2;
        });
        body.classList.toggle('is-wide', wide);
    };

    TileDrawer.prototype.notch = function () {
        if (!this.opened || !this.panel) return;
        var t = this.opened.getBoundingClientRect();
        var p = this.panel.getBoundingClientRect();
        var x = Math.round(t.left + t.width / 2 - p.left);
        this.panel.style.setProperty('--td-notch', Math.max(22, Math.min(p.width - 22, x)) + 'px');
    };

    // The open tile's line and the panel's head in view, without jumping when
    // they already are.
    TileDrawer.prototype.keepInView = function (tile) {
        var top = topInset();
        var t = tile.getBoundingClientRect();
        var p = this.panel.getBoundingClientRect();
        var room = window.innerHeight - top;
        if (t.top < top) {
            window.scrollBy(0, t.top - top - 8);
        } else if (p.bottom > window.innerHeight) {
            window.scrollBy(0, Math.min(p.bottom - window.innerHeight + 16, t.top - top - 8, room));
        }
    };

    TileDrawer.prototype.step = function (delta) {
        if (!this.opened) return;
        var tiles = this.tiles();
        var next = tiles[tiles.indexOf(this.opened) + delta];
        if (next) this.open(next, { force: true });
    };

    TileDrawer.prototype.fill = function (tile) {
        var S = this.strings;
        var panel = this.panel;
        var template = tile.querySelector('template[data-td-panel]');
        panel.replaceChildren(template.content.cloneNode(true));
        panel.setAttribute('aria-label', this.name(tile));

        var tiles = this.tiles();
        var at = tiles.indexOf(tile);
        var prev = tiles[at - 1];
        var next = tiles[at + 1];
        var slot = panel.querySelector('[data-td-stepper]');
        if (slot && tiles.length > 1) {
            slot.replaceWith(h('div', { class: 'td-step', role: 'group', 'aria-label': S.neighbours }, [
                h('button', {
                    type: 'button', class: 'td-step-btn', 'data-td-step': '-1', disabled: !prev,
                    title: prev ? fmt(S.previous, [this.name(prev)]) + ' (←)' : null,
                    'aria-label': prev ? fmt(S.previous, [this.name(prev)]) : S.noPrevious
                }, [icon('fas fa-chevron-left')]),
                h('span', { class: 'td-step-pos', 'aria-live': 'polite', text: tile.getAttribute('data-td-pos') }),
                h('button', {
                    type: 'button', class: 'td-step-btn', 'data-td-step': '1', disabled: !next,
                    title: next ? fmt(S.next, [this.name(next)]) + ' (→)' : null,
                    'aria-label': next ? fmt(S.next, [this.name(next)]) : S.noNext
                }, [icon('fas fa-chevron-right')])
            ]));
        } else if (slot) {
            slot.remove();
        }
        this.foldTables();
        if (this.opts.onFill) this.opts.onFill(panel, tile);
    };

    // Folds count the rows on screen: the value page's list engine hides
    // the rows a brush or a filter leaves out, and the fold follows it,
    // as it follows a sorted heading's new order.
    TileDrawer.prototype.foldTables = function () {
        var S = this.strings;
        this.panel.querySelectorAll('.td-draw table.vp-rf-table').forEach(function (table) {
            var body = table.tBodies[0];
            if (!body || body.rows.length <= ROWS_SHOWN + 2) return;
            var all = false;
            var btn = h('button', { type: 'button', class: 'btn btn-link' });
            var say = h('span', {});
            var line = h('div', { class: 'td-rows' }, [say, btn]);
            var refold = function () {
                var shown = Array.prototype.filter.call(body.rows, function (row) {
                    return !row.classList.contains('d-none');
                });
                var count = shown.length;
                var fold = !all && count > ROWS_SHOWN + 2;
                shown.forEach(function (row, i) {
                    row.classList.toggle('td-folded', fold && i >= ROWS_SHOWN);
                });
                line.hidden = count <= ROWS_SHOWN + 2;
                btn.setAttribute('aria-expanded', fold ? 'false' : 'true');
                say.textContent = fold ? fmt(S.rows, [ROWS_SHOWN, n(count)]) : fmt(S.allRows, [n(count)]);
                btn.replaceChildren(
                    icon(fold ? 'fas fa-chevron-down me-1' : 'fas fa-chevron-up me-1'),
                    fold ? fmt(S.showAll, [n(count)]) : S.showFewer
                );
            };
            btn.addEventListener('click', function () {
                all = !all;
                refold();
            });
            table.after(line);
            refold();
            if ((table.closest('[data-vp-list]') || table.querySelector('[data-vp-sort-col]'))
                && window.MutationObserver) {
                new MutationObserver(refold).observe(body, {
                    attributes: true, attributeFilter: ['class'], subtree: true, childList: true
                });
            }
        });
    };

    TileDrawer.prototype.onClick = function (e) {
        if (this.opts.onClick && this.opts.onClick(e)) return;
        var inPanel = this.panel && this.panel.contains(e.target);
        var stepButton = inPanel && e.target.closest('[data-td-step]');
        if (stepButton) {
            this.step(+stepButton.getAttribute('data-td-step'));
            return;
        }
        if (inPanel && e.target.closest('[data-td-close]')) {
            this.close(true);
            return;
        }
        if (inPanel || e.target.closest('a')) return;
        var tile = this.tileOf(e.target);
        if (tile) this.open(tile);
    };

    TileDrawer.prototype.onKey = function (e) {
        var tile = this.tileOf(e.target);
        if (tile && e.target === tile) {
            if (e.key === 'Escape' && tile === this.opened) {
                e.preventDefault();
                this.close(true);
                return;
            }
            if (e.key === 'Enter' || e.key === ' ') {
                e.preventDefault();
                this.open(tile, { focus: 'title' });
                return;
            }
            if (e.key === 'ArrowRight' || e.key === 'ArrowLeft') {
                var visible = this.tiles().filter(function (t) { return !t.hidden; });
                var to = visible[visible.indexOf(tile) + (e.key === 'ArrowRight' ? 1 : -1)];
                if (to) {
                    e.preventDefault();
                    to.focus();
                }
                return;
            }
        }
        if (this.panel && this.panel.contains(e.target)) {
            if (e.key === 'Escape') {
                e.preventDefault();
                this.close(true);
                return;
            }
            var keep = 'input, textarea, select' + (this.opts.keepArrows ? ', ' + this.opts.keepArrows : '');
            if ((e.key === 'ArrowRight' || e.key === 'ArrowLeft') && !e.target.closest(keep)) {
                e.preventDefault();
                this.step(e.key === 'ArrowRight' ? 1 : -1);
            }
        }
    };

    // Escape closes the panel even when focus has fallen back to the page.
    document.addEventListener('keydown', function (e) {
        if (e.key !== 'Escape' || e.target !== document.body || document.querySelector('.modal.show')) return;
        drawers = drawers.filter(function (d) { return document.contains(d.root); });
        drawers.forEach(function (d) {
            if (d.isOpen()) d.close(true);
        });
    });

    TileDrawer.util = { fmt: fmt, n: n, h: h, icon: icon, topInset: topInset };
    window.TileDrawer = TileDrawer;
})();
