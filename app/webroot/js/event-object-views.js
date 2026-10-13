/*
 * The event overview's object views (Events/view_event_object_views.ctp):
 * what needs the live layout. How many tiles fit a line, "show all", the
 * panel opening under a tile's line with its notch, stepping between tiles,
 * long tables folded, and the map, drawn when its panel opens.
 */
(function () {
    'use strict';

    var PART_ROWS = 2;      // lines of a bay shown before "show all"
    var ROWS_SHOWN = 12;    // table rows of a full drawing before "show all"

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

    var shelf = null;

    function Shelf(root) {
        var self = this;
        this.root = root;
        this.tray = root.querySelector('.eov-tray');
        this.strings = JSON.parse(root.getAttribute('data-eov-strings') || '{}');
        this.tiles = [];
        this.groups = [];
        this.panel = null;
        this.opened = null;
        this.mapState = null;
        Array.prototype.forEach.call(this.tray.children, function (el) {
            if (!el.classList.contains('eov-group')) return;
            var group = {
                el: el,
                kind: el.hasAttribute('data-eov-each') ? 'each' : 'set',
                tiles: [],
                more: el.querySelector('[data-eov-more]'),
                expanded: false
            };
            el.querySelectorAll('[data-eov-tile]').forEach(function (tile) {
                var rec = { el: tile, group: group, index: self.tiles.length };
                group.tiles.push(rec);
                self.tiles.push(rec);
            });
            self.groups.push(group);
        });
        this.layout();
        if (window.ResizeObserver) {
            var lastWidth = 0;
            new ResizeObserver(function () {
                var width = self.tray.clientWidth;
                if (width === lastWidth) return;
                lastWidth = width;
                self.layout();
            }).observe(this.tray);
        }
        root.addEventListener('click', function (e) { self.onClick(e); });
        root.addEventListener('keydown', function (e) { self.onKey(e); });
    }

    Shelf.prototype.columns = function () {
        var cols = getComputedStyle(this.tray).gridTemplateColumns.split(' ').filter(Boolean).length;
        return Math.max(1, cols);
    };

    Shelf.prototype.layout = function () {
        var S = this.strings;
        var room = this.columns() * PART_ROWS;
        this.groups.forEach(function (g) {
            if (g.kind !== 'each' || !g.more) return;
            var total = g.tiles.length;
            var partial = !g.expanded && total > room;
            var shown = partial ? room - 1 : total;
            g.tiles.forEach(function (t, i) {
                t.el.hidden = i >= shown;
            });
            if (total <= room) {
                g.more.hidden = true;
                return;
            }
            g.more.hidden = false;
            g.more.textContent = '';
            if (partial) {
                g.more.append(
                    h('span', {}, [icon('fas fa-chevron-down'), ' ' + fmt(S.showAll, [n(total)])]),
                    h('small', { text: fmt(S.shown, [n(shown), n(total)]) })
                );
                g.more.setAttribute('aria-label', fmt(S.showAll, [n(total)]) + '; '
                    + fmt(S.shown, [n(shown), n(total)]));
            } else {
                g.more.append(
                    h('span', {}, [icon('fas fa-chevron-up'), ' ' + S.showFewer]),
                    h('small', { text: fmt(S.allShown, [n(total)]) })
                );
                g.more.setAttribute('aria-label', S.showFewer);
            }
        });
        if (this.opened) this.place();
    };

    // After the last item on the open tile's line: in the bay when the bay
    // runs over several lines, else in the tray.
    Shelf.prototype.place = function () {
        var panel = this.panel;
        var focusWas = panel.contains(document.activeElement) ? document.activeElement : null;
        if (panel.parentNode) panel.parentNode.removeChild(panel);
        var g = this.opened.group;
        var anchor = this.opened.el;
        var container;
        var items;
        if (g.kind === 'each') {
            container = g.el;
            items = Array.prototype.filter.call(g.el.children, function (el) {
                return (el.classList.contains('eov-tile') || el.classList.contains('eov-more')) && !el.hidden;
            });
        } else {
            container = this.tray;
            items = Array.prototype.filter.call(this.tray.children, function (el) {
                return el.classList.contains('eov-group');
            });
            anchor = g.el;
        }
        var top = anchor.offsetTop;
        var last = anchor;
        items.forEach(function (el) {
            if (Math.abs(el.offsetTop - top) < 2) last = el;
        });
        container.insertBefore(panel, last.nextSibling);
        this.fitBody();
        this.notch();
        if (focusWas && document.contains(focusWas)) focusWas.focus({ preventScroll: true });
        if (this.mapState) this.mapState.map.invalidateSize();
    };

    // A drawing too wide for its column beside the aside takes the panel's
    // whole width, and the aside moves under it.
    Shelf.prototype.fitBody = function () {
        var body = this.panel.querySelector('.eov-panel-body');
        if (!body) return;
        body.classList.remove('is-wide');
        var wide = Array.prototype.some.call(body.querySelectorAll('.eov-pdraw .vp-rf-table'), function (t) {
            return t.scrollWidth > t.clientWidth + 2;
        });
        body.classList.toggle('is-wide', wide);
    };

    Shelf.prototype.notch = function () {
        var t = this.opened.el.getBoundingClientRect();
        var p = this.panel.getBoundingClientRect();
        var x = Math.round(t.left + t.width / 2 - p.left);
        this.panel.style.setProperty('--eov-notch', Math.max(22, Math.min(p.width - 22, x)) + 'px');
    };

    Shelf.prototype.name = function (rec) {
        return rec ? rec.el.getAttribute('data-eov-name') || '' : '';
    };

    Shelf.prototype.open = function (rec, opts) {
        opts = opts || {};
        if (this.opened === rec && !opts.force) {
            this.close(true);
            return;
        }
        if (this.opened) this.opened.el.setAttribute('aria-expanded', 'false');
        this.destroyMap();
        if (rec.el.hidden) {
            rec.group.expanded = true;
            this.opened = null;
            this.layout();
        }
        this.opened = rec;
        rec.el.setAttribute('aria-expanded', 'true');
        if (!this.panel) {
            this.panel = h('div', { class: 'eov-panel', id: 'eov-panel', role: 'region' });
        }
        // Stepping redraws the panel: keep the reader's focus on the same control.
        var had = this.panel.contains(document.activeElement) ? document.activeElement : null;
        var focusSel = opts.focus === 'title' ? '.eov-ptitle'
            : had && had.hasAttribute('data-eov-step') ? '[data-eov-step="' + had.getAttribute('data-eov-step') + '"]'
                : had ? '.eov-ptitle' : null;
        this.fill(rec);
        this.place();
        this.drawMap();
        if (focusSel) {
            var target = this.panel.querySelector(focusSel);
            if (!target || target.disabled) target = this.panel.querySelector('.eov-ptitle');
            if (target) target.focus({ preventScroll: true });
        }
        this.keepInView(rec);
    };

    Shelf.prototype.close = function (focusTile) {
        if (!this.opened) return;
        var rec = this.opened;
        this.destroyMap();
        rec.el.setAttribute('aria-expanded', 'false');
        this.opened = null;
        if (this.panel && this.panel.parentNode) this.panel.parentNode.removeChild(this.panel);
        if (focusTile) rec.el.focus({ preventScroll: true });
    };

    // The open tile's line and the panel's head in view, without jumping when
    // they already are.
    Shelf.prototype.keepInView = function (rec) {
        var top = topInset();
        var t = rec.el.getBoundingClientRect();
        var p = this.panel.getBoundingClientRect();
        var room = window.innerHeight - top;
        if (t.top < top) {
            window.scrollBy(0, t.top - top - 8);
        } else if (p.bottom > window.innerHeight) {
            window.scrollBy(0, Math.min(p.bottom - window.innerHeight + 16, t.top - top - 8, room));
        }
    };

    Shelf.prototype.step = function (delta) {
        if (!this.opened) return;
        var next = this.tiles[this.opened.index + delta];
        if (next) this.open(next, { force: true });
    };

    Shelf.prototype.fill = function (rec) {
        var S = this.strings;
        var panel = this.panel;
        var template = rec.el.querySelector('template[data-eov-panel]');
        panel.replaceChildren(template.content.cloneNode(true));
        panel.setAttribute('aria-label', this.name(rec));
        rec.el.setAttribute('aria-controls', 'eov-panel');

        var slot = panel.querySelector('[data-eov-stepper]');
        var prev = this.tiles[rec.index - 1];
        var next = this.tiles[rec.index + 1];
        if (slot && this.tiles.length > 1) {
            slot.replaceWith(h('div', { class: 'eov-step', role: 'group', 'aria-label': S.neighbours }, [
                h('button', {
                    type: 'button', class: 'eov-step-btn', 'data-eov-step': '-1', disabled: !prev,
                    title: prev ? fmt(S.previous, [this.name(prev)]) + ' (←)' : null,
                    'aria-label': prev ? fmt(S.previous, [this.name(prev)]) : S.noPrevious
                }, [icon('fas fa-chevron-left')]),
                h('span', { class: 'eov-step-pos', 'aria-live': 'polite', text: rec.el.getAttribute('data-eov-pos') }),
                h('button', {
                    type: 'button', class: 'eov-step-btn', 'data-eov-step': '1', disabled: !next,
                    title: next ? fmt(S.next, [this.name(next)]) + ' (→)' : null,
                    'aria-label': next ? fmt(S.next, [this.name(next)]) : S.noNext
                }, [icon('fas fa-chevron-right')])
            ]));
        } else if (slot) {
            slot.remove();
        }
        this.foldTables(panel);
    };

    Shelf.prototype.foldTables = function (panel) {
        var S = this.strings;
        panel.querySelectorAll('.eov-pdraw table.vp-rf-table').forEach(function (table) {
            var rows = table.tBodies[0] ? table.tBodies[0].rows.length : 0;
            if (rows <= ROWS_SHOWN + 2) return;
            var btn = h('button', { type: 'button', class: 'btn btn-link', 'aria-expanded': 'false' });
            var say = h('span', {});
            var set = function (all) {
                table.classList.toggle('eov-clamp', !all);
                btn.setAttribute('aria-expanded', all ? 'true' : 'false');
                say.textContent = all ? fmt(S.allRows, [n(rows)]) : fmt(S.rows, [ROWS_SHOWN, n(rows)]);
                btn.replaceChildren(
                    icon(all ? 'fas fa-chevron-up me-1' : 'fas fa-chevron-down me-1'),
                    all ? S.showFewer : fmt(S.showAll, [n(rows)])
                );
            };
            btn.addEventListener('click', function () { set(table.classList.contains('eov-clamp')); });
            set(false);
            table.after(h('div', { class: 'eov-rows' }, [say, btn]));
        });
    };

    Shelf.prototype.drawMap = function () {
        var holder = this.panel.querySelector('[data-eov-map]');
        if (!holder || !window.ObjectMap || !window.L) return;
        var css = getComputedStyle(this.root);
        var colour = function (name, fallback) {
            return css.getPropertyValue(name).trim() || fallback;
        };
        var panel = this.panel;
        this.mapState = window.ObjectMap.drawAll(holder, JSON.parse(holder.getAttribute('data-eov-map')), {
            colours: {
                point: colour('--eov-geo-point', '#6f5fb5'),
                area: colour('--eov-geo-area', '#0b7f9c'),
                track: colour('--eov-geo-track', '#d9480f'),
                focus: colour('--eov-geo-focus', '#000')
            },
            tileClass: 'eov-map-tiles',
            focusClass: 'eov-geo-focus',
            fitAllLabel: this.strings.fitAll,
            onStatus: function (attachment, text, drawn) {
                var status = panel.querySelector('[data-eov-status="' + attachment + '"]');
                if (status) status.textContent = text;
                var locate = panel.querySelector('[data-eov-locate="file:' + attachment + '"]');
                if (locate) locate.disabled = !drawn;
            },
            onReady: function () {
                holder.setAttribute('data-eov-map-ready', '');
            }
        });
    };

    // The legend sits under the map: bring the map back into view before
    // moving it, or the reader sees nothing happen.
    Shelf.prototype.locate = function (key) {
        var holder = this.panel.querySelector('[data-eov-map]');
        if (!this.mapState || !holder) return;
        var top = topInset();
        var r = holder.getBoundingClientRect();
        if (r.top < top) {
            window.scrollBy({ top: r.top - top - 8, behavior: 'instant' });
        } else if (r.bottom > window.innerHeight) {
            window.scrollBy({ top: Math.min(r.bottom - window.innerHeight + 16, r.top - top - 8), behavior: 'instant' });
        }
        this.mapState.focus(key);
    };

    Shelf.prototype.destroyMap = function () {
        if (this.mapState) this.mapState.remove();
        this.mapState = null;
    };

    Shelf.prototype.tileOf = function (el) {
        var tile = el && el.closest && el.closest('[data-eov-tile]');
        return tile ? this.tiles[+tile.getAttribute('data-eov-tile')] : null;
    };

    Shelf.prototype.onClick = function (e) {
        var object = e.target.closest('a[data-eov-object]');
        if (object && window.MispEventOverview && e.button === 0
            && !e.ctrlKey && !e.metaKey && !e.shiftKey && !e.altKey) {
            e.preventDefault();
            window.MispEventOverview.openFiltered('objects', { object: object.getAttribute('data-eov-object') });
            return;
        }
        var locate = e.target.closest('[data-eov-locate]');
        if (locate) {
            this.locate(locate.getAttribute('data-eov-locate'));
            return;
        }
        var objects = e.target.closest('[data-eov-objects]');
        if (objects) {
            e.preventDefault();
            if (window.MispEventOverview) {
                window.MispEventOverview.openFiltered('objects', { name: objects.getAttribute('data-eov-objects') });
            }
            return;
        }
        var more = e.target.closest('[data-eov-more]');
        if (more) {
            var g = this.groups.filter(function (x) { return x.more === more; })[0];
            if (g) {
                g.expanded = !g.expanded;
                if (!g.expanded && this.opened && this.opened.group === g
                    && g.tiles.indexOf(this.opened) >= this.columns() * PART_ROWS - 1) {
                    this.close(false);
                }
                this.layout();
                more.focus({ preventScroll: true });
            }
            return;
        }
        var stepButton = e.target.closest('[data-eov-step]');
        if (stepButton) {
            this.step(+stepButton.getAttribute('data-eov-step'));
            return;
        }
        if (e.target.closest('[data-eov-close]')) {
            this.close(true);
            return;
        }
        if (e.target.closest('a') || (this.panel && this.panel.contains(e.target))) return;
        var rec = this.tileOf(e.target);
        if (rec) this.open(rec);
    };

    Shelf.prototype.onKey = function (e) {
        var rec = this.tileOf(e.target);
        if (rec && e.target === rec.el) {
            if (e.key === 'Enter' || e.key === ' ') {
                e.preventDefault();
                this.open(rec, { focus: 'title' });
                return;
            }
            if (e.key === 'ArrowRight' || e.key === 'ArrowLeft') {
                var visible = this.tiles.filter(function (t) { return !t.el.hidden; });
                var to = visible[visible.indexOf(rec) + (e.key === 'ArrowRight' ? 1 : -1)];
                if (to) {
                    e.preventDefault();
                    to.el.focus();
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
            if ((e.key === 'ArrowRight' || e.key === 'ArrowLeft')
                && !e.target.closest('.eov-map, input, textarea, select')) {
                e.preventDefault();
                this.step(e.key === 'ArrowRight' ? 1 : -1);
            }
        }
    };

    // Escape closes the panel even when focus has fallen back to the page.
    document.addEventListener('keydown', function (e) {
        if (e.key === 'Escape' && shelf && shelf.opened && e.target === document.body
            && !document.querySelector('.modal.show')) {
            shelf.close(true);
        }
    });

    document.addEventListener('misp:overview-fragment', function (e) {
        var el = e.detail && e.detail.el;
        if (!el || el.id !== 'eo-object-views') return;
        if (shelf) shelf.destroyMap();
        var root = el.querySelector('[data-eov-shelf]');
        shelf = root ? new Shelf(root) : null;
    });

    window.EventObjectViews = {
        shelf: function () { return shelf; }
    };
})();
