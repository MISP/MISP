/*
 * The event overview's object views (Events/view_event_object_views.ctp):
 * what needs the live layout. How many tiles fit a line, "show all", the
 * links that filter the Objects tab, and the map, drawn when its panel
 * opens. Opening, stepping and folding are js/tile-drawer.js.
 */
(function () {
    'use strict';

    var PART_ROWS = 2;      // lines of a bay shown before "show all"

    var util = window.TileDrawer.util;
    var fmt = util.fmt;
    var n = util.n;
    var h = util.h;
    var icon = util.icon;

    var shelf = null;

    // A drawn table's heading cycles ascending, descending, then the order
    // the server sent, on the row tokens the value page's list engine
    // sorts by. An empty token sorts last both ways.
    function sortTable(button) {
        var table = button.closest('table');
        var body = table && table.tBodies[0];
        if (!body) return;
        var column = button.getAttribute('data-vp-sort-col');
        var dir = table.getAttribute('data-vp-sorted-col') !== column ? 'asc'
            : table.getAttribute('data-vp-sorted-dir') === 'asc' ? 'desc' : null;
        if (dir) {
            table.setAttribute('data-vp-sorted-col', column);
            table.setAttribute('data-vp-sorted-dir', dir);
        } else {
            table.removeAttribute('data-vp-sorted-col');
            table.removeAttribute('data-vp-sorted-dir');
        }
        table.querySelectorAll('[data-vp-sort-col]').forEach(function (b) {
            var th = b.closest('th');
            if (b === button && dir) {
                th.setAttribute('aria-sort', dir === 'asc' ? 'ascending' : 'descending');
            } else {
                th.removeAttribute('aria-sort');
            }
        });
        var attr = 'data-vp-sort-' + (dir ? column : 'default');
        var sign = dir === 'desc' ? -1 : 1;
        Array.prototype.slice.call(body.rows).sort(function (a, b) {
            var x = a.getAttribute(attr) || '';
            var y = b.getAttribute(attr) || '';
            if (x === y) return 0;
            if (x === '') return 1;
            if (y === '') return -1;
            return x < y ? -sign : sign;
        }).forEach(function (row) {
            body.appendChild(row);
        });
    }

    function Shelf(root) {
        var self = this;
        this.root = root;
        this.tray = root.querySelector('.eov-tray');
        this.strings = JSON.parse(root.getAttribute('data-td-strings') || '{}');
        this.groups = [];
        this.groupOf = new Map();
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
            el.querySelectorAll('[data-td-tile]').forEach(function (tile) {
                group.tiles.push(tile);
                self.groupOf.set(tile, group);
            });
            self.groups.push(group);
        });
        this.drawer = new window.TileDrawer(root, {
            panelId: 'eov-panel',
            // A bay that runs over several lines opens under the tile's own
            // line; a `set` tile opens under its group's line in the tray.
            anchor: function (tile) {
                var g = self.groupOf.get(tile);
                return g.kind === 'each' ? tile : g.el;
            },
            reveal: function (tile) {
                self.groupOf.get(tile).expanded = true;
                self.layout();
            },
            keepArrows: '.eov-map',
            onClick: function (e) { return self.onClick(e); },
            onOpen: function () { self.drawMap(); },
            onPlace: function () {
                if (self.mapState) self.mapState.map.invalidateSize();
            },
            onClose: function () { self.destroyMap(); }
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
                t.hidden = i >= shown;
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
        if (this.drawer.isOpen()) this.drawer.place();
    };

    Shelf.prototype.drawMap = function () {
        var panel = this.drawer.panel;
        var holder = panel.querySelector('[data-eov-map]');
        if (!holder || !window.ObjectMap || !window.L) return;
        var css = getComputedStyle(this.root);
        var colour = function (name, fallback) {
            return css.getPropertyValue(name).trim() || fallback;
        };
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
        var holder = this.drawer.panel.querySelector('[data-eov-map]');
        if (!this.mapState || !holder) return;
        var top = util.topInset();
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

    // The clicks that are the shelf's own; anything else is the drawer's.
    Shelf.prototype.onClick = function (e) {
        var object = e.target.closest('a[data-eov-object]');
        if (object && window.MispEventOverview && e.button === 0
            && !e.ctrlKey && !e.metaKey && !e.shiftKey && !e.altKey) {
            e.preventDefault();
            window.MispEventOverview.openFiltered('objects', { object: object.getAttribute('data-eov-object') });
            return true;
        }
        var locate = e.target.closest('[data-eov-locate]');
        if (locate) {
            this.locate(locate.getAttribute('data-eov-locate'));
            return true;
        }
        var sort = e.target.closest('[data-vp-sort-col]');
        if (sort) {
            sortTable(sort);
            return true;
        }
        var objects = e.target.closest('[data-eov-objects]');
        if (objects) {
            e.preventDefault();
            if (window.MispEventOverview) {
                window.MispEventOverview.openFiltered('objects', { name: objects.getAttribute('data-eov-objects') });
            }
            return true;
        }
        var more = e.target.closest('[data-eov-more]');
        if (more) {
            var g = this.groups.filter(function (x) { return x.more === more; })[0];
            if (g) {
                var opened = this.drawer.opened;
                g.expanded = !g.expanded;
                if (!g.expanded && opened && this.groupOf.get(opened) === g
                    && g.tiles.indexOf(opened) >= this.columns() * PART_ROWS - 1) {
                    this.drawer.close(false);
                }
                this.layout();
                more.focus({ preventScroll: true });
            }
            return true;
        }
        return false;
    };

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
