// A Gantt-like ledger of rows over a time axis, and the histogram strip
// that sets its window. Knows rows, times and callbacks; nothing about
// what a row stands for. Times are milliseconds since epoch, UTC.
// Styles: misp-timeline.css. The strip needs misp-brush.js/css.
(function () {
    'use strict';

    var HOUR = 3600000;
    var DAY = 86400000;
    var MONTHS = ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun', 'Jul', 'Aug',
        'Sep', 'Oct', 'Nov', 'Dec'];
    var STEPS = [
        ['hour', 1, HOUR], ['hour', 3, 3 * HOUR], ['hour', 6, 6 * HOUR],
        ['hour', 12, 12 * HOUR], ['day', 1, DAY], ['day', 2, 2 * DAY],
        ['week', 1, 7 * DAY], ['week', 2, 14 * DAY],
        ['month', 1, 30.4 * DAY], ['month', 3, 91 * DAY],
        ['month', 6, 182 * DAY], ['year', 1, 365.25 * DAY],
        ['year', 2, 730.5 * DAY], ['year', 5, 1826 * DAY],
        ['year', 10, 3652 * DAY]
    ];
    // Rows drawn above and below the visible ones, so a scroll of a few
    // rows does not show a gap before the next frame.
    var OVERSCAN = 8;

    function pad(n) {
        return n < 10 ? '0' + n : '' + n;
    }

    function el(tag, cls, html) {
        var node = document.createElement(tag);
        if (cls) {
            node.className = cls;
        }
        if (html != null) {
            node.innerHTML = html;
        }
        return node;
    }

    function advance(t, unit, n) {
        var d = new Date(t);
        if (unit === 'hour') {
            return t + n * HOUR;
        }
        if (unit === 'day') {
            return t + n * DAY;
        }
        if (unit === 'week') {
            return t + 7 * n * DAY;
        }
        if (unit === 'month') {
            return Date.UTC(d.getUTCFullYear(), d.getUTCMonth() + n, 1);
        }
        return Date.UTC(d.getUTCFullYear() + n, 0, 1);
    }

    function tickLabel(t, unit, prev) {
        var d = new Date(t);
        var p = prev == null ? null : new Date(prev);
        var newYear = p === null || p.getUTCFullYear() !== d.getUTCFullYear();
        var dayMonth = d.getUTCDate() + ' ' + MONTHS[d.getUTCMonth()];
        if (unit === 'hour') {
            if (d.getUTCHours() === 0) {
                return { text: dayMonth, major: true };
            }
            return { text: pad(d.getUTCHours()) + ':00', major: false };
        }
        if (unit === 'day' || unit === 'week') {
            return {
                text: newYear ? dayMonth + ' ' + d.getUTCFullYear() : dayMonth,
                major: newYear && d.getUTCDate() <= (unit === 'week' ? 7 : 1)
            };
        }
        if (unit === 'month') {
            if (d.getUTCMonth() === 0) {
                return { text: '' + d.getUTCFullYear(), major: true };
            }
            return {
                text: MONTHS[d.getUTCMonth()]
                    + (p === null ? ' ' + d.getUTCFullYear() : ''),
                major: false
            };
        }
        return { text: '' + d.getUTCFullYear(), major: true };
    }

    /**
     * Ticks for an axis from `from` to `to`, at the finest step that
     * yields at most `maxCount` of them.
     *
     * @return {{unit: string, ticks: Array<{t: number, text: string,
     *     major: boolean}>}}
     */
    function ticks(from, to, maxCount) {
        var span = to - from;
        var s = STEPS[STEPS.length - 1];
        for (var i = 0; i < STEPS.length; i++) {
            if (span / STEPS[i][2] <= maxCount) {
                s = STEPS[i];
                break;
            }
        }
        var unit = s[0];
        var n = s[1];
        var d = new Date(from);
        var y = d.getUTCFullYear();
        var t;
        if (unit === 'hour') {
            t = Date.UTC(y, d.getUTCMonth(), d.getUTCDate(),
                Math.floor(d.getUTCHours() / n) * n);
        } else if (unit === 'day') {
            t = Date.UTC(y, d.getUTCMonth(), d.getUTCDate());
        } else if (unit === 'week') {
            t = Date.UTC(y, d.getUTCMonth(), d.getUTCDate());
            t -= ((new Date(t).getUTCDay() + 6) % 7) * DAY;
        } else if (unit === 'month') {
            t = Date.UTC(y, Math.floor(d.getUTCMonth() / n) * n, 1);
        } else {
            t = Date.UTC(Math.floor(y / n) * n, 0, 1);
        }
        var out = [];
        var prev = null;
        for (var guard = 0; t <= to && guard < 400; guard++) {
            if (t >= from) {
                var label = tickLabel(t, unit, prev);
                out.push({ t: t, text: label.text, major: label.major });
                prev = t;
            }
            t = advance(t, unit, n);
        }
        return { unit: unit, ticks: out };
    }

    // Keep a label at either end of the axis inside it.
    function edgeShift(x) {
        if (x < 4) {
            return 'transform:none';
        }
        if (x > 96) {
            return 'transform:translateX(-100%)';
        }
        return '';
    }

    /**
     * The ledger: a label column, the plot and a dates column, one row per
     * item, only the rows on screen in the DOM.
     *
     * A row is `{key, start, end, shape}` with `shape` one of `range`,
     * `first` (only the start is known), `last` (only the end) or `point`
     * (a single instant, at `start`). A row
     * with `envelope: true` spans its `children` (rows, or `null` until
     * `loadChildren` fetches them) and may carry `own`, its own dates as
     * `{start, end, shape}`; `childCount` says whether it can unfold.
     * `cue` is a CSS colour for its left edge.
     *
     * The callbacks that return HTML are trusted: they must escape what
     * they print.
     *
     * @param {Element} host Where the ledger is appended
     * @param {Object} opt `label(row, ctx)` and `dates(row, ctx)` return
     *     cell HTML, `tooltip(row, ctx)` the tooltip's; `onClick(row,
     *     ctx)`; `loadChildren(row)` returns a promise of rows;
     *     `loadingText(row)`, `failedText`, `emptyHtml()`, `labelHead`,
     *     `datesHead`, `rowHeight`; `onCount(rows, drawn)` after every
     *     refresh, `onAxis(unit, width)` after every axis draw
     */
    function Ledger(host, opt) {
        var self = this;
        this.opt = opt;
        this.rowHeight = opt.rowHeight || 32;
        this.rows = [];
        this.flat = [];
        this.expanded = {};
        this.loading = {};
        this.drawn = {};
        this.from = 0;
        this.to = DAY;
        this.plotWidth = 0;
        this.unit = null;

        this.scroller = el('div', 'tl-ledger');
        this.scroller.style.setProperty('--tl-row-h', this.rowHeight + 'px');
        this.head = el('div', 'tl-head tl-grid',
            '<div class="tl-head-label"></div>'
            + '<div class="tl-head-plot"><div class="tl-ticks"></div></div>'
            + '<div class="tl-head-dates"></div>');
        this.head.firstChild.innerHTML = opt.labelHead || '';
        this.head.lastChild.innerHTML = opt.datesHead || '';
        this.body = el('div', 'tl-rows');
        this.frame = el('div', 'tl-plotframe');
        this.grid = el('div', 'tl-gridlayer');
        this.layer = el('div', 'tl-layer');
        this.body.appendChild(this.frame);
        this.body.appendChild(this.grid);
        this.body.appendChild(this.layer);
        this.scroller.appendChild(this.head);
        this.scroller.appendChild(this.body);
        host.appendChild(this.scroller);

        this.tip = document.querySelector('body > .tl-tip');
        if (!this.tip) {
            this.tip = el('div', 'tl-tip');
            this.tip.setAttribute('data-timeline-tooltip', '');
            this.tip.setAttribute('role', 'tooltip');
            this.tip.hidden = true;
            document.body.appendChild(this.tip);
        }

        var pending = false;
        this.scroller.addEventListener('scroll', function () {
            self.hideTip();
            if (pending) {
                return;
            }
            pending = true;
            requestAnimationFrame(function () {
                pending = false;
                self.draw();
            });
        });
        this.layer.addEventListener('click', function (event) {
            var entry = self.entryAt(event.target);
            if (!entry || entry.loading) {
                return;
            }
            if (event.target.closest('[data-timeline-expand]')) {
                self.toggle(entry.row);
            } else if (opt.onClick) {
                opt.onClick(entry.row, self.context(entry));
            }
        });
        this.layer.addEventListener('mouseover', function (event) {
            var rowEl = event.target.closest('[data-timeline-row]');
            if (!rowEl || rowEl === self.hot) {
                return;
            }
            var entry = self.entryAt(rowEl);
            if (!entry || entry.loading || !opt.tooltip) {
                self.hideTip();
                return;
            }
            self.hot = rowEl;
            self.tip.innerHTML = opt.tooltip(entry.row, self.context(entry));
            self.tip.hidden = false;
            self.placeTip(event);
        });
        this.layer.addEventListener('mousemove', function (event) {
            if (!self.tip.hidden) {
                self.placeTip(event);
            }
        });
        this.layer.addEventListener('mouseleave', function () {
            self.hideTip();
        });
        this.onResize = function () {
            self.drawAxis();
        };
        window.addEventListener('resize', this.onResize);
    }

    Ledger.prototype.destroy = function () {
        window.removeEventListener('resize', this.onResize);
        this.hideTip();
        this.scroller.remove();
    };

    Ledger.prototype.entryAt = function (node) {
        var rowEl = node.closest('[data-timeline-row]');
        return rowEl ? this.flat[+rowEl.dataset.i] : null;
    };

    Ledger.prototype.context = function (entry) {
        return {
            depth: entry.depth,
            parent: entry.parent || null,
            open: !!entry.open,
            last: !!entry.last
        };
    };

    Ledger.prototype.hideTip = function () {
        this.hot = null;
        this.tip.hidden = true;
    };

    Ledger.prototype.placeTip = function (event) {
        var w = this.tip.offsetWidth;
        var h = this.tip.offsetHeight;
        var x = event.clientX + 14;
        var y = event.clientY + 18;
        if (x + w > window.innerWidth - 8) {
            x = Math.max(8, event.clientX - w - 14);
        }
        if (y + h > window.innerHeight - 8) {
            y = Math.max(8, event.clientY - h - 14);
        }
        this.tip.style.left = x + 'px';
        this.tip.style.top = y + 'px';
    };

    Ledger.prototype.pct = function (t) {
        return 100 * (t - this.from) / (this.to - this.from);
    };

    /**
     * @param {Array<Object>} rows In display order
     */
    Ledger.prototype.setRows = function (rows) {
        this.rows = rows;
        this.refresh();
    };

    /**
     * Set the window the plot shows.
     */
    Ledger.prototype.setDomain = function (from, to) {
        this.from = from;
        this.to = Math.max(to, from + 1);
        this.drawAxis();
        this.refresh();
    };

    Ledger.prototype.toggle = function (row) {
        var self = this;
        if (this.expanded[row.key]) {
            delete this.expanded[row.key];
        } else {
            this.expanded[row.key] = true;
            if (row.children == null && this.opt.loadChildren
                && !this.loading[row.key]) {
                this.loading[row.key] = true;
                this.opt.loadChildren(row).then(function (children) {
                    row.children = children;
                    delete self.loading[row.key];
                    self.refresh();
                }, function () {
                    row.children = [];
                    row.loadFailed = true;
                    delete self.loading[row.key];
                    self.refresh();
                });
            }
        }
        this.refresh();
    };

    Ledger.prototype.flatten = function () {
        var flat = [];
        var expanded = this.expanded;
        this.rows.forEach(function (r) {
            var open = !!expanded[r.key];
            flat.push({
                row: r,
                depth: 0,
                open: open,
                key: r.key + (open ? '+' : '-')
                    + (r.children ? r.children.length : 'n')
            });
            if (!open) {
                return;
            }
            if (r.children == null || (r.loadFailed && !r.children.length)) {
                flat.push({
                    loading: true,
                    failed: !!r.loadFailed,
                    parent: r,
                    depth: 1,
                    last: true,
                    key: r.key + '/loading' + (r.loadFailed ? 'x' : '')
                });
                return;
            }
            r.children.forEach(function (c, i) {
                var last = i === r.children.length - 1;
                flat.push({
                    row: c,
                    parent: r,
                    depth: 1,
                    last: last,
                    key: r.key + '/' + c.key + (last ? 'L' : '')
                });
            });
        });
        this.flat = flat;
    };

    Ledger.prototype.refresh = function () {
        this.flatten();
        this.hideTip();
        this.body.style.height = this.flat.length
            ? (this.flat.length * this.rowHeight) + 'px'
            : '';
        this.frame.hidden = this.grid.hidden = this.flat.length === 0;
        if (this.opt.onCount) {
            this.opt.onCount(this.rows.length, this.flat.length);
        }
        this.draw(true);
    };

    Ledger.prototype.drawAxis = function () {
        var plot = this.head.querySelector('.tl-head-plot');
        var track = this.grid.getBoundingClientRect().width;
        var width = Math.max(100, track || plot.clientWidth - 52);
        var axis = ticks(this.from, this.to,
            Math.max(2, Math.floor(width / 80)));
        var self = this;
        var head = [];
        var lines = [];
        axis.ticks.forEach(function (k) {
            var x = self.pct(k.t);
            var major = k.major ? ' tl-tick-major' : '';
            head.push('<span class="tl-tick' + major + '" style="left:' + x
                + '%;' + edgeShift(x) + '">' + k.text + '</span>');
            lines.push('<div class="tl-gridline'
                + (k.major ? ' tl-gridline-major' : '')
                + '" style="left:' + x + '%"></div>');
        });
        var now = Date.now();
        if (now >= this.from && now <= this.to) {
            var x = this.pct(now);
            head.push('<span class="tl-tick tl-tick-today" style="left:' + x
                + '%;' + edgeShift(x) + '">today</span>');
            lines.push('<div class="tl-gridline tl-gridline-today" style="left:'
                + x + '%"></div>');
        }
        this.plotWidth = width;
        this.unit = axis.unit;
        plot.firstChild.innerHTML = head.join('');
        this.grid.innerHTML = lines.join('');
        if (this.opt.onAxis) {
            this.opt.onAxis(axis.unit, width);
        }
    };

    // A one-ended shape is a fixed screen length from its known end, so
    // only that end is placed.
    Ledger.prototype.placement = function (r, minWidth) {
        var x = this.pct(r.start);
        var x2 = this.pct(r.end);
        if (r.shape === 'first' || r.shape === 'point') {
            return 'left:' + x + '%';
        }
        if (r.shape === 'last') {
            return 'left:' + x2 + '%';
        }
        var a = Math.max(x, 0);
        var b = Math.max(a, Math.min(x2, 100));
        return 'left:' + a + '%;width:max(' + minWidth + 'px,' + (b - a) + '%)';
    };

    Ledger.prototype.clipped = function (r) {
        if (r.shape !== 'range') {
            return '';
        }
        return (this.pct(r.start) < 0 ? ' tl-clip-l' : '')
            + (this.pct(r.end) > 100 ? ' tl-clip-r' : '');
    };

    Ledger.prototype.rowHtml = function (entry, i) {
        var opt = this.opt;
        var r = entry.row;
        var cls = ['tl-row', 'tl-grid'];
        var style = 'top:' + (i * this.rowHeight) + 'px;';
        var label = '';
        var plot = '';
        var dates = '';
        var ctx = this.context(entry);
        if (entry.depth > 0) {
            var p = entry.parent;
            cls.push(entry.loading ? 'tl-row-loading' : 'tl-row-child');
            label += '<span class="tl-tree'
                + (entry.last ? ' tl-tree-last' : '') + '"></span>';
            plot += '<div class="tl-seg tl-seg-' + p.shape
                + (entry.last ? ' tl-seg-end' : '') + '" style="'
                + this.placement(p, 8) + '"></div>';
        } else if (r.envelope) {
            cls.push('tl-row-envelope');
            if (entry.open) {
                cls.push('tl-open');
            }
        }
        if (entry.loading) {
            label += entry.failed
                ? '<span class="tl-loading-text">'
                    + (opt.failedText || 'Could not load') + '</span>'
                : '<span class="tl-spin" aria-hidden="true"></span>'
                    + '<span class="tl-loading-text">'
                    + (opt.loadingText ? opt.loadingText(entry.parent)
                        : 'Loading…')
                    + '</span>';
        } else {
            if (entry.depth === 0) {
                if (r.envelope && r.childCount > 0) {
                    label += '<button type="button" class="tl-caret"'
                        + ' data-timeline-expand aria-expanded="'
                        + (entry.open ? 'true' : 'false') + '" aria-label="'
                        + (entry.open ? 'Fold' : 'Unfold') + '">'
                        + '<i class="fas fa-chevron-right"></i></button>';
                } else {
                    label += '<span class="tl-caret tl-caret-none"></span>';
                }
            }
            label += opt.label(r, ctx);
            dates = opt.dates ? opt.dates(r, ctx) : '';
            if (r.envelope) {
                plot += '<div class="tl-env tl-env-' + r.shape + '"'
                    + ' data-timeline-item data-shape="' + r.shape
                    + '" style="' + this.placement(r, 8) + '"></div>';
                if (r.own) {
                    plot += '<div class="tl-own tl-own-' + r.own.shape
                        + '" style="' + this.placement(r.own, 4) + '"></div>';
                }
            } else {
                plot += '<div class="tl-mark tl-mark-' + r.shape
                    + this.clipped(r) + '" data-timeline-item data-shape="'
                    + r.shape + '" style="' + this.placement(r, 6)
                    + '"></div>';
            }
        }
        var cue = r && r.cue ? r.cue : (entry.parent && entry.parent.cue);
        if (cue) {
            cls.push('tl-cue');
            style += '--tl-cue:' + cue + ';';
        }
        return '<div class="' + cls.join(' ') + '" data-timeline-row data-i="'
            + i + '" style="' + style + '">'
            + '<div class="tl-cell-label">' + label + '</div>'
            + '<div class="tl-cell-plot"><div class="tl-track">' + plot
            + '</div></div>'
            + '<div class="tl-cell-dates">' + dates + '</div></div>';
    };

    Ledger.prototype.draw = function (force) {
        if (force) {
            this.drawn = {};
            this.layer.innerHTML = '';
        }
        if (!this.flat.length) {
            this.layer.innerHTML = this.opt.emptyHtml
                ? this.opt.emptyHtml()
                : '';
            return;
        }
        var top = this.scroller.scrollTop;
        var height = this.scroller.clientHeight || 540;
        var headHeight = this.head.offsetHeight;
        var first = Math.max(0,
            Math.floor((top - headHeight) / this.rowHeight) - OVERSCAN);
        var last = Math.min(this.flat.length,
            Math.ceil((top + height) / this.rowHeight) + OVERSCAN);
        var keep = {};
        var scratch = document.createElement('div');
        for (var i = first; i < last; i++) {
            var key = this.flat[i].key + '@' + i;
            var node = this.drawn[key];
            if (!node) {
                scratch.innerHTML = this.rowHtml(this.flat[i], i);
                node = scratch.firstChild;
                this.layer.appendChild(node);
            }
            keep[key] = node;
        }
        for (var k in this.drawn) {
            if (!keep[k]) {
                this.drawn[k].remove();
            }
        }
        this.drawn = keep;
    };

    /**
     * A histogram strip with a MispBrush over it, in bucket indices.
     *
     * @param {Object} o `bars` ({count}), `max`, `scale` (`sqrt`, the
     *     default, or `linear`), `head` (trusted HTML), `tickLabel(i)`
     *     returning `{text, major}` or null, `maxLabels`, `selected`
     *     ({from, to} or null); `onRange(from, to)` while dragging,
     *     `onSettle(from, to)` on release, `onClear()` on a click
     * @return {{el: Element, set: function(Object|null)}}
     */
    function overview(o) {
        var n = o.bars.length;
        var max = Math.max(1, o.max || 0);
        var height = o.scale === 'linear'
            ? function (c) { return 100 * c / max; }
            : function (c) { return 100 * Math.sqrt(c) / Math.sqrt(max); };
        var wrap = el('div', 'tl-ov');
        wrap.setAttribute('data-timeline-overview', '');
        var bars = o.bars.map(function (b) {
            if (!b.count) {
                return '<div class="tl-ov-bar tl-ov-bar-zero"></div>';
            }
            return '<div class="tl-ov-bar" style="height:max(3px,'
                + height(b.count) + '%)"></div>';
        }).join('');
        var gap = Math.max(1, Math.ceil(n / (o.maxLabels || 10)));
        var labels = [];
        var last = -Infinity;
        for (var i = 0; i < n; i++) {
            var label = o.tickLabel(i);
            if (!label || i - last < gap || (n - i < gap / 2 && i > 0)) {
                continue;
            }
            last = i;
            labels.push('<span class="' + (label.major ? 'tl-ov-major' : '')
                + '" style="left:' + (100 * i / n) + '%">' + label.text
                + '</span>');
        }
        wrap.innerHTML = '<div class="tl-ov-head">' + o.head + '</div>'
            + '<div class="tl-ov-plot"><div class="tl-ov-bars">' + bars
            + '</div>'
            + '<div class="misp-brush" data-misp-brush>'
            + '<div class="misp-brush-mask" data-misp-brush-mask-left></div>'
            + '<div class="misp-brush-window" data-misp-brush-handle></div>'
            + '<div class="misp-brush-mask" data-misp-brush-mask-right></div>'
            + '</div></div>'
            + '<div class="tl-ov-axis">' + labels.join('') + '</div>';
        var selected = null;
        function set(s) {
            selected = s;
            if (s) {
                window.MispBrush.paint(wrap, s, n);
            } else {
                window.MispBrush.clear(wrap);
            }
        }
        set(o.selected || null);
        window.MispBrush.attach(wrap.querySelector('[data-misp-brush]'), {
            count: function () {
                return n;
            },
            range: function (from, to) {
                set({ from: from, to: to });
                if (o.onRange) {
                    o.onRange(from, to);
                }
            },
            clear: function () {
                set(null);
                o.onClear();
            },
            settle: function () {
                if (selected) {
                    o.onSettle(selected.from, selected.to);
                }
            }
        });
        return { el: wrap, set: set };
    }

    window.MispTimeline = { Ledger: Ledger, overview: overview, ticks: ticks };
})();
