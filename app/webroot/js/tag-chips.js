/*
 * Client-side tag chips, mirroring TagChipHelper so a tag drawn by JS looks
 * and colours exactly like one drawn by the server. Styles: css/tag-chips.css.
 *
 *   TagChips.chip(tag, opts)        -> HTML string, one chip
 *   TagChips.collection(tags, opts) -> HTML string, grouped like the server
 *   TagChips.cluster(c, opts)       -> HTML string, one galaxy cluster
 *   TagChips.clusters(list, opts)   -> HTML string, grouped by galaxy
 *
 * tag is {name, colour, id?, numerical_value?, local?, relationship_type?}.
 * A cluster is {value|name, galaxy, id?, galaxy_id?, hue?, iconClass?,
 * tag_id?, local?, relationship_type?, description?}; hue is
 * GalaxyColour::hue() and is derived here when missing.
 * opts: searchUrl (prefix, '' for no link), display ('full'|'leaf'|'swatch'),
 * inline (a lone tag on one row), group, minGroup, wideAt, cls.
 */
(function (root) {
    'use strict';

    var semantic = null;

    function semanticNamespaces() {
        if (semantic === null) {
            var meta = document.querySelector('meta[name="misp-tag-palettes"]');
            var content = meta ? meta.getAttribute('content') : '';
            semantic = content ? content.split(' ') : [];
        }
        return semantic;
    }

    function esc(s) {
        return String(s === null || s === undefined ? '' : s)
            .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
            .replace(/"/g, '&quot;').replace(/'/g, '&#039;');
    }

    function parse(raw) {
        raw = String(raw || '').trim();
        var value = null;
        var head = raw;
        var eq = raw.indexOf('=');
        if (eq !== -1) {
            head = raw.slice(0, eq);
            value = raw.slice(eq + 1).trim().replace(/^"+|"+$/g, '');
        }
        var segs = head.split(':');
        var namespace = segs.length > 1 ? segs.shift() : null;
        if (namespace === '') {
            namespace = null;
            segs = [head];
        }
        var path = namespace === null ? [] : segs;
        var leaf;
        if (value !== null) {
            leaf = value;
        } else if (path.length) {
            leaf = path[path.length - 1];
        } else {
            leaf = head;
        }
        if (leaf === '') {
            leaf = raw;
        }
        return {
            raw: raw,
            namespace: namespace,
            path: path,
            above: value !== null ? path : path.slice(0, -1),
            value: value,
            leaf: leaf
        };
    }

    // FNV-1a over the UTF-8 bytes, as the PHP side hashes them
    function hue(str) {
        var bytes = unescape(encodeURIComponent(String(str).toLowerCase()));
        var h = 2166136261;
        for (var i = 0; i < bytes.length; i++) {
            h ^= bytes.charCodeAt(i);
            h = Math.imul(h, 16777619) >>> 0;
        }
        return h % 360;
    }

    // GalaxyColour::hue(): a 31-multiplier rolling hash over the UTF-8 bytes
    function galaxyHue(name) {
        var bytes = unescape(encodeURIComponent(String(name || '')));
        var h = 0;
        for (var i = 0; i < bytes.length; i++) {
            h = (h * 31 + bytes.charCodeAt(i)) % 2147483648;
        }
        return h % 360;
    }

    function hueSat(hex) {
        var c = String(hex || '').replace(/^#/, '');
        if (c.length === 3) {
            c = c[0] + c[0] + c[1] + c[1] + c[2] + c[2];
        }
        if (!/^[0-9a-fA-F]{6}$/.test(c)) {
            return {h: 0, s: 0};
        }
        var r = parseInt(c.slice(0, 2), 16) / 255;
        var g = parseInt(c.slice(2, 4), 16) / 255;
        var b = parseInt(c.slice(4, 6), 16) / 255;
        var max = Math.max(r, g, b);
        var min = Math.min(r, g, b);
        var d = max - min;
        if (d === 0) {
            return {h: 0, s: 0};
        }
        var l = (max + min) / 2;
        var s = d / (1 - Math.abs(2 * l - 1));
        var h;
        if (max === r) {
            h = ((g - b) / d) % 6;
        } else if (max === g) {
            h = (b - r) / d + 2;
        } else {
            h = (r - g) / d + 4;
        }
        h = Math.round(h * 60);
        return {h: ((h % 360) + 360) % 360, s: Math.round(s * 100)};
    }

    function hueOf(p, colour) {
        if (p.namespace === null) {
            return [0, '0%', null];
        }
        if (semanticNamespaces().indexOf(p.namespace.toLowerCase()) !== -1) {
            if (!/^#[0-9a-fA-F]{3}(?:[0-9a-fA-F]{3})?$/.test(String(colour))) {
                return [0, '0%', null];
            }
            var declared = hueSat(colour);
            return [declared.h, declared.s < 15 ? '0%' : '62%', String(colour).toLowerCase()];
        }
        return [hue(p.namespace), '62%', null];
    }

    function normalise(tag) {
        if (tag && tag.Tag) {
            var t = Object.assign({}, tag.Tag);
            if (tag.local !== undefined) t.local = tag.local;
            if (tag.relationship_type !== undefined) t.relationship_type = tag.relationship_type;
            return t;
        }
        return tag;
    }

    function numeral(nv, over) {
        return '<span class="hg-n' + (over ? ' is-over' : '') + '" title="Numerical value: ' + esc(nv) + '">' +
            esc(over ? nv + '↑' : nv) + '</span>';
    }

    function iconHtml(x) {
        return x && x.iconClass ? '<i class="hg-icon ' + esc(x.iconClass) + '" aria-hidden="true"></i>' : '';
    }

    // x carries a cluster's own hue, icon, link, title and unit attributes
    function renderChip(tag, p, mode, opts, x) {
        x = x || {};
        var display = opts.display || 'full';
        var isLocal = !!(tag.local && tag.local !== '0');
        var rel = tag.relationship_type ? String(tag.relationship_type) : null;
        var member = mode === 'member';
        // A free-text tag has no ancestry, and a member's namespace is
        // already in the block's header
        var showPath = display === 'full' &&
            (member ? p.above.length > 0 : p.namespace !== null);
        var stacked = display !== 'swatch' && !!(showPath || rel);
        var inline = stacked && !!opts.inline && !member;
        var nvRaw = tag.numerical_value;
        var hasNv = nvRaw !== null && nvRaw !== undefined && nvRaw !== '' && !isNaN(Number(nvRaw)) &&
            display !== 'swatch';
        var nv = hasNv ? Number(nvRaw) : null;
        var over = hasNv && (nv > 100 || nv < 0);
        var hs = x.hue !== undefined ? [x.hue, '62%', null] : hueOf(p, tag.colour || '#0088cc');

        var classes = ['hg-chip'];
        if (isLocal) classes.push('is-local');
        if (display === 'swatch') {
            classes.push('is-swatch');
        } else if (!stacked) {
            classes.push(member || display !== 'full' ? 'is-tight' : 'is-single');
        } else if (inline) {
            classes.push('is-inline');
        } else if (!member) {
            classes.push('is-stacked');
        }
        if (hasNv) classes.push('has-meter');
        if (hs[2]) {
            classes.push('has-colour');
            if (hs[1] === '0%') classes.push('is-neutral');
        }

        var inner = '';
        if (display !== 'swatch') {
            if (stacked) {
                var rail = '';
                if (rel) {
                    rail += '<span class="hg-rel" title="Relationship: ' + esc(rel) + '">' + esc(rel) + '</span>';
                }
                if (showPath) {
                    var segs = p.above.slice();
                    var path = member
                        ? esc(segs.shift())
                        : iconHtml(x) + '<b class="hg-ns">' + esc(p.namespace) + '</b>';
                    segs.forEach(function (seg) {
                        path += '<i class="hg-sep">&rsaquo;</i>' + esc(seg);
                    });
                    rail += '<span class="hg-path">' + path + '</span>';
                }
                if (hasNv && !inline) rail += numeral(nv, over);
                inner += '<span class="hg-rail">' + rail + '</span>';
            }
            var tail = '<span class="hg-leaf">' + esc(p.leaf) + '</span>';
            if (hasNv && (!stacked || inline)) tail += numeral(nv, over);
            if (isLocal) {
                tail += '<span class="hg-flag" title="' + (x.galaxy ? 'Local cluster' : 'Local tag') + '">local</span>';
            }
            inner += '<span class="hg-tail">' + tail + '</span>';
            if (hasNv) {
                var fill = over ? 100 : Math.max(0, Math.min(100, Math.round(nv)));
                inner += '<span class="hg-meter' + (over ? ' is-over' : '') + '" aria-hidden="true">' +
                    '<i style="width:' + fill + '%"></i></span>';
            }
        }

        var title = (rel ? rel + ': ' : '') + (x.title || p.raw) + (isLocal ? ' (local)' : '') +
            (x.note ? '\n\n' + x.note : '');
        var attrs = 'class="' + classes.join(' ') + '" style="--hg-h:' + hs[0] + ';--hg-s:' + hs[1] +
            (hs[2] ? ';--hg-c:' + hs[2] : '') + '" title="' + esc(title) + '"' + (display === 'swatch' ? ' aria-label="' + esc(title) + '"' : '');
        var searchUrl = opts.searchUrl === undefined ? '/events/index/searchtag:' : opts.searchUrl;
        var out;
        if (tag.id) {
            attrs += ' data-tag-id="' + parseInt(tag.id, 10) + '"';
        }
        var href = typeof opts.href === 'function' ? opts.href(x.source || tag) : null;
        if (!href && !opts.href && 'href' in x) {
            href = x.href;
        } else if (!href && !opts.href && tag.id && searchUrl) {
            href = (typeof baseurl !== 'undefined' ? baseurl : '') + searchUrl + parseInt(tag.id, 10);
        }
        if (href) {
            out = '<a href="' + esc(href) + '" ' + attrs + '>' + inner + '</a>';
        } else {
            out = '<span ' + attrs + '>' + inner + '</span>';
        }
        var unit = x.unit || 'data-tag-item data-tag-name="' + esc(p.raw.toLowerCase()) + '"';
        return '<span class="hg-unit" ' + unit + '>' + out + '</span>';
    }

    function wrap(body, opts) {
        return '<span class="hinge-tags' + (opts.cls ? ' ' + esc(opts.cls) : '') + '">' + body + '</span>';
    }

    function chip(tag, opts) {
        opts = opts || {};
        tag = normalise(tag);
        if (!tag || !tag.name) return '';
        return wrap(renderChip(tag, parse(tag.name), 'flow', opts), opts);
    }

    function renderRows(rows, opts) {
        var display = opts.display || 'full';
        var grouping = opts.group !== false && display === 'full';
        var minGroup = opts.minGroup || 2;
        var wideAt = opts.wideAt || 8;
        var groups = [];
        var byKey = {};
        rows.forEach(function (row) {
            var p = row.parsed;
            var x = row.x || {};
            var key;
            if (p.namespace === null || !grouping) {
                key = '\0' + groups.length;
            } else if (x.groupKey !== undefined) {
                key = '\u0002' + x.groupKey;
            } else {
                key = '\u0001' + p.namespace.toLowerCase();
            }
            if (!byKey[key]) {
                byKey[key] = {namespace: p.namespace, galaxy: x.galaxy || null, rows: []};
                groups.push(byKey[key]);
            }
            byKey[key].rows.push(row);
        });
        var body = '';
        groups.forEach(function (g) {
            if (grouping && g.namespace !== null && g.rows.length >= minGroup) {
                var first = g.rows[0].x || {};
                var classes = ['hg-group'];
                if (g.rows.length >= wideAt) classes.push('is-wide');
                if (!g.galaxy && semanticNamespaces().indexOf(g.namespace.toLowerCase()) !== -1) {
                    classes.push('is-varied');
                }
                var head = iconHtml(first);
                if (g.galaxy && g.galaxy.href) {
                    head += '<a class="hg-hns" href="' + esc(g.galaxy.href) + '" title="View galaxy">' +
                        esc(g.namespace) + '</a>';
                } else {
                    head += '<b class="hg-hns">' + esc(g.namespace) + '</b>';
                }
                head += '<span class="hg-count">' + g.rows.length + '</span>';
                var members = '';
                g.rows.forEach(function (row) {
                    members += renderChip(row.tag, row.parsed, 'member', opts, row.x);
                });
                body += '<span class="' + classes.join(' ') + '" style="--hg-h:' +
                    (first.hue !== undefined ? first.hue : hue(g.namespace)) +
                    ';--hg-s:62%" title="' + esc(g.namespace) + '"' +
                    (g.galaxy ? ' data-galaxy-group data-galaxy-name="' + esc(g.galaxy.name.toLowerCase()) + '"' : '') +
                    '><span class="hg-head">' + head + '</span><span class="hg-members">' + members +
                    '</span></span>';
            } else {
                g.rows.forEach(function (row) {
                    body += renderChip(row.tag, row.parsed, 'flow', opts, row.x);
                });
            }
        });
        return body ? wrap(body, opts) : '';
    }

    function collection(tags, opts) {
        opts = opts || {};
        var rows = [];
        (tags || []).forEach(function (raw) {
            var tag = normalise(raw);
            if (!tag || !tag.name) return;
            rows.push({tag: tag, parsed: parse(tag.name)});
        });
        return renderRows(rows, opts);
    }

    function clusterRow(c) {
        var value = String((c && (c.value !== undefined ? c.value : c.name)) || '').trim();
        if (!value) return null;
        var galaxy = String(c.galaxy || '').trim();
        var base = typeof baseurl !== 'undefined' ? baseurl : '';
        var id = parseInt(c.id, 10);
        var galaxyId = parseInt(c.galaxy_id, 10);
        var note = String(c.description || '').trim();
        if (note.length > 300) note = note.slice(0, 300).trim() + '…';
        return {
            tag: {
                id: c.tag_id,
                name: value,
                local: c.local,
                relationship_type: c.relationship_type
            },
            parsed: {
                raw: value,
                namespace: galaxy || null,
                path: [],
                above: [],
                value: value,
                leaf: value
            },
            x: {
                source: c,
                hue: c.hue !== undefined && c.hue !== null ? c.hue : galaxyHue(galaxy),
                iconClass: c.iconClass || null,
                href: id ? base + '/galaxy_clusters/view/' + id : null,
                title: galaxy ? galaxy + ' › ' + value : value,
                note: note,
                groupKey: galaxyId || galaxy.toLowerCase(),
                galaxy: {name: galaxy, href: galaxyId ? base + '/galaxies/view/' + galaxyId : null},
                unit: 'data-cluster-item data-cluster-name="' + esc(value.toLowerCase()) +
                    '" data-galaxy-name="' + esc(galaxy.toLowerCase()) + '"' +
                    (id ? ' data-cluster-id="' + id + '"' : '')
            }
        };
    }

    function cluster(c, opts) {
        opts = opts || {};
        var row = clusterRow(c);
        if (!row) return '';
        return wrap(renderChip(row.tag, row.parsed, 'flow', opts, row.x), opts);
    }

    function clusters(list, opts) {
        return renderRows((list || []).map(clusterRow).filter(Boolean), opts || {});
    }

    root.TagChips = {
        chip: chip,
        collection: collection,
        cluster: cluster,
        clusters: clusters,
        parse: parse,
        hue: hue,
        galaxyHue: galaxyHue
    };
})(window);

/*
 * A collection's "+N" toggle, and the popover listing a folded block's
 * members. Index rows are re-rendered by AJAX, so both are delegated and the
 * popover is built on first hover or focus. Bootstrap's hover trigger closes
 * as soon as the pointer leaves the strip, so the popover is driven here and
 * held open while the pointer is over it.
 */
(function () {
    'use strict';

    var HIDE_DELAY = 160;

    document.addEventListener('click', function (e) {
        var toggle = e.target.closest ? e.target.closest('.hg-overflow') : null;
        if (!toggle) return;
        e.stopPropagation();
        var root = toggle.closest('.hinge-tags');
        var open = root.classList.toggle('is-open');
        toggle.setAttribute('aria-expanded', open ? 'true' : 'false');
        toggle.textContent = open ? '−' : '+' + toggle.dataset.hidden;
    });

    function tipOf(strip) {
        var id = strip.getAttribute('aria-describedby');
        return id ? document.getElementById(id) : null;
    }

    function setup(strip) {
        if (strip._hgFold) return strip._hgFold;
        var template = strip.parentNode.querySelector('template');
        var state = {open: false, timer: null};
        var popover = new bootstrap.Popover(strip, {
            trigger: 'manual',
            html: true,
            content: template.content.cloneNode(true).firstElementChild,
            placement: 'bottom',
            fallbackPlacements: ['top', 'right', 'left'],
            container: 'body',
            customClass: 'hg-pop',
            offset: [0, 6],
        });
        function cancel() {
            clearTimeout(state.timer);
        }
        state.show = function () {
            cancel();
            if (!state.open) {
                state.open = true;
                popover.show();
            }
        };
        state.hide = function (now) {
            cancel();
            var go = function () {
                state.open = false;
                popover.hide();
            };
            if (now) go(); else state.timer = setTimeout(go, HIDE_DELAY);
        };
        strip.addEventListener('inserted.bs.popover', function () {
            var tip = tipOf(strip);
            if (!tip || tip._hgFold) return;
            tip._hgFold = true;
            tip.addEventListener('mouseenter', cancel);
            tip.addEventListener('mouseleave', function () { state.hide(); });
        });
        strip.addEventListener('shown.bs.popover', function () {
            strip.setAttribute('aria-expanded', 'true');
        });
        strip.addEventListener('hidden.bs.popover', function () {
            strip.setAttribute('aria-expanded', 'false');
        });
        strip.addEventListener('mouseleave', function () { state.hide(); });
        strip.addEventListener('focusout', function (e) {
            var tip = tipOf(strip);
            if (!tip || !tip.contains(e.relatedTarget)) state.hide();
        });
        strip.addEventListener('keydown', function (e) {
            if (e.key === 'Escape' && state.open) {
                e.stopPropagation();
                state.hide(true);
            }
        });
        strip._hgFold = state;
        return state;
    }

    function lazy(e) {
        var strip = e.target && e.target.closest ? e.target.closest('.hg-strip') : null;
        if (strip && typeof bootstrap !== 'undefined') setup(strip).show();
    }
    document.addEventListener('mouseenter', lazy, true);
    document.addEventListener('focusin', lazy);
})();
