// IntelGraphThumb — places a thumbnail (IntelGraph.thumbnail()) in a box.
//
// Pure, no DOM. A node with a saved position keeps it relative to the others;
// the rest are laid out around them by a small force layout seeded from each
// node's key, so the same thumbnail always gives the same picture. Then the
// whole is fitted, aspect kept, into the box.
//
//   IntelGraphThumb.layout(thumb, { width, height, padding })
//     → { width, height, scale,
//         nodes: [{ key, type, x, y, pinned }],   box coordinates
//         edges: [{ from, to, kind }] }           indexes into nodes

(function (root) {
    'use strict';

    var IDEAL = 60;
    // Pull toward the middle: unlinked nodes settle about 2.4 ideal lengths apart
    var GRAVITY = 0.3;

    // [0, 1), from FNV-1a
    function hash(text) {
        var h = 2166136261;
        for (var i = 0; i < text.length; i++) {
            h ^= text.charCodeAt(i);
            h = Math.imul(h, 16777619);
        }
        return (h >>> 0) / 4294967296;
    }

    function place(nodes, edges) {
        var fixed = nodes.filter(function (n) { return n.fixed; });
        var free = nodes.filter(function (n) { return !n.fixed; });
        var cx = 0;
        var cy = 0;
        fixed.forEach(function (n) { cx += n.x; cy += n.y; });
        if (fixed.length) {
            cx /= fixed.length;
            cy /= fixed.length;
        }
        var radius = IDEAL * (1 + Math.sqrt(free.length) / 2);
        var neighbours = nodes.map(function () { return []; });
        edges.forEach(function (e) {
            neighbours[e.from].push(e.to);
            neighbours[e.to].push(e.from);
        });
        nodes.forEach(function (n, i) {
            if (n.fixed) return;
            var angle = hash(n.key) * 2 * Math.PI;
            var anchor = null;
            for (var k = 0; k < neighbours[i].length; k++) {
                if (nodes[neighbours[i][k]].fixed) { anchor = nodes[neighbours[i][k]]; break; }
            }
            var r = anchor ? IDEAL : radius * Math.sqrt(hash(n.key + '#'));
            n.x = (anchor ? anchor.x : cx) + Math.cos(angle) * r;
            n.y = (anchor ? anchor.y : cy) + Math.sin(angle) * r;
        });

        // Fruchterman–Reingold; only the free nodes move
        var count = nodes.length;
        var iterations = count > 150 ? 120 : 250;
        var temperature = radius / 3;
        var cooling = temperature / (iterations + 1);
        var dx = new Float64Array(count);
        var dy = new Float64Array(count);
        for (var it = 0; it < iterations; it++) {
            dx.fill(0);
            dy.fill(0);
            for (var a = 0; a < count; a++) {
                for (var b = a + 1; b < count; b++) {
                    var ddx = nodes[a].x - nodes[b].x;
                    var ddy = nodes[a].y - nodes[b].y;
                    var d2 = ddx * ddx + ddy * ddy;
                    if (d2 < 0.01) {
                        ddx = hash(nodes[a].key + nodes[b].key) - 0.5;
                        ddy = 0.5 - hash(nodes[b].key + nodes[a].key);
                        d2 = ddx * ddx + ddy * ddy || 0.01;
                    }
                    var push = IDEAL * IDEAL / d2;
                    dx[a] += ddx * push;
                    dy[a] += ddy * push;
                    dx[b] -= ddx * push;
                    dy[b] -= ddy * push;
                }
            }
            edges.forEach(function (e) {
                var ex = nodes[e.to].x - nodes[e.from].x;
                var ey = nodes[e.to].y - nodes[e.from].y;
                var pull = Math.sqrt(ex * ex + ey * ey) / IDEAL;
                dx[e.from] += ex * pull;
                dy[e.from] += ey * pull;
                dx[e.to] -= ex * pull;
                dy[e.to] -= ey * pull;
            });
            for (var i = 0; i < count; i++) {
                var n = nodes[i];
                if (n.fixed) continue;
                dx[i] += (cx - n.x) * GRAVITY;
                dy[i] += (cy - n.y) * GRAVITY;
                var len = Math.sqrt(dx[i] * dx[i] + dy[i] * dy[i]);
                if (len > 0) {
                    var step = Math.min(len, temperature);
                    n.x += dx[i] / len * step;
                    n.y += dy[i] / len * step;
                }
            }
            temperature -= cooling;
        }
    }

    function fit(nodes, edges, o) {
        var box = { width: o.width, height: o.height, scale: 1, nodes: [], edges: edges };
        if (!nodes.length) return box;
        var minX = Infinity, minY = Infinity, maxX = -Infinity, maxY = -Infinity;
        nodes.forEach(function (n) {
            minX = Math.min(minX, n.x); maxX = Math.max(maxX, n.x);
            minY = Math.min(minY, n.y); maxY = Math.max(maxY, n.y);
        });
        var w = Math.max(o.width - 2 * o.padding, 0);
        var h = Math.max(o.height - 2 * o.padding, 0);
        var spanX = maxX - minX;
        var spanY = maxY - minY;
        // A sparse graph is not stretched to the corners: an edge of the
        // layout's ideal length is drawn at most a fifth of the box's side
        var most = Math.min(w, h) / (5 * IDEAL) * (o.maxZoom || 1);
        var scale = Math.min(spanX > 0 ? w / spanX : Infinity, spanY > 0 ? h / spanY : Infinity, most);
        if (!isFinite(scale) || scale <= 0) scale = 1;
        var ox = o.padding + (w - spanX * scale) / 2 - minX * scale;
        var oy = o.padding + (h - spanY * scale) / 2 - minY * scale;
        box.scale = scale;
        box.nodes = nodes.map(function (n) {
            return { key: n.key, type: n.type, x: n.x * scale + ox, y: n.y * scale + oy, pinned: n.pinned };
        });
        return box;
    }

    function layout(thumb, options) {
        var o = Object.assign({ width: 160, height: 90, padding: 8 }, options || {});
        var nodes = ((thumb && thumb.nodes) || []).map(function (n) {
            var fixed = typeof n.x === 'number' && typeof n.y === 'number' && isFinite(n.x) && isFinite(n.y);
            return { key: String(n.key), type: n.type, x: fixed ? n.x : 0, y: fixed ? n.y : 0, fixed: fixed, pinned: !!n.pinned };
        });
        var edges = ((thumb && thumb.edges) || []).filter(function (e) {
            return Array.isArray(e) && nodes[e[0]] && nodes[e[1]] && e[0] !== e[1];
        }).map(function (e) {
            return { from: e[0], to: e[1], kind: e[2] };
        });
        if (nodes.some(function (n) { return !n.fixed; })) {
            place(nodes, edges);
        }
        return fit(nodes, edges, o);
    }

    root.IntelGraphThumb = { layout: layout };
    if (typeof module !== 'undefined' && module.exports) {
        module.exports = root.IntelGraphThumb;
    }
}(typeof window !== 'undefined' ? window : globalThis));
