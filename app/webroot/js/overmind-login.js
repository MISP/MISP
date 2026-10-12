(function () {
    'use strict';

    var root = document.documentElement;

    var pw = document.getElementById('UserPassword');
    var toggle = document.getElementById('omlPasswordToggle');
    if (pw && toggle) {
        toggle.addEventListener('click', function () {
            var show = pw.type === 'password';
            pw.type = show ? 'text' : 'password';
            toggle.setAttribute('aria-pressed', show ? 'true' : 'false');
            toggle.setAttribute('aria-label', show ? toggle.dataset.labelHide : toggle.dataset.labelShow);
            var icon = toggle.querySelector('i');
            icon.classList.toggle('fa-eye', !show);
            icon.classList.toggle('fa-eye-slash', show);
        });
    }

    // A page left open outlives its CSRF token: fetch a fresh one just before submitting.
    var form = document.querySelector('.oml-panel form[id]');
    if (form && window.fetch && window.DOMParser) {
        form.addEventListener('submit', function (event) {
            event.preventDefault();
            if (!form.checkValidity()) {
                form.reportValidity();
                return;
            }
            var submit = form.querySelector('[type="submit"]');
            if (submit) {
                submit.disabled = true;
            }
            fetch(form.action, {
                credentials: 'same-origin',
                cache: 'no-store',
                headers: {'X-Requested-With': 'XMLHttpRequest'}
            }).then(function (response) {
                return response.text();
            }).then(function (html) {
                var fresh = new DOMParser().parseFromString(html, 'text/html').getElementById(form.id);
                if (!fresh) {
                    window.location = form.action;
                    return;
                }
                // Only the token: a checkbox's hidden "0" must stay ahead of the checkbox.
                form.querySelectorAll('input[name^="data[_Token]"]').forEach(function (input) {
                    input.remove();
                });
                fresh.querySelectorAll('input[name^="data[_Token]"]').forEach(function (input) {
                    form.appendChild(document.importNode(input, true));
                });
                form.submit();
            }).catch(function () {
                form.submit();
            });
        });
    }

    var customPerms = document.getElementById('UserCustomPerms');
    var rolePerms = document.getElementById('omlRolePerms');
    if (customPerms && rolePerms) {
        var syncRolePerms = function () {
            rolePerms.hidden = !customPerms.checked;
            customPerms.setAttribute('aria-expanded', customPerms.checked ? 'true' : 'false');
            if (!customPerms.checked) {
                rolePerms.querySelectorAll('input[type="checkbox"]').forEach(function (input) {
                    input.checked = false;
                });
            }
        };
        customPerms.addEventListener('change', syncRolePerms);
        syncRolePerms();
    }

    var canvas = document.getElementById('omlSky');
    var ctx = canvas && canvas.getContext ? canvas.getContext('2d') : null;
    if (!ctx) {
        return;
    }
    var host = canvas.closest('.oml') || root;
    var panel = host.querySelector('.oml-panel');
    var portEls = [document.getElementById('omlPortHub'), document.getElementById('omlPortSide')].filter(Boolean);
    var mqReduce = window.matchMedia('(prefers-reduced-motion: reduce)');

    // Sharing communities: instances hold events, events hold attributes,
    // instances sync across communities, and the panel's ports join the graph.
    var W = 0, H = 0, dpr = 1;
    var nodes = [], edges = [], adj = [], pulses = [], corrs = [];
    var pal = {};
    var pointer = {x: -9999, y: -9999, active: false};
    var raf = 0, last = 0, nextPulse = 0, nextPortPulse = 0, portTurn = 0, resizeTimer = 0;
    var LINK = 150, POINTER_R = 170;
    var EDGE_STYLE = {
        attr: {a: 0.75, w: 0.7},
        event: {a: 1.15, w: 0.9},
        local: {a: 1.1, w: 1},
        bridge: {a: 1, w: 1},
        port: {a: 1.5, w: 1.1}
    };

    function readPalette() {
        var cs = getComputedStyle(host);
        function v(n) { return cs.getPropertyValue(n).trim(); }
        pal = {
            a: v('--oml-c-node-a'), b: v('--oml-c-node-b'), c: v('--oml-c-node-c'),
            link: v('--oml-c-link'), pulse: v('--oml-c-pulse'),
            corr: v('--oml-c-corr'), badge: v('--oml-c-badge'),
            linkAlpha: parseFloat(v('--oml-c-link-alpha')) || 0.25,
            nodeAlpha: parseFloat(v('--oml-c-node-alpha')) || 0.6,
            instAlpha: parseFloat(v('--oml-c-inst-alpha')) || 0.85,
            facets: v('--oml-c-facets').split('|').map(function (s) { return s.trim(); }),
            satLeft: v('--oml-c-sat-left'), satRight: v('--oml-c-sat-right')
        };
    }

    function rand(a, b) { return a + Math.random() * (b - a); }
    function randInt(a, b) { return Math.floor(rand(a, b + 1)); }
    function clamp(v, a, b) { return Math.max(a, Math.min(b, v)); }
    function pick(list) { return list[Math.floor(Math.random() * list.length)]; }
    function dist(a, b) { return Math.hypot(a.x - b.x, a.y - b.y); }

    function panelRect(pad) {
        var r = panel ? panel.getBoundingClientRect() : {left: 0, top: 0, right: 0, bottom: 0};
        return {l: r.left - pad, t: r.top - pad, r: r.right + pad, b: r.bottom + pad};
    }

    function inRect(x, y, q) {
        return x > q.l && x < q.r && y > q.t && y < q.b;
    }

    function crossesPanel(a, b) {
        var q = panelRect(10);
        for (var s = 0; s <= 16; s++) {
            if (inRect(a.x + (b.x - a.x) * s / 16, a.y + (b.y - a.y) * s / 16, q)) {
                return true;
            }
        }
        return false;
    }

    function node(o) {
        return Object.assign({vx: 0, vy: 0, ox: 0, oy: 0, glow: 0, parent: null, comm: -1, tone: 'a'}, o);
    }

    function seedCommunities() {
        var count = clamp(Math.round(W * H / 260000), 3, 6);
        var R = clamp(Math.min(W, H) * 0.15, 70, 140);
        var avoid = panelRect(R * 0.8);
        var centres = [];
        for (var tries = 0; centres.length < count && tries < 900; tries++) {
            var c = {x: rand(R * 0.6, W - R * 0.6), y: rand(R * 0.6, H - R * 0.6)};
            var relaxed = tries >= 600;
            if (!relaxed && inRect(c.x, c.y, avoid)) {
                continue;
            }
            var gap = relaxed ? R * 1.6 : R * 2.3;
            if (centres.every(function (o) { return dist(o, c) > gap; })) {
                centres.push(c);
            }
        }

        centres.forEach(function (c, ci) {
            var instances = [];
            var pair = R > 100 && Math.random() < 0.35;
            var spin = rand(0, Math.PI * 2);
            for (var k = 0; k < (pair ? 2 : 1); k++) {
                var ix = pair ? c.x + Math.cos(spin + k * Math.PI) * R * 0.42 : c.x;
                var iy = pair ? c.y + Math.sin(spin + k * Math.PI) * R * 0.42 : c.y;
                instances.push(nodes.length);
                nodes.push(node({x: ix, y: iy, hx: ix, hy: iy, comm: ci, kind: 'instance', r: rand(14, 16.5), tone: 'b'}));
            }
            var eventCount = randInt(3, 5), base = rand(0, Math.PI * 2);
            for (var e = 0; e < eventCount; e++) {
                var ang = base + e * Math.PI * 2 / eventCount + rand(-0.35, 0.35);
                var d = rand(R * 0.5, R * 0.98);
                var ev = {x: c.x + Math.cos(ang) * d, y: c.y + Math.sin(ang) * d};
                var parent = instances.reduce(function (best, i) {
                    return dist(nodes[i], ev) < dist(nodes[best], ev) ? i : best;
                }, instances[0]);
                var ei = nodes.length;
                nodes.push(node({
                    x: ev.x, y: ev.y, hx: ev.x, hy: ev.y, comm: ci, kind: 'event', parent: parent,
                    r: rand(5.6, 6.6), tone: Math.random() < 0.5 ? 'a' : 'b'
                }));
                var attrCount = randInt(2, 4), attrBase = rand(0, Math.PI * 2);
                for (var t = 0; t < attrCount; t++) {
                    nodes.push(node({
                        x: ev.x, y: ev.y, comm: ci, kind: 'attribute', parent: ei,
                        offA: attrBase + t * Math.PI * 2 / attrCount + rand(-0.4, 0.4), offD: rand(17, 31),
                        spin: rand(0.0008, 0.0022) * (Math.random() < 0.5 ? -1 : 1),
                        r: rand(1.8, 2.6), tone: Math.random() < 0.6 ? 'c' : 'a'
                    }));
                }
            }
        });

        var strays = clamp(Math.round(W * H / 110000), 4, 14);
        for (var s = 0; s < strays; s++) {
            nodes.push(node({
                x: rand(0, W), y: rand(0, H), vx: rand(-0.1, 0.1), vy: rand(-0.1, 0.1),
                kind: 'stray', r: rand(1.6, 3), hollow: Math.random() < 0.3, tone: pick(['a', 'b', 'c'])
            }));
        }
    }

    function updatePorts() {
        for (var i = 0; i < nodes.length; i++) {
            var n = nodes[i];
            if (n.kind === 'port') {
                var r = n.el.getBoundingClientRect();
                n.x = r.left + r.width / 2;
                n.y = r.top + r.height / 2;
            }
        }
    }

    function layoutAttributes() {
        for (var i = 0; i < nodes.length; i++) {
            var n = nodes[i];
            if (n.kind === 'attribute') {
                var p = nodes[n.parent];
                n.x = p.x + p.ox + Math.cos(n.offA) * n.offD;
                n.y = p.y + p.oy + Math.sin(n.offA) * n.offD;
            }
        }
    }

    function buildEdges() {
        edges = [];
        var byComm = {};
        nodes.forEach(function (n, i) {
            if (n.parent !== null) {
                edges.push({a: n.parent, b: i, t: n.kind === 'attribute' ? 'attr' : 'event'});
            }
            if (n.kind === 'instance') {
                (byComm[n.comm] = byComm[n.comm] || []).push(i);
            }
        });

        var reps = Object.keys(byComm).map(function (c) {
            if (byComm[c].length > 1) {
                edges.push({a: byComm[c][0], b: byComm[c][1], t: 'local'});
            }
            return byComm[c][0];
        });
        // a minimum spanning tree keeps every community reachable with few, short bridges
        var linked = reps.slice(0, 1), rest = reps.slice(1);
        while (rest.length) {
            var best = null;
            linked.forEach(function (a) {
                rest.forEach(function (b) {
                    var d = dist(nodes[a], nodes[b]);
                    if (!best || d < best.d) {
                        best = {a: a, b: b, d: d};
                    }
                });
            });
            edges.push({a: best.a, b: best.b, t: 'bridge'});
            linked.push(best.b);
            rest.splice(rest.indexOf(best.b), 1);
        }
        if (reps.length >= 4) {
            var far = reps.reduce(function (f, b) {
                return dist(nodes[reps[0]], nodes[b]) > dist(nodes[reps[0]], nodes[f]) ? b : f;
            }, reps[1]);
            var exists = edges.some(function (e) {
                return (e.a === reps[0] && e.b === far) || (e.a === far && e.b === reps[0]);
            });
            if (!exists) {
                edges.push({a: reps[0], b: far, t: 'bridge'});
            }
        }

        updatePorts();
        var inside = panelRect(0), used = [];
        nodes.forEach(function (p, pi) {
            if (p.kind !== 'port') {
                return;
            }
            var nearest = -1;
            nodes.forEach(function (n, i) {
                if (n.kind !== 'instance' || used.indexOf(i) >= 0 || inRect(n.x, n.y, inside)) {
                    return;
                }
                if (nearest < 0 || dist(n, p) < dist(nodes[nearest], p)) {
                    nearest = i;
                }
            });
            if (nearest >= 0) {
                used.push(nearest);
                edges.push({a: nearest, b: pi, t: 'port'});
            }
        });

        adj = nodes.map(function () { return []; });
        edges.forEach(function (e) {
            adj[e.a].push(e.b);
            adj[e.b].push(e.a);
        });
    }

    function seed() {
        nodes = [];
        pulses = [];
        corrs = [];
        seedCommunities();
        portEls.forEach(function (el) {
            nodes.push(node({x: -999, y: -999, kind: 'port', el: el, r: 7}));
        });
        layoutAttributes();
        buildEdges();
    }

    function resize() {
        dpr = Math.min(window.devicePixelRatio || 1, 2);
        W = window.innerWidth;
        H = window.innerHeight;
        canvas.width = Math.round(W * dpr);
        canvas.height = Math.round(H * dpr);
        ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
        seed();
        if (!raf) {
            staticFrame();
        }
    }

    function hexPoint(x, y, r, k) {
        var ang = Math.PI / 3 * k - Math.PI / 2;
        return [x + r * Math.cos(ang), y + r * Math.sin(ang)];
    }

    function hexPath(x, y, r) {
        ctx.beginPath();
        for (var k = 0; k < 6; k++) {
            var p = hexPoint(x, y, r, k);
            if (k === 0) {
                ctx.moveTo(p[0], p[1]);
            } else {
                ctx.lineTo(p[0], p[1]);
            }
        }
        ctx.closePath();
    }

    function rgba(rgb, alpha) {
        return 'rgba(' + rgb + ',' + alpha.toFixed(3) + ')';
    }

    // the mark's construction: a hexagon ring cut into six shaded facets
    function instanceGlyph(x, y, r, alpha) {
        var ri = r * 0.46;
        hexPath(x, y, ri);
        ctx.fillStyle = 'rgb(' + pal.badge + ')';
        ctx.fill();
        for (var k = 0; k < 6; k++) {
            var o1 = hexPoint(x, y, r, k), o2 = hexPoint(x, y, r, k + 1);
            var i1 = hexPoint(x, y, ri, k), i2 = hexPoint(x, y, ri, k + 1);
            ctx.beginPath();
            ctx.moveTo(o1[0], o1[1]);
            ctx.lineTo(o2[0], o2[1]);
            ctx.lineTo(i2[0], i2[1]);
            ctx.lineTo(i1[0], i1[1]);
            ctx.closePath();
            ctx.fillStyle = rgba(pal.facets[k], alpha);
            ctx.fill();
        }
        var s = Math.max(1.9, r * 0.24);
        hexPath(x - r * 1.18, y - r * 1.02, s);
        ctx.fillStyle = rgba(pal.satLeft, alpha);
        ctx.fill();
        hexPath(x + r * 1.18, y - r * 1.02, s);
        ctx.fillStyle = rgba(pal.satRight, alpha);
        ctx.fill();
    }

    function px(i) { return nodes[i].x + nodes[i].ox; }
    function py(i) { return nodes[i].y + nodes[i].oy; }

    function envelope(life) {
        return clamp(life < 0.15 ? life / 0.15 : life > 0.7 ? (1 - life) / 0.3 : 1, 0, 1);
    }

    function drawCorrelation(c) {
        var env = envelope(c.life);
        var ax = px(c.a), ay = py(c.a), bx = px(c.b), by = py(c.b);
        ctx.setLineDash([4, 4]);
        ctx.lineWidth = 1.2;
        ctx.strokeStyle = rgba(pal.corr, 0.75 * env);
        ctx.beginPath();
        ctx.moveTo(ax, ay);
        ctx.lineTo(bx, by);
        ctx.stroke();
        ctx.setLineDash([]);
        ctx.strokeStyle = rgba(pal.corr, 0.8 * env);
        hexPath(ax, ay, nodes[c.a].r + 5);
        ctx.stroke();
        hexPath(bx, by, nodes[c.b].r + 5);
        ctx.stroke();
        var mx = (ax + bx) / 2, my = (ay + by) / 2;
        ctx.beginPath();
        ctx.arc(mx, my, 7.5, 0, Math.PI * 2);
        ctx.fillStyle = rgba(pal.badge, 0.95 * env);
        ctx.fill();
        ctx.strokeStyle = rgba(pal.corr, 0.9 * env);
        ctx.stroke();
        ctx.beginPath();
        ctx.moveTo(mx - 3.2, my - 1.8);
        ctx.lineTo(mx + 3.2, my - 1.8);
        ctx.moveTo(mx - 3.2, my + 1.8);
        ctx.lineTo(mx + 3.2, my + 1.8);
        ctx.stroke();
    }

    function drawPulse(p) {
        var x1 = px(p.a), y1 = py(p.a), x2 = px(p.b), y2 = py(p.b);
        var hx = x1 + (x2 - x1) * p.t, hy = y1 + (y2 - y1) * p.t;
        var tail = Math.max(0, p.t - p.tail);
        var tx = x1 + (x2 - x1) * tail, ty = y1 + (y2 - y1) * tail;
        var grad = ctx.createLinearGradient(tx, ty, hx, hy);
        grad.addColorStop(0, rgba(pal.pulse, 0));
        grad.addColorStop(1, rgba(pal.pulse, 0.85));
        ctx.strokeStyle = grad;
        ctx.lineWidth = 1.6;
        ctx.beginPath();
        ctx.moveTo(tx, ty);
        ctx.lineTo(hx, hy);
        ctx.stroke();
        ctx.fillStyle = rgba(pal.pulse, 0.25);
        ctx.beginPath();
        ctx.arc(hx, hy, 5, 0, Math.PI * 2);
        ctx.fill();
        ctx.fillStyle = rgba(pal.pulse, 0.95);
        ctx.beginPath();
        ctx.arc(hx, hy, 1.8, 0, Math.PI * 2);
        ctx.fill();
    }

    function drawNode(a, x, y) {
        var col = pal[a.tone];
        var alpha = Math.min(1, pal.nodeAlpha + a.glow * 0.5) * (a.kind === 'stray' ? 0.6 : 1);
        if (a.glow > 0.02) {
            ctx.strokeStyle = rgba(pal.pulse, a.glow * 0.6);
            ctx.lineWidth = 1;
            hexPath(x, y, a.r + 4 + (1 - a.glow) * 8);
            ctx.stroke();
        }
        if (a.kind === 'instance') {
            instanceGlyph(x, y, a.r, Math.min(1, pal.instAlpha + a.glow * 0.15));
            return;
        }
        hexPath(x, y, a.r);
        if (a.kind === 'event') {
            ctx.fillStyle = rgba(col, alpha * 0.18);
            ctx.fill();
        }
        if (a.kind === 'event' || a.hollow) {
            ctx.strokeStyle = rgba(col, alpha);
            ctx.lineWidth = a.kind === 'event' ? 1.3 : 1.2;
            ctx.stroke();
        } else {
            ctx.fillStyle = rgba(col, alpha);
            ctx.fill();
        }
    }

    function draw() {
        ctx.clearRect(0, 0, W, H);
        var i, j, a, b;

        ctx.lineWidth = 0.8;
        for (i = 0; i < nodes.length; i++) {
            a = nodes[i];
            if (a.kind !== 'event') {
                continue;
            }
            for (j = i + 1; j < nodes.length; j++) {
                b = nodes[j];
                if (b.kind !== 'event' || b.comm !== a.comm) {
                    continue;
                }
                var d = Math.hypot(px(i) - px(j), py(i) - py(j));
                if (d < LINK) {
                    ctx.strokeStyle = rgba(pal.link, (1 - d / LINK) * pal.linkAlpha * 0.6);
                    ctx.beginPath();
                    ctx.moveTo(px(i), py(i));
                    ctx.lineTo(px(j), py(j));
                    ctx.stroke();
                }
            }
        }

        for (i = 0; i < edges.length; i++) {
            var e = edges[i], st = EDGE_STYLE[e.t];
            ctx.strokeStyle = rgba(pal.link, Math.min(1, pal.linkAlpha * st.a));
            ctx.lineWidth = st.w;
            ctx.beginPath();
            ctx.moveTo(px(e.a), py(e.a));
            ctx.lineTo(px(e.b), py(e.b));
            ctx.stroke();
        }

        corrs.forEach(drawCorrelation);
        pulses.forEach(drawPulse);

        for (i = 0; i < nodes.length; i++) {
            if (nodes[i].kind !== 'port') {
                drawNode(nodes[i], px(i), py(i));
            }
        }
    }

    function makePulse(a, b, hops, crossed) {
        var len = Math.max(20, Math.hypot(px(b) - px(a), py(b) - py(a)));
        var bridge = nodes[a].kind === 'instance' && nodes[b].kind === 'instance';
        return {
            a: a, b: b, t: 0, hops: hops, crossed: crossed,
            v: (bridge ? 2.6 : 1.3) * rand(0.85, 1.2) / len,
            tail: Math.min(0.6, 30 / len)
        };
    }

    // pulses climb from an attribute to its instance, may cross to another
    // community, then fan back down
    function nextHop(cur, prev, crossed) {
        var options = adj[cur].filter(function (j) { return j !== prev; });
        if (!options.length) {
            return -1;
        }
        var kind = nodes[cur].kind, want = null;
        if (!crossed) {
            want = {attribute: ['event'], event: ['instance'], instance: ['instance', 'port']}[kind];
        } else {
            want = {instance: ['event'], event: ['attribute']}[kind];
        }
        if (want) {
            var preferred = options.filter(function (j) { return want.indexOf(nodes[j].kind) >= 0; });
            if (preferred.length) {
                return pick(preferred);
            }
        }
        return pick(options);
    }

    function spawnPulse() {
        var attributes = [];
        nodes.forEach(function (n, i) {
            if (n.kind === 'attribute') {
                attributes.push(i);
            }
        });
        if (!attributes.length) {
            return;
        }
        var from = pick(attributes), to = nextHop(from, -1, false);
        if (to >= 0) {
            pulses.push(makePulse(from, to, randInt(3, 6), false));
        }
    }

    function spawnPortPulse() {
        var ports = edges.filter(function (e) { return e.t === 'port'; });
        if (ports.length) {
            var e = ports[portTurn++ % ports.length];
            pulses.push(makePulse(e.a, e.b, 0, true));
        }
    }

    function lightPort(el) {
        el.classList.remove('oml-lit');
        void el.getBoundingClientRect();
        el.classList.add('oml-lit');
        clearTimeout(el.omlTimer);
        el.omlTimer = setTimeout(function () { el.classList.remove('oml-lit'); }, 60);
    }

    function spawnCorrelation(from) {
        if (corrs.length >= 2) {
            return;
        }
        var src = nodes[from];
        for (var tries = 0; tries < 14; tries++) {
            var j = Math.floor(Math.random() * nodes.length), n = nodes[j];
            if (n.kind !== 'attribute' || n.comm === src.comm) {
                continue;
            }
            var d = dist(n, src);
            if (d < 140 || d > Math.max(W, H) * 0.55 || crossesPanel(src, n)) {
                continue;
            }
            corrs.push({a: from, b: j, life: 0});
            return;
        }
    }

    function arrive(p) {
        var n = nodes[p.b];
        n.glow = 1;
        if (n.kind === 'port') {
            lightPort(n.el);
            return;
        }
        if (n.kind === 'attribute' && Math.random() < 0.45) {
            spawnCorrelation(p.b);
        }
        if (p.hops > 0 && pulses.length < 9) {
            var crossed = p.crossed || (nodes[p.a].kind === 'instance' && n.kind === 'instance');
            var next = nextHop(p.b, p.a, crossed);
            if (next >= 0) {
                pulses.push(makePulse(p.b, next, p.hops - 1, crossed));
            }
        }
    }

    function step(now) {
        var dt = last ? Math.min(50, now - last) : 16;
        last = now;
        var f = dt / 16.67;
        var i, a;

        updatePorts();
        for (i = 0; i < nodes.length; i++) {
            a = nodes[i];
            if (a.kind === 'port') {
                continue;
            }
            if (a.kind === 'stray') {
                a.x += a.vx * f;
                a.y += a.vy * f;
                if (a.x < -20) { a.x = W + 20; } else if (a.x > W + 20) { a.x = -20; }
                if (a.y < -20) { a.y = H + 20; } else if (a.y > H + 20) { a.y = -20; }
            } else if (a.kind === 'attribute') {
                a.offA += a.spin * f;
            } else {
                // wander, but stay with the community
                a.vx = clamp((a.vx + ((Math.random() - 0.5) * 0.012 + (a.hx - a.x) * 0.00004) * f) * 0.992, -0.16, 0.16);
                a.vy = clamp((a.vy + ((Math.random() - 0.5) * 0.012 + (a.hy - a.y) * 0.00004) * f) * 0.992, -0.16, 0.16);
                a.x += a.vx * f;
                a.y += a.vy * f;
            }

            var tx = 0, ty = 0;
            if (pointer.active) {
                var dx = a.x - pointer.x, dy = a.y - pointer.y;
                var d = Math.sqrt(dx * dx + dy * dy);
                if (d < POINTER_R && d > 0.01) {
                    var push = 1 - d / POINTER_R;
                    push = push * push * 26;
                    tx = dx / d * push;
                    ty = dy / d * push;
                }
            }
            a.ox += (tx - a.ox) * 0.08 * f;
            a.oy += (ty - a.oy) * 0.08 * f;
            if (a.glow > 0) {
                a.glow = Math.max(0, a.glow - 0.012 * f);
            }
        }
        layoutAttributes();

        if (now > nextPulse && pulses.length < 6) {
            spawnPulse();
            nextPulse = now + rand(700, 1600);
        }
        if (now > nextPortPulse) {
            if (nextPortPulse) {
                spawnPortPulse();
            }
            nextPortPulse = now + rand(3500, 5500);
        }
        for (i = pulses.length - 1; i >= 0; i--) {
            var p = pulses[i];
            p.t += p.v * f;
            if (p.t >= 1) {
                pulses.splice(i, 1);
                arrive(p);
            }
        }
        for (i = corrs.length - 1; i >= 0; i--) {
            var c = corrs[i];
            c.life += dt / 2800;
            var env = envelope(c.life);
            nodes[c.a].glow = Math.max(nodes[c.a].glow, env * 0.6);
            nodes[c.b].glow = Math.max(nodes[c.b].glow, env * 0.6);
            if (c.life >= 1) {
                corrs.splice(i, 1);
            }
        }

        draw();
        raf = requestAnimationFrame(step);
    }

    // one representative frame, for reduced motion
    function staticFrame() {
        pulses = [];
        corrs = [];
        updatePorts();
        for (var i = 0; i < nodes.length; i++) {
            nodes[i].ox = nodes[i].oy = 0;
            nodes[i].glow = 0;
        }
        layoutAttributes();
        ['bridge', 'event', 'attr', 'port'].forEach(function (type) {
            var list = edges.filter(function (e) { return e.t === type; });
            if (list.length) {
                var e = pick(list), p = makePulse(e.a, e.b, 0, false);
                p.t = rand(0.45, 0.7);
                pulses.push(p);
            }
        });
        for (var tries = 30; !corrs.length && tries > 0; tries--) {
            var from = Math.floor(Math.random() * nodes.length);
            if (nodes[from].kind === 'attribute') {
                spawnCorrelation(from);
            }
        }
        corrs.forEach(function (c) {
            c.life = 0.4;
            nodes[c.a].glow = nodes[c.b].glow = 0.6;
        });
        draw();
    }

    function start() {
        if (raf || mqReduce.matches || document.hidden) {
            return;
        }
        last = 0;
        raf = requestAnimationFrame(step);
    }

    function stop() {
        if (raf) {
            cancelAnimationFrame(raf);
        }
        raf = 0;
    }

    window.addEventListener('resize', function () {
        clearTimeout(resizeTimer);
        resizeTimer = setTimeout(resize, 120);
    });
    window.addEventListener('pointermove', function (e) {
        pointer.x = e.clientX;
        pointer.y = e.clientY;
        pointer.active = true;
    }, {passive: true});
    document.addEventListener('pointerleave', function () { pointer.active = false; });
    window.addEventListener('blur', function () { pointer.active = false; });
    document.addEventListener('visibilitychange', function () {
        if (document.hidden) {
            stop();
        } else {
            start();
        }
    });
    if (mqReduce.addEventListener) {
        mqReduce.addEventListener('change', function () {
            if (mqReduce.matches) {
                stop();
                staticFrame();
            } else {
                start();
            }
        });
    }
    new MutationObserver(function () {
        readPalette();
        if (!raf) {
            draw();
        }
    }).observe(root, {attributes: true, attributeFilter: ['data-misp-mode']});

    readPalette();
    resize();
    start();
})();
