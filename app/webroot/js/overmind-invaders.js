(function () {
    'use strict';

    var CLICKS_TO_LAUNCH = 4;
    var CLICK_WINDOW = 400;     // ms a click waits for its successor

    var W = 480, H = 360;       // logical canvas, scaled by CSS
    var AW = 26, AH = 21;       // invader box — the glyphs are 1.25:1
    var SW = 30, SH = 30;       // ship box — the logo is square
    var SHIP_Y = H - 40;
    var COLS = 8, ROWS = 4;
    var OVER_LOCK = 700;        // ms an end screen ignores the keyboard
    var BEST_KEY = 'mispInvadersBest';

    var ATTR_COLOUR = ['#e8c547', '#4fc3dd', '#4fc3dd', '#7ad3a1'];
    var OBJ_COLOUR = ['#ff8f5a', '#c9a0ff'];    // index by hp - 1: hurt, whole

    var CSS =
        '.mi-overlay{position:fixed;inset:0;z-index:20000;display:flex;align-items:center;' +
        'justify-content:center;background:rgba(20,13,14,.9);backdrop-filter:blur(3px);}' +
        '.mi-box{font-family:ui-monospace,SFMono-Regular,Menlo,monospace;color:#e6eef0;text-align:center;}' +
        '.mi-bar{display:flex;;gap:1rem;justify-content:space-between;padding:0 .25rem .5rem;}' +
        '.mi-title{color:#1892B1;letter-spacing:.18em;font-size:.8rem;font-weight:700;}' +
        '.mi-hud{font-size:.75rem;opacity:.85;}' +
        '.mi-hud b{color:#e8c547;font-weight:700;}' +
        '.mi-close{background:none;border:0;color:#e6eef0;font-size:1.4rem;line-height:1;opacity:.6;cursor:pointer;}' +
        '.mi-close:hover{opacity:1;}' +
        '.mi-canvas{display:block;width:min(92vw,720px);height:auto;' +
        'background:#0d0708;border:1px solid rgba(24,146,177,.45);border-radius:.35rem;}' +
        '.mi-foot{padding-top:.5rem;font-size:.7rem;opacity:.55;letter-spacing:.06em;}';

    // --- launcher ---------------------------------------------------------

    function bindLogo() {
        var logo = document.querySelector('.navbar-brand .navbar-logo');
        if (!logo) { return; }
        var link = logo.closest('a');
        var count = 0, timer = null;

        logo.addEventListener('click', function (e) {
            if (e.detail === 0) { return; }
            if (e.button !== 0 || e.ctrlKey || e.metaKey || e.shiftKey || e.altKey) { return; }
            e.preventDefault();
            window.clearTimeout(timer);
            if (++count >= CLICKS_TO_LAUNCH) {
                count = 0;
                if (link) { link.blur(); }
                launch(logo);
                return;
            }
            timer = window.setTimeout(function () {
                count = 0;
                if (link && link.href) { window.location.href = link.href; }
            }, CLICK_WINDOW);
        });
    }

    // --- artwork ----------------------------------------------------------
    function maskUrl(name) {
        var probe = document.createElement('i');
        probe.className = 'misp-icon misp-icon-' + name + ' misp-simple';
        probe.style.cssText = 'position:absolute;visibility:hidden';
        document.body.appendChild(probe);
        var css = window.getComputedStyle(probe);
        var raw = css.maskImage || css.webkitMaskImage || '';
        probe.remove();
        var found = raw.match(/url\((['"]?)(.*?)\1\)/);
        return found ? found[2] : null;
    }

    function load(id, src, done) {
        if (!src) { return done(null); }
        var img = new Image();
        img.onload = function () { img.id = id; done(img); };
        img.onerror = function () { done(null); };
        img.src = src;
    }

    var tints = {};
    function tinted(img, colour) {
        if (!img) { return null; }
        var key = img.id + colour;
        if (!tints[key]) {
            var off = document.createElement('canvas');
            off.width = AW;
            off.height = AH;
            var g = off.getContext('2d');
            g.drawImage(img, 0, 0, AW, AH);
            g.globalCompositeOperation = 'source-in';
            g.fillStyle = colour;
            g.fillRect(0, 0, AW, AH);
            tints[key] = off;
        }
        return tints[key];
    }

    // --- the game ---------------------------------------------------------

    function launch(logo) {
        if (document.querySelector('.mi-overlay')) { return; }

        var style = document.createElement('style');
        style.textContent = CSS;
        document.head.appendChild(style);

        var overlay = document.createElement('div');
        overlay.className = 'mi-overlay';
        overlay.innerHTML =
            '<div class="mi-box">' +
                '<div class="mi-bar">' +
                    '<span class="mi-title">MISP INVADERS</span>' +
                    '<span class="mi-hud">score <b class="mi-score">0</b> &middot; best ' +
                        '<b class="mi-best">0</b> &middot; <b class="mi-lives"></b></span>' +
                    '<button type="button" class="mi-close" aria-label="Close">&times;</button>' +
                '</div>' +
                '<canvas class="mi-canvas" width="' + W + '" height="' + H + '"></canvas>' +
                '<div class="mi-foot">&larr; &rarr; move &middot; space fire &middot; esc quit</div>' +
            '</div>';
        document.body.appendChild(overlay);

        var ctx = overlay.querySelector('.mi-canvas').getContext('2d');
        var elScore = overlay.querySelector('.mi-score');
        var elBest = overlay.querySelector('.mi-best');
        var elLives = overlay.querySelector('.mi-lives');
        var art = {}, pending = 3;
        var keys = {}, raf = null, last = 0, best = readBest(), s, closed = false;

        function ready(name) {
            return function (img) {
                art[name] = img;
                if (--pending === 0 && !closed) {
                    wave(1, 0, 1);
                    raf = window.requestAnimationFrame(function (t) { last = t; frame(t); });
                }
            };
        }
        load('ship', logo.currentSrc || logo.src, ready('ship'));
        load('attr', maskUrl('attribute'), ready('attr'));
        load('obj', maskUrl('object'), ready('obj'));

        function wave(level, score, lives) {
            var aliens = [], r, c, mid;
            for (r = 0; r < ROWS; r++) {
                for (c = 0; c < COLS; c++) {
                    // Objects are the core of the formation, attributes its skin.
                    mid = (r === 1 || r === 2) && (c === 2 || c === 3 || c === 4 || c === 5);
                    aliens.push({
                        x: 73 + c * 44, y: 34 + r * 30, row: r,
                        object: mid, hp: mid ? 2 : 1, alive: true
                    });
                }
            }
            keys = {};
            s = {
                level: level, score: score, lives: lives, aliens: aliens,
                ship: {x: W / 2 - SW / 2, cd: 0}, shots: [], bombs: [], booms: [],
                dir: 1, stepIn: 0, bombIn: 900, over: null, overAt: 0
            };
            paintHud();
        }

        function paintHud() {
            elScore.textContent = s.score;
            elBest.textContent = best;
            elLives.textContent = new Array(s.lives + 1).join('♥') || '–';
        }


        function march() {
            var minX = W, maxX = 0, i, a;
            for (i = 0; i < s.aliens.length; i++) {
                a = s.aliens[i];
                if (!a.alive) { continue; }
                if (a.x < minX) { minX = a.x; }
                if (a.x + AW > maxX) { maxX = a.x + AW; }
            }
            var edge = s.dir > 0 ? maxX + 10 > W - 8 : minX - 10 < 8;
            for (i = 0; i < s.aliens.length; i++) {
                if (edge) { s.aliens[i].y += 14; } else { s.aliens[i].x += 10 * s.dir; }
            }
            if (edge) { s.dir *= -1; }
        }

        function alive() {
            return s.aliens.filter(function (a) { return a.alive; });
        }

        function hits(a, b) {
            return a.x < b.x + b.w && a.x + a.w > b.x && a.y < b.y + b.h && a.y + a.h > b.y;
        }

        function boom(x, y, small) {
            s.booms.push({x: x, y: y, t: 0, r: small ? 16 : 40});
        }

        function update(dt) {
            if (s.over) { return; }
            var i, a, list = alive();

            // Ship
            if (keys.left) { s.ship.x -= 190 * dt; }
            if (keys.right) { s.ship.x += 190 * dt; }
            s.ship.x = Math.max(8, Math.min(W - 8 - SW, s.ship.x));
            s.ship.cd -= dt;
            if (keys.fire && s.ship.cd <= 0 && s.shots.length < 2) {
                s.shots.push({x: s.ship.x + SW / 2 - 1, y: SHIP_Y - 6, w: 2, h: 8});
                s.ship.cd = 0.32;
            }

            // The grid speeds up as it thins out, and each wave starts faster.
            s.stepIn -= dt * 1000;
            if (s.stepIn <= 0) {
                march();
                s.stepIn = Math.max(80, (560 * list.length / (COLS * ROWS) + 60) / (1 + s.level * 0.15));
            }

            // Bombs, dropped by whoever is lowest in a random column
            s.bombIn -= dt * 1000;
            if (s.bombIn <= 0 && list.length) {
                var pick = list[Math.floor(Math.random() * list.length)];
                list.forEach(function (o) {
                    if (o.x === pick.x && o.y > pick.y) { pick = o; }
                });
                s.bombs.push({x: pick.x + AW / 2 - 1, y: pick.y + AH, w: 3, h: 8});
                s.bombIn = Math.max(320, 950 - s.level * 90 - (COLS * ROWS - list.length) * 12);
            }

            for (i = s.shots.length - 1; i >= 0; i--) {
                var sh = s.shots[i];
                sh.y -= 340 * dt;
                if (sh.y < -8) { s.shots.splice(i, 1); continue; }
                for (var j = 0; j < s.aliens.length; j++) {
                    a = s.aliens[j];
                    if (!a.alive || !hits(sh, {x: a.x, y: a.y, w: AW, h: AH})) { continue; }
                    s.shots.splice(i, 1);
                    a.hp -= 1;
                    a.alive = a.hp > 0;
                    s.score += a.alive ? 15 : (a.object ? 50 : (ROWS - a.row) * 10);
                    boom(a.x + AW / 2, a.y + AH / 2, a.alive);
                    paintHud();
                    break;
                }
            }

            var ship = {x: s.ship.x + 4, y: SHIP_Y + 6, w: SW - 8, h: SH - 10};
            for (i = s.bombs.length - 1; i >= 0; i--) {
                var b = s.bombs[i];
                b.y += (150 + s.level * 6) * dt;
                if (b.y > H) { s.bombs.splice(i, 1); continue; }
                if (hits(b, ship)) {
                    s.bombs.splice(i, 1);
                    boom(s.ship.x + SW / 2, SHIP_Y + SH / 2);
                    if (--s.lives <= 0) { finish('dead'); }
                    s.ship.x = W / 2 - SW / 2;
                    paintHud();
                    if (s.over) { break; }
                }
            }

            for (i = s.booms.length - 1; i >= 0; i--) {
                if ((s.booms[i].t += dt) > 0.25) { s.booms.splice(i, 1); }
            }

            var left = alive();
            if (!left.length) {
                finish('clear');
            } else if (left.some(function (o) { return o.y + AH >= SHIP_Y; })) {
                finish('dead');
            }
        }

        function finish(how) {
            s.over = how;
            s.overAt = window.performance.now();
            if (s.score > best) {
                best = s.score;
                writeBest(best);
            }
            paintHud();
        }

        function draw() {
            ctx.fillStyle = '#0d0708';
            ctx.fillRect(0, 0, W, H);

            s.aliens.forEach(function (a) {
                if (!a.alive) { return; }
                var colour = a.object ? OBJ_COLOUR[a.hp - 1] : ATTR_COLOUR[a.row];
                var glyph = tinted(a.object ? art.obj : art.attr, colour);
                if (glyph) {
                    ctx.drawImage(glyph, a.x, a.y);
                } else {
                    ctx.fillStyle = colour;
                    ctx.fillRect(a.x, a.y + 4, AW, AH - 8);
                }
            });

            if (!s.over || s.over === 'clear') {
                if (art.ship) {
                    ctx.save();
                    ctx.translate(s.ship.x + SW / 2, SHIP_Y + SH / 2);
                    ctx.rotate(Math.PI);
                    ctx.drawImage(art.ship, -SW / 2, -SH / 2, SW, SH);
                    ctx.restore();
                } else {
                    ctx.fillStyle = '#e6eef0';
                    ctx.fillRect(s.ship.x, SHIP_Y + 8, SW, SH - 12);
                }
            }

            ctx.fillStyle = '#9be7ff';
            s.shots.forEach(function (o) { ctx.fillRect(o.x, o.y, o.w, o.h); });
            ctx.fillStyle = '#ff6b6b';
            s.bombs.forEach(function (o) { ctx.fillRect(o.x, o.y, o.w, o.h); });

            s.booms.forEach(function (o) {
                ctx.strokeStyle = 'rgba(232,197,71,' + (1 - o.t / 0.25).toFixed(2) + ')';
                ctx.beginPath();
                ctx.arc(o.x, o.y, 3 + o.t * o.r, 0, Math.PI * 2);
                ctx.stroke();
            });

            if (s.over) {
                ctx.fillStyle = 'rgba(13,7,8,.72)';
                ctx.fillRect(0, H / 2 - 34, W, 68);
                ctx.textAlign = 'center';
                ctx.fillStyle = s.over === 'dead' ? '#ff6b6b' : '#7ad3a1';
                ctx.font = 'bold 20px ui-monospace, monospace';
                ctx.fillText(s.over === 'dead' ? 'GAME OVER' : 'WAVE ' + s.level + ' CLEARED', W / 2, H / 2 - 6);
                ctx.fillStyle = '#e6eef0';
                ctx.font = '11px ui-monospace, monospace';
                ctx.fillText(s.over === 'dead' ? 'press R to play again' : 'press N for the next wave', W / 2, H / 2 + 18);
            }
        }

        function frame(now) {
            var dt = Math.min(0.05, (now - last) / 1000 || 0);
            last = now;
            update(dt);
            draw();
            if (!closed) { raf = window.requestAnimationFrame(frame); }
        }

        function onKey(e) {
            var down = e.type === 'keydown';
            var key = e.key.length === 1 ? e.key.toLowerCase() : e.key;
            if (key === 'Escape' && down) { return close(); }
            if ([' ', 'ArrowLeft', 'ArrowRight', 'ArrowUp', 'ArrowDown'].indexOf(e.key) !== -1) {
                e.preventDefault();
            }
            if (!s) { return; }
            if (s.over) {
                if (!down || e.repeat || window.performance.now() - s.overAt < OVER_LOCK) { return; }
                if (s.over === 'clear' && key === 'n') { wave(s.level + 1, s.score, s.lives); }
                if (s.over === 'dead' && key === 'r') { wave(1, 0, 1); }
                return;
            }
            if (key === 'ArrowLeft' || key === 'a') { keys.left = down; }
            if (key === 'ArrowRight' || key === 'd') { keys.right = down; }
            if (key === ' ') { keys.fire = down; }
        }

        function close() {
            closed = true;      // the art may still be loading — see ready()
            window.cancelAnimationFrame(raf);
            document.removeEventListener('keydown', onKey);
            document.removeEventListener('keyup', onKey);
            overlay.remove();
            style.remove();
        }

        overlay.querySelector('.mi-close').addEventListener('click', close);
        overlay.addEventListener('click', function (e) {
            if (e.target === overlay) { close(); }
        });
        document.addEventListener('keydown', onKey);
        document.addEventListener('keyup', onKey);
    }

    function readBest() {
        try { return parseInt(window.localStorage.getItem(BEST_KEY), 10) || 0; } catch (e) { return 0; }
    }

    function writeBest(value) {
        try { window.localStorage.setItem(BEST_KEY, value); } catch (e) { /* ignore */ }
    }

    document.addEventListener('DOMContentLoaded', bindLogo);
})();
