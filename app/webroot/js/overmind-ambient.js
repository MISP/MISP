(function () {
    'use strict';

    var EVERY = 0;             // s; 0 for the dated schedule
    var KEY = 'oaNext';
    var FROM = 0x4b1, TO = 0x4c8;
    var RATE = [0.5, 3];
    var SIDES = ['t', 'r', 'b', 'l'];
    var TURN = {b: 0, t: Math.PI, l: Math.PI / 2, r: -Math.PI / 2};
    var ENDS = ['oa-in', 'oa-fd'];
    var G = 2600, MASS = [0.5, 0.6], GYR = 0.3, PULL = 60000, SPIN = 22;
    var DRAG = 1.2, AIR = 0.3, SMOOTH = 0.03, SUB = 1 / 240, FIRST = 1200;

    var CSS = [
        '.oa-v{--oa-at:50%;position:fixed;z-index:1075;width:75px;height:117px;',
        'pointer-events:none;transform-origin:50% 100%}',
        '.oa-v--b{left:var(--oa-at);top:100%;transform:translate(-50%,-100%)}',
        '.oa-v--t{left:var(--oa-at);top:0;transform:translate(-50%,-100%) rotate(180deg)}',
        '.oa-v--l{left:0;top:var(--oa-at);transform:translate(-50%,-100%) rotate(90deg)}',
        '.oa-v--r{left:100%;top:var(--oa-at);transform:translate(-50%,-100%) rotate(-90deg)}',
        '.oa-f{display:block;width:100%;height:100%;overflow:visible;',
        'filter:drop-shadow(0 2px 5px rgba(0,0,0,.22));touch-action:none;animation:oa-in 4.3s both}',
        '.oa-f *{pointer-events:visiblePainted;cursor:grab}',
        '@keyframes oa-in{',
        '0%{transform:translateY(115%);animation-timing-function:cubic-bezier(.2,.8,.3,1)}',
        '16%{transform:translateY(14%)}',
        '86%{transform:translateY(14%);animation-timing-function:cubic-bezier(.55,0,.9,.45)}',
        '100%{transform:translateY(115%)}}',
        '.oa-v:not(.oa-free) .oa-g{visibility:hidden}',
        '.oa-a{animation:oa-sw .5s ease-in-out .7s 6 alternate both}',
        '@keyframes oa-sw{from{transform:rotate(-12deg)}to{transform:rotate(14deg)}}',
        '.oa-h{animation:oa-wr .25s ease-in-out .7s 12 alternate both}',
        '@keyframes oa-wr{from{transform:rotate(-9deg)}to{transform:rotate(9deg)}}',
        '.oa-v.oa-free .oa-f{transform:none;animation:none}',
        '.oa-v.oa-free .oa-a{animation:oa-sw .5s ease-in-out infinite alternate}',
        '.oa-v.oa-free .oa-h{animation:oa-wr .25s ease-in-out infinite alternate}',
        '.oa-v.oa-free .oa-g{animation:oa-kk .3s ease-in-out infinite alternate}',
        '.oa-v.oa-free .oa-g2{animation-delay:-.3s}',
        '.oa-v.oa-held .oa-a{animation-duration:.28s}',
        '.oa-v.oa-held .oa-h{animation-duration:.14s}',
        '.oa-v.oa-held .oa-f *{cursor:grabbing}',
        '@keyframes oa-kk{from{transform:rotate(-12deg)}to{transform:rotate(12deg)}}',
        '@media (max-width:576px){.oa-v{width:56px;height:88px}}',
        '@media (prefers-reduced-motion:reduce){.oa-f{transform:translateY(14%);animation-name:oa-fd}',
        '.oa-v .oa-a,.oa-v .oa-h,.oa-v .oa-g{animation:none!important}}',
        '@keyframes oa-fd{0%,100%{opacity:0}16%,86%{opacity:1}}',
        '@media print{.oa-v{display:none}}'
    ].join('');

    var SVG = [
        '<svg class="oa-f" viewBox="0 0 160 250">',
        '<g transform="translate(58 212)">',
        '<g class="oa-g">',
        '<rect x="-13" y="-6" width="26" height="26" fill="#C62828"/>',
        '<path d="M-17 18H13V34C13 36 11 38 9 38H-23C-27 38 -29 35 -27 32C-25 26 -21 22 -17 20Z" fill="#3A2F2D"/>',
        '<ellipse cx="-20" cy="30" rx="3.5" ry="1.8" fill="#5A4D4A"/>',
        '</g>',
        '</g>',
        '<g transform="translate(102 212)">',
        '<g class="oa-g oa-g2">',
        '<rect x="-13" y="-6" width="26" height="26" fill="#C62828"/>',
        '<path d="M-13 18H17C21 22 25 26 27 32C29 35 27 38 23 38H-9C-11 38 -13 36 -13 34Z" fill="#3A2F2D"/>',
        '<ellipse cx="20" cy="30" rx="3.5" ry="1.8" fill="#5A4D4A"/>',
        '</g>',
        '</g>',
        '<path d="M10 210V196C10 156 38 128 80 128S150 156 150 196V210Z" fill="#E53935"/>',
        '<path d="M110 132C134 142 150 164 150 196V210H122V196C122 168 118 148 110 132Z" fill="#C62828"/>',
        '<rect x="70" y="140" width="20" height="66" fill="#FFFFFF"/>',
        '<rect x="82" y="140" width="8" height="66" fill="#DCE6F0"/>',
        '<path d="M11 176H149L150 190H10Z" fill="#3A2F2D"/>',
        '<rect x="67" y="171" width="26" height="24" rx="5" fill="#FFC531"/>',
        '<rect x="73" y="177" width="14" height="12" rx="2" fill="#3A2F2D"/>',
        '<rect x="8" y="202" width="144" height="16" rx="8" fill="#FFFFFF"/>',
        '<path d="M16 218H144A8 8 0 0 0 152 211C146 213 138 214 130 214H30C22 214 14 213 8 211A8 8 0 0 0 16 218Z" fill="#DCE6F0"/>',
        '<circle cx="51" cy="88" r="7" fill="#EDB18E"/>',
        '<circle cx="109" cy="88" r="7" fill="#EDB18E"/>',
        '<circle cx="80" cy="84" r="29" fill="#F8C9A8"/>',
        '<circle cx="63" cy="95" r="6" fill="#F4978E"/>',
        '<circle cx="97" cy="95" r="6" fill="#F4978E"/>',
        '<ellipse cx="70" cy="85" rx="3.2" ry="4" fill="#3E2A26"/>',
        '<ellipse cx="90" cy="85" rx="3.2" ry="4" fill="#3E2A26"/>',
        '<circle cx="71.2" cy="83.4" r="1.1" fill="#FFFFFF"/>',
        '<circle cx="91.2" cy="83.4" r="1.1" fill="#FFFFFF"/>',
        '<path d="M62 78Q69 72 76 77M84 77Q91 72 98 78" stroke="#FFFFFF" stroke-width="4.5" stroke-linecap="round" fill="none"/>',
        '<path d="M46 90C38 104 38 122 46 134C48 148 62 160 80 162C98 160 112 148 114 134C122 122 122 104 114 90C106 102 94 106 80 105C66 106 54 102 46 90Z" fill="#FFFFFF"/>',
        '<path d="M114 90C122 104 122 122 114 134C112 148 98 160 80 162C94 155 104 144 106 131C112 119 115 104 114 90Z" fill="#DCE6F0"/>',
        '<path d="M72 109Q80 120 88 109Z" fill="#9E2B25"/>',
        '<path d="M80 106C74 99 61 98 53 107C60 115 72 115 80 110C88 115 100 115 107 107C99 98 86 99 80 106Z" fill="#DCE6F0"/>',
        '<path d="M80 103C74 96 61 95 53 104C60 112 72 112 80 107C88 112 100 112 107 104C99 95 86 96 80 103Z" fill="#FFFFFF"/>',
        '<circle cx="80" cy="99" r="6" fill="#EE8379"/>',
        '<path d="M112 66C112 38 98 20 76 20C56 20 40 30 30 48L42 56C47 47 54 41 62 40C55 48 50 56 48 66Z" fill="#E53935"/>',
        '<path d="M62 40C55 48 50 56 48 66H58C58 54 60 46 62 40ZM30 48L42 56C47 47 54 41 62 40C50 40 38 44 30 48Z" fill="#C62828"/>',
        '<rect x="42" y="58" width="76" height="16" rx="8" fill="#FFFFFF"/>',
        '<path d="M50 74H110A8 8 0 0 0 118 67C112 70 104 71 96 71H50C47 71 44 70 42 68A8 8 0 0 0 50 74Z" fill="#DCE6F0"/>',
        '<circle cx="29" cy="51" r="10" fill="#FFFFFF"/>',
        '<path d="M37 45A10 10 0 0 1 22 59C30 59 36 53 37 45Z" fill="#DCE6F0"/>',
        '<g transform="translate(114 146)">',
        '<g class="oa-a">',
        '<g transform="rotate(22)">',
        '<rect x="-11" y="-52" width="22" height="60" rx="11" fill="#E53935"/>',
        '<path d="M3 -50A11 11 0 0 1 11 -41V-3A11 11 0 0 1 3 7Z" fill="#C62828"/>',
        '<rect x="-13" y="-58" width="26" height="13" rx="6.5" fill="#FFFFFF"/>',
        '<path d="M-13 -51.5H13A6.5 6.5 0 0 1 6.5 -45H-6.5A6.5 6.5 0 0 1 -13 -51.5Z" fill="#DCE6F0"/>',
        '<g transform="translate(0 -60)">',
        '<g class="oa-h">',
        '<rect x="-10.5" y="-31" width="5" height="16" rx="2.5" fill="#F8C9A8"/>',
        '<rect x="-4.8" y="-34" width="5" height="18" rx="2.5" fill="#F8C9A8"/>',
        '<rect x="0.9" y="-33" width="5" height="17" rx="2.5" fill="#F8C9A8"/>',
        '<rect x="6.4" y="-29" width="4.6" height="14" rx="2.3" fill="#F8C9A8"/>',
        '<rect x="-11" y="-20" width="22" height="20" rx="8" fill="#F8C9A8"/>',
        '<rect x="-17" y="-14" width="5" height="13" rx="2.5" transform="rotate(-38 -14.5 -7.5)" fill="#EDB18E"/>',
        '</g>',
        '</g>',
        '</g>',
        '</g>',
        '</g>',
        '</svg>'
    ].join('');

    var today = new Date();
    var md = (today.getMonth() + 1) * 100 + today.getDate();
    var slot = EVERY * 1000;
    if (!slot) {
        if (md < FROM || md > TO) {
            return;
        }
        slot = 3600000 / (RATE[0] * Math.pow(RATE[1] / RATE[0], (md - FROM) / (TO - FROM)));
    }

    var memory = null;
    var timer = null;
    var styled = false;

    function load() {
        var next = memory;
        try {
            next = JSON.parse(localStorage.getItem(KEY));
        } catch (e) {}
        if (!next || next.slot !== slot || typeof next.at !== 'number') {
            return null;
        }
        return next;
    }

    function save(at) {
        memory = {at: at, slot: slot};
        try {
            localStorage.setItem(KEY, JSON.stringify(memory));
        } catch (e) {}
    }

    function after(time) {
        if (EVERY) {
            return time + slot;
        }
        return (Math.floor(time / slot) + 1 + Math.random()) * slot;
    }

    function check() {
        clearTimeout(timer);
        var now = Date.now();
        var next = load();
        if (!next) {
            save(after(now));
            next = memory;
        }
        if (next.at > now) {
            timer = setTimeout(check, next.at - now);
            return;
        }
        if (now - next.at > slot) {
            save(after(now));
            check();
            return;
        }
        if (document.hidden) {
            return;
        }
        save(after(now));
        pop();
        check();
    }

    function pop() {
        if (document.querySelector('.oa-v')) {
            return;
        }
        if (!styled) {
            var style = document.createElement('style');
            style.textContent = CSS;
            document.head.appendChild(style);
            styled = true;
        }
        var side = SIDES[Math.floor(Math.random() * SIDES.length)];
        var el = document.createElement('div');
        el.className = 'oa-v oa-v--' + side;
        el.setAttribute('aria-hidden', 'true');
        el.style.setProperty('--oa-at', (15 + Math.random() * 70) + '%');
        el.innerHTML = SVG;

        var fig = el.firstElementChild;
        var safety = null;
        var gone = function () {
            clearTimeout(safety);
            el.remove();
        };
        var hold = function (ms) {
            clearTimeout(safety);
            safety = ms ? setTimeout(gone, ms) : null;
        };
        fig.addEventListener('animationend', function (e) {
            if (e.target === fig && ENDS.indexOf(e.animationName) !== -1) {
                gone();
            }
        });
        hold(10000);
        document.body.appendChild(el);
        grip(el, fig, TURN[side], hold, gone);
    }

    function grip(el, fig, theta, hold, gone) {
        var state = null;
        var ox = 0, oy = 0, rx = 0, ry = 0, inertia = 1;
        var px = 0, py = 0, lastPx = 0, lastPy = 0, vpx = 0, vpy = 0;
        var omega = 0, comX = 0, comY = 0, vy = 0;
        var frame = null, last = 0;

        function arm() {
            var cos = Math.cos(theta), sin = Math.sin(theta);
            return [rx * cos - ry * sin, rx * sin + ry * cos];
        }

        function grab(e) {
            if (e.button !== 0) {
                return;
            }
            e.preventDefault();
            hold(0);
            var rect = fig.getBoundingClientRect();
            var w = el.offsetWidth, h = el.offsetHeight;
            var dx = e.clientX - (rect.left + rect.width / 2);
            var dy = e.clientY - (rect.top + rect.height / 2);
            var cos = Math.cos(theta), sin = Math.sin(theta);
            ox = w / 2 + dx * cos + dy * sin;
            oy = h / 2 - dx * sin + dy * cos;
            rx = MASS[0] * w - ox;
            ry = MASS[1] * h - oy;
            inertia = Math.pow(GYR * h, 2) + rx * rx + ry * ry;
            px = lastPx = e.clientX;
            py = lastPy = e.clientY;
            vpx = vpy = 0;
            state = 'held';
            el.classList.add('oa-free', 'oa-held');
            el.style.transformOrigin = ox + 'px ' + oy + 'px';
            fig.setPointerCapture(e.pointerId);
            place();
            run();
        }

        function move(e) {
            if (state === 'held') {
                px = e.clientX;
                py = e.clientY;
            }
        }

        function drop() {
            if (state !== 'held') {
                return;
            }
            state = 'drop';
            el.classList.remove('oa-held');
            var r = arm();
            comX = px + r[0];
            comY = py + r[1];
            vy = Math.max(0, vpy + omega * r[0]);
            el.style.transformOrigin = (ox + rx) + 'px ' + (oy + ry) + 'px';
            hold(8000);
        }

        function place() {
            var x = px - ox, y = py - oy;
            if (state === 'drop') {
                x = comX - ox - rx;
                y = comY - oy - ry;
            }
            el.style.left = x + 'px';
            el.style.top = y + 'px';
            el.style.transform = 'rotate(' + theta + 'rad)';
        }

        function swing(dt) {
            var ivx = (px - lastPx) / dt, ivy = (py - lastPy) / dt;
            lastPx = px;
            lastPy = py;
            var k = Math.min(1, dt / SMOOTH);
            var nvx = vpx + (ivx - vpx) * k, nvy = vpy + (ivy - vpy) * k;
            var ax = clamp((nvx - vpx) / dt, PULL);
            var ay = clamp((nvy - vpy) / dt, PULL);
            vpx = nvx;
            vpy = nvy;
            var n = Math.ceil(dt / SUB), h = dt / n;
            for (var i = 0; i < n; i++) {
                var r = arm();
                var torque = r[0] * (G - ay) + r[1] * ax;
                omega = clamp(omega + (torque / inertia - DRAG * omega) * h, SPIN);
                theta += omega * h;
            }
        }

        function step(now) {
            var dt = Math.min(0.05, (now - last) / 1000);
            last = now;
            if (dt > 0) {
                if (state === 'held') {
                    swing(dt);
                } else if (state === 'drop') {
                    omega *= Math.exp(-AIR * dt);
                    theta += omega * dt;
                    vy += G * dt;
                    comY += vy * dt;
                }
            }
            place();
            if (state === 'drop' && el.getBoundingClientRect().top > window.innerHeight) {
                gone();
            }
            if (!el.isConnected) {
                frame = null;
                return;
            }
            frame = requestAnimationFrame(step);
        }

        function run() {
            if (!frame) {
                last = performance.now();
                frame = requestAnimationFrame(step);
            }
        }

        fig.addEventListener('pointerdown', grab);
        fig.addEventListener('pointermove', move);
        fig.addEventListener('pointerup', drop);
        fig.addEventListener('pointercancel', drop);
        fig.addEventListener('lostpointercapture', drop);
    }

    function clamp(value, limit) {
        return Math.max(-limit, Math.min(limit, value));
    }

    document.addEventListener('visibilitychange', function () {
        if (!document.hidden) {
            check();
        }
    });
    timer = setTimeout(check, FIRST);
})();
