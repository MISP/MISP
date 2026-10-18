/*
 * The Value Index's second door: Look up | Search.
 *
 * Look up is the page's own box, untouched (value-index.js). Search is a
 * one-line field whose answer is a ranked page of the stored values the
 * reader can see matching the text (POST /values/matches), each row
 * assessed in place as the worklist assesses (POST /values/assess, five in
 * flight). The words come from the page (#vsr-strings).
 */
(function () {
    'use strict';

    var LANES = 5;
    var WORD = /[\p{L}\p{N}]/u;
    var CIDR4 = /^\d{1,3}(\.\d{1,3}){3}\/\d{1,2}$/;
    var CIDR6 = /^[0-9a-f:]+:[0-9a-f:]*\/\d{1,3}$/i;

    function esc(text) {
        return String(text).replace(/[&<>"']/g, function (c) {
            return { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c];
        });
    }

    function boot() {
        var form = document.getElementById('vi-prompt');
        var out = document.querySelector('[data-vi-out]');
        var source = document.getElementById('vsr-strings');
        if (!form || !out || !source || !window.fetch || !window.FormData) {
            return;
        }
        var L = JSON.parse(source.textContent);
        // '0' when the reader's analyst profile switches the assessment off.
        var assessed = source.getAttribute('data-vsr-assessed') !== '0';
        var base = (form.getAttribute('action') || '').replace(/\/values\/resolve$/, '');
        var MATCHES = base + '/values/matches';
        var ASSESS = base + '/values/assess';
        var box = form.querySelector('#ValueValue');
        var invite = document.querySelector('[data-vi-invite]');

        /* A translated sentence with its placeholders filled by markup. */
        function T(text) {
            var args = Array.prototype.slice.call(arguments, 1);
            var n = 0;
            return esc(text).replace(/%(?:(\d+)\$)?s/g, function (m, at) {
                var arg = at ? args[at - 1] : args[n++];
                return arg === undefined ? '' : String(arg);
            });
        }

        function code(text, cls) {
            return '<code' + (cls ? ' class="' + cls + '"' : '') + '>' + esc(text) + '</code>';
        }

        function pageOf(value) {
            return base + '/values/view/'
                + window.MispValueAddress.address(value);
        }

        function token() {
            var key = form.querySelector('[name="data[_Token][key]"]');
            return key ? key.value : '';
        }

        function el(html) {
            var t = document.createElement('template');
            t.innerHTML = html.trim();
            return t.content.firstElementChild;
        }

        /*
         * How a text will be read: a cruder copy of the server's rule, used
         * only to say beforehand what a press will do. The answer's own
         * `mode` is what the results report.
         */
        function guess(text) {
            var t = text.trim();
            if (t === '') {
                return null;
            }
            if (Array.from(t).length < 2) {
                return 'short';
            }
            if (CIDR4.test(t) || CIDR6.test(t)) {
                return 'block';
            }
            if (S.anywhere) {
                return 'anywhere';
            }
            return /[\p{L}\p{N}]{3,}/u.test(t) ? 'words' : 'prefix';
        }

        function badge(mode) {
            return '<span class="vsr-badge vsr-badge--' + mode + '">' + esc(L.badge[mode]) + '</span>';
        }

        /* ---------------------------------------------------------------
         * The doors
         * --------------------------------------------------------------- */
        var doors = el(
            '<div class="vsr-doors">'
            + '<div class="vsr-seg" role="tablist" aria-label="' + esc(L.doors) + '">'
            + '<button type="button" class="vsr-tab" role="tab" id="vsr-tab-lookup"'
            + ' data-vsr-door="lookup" aria-selected="true">'
            + '<i class="fas fa-arrow-right-to-bracket" aria-hidden="true"></i>' + esc(L.tabLookup) + '</button>'
            + '<button type="button" class="vsr-tab" role="tab" id="vsr-tab-search"'
            + ' data-vsr-door="search" aria-selected="false" tabindex="-1">'
            + '<i class="fas fa-magnifying-glass" aria-hidden="true"></i>' + esc(L.tabSearch) + '</button>'
            + '</div>'
            + '<p class="vsr-doorsay" data-vsr-say aria-live="polite"></p>'
            + '</div>'
        );
        var field = el(
            '<div class="vsr-field">'
            + '<div class="vsr-box">'
            + '<i class="fas fa-magnifying-glass vsr-box__icon" aria-hidden="true"></i>'
            + '<input type="text" id="vsr-q" class="vsr-q" autocomplete="off"'
            + ' autocapitalize="off" spellcheck="false" enterkeyhint="search"'
            + ' aria-label="' + esc(L.field) + '" aria-describedby="vsr-reading"'
            + ' placeholder="' + esc(L.placeholder) + '">'
            + '<button type="button" class="vsr-anywhere" data-vsr-anywhere aria-pressed="false"'
            + ' title="' + esc(L.anywhereTitle) + '">'
            + '<span class="vsr-anywhere__dot" aria-hidden="true"></span>' + esc(L.anywhere)
            + ' <span class="vsr-anywhere__slow">' + esc(L.anywhereSlow) + '</span></button>'
            + '<button type="button" class="vsr-x" data-vsr-x hidden'
            + ' aria-label="' + esc(L.clear) + '" title="' + esc(L.clearTitle) + '">'
            + '<i class="fas fa-xmark" aria-hidden="true"></i></button>'
            + '</div>'
            + '<p class="vsr-reading" id="vsr-reading" data-vsr-reading></p>'
            + '</div>'
        );
        var side = el(
            '<div class="vsr-side">'
            + '<button type="button" class="vsr-go" data-vsr-go disabled>'
            + '<span data-vsr-goword>' + esc(L.go) + '</span><span class="vsr-kbd">Enter</span>'
            + '</button></div>'
        );
        form.insertBefore(doors, form.querySelector('.vi-prompt__field'));
        var lookSide = form.querySelector('.vi-prompt__side');
        lookSide.parentNode.insertBefore(field, lookSide.nextSibling);
        field.parentNode.insertBefore(side, field.nextSibling);

        var q = field.querySelector('#vsr-q');
        var x = field.querySelector('[data-vsr-x]');
        var anywhere = field.querySelector('[data-vsr-anywhere]');
        var reading = field.querySelector('[data-vsr-reading]');
        var go = side.querySelector('[data-vsr-go]');
        var goWord = side.querySelector('[data-vsr-goword]');
        var say = doors.querySelector('[data-vsr-say]');
        var tabs = Array.prototype.slice.call(doors.querySelectorAll('[data-vsr-door]'));

        var door = 'lookup';
        var held = { lookup: null, search: null };
        var notice = null;

        var S = {
            gen: 0,
            busy: false,
            text: null,
            answered: null,
            anywhere: false,
            mode: null,
            page: 0,
            more: false,
            rows: [],
            flying: 0,
            list: null
        };

        function link(to, text) {
            return '<button type="button" class="vsr-link" data-vsr-to="' + to + '">' + esc(text) + '</button>';
        }

        function paintSay() {
            if (notice) {
                say.innerHTML = notice;
            } else if (door === 'lookup') {
                say.innerHTML = T(L.sayLookup, '<b>' + esc(L.tabLookup) + '</b>', link('search', L.sayLookupLink));
            } else {
                say.innerHTML = T(L.saySearch, '<b>' + esc(L.tabSearch) + '</b>', link('lookup', L.saySearchLink));
            }
        }

        /* The door and the question go into the history entry, never the URL. */
        function remember() {
            try {
                history.replaceState(Object.assign({}, history.state || {}, {
                    vsrDoor: door,
                    vsrText: S.text,
                    vsrPages: S.page,
                    vsrAnywhere: S.anywhere
                }), '');
            } catch (e) {
                /* a sandboxed frame may refuse; the page works without it */
            }
        }

        function stash() {
            var frag = document.createDocumentFragment();
            while (out.firstChild) {
                frag.appendChild(out.firstChild);
            }
            return frag;
        }

        function open(to, opts) {
            opts = opts || {};
            if (to === door) {
                if (opts.focus !== false) {
                    (to === 'search' ? q : box).focus();
                }
                return;
            }
            held[door] = stash();
            door = to;
            if (held[to]) {
                out.appendChild(held[to]);
                held[to] = null;
            } else if (to === 'search') {
                out.appendChild(searchInvite());
            } else if (invite && invite.content) {
                out.appendChild(invite.content.cloneNode(true));
            }
            // One line follows the reader through the door when the other box is empty
            if (to === 'search' && q.value === '' && box.value.trim() !== ''
                    && !/[\r\n]/.test(box.value.trim())) {
                q.value = box.value.trim();
            } else if (to === 'lookup' && box.value === '' && q.value.trim() !== '') {
                box.value = q.value.trim();
            }
            form.classList.toggle('vsr-on-search', to === 'search');
            tabs.forEach(function (tab) {
                var on = tab.getAttribute('data-vsr-door') === to;
                tab.setAttribute('aria-selected', String(on));
                tab.tabIndex = on ? 0 : -1;
            });
            notice = opts.notice || null;
            paintSay();
            box.dispatchEvent(new Event('input', { bubbles: true }));
            paintField();
            remember();
            if (opts.focus !== false) {
                var target = to === 'search' ? q : box;
                target.focus();
                if (target.value) {
                    target.setSelectionRange(target.value.length, target.value.length);
                }
            }
        }

        doors.addEventListener('click', function (event) {
            var tab = event.target.closest('[data-vsr-door], [data-vsr-to]');
            if (tab) {
                open(tab.getAttribute('data-vsr-door') || tab.getAttribute('data-vsr-to'));
            }
        });
        doors.querySelector('[role="tablist"]').addEventListener('keydown', function (event) {
            if (['ArrowLeft', 'ArrowRight', 'Home', 'End'].indexOf(event.key) === -1) {
                return;
            }
            event.preventDefault();
            var to = event.key === 'Home' ? 'lookup'
                : (event.key === 'End' ? 'search' : (door === 'lookup' ? 'search' : 'lookup'));
            open(to, { focus: false });
            doors.querySelector('[data-vsr-door="' + to + '"]').focus();
        });

        /* ---------------------------------------------------------------
         * The search field
         * --------------------------------------------------------------- */
        function setAnywhere(on) {
            S.anywhere = !!on;
            anywhere.setAttribute('aria-pressed', String(S.anywhere));
            paintField();
        }

        function paintField() {
            var text = q.value;
            var mode = guess(text);
            x.hidden = text === '';
            go.disabled = S.busy || text.trim() === '';
            goWord.textContent = S.busy ? L.going : L.go;
            var t = code(text.trim());
            reading.hidden = S.answered !== null && text.trim() === S.answered.trim()
                && S.anywhere === S.answeredAnywhere;
            var refang = /hxxp|\[\.\]|\(\.\)|\{\.\}/i.test(text) ? ' ' + esc(L.readRefang) : '';
            if (mode === null) {
                reading.innerHTML = esc(L.readNone);
            } else if (mode === 'short') {
                reading.innerHTML = esc(L.readShort);
            } else if (mode === 'block') {
                reading.innerHTML = badge('block') + ' ' + T(L.readBlock, t);
            } else if (mode === 'anywhere') {
                reading.innerHTML = badge('anywhere') + ' ' + T(L.readAnywhere, t) + refang;
            } else if (mode === 'words') {
                reading.innerHTML = badge('words') + ' ' + T(L.readWords, t) + refang;
            } else {
                reading.innerHTML = badge('prefix') + ' ' + T(L.readPrefix, t) + refang;
            }
        }

        q.addEventListener('input', paintField);

        q.addEventListener('keydown', function (event) {
            if (event.key === 'Enter') {
                event.preventDefault();
                if (q.value.trim() !== '') {
                    search(q.value, 1);
                }
            } else if (event.key === 'Escape' || event.key === 'Esc') {
                event.preventDefault();
                event.stopPropagation();
                wipe();
            } else if (event.key === 'ArrowDown') {
                var first = out.querySelector('.vsr-val');
                if (first) {
                    event.preventDefault();
                    first.focus();
                }
            }
        });

        q.addEventListener('paste', function (event) {
            var text = event.clipboardData ? event.clipboardData.getData('text') : '';
            if (!/[\r\n]/.test(text.trim())) {
                return;
            }
            event.preventDefault();
            box.value = text;
            held.lookup = null;
            open('lookup', {
                notice: T(L.pasteMoved, '<b>' + esc(L.tabLookup) + '</b>') + ' ' + link('search', L.pasteBack)
            });
        });

        anywhere.addEventListener('click', function () {
            setAnywhere(!S.anywhere);
            q.focus();
        });
        x.addEventListener('click', wipe);
        go.addEventListener('click', function () {
            if (q.value.trim() !== '') {
                search(q.value, 1);
            }
        });

        // A submit while Search is open is a search, never a lookup
        form.addEventListener('submit', function (event) {
            if (door !== 'search') {
                return;
            }
            event.preventDefault();
            event.stopImmediatePropagation();
            if (q.value.trim() !== '') {
                search(q.value, 1);
            }
        }, true);

        function wipe() {
            S.gen++;
            S.busy = false;
            S.text = null;
            S.answered = null;
            S.page = 0;
            q.value = '';
            out.innerHTML = '';
            out.removeAttribute('aria-busy');
            out.appendChild(searchInvite());
            paintField();
            remember();
            q.focus();
        }

        function way(mode, example, lead, body, onAnywhere) {
            return '<li class="vsr-way">' + badge(mode)
                + '<span class="vsr-way__lead">' + esc(lead) + '</span>'
                + '<span class="vsr-way__body">' + body + '</span>'
                + '<button type="button" class="vsr-try" data-vsr-try="' + esc(example) + '"'
                + (onAnywhere ? ' data-vsr-try-anywhere' : '') + '>'
                + T(L.try, code(example)) + '</button></li>';
        }

        function searchInvite() {
            return el(
                '<div class="vsr-invite">'
                + '<h2 class="vsr-invite__title">' + esc(L.inviteTitle) + '</h2>'
                + '<p class="vsr-invite__lead">' + esc(L.inviteLead) + '</p>'
                + '<ul class="vsr-ways">'
                + way('words', 'github', L.wayWordsLead,
                    T(L.wayWordsBody, code('github.com'), code('api.github.com'), code('mygithub.com')))
                + way('prefix', '8.8', L.wayPrefixLead,
                    T(L.wayPrefixBody, code('8.8.8.8'), code('8.8.4.4')))
                + way('block', '8.8.8.0/24', L.wayBlockLead, esc(L.wayBlockBody))
                + way('anywhere', 'verifypaypal', L.wayAnywhereLead,
                    T(L.wayAnywhereBody, '<b>' + esc(L.anywhere) + '</b>', code('verifypaypal'),
                        code('theverifypaypal.com')), true)
                + '</ul>'
                + '<p class="vsr-invite__foot">'
                + T(L.inviteFoot, code('hxxp://'), code('1.2.3[.]4')) + '</p>'
                + '</div>'
            );
        }

        /* ---------------------------------------------------------------
         * Asking
         * --------------------------------------------------------------- */
        function ask(text, page) {
            var body = new FormData();
            body.append('data[Value][value]', text);
            body.append('data[Value][page]', String(page));
            if (S.anywhere) {
                body.append('data[Value][anywhere]', '1');
            }
            var key = token();
            if (key) {
                body.append('data[_Token][key]', key);
            }
            return fetch(MATCHES, {
                method: 'POST',
                body: body,
                credentials: 'same-origin',
                headers: { 'X-Requested-With': 'XMLHttpRequest', Accept: 'application/json' }
            }).then(function (response) {
                if (!response.ok) {
                    throw new Error(String(response.status));
                }
                return response.json();
            });
        }

        function search(raw, page) {
            var gen = page === 1 ? ++S.gen : S.gen;
            S.busy = true;
            paintField();
            out.setAttribute('aria-busy', 'true');
            var moreBtn = out.querySelector('[data-vsr-more]');
            if (moreBtn) {
                moreBtn.disabled = true;
                moreBtn.querySelector('span').textContent = L.loading;
            }
            return ask(raw, page).then(function (answer) {
                if (gen !== S.gen) {
                    return;
                }
                S.busy = false;
                out.removeAttribute('aria-busy');
                if (page === 1) {
                    S.answered = raw;
                    S.answeredAnywhere = S.anywhere;
                    draw(raw, answer);
                } else {
                    extend(answer);
                }
                paintField();
                remember();
            }).catch(function () {
                if (gen !== S.gen) {
                    return;
                }
                S.busy = false;
                out.removeAttribute('aria-busy');
                paintField();
                if (page === 1) {
                    out.innerHTML = '';
                    out.appendChild(noteBlock('fail', esc(L.failTitle),
                        '<p>' + esc(L.failBody) + '</p>',
                        '<button type="button" class="vsr-btn vsr-btn--lead" data-vsr-again>' + esc(L.again) + '</button>'));
                } else if (moreBtn) {
                    moreBtn.disabled = false;
                    moreBtn.querySelector('span').textContent = L.moreFailed;
                }
            });
        }

        function noteBlock(kind, title, body, actions) {
            var icon = {
                none: 'fa-magnifying-glass',
                many: 'fa-filter',
                short: 'fa-keyboard',
                fail: 'fa-plug-circle-xmark'
            }[kind];
            return el(
                '<div class="vsr-res">'
                + '<div class="vsr-note vsr-note--' + kind + '"'
                + (kind === 'none' ? ' data-vsr-empty' : ' data-vsr-refused="' + kind + '"') + '>'
                + '<span class="vsr-note__icon"><i class="fas ' + icon + '" aria-hidden="true"></i></span>'
                + '<div class="vsr-note__text">'
                + '<h3 class="vsr-note__title">' + title + '</h3>'
                + body
                + (actions ? '<div class="vsr-note__acts">' + actions + '</div>' : '')
                + '</div></div></div>'
            );
        }

        function readLine(answer, raw) {
            if (!answer.changed || answer.changed.indexOf('refanged') === -1) {
                return '';
            }
            return '<p class="vsr-readas"><i class="fas fa-wand-magic-sparkles" aria-hidden="true"></i>'
                + T(L.readAs, code(answer.text), code(raw.trim())) + '</p>';
        }

        function anywhereButton() {
            return '<button type="button" class="vsr-link" data-vsr-anywhere-on>'
                + esc(L.anywhere + ' ' + L.anywhereSlow) + '</button>';
        }

        function why(mode, t, values) {
            if (mode === 'block') {
                return esc(L.whyBlock);
            }
            if (mode === 'prefix') {
                return T(L.whyPrefix, code(t));
            }
            if (mode === 'anywhere') {
                return esc(L.whyAnywhere);
            }
            var inner = null;
            for (var i = 0; i < values.length && !inner; i++) {
                var hits = hitsOf(values[i], t, 'words');
                if (hits.length && hits[0][0] > 0) {
                    inner = values[i];
                }
            }
            var said = esc(L.whyWords);
            if (inner) {
                said += ' ' + T(L.whyWordsFinds, code(t), code(clip(inner, 48)));
            }
            if (/^\p{L}/u.test(t)) {
                said += ' ' + T(L.whyWordsNot, code('the' + t.toLowerCase(), 'vsr-nowrap'), anywhereButton());
            }
            return said;
        }

        function clip(text, n) {
            var chars = Array.from(text);
            return chars.length > n ? chars.slice(0, n - 1).join('') + '…' : text;
        }

        function draw(raw, answer) {
            S.rows = [];
            S.flying = 0;
            S.text = raw;
            S.mode = answer.mode;
            S.page = answer.page || 1;
            S.more = !!answer.more;
            out.innerHTML = '';
            var t = answer.text;
            var lookupBtn = '<button type="button" class="vsr-btn" data-vsr-lookup>'
                + T(L.lookupAs, code(clip(t, 40))) + '</button>';
            var editBtn = '<button type="button" class="vsr-btn vsr-btn--quiet" data-vsr-edit>' + esc(L.edit) + '</button>';

            if (answer.refused === 'short') {
                out.appendChild(noteBlock('short', esc(L.shortTitle),
                    '<p>' + esc(L.shortBody) + '</p>', lookupBtn + editBtn));
                return;
            }
            if (answer.refused === 'many') {
                out.appendChild(noteBlock('many', T(L.manyTitle, code(t, 'vsr-said')),
                    '<p>' + esc(L.manyBody) + '</p>',
                    editBtn.replace('vsr-btn--quiet', 'vsr-btn--lead')));
                return;
            }
            var mode = answer.mode || 'words';
            if (!answer.values || !answer.values.length) {
                var hint = mode === 'words'
                    ? '<p>' + T(L.noneWords, anywhereButton()) + '</p>'
                    : (mode === 'anywhere' ? '' : '<p>' + esc(L.noneOther) + '</p>');
                var note = noteBlock('none', T(L.none[mode], code(t, 'vsr-said')), hint, lookupBtn + editBtn);
                if (readLine(answer, raw)) {
                    note.insertBefore(el(readLine(answer, raw)), note.firstChild);
                }
                out.appendChild(note);
                return;
            }

            var res = el(
                '<div class="vsr-res" data-vsr-results>'
                + readLine(answer, raw)
                + '<div class="vsr-head">'
                + '<div class="vsr-what">'
                + '<div class="vsr-what__line">' + badge(mode)
                + '<span class="vsr-what__say">' + T(L.phrase[mode], code(t, 'vsr-said')) + '</span></div>'
                + '<p class="vsr-what__why">' + why(mode, t, answer.values) + '</p>'
                + '</div>'
                + '<div class="vsr-tally">'
                + '<span class="vsr-tally__n" data-vsr-tally aria-live="polite"></span>'
                + '<span class="vsr-keys"><span class="vsr-kbd">↑</span><span class="vsr-kbd">↓</span> ' + esc(L.keysMove)
                + ' <span class="vsr-kbd">Enter</span> ' + esc(L.keysOpen)
                + ' <span class="vsr-kbd">→</span> ' + esc(L.keysDetails) + '</span>'
                + '</div></div>'
                + '<div class="vsr-wrap' + (assessed ? '' : ' is-unassessed') + '">'
                + '<div class="vsr-thead" aria-hidden="true"><span></span><span>' + esc(L.headValue) + '</span>'
                + '<span class="vsr-c-types">' + esc(L.headTypes) + '</span><span class="vsr-c-lean">' + esc(L.headLean) + '</span>'
                + '<span class="vsr-c-str">' + esc(L.headStrength) + '</span><span class="vsr-c-rel">' + esc(L.headRelevance) + '</span>'
                + '<span></span></div>'
                + '<ol class="vsr-rows" data-vsr-rows aria-label="' + esc(L.list) + '"></ol>'
                + '<div class="vsr-foot" data-vsr-foot></div>'
                + '</div></div>'
            );
            out.appendChild(res);
            S.list = res.querySelector('[data-vsr-rows]');
            S.list.addEventListener('keydown', listKey);
            S.list.addEventListener('click', listClick);
            S.list.addEventListener('focusin', function (event) {
                var row = event.target.closest('.vsr-row');
                S.list.querySelectorAll('.vsr-row.is-cur').forEach(function (r) {
                    r.classList.toggle('is-cur', r === row);
                });
                if (row) {
                    row.classList.add('is-cur');
                }
            });
            addRows(answer.values);
            paintTally();
            paintFoot();
            pump(S.gen);
        }

        function extend(answer) {
            if (!S.list) {
                return;
            }
            S.page = answer.page || S.page + 1;
            S.more = !!answer.more;
            var before = S.rows.length;
            if (answer.values && answer.values.length) {
                S.list.appendChild(el('<li class="vsr-break" aria-hidden="true">'
                    + '<span>' + T(L.page, String(S.page)) + '</span></li>'));
                addRows(answer.values);
            }
            paintTally();
            paintFoot();
            pump(S.gen);
            var first = S.rows[before];
            if (first) {
                first.el.querySelector('.vsr-val').focus({ preventScroll: true });
                first.el.scrollIntoView({ block: 'nearest' });
            }
        }

        function paintTally() {
            var tally = out.querySelector('[data-vsr-tally]');
            if (tally) {
                tally.innerHTML = T(L.showing, '<b>' + S.rows.length + '</b>')
                    + (S.more ? ' · <span class="vsr-more-mark">' + esc(L.moreMark) + '</span>' : '');
            }
        }

        function paintFoot() {
            var foot = out.querySelector('[data-vsr-foot]');
            if (!foot) {
                return;
            }
            if (S.more) {
                foot.innerHTML = '<button type="button" class="vsr-btn vsr-btn--lead vsr-morebtn" data-vsr-more>'
                    + '<i class="fas fa-angles-down" aria-hidden="true"></i><span>' + esc(L.showMore) + '</span></button>'
                    + '<span class="vsr-foot__say">' + esc(L.moreSay) + '</span>';
            } else {
                foot.innerHTML = '<span class="vsr-foot__say vsr-foot__end">'
                    + '<i class="fas fa-check" aria-hidden="true"></i> ' + esc(L.noMore) + '</span>';
            }
        }

        out.addEventListener('click', function (event) {
            var target = event.target;
            if (target.closest('[data-vsr-more]')) {
                search(S.text, S.page + 1);
            } else if (target.closest('[data-vsr-try]')) {
                var tried = target.closest('[data-vsr-try]');
                q.value = tried.getAttribute('data-vsr-try');
                setAnywhere(tried.hasAttribute('data-vsr-try-anywhere'));
                search(q.value, 1);
            } else if (target.closest('[data-vsr-anywhere-on]')) {
                setAnywhere(true);
                search(q.value, 1);
            } else if (target.closest('[data-vsr-edit]')) {
                q.focus();
                q.select();
            } else if (target.closest('[data-vsr-again]')) {
                search(q.value, 1);
            } else if (target.closest('[data-vsr-lookup]')) {
                box.value = q.value.trim();
                held.lookup = null;
                open('lookup');
                if (typeof form.requestSubmit === 'function') {
                    form.requestSubmit();
                }
            }
        });

        /* ---------------------------------------------------------------
         * The rows
         * --------------------------------------------------------------- */
        function hitsOf(value, t, mode) {
            var low = value.toLowerCase();
            var needle = t.toLowerCase();
            var ranges = [];
            var at;
            if (mode === 'prefix') {
                if (low.indexOf(needle) === 0) {
                    ranges.push([0, t.length]);
                }
                return ranges;
            }
            if (mode === 'anywhere') {
                var from = 0;
                while (needle && (at = low.indexOf(needle, from)) !== -1) {
                    ranges.push([at, at + needle.length]);
                    from = at + needle.length;
                }
                return ranges;
            }
            if (mode !== 'words') {
                return ranges;
            }
            needle.split(/[^\p{L}\p{N}]+/u).filter(Boolean).forEach(function (word) {
                var start = 0;
                while ((at = low.indexOf(word, start)) !== -1) {
                    if (at === 0 || !WORD.test(low.charAt(at - 1))) {
                        ranges.push([at, at + word.length]);
                    }
                    start = at + 1;
                }
            });
            ranges.sort(function (a, b) { return a[0] - b[0]; });
            var merged = [];
            ranges.forEach(function (r) {
                var last = merged[merged.length - 1];
                if (last && r[0] <= last[1]) {
                    last[1] = Math.max(last[1], r[1]);
                } else {
                    merged.push(r.slice());
                }
            });
            return merged;
        }

        function marked(value, ranges) {
            var start = 0;
            var lead = '';
            if (ranges.length && ranges[0][0] > 44) {
                start = ranges[0][0] - 18;
                lead = '<span class="vsr-elide">…</span>';
            }
            var html = lead;
            var at = start;
            ranges.forEach(function (r) {
                html += esc(value.slice(at, r[0])) + '<mark class="vsr-hit">'
                    + esc(value.slice(r[0], r[1])) + '</mark>';
                at = r[1];
            });
            return html + esc(value.slice(at));
        }

        function ip4(text) {
            var m = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})(?:\/(\d{1,2}))?$/.exec(text);
            if (!m) {
                return null;
            }
            var n = 0;
            for (var i = 1; i <= 4; i++) {
                if (+m[i] > 255) {
                    return null;
                }
                n = n * 256 + (+m[i]);
            }
            var len = m[5] === undefined ? 32 : +m[5];
            return len > 32 ? null : { n: n, len: len };
        }

        function inside(a, b) {
            var size = Math.pow(2, 32 - b.len);
            return a.len >= b.len && Math.floor(a.n / size) === Math.floor(b.n / size);
        }

        function where(value, block) {
            var a = ip4(value);
            var b = ip4(block);
            if (!a || !b) {
                return null;
            }
            if (a.len === b.len && inside(a, b)) {
                return 'same';
            }
            if (inside(a, b)) {
                return 'in';
            }
            return inside(b, a) ? 'around' : null;
        }

        function addRows(values) {
            var frag = document.createDocumentFragment();
            var t = S.text.trim();
            values.forEach(function (value) {
                var n = S.rows.length + 1;
                var href = pageOf(value);
                var rel = S.mode === 'block' ? where(value, t) : null;
                var li = el(
                    '<li class="vsr-row" data-s="queued">'
                    + '<span class="vsr-rank">' + n + '</span>'
                    + '<span class="vsr-c-val">'
                    + '<a class="vsr-val" href="' + esc(href) + '" title="' + esc(value) + '">'
                    + marked(value, hitsOf(value, t, S.mode)) + '</a>'
                    + (rel ? '<span class="vsr-where vsr-where--' + rel + '">' + esc(L.where[rel]) + '</span>' : '')
                    + '</span>'
                    + '<span class="vsr-cell vsr-c-types" data-vsr-cell="types"><i class="vsr-bar" style="width:46px"></i></span>'
                    + '<span class="vsr-cell vsr-c-lean" data-vsr-cell="lean"><i class="vsr-bar" style="width:72px"></i></span>'
                    + '<span class="vsr-cell vsr-c-str" data-vsr-cell="strength"><i class="vsr-bar" style="width:52px"></i></span>'
                    + '<span class="vsr-cell vsr-c-rel" data-vsr-cell="rel"><i class="vsr-bar" style="width:86px"></i></span>'
                    + '<span class="vsr-acts">'
                    + '<button type="button" class="vsr-disc" data-vsr-disc aria-expanded="false"'
                    + ' aria-label="' + esc(L.disc) + '" tabindex="-1">'
                    + '<i class="fas fa-chevron-down" aria-hidden="true"></i></button>'
                    + '<a class="vsr-open" href="' + esc(href) + '" tabindex="-1" aria-hidden="true">'
                    + esc(L.open) + '<span class="vsr-open__more">' + esc(L.openMore) + '</span>'
                    + '<i class="fas fa-arrow-right" aria-hidden="true"></i></a>'
                    + '</span>'
                    + '<div class="vsr-detail" data-vsr-detail hidden>'
                    + '<div class="vsr-full"><span class="vsr-full__label">' + esc(L.whole) + '</span>'
                    + '<code class="vsr-full__value">' + esc(value) + '</code></div>'
                    + '<div class="vsr-ev" data-vsr-ev></div>'
                    + '</div>'
                    + '</li>'
                );
                S.rows.push({ el: li, value: value, state: 'queued' });
                frag.appendChild(li);
            });
            S.list.appendChild(frag);
        }

        function pump(gen) {
            if (gen !== S.gen) {
                return;
            }
            while (S.flying < LANES) {
                var row = null;
                for (var i = 0; i < S.rows.length; i++) {
                    if (S.rows[i].state === 'queued') {
                        row = S.rows[i];
                        break;
                    }
                }
                if (!row) {
                    return;
                }
                row.state = 'flight';
                row.el.setAttribute('data-s', 'flight');
                S.flying++;
                assess(row, gen);
            }
        }

        function assess(row, gen) {
            var body = new FormData();
            body.append('data[Value][value]', row.value);
            var key = token();
            if (key) {
                body.append('data[_Token][key]', key);
            }
            fetch(ASSESS, {
                method: 'POST',
                body: body,
                credentials: 'same-origin',
                headers: { 'X-Requested-With': 'XMLHttpRequest' }
            }).then(function (response) {
                if (!response.ok) {
                    throw new Error(String(response.status));
                }
                return response.text();
            }).then(function (html) {
                if (gen !== S.gen) {
                    return;
                }
                fillRow(row, html);
                S.flying--;
                pump(gen);
            }).catch(function () {
                if (gen !== S.gen) {
                    return;
                }
                row.state = 'failed';
                row.el.setAttribute('data-s', 'failed');
                S.flying--;
                pump(gen);
            });
        }

        function fillRow(row, html) {
            var t = document.createElement('template');
            t.innerHTML = html;
            var frag = t.content;
            var cells = frag.querySelector('.vi-cells');
            var put = function (name, sel) {
                var slot = row.el.querySelector('[data-vsr-cell="' + name + '"]');
                var got = cells ? cells.querySelector(sel) : null;
                slot.innerHTML = '';
                if (got && got.textContent.trim() !== '') {
                    slot.appendChild(got);
                } else {
                    slot.innerHTML = '<span class="vsr-dash">—</span>';
                }
            };
            put('types', '.vi-c-types');
            put('lean', '.vi-c-lean');
            put('strength', '.vi-c-strength');
            put('rel', '.vi-c-rel');
            var ev = row.el.querySelector('[data-vsr-ev]');
            var card = frag.querySelector('.vi-card');
            if (card) {
                var bits = [card.querySelector('.vi-counts'), card.querySelector('.vi-l3')];
                var ledger = card.querySelector('.vi-l4');
                if (ledger) {
                    bits = bits.concat(Array.prototype.slice.call(ledger.children));
                }
                bits.forEach(function (bit) {
                    if (bit) {
                        var holder = document.createElement('div');
                        holder.className = 'vsr-ev__row';
                        holder.appendChild(bit);
                        ev.appendChild(holder);
                    }
                });
            }
            row.state = 'done';
            row.el.setAttribute('data-s', 'done');
        }

        function rowLinks() {
            return S.list ? Array.prototype.slice.call(S.list.querySelectorAll('.vsr-val')) : [];
        }

        function toggle(rowEl, force) {
            var detail = rowEl.querySelector('[data-vsr-detail]');
            var disc = rowEl.querySelector('[data-vsr-disc]');
            var on = force === undefined ? detail.hidden : force;
            detail.hidden = !on;
            rowEl.classList.toggle('is-open', on);
            disc.setAttribute('aria-expanded', String(on));
        }

        function listClick(event) {
            var disc = event.target.closest('[data-vsr-disc]');
            if (disc) {
                toggle(disc.closest('.vsr-row'));
            }
        }

        function listKey(event) {
            if (event.ctrlKey || event.metaKey || event.altKey) {
                return;
            }
            var row = event.target.closest('.vsr-row');
            if (!row) {
                return;
            }
            var links = rowLinks();
            var at = links.indexOf(row.querySelector('.vsr-val'));
            var k = event.key;
            if (k === 'ArrowDown' || k === 'j') {
                event.preventDefault();
                if (links[at + 1]) {
                    links[at + 1].focus();
                }
            } else if (k === 'ArrowUp' || k === 'k') {
                event.preventDefault();
                if (at > 0) {
                    links[at - 1].focus();
                } else {
                    q.focus();
                }
            } else if (k === 'ArrowRight') {
                event.preventDefault();
                toggle(row, true);
            } else if (k === 'ArrowLeft') {
                event.preventDefault();
                toggle(row, false);
            } else if (k === 'Escape') {
                event.preventDefault();
                q.focus();
            }
        }

        /*
         * Arrival: a fresh visit opens on Look up; coming Back to the page
         * restores the Search door, its text and its pages from the history
         * entry.
         */
        paintSay();
        paintField();
        var back = null;
        try {
            back = history.state;
        } catch (e) {
            back = null;
        }
        if (back && back.vsrDoor === 'search') {
            open('search', { focus: false });
            setAnywhere(!!back.vsrAnywhere);
            if (back.vsrText) {
                q.value = back.vsrText;
                paintField();
                var pages = back.vsrPages || 1;
                var chain = search(back.vsrText, 1);
                for (var p = 2; p <= pages; p++) {
                    chain = chain.then((function (pg) {
                        return function () { return S.more ? search(S.text, pg) : null; };
                    })(p));
                }
            }
        }
    }

    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', boot);
    } else {
        boot();
    }
}());
