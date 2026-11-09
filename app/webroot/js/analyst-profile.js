/*
 * The Analyst Profile editor.
 *
 * Four jobs and no arithmetic: switch the open section, mark the
 * fields this session has changed, put a value on the bench, and ask
 * the server what the changed document does to it.
 *
 * The last is what makes the bench recomputed rather than a reading
 * of the saved document, and it is the only kind of network call the
 * page makes. Nothing here re-implements the ledger: a second scoring
 * engine in JavaScript is exactly the thing this feature exists to
 * avoid having, so every number on the bench arrives from the one
 * that already exists.
 */
(function () {
    'use strict';

    /*
     * `assetLoader` echoes the script tag where the view runs, which is
     * above the markup this file drives — so at the moment it executes
     * there is no `.wb-bench` to find, and a lookup here answers null.
     * Waiting for the document is the whole difference between an
     * editor and a page that shipped no JS at all.
     */
    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', boot);
    } else {
        boot();
    }

    /*
     * The full comparison opens in #mainModal. The editor posts its form,
     * unsaved fields and benched value included, so the candidate is what
     * is being typed; anywhere else the link's own value is the one read.
     */
    window.analystProfileCompare = function (url) {
        var form = document.getElementById('ap-form');
        if (form && form.getAttribute('data-ap-simulate')
            && typeof openModalPostChained === 'function'
        ) {
            openModalPostChained(form.getAttribute('data-ap-simulate')
                + '?full=1', new FormData(form), 'xl');
            return;
        }
        if (typeof openModal === 'function') {
            openModal(url + (url.indexOf('?') === -1 ? '?' : '&') + 'full=1',
                'xl');
        } else {
            window.location.href = url;
        }
    };
    document.addEventListener('click', function (event) {
        var link = event.target.closest
            ? event.target.closest('a[data-ap-compare]')
            : null;
        if (!link) {
            return;
        }
        event.preventDefault();
        window.analystProfileCompare(link.getAttribute('href'));
    });

    // An `i` keeps the rest of a sentence in its title; a click shows it inline.
    document.addEventListener('click', function (event) {
        var info = event.target.closest ? event.target.closest('.wb-i[title]') : null;
        if (!info) {
            return;
        }
        event.preventDefault();
        var more = info.nextElementSibling;
        if (more && more.classList.contains('wb-i-more')) {
            more.hidden = !more.hidden;
            return;
        }
        more = document.createElement('span');
        more.className = 'wb-i-more';
        more.textContent = info.getAttribute('title');
        info.parentNode.insertBefore(more, info.nextSibling);
    });

function boot() {
    var form = document.getElementById('ap-form');
    var bench = document.querySelector('.wb-bench');
    if (!form && !bench && !document.querySelector('[data-ap-settings]')) {
        return;
    }

    /*
     * The editor and the read-only viewer carry the form, so their
     * bench recomputes in place. The expanded simulator is a page with
     * no form: there the same controls navigate instead.
     */
    var carried = document.getElementById('ap-bench-value');
    var live = !!(form && bench && carried);
    var inits = [];

    /* ------------------------------------------------------------ *
     * What this session has changed, and where
     * ------------------------------------------------------------ */

    function changed(field) {
        var was = field.getAttribute('data-ap-was');
        if (was === null) {
            return false;
        }
        if (field.type === 'checkbox') {
            return String(field.checked) !== was;
        }
        // A radio group changed once the radio now checked is not the one it had.
        if (field.type === 'radio') {
            return field.checked && String(field.value) !== was;
        }
        return String(field.value) !== was;
    }

    function sectionOf(field) {
        var pane = field.closest ? field.closest('.wb-sec') : null;
        return pane ? pane.getAttribute('data-sec') : null;
    }

    function mark() {
        var dirty = {};
        var folds = [];
        var count = 0;
        Array.prototype.forEach.call(
            document.querySelectorAll('[data-ap-field]'),
            function (field) {
                var moved = changed(field);
                var chip = field.closest ? field.closest('.kv') : null;
                if (chip) {
                    chip.classList.toggle('is-edited', moved);
                }
                /*
                 * A row reads as off when its switch is off, and the
                 * class was rendered from the *stored* value — so
                 * ticking a disabled rule left it greyed out until a
                 * save, which is the page showing a state the form no
                 * longer has. Toggled here rather than on the click,
                 * because this already runs on every change and the
                 * switch is not the only way one arrives.
                 *
                 * A row the instance does not implement stays dimmed
                 * either way: that is a fact about the instance, and
                 * ticking a box cannot change it.
                 */
                if (field.type === 'checkbox') {
                    var row = field.closest
                        ? field.closest('tr[data-ap-item]')
                        : null;
                    if (row
                        && row.getAttribute('data-ap-state') !== 'missing'
                    ) {
                        row.classList.toggle('is-off', !field.checked);
                    }
                }
                if (!moved) {
                    return;
                }
                count++;
                var section = sectionOf(field);
                if (section) {
                    dirty[section] = true;
                }
                var fold = field.closest
                    ? field.closest('[data-ap-fold]')
                    : null;
                if (fold) {
                    folds.push(fold);
                }
            }
        );
        Array.prototype.forEach.call(
            document.querySelectorAll('[data-ap-fold]'),
            function (fold) {
                fold.classList.toggle('is-edited',
                    folds.indexOf(fold) !== -1);
            }
        );
        return count;
    }

    /* ------------------------------------------------------------ *
     * The bench, recomputed by the engine that scores the real thing
     * ------------------------------------------------------------ */

    var pending = null;
    var inflight = null;

    /*
     * The recompute answers the bench and nothing else, so the
     * contribution column in the signals pane would keep the numbers
     * the page loaded with — a confident `+7` beside a signal strength that had
     * just moved to 48. The fragment carries the new ledger back and
     * this writes it into the cells, which is the whole reason the
     * column can be trusted enough to colour.
     *
     * No arithmetic here either: the numbers, the labels and the
     * direction pair all arrive computed.
     */
    function repaintLedger() {
        if (!bench) {
            return;
        }
        var carrier = bench.querySelector('[data-ap-ledger]');
        if (!carrier) {
            return;
        }
        var carry;
        try {
            carry = JSON.parse(carrier.getAttribute('data-ap-ledger'));
        } catch (error) {
            return;
        }
        var rows = carry.rows || {};
        var labels = carry.labels || {};

        var table = document.querySelector(
            '.wb-sec[data-sec="signals"] table.wb-tbl, .wb-sec[data-sec="signals"] .ap-rules');
        if (table) {
            /*
             * Editing a weight can move the lean itself, and the pair
             * is *with* and *against* it — so the swap is re-applied,
             * not assumed to be the one the page rendered with.
             */
            if (carry.direction) {
                table.setAttribute('style', carry.direction);
            } else {
                table.removeAttribute('style');
            }
        }
        var anchor = document.querySelector('[data-ap-anchor]');
        if (anchor) {
            anchor.textContent = carry.anchor || '';
            anchor.hidden = !carry.anchor;
        }

        Array.prototype.forEach.call(
            document.querySelectorAll('[data-ap-contrib]'),
            function (cell) {
                var id = cell.getAttribute('data-ap-contrib');
                var has = Object.prototype.hasOwnProperty.call(rows, id);
                while (cell.firstChild) {
                    cell.removeChild(cell.firstChild);
                }
                if (!carry.benched) {
                    cell.appendChild(sub(labels.none || '—'));
                    return;
                }
                if (!has) {
                    cell.appendChild(sub(labels.no_row || ''));
                    if (labels.no_row_sub) {
                        cell.appendChild(sub(labels.no_row_sub));
                    }
                    return;
                }
                var points = rows[id];
                var box = document.createElement('div');
                box.className = 'num fw-bold '
                    + (points > 0 ? 'd-up' : (points < 0 ? 'd-dn' : 'd-0'));
                box.textContent = points > 0 ? '+' + points : String(points);
                cell.appendChild(box);
            }
        );
    }

    function sub(text) {
        var node = document.createElement('div');
        node.className = 'wb-sub';
        node.textContent = text;
        return node;
    }

    /*
     * The TTL curve lives in the relevance section, not in the bench —
     * so a recompute that swaps only the bench left the decay speed's
     * own picture drawn from the saved document, which is the one field
     * on this page whose entire output is that shape.
     *
     * The fragment carries a redrawn figure in a hidden carrier and
     * this moves it across. Server-drawn, like everything else here: no
     * arithmetic in this file, and one polynomial rather than two that
     * can drift.
     */
    function repaintCurve() {
        if (!bench) {
            return;
        }
        var carrier = bench.querySelector('[data-ap-curve]');
        if (!carrier) {
            return;
        }
        var drawn = carrier.querySelector('.ttl-curve');
        var live = document.querySelector('.ttl-grid .ttl-curve');
        if (drawn && live) {
            live.parentNode.replaceChild(drawn, live);
        }
        carrier.parentNode.removeChild(carrier);
    }

    function refresh() {
        if (!form || !bench) {
            return;
        }
        var url = form.getAttribute('data-ap-simulate');
        if (!url) {
            return;
        }
        if (inflight) {
            inflight.abort();
        }
        var request = new XMLHttpRequest();
        inflight = request;
        request.open('POST', url, true);
        request.setRequestHeader('X-Requested-With', 'XMLHttpRequest');
        bench.classList.add('is-recomputing');
        request.onload = function () {
            inflight = null;
            bench.classList.remove('is-recomputing');
            if (request.status >= 200 && request.status < 300) {
                bench.innerHTML = request.responseText;
                repaintCurve();
                repaintLedger();
            }
        };
        request.onerror = function () {
            inflight = null;
            bench.classList.remove('is-recomputing');
        };
        request.send(new FormData(form));
    }

    /* ------------------------------------------------------------ *
     * What the chosen option is worth, beside the option
     * ------------------------------------------------------------ */

    /*
     * A grade is a letter until the multiplier is next to it, and the
     * multipliers are themselves editable — so the number on the row
     * is read from the box that sets it, and falls back to the scale
     * the server resolved. A printed constant would be right until the
     * first keystroke and then argue with the field it describes,
     * which is §7e.2's lesson about the aging fraction in a new place.
     */
    function priceRow(row, factors, prefix) {
        var cell = row.querySelector('[data-ap-factor]');
        var control = row.querySelector('[data-ap-field]');
        if (!cell || !control) {
            return;
        }
        var grade = control.value;
        var factor = null;
        if (grade !== '') {
            if (prefix) {
                var box = document.querySelector(
                    '[name="' + prefix + '[' + grade + ']"]');
                if (box && box.value !== '' && isFinite(Number(box.value))) {
                    factor = Number(box.value);
                }
            }
            if (factor === null && factors
                && Object.prototype.hasOwnProperty.call(factors, grade)
            ) {
                factor = Number(factors[grade]);
            }
        }
        cell.textContent = factor === null || !isFinite(factor)
            ? ''
            : '×' + factor.toFixed(2);
    }

    function price() {
        Array.prototype.forEach.call(
            document.querySelectorAll('.ap-map[data-ap-factors]'),
            function (map) {
                var factors;
                try {
                    factors = JSON.parse(map.getAttribute('data-ap-factors'));
                } catch (error) {
                    factors = null;
                }
                var prefix = map.getAttribute('data-ap-factor-name');
                Array.prototype.forEach.call(
                    map.querySelectorAll('tbody tr'),
                    function (row) {
                        priceRow(row, factors, prefix);
                    }
                );
            }
        );
    }

    document.addEventListener('change', function (event) {
        if (!event.target.hasAttribute
            || !event.target.hasAttribute('data-ap-field')) {
            return;
        }
        mark();
        /*
         * Every priced row, not the one that changed: the box that
         * moved may be a price rather than a grade, and one price is
         * read by every row carrying that grade.
         */
        price();
        window.clearTimeout(pending);
        pending = window.setTimeout(refresh, 250);
    });

    /*
     * A price is a number box, and a number box is edited by typing
     * rather than by committing — so the row follows the keystroke
     * instead of waiting for the focus to leave.
     */
    document.addEventListener('input', function (event) {
        if (event.target.hasAttribute
            && event.target.hasAttribute('data-ap-field')
        ) {
            price();
        }
    });

    /* ------------------------------------------------------------ *
     * Putting a value on the bench, and keeping one there
     * ------------------------------------------------------------ */

    /*
     * The URL-safe base64 `ValueUrlTool` mints, for the hidden field: a
     * form post would rewrite a bare LF as CRLF. `btoa` takes bytes, not
     * characters, and a value can hold any of them.
     */
    function encodeValue(value) {
        var bytes = new TextEncoder().encode(value);
        var binary = '';
        for (var i = 0; i < bytes.length; i++) {
            binary += String.fromCharCode(bytes[i]);
        }
        return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_');
    }

    /*
     * Benching is not navigation. The bench exists to be read while a
     * weight is being changed, so swapping the value under it must not
     * throw away the edits that have not been saved — the value rides
     * in a hidden field the recompute already posts, and the address
     * bar is corrected afterwards so a reload lands on the same value.
     *
     * The expanded simulator has no form to post, and nothing unsaved
     * to lose, so there the same press is a link.
     */
    function benchValue(value) {
        if (!live) {
            var inner = document.querySelector('[data-ap-bench-url]');
            var target = inner
                ? inner.getAttribute('data-ap-bench-url')
                : null;
            if (target) {
                window.location.href = target
                    + (target.indexOf('?') === -1 ? '?' : '&')
                    + 'value=' + encodeURIComponent(value);
            }
            return;
        }
        carried.value = value === '' ? '' : encodeValue(value);
        if (window.history && window.history.replaceState) {
            var url = new URL(window.location.href);
            if (value === '') {
                url.searchParams.delete('value');
            } else {
                url.searchParams.set('value', value);
            }
            window.history.replaceState(null, '', url.toString());
        }
        refresh();
    }

    document.addEventListener('click', function (event) {
        var press = event.target.closest
            ? event.target.closest('[data-ap-bench]')
            : null;
        if (!press) {
            return;
        }
        event.preventDefault();
        var value = press.getAttribute('data-ap-bench');
        if (value === '') {
            var input = document.querySelector('[data-ap-bench-input]');
            value = input ? input.value.trim() : '';
            if (value === '') {
                if (input) {
                    input.focus();
                }
                return;
            }
        }
        benchValue(value);
    });

    document.addEventListener('keydown', function (event) {
        if (event.key !== 'Enter'
            || !event.target.hasAttribute
            || !event.target.hasAttribute('data-ap-bench-input')
        ) {
            return;
        }
        /* Inside the editor's form, so Enter would otherwise save. */
        event.preventDefault();
        var value = event.target.value.trim();
        if (value !== '') {
            benchValue(value);
        }
    });

    /*
     * Pinning writes a user setting, never the profile — so it is a
     * POST, and the token that authenticates it is the editor form's.
     * Re-rendering the bench afterwards rather than following the
     * redirect is what keeps the unsaved document on screen.
     */
    document.addEventListener('click', function (event) {
        var press = event.target.closest
            ? event.target.closest('[data-ap-pin]')
            : null;
        if (!press || !form) {
            return;
        }
        event.preventDefault();
        /*
         * Unpinning is not un-benching. Without this the last pinned
         * value is what the bench was reading, so dropping it from the
         * set would empty the pane the press was made from.
         */
        var keep = press.getAttribute('data-ap-value');
        var request = new XMLHttpRequest();
        request.open('POST', press.getAttribute('data-ap-pin'), true);
        request.setRequestHeader('X-Requested-With', 'XMLHttpRequest');
        press.disabled = true;
        request.onload = function () {
            if (live && keep) {
                carried.value = encodeValue(keep);
            }
            refresh();
        };
        request.onerror = function () {
            press.disabled = false;
        };
        request.send(new FormData(form));
    });

    /* ------------------------------------------------------------ *
     * Map rows: removing one and adding one
     * ------------------------------------------------------------ */

    document.addEventListener('click', function (event) {
        var drop = event.target.closest
            ? event.target.closest('[data-ap-drop]')
            : null;
        if (!drop) {
            return;
        }
        event.preventDefault();
        /*
         * A map is written whole on save, so a row taken off the page
         * is a key removed from the document. Nothing is written until
         * Save — the bench below says what removing it did.
         */
        var row = drop.closest('tr');
        if (row) {
            var map = row.closest ? row.closest('.ap-map') : null;
            var table = row.closest('table');
            var rows = row.parentNode;
            rows.removeChild(row);
            countNew(rows);
            /*
             * Back to the note the map started with. An empty table
             * with its headings still up says the map has columns; the
             * note says an empty map overrides nothing, which is the
             * thing the analyst who just removed the last row needs
             * told.
             */
            if (map && table && !table.hasAttribute('data-ap-new-table')
                && !table.querySelector('tbody tr[data-ap-key]')
            ) {
                table.hidden = true;
                var note = map.querySelector('[data-ap-map-empty]');
                if (note) {
                    note.hidden = false;
                }
            }
            mark();
            refresh();
        }
    });

    /*
     * The control a value gets, decided the same way the server
     * decides it. A map whose values are days gets a `number`; a map
     * whose values are a closed vocabulary gets that vocabulary. The
     * options ride on the add control because the block knows them and
     * the row does not yet exist.
     */
    function jsonAttr(add, attribute) {
        var raw = add.getAttribute(attribute);
        if (!raw) {
            return null;
        }
        try {
            return JSON.parse(raw);
        } catch (e) {
            return null;
        }
    }

    /*
     * The option list a `<select>` gets, from a vocabulary that may be
     * bare values or `value`/`label` pairs.
     */
    function fill(control, options, blank) {
        if (blank !== null) {
            var empty = document.createElement('option');
            empty.value = '';
            empty.textContent = blank;
            control.appendChild(empty);
        }
        options.forEach(function (option) {
            var node = document.createElement('option');
            node.value = option && option.value !== undefined
                ? option.value
                : option;
            node.textContent = option && option.label !== undefined
                ? option.label
                : node.value;
            control.appendChild(node);
        });
    }

    /*
     * A declaration: one state per name the row admits, drawn like the
     * ones the server drew beside it.
     *
     * The map whose value is not a scalar, and so the one the fallback
     * below could not draw — a row declared on the page got a text
     * box, posted nothing, and was gone again by the time the page
     * came back from the save. `__present` is what makes the row a
     * declaration at all: the merge reads it as *this map was on
     * screen*, and without it a row whose names are all left at
     * `not declared` is indistinguishable from a row never drawn.
     */
    function stateControl(add, name, names, options) {
        var box = document.createElement('div');
        box.className = 'mod-states';
        var present = document.createElement('input');
        present.type = 'hidden';
        present.name = name + '[__present]';
        present.value = '1';
        box.appendChild(present);
        names.forEach(function (rowName) {
            var row = document.createElement('div');
            row.className = 'mod-row';
            var title = document.createElement('span');
            title.className = 'wb-id';
            title.textContent = rowName;
            var group = document.createElement('span');
            group.className = 'mod-seg';
            group.setAttribute('role', 'radiogroup');
            group.setAttribute('aria-label', rowName);
            options.forEach(function (option, index) {
                group.appendChild(stateSegment(option, name + '[' + rowName + ']', index === 0));
            });
            row.appendChild(title);
            row.appendChild(group);
            box.appendChild(row);
        });
        return box;
    }

    // One state of a row, drawn as the server draws it in field.ctp.
    function stateSegment(option, name, checked) {
        var value = option && option.value !== undefined ? String(option.value) : String(option);
        var label = document.createElement('label');
        label.className = 'mod-seg-b t-' + (option.tone || 'custom');
        label.title = option.label || value;
        var input = document.createElement('input');
        input.type = 'radio';
        input.className = 'mod-seg-in';
        input.name = name;
        input.value = value;
        input.checked = checked;
        input.setAttribute('data-ap-field', '1');
        input.setAttribute('data-ap-was', '');
        var face = document.createElement('span');
        face.className = 'mod-seg-face';
        if (option.icon_class) {
            var icon = document.createElement('i');
            icon.className = option.icon_class;
            icon.setAttribute('aria-hidden', 'true');
            face.appendChild(icon);
        }
        var text = document.createElement('span');
        text.className = 'mod-seg-t';
        text.setAttribute('data-t', option.short || option.label || value);
        var word = document.createElement('span');
        word.textContent = text.getAttribute('data-t');
        text.appendChild(word);
        face.appendChild(text);
        label.appendChild(input);
        label.appendChild(face);
        return label;
    }

    /*
     * `key` is what the row is being added for, and for a `state_map`
     * it decides the sub-rows: the modules block draws one row per
     * module and one select per attribute type *that module* accepts,
     * so there is no single list the whole map could share.
     */
    function valueControl(add, name, key) {
        var kind = add.getAttribute('data-ap-add-type');
        var options = kind === 'select' || kind === 'state_map'
            ? jsonAttr(add, 'data-ap-add-options')
            : null;
        if (kind === 'state_map') {
            var rows = jsonAttr(add, 'data-ap-add-rows');
            var names = rows && key && rows[key] ? rows[key] : null;
            if (names && names.length && options && options.length) {
                return stateControl(add, name, names, options);
            }
        }
        var control;
        if (options && options.length) {
            control = document.createElement('select');
            control.className = 'form-select form-select-sm';
            /*
             * Nothing is preselected, and the box is `required`. A
             * grade the analyst did not choose is an opinion the
             * document would be recording on their behalf, and the
             * first letter of the scale is the worst possible guess at
             * one. The browser refuses the save and the pane the box
             * is in opens itself — that is the `invalid` handler above.
             */
            fill(control, options, '—');
            control.required = true;
            // A one-word vocabulary is not a choice to leave open.
            if (options.length === 1) {
                control.value = typeof options[0] === 'object'
                    ? options[0].value
                    : options[0];
            }
        } else {
            control = document.createElement('input');
            control.className = 'form-control form-control-sm num text-end';
            control.type = kind === 'int' || kind === 'float'
                ? 'number'
                : 'text';
            if (control.type === 'number') {
                control.step = kind === 'int' ? '1' : 'any';
            }
        }
        control.name = name;
        control.setAttribute('data-ap-field', '1');
        control.setAttribute('data-ap-was', '');
        return control;
    }

    /*
     * One row, drawn like the ones the server drew beside it — the
     * label, the key underneath when they differ, the control, and the
     * cross that takes it back off. A row added and not removable is a
     * mistake that needs a page reload to undo.
     *
     * `key` is what the document stores; `label` is what the analyst
     * recognises. For a graded organisation those are a uuid and a
     * name, and conflating them is how the key came to be typed by
     * hand in the first place.
     */
    function addRow(add, key, label) {
        var prefix = add.getAttribute('data-ap-add-name');
        if (!key || !prefix) {
            return null;
        }
        /*
         * The map this control belongs to, not the first table in the
         * pane: the relevance section holds three of them and the
         * buckets table is the one that comes first.
         */
        var map = add.closest ? add.closest('.ap-map') : null;
        var table = map ? map.querySelector('table.wb-tbl:not([data-ap-new-table])') : null;
        var body = table ? table.querySelector('tbody') : null;
        if (!body) {
            return null;
        }
        if (map.querySelector('tr[data-ap-key="' + cssEscape(key) + '"]')) {
            return null;
        }
        // What the picker knows of the key: its name, icon and description.
        var facts = null;
        (add.apRows || []).some(function (known) {
            facts = known.key === key ? known : null;
            return facts !== null;
        });
        if (!label && facts) {
            label = facts.label;
        }
        var row = document.createElement('tr');
        row.setAttribute('data-ap-key', key);
        var name = document.createElement('td');
        var title = document.createElement('div');
        title.className = 'fw-semibold';
        if (facts && facts.icon) {
            var icon = document.createElement('i');
            icon.className = facts.icon + ' ap-map-ico';
            icon.setAttribute('aria-hidden', 'true');
            title.appendChild(icon);
        }
        title.appendChild(document.createTextNode(label || key));
        name.appendChild(title);
        if (label && label !== key) {
            var sub = document.createElement('div');
            sub.className = 'wb-sub';
            sub.textContent = key;
            name.appendChild(sub);
        }
        if (facts && facts.desc) {
            var about = document.createElement('div');
            about.className = 'wb-sub ap-map-desc';
            about.textContent = facts.desc;
            name.appendChild(about);
            row.title = facts.desc;
        }
        var value = document.createElement('td');
        var control = valueControl(add, prefix + '[' + key + ']', key);
        var holder = document.createElement('div');
        holder.className = 'ap-map-val';
        holder.appendChild(control);
        if (map.hasAttribute('data-ap-factors')) {
            var priced = document.createElement('span');
            priced.className = 'ap-factor';
            priced.setAttribute('data-ap-factor', '');
            holder.appendChild(priced);
        }
        value.appendChild(holder);
        var drop = document.createElement('td');
        drop.className = 'r';
        var button = document.createElement('button');
        button.type = 'button';
        button.className = 'wb-drop';
        button.setAttribute('data-ap-drop', key);
        button.innerHTML = '<i class="fa-solid fa-trash-can" aria-hidden="true"></i>';
        drop.appendChild(button);
        row.appendChild(name);
        row.appendChild(value);
        row.appendChild(drop);
        row.classList.add('is-new');
        /*
         * A row nobody saved yet belongs to none of the groups: it waits
         * beside the control that added it where the map has a place for
         * that, and otherwise at the top under a heading of its own.
         */
        var fresh = map.querySelector('[data-ap-new-rows]');
        if (fresh) {
            fresh.appendChild(row);
            countNew(fresh);
        } else if (body.querySelector('tr.ap-map-grp:not(.ap-map-new)')) {
            var added = body.querySelectorAll('tr.is-new');
            var after = added.length
                ? added[added.length - 1]
                : newHeading(map, body, row.cells.length);
            body.insertBefore(row, after.nextSibling);
            countNew(body);
        } else {
            body.appendChild(row);
        }
        /*
         * The table was folded away while the map was empty, and the
         * note beside it said so. The first row swaps them.
         */
        table.hidden = false;
        var note = map.querySelector('[data-ap-map-empty]');
        if (note) {
            note.hidden = true;
        }
        add.value = '';
        /*
         * A declaration is a box of controls rather than one control,
         * so the thing to put the cursor in is the first select inside
         * it — `focus()` on a div does nothing and would leave the
         * analyst's next keystroke in the picker they just used.
         */
        var first = control.matches && control.matches('select, input')
            ? control
            : control.querySelector('select, input:not([type=hidden])');
        if (first) {
            first.focus();
        }
        mark();
        price();
        return control;
    }

    function newHeading(map, body, span) {
        var heading = document.createElement('tr');
        heading.className = 'wb-grp ap-map-grp ap-map-new';
        var cell = document.createElement('td');
        cell.colSpan = span;
        cell.appendChild(document.createTextNode(
            map.getAttribute('data-ap-new-label') || ''));
        var count = document.createElement('span');
        count.className = 'ap-map-grp-n';
        cell.appendChild(count);
        heading.appendChild(cell);
        body.insertBefore(heading, body.firstChild);
        return heading;
    }

    // The heading over the rows not saved yet counts them, and goes with the last.
    function countNew(body) {
        var wrap = body.closest ? body.closest('[data-ap-new-wrap]') : null;
        if (wrap) {
            var waiting = wrap.querySelectorAll('tr.is-new').length;
            wrap.querySelector('[data-ap-new-n]').textContent = waiting;
            wrap.hidden = waiting === 0;
            return;
        }
        var heading = body.querySelector('tr.ap-map-new');
        if (!heading) {
            return;
        }
        var count = body.querySelectorAll('tr.is-new').length;
        if (count === 0) {
            body.removeChild(heading);
            return;
        }
        heading.querySelector('.ap-map-grp-n').textContent = count;
    }

    /*
     * Filling a map from a list written elsewhere in the same document.
     *
     * One press, one row per key, and each row is the row the picker
     * would have drawn — so what the analyst is about to store is on
     * screen before they store it, and a key the map already carries is
     * skipped rather than doubled (`addRow` returns null for it).
     */
    document.addEventListener('click', function (event) {
        var button = event.target.closest
            ? event.target.closest('[data-ap-copy]')
            : null;
        if (!button) {
            return;
        }
        var map = button.closest('.ap-map');
        var add = map ? map.querySelector('[data-ap-add]') : null;
        if (!add) {
            return;
        }
        var keys;
        try {
            keys = JSON.parse(button.getAttribute('data-ap-copy'));
        } catch (error) {
            return;
        }
        if (!Array.isArray(keys)) {
            return;
        }
        var value = button.getAttribute('data-ap-copy-value') || '';
        keys.forEach(function (key) {
            var control = addRow(add, String(key), '');
            if (control && value !== '') {
                var field = control.matches
                    && control.matches('select, input')
                    ? control
                    : control.querySelector('select, input');
                if (field) {
                    field.value = value;
                }
            }
        });
    });

    /*
     * `CSS.escape` where it exists, and a key that cannot carry a
     * quote otherwise. Every key a map takes is a uuid, an attribute
     * type or a warninglist name, so this only has to be safe rather
     * than complete.
     */
    function cssEscape(value) {
        if (window.CSS && window.CSS.escape) {
            return window.CSS.escape(value);
        }
        return String(value).replace(/["\\\]]/g, '\\$&');
    }

    /*
     * A picker is not one of these. Both comboboxes below name a key
     * by choosing one, and a `type=search` box fires `change` on its
     * way out — so without the guard, tabbing away from a half-typed
     * warninglist name would add a row for a list nobody has.
     */
    document.addEventListener('change', function (event) {
        var add = event.target;
        if (!add.hasAttribute || !add.hasAttribute('data-ap-add')
            || add.hasAttribute('data-ap-pick')
        ) {
            return;
        }
        addRow(add, add.value.trim(), '');
    });

    /* ------------------------------------------------------------ *
     * Naming a key out of a list nobody reads to the bottom of
     * ------------------------------------------------------------ */

    /*
     * Two kinds of list, one control. Organisations are the key the
     * page cannot hold: an instance carries thousands of them and the
     * document stores the uuid, so what was here was a search box with
     * nothing behind it — which made *grade an organisation* mean
     * *type a uuid*. The endpoint answers fifty at a time and the row
     * keeps the uuid the name resolved to.
     *
     * The warninglists are the other kind: the whole roster is already
     * in the page, as the options of a select. Nothing needs fetching
     * there and the box narrows what is on screen instead — same list,
     * same keys, same keyboard.
     */
    var UUID =
        /^[0-9a-f]{8}(-[0-9a-f]{4}){3}-[0-9a-f]{12}$/i;
    var lookup = null;
    var typing = null;

    function panel(add) {
        var box = add.closest ? add.closest('.ap-pick') : null;
        return box ? box.querySelector('.ap-pick-list') : null;
    }

    function close(add) {
        var list = panel(add);
        if (list) {
            list.hidden = true;
            list.innerHTML = '';
        }
        add.setAttribute('aria-expanded', 'false');
    }

    function taken(add) {
        var map = add.closest ? add.closest('.ap-map, .ap-order') : null;
        var keys = {};
        if (!map) {
            return keys;
        }
        Array.prototype.forEach.call(
            map.querySelectorAll('tbody tr[data-ap-key], [data-ap-order-row]'),
            function (row) {
                keys[row.getAttribute('data-ap-key')] = true;
            }
        );
        return keys;
    }

    /*
     * One option. `key` is what the document stores and `label` is
     * what the analyst recognises; `sub` is the second line, drawn
     * only where the two differ enough to be worth printing both. A
     * warninglist is its own name, so it gets one line.
     */
    function option(key, label, sub, desc) {
        var node = document.createElement('button');
        node.type = 'button';
        node.className = 'ap-pick-opt';
        node.setAttribute('role', 'option');
        node.setAttribute('data-value', key);
        node.setAttribute('data-label', label || '');
        var title = document.createElement('span');
        title.className = 'ap-pick-name';
        title.textContent = label || key;
        node.appendChild(title);
        if (sub) {
            var line = document.createElement('span');
            line.className = 'ap-pick-uuid';
            line.textContent = sub;
            node.appendChild(line);
        }
        // What the key is about, for a key that is only a short name.
        if (desc) {
            var about = document.createElement('span');
            about.className = 'ap-pick-desc';
            about.textContent = desc;
            node.title = desc;
            node.appendChild(about);
        }
        return node;
    }

    function offer(add, rows, query) {
        var list = panel(add);
        if (!list) {
            return;
        }
        var already = taken(add);
        list.innerHTML = '';
        var drawn = 0;
        // What picking does, said above the options when the box asks for it.
        var head = add.getAttribute('data-ap-pick-head');
        if (head) {
            var heading = document.createElement('div');
            heading.className = 'ap-pick-head';
            heading.textContent = head;
            list.appendChild(heading);
        }
        rows.forEach(function (row) {
            if (!row || !row.key || already[row.key]) {
                return;
            }
            list.appendChild(option(row.key, row.label, row.sub, row.desc));
            drawn += 1;
        });
        /*
         * A uuid this instance has no organisation for is still worth
         * grading: a profile written elsewhere is exactly what import
         * exists for, and the row the server draws for one already
         * says it does not recognise it. Offered only when it was
         * typed in full, so it cannot be reached by accident — and
         * only by the box that asks the server, because the other one
         * is showing the entire list it has and a miss there is a
         * name that does not exist.
         */
        if (add.hasAttribute('data-ap-add-url') && UUID.test(query)
            && !already[query.toLowerCase()] && drawn === 0
        ) {
            list.appendChild(option(query.toLowerCase(), '',
                add.getAttribute('data-ap-pick-unknown') || ''));
            drawn += 1;
        }
        if (drawn === 0 && heading) {
            list.removeChild(heading);
        }
        if (drawn === 0) {
            var none = document.createElement('div');
            none.className = 'ap-pick-none';
            none.textContent = add.getAttribute(query === ''
                ? 'data-ap-pick-hint'
                : 'data-ap-pick-none') || '';
            list.appendChild(none);
        }
        list.hidden = false;
        add.setAttribute('aria-expanded', 'true');
    }

    function search(add) {
        var url = add.getAttribute('data-ap-add-url');
        var query = add.value.trim();
        if (!url) {
            return;
        }
        if (lookup) {
            lookup.abort();
        }
        var request = new XMLHttpRequest();
        lookup = request;
        request.open('GET',
            url + (url.indexOf('?') === -1 ? '?' : '&')
                + 'q=' + encodeURIComponent(query),
            true);
        request.setRequestHeader('Accept', 'application/json');
        request.setRequestHeader('X-Requested-With', 'XMLHttpRequest');
        request.onload = function () {
            lookup = null;
            var rows = [];
            if (request.status >= 200 && request.status < 300) {
                try {
                    rows = JSON.parse(request.responseText);
                } catch (e) {
                    rows = [];
                }
            }
            offer(add, (Array.isArray(rows) ? rows : []).map(function (row) {
                return {
                    key: row && row.uuid,
                    label: (row && row.name) || (row && row.uuid),
                    sub: row && row.uuid
                };
            }), query);
        };
        request.onerror = function () {
            lookup = null;
            offer(add, [], query);
        };
        request.send();
    }

    /*
     * The same list, narrowed. Every word has to land somewhere in the
     * name, in any order: the lists are named as sentences, and *azure
     * ip* is how somebody looking for `List of known Microsoft Azure
     * Datacenter IP Ranges` actually asks for it. An empty box matches
     * everything, which is the select this replaced.
     */
    function narrow(add) {
        var rows = add.apRows || [];
        var words = add.value.trim().toLowerCase().split(/\s+/)
            .filter(function (word) {
                return word !== '';
            });
        var named = function (haystack) {
            return words.every(function (word) {
                return haystack.indexOf(word) !== -1;
            });
        };
        // A description matches too, after the names that do.
        var byName = [];
        var byDesc = [];
        rows.forEach(function (row) {
            var name = (row.key + ' ' + (row.label || '')).toLowerCase();
            if (named(name)) {
                byName.push(row);
            } else if (row.desc && named(name + ' ' + row.desc.toLowerCase())) {
                byDesc.push(row);
            }
        });
        return byName.concat(byDesc);
    }

    function suggest(add) {
        if (add.hasAttribute('data-ap-add-url')) {
            search(add);
        } else {
            offer(add, narrow(add), add.value.trim());
        }
    }

    document.addEventListener('input', function (event) {
        var add = event.target;
        if (!add.hasAttribute || !add.hasAttribute('data-ap-pick')) {
            return;
        }
        /*
         * The wait belongs to the network, not to the reader. A list
         * the page is already holding is narrowed on the keystroke.
         */
        if (!add.hasAttribute('data-ap-add-url')) {
            suggest(add);
            return;
        }
        window.clearTimeout(typing);
        typing = window.setTimeout(function () {
            suggest(add);
        }, 200);
    });

    document.addEventListener('focusin', function (event) {
        var add = event.target;
        if (!add.hasAttribute || !add.hasAttribute('data-ap-pick')) {
            return;
        }
        /*
         * A held list opens whole: it is a select, and a select shows
         * its options the moment you reach it. The box that asks the
         * server has nothing to show until there is something to ask.
         */
        if (!add.hasAttribute('data-ap-add-url') || add.value.trim() !== '') {
            suggest(add);
        }
    });

    /*
     * `mousedown` and not `click`: the box loses focus first, and a
     * handler that closed the list on blur would take the option away
     * before the click landed on it.
     */
    document.addEventListener('mousedown', function (event) {
        var option = event.target.closest
            ? event.target.closest('.ap-pick-opt')
            : null;
        if (!option) {
            return;
        }
        event.preventDefault();
        var box = option.closest('.ap-pick');
        var add = box ? box.querySelector('[data-ap-pick]') : null;
        if (!add) {
            return;
        }
        choose(add, option);
        close(add);
    });

    // A pick is a row of a map, or a tile of a ranking, which draws its own.
    function choose(add, option) {
        var key = option.getAttribute('data-value');
        var label = option.getAttribute('data-label');
        if (add.hasAttribute('data-ap-order-pick')) {
            add.dispatchEvent(new CustomEvent('ap-order-pick',
                {detail: {key: key, label: label}}));
            add.value = '';
            return;
        }
        addRow(add, key, label);
    }

    document.addEventListener('keydown', function (event) {
        var add = event.target;
        if (!add.hasAttribute || !add.hasAttribute('data-ap-pick')) {
            return;
        }
        /*
         * Enter never submits from this box, list open or not. It is
         * not a field of the document — it names one — and a return
         * pressed halfway through a name would otherwise save the
         * profile, because a lone text input in a form submits it.
         */
        if (event.key === 'Enter') {
            event.preventDefault();
        }
        var list = panel(add);
        if (!list || list.hidden) {
            return;
        }
        var options = list.querySelectorAll('.ap-pick-opt');
        var active = list.querySelector('.ap-pick-opt.is-on');
        var index = Array.prototype.indexOf.call(options, active);
        if (event.key === 'ArrowDown' || event.key === 'ArrowUp') {
            event.preventDefault();
            if (!options.length) {
                return;
            }
            index += event.key === 'ArrowDown' ? 1 : -1;
            if (index < 0) {
                index = options.length - 1;
            }
            if (index >= options.length) {
                index = 0;
            }
            if (active) {
                active.classList.remove('is-on');
            }
            options[index].classList.add('is-on');
            options[index].scrollIntoView({block: 'nearest'});
        } else if (event.key === 'Enter') {
            var pick = active || (options.length === 1 ? options[0] : null);
            if (pick) {
                choose(add, pick);
                close(add);
            }
        } else if (event.key === 'Escape') {
            close(add);
        }
    });

    document.addEventListener('focusout', function (event) {
        var add = event.target;
        if (add.hasAttribute && add.hasAttribute('data-ap-pick')) {
            window.setTimeout(function () {
                close(add);
            }, 120);
        }
    });

    /*
     * The select the server drew, swapped for the box that narrows it.
     *
     * Done here rather than in the template because the select is the
     * answer for a browser that never runs this file: the options are
     * really there, `change` on one really adds the row, and the
     * warninglist override is not a feature that should need
     * JavaScript to exist. So the markup ships the working control and
     * the page upgrades it — which also means the options are read
     * from the one place that already has them rather than printed
     * twice into the document.
     */
    function upgrade(select) {
        var pick = document.createElement('div');
        pick.className = 'ap-pick';
        var box = document.createElement('input');
        box.type = 'search';
        box.className = 'form-control form-control-sm';
        box.autocomplete = 'off';
        box.setAttribute('role', 'combobox');
        box.setAttribute('aria-expanded', 'false');
        box.setAttribute('aria-autocomplete', 'list');
        box.setAttribute('data-ap-pick', '1');
        /*
         * Everything the row builder reads — the name prefix, the
         * value options, the id the label points at — carried over as
         * it stands. Only what described the select itself is left
         * behind.
         */
        var scaffolding = {
            'class': true,
            'style': true,
            'data-ap-add-filter': true,
            'data-ap-pick-placeholder': true
        };
        Array.prototype.forEach.call(select.attributes, function (attr) {
            if (!scaffolding[attr.name]) {
                box.setAttribute(attr.name, attr.value);
            }
        });
        box.placeholder =
            select.getAttribute('data-ap-pick-placeholder') || '';
        /*
         * On the element and not in an attribute: the roster is a
         * hundred names long, and a second copy of it serialised into
         * the DOM would be a hundred names nobody reads.
         */
        box.apRows = [];
        // An option may name its key: the name is shown, the key under it.
        Array.prototype.forEach.call(select.options, function (node) {
            var key = node.value.trim();
            var label = node.textContent.trim();
            if (key !== '') {
                box.apRows.push({key: key, label: label || key,
                    sub: label !== '' && label !== key ? key : '',
                    desc: node.getAttribute('data-desc') || '',
                    icon: node.getAttribute('data-icon') || ''});
            }
        });
        var list = document.createElement('div');
        list.className = 'ap-pick-list';
        list.setAttribute('role', 'listbox');
        list.hidden = true;
        pick.appendChild(box);
        pick.appendChild(list);
        select.parentNode.replaceChild(pick, select);
    }

    inits.push(function (root) {
        Array.prototype.forEach.call(
            root.querySelectorAll('select[data-ap-add-filter]'),
            upgrade
        );
    });

    /* ------------------------------------------------------------ *
     * A bucket's types: chips in, chips out
     * ------------------------------------------------------------ */

    document.addEventListener('click', function (event) {
        var drop = event.target.closest
            ? event.target.closest('.ap-chip-drop')
            : null;
        if (!drop) {
            return;
        }
        event.preventDefault();
        var chip = drop.closest('.chip');
        if (chip) {
            chip.parentNode.removeChild(chip);
            mark();
            refresh();
        }
    });

    document.addEventListener('change', function (event) {
        var picker = event.target;
        if (!picker.hasAttribute
            || !picker.hasAttribute('data-ap-type-add')) {
            return;
        }
        var type = picker.value.trim();
        if (type === '') {
            return;
        }
        var chip = document.createElement('span');
        chip.className = 'chip is-on';
        chip.appendChild(document.createTextNode(type + ' '));
        var carried = document.createElement('input');
        carried.type = 'hidden';
        // Type-first, like the chips the server drew: the name carries
        // the type and the value carries the bucket.
        carried.name = picker.getAttribute('data-ap-type-add')
            + '[' + type + ']';
        carried.value = picker.getAttribute('data-ap-type-value');
        carried.setAttribute('data-ap-field', '1');
        carried.setAttribute('data-ap-was', '');
        chip.appendChild(carried);
        var remove = document.createElement('a');
        remove.href = '#';
        remove.className = 'ap-chip-drop';
        remove.textContent = '\u00d7';
        chip.appendChild(remove);
        picker.parentNode.insertBefore(chip, picker);
        picker.value = '';
        mark();
        refresh();
    });

    /*
     * Exposed for the header's Save button.
     *
     * `requestSubmit()` and not `submit()`: the second one skips the
     * browser's own checks altogether, so the Save in the header would
     * post a number box holding a half-typed number where the Save
     * inside a pane refuses it. A button that is the page's main one
     * cannot be the one that validates least.
     */
    /* ------------------------------------------------------------ *
     * One choice for a whole row
     * ------------------------------------------------------------ */

    /*
     * A module row is one select per attribute type it accepts, and
     * the usual declaration is the same answer for all of them —
     * `circl_passivedns` is six identical choices. This writes them
     * all and then hands back to `mark()`, so the row lights up as
     * edited exactly as it would have done one select at a time.
     *
     * Revealed here rather than rendered visible, because it writes
     * fields instead of being one: without this script it would be a
     * control that silently does nothing.
     */
    /*
     * The row-wide segments read as pressed when every type holds that
     * state, and otherwise say how the row is split; each type row is
     * flagged once its choice is not the stored one.
     */
    function paintStates(box) {
        var counts = {};
        var kinds = 0;
        var same = null;
        Array.prototype.forEach.call(
            box.querySelectorAll('.mod-row:not(.mod-bulk)'),
            function (row) {
                var checked = row.querySelector('.mod-seg-in:checked');
                if (!checked) {
                    return;
                }
                row.classList.toggle('is-edited',
                    checked.value !== checked.getAttribute('data-ap-was'));
                if (!(checked.value in counts)) {
                    counts[checked.value] = 0;
                    kinds++;
                    same = checked.value;
                }
                counts[checked.value]++;
            }
        );
        if (kinds !== 1) {
            same = null;
        }
        var sum = box.querySelector('[data-ap-bulk-sum]');
        if (sum) {
            sum.textContent = '';
        }
        // The split is said in the segments' own order, one part per state held.
        Array.prototype.forEach.call(
            box.querySelectorAll('[data-ap-bulk]'),
            function (button) {
                var value = button.getAttribute('data-ap-bulk');
                button.setAttribute('aria-pressed', value === same ? 'true' : 'false');
                if (!sum || same !== null || !counts[value]) {
                    return;
                }
                if (sum.childNodes.length) {
                    sum.appendChild(document.createTextNode(' · '));
                }
                var part = document.createElement('span');
                part.textContent = counts[value] + ' '
                    + button.querySelector('.mod-seg-t').getAttribute('data-t');
                sum.appendChild(part);
            }
        );
    }

    inits.push(function (root) {
        Array.prototype.forEach.call(
            root.querySelectorAll('[data-ap-bulk-wrap]'),
            function (wrap) { wrap.hidden = false; }
        );
        Array.prototype.forEach.call(
            root.querySelectorAll('.mod-states'),
            paintStates
        );
    });

    document.addEventListener('change', function (event) {
        var box = event.target.matches && event.target.matches('.mod-seg-in')
            ? event.target.closest('.mod-states')
            : null;
        if (box) {
            paintStates(box);
        }
    });

    document.addEventListener('click', function (event) {
        var bulk = event.target.closest
            ? event.target.closest('[data-ap-bulk]')
            : null;
        if (!bulk) {
            return;
        }
        var box = bulk.closest('.mod-states');
        if (!box) {
            return;
        }
        var value = bulk.getAttribute('data-ap-bulk');
        var written = [];
        Array.prototype.forEach.call(
            box.querySelectorAll('.mod-row:not(.mod-bulk) .mod-seg'),
            function (group) {
                Array.prototype.forEach.call(
                    group.querySelectorAll('.mod-seg-in'),
                    function (radio) {
                        if (radio.value === value) {
                            radio.checked = true;
                            written.push(radio);
                        }
                    }
                );
            }
        );
        /* A folded row that was just written to has something to show. */
        expand(box, true);
        /*
         * One synthetic `change` rather than a call to `mark()` here:
         * the change handlers already mark, re-price and debounce the
         * bench, and a second copy of that sequence is how the two
         * come to disagree. Dispatched once, from the last field
         * written, because the handler does not care which.
         */
        if (written.length) {
            written[written.length - 1].dispatchEvent(
                new Event('change', {bubbles: true})
            );
        }
    });

    /* ------------------------------------------------------------ *
     * Long rows fold
     * ------------------------------------------------------------ */

    function expand(box, open) {
        var button = box.querySelector('[data-ap-more]');
        if (!button) {
            return;
        }
        Array.prototype.forEach.call(
            box.querySelectorAll('.mod-folded'),
            function (row) { row.classList.toggle('is-folded', !open); }
        );
        button.textContent = open
            ? button.getAttribute('data-ap-more-less')
            : button.getAttribute('data-ap-more-label');
        button.setAttribute('aria-expanded', open ? 'true' : 'false');
    }

    inits.push(function (root) {
        Array.prototype.forEach.call(
            root.querySelectorAll('.mod-states[data-ap-collapse]'),
            function (box) {
                var button = box.querySelector('[data-ap-more]');
                if (button) {
                    button.hidden = false;
                }
                expand(box, false);
            }
        );
    });

    document.addEventListener('click', function (event) {
        var button = event.target.closest
            ? event.target.closest('[data-ap-more]')
            : null;
        if (!button) {
            return;
        }
        event.preventDefault();
        var box = button.closest('.mod-states');
        if (box) {
            expand(box, button.getAttribute('aria-expanded') !== 'true');
        }
    });

    /* ------------------------------------------------------------ *
     * Narrowing the rows already in a table
     * ------------------------------------------------------------ */

    /*
     * Not the picker above it: that one finds a row to *add*, this
     * finds one you already have. It matches the key and whatever the
     * row says under it — a module's description, so `geolocation`
     * finds `mmdb_lookup` without the reader knowing the name.
     */
    inits.push(function (root) {
        Array.prototype.forEach.call(
            root.querySelectorAll('[data-ap-rowfilter-wrap]'),
            function (wrap) { wrap.hidden = false; }
        );
    });

    document.addEventListener('input', function (event) {
        var box = event.target.closest
            ? event.target.closest('[data-ap-rowfilter]')
            : null;
        if (!box) {
            return;
        }
        var map = box.closest('.ap-map');
        var body = map ? map.querySelector('table.wb-tbl:not([data-ap-new-table]) tbody') : null;
        if (!body) {
            return;
        }
        var query = box.value.trim().toLowerCase();
        var hidden = 0;
        var rows = body.querySelectorAll('tr[data-ap-key]');
        Array.prototype.forEach.call(rows, function (row) {
            var key = (row.getAttribute('data-ap-key') || '').toLowerCase();
            var sub = row.querySelector('.wb-sub');
            var text = key + ' ' + (sub ? sub.textContent.toLowerCase() : '');
            var match = query === '' || text.indexOf(query) !== -1;
            row.hidden = !match;
            if (!match) {
                hidden++;
            }
        });
        var count = map.querySelector('[data-ap-rowfilter-count]');
        if (count) {
            if (query === '') {
                count.textContent = '';
            } else if (hidden === rows.length) {
                count.textContent = box.getAttribute('data-ap-rowfilter-empty');
            } else {
                count.textContent = (rows.length - hidden) + '/' + rows.length;
            }
        }
    });

    /*
     * The ordered list, where the position is the setting.
     *
     * Everything here renumbers rather than rewrites: a row carries a
     * hidden input whose *value* is the shape and whose *name* holds
     * its position, so moving a row is swapping two list items and
     * re-indexing. Nothing needs to know what a shape is.
     */
    inits.push(function (root) {
        root.querySelectorAll('[data-ap-order]').forEach(initOrder);
    });

    function initOrder(box) {
        var list = box.querySelector('[data-ap-order-list]');
        var empty = box.querySelector('[data-ap-order-empty]');
        var capNote = box.querySelector('[data-ap-order-capnote]');
        var pick = box.querySelector('[data-ap-order-pick]');
        var prefix = box.getAttribute('data-ap-order-name');
        var cap = parseInt(box.getAttribute('data-ap-order-cap'), 10) || 0;
        if (!list) {
            return;
        }

        function renumber() {
            var rows = list.querySelectorAll('[data-ap-order-row]');
            rows.forEach(function (row, i) {
                var input = row.querySelector('[data-ap-order-input]');
                var rank = row.querySelector('[data-ap-order-rank]');
                if (input) {
                    input.name = prefix + '[' + i + ']';
                }
                if (rank) {
                    rank.textContent = i + 1;
                }
                /*
                 * Past the cap a row is still a real declaration - it
                 * simply only matters when something above it is not
                 * drawn - so it is dimmed rather than refused. An
                 * analyst with a reason to rank eight is spending
                 * something, and the editor's job is to say what.
                 */
                row.classList.toggle('is-past-cap', cap > 0 && i >= cap);
            });
            if (empty) {
                empty.hidden = rows.length > 0;
            }
            list.hidden = rows.length === 0;
            if (capNote) {
                capNote.hidden = !(cap > 0 && rows.length > cap);
            }
            mark();
        }

        // A tile moved by a drag or by the arrow keys is renumbered like one moved here.
        new MutationObserver(renumber).observe(list, { childList: true });

        list.addEventListener('click', function (event) {
            var row = event.target.closest
                ? event.target.closest('[data-ap-order-row]')
                : null;
            if (!row || !event.target.closest('[data-ap-order-remove]')) {
                return;
            }
            event.preventDefault();
            // The picker offers it again: it leaves out only the tiles on screen.
            row.parentNode.removeChild(row);
        });

        // A tile drawn like the server's, at the end of the ranking.
        function tile(key, label, desc) {
            var row = document.createElement('li');
            row.className = 'ap-order-row is-new';
            row.setAttribute('data-ap-order-row', '');
            row.setAttribute('data-ap-key', key);
            if (desc) {
                row.title = desc;
            }
            var input = document.createElement('input');
            input.type = 'hidden';
            input.value = key;
            input.setAttribute('data-ap-order-input', '');
            var rank = document.createElement('span');
            rank.className = 'ap-order-rank';
            rank.setAttribute('data-ap-order-rank', '');
            var body = document.createElement('span');
            body.className = 'ap-order-body';
            var title = document.createElement('span');
            title.className = 'fw-semibold';
            title.textContent = label;
            body.appendChild(title);
            if (desc) {
                var about = document.createElement('span');
                about.className = 'wb-sub';
                about.textContent = desc;
                body.appendChild(about);
            }
            var drop = document.createElement('button');
            drop.type = 'button';
            drop.className = 'wb-drop';
            drop.setAttribute('data-ap-order-remove', '');
            drop.title = box.getAttribute('data-ap-order-remove-label') || '';
            drop.innerHTML = '<i class="fa-solid fa-trash-can" aria-hidden="true"></i>';
            row.appendChild(input);
            row.appendChild(rank);
            row.appendChild(body);
            row.appendChild(drop);
            return row;
        }

        // The search box the select was upgraded to hands over a pick, with its description.
        if (pick) {
            pick.addEventListener('ap-order-pick', function (event) {
                var key = event.detail.key;
                if (!key || list.querySelector('[data-ap-key="' + cssEscape(key) + '"]')) {
                    return;
                }
                var known = (pick.apRows || []).filter(function (row) {
                    return row.key === key;
                })[0];
                list.appendChild(tile(key, event.detail.label || key,
                    known ? known.desc : ''));
            });
        }

        renumber();
    }

    /*
     * What the page's controls need once they are in the document. The
     * view swaps a parameter's inputs in when it is edited, so it runs
     * this again on what it inserted.
     */
    function initEditors(root) {
        inits.forEach(function (init) {
            init(root);
        });
    }
    window.analystProfileInitEditors = initEditors;
    initEditors(document);

    mark();
}
})();
