/*
 * The analyst profile page on the server settings frame: the section
 * list, a search over every parameter, and editing a parameter where it
 * is shown.
 *
 * A parameter is edited with the inputs `edit` draws for its section,
 * fetched once per section and swapped in for the one row, field or
 * list. Saving posts those inputs alone: `edit` merges them into the
 * stored document, and the board is redrawn from the saved profile.
 */
(function () {
    'use strict';

    var XHR = { 'X-Requested-With': 'XMLHttpRequest' };
    var SEARCH_LIMIT = 40;

    var config;
    var L;
    var board;
    var pane = null;
    var current = null;
    var busy = false;
    var editCache = {};
    var index = null;
    var searchModal;
    var searchInput;
    var searchResults;

    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', start);
    } else {
        start();
    }

    function start() {
        board = document.querySelector('[data-ap-settings]');
        var holder = document.getElementById('ap-settings-config');
        if (!board || !holder) {
            return;
        }
        config = JSON.parse(holder.textContent);
        L = config.labels;
        var open = board.querySelector('[data-ap-pane]:not([hidden])');
        pane = open ? open.getAttribute('data-ap-pane') : null;
        decorate();
        watchLive();
        jsonBoxes();
        board.addEventListener('click', onClick);
        board.addEventListener('dblclick', onDblclick);
        board.addEventListener('keydown', onKeydown);
        board.addEventListener('input', onInput);
        board.addEventListener('change', onChange);
        board.addEventListener('dragstart', onDragstart);
        board.addEventListener('dragover', onDragover);
        board.addEventListener('drop', onDrop);
        board.addEventListener('dragend', onDragend);
        document.addEventListener('keydown', onGlobalKeydown);
        window.addEventListener('resize', fitRaw);
        initSearch();
    }

    /* ------------------------------------------------------------ helpers */

    function esc(text) {
        var div = document.createElement('div');
        div.textContent = text == null ? '' : String(text);
        return div.innerHTML;
    }

    function text(node) {
        return node ? node.textContent.replace(/\s+/g, ' ').trim() : '';
    }

    // A cell's reading for the search, without the dash an empty cell shows.
    function reading(node) {
        var value = text(node);
        return value === '—' || value === '-' ? '' : value;
    }

    // A cell drawn as a select reads as its choice, not as every option it offers.
    function cellValue(cell) {
        var chips = cell.querySelectorAll('.mod-chips .wb-id');
        if (chips.length) {
            return Array.prototype.map.call(chips, text).join(' ');
        }
        var select = cell.querySelector('select');
        if (select) {
            return select.selectedIndex < 0 ? '' : text(select.options[select.selectedIndex]);
        }
        var segments = cell.querySelectorAll('.mod-seg-in:checked');
        if (segments.length) {
            return Array.prototype.map.call(segments, function (radio) {
                return text(radio.closest('.mod-row').querySelector('.wb-id'));
            }).join(' ');
        }
        return reading(cell);
    }

    function fmt(template, value) {
        return String(template).replace('%s', value);
    }

    function toast(message, variant) {
        if (typeof showToast === 'function') {
            showToast(esc(message), variant || 'success');
        }
    }

    function query(name) {
        return new URL(window.location.href).searchParams.get(name);
    }

    /* ---------------------------------------------------------- sections */

    function show(id) {
        var found = false;
        board.querySelectorAll('[data-ap-pane]').forEach(function (node) {
            var on = node.getAttribute('data-ap-pane') === id;
            node.hidden = !on;
            found = found || on;
        });
        if (!found) {
            return;
        }
        pane = id;
        board.querySelectorAll('[data-ap-nav]').forEach(function (link) {
            var on = link.getAttribute('data-ap-nav') === id;
            link.classList.toggle('active', on);
            if (on) {
                link.setAttribute('aria-current', 'page');
            } else {
                link.removeAttribute('aria-current');
            }
        });
        var kept = board.querySelector('[data-ap-vbar-section]');
        if (kept) {
            kept.value = id;
        }
        fitRaw();
        var url = new URL(window.location.href);
        url.searchParams.set('section', id);
        window.history.replaceState(null, '', url.toString());
    }

    /* ------------------------------------------------------ inline edit */

    // What a click edits: a row of a palette, one field, or a whole list.
    function decorate() {
        if (!config.mayEdit) {
            return;
        }
        board.querySelectorAll('.ap-pane .wb-sec').forEach(function (sec) {
            sec.querySelectorAll('[data-ap-kind="items"] tr[data-ap-item],'
                + ' .wb-field[data-ap-unit]').forEach(function (unit) {
                // A live block's inputs are on the page already.
                if (unit.closest('[data-ap-live]')) {
                    return;
                }
                unit.classList.add('ap-unit');
                unit.tabIndex = 0;
                unit.title = L.editHint;
            });
            sec.querySelectorAll('.wb-block[data-ap-kind="map"]:not([data-ap-live]),'
                + ' .wb-block[data-ap-kind="order"]:not([data-ap-live]),'
                + ' .wb-block[data-ap-kind="strip"]:not([data-ap-live])').forEach(function (block) {
                // The band strip's two numbers are fields, edited one at a time.
                if (block.querySelector('.ap-unit')) {
                    return;
                }
                var button = document.createElement('button');
                button.type = 'button';
                button.className = 'btn btn-sm btn-outline-primary ap-blk-edit';
                button.setAttribute('data-ap-blk-edit', '');
                button.innerHTML = '<i class="fas fa-pen me-1" aria-hidden="true"></i>'
                    + esc(L.edit);
                block.insertBefore(button, block.firstChild);
            });
        });
    }

    function locate(unit) {
        var sec = unit.closest('.wb-sec').getAttribute('data-sec');
        var base = '.wb-sec[data-sec="' + CSS.escape(sec) + '"] ';
        var block = unit.closest('[data-ap-block]');
        if (unit.matches('tr[data-ap-item]')) {
            return { sec: sec, sel: base + '[data-ap-block="'
                + CSS.escape(block.getAttribute('data-ap-block')) + '"] tr[data-ap-item="'
                + CSS.escape(unit.getAttribute('data-ap-item')) + '"]' };
        }
        if (unit.matches('.wb-field')) {
            return { sec: sec, sel: base + '.wb-field[data-ap-unit="'
                + CSS.escape(unit.getAttribute('data-ap-unit')) + '"]' };
        }
        return { sec: sec, sel: base + '.wb-block[data-ap-block="'
            + CSS.escape(unit.getAttribute('data-ap-block')) + '"]', block: true };
    }

    function loadSection(sec) {
        if (!editCache[sec]) {
            var url = new URL(config.editUrl, window.location.href);
            url.searchParams.set('section', sec);
            if (query('value')) {
                url.searchParams.set('value', query('value'));
            }
            editCache[sec] = fetch(url.toString(), { headers: XHR, credentials: 'same-origin' })
                .then(function (response) {
                    if (!response.ok) {
                        throw new Error('HTTP ' + response.status);
                    }
                    return response.text();
                })
                .then(function (html) {
                    return new DOMParser().parseFromString(html, 'text/html');
                })
                .catch(function (error) {
                    delete editCache[sec];
                    throw error;
                });
        }
        return editCache[sec];
    }

    function openUnit(unit) {
        if (busy || unit.classList.contains('is-loading')) {
            return;
        }
        closeUnit();
        var at = locate(unit);
        unit.classList.add('is-loading');
        loadSection(at.sec).then(function (doc) {
            unit.classList.remove('is-loading');
            var twin = doc.querySelector(at.sel);
            if (!twin) {
                throw new Error('No editor for ' + at.sel);
            }
            var edit = document.importNode(twin, true);
            edit.classList.add('ap-unit-editing');
            unit.replaceWith(edit);
            current = { view: unit, edit: edit, at: at };
            bar(edit);
            if (typeof window.analystProfileInitEditors === 'function') {
                window.analystProfileInitEditors(edit);
            }
            var first = edit.querySelector('input:not([type="hidden"]):not([disabled]),'
                + ' select:not([disabled]), textarea');
            if (first) {
                first.focus();
            }
        }).catch(function () {
            unit.classList.remove('is-loading');
            toast(L.formFailed, 'danger');
        });
    }

    // Save and Cancel: beside the box for one field, under a row or a list.
    function bar(edit) {
        var inline = edit.matches('.wb-field') && edit.querySelector('.wb-inline');
        if (inline) {
            var buttons = document.createElement('span');
            buttons.className = 'ap-unit-bar ap-unit-bar-inline';
            buttons.innerHTML = '<button type="button" class="btn btn-sm btn-success" data-ap-unit-save'
                + ' title="' + esc(L.save) + '" aria-label="' + esc(L.save) + '">'
                + '<i class="fas fa-check" aria-hidden="true"></i></button>'
                + '<button type="button" class="btn btn-sm btn-outline-secondary" data-ap-unit-cancel'
                + ' title="' + esc(L.cancel) + '" aria-label="' + esc(L.cancel) + '">'
                + '<i class="fas fa-xmark" aria-hidden="true"></i></button>';
            inline.appendChild(buttons);
            var slot = document.createElement('span');
            slot.className = 'ap-unit-msg';
            slot.setAttribute('role', 'alert');
            edit.appendChild(slot);
            current.bar = buttons;
            current.msg = slot;
            return;
        }
        var html = '<div class="ap-unit-bar-in">'
            + '<span class="ap-unit-msg" role="alert"></span>'
            + (current.at.block ? '' : '<span class="ap-unit-keys">' + esc(L.keys) + '</span>')
            + '<button type="button" class="btn btn-sm btn-outline-secondary" data-ap-unit-cancel>'
            + esc(L.cancel) + '</button>'
            + '<button type="button" class="btn btn-sm btn-success" data-ap-unit-save>'
            + '<i class="fas fa-check me-1" aria-hidden="true"></i>' + esc(L.save) + '</button>'
            + '</div>';
        var node;
        if (edit.tagName === 'TR') {
            node = document.createElement('tr');
            node.className = 'ap-unit-bar';
            var cell = document.createElement('td');
            cell.colSpan = edit.cells.length;
            cell.innerHTML = html;
            node.appendChild(cell);
            edit.parentNode.insertBefore(node, edit.nextSibling);
        } else {
            node = document.createElement('div');
            node.className = 'ap-unit-bar';
            node.innerHTML = html;
            edit.appendChild(node);
        }
        current.bar = node;
        current.msg = node.querySelector('.ap-unit-msg');
    }

    function closeUnit() {
        if (!current || busy) {
            return;
        }
        if (current.bar.parentNode && current.bar.tagName === 'TR') {
            current.bar.parentNode.removeChild(current.bar);
        }
        current.edit.replaceWith(current.view);
        current = null;
    }

    // What the edited inputs would post as a form, and nothing else.
    function collect(root, data) {
        root.querySelectorAll('input, select, textarea').forEach(function (field) {
            var type = (field.type || '').toLowerCase();
            if (!field.name || field.disabled
                || ['button', 'submit', 'reset', 'file'].indexOf(type) !== -1
            ) {
                return;
            }
            if ((type === 'checkbox' || type === 'radio') && !field.checked) {
                return;
            }
            if (field.tagName === 'SELECT' && field.multiple) {
                Array.prototype.forEach.call(field.selectedOptions, function (option) {
                    data.append(field.name, option.value);
                });
                return;
            }
            data.append(field.name, field.value);
        });
    }

    function message(lines) {
        if (current && current.msg) {
            current.msg.textContent = lines.join(' ');
        }
    }

    function errorsOf(answer) {
        var out = [];
        (function walk(node) {
            if (node == null) {
                return;
            }
            if (typeof node === 'string') {
                out.push(node);
            } else if (typeof node === 'object') {
                Object.keys(node).forEach(function (key) {
                    walk(node[key]);
                });
            }
        })(answer && answer.errors);
        return out.length ? out : [L.saveFailed];
    }

    function saving(on) {
        busy = on;
        if (current) {
            current.bar.querySelectorAll('button').forEach(function (button) {
                button.disabled = on;
            });
        }
    }

    // The inputs under root, posted to `edit` with the page's CSRF token.
    // `extra`, when given, is a second part of the page posted with the first.
    function post(root, extra) {
        var data = new FormData();
        var token = document.getElementById('ap-token');
        if (token) {
            token.querySelectorAll('input[type="hidden"]').forEach(function (field) {
                if (field.name) {
                    data.append(field.name, field.value);
                }
            });
        }
        collect(root, data);
        if (extra) {
            collect(extra, data);
        }
        return fetch(config.editUrl, {
            method: 'POST',
            body: data,
            credentials: 'same-origin',
            headers: { 'Accept': 'application/json', 'X-Requested-With': 'XMLHttpRequest' },
        }).then(function (response) {
            return response.json();
        });
    }

    function announce(answer) {
        toast(answer.parameters_changed
            ? fmt(L.saved, answer.profile ? answer.profile.revision : '')
            : L.unchanged, answer.parameters_changed ? 'success' : 'info');
    }

    function saveUnit() {
        if (!current || busy) {
            return;
        }
        var at = current.at;
        saving(true);
        post(current.edit).then(function (answer) {
            saving(false);
            if (!answer || !answer.saved) {
                message(errorsOf(answer));
                return;
            }
            announce(answer);
            current = null;
            redraw(at);
        }).catch(function () {
            saving(false);
            message([L.saveFailed]);
        });
    }

    /* ------------------------------------------------------- live lists */

    /*
     * A list drawn with its inputs on the read page. Edit shows what
     * changes it: a remove button per entry and the frame that adds
     * one. Any change is said by a bar under the list, and its Save or
     * Discard is the way out; the list's own search only narrows it.
     */
    function watchLive() {
        board.querySelectorAll('.wb-block[data-ap-live]').forEach(function (block) {
            var watch = new MutationObserver(function () {
                var box = block.querySelector('[data-ap-live-filter]');
                narrow(block, box ? box.value : '');
                sortable(block);
            });
            block.querySelectorAll('table.wb-tbl tbody, [data-ap-order-list]').forEach(function (body) {
                watch.observe(body, { childList: true });
            });
        });
    }

    // Edit gives way to Discard and Save at once: they are the way back out.
    function liveEdit(block) {
        block.classList.add('is-editing');
        var toggle = block.querySelector('[data-ap-live-edit]');
        if (toggle) {
            toggle.hidden = true;
        }
        liveBar(block).hidden = false;
        sortable(block);
        var pick = block.querySelector('.ap-map-add input[type="search"], .ap-map-add select');
        if (pick) {
            pick.focus();
        }
    }

    function liveBar(block) {
        var bar = block.querySelector('.ap-live-bar');
        if (!bar) {
            bar = document.createElement('div');
            bar.className = 'ap-unit-bar ap-live-bar';
            bar.hidden = true;
            bar.innerHTML = '<div class="ap-unit-bar-in">'
                + '<span class="ap-unit-msg" role="alert"></span>'
                + '<span class="ap-unit-keys">' + esc(L.unsaved) + '</span>'
                + '<button type="button" class="btn btn-sm btn-outline-secondary" data-ap-live-discard>'
                + esc(L.discard) + '</button>'
                + '<button type="button" class="btn btn-sm btn-success" data-ap-live-save>'
                + '<i class="fas fa-check me-1" aria-hidden="true"></i>' + esc(L.save) + '</button>'
                + '</div>';
            (block.querySelector('.ap-live-tools') || block).appendChild(bar);
        }
        return bar;
    }

    function saveLive(block) {
        // A row added without its value, a tier say, is asked for rather than posted empty.
        var missing = block.querySelector('select:invalid, input:invalid');
        if (missing) {
            missing.focus();
            missing.reportValidity();
            return;
        }
        var bar = liveBar(block);
        var buttons = bar.querySelectorAll('button');
        buttons.forEach(function (button) {
            button.disabled = true;
        });
        post(block).then(function (answer) {
            if (!answer || !answer.saved) {
                buttons.forEach(function (button) {
                    button.disabled = false;
                });
                bar.querySelector('.ap-unit-msg').textContent = errorsOf(answer).join(' ');
                return;
            }
            announce(answer);
            redraw(locate(block));
        }).catch(function () {
            buttons.forEach(function (button) {
                button.disabled = false;
            });
            bar.querySelector('.ap-unit-msg').textContent = L.saveFailed;
        });
    }

    // Whether a field no longer holds what the page was drawn with.
    function moved(field) {
        var was = field.getAttribute('data-ap-was');
        if (was === null) {
            return false;
        }
        if (field.type === 'checkbox') {
            return String(field.checked) !== was;
        }
        if (field.type === 'radio') {
            return field.checked && field.value !== was;
        }
        return String(field.value) !== was;
    }

    // Hide the entries the search does not match, and a group left empty; recount the groups.
    function narrow(block, query) {
        var body = block.querySelector('table.wb-tbl:not([data-ap-new-table]) tbody');
        if (!body) {
            return;
        }
        query = query.trim().toLowerCase();
        var heading = null;
        var shown = 0;
        var members = 0;
        var matched = 0;
        var total = 0;
        var close = function () {
            if (heading) {
                heading.hidden = shown === 0;
                var n = heading.querySelector('.ap-map-grp-n');
                if (n) {
                    n.textContent = members;
                }
            }
        };
        Array.prototype.forEach.call(body.rows, function (row) {
            if (row.classList.contains('ap-map-grp')) {
                close();
                heading = row;
                shown = 0;
                members = 0;
                return;
            }
            members += 1;
            var hay = ((row.getAttribute('data-ap-key') || '') + ' ' + text(row)).toLowerCase();
            row.hidden = query !== '' && hay.indexOf(query) === -1;
            shown += row.hidden ? 0 : 1;
            matched += row.hidden ? 0 : 1;
            total += 1;
        });
        close();
        // While a search narrows the list, it says how much is left.
        var count = block.querySelector('[data-ap-find-count]');
        if (count) {
            count.hidden = query === '';
            count.textContent = matched === 0 && count.getAttribute('data-none')
                ? count.getAttribute('data-none')
                : count.getAttribute('data-of')
                    .replace('%1$s', matched).replace('%2$s', total);
        }
    }

    function onInput(event) {
        var box = event.target;
        if (box.matches && box.matches('[data-ap-live-filter]')) {
            narrow(box.closest('.wb-block'), box.value);
            return;
        }
        if (box.matches && box.matches('[data-ap-reuse-range], [data-ap-reuse-hours]')) {
            var scope = box.closest('[data-ap-reuse]');
            // Moving the slider leaves Custom: it is the slider's value again.
            if (box.matches('[data-ap-reuse-range]')) {
                scope.classList.remove('is-custom');
            }
            paintReuse(scope);
        }
    }

    function onChange(event) {
        var field = event.target;
        if (!field.matches) {
            return;
        }
        if (field.matches('.wb-block[data-ap-live] .wb-field .wb-switch input[type="checkbox"]')) {
            // While a list is edited its switches wait for its Save like the rest.
            if (field.closest('.wb-block').classList.contains('is-editing')) {
                paintSwitch(field.closest('.wb-field'), field.checked);
                return;
            }
            saveSwitch(field);
            return;
        }
        if (field.matches('.ap-map[data-ap-group-by-value] tr[data-ap-key] select')) {
            regroup(field);
            return;
        }
        // A choice is made as it is picked.
        if (field.matches('[data-ap-set].is-open .ap-set-in select[data-ap-field]')) {
            saveSet(field.closest('[data-ap-set]'));
            return;
        }
        if (field.matches('[data-ap-reuse-range], [data-ap-reuse-hours]')) {
            saveReuse(field.closest('[data-ap-reuse]'));
        }
    }

    /* ------------------------------------------- settings changed in place */

    // A setting opens where it is read (inline_value.ctp), one at a time.
    function openSet(set) {
        board.querySelectorAll('[data-ap-set].is-open').forEach(function (other) {
            if (other !== set) {
                closeSet(other);
            }
        });
        set.classList.add('is-open');
        set.querySelector('.ap-set-in').hidden = false;
        var box = set.querySelector('.ap-set-in [data-ap-field]');
        if (box) {
            box.focus();
            if (box.tagName === 'INPUT') {
                box.select();
            }
        }
    }

    // Closed again, holding what it was drawn with.
    function closeSet(set) {
        set.querySelectorAll('.ap-set-in [data-ap-field]').forEach(function (field) {
            var was = field.getAttribute('data-ap-was');
            if (was !== null) {
                field.value = was;
            }
        });
        set.classList.remove('is-open');
        set.querySelector('.ap-set-in').hidden = true;
        var value = set.querySelector('[data-ap-set-edit]');
        if (value) {
            value.focus();
        }
    }

    // One setting saved alone; a rule's goes with its switch, so a number never switches a rule on.
    function saveSet(set) {
        var box = set.querySelector('.ap-set-in [data-ap-field]');
        if (!box) {
            return;
        }
        if (!box.checkValidity()) {
            box.reportValidity();
            return;
        }
        if (!moved(box)) {
            closeSet(set);
            return;
        }
        var rule = set.closest('.ap-rule');
        var sent = post(set, rule ? rule.querySelector('.ap-rule-sw .wb-field') : null);
        var controls = set.querySelectorAll('.ap-set-in button, .ap-set-in [data-ap-field]');
        controls.forEach(function (control) {
            control.disabled = true;
        });
        var release = function (lines) {
            controls.forEach(function (control) {
                control.disabled = false;
            });
            toast(lines.join(' '), 'danger');
        };
        var at = { sel: '[data-ap-set="' + CSS.escape(set.getAttribute('data-ap-set')) + '"]' };
        sent.then(function (answer) {
            if (!answer || !answer.saved) {
                release(errorsOf(answer));
                return;
            }
            announce(answer);
            redraw(at).then(function () {
                var node = board.querySelector(at.sel);
                if (node) {
                    node.classList.add('is-saved');
                    window.setTimeout(function () {
                        node.classList.remove('is-saved');
                    }, 4000);
                }
            });
        }).catch(function () {
            release([L.saveFailed]);
        });
    }

    /* ------------------------------------------------------ reuse window */

    function duration(scope, hours) {
        var text = fmt(scope.getAttribute(hours === 1 ? 'data-hour' : 'data-hours'), hours);
        if (hours > 24) {
            var days = Math.round(hours / 24 * 10) / 10;
            text += ' · ' + fmt(scope.getAttribute(days <= 1 ? 'data-day' : 'data-days'), days);
        }
        return text;
    }

    // The slider, the box behind it and the step that says the window, kept in step.
    function paintReuse(scope) {
        var range = scope.querySelector('[data-ap-reuse-range]');
        var box = scope.querySelector('[data-ap-reuse-hours]');
        var custom = scope.classList.contains('is-custom');
        if (!range || !box) {
            return;
        }
        if (!custom) {
            box.value = range.value;
        }
        range.style.setProperty('--ratio', (range.value - 1) / 23);
        var hours = parseInt(box.value, 10);
        var text = hours >= 1 ? duration(scope, hours) : '—';
        scope.querySelector('[data-ap-reuse-value]').textContent = text;
        scope.querySelector('[data-ap-reuse-kept]').textContent = fmt(scope.getAttribute('data-kept'), text);
        scope.querySelector('[data-ap-reuse-custom]').hidden = !custom;
        scope.querySelector('[data-ap-reuse-toggle]').setAttribute('aria-pressed', custom ? 'true' : 'false');
    }

    function toggleReuse(scope) {
        scope.classList.toggle('is-custom');
        paintReuse(scope);
        var box = scope.querySelector('[data-ap-reuse-hours]');
        if (scope.classList.contains('is-custom')) {
            box.focus();
            box.select();
        } else {
            saveReuse(scope);
        }
    }

    // Saved as soon as it is let go, unless it is back where it started.
    function saveReuse(scope) {
        var box = scope.querySelector('[data-ap-reuse-hours]');
        if (!box.checkValidity()) {
            box.reportValidity();
            return;
        }
        if (box.value === box.getAttribute('data-ap-reuse-from')) {
            return;
        }
        var unit = box.closest('.wb-field');
        var sent = post(unit);
        scope.classList.add('is-saving');
        sent.then(function (answer) {
            if (!answer || !answer.saved) {
                toast(errorsOf(answer).join(' '), 'danger');
            } else {
                announce(answer);
            }
            redraw(null);
        }).catch(function () {
            toast(L.saveFailed, 'danger');
            redraw(null);
        });
    }

    // A tile whose value heads its group goes under its new heading once that value changes.
    function regroup(select) {
        var row = select.closest('tr[data-ap-key]');
        var body = row.parentNode;
        if (!body || body.closest('[data-ap-new-table]')) {
            return;
        }
        var heading = body.querySelector('tr.ap-map-grp[data-ap-grp-value="'
            + CSS.escape(select.value) + '"]');
        if (!heading) {
            return;
        }
        var next = heading.nextElementSibling;
        while (next && !next.classList.contains('ap-map-grp')) {
            next = next.nextElementSibling;
        }
        body.insertBefore(row, next);
        row.classList.add('is-moved');
    }

    /* ---------------------------------------------------------- sorting */

    var dragged = null;

    // An ordered list's tiles, picked ones included, are dragged into place while it is edited.
    function sortable(block) {
        if (!block.classList.contains('is-editing')) {
            return;
        }
        block.querySelectorAll('.ap-map.is-sortable table.wb-tbl:not([data-ap-new-table])'
            + ' tr[data-ap-key], .ap-order.is-sortable [data-ap-order-row]').forEach(function (row) {
            row.draggable = true;
            row.tabIndex = 0;
        });
    }

    // The keyboard's way of dragging: an arrow moves the focused tile one place.
    function nudge(row, key) {
        var back = key === 'ArrowLeft' || key === 'ArrowUp';
        var next = back ? row.previousElementSibling : row.nextElementSibling;
        if (!next || !next.hasAttribute('data-ap-key')) {
            return;
        }
        row.parentNode.insertBefore(row, back ? next : next.nextSibling);
        row.focus();
    }

    function onDragstart(event) {
        var row = event.target.closest ? event.target.closest('[draggable="true"][data-ap-key]') : null;
        if (!row || !row.closest('.wb-block.is-editing .is-sortable')) {
            return;
        }
        dragged = row;
        row.classList.add('is-dragging');
        event.dataTransfer.effectAllowed = 'move';
        event.dataTransfer.setData('text/plain', row.getAttribute('data-ap-key'));
    }

    // Before the tile under the pointer when on its first half, after it otherwise.
    function onDragover(event) {
        if (!dragged) {
            return;
        }
        var body = dragged.parentNode;
        var over = event.target.closest ? event.target.closest('[data-ap-key]') : null;
        if (!over || over.parentNode !== body) {
            if (event.target.closest && event.target.closest('tbody, ol') === body) {
                event.preventDefault();
            }
            return;
        }
        event.preventDefault();
        event.dataTransfer.dropEffect = 'move';
        if (over === dragged) {
            return;
        }
        var box = over.getBoundingClientRect();
        var first = event.clientX < box.left + box.width / 2;
        body.insertBefore(dragged, first ? over : over.nextSibling);
    }

    function onDrop(event) {
        if (dragged) {
            event.preventDefault();
        }
    }

    function onDragend() {
        if (dragged) {
            dragged.classList.remove('is-dragging');
            dragged = null;
        }
    }

    /* ---------------------------------------------------------- switches */

    function paintSwitch(unit, on) {
        var state = unit.querySelector('.wb-switch-t');
        if (state) {
            state.textContent = state.getAttribute(on ? 'data-on' : 'data-off');
        }
        // What the switch governs reads its new state before the save returns.
        var scope = unit.closest('[data-ap-switch-scope]');
        if (scope) {
            scope.classList.toggle('is-off', !on);
        }
    }

    // A switch on the read page is saved as soon as it is flipped, as a module's is.
    function saveSwitch(input) {
        var unit = input.closest('.wb-field');
        paintSwitch(unit, input.checked);
        var sent = post(unit);
        input.disabled = true;
        var undo = function (lines) {
            input.disabled = false;
            input.checked = !input.checked;
            paintSwitch(unit, input.checked);
            toast(lines.join(' '), 'danger');
        };
        sent.then(function (answer) {
            if (!answer || !answer.saved) {
                undo(errorsOf(answer));
                return;
            }
            announce(answer);
            // A switch that repaints what it governs has said so already: no flash.
            redraw(unit.closest('[data-ap-switch-scope]') ? null : locate(unit));
        }).catch(function () {
            undo([L.saveFailed]);
        });
    }

    // The board from the saved profile: badges, readings and the row itself.
    function redraw(at) {
        var url = new URL(config.viewUrl, window.location.href);
        url.searchParams.set('fragment', 'board');
        url.searchParams.set('section', pane);
        if (query('value')) {
            url.searchParams.set('value', query('value'));
        }
        return fetch(url.toString(), { headers: XHR, credentials: 'same-origin' })
            .then(function (response) {
                if (!response.ok) {
                    throw new Error('HTTP ' + response.status);
                }
                return response.text();
            })
            .then(function (html) {
                var y = window.scrollY;
                board.innerHTML = html;
                editCache = {};
                index = null;
                // A live list's pickers are drawn as selects until the editor upgrades them.
                if (typeof window.analystProfileInitEditors === 'function') {
                    window.analystProfileInitEditors(board);
                }
                decorate();
                watchLive();
                jsonBoxes();
                show(pane);
                window.scrollTo(0, y);
                var node = at ? board.querySelector(at.sel) : null;
                if (node) {
                    flash(node);
                }
            })
            .catch(function () {
                toast(L.refreshFailed, 'warning');
            });
    }

    function flash(node) {
        var cls = node.tagName === 'TR' ? 'ss-row-flash' : 'ap-flash';
        node.classList.remove(cls);
        void node.offsetWidth;
        node.classList.add(cls);
        window.setTimeout(function () {
            node.classList.remove(cls);
        }, 6000);
    }

    /* ----------------------------------------------------------- events */

    function onClick(event) {
        var target = event.target;
        var nav = target.closest('[data-ap-nav]');
        if (nav) {
            event.preventDefault();
            closeUnit();
            show(nav.getAttribute('data-ap-nav'));
            return;
        }
        if (target.closest('[data-ap-search-open]')) {
            openSearch();
            return;
        }
        if (target.closest('[data-ap-unit-save]')) {
            saveUnit();
            return;
        }
        if (target.closest('[data-ap-unit-cancel]')) {
            closeUnit();
            return;
        }
        var toggle = target.closest('[data-ap-live-edit]');
        if (toggle) {
            liveEdit(toggle.closest('.wb-block'));
            return;
        }
        var setButton = target.closest('[data-ap-set-edit], [data-ap-set-save], [data-ap-set-cancel]');
        if (setButton) {
            var set = setButton.closest('[data-ap-set]');
            if (setButton.hasAttribute('data-ap-set-edit')) {
                openSet(set);
            } else if (setButton.hasAttribute('data-ap-set-save')) {
                saveSet(set);
            } else {
                closeSet(set);
            }
            return;
        }
        var custom = target.closest('[data-ap-reuse-toggle]');
        if (custom) {
            toggleReuse(custom.closest('[data-ap-reuse]'));
            return;
        }
        var press = target.closest('[data-ap-live-save], [data-ap-live-discard]');
        if (press) {
            if (press.hasAttribute('data-ap-live-save')) {
                saveLive(press.closest('.wb-block'));
            } else {
                redraw(null);
            }
            return;
        }
        if (target.closest('[data-ap-raw-cancel]')) {
            raw(false);
            return;
        }
        if (target.closest('[data-ap-raw-save]')) {
            saveRaw();
            return;
        }
        var edit = target.closest('[data-ap-blk-edit]');
        if (edit) {
            openUnit(edit.closest('.wb-block'));
            return;
        }
        var unit = target.closest('.ap-unit');
        if (!unit || target.closest('a, button, summary, input, select, textarea')) {
            return;
        }
        openUnit(unit);
    }

    function onKeydown(event) {
        var target = event.target;
        // An open setting takes Enter to save and Escape to leave it as it was.
        if ((event.key === 'Enter' || event.key === 'Escape') && target.closest
            && target.closest('[data-ap-set].is-open .ap-set-in')
        ) {
            event.preventDefault();
            if (event.key === 'Enter') {
                saveSet(target.closest('[data-ap-set]'));
            } else {
                closeSet(target.closest('[data-ap-set]'));
            }
            return;
        }
        // Enter in the custom box commits it, as leaving it does.
        if (event.key === 'Enter' && target.matches && target.matches('[data-ap-reuse-hours]')) {
            event.preventDefault();
            target.blur();
            return;
        }
        if (/^Arrow(Left|Right|Up|Down)$/.test(event.key) && target.matches
            && target.matches('.wb-block.is-editing .is-sortable [draggable="true"][data-ap-key]')
        ) {
            event.preventDefault();
            nudge(target, event.key);
            return;
        }
        if (event.key === 'Escape' && target.closest && target.closest('[data-ap-raw].is-editing')) {
            event.preventDefault();
            raw(false);
            return;
        }
        if (current && current.edit.contains(target)) {
            // A list's own pickers take Enter and Escape for themselves.
            if (current.at.block || target.closest('.ap-pick') || target.tagName === 'TEXTAREA') {
                return;
            }
            if (event.key === 'Enter') {
                event.preventDefault();
                saveUnit();
            } else if (event.key === 'Escape') {
                event.preventDefault();
                closeUnit();
            }
            return;
        }
        if (event.key === 'Enter' && target.classList.contains('ap-unit')) {
            event.preventDefault();
            openUnit(target);
        }
    }

    function onGlobalKeydown(event) {
        if ((event.ctrlKey || event.metaKey) && !event.altKey && event.key.toLowerCase() === 'k') {
            event.preventDefault();
            openSearch();
        }
    }

    /* ------------------------------------------------------------ raw */

    // The document box is the modals' JSON field, bound like theirs.
    function jsonBoxes() {
        if (typeof initJsonFields === 'function') {
            initJsonFields(board);
        }
        fitRaw();
    }

    // The document card ends where the section list does, on a wide page.
    function fitRaw() {
        var doc = board.querySelector('[data-ap-raw]');
        var list = board.querySelector('.ss-nav-sticky');
        var layout = board.querySelector('.ss-layout');
        if (!doc || !list || !layout) {
            return;
        }
        var wide = window.matchMedia('(min-width: 992px)').matches;
        if (!wide || doc.offsetParent === null) {
            doc.classList.remove('is-fitted');
            doc.style.height = '';
            return;
        }
        var top = doc.getBoundingClientRect().top - layout.getBoundingClientRect().top;
        doc.classList.add('is-fitted');
        doc.style.height = Math.max(list.offsetHeight - top, 320) + 'px';
    }

    function onDblclick(event) {
        var doc = event.target.closest ? event.target.closest('[data-ap-raw].is-editable') : null;
        if (doc && !doc.classList.contains('is-editing')) {
            raw(true);
        }
    }

    // The document read, or open for editing with its Save and Cancel up top.
    function raw(open) {
        var doc = board.querySelector('[data-ap-raw]');
        var box = doc ? doc.querySelector('textarea') : null;
        if (!box) {
            return;
        }
        if (open && !doc.classList.contains('is-editing')) {
            box.setAttribute('data-ap-raw-was', box.value);
        }
        if (!open && box.hasAttribute('data-ap-raw-was')) {
            box.value = box.getAttribute('data-ap-raw-was');
            box.dispatchEvent(new Event('input', { bubbles: true }));
        }
        box.readOnly = !open;
        doc.classList.toggle('is-editing', open);
        var acts = board.querySelector('[data-ap-raw-acts]');
        var hint = board.querySelector('[data-ap-raw-hint]');
        var msg = board.querySelector('[data-ap-raw-msg]');
        if (acts) {
            acts.hidden = !open;
        }
        if (hint) {
            hint.hidden = open;
        }
        if (msg && !open) {
            msg.hidden = true;
        }
        if (open) {
            box.focus();
        }
    }

    function saveRaw() {
        var doc = board.querySelector('[data-ap-raw]');
        var msg = board.querySelector('[data-ap-raw-msg]');
        var buttons = board.querySelectorAll('[data-ap-raw-acts] button');
        if (!doc || busy) {
            return;
        }
        busy = true;
        buttons.forEach(function (button) {
            button.disabled = true;
        });
        var failed = function (lines) {
            busy = false;
            buttons.forEach(function (button) {
                button.disabled = false;
            });
            if (msg) {
                msg.textContent = lines.join(' ');
                msg.hidden = false;
            }
        };
        post(doc).then(function (answer) {
            var parse = answer && answer.data ? answer.data.parse : null;
            if (parse) {
                failed([L.notSaved, parse.error].concat(parse.line ? [fmt(L.atLine, parse.line)] : []));
                return;
            }
            if (!answer || !answer.saved) {
                failed([L.notSaved].concat(errorsOf(answer)));
                return;
            }
            busy = false;
            announce(answer);
            redraw(null);
        }).catch(function () {
            failed([L.saveFailed]);
        });
    }

    /* ----------------------------------------------------------- search */

    function initSearch() {
        searchModal = document.getElementById('ssSearchModal');
        searchInput = document.getElementById('apSearchInput');
        searchResults = document.getElementById('apSearchResults');
        if (!searchModal) {
            return;
        }
        searchModal.addEventListener('shown.bs.modal', function () {
            searchInput.focus();
            searchInput.select();
        });
        searchInput.addEventListener('input', renderSearch);
        searchInput.addEventListener('keydown', function (event) {
            var items = Array.prototype.slice.call(searchResults.querySelectorAll('.ss-search-result'));
            var at = items.indexOf(searchResults.querySelector('.ss-search-result.active'));
            if (event.key === 'ArrowDown' || event.key === 'ArrowUp') {
                event.preventDefault();
                if (!items.length) {
                    return;
                }
                at = event.key === 'ArrowDown' ? Math.min(at + 1, items.length - 1) : Math.max(at - 1, 0);
                pick(items, at);
            } else if (event.key === 'Enter' && at >= 0) {
                event.preventDefault();
                items[at].click();
            }
        });
        searchResults.addEventListener('click', function (event) {
            var result = event.target.closest('.ss-search-result');
            if (!result || !index) {
                return;
            }
            var entry = index[Number(result.getAttribute('data-i'))];
            bootstrap.Modal.getOrCreateInstance(searchModal).hide();
            reveal(entry);
        });
    }

    function openSearch() {
        if (!searchModal || !window.bootstrap) {
            return;
        }
        bootstrap.Modal.getOrCreateInstance(searchModal).show();
        renderSearch();
    }

    function buildIndex() {
        var out = [];
        board.querySelectorAll('[data-ap-pane]').forEach(function (node) {
            var id = node.getAttribute('data-ap-pane');
            var where = text(board.querySelector('[data-ap-nav="' + CSS.escape(id) + '"] .ss-nav-label')) || id;
            var add = function (target, name, path, value, about) {
                var entry = { pane: id, where: where, node: target, name: name, path: path,
                    value: value, about: about };
                entry.hay = [name, path, value, about].join(' ').toLowerCase();
                entry.lowerName = (name + ' ' + path).toLowerCase();
                out.push(entry);
            };
            node.querySelectorAll('tr[data-ap-item]').forEach(function (row) {
                var help = row.querySelector('.sig-more[title], .wb-i[title]');
                add(row, text(row.querySelector('.wb-name')) || row.getAttribute('data-ap-item'),
                    row.getAttribute('data-ap-item'),
                    Array.prototype.slice.call(row.cells, 2).map(reading).filter(Boolean).join(' · '),
                    help ? help.getAttribute('title') : '');
            });
            node.querySelectorAll('.ap-rule[data-ap-item]').forEach(function (rule) {
                add(rule, text(rule.querySelector('.wb-name')), rule.getAttribute('data-ap-item'),
                    Array.prototype.map.call(rule.querySelectorAll('.ap-rule-set'), function (set) {
                        return text(set.querySelector('.ap-rule-k')) + ' '
                            + text(set.querySelector('.ap-set-v, .ap-rule-v'));
                    }).join(' · '),
                    text(rule.querySelector('.ap-rule-desc')));
            });
            node.querySelectorAll('.ap-grade[data-ap-unit]').forEach(function (grade) {
                add(grade, text(grade.querySelector('.ap-grade-badge')) + ' · '
                    + text(grade.querySelector('.ap-grade-m')), grade.getAttribute('data-ap-unit'),
                    '×' + (text(grade.querySelector('.ap-set-v')) || text(grade.querySelector('.ap-grade-v b'))), '');
            });
            node.querySelectorAll('.wb-field[data-ap-unit]').forEach(function (field) {
                // A rule's switch is found as the rule.
                if (field.closest('.ap-rule')) {
                    return;
                }
                // A setting changed in place reads as its value, not as every option its box holds.
                add(field, text(field.querySelector('label')), field.getAttribute('data-ap-unit'),
                    text(field.querySelector('.ap-set-v')) || text(field.querySelector('.wb-inline')),
                    text(field.querySelector('.help')));
            });
            node.querySelectorAll('tr[data-ap-key]').forEach(function (row) {
                var block = row.closest('[data-ap-block]');
                add(row, text(row.cells[0].querySelector('.fw-semibold')) || text(row.cells[0]),
                    (block ? block.getAttribute('data-ap-block') + ' · ' : '')
                    + row.getAttribute('data-ap-key'),
                    Array.prototype.slice.call(row.cells, 1).map(cellValue).filter(Boolean).join(' · '),
                    text(row.cells[0].querySelector('.ap-map-desc')));
            });
            node.querySelectorAll('[data-ap-order-row]').forEach(function (row) {
                var block = row.closest('[data-ap-block]');
                add(row, text(row.querySelector('.fw-semibold')) || row.getAttribute('data-ap-key'),
                    (block ? block.getAttribute('data-ap-block') + ' · ' : '') + row.getAttribute('data-ap-key'),
                    text(row.querySelector('[data-ap-order-rank]')), '');
            });
        });
        return out;
    }

    function renderSearch() {
        var q = searchInput.value.trim().toLowerCase();
        if (!q) {
            searchResults.innerHTML = '<p class="text-muted small p-2 mb-0">' + esc(L.searchHint) + '</p>';
            return;
        }
        if (!index) {
            index = buildIndex();
        }
        var terms = q.split(/\s+/);
        var hits = [];
        index.forEach(function (entry, i) {
            for (var t = 0; t < terms.length; t++) {
                if (entry.hay.indexOf(terms[t]) === -1) {
                    return;
                }
            }
            hits.push({ i: i, score: entry.lowerName.indexOf(terms[0]) !== -1 ? 10 : 0 });
        });
        hits.sort(function (a, b) {
            return b.score - a.score || a.i - b.i;
        });
        if (!hits.length) {
            searchResults.innerHTML = '<p class="text-muted small p-2 mb-0">' + esc(L.searchEmpty) + '</p>';
            return;
        }
        var html = '';
        var last = null;
        hits.slice(0, SEARCH_LIMIT).forEach(function (hit) {
            var entry = index[hit.i];
            if (entry.where !== last) {
                html += (last === null ? '' : '</div>') + '<div class="ss-search-group">'
                    + '<div class="ss-eyebrow px-2 pt-2 pb-1">' + esc(entry.where) + '</div>';
                last = entry.where;
            }
            html += '<button type="button" class="ss-search-result" role="option" aria-selected="false"'
                + ' data-i="' + hit.i + '">'
                + '<span class="min-w-0 flex-grow-1"><span class="d-block fw-semibold">' + esc(entry.name) + '</span>'
                + '<span class="ss-setting-name d-block">' + esc(entry.path) + '</span>'
                + (entry.about ? '<span class="d-block text-muted small text-truncate">' + esc(entry.about) + '</span>' : '')
                + '</span>'
                + (entry.value ? '<span class="ap-search-v">' + esc(entry.value) + '</span>' : '')
                + '</button>';
        });
        html += '</div>';
        if (hits.length > SEARCH_LIMIT) {
            html += '<p class="text-muted small p-2 mb-0">' + esc(fmt(L.searchMore, hits.length - SEARCH_LIMIT)) + '</p>';
        }
        searchResults.innerHTML = html;
        pick(Array.prototype.slice.call(searchResults.querySelectorAll('.ss-search-result')), 0);
    }

    function pick(items, at) {
        items.forEach(function (item, i) {
            item.classList.toggle('active', i === at);
            item.setAttribute('aria-selected', i === at ? 'true' : 'false');
        });
        if (items[at]) {
            items[at].scrollIntoView({ block: 'nearest' });
        }
    }

    function reveal(entry) {
        closeUnit();
        show(entry.pane);
        var node = entry.node;
        if (!node.isConnected) {
            return;
        }
        for (var up = node.parentElement; up; up = up.parentElement) {
            if (up.tagName === 'DETAILS') {
                up.open = true;
            }
        }
        node.scrollIntoView({ block: 'center' });
        flash(node);
    }
})();
