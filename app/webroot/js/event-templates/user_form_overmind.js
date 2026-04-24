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
        }).then((rows) => {
            // /tags/index.json wraps each row in a Tag envelope;
            // strip to {name, colour} so Tom Select can render
            // colour swatches inline without re-walking the envelope.
            return (rows || []).map((row) => {
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
    function attachTagPicker($field) {
        const $select = $field.querySelector('.et-tag-select');
        const $value = $field.querySelector('.et-value');
        if (!$select || !$value) { return; }
        const multiple = $field.getAttribute('data-et-multiple') === '1';
        const restrict = parseRestrictAttr(
            $field, 'data-et-restrict-taxonomies'
        );
        const initial = readInitialCsv($value);

        const ts = new window.TomSelect($select, {
            valueField: 'name',
            labelField: 'name',
            searchField: ['name'],
            options: initial.map((n) => ({name: n})),
            items: initial,
            maxItems: multiple ? null : 1,
            maxOptions: 200,
            create: false,
            plugins: multiple ? ['remove_button'] : [],
            placeholder: multiple
                ? 'Add tag(s)…'
                : 'Pick a tag…',
            preload: 'focus',
            load(query, callback) {
                loadTagCache().then((rows) => {
                    const term = (query || '').toLowerCase();
                    const filtered = rows
                        .filter((r) => tagMatchesRestrict(r.name, restrict))
                        .filter((r) => !term ||
                            r.name.toLowerCase().indexOf(term) !== -1);
                    callback(filtered.slice(0, 200));
                }).catch(() => callback());
            },
            render: {
                option(data, escape) {
                    const swatch = data.colour
                        ? '<span style="display:inline-block;width:10px;' +
                          'height:10px;border:1px solid rgba(0,0,0,0.15);' +
                          'border-radius:2px;margin-right:6px;' +
                          'background:' + escape(data.colour) + ';"></span>'
                        : '';
                    return '<div>' + swatch + escape(data.name) + '</div>';
                }
            },
            onChange(values) {
                const arr = Array.isArray(values)
                    ? values
                    : (values ? [values] : []);
                csvSync($value, arr);
            }
        });
        // Tom Select fires onChange synchronously on init for items
        // already in `items`; nothing to do post-init.
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
