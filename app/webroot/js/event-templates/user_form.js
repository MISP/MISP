/*
 * MISP Event Templates — default-theme user form (Phase 2.3).
 *
 * Drives the form a template user fills in to instantiate an event
 * from a template. Scope of this commit: repeatable-field add/remove,
 * client-side mandatory-field guard, form helpers consumed by the
 * next commit's submit flow. The submit button is inert for now — a
 * follow-up commit wires the fetch() + FormData call to
 * /event_templates/instantiate/{id}, plus inline tag / galaxy
 * pickers reusing MISP's existing patterns.
 */
(function () {
    'use strict';

    var cfg = window.ET_USER_FORM_CONFIG || null;
    if (!cfg) { return; }

    function qsa(root, sel) {
        return Array.prototype.slice.call(root.querySelectorAll(sel));
    }

    // -----------------------------------------------------------------
    // Repeatable fields — add / remove entry rows.
    // -----------------------------------------------------------------

    function wireRepeatable() {
        document.addEventListener('click', function (e) {
            var $add = e.target.closest('.et-add-entry');
            if ($add) {
                e.preventDefault();
                addEntry($add.closest('.et-field'));
                return;
            }
            var $rm = e.target.closest('.et-remove-entry');
            if ($rm) {
                e.preventDefault();
                removeEntry($rm.closest('.et-entry'));
                return;
            }
        });
    }

    function addEntry($field) {
        if (!$field) { return; }
        var $entries = $field.querySelector('.et-entries');
        if (!$entries) { return; }
        var $first = $entries.querySelector('.et-entry');
        if (!$first) { return; }
        var $clone = $first.cloneNode(true);
        qsa($clone, 'input.et-value, textarea.et-value, select.et-value').forEach(function ($i) {
            if ($i.type === 'checkbox' || $i.type === 'radio') {
                $i.checked = false;
            } else {
                $i.value = '';
            }
            $i.classList.remove('et-invalid');
        });
        $entries.appendChild($clone);
        refreshRemoveButtons($field);
    }

    function removeEntry($entry) {
        if (!$entry) { return; }
        var $field = $entry.closest('.et-field');
        var $entries = $entry.parentNode;
        // Don't let the user delete the last row — emptying is done by
        // clearing the inputs, not by having zero rows.
        if ($entries.querySelectorAll('.et-entry').length <= 1) {
            qsa($entry, 'input.et-value, textarea.et-value, select.et-value').forEach(function ($i) {
                if ($i.type === 'checkbox' || $i.type === 'radio') {
                    $i.checked = false;
                } else {
                    $i.value = '';
                }
            });
            refreshRemoveButtons($field);
            return;
        }
        $entries.removeChild($entry);
        refreshRemoveButtons($field);
    }

    function refreshRemoveButtons($field) {
        if (!$field) { return; }
        var $entries = qsa($field, '.et-entries > .et-entry');
        // Only show the × button when there's more than one row.
        var visible = $entries.length > 1;
        qsa($field, '.et-entries > .et-entry .et-remove-entry').forEach(function ($b) {
            $b.style.display = visible ? '' : 'none';
        });
    }

    // -----------------------------------------------------------------
    // Mandatory-field guard. Value-collection helpers are exposed on
    // window.ETUserForm so the next commit's submit wiring can pick
    // them up without another pass over the DOM.
    // -----------------------------------------------------------------

    // Tracks base64-encoded file_field uploads; keyed by element id.
    // Populated asynchronously when the user picks files; collectValues()
    // reads directly from here at submit time.
    var fileStaging = {};

    function wireFileInputs() {
        document.addEventListener('change', function (e) {
            var $input = e.target;
            if (!$input.matches || !$input.matches('.et-file-input[data-et-file-target]')) {
                return;
            }
            var id = $input.getAttribute('data-et-file-target');
            if (!id) { return; }
            var files = Array.prototype.slice.call($input.files || []);
            if (!files.length) {
                fileStaging[id] = [];
                renderFileList(id);
                updateSubmitEnabled();
                return;
            }
            fileStaging[id] = files.map(function (f) {
                return {filename: f.name, size: f.size, data: null};
            });
            renderFileList(id);
            updateSubmitEnabled();

            // Read each File into base64 asynchronously; re-render once
            // each completes. A FileReader per file is fine here — users
            // typically pick a handful, and browsers throttle internally.
            files.forEach(function (f, idx) {
                var reader = new FileReader();
                reader.onload = function () {
                    // result is a data URL: "data:...;base64,AAAA..."
                    var b64 = String(reader.result || '').split(',')[1] || '';
                    if (fileStaging[id] && fileStaging[id][idx]) {
                        fileStaging[id][idx].data = b64;
                    }
                    renderFileList(id);
                    updateSubmitEnabled();
                };
                reader.onerror = function () {
                    if (fileStaging[id] && fileStaging[id][idx]) {
                        fileStaging[id][idx].error = 'read failed';
                    }
                    renderFileList(id);
                };
                reader.readAsDataURL(f);
            });
        });
    }

    function renderFileList(elementId) {
        var $list = document.querySelector(
            '[data-et-file-list-for="' + cssEscape(elementId) + '"]'
        );
        if (!$list) { return; }
        $list.innerHTML = '';
        var files = fileStaging[elementId] || [];
        files.forEach(function (f) {
            var $row = document.createElement('div');
            $row.style.padding = '2px 0';
            var status;
            if (f.error) { status = '⚠ ' + f.error; }
            else if (f.data === null) { status = '… reading'; }
            else { status = '✓ ' + humanSize(f.size); }
            $row.textContent = f.filename + ' — ' + status;
            $list.appendChild($row);
        });
    }

    function humanSize(n) {
        if (!n || n <= 0) { return '0 B'; }
        if (n < 1024) { return n + ' B'; }
        if (n < 1024 * 1024) { return (n / 1024).toFixed(1) + ' KiB'; }
        return (n / (1024 * 1024)).toFixed(1) + ' MiB';
    }

    function collectValues() {
        var values = {};
        qsa(document, '#et-user-form .et-field').forEach(function ($field) {
            var id = $field.getAttribute('data-et-element-id');
            var type = $field.getAttribute('data-et-element-type');
            if (!id || !type) { return; }
            if (type === 'file_field') {
                var files = (fileStaging[id] || []).filter(function (f) {
                    return f && f.data;
                }).map(function (f) {
                    return {filename: f.filename, data: f.data};
                });
                if (!files.length) { return; }
                if ($field.getAttribute('data-et-repeatable') === '1') {
                    values[id] = files;
                } else {
                    values[id] = files[0];
                }
                return;
            }
            if (type === 'object_field') {
                var instances = qsa($field, '.et-entries > .et-entry').map(collectEntryRelations);
                // Scalar object if not repeatable, array otherwise.
                if ($field.getAttribute('data-et-repeatable') === '1') {
                    instances = instances.filter(function (o) {
                        return Object.keys(o).length > 0;
                    });
                    if (instances.length) { values[id] = instances; }
                } else if (instances.length) {
                    var obj = instances[0];
                    if (Object.keys(obj).length > 0) { values[id] = obj; }
                }
                return;
            }

            var isCsv = !!$field.querySelector('[data-et-csv="1"]');

            // Attribute / object fields wrap their input(s) in
            // .et-entries > .et-entry; tag / galaxy fields render a
            // single flat input directly under .et-field. Fall back to
            // field-level lookup when the entry wrapper isn't present.
            var $entries = qsa($field, '.et-entries > .et-entry');
            if (!$entries.length) {
                $entries = qsa($field, '.et-value[data-et-path]').map(function ($i) {
                    return $i;
                });
            }
            var entryVals = $entries.map(function ($scope) {
                var $input = $scope.classList && $scope.classList.contains('et-value')
                    ? $scope
                    : $scope.querySelector('.et-value[data-et-path]');
                if (!$input) { return ''; }
                return $input.value;
            });

            if (isCsv) {
                var pieces = [];
                entryVals.forEach(function (v) {
                    (v || '').split(',').forEach(function (p) {
                        p = p.trim();
                        if (p) { pieces.push(p); }
                    });
                });
                if (pieces.length === 1 && $field.getAttribute('data-et-multiple') !== '1') {
                    values[id] = pieces[0];
                } else if (pieces.length > 0) {
                    values[id] = pieces;
                }
                return;
            }

            if ($field.getAttribute('data-et-repeatable') === '1') {
                var filtered = entryVals.map(function (v) { return (v || '').trim(); })
                    .filter(function (v) { return v !== ''; });
                if (filtered.length) { values[id] = filtered; }
            } else {
                var v = (entryVals[0] || '').trim();
                if (v !== '') { values[id] = v; }
            }
        });
        return values;
    }

    function collectEntryRelations($entry) {
        var obj = {};
        qsa($entry, '.et-value[data-et-path]').forEach(function ($i) {
            var path = $i.getAttribute('data-et-path');
            // path is "<id>.<relation>"
            var rel = path.split('.').slice(1).join('.');
            var v = ($i.value || '').trim();
            if (v !== '') { obj[rel] = v; }
        });
        return obj;
    }

    function validateMandatory() {
        var missing = [];
        qsa(document, '#et-user-form .et-field[data-et-mandatory="1"]').forEach(function ($field) {
            $field.classList.remove('et-missing');
            qsa($field, '.et-value').forEach(function ($i) { $i.classList.remove('et-invalid'); });
            var id = $field.getAttribute('data-et-element-id');
            var type = $field.getAttribute('data-et-element-type');
            var label = ($field.querySelector('label') || {}).textContent || id;
            label = label.replace(/\s*\*\s*$/, '').trim();

            var filled = false;
            if (type === 'object_field') {
                // Mandatory object_field: at least one instance with any value.
                qsa($field, '.et-entries > .et-entry').forEach(function ($entry) {
                    qsa($entry, '.et-value[data-et-path]').forEach(function ($i) {
                        if (($i.value || '').trim() !== '') { filled = true; }
                    });
                });
            } else if (type === 'file_field') {
                // Mandatory file_field: at least one fully-read file.
                var stagedFiles = fileStaging[id] || [];
                filled = stagedFiles.some(function (f) {
                    return f && f.data;
                });
            } else {
                qsa($field, '.et-value[data-et-path]').forEach(function ($i) {
                    if (($i.value || '').trim() !== '') { filled = true; }
                });
            }
            if (!filled) {
                missing.push(label || id);
                qsa($field, '.et-value').forEach(function ($i) { $i.classList.add('et-invalid'); });
            }
        });
        return missing;
    }

    function updateSubmitEnabled() {
        if (cfg.isPreview) { return; }
        var $btn = document.getElementById('et-user-form-submit');
        if (!$btn) { return; }
        var missing = validateMandatory();
        if (missing.length === 0) {
            $btn.disabled = false;
            $btn.title = '';
        } else {
            $btn.disabled = true;
            $btn.title = 'Missing: ' + missing.join(', ');
        }
    }

    function wireMandatoryGuard() {
        // Recompute on any input change across the whole form.
        document.addEventListener('input', function (e) {
            if (e.target.closest('#et-user-form')) { updateSubmitEnabled(); }
        });
        document.addEventListener('change', function (e) {
            if (e.target.closest('#et-user-form')) { updateSubmitEnabled(); }
        });
    }

    // -----------------------------------------------------------------
    // Submit flow — POST /event_templates/instantiate/{id}.
    // -----------------------------------------------------------------

    var submitting = false;

    function wireSubmit() {
        var $btn = document.getElementById('et-user-form-submit');
        if (!$btn) { return; }
        $btn.addEventListener('click', function (e) {
            e.preventDefault();
            submit();
        });
    }

    function submit() {
        if (submitting || cfg.isPreview) { return; }
        var $form = document.getElementById('et-user-form');
        var $btn = document.getElementById('et-user-form-submit');
        var $status = document.getElementById('et-user-form-status');
        if (!$form) { return; }

        var missing = validateMandatory();
        if (missing.length > 0) {
            renderErrors(['Missing mandatory fields: ' + missing.join(', ')]);
            return;
        }

        var url = $form.getAttribute('data-et-instantiate-url') ||
            (cfg.baseurl + '/event_templates/instantiate/' + cfg.templateId);
        var body = {values: collectValues()};

        submitting = true;
        renderErrors([]);
        if ($btn) {
            $btn.disabled = true;
            $btn.dataset.etOrigLabel = $btn.dataset.etOrigLabel || $btn.textContent;
            $btn.textContent = 'Creating event…';
        }
        if ($status) { $status.textContent = ''; }

        fetch(url, {
            method: 'POST',
            credentials: 'same-origin',
            headers: {
                'Accept': 'application/json',
                'Content-Type': 'application/json',
                'X-Requested-With': 'XMLHttpRequest'
            },
            body: JSON.stringify(body)
        }).then(function (r) {
            return r.json().then(function (data) {
                return {status: r.status, data: data};
            });
        }).then(function (res) {
            if (res.status >= 200 && res.status < 300 && res.data && res.data.event_id) {
                // Redirect to the newly-created event.
                window.location.href = cfg.baseurl + '/events/view/' + res.data.event_id;
                return;
            }
            submitting = false;
            if ($btn) {
                $btn.disabled = false;
                $btn.textContent = $btn.dataset.etOrigLabel || 'Create event';
            }
            renderErrors(extractErrors(res.data));
            // Re-run mandatory guard in case the user edits a field.
            updateSubmitEnabled();
        }).catch(function (err) {
            submitting = false;
            if ($btn) {
                $btn.disabled = false;
                $btn.textContent = $btn.dataset.etOrigLabel || 'Create event';
            }
            renderErrors(['Network error: ' + (err && err.message ? err.message : err)]);
            updateSubmitEnabled();
        });
    }

    function extractErrors(data) {
        if (!data) { return ['Unknown error.']; }
        if (Array.isArray(data.errors)) { return data.errors; }
        if (data.errors && typeof data.errors === 'object') {
            var out = [];
            Object.keys(data.errors).forEach(function (field) {
                var list = data.errors[field];
                if (Array.isArray(list)) {
                    list.forEach(function (msg) { out.push(field + ': ' + msg); });
                } else {
                    out.push(field + ': ' + list);
                }
            });
            return out;
        }
        if (data.message) { return [data.message]; }
        return ['Unknown error.'];
    }

    function renderErrors(errors) {
        var $panel = document.getElementById('et-user-form-errors');
        if (!$panel) { return; }
        $panel.innerHTML = '';
        if (!errors || !errors.length) { return; }
        var $alert = document.createElement('div');
        $alert.className = 'alert alert-error';
        var $h = document.createElement('strong');
        $h.textContent = 'Could not create event:';
        $alert.appendChild($h);
        var $ul = document.createElement('ul');
        errors.forEach(function (err) {
            var $li = document.createElement('li');
            $li.textContent = String(err);
            $ul.appendChild($li);
        });
        $alert.appendChild($ul);
        $panel.appendChild($alert);
        // Scroll the error into view so the user sees it.
        $panel.scrollIntoView({behavior: 'smooth', block: 'start'});
    }

    // Expose collection helpers + the mandatory check so other page
    // JS (e.g. future preview extensions) can reuse them.
    window.ETUserForm = {
        collectValues: collectValues,
        validateMandatory: validateMandatory,
        submit: submit
    };

    // -----------------------------------------------------------------
    // Tag picker — inline modal reusing MISP's /tags/index.json source.
    //
    // For a typical instance there are thousands of tags, so we fetch
    // on first open and cache the result in-memory for the rest of the
    // page lifetime. When the tag_field element declares
    // restrict_taxonomies, the list is filtered client-side to names
    // whose taxonomy namespace (prefix before ':') matches.
    // -----------------------------------------------------------------

    var tagCache = null;      // full list of {name, colour}
    var tagCacheLoading = null; // promise while the fetch is in flight
    var tagPickerCtx = null;  // {elementId, multiple, restrict}

    function wireTagPicker() {
        document.addEventListener('click', function (e) {
            var $btn = e.target.closest('[data-et-open-tag-picker]');
            if ($btn) {
                e.preventDefault();
                openTagPicker($btn.getAttribute('data-et-open-tag-picker'));
            }
        });
        var $search = document.getElementById('et-tag-picker-search');
        if ($search) {
            $search.addEventListener('input', function () {
                filterTagPicker($search.value);
            });
        }
        var $apply = document.getElementById('et-tag-picker-apply');
        if ($apply) {
            $apply.addEventListener('click', function (e) {
                e.preventDefault();
                applyTagPicker();
            });
        }
    }

    function openTagPicker(elementId) {
        var $field = document.querySelector('.et-field[data-et-element-id="' + cssEscape(elementId) + '"]');
        if (!$field) { return; }
        var restrictJson = $field.getAttribute('data-et-restrict-taxonomies') || '[]';
        var restrict = [];
        try { restrict = JSON.parse(restrictJson); } catch (e) { restrict = []; }
        var multiple = $field.getAttribute('data-et-multiple') === '1';
        var $input = $field.querySelector('input.et-value[data-et-path]');
        var currentCsv = ($input && $input.value) || '';

        tagPickerCtx = {
            elementId: elementId,
            multiple: multiple,
            restrict: restrict.map(function (t) { return String(t).trim(); }).filter(Boolean),
            targetInput: $input,
            preChecked: currentCsv.split(',')
                .map(function (s) { return s.trim(); })
                .filter(Boolean)
        };

        var $hint = document.getElementById('et-tag-picker-restriction-hint');
        if ($hint) {
            if (tagPickerCtx.restrict.length) {
                $hint.textContent =
                    'Restricted to taxonomies: ' + tagPickerCtx.restrict.join(', ');
            } else {
                $hint.textContent = 'Any enabled taxonomy allowed.';
            }
        }
        var $search = document.getElementById('et-tag-picker-search');
        if ($search) { $search.value = ''; }

        var $modal = document.getElementById('et-tag-picker-modal');
        if (window.jQuery && $modal) {
            window.jQuery($modal).modal('show');
            if ($search) { setTimeout(function () { $search.focus(); }, 150); }
        }

        ensureTagCache().then(function () {
            renderTagPickerList();
        }).catch(function (err) {
            var $loading = document.getElementById('et-tag-picker-loading');
            if ($loading) {
                $loading.textContent =
                    'Failed to load tags: ' + (err && err.message ? err.message : err);
            }
        });
    }

    function ensureTagCache() {
        if (tagCache !== null) { return Promise.resolve(); }
        if (tagCacheLoading) { return tagCacheLoading; }
        var $loading = document.getElementById('et-tag-picker-loading');
        var $list = document.getElementById('et-tag-picker-list');
        if ($loading) { $loading.style.display = ''; }
        if ($list) { $list.innerHTML = ''; }

        tagCacheLoading = fetch(cfg.baseurl + '/tags/index.json', {
            method: 'GET',
            credentials: 'same-origin',
            headers: {
                'Accept': 'application/json',
                'X-Requested-With': 'XMLHttpRequest'
            }
        }).then(function (r) {
            if (!r.ok) { throw new Error('HTTP ' + r.status); }
            return r.json();
        }).then(function (data) {
            // /tags/index.json returns { "Tag": [ {id, name, colour, hide_tag, is_galaxy, ...}, ... ] }
            var rows = (data && data.Tag) ? data.Tag : [];
            tagCache = rows.filter(function (t) {
                return !t.hide_tag && !t.is_galaxy;
            }).map(function (t) {
                return {
                    name: (t.name || '').replace(/^\s+/, ''), // leading whitespace slips in sometimes
                    colour: t.colour || '#777'
                };
            });
            tagCache.sort(function (a, b) {
                return a.name.localeCompare(b.name);
            });
            tagCacheLoading = null;
        }).catch(function (err) {
            tagCacheLoading = null;
            throw err;
        });
        return tagCacheLoading;
    }

    function renderTagPickerList() {
        var $loading = document.getElementById('et-tag-picker-loading');
        if ($loading) { $loading.style.display = 'none'; }
        var $list = document.getElementById('et-tag-picker-list');
        if (!$list || !tagPickerCtx) { return; }
        var restrict = tagPickerCtx.restrict;
        var filtered = tagCache.filter(function (t) {
            if (!restrict.length) { return true; }
            // Match tag names whose taxonomy prefix (before ':') is in the list.
            var i = t.name.indexOf(':');
            if (i === -1) { return false; }
            var ns = t.name.slice(0, i);
            return restrict.indexOf(ns) !== -1;
        });
        var preSet = {};
        tagPickerCtx.preChecked.forEach(function (n) { preSet[n] = true; });
        $list.innerHTML = '';
        if (!filtered.length) {
            $list.innerHTML =
                '<div style="padding:20px; text-align:center; color:#888;">' +
                '<em>No tags match this restriction.</em></div>';
            return;
        }
        filtered.forEach(function (t) {
            var $label = document.createElement('label');
            $label.className = 'et-tag-picker-item';
            $label.setAttribute('data-search', t.name.toLowerCase());
            var $cb = document.createElement('input');
            $cb.type = 'checkbox';
            $cb.value = t.name;
            if (preSet[t.name]) { $cb.checked = true; }
            var $swatch = document.createElement('span');
            $swatch.className = 'et-tag-swatch';
            $swatch.style.background = t.colour;
            var $name = document.createElement('span');
            $name.textContent = t.name;
            $label.appendChild($cb);
            $label.appendChild($swatch);
            $label.appendChild($name);
            $list.appendChild($label);
        });
    }

    function filterTagPicker(term) {
        term = (term || '').toLowerCase().trim();
        qsa(document, '#et-tag-picker-list .et-tag-picker-item').forEach(function ($item) {
            if (!term) { $item.style.display = ''; return; }
            var hay = $item.getAttribute('data-search') || '';
            $item.style.display = hay.indexOf(term) === -1 ? 'none' : '';
        });
    }

    function applyTagPicker() {
        if (!tagPickerCtx) { return; }
        var picked = [];
        qsa(document, '#et-tag-picker-list .et-tag-picker-item input[type=checkbox]')
            .forEach(function ($cb) { if ($cb.checked) { picked.push($cb.value); } });
        if (tagPickerCtx.targetInput) {
            if (!tagPickerCtx.multiple && picked.length > 1) {
                // Respect single-tag constraint: keep the first.
                picked = picked.slice(0, 1);
            }
            tagPickerCtx.targetInput.value = picked.join(', ');
            tagPickerCtx.targetInput.dispatchEvent(new Event('input', {bubbles: true}));
        }
        if (window.jQuery) {
            var $modal = document.getElementById('et-tag-picker-modal');
            if ($modal) { window.jQuery($modal).modal('hide'); }
        }
        tagPickerCtx = null;
    }

    // Tiny CSS-escape polyfill for element ids we use in selectors —
    // element ids are already validated against the PRD identifier
    // pattern server-side, but an extra layer doesn't hurt.
    function cssEscape(s) {
        if (window.CSS && window.CSS.escape) { return window.CSS.escape(s); }
        return String(s).replace(/[^a-zA-Z0-9_-]/g, function (c) {
            return '\\' + c;
        });
    }

    function init() {
        wireRepeatable();
        wireMandatoryGuard();
        wireSubmit();
        wireTagPicker();
        wireFileInputs();
        // Initial state — disable submit if any mandatory field is empty.
        qsa(document, '#et-user-form .et-field[data-et-repeatable="1"]').forEach(refreshRemoveButtons);
        updateSubmitEnabled();
    }

    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', init);
    } else {
        init();
    }
})();
