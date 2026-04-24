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

    function collectValues() {
        var values = {};
        qsa(document, '#et-user-form .et-field').forEach(function ($field) {
            var id = $field.getAttribute('data-et-element-id');
            var type = $field.getAttribute('data-et-element-type');
            if (!id || !type) { return; }
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
            var entryVals = qsa($field, '.et-entries > .et-entry').map(function ($entry) {
                var $input = $entry.querySelector('.et-value[data-et-path]');
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

    function init() {
        wireRepeatable();
        wireMandatoryGuard();
        wireSubmit();
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
