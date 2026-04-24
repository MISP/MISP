/*
 * MISP Event Templates — default-theme builder (Phase 2.2).
 *
 * Vanilla JS state manager for the template definition (PRD §11
 * intentionally skips Alpine.js on the classic theme). The whole state
 * lives on one object; every mutation calls render() which rebuilds
 * the canvas from scratch and re-populates the properties panel via
 * the per-element-type .ctp partials emitted by the shell.
 *
 * This commit covers every element type from PRD §5.1 F1.4
 * (section, text_block, attribute_field, object_field, tag_field,
 * galaxy_field, file_field, object_reference). The next builder commit
 * layers on jQuery UI sortable for reorder, modal pickers for
 * taxonomies/galaxy types, and inline server-side validation from
 * /event_templates/validate_definition.
 */
(function () {
    'use strict';

    var cfg = window.ET_BUILDER_CONFIG || null;
    if (!cfg) { return; }

    // ---------------------------------------------------------------
    // State
    // ---------------------------------------------------------------
    var state = {
        envelope: Object.assign({
            name: '',
            description: '',
            distribution: 0,
            active: 1
        }, cfg.envelope || {}),
        definition: cloneDefinition(cfg.definition || minimalDefinition()),
        selectedId: null,
        errors: [],
        saving: false
    };

    if (!state.definition.uuid) {
        state.definition.uuid = uuidv4();
    }

    // ---------------------------------------------------------------
    // Factories and canvas-summary rules, indexed by element type.
    // ---------------------------------------------------------------
    var ELEMENT_TYPES = {
        section: {
            label: 'Section',
            factory: function (id) {
                return { type: 'section', id: id, label: 'New section', help: '' };
            },
            summary: function (el) { return el.label || '(untitled section)'; }
        },
        text_block: {
            label: 'Text block',
            factory: function (id) {
                return { type: 'text_block', id: id, content: '' };
            },
            summary: function (el) {
                return (el.content || '(empty text block)').slice(0, 80);
            }
        },
        attribute_field: {
            label: 'Attribute',
            factory: function (id) {
                return {
                    type: 'attribute_field', id: id,
                    label: 'New attribute', help: '',
                    mandatory: false, repeatable: false,
                    misp: {
                        category: '', type: '',
                        to_ids_default: false,
                        comment_template: '', default_value: ''
                    }
                };
            },
            summary: function (el) {
                var label = el.label || '(unnamed)';
                var t = (el.misp && el.misp.type) || '?';
                var c = (el.misp && el.misp.category) || '?';
                return label + ' — ' + c + '/' + t;
            }
        },
        object_field: {
            label: 'Object',
            factory: function (id) {
                return {
                    type: 'object_field', id: id,
                    label: 'New object', help: '',
                    mandatory: false, repeatable: false,
                    object_template: { uuid: '', name: '', pinned_version: 0 },
                    relations: []
                };
            },
            summary: function (el) {
                var label = el.label || '(unnamed)';
                var ot = el.object_template || {};
                return label + ' — ' + (ot.name || 'no template') +
                    (ot.pinned_version ? ' v' + ot.pinned_version : '');
            }
        },
        tag_field: {
            label: 'Tag',
            factory: function (id) {
                return {
                    type: 'tag_field', id: id,
                    label: 'New tag field', help: '',
                    mandatory: false, multiple: true,
                    restrict_taxonomies: []
                };
            },
            summary: function (el) { return el.label || '(unnamed)'; }
        },
        galaxy_field: {
            label: 'Galaxy',
            factory: function (id) {
                return {
                    type: 'galaxy_field', id: id,
                    label: 'New galaxy field', help: '',
                    mandatory: false, multiple: false,
                    restrict_galaxy_types: []
                };
            },
            summary: function (el) { return el.label || '(unnamed)'; }
        },
        file_field: {
            label: 'File',
            factory: function (id) {
                return {
                    type: 'file_field', id: id,
                    label: 'New file field', help: '',
                    mandatory: false, repeatable: false,
                    as: 'attachment'
                };
            },
            summary: function (el) {
                return (el.label || '(unnamed)') + ' — as ' + (el.as || 'attachment');
            }
        },
        object_reference: {
            label: 'Reference',
            factory: function (id) {
                return {
                    type: 'object_reference', id: id,
                    from: '', to: '', relationship_type: '', comment: ''
                };
            },
            summary: function (el) {
                return (el.from || '?') + ' → ' + (el.to || '?') +
                    ' (' + (el.relationship_type || '?') + ')';
            }
        }
    };

    // ---------------------------------------------------------------
    // Helpers
    // ---------------------------------------------------------------

    function minimalDefinition() {
        return {
            schema_version: 1,
            uuid: uuidv4(),
            name: '',
            event_defaults: {distribution: 0},
            structure: []
        };
    }

    function cloneDefinition(d) { return JSON.parse(JSON.stringify(d)); }

    function uuidv4() {
        if (window.crypto && window.crypto.randomUUID) {
            return window.crypto.randomUUID();
        }
        return 'xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx'.replace(/[xy]/g, function (c) {
            var r = (Math.random() * 16) | 0;
            var v = c === 'x' ? r : (r & 0x3) | 0x8;
            return v.toString(16);
        });
    }

    function newElementId(type) {
        var prefix = {
            section: 'section', text_block: 'text',
            attribute_field: 'attr', object_field: 'obj',
            tag_field: 'tags', galaxy_field: 'gal',
            file_field: 'file', object_reference: 'ref'
        }[type] || 'el';
        var existing = {};
        state.definition.structure.forEach(function (el) {
            if (el && el.id) { existing[el.id] = true; }
        });
        var n = state.definition.structure.length + 1;
        var candidate;
        do {
            candidate = prefix + '_' + n;
            n += 1;
        } while (existing[candidate]);
        return candidate;
    }

    // Walks a dotted path like "misp.category" on a plain object.
    function getDeep(obj, path) {
        var parts = path.split('.');
        var cur = obj;
        for (var i = 0; i < parts.length; i += 1) {
            if (cur == null || typeof cur !== 'object') { return undefined; }
            cur = cur[parts[i]];
        }
        return cur;
    }

    function setDeep(obj, path, value) {
        var parts = path.split('.');
        var cur = obj;
        for (var i = 0; i < parts.length - 1; i += 1) {
            if (cur[parts[i]] == null || typeof cur[parts[i]] !== 'object') {
                cur[parts[i]] = {};
            }
            cur = cur[parts[i]];
        }
        cur[parts[parts.length - 1]] = value;
    }

    // ---------------------------------------------------------------
    // Mutations
    // ---------------------------------------------------------------

    function addElement(type) {
        var spec = ELEMENT_TYPES[type];
        if (!spec) { return; }
        var el = spec.factory(newElementId(type));
        state.definition.structure.push(el);
        state.selectedId = el.id;
        render();
    }

    function removeElement(id) {
        state.definition.structure = state.definition.structure.filter(function (el) {
            return el.id !== id;
        });
        if (state.selectedId === id) { state.selectedId = null; }
        render();
    }

    function selectElement(id) {
        state.selectedId = id;
        render();
    }

    function setElementFieldDeep(id, path, value) {
        state.definition.structure = state.definition.structure.map(function (el) {
            if (el.id !== id) { return el; }
            var next = JSON.parse(JSON.stringify(el));
            setDeep(next, path, value);
            return next;
        });
        // Only re-render the canvas summary; the properties pane inputs
        // are already up to date (the user just typed into them).
        renderCanvas();
    }

    function setEnvelopeField(field, value) {
        state.envelope[field] = value;
    }

    function findElement(id) {
        for (var i = 0; i < state.definition.structure.length; i += 1) {
            if (state.definition.structure[i].id === id) {
                return state.definition.structure[i];
            }
        }
        return null;
    }

    // ---------------------------------------------------------------
    // Save
    // ---------------------------------------------------------------

    function save() {
        if (state.saving) { return; }
        state.saving = true;
        state.errors = [];

        // The PRD §7 schema requires the definition to carry its own
        // `name` (minLength 1) alongside the row-level envelope `name`.
        // Mirror at save time so the user only has one input to fill.
        state.definition.name = state.envelope.name;
        if (state.envelope.description) {
            state.definition.description = state.envelope.description;
        } else {
            delete state.definition.description;
        }

        var body = {
            EventTemplate: {
                name: state.envelope.name,
                description: state.envelope.description,
                distribution: Number(state.envelope.distribution) || 0,
                active: state.envelope.active ? 1 : 0,
                definition: state.definition
            }
        };

        render();

        fetch(cfg.submitUrl, {
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
            state.saving = false;
            if (res.status >= 200 && res.status < 300 && res.data.EventTemplate) {
                window.location.href = cfg.baseurl + '/event_templates/view/' + res.data.EventTemplate.id;
                return;
            }
            state.errors = extractErrors(res.data);
            render();
        }).catch(function (err) {
            state.saving = false;
            state.errors = ['Network error while saving: ' + (err && err.message ? err.message : err)];
            render();
        });
    }

    function validate() {
        // Mirror envelope name/description into the definition the same
        // way save() does, so the user-entered envelope name doesn't
        // trigger a false-positive "name must be at least 1 char" from
        // the schema on every Validate click.
        var probe = JSON.parse(JSON.stringify(state.definition));
        probe.name = state.envelope.name;
        if (state.envelope.description) {
            probe.description = state.envelope.description;
        }

        var $status = document.getElementById('et-validate-status');
        if ($status) {
            $status.textContent = 'Validating…';
            $status.className = '';
        }

        fetch(cfg.baseurl + '/event_templates/validate_definition', {
            method: 'POST',
            credentials: 'same-origin',
            headers: {
                'Accept': 'application/json',
                'Content-Type': 'application/json',
                'X-Requested-With': 'XMLHttpRequest'
            },
            body: JSON.stringify(probe)
        }).then(function (r) {
            return r.json().then(function (data) {
                return {status: r.status, data: data};
            });
        }).then(function (res) {
            var valid = res.data && res.data.valid;
            var errs = (res.data && Array.isArray(res.data.errors))
                ? res.data.errors
                : [];
            if (valid) {
                state.errors = [];
                if ($status) {
                    $status.textContent = '✓ Definition is valid.';
                    $status.className = 'text-success';
                }
            } else {
                state.errors = errs.length ? errs : ['Definition is invalid.'];
                if ($status) {
                    $status.textContent = '✗ ' + state.errors.length +
                        (state.errors.length === 1 ? ' error' : ' errors');
                    $status.className = 'text-error';
                }
            }
            renderErrors();
        }).catch(function (err) {
            state.errors = ['Validation request failed: ' + (err && err.message ? err.message : err)];
            if ($status) {
                $status.textContent = '✗ network error';
                $status.className = 'text-error';
            }
            renderErrors();
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

    // ---------------------------------------------------------------
    // Rendering
    // ---------------------------------------------------------------

    function render() {
        renderEnvelope();
        renderCanvas();
        renderProperties();
        renderErrors();
        renderSaveButton();
    }

    function renderEnvelope() {
        var $n = document.getElementById('et-envelope-name');
        var $d = document.getElementById('et-envelope-description');
        var $dist = document.getElementById('et-envelope-distribution');
        var $a = document.getElementById('et-envelope-active');
        if ($n && document.activeElement !== $n) { $n.value = state.envelope.name || ''; }
        if ($d && document.activeElement !== $d) { $d.value = state.envelope.description || ''; }
        if ($dist) { $dist.value = String(state.envelope.distribution || 0); }
        if ($a) { $a.checked = !!state.envelope.active; }
    }

    function renderCanvas() {
        var $canvas = document.getElementById('et-canvas');
        if (!$canvas) { return; }
        // jQuery UI sortable attaches handlers to the canvas's current
        // children; rebuilding the DOM underneath it leaves stale
        // references. Tear down before the rebuild, re-init after.
        teardownSortable($canvas);
        $canvas.innerHTML = '';
        if (!state.definition.structure.length) {
            $canvas.appendChild(h('div', {'class': 'et-empty'},
                'No elements yet. Use the palette on the left to add one.'
            ));
            return;
        }
        state.definition.structure.forEach(function (el) {
            $canvas.appendChild(renderCanvasElement(el));
        });
        initSortable($canvas);
    }

    function teardownSortable($canvas) {
        if (!window.jQuery) { return; }
        var $j = window.jQuery($canvas);
        if ($j.hasClass('ui-sortable') || $j.data('ui-sortable')) {
            try { $j.sortable('destroy'); } catch (e) { /* noop */ }
        }
    }

    function initSortable($canvas) {
        if (!window.jQuery || !window.jQuery.fn || !window.jQuery.fn.sortable) {
            return; // jQuery UI not loaded (shouldn't happen on the add/edit views)
        }
        window.jQuery($canvas).sortable({
            items: '.et-canvas-element',
            handle: '.et-drag-handle',
            placeholder: 'et-canvas-element et-sortable-placeholder',
            forcePlaceholderSize: true,
            tolerance: 'pointer',
            update: function () {
                // Rebuild structure from DOM order. selectedId is preserved
                // because we key by id, not index.
                var byId = {};
                state.definition.structure.forEach(function (el) {
                    byId[el.id] = el;
                });
                var reordered = [];
                window.jQuery($canvas).find('.et-canvas-element').each(function () {
                    var id = this.getAttribute('data-element-id');
                    if (byId[id]) { reordered.push(byId[id]); }
                });
                // Only commit if the set of ids matches (guard against
                // any stray DOM nodes sortable might have injected).
                if (reordered.length === state.definition.structure.length) {
                    state.definition.structure = reordered;
                    // A full renderCanvas() would destroy/rebuild DOM
                    // mid-sortable-callback and corrupt jQuery UI state;
                    // the DOM already reflects the new order, so we just
                    // refresh selection highlights if needed.
                    refreshSelectionHighlight();
                }
            }
        });
    }

    function refreshSelectionHighlight() {
        var $canvas = document.getElementById('et-canvas');
        if (!$canvas) { return; }
        $canvas.querySelectorAll('.et-canvas-element').forEach(function ($el) {
            var id = $el.getAttribute('data-element-id');
            if (id === state.selectedId) {
                $el.classList.add('selected');
            } else {
                $el.classList.remove('selected');
            }
        });
    }

    function renderCanvasElement(el) {
        var selected = el.id === state.selectedId;
        var spec = ELEMENT_TYPES[el.type] || {};
        var $row = h('div', {
            'class': 'et-canvas-element' + (selected ? ' selected' : ''),
            'data-element-id': el.id
        });
        $row.addEventListener('click', function (e) {
            if (e.target.closest('.et-delete-button')) { return; }
            if (e.target.closest('.et-drag-handle')) { return; }
            selectElement(el.id);
        });
        var summary = spec.summary ? spec.summary(el) : el.id;
        $row.appendChild(h('div', {'class': 'et-element-header'},
            h('span', {
                'class': 'et-drag-handle',
                'title': 'Drag to reorder'
            }, '☰'),
            h('span', {'class': 'et-element-type-badge'}, spec.label || el.type),
            h('span', {'class': 'et-element-summary'}, summary),
            h('code', {'class': 'et-element-id'}, el.id),
            renderDeleteButton(el.id)
        ));
        return $row;
    }

    function renderDeleteButton(id) {
        var $b = h('button', {
            'type': 'button',
            'class': 'btn btn-mini btn-danger et-delete-button',
            'title': 'Delete element'
        }, '×');
        $b.addEventListener('click', function (e) {
            e.stopPropagation();
            if (window.confirm('Remove this element?')) { removeElement(id); }
        });
        return $b;
    }

    function renderProperties() {
        var $panes = document.querySelectorAll('[data-et-properties-for]');
        $panes.forEach(function ($p) { $p.style.display = 'none'; });
        var $empty = document.getElementById('et-properties-empty');

        if (!state.selectedId) {
            if ($empty) { $empty.style.display = ''; }
            return;
        }
        var el = findElement(state.selectedId);
        if (!el) {
            state.selectedId = null;
            if ($empty) { $empty.style.display = ''; }
            return;
        }
        if ($empty) { $empty.style.display = 'none'; }

        var $pane = document.querySelector('[data-et-properties-for="' + el.type + '"]');
        if (!$pane) { return; }
        $pane.style.display = '';
        populatePane($pane, el);
    }

    function populatePane($pane, el) {
        // Straight data-et-field inputs: scalar / boolean mirror.
        $pane.querySelectorAll('[data-et-field]').forEach(function ($i) {
            var field = $i.getAttribute('data-et-field');
            var v = getDeep(el, field);
            if ($i.tagName === 'SELECT') {
                $i.value = v == null ? '' : String(v);
            } else if ($i.type === 'checkbox') {
                $i.checked = !!v;
            } else {
                if (document.activeElement === $i) { return; }
                $i.value = v == null ? '' : String(v);
            }
        });

        // CSV fields: array <-> "a, b, c"
        $pane.querySelectorAll('[data-et-field-csv]').forEach(function ($i) {
            if (document.activeElement === $i) { return; }
            var field = $i.getAttribute('data-et-field-csv');
            var v = getDeep(el, field);
            $i.value = Array.isArray(v) ? v.join(', ') : '';
        });

        // Per-type refinements
        if (el.type === 'attribute_field') {
            refreshAttributeTypeOptions($pane, el);
        }
        if (el.type === 'object_field') {
            refreshObjectTemplateDisplay($pane, el);
        }
        if (el.type === 'object_reference') {
            refreshObjectFieldSelects($pane, el);
        }
    }

    function refreshAttributeTypeOptions($pane, el) {
        var $sel = $pane.querySelector('[data-et-field="misp.type"]');
        if (!$sel) { return; }
        var cat = (el.misp && el.misp.category) || '';
        var types = (cfg.attrCategories && cfg.attrCategories[cat]) || [];
        var current = (el.misp && el.misp.type) || '';
        $sel.innerHTML = '';
        var $opt = document.createElement('option');
        $opt.value = '';
        $opt.textContent = cat ? '— select a type —' : '— select a category first —';
        $sel.appendChild($opt);
        types.forEach(function (t) {
            var $o = document.createElement('option');
            $o.value = t;
            $o.textContent = t;
            if (t === current) { $o.selected = true; }
            $sel.appendChild($o);
        });
        // If current type is no longer valid for the new category, clear it.
        if (current && types.indexOf(current) === -1) {
            setElementFieldDeep(el.id, 'misp.type', '');
        }
    }

    function refreshObjectTemplateDisplay($pane, el) {
        var ot = el.object_template || {};
        var $name = $pane.querySelector('[data-et-ot-display="name"]');
        var $ver = $pane.querySelector('[data-et-ot-display="version"]');
        var $meta = $pane.querySelector('[data-et-ot-display="meta"]');
        if ($name) {
            if (ot.name) {
                $name.textContent = ot.name;
            } else {
                $name.innerHTML = '<em>(none selected)</em>';
            }
        }
        if ($ver) {
            $ver.textContent = ot.pinned_version ? ('v' + ot.pinned_version) : '';
        }
        if ($meta) {
            // Meta isn't persisted in state, but we can resolve it via
            // cfg.objectTemplates when a uuid is set.
            if (ot.uuid && Array.isArray(cfg.objectTemplates)) {
                for (var i = 0; i < cfg.objectTemplates.length; i += 1) {
                    if (cfg.objectTemplates[i].uuid === ot.uuid) {
                        $meta.textContent = cfg.objectTemplates[i].meta_category || '';
                        return;
                    }
                }
            }
            $meta.textContent = '';
        }
    }

    function refreshObjectFieldSelects($pane, el) {
        var existing = state.definition.structure
            .filter(function (e) { return e.type === 'object_field'; })
            .map(function (e) {
                return {id: e.id, label: e.label || e.id};
            });
        $pane.querySelectorAll('[data-et-object-field-select]').forEach(function ($sel) {
            var field = $sel.getAttribute('data-et-field');
            var current = getDeep(el, field) || '';
            $sel.innerHTML = '';
            var $opt = document.createElement('option');
            $opt.value = '';
            $opt.textContent = '— select —';
            $sel.appendChild($opt);
            existing.forEach(function (of) {
                var $o = document.createElement('option');
                $o.value = of.id;
                $o.textContent = of.label + ' (' + of.id + ')';
                if (of.id === current) { $o.selected = true; }
                $sel.appendChild($o);
            });
            if (current && !existing.some(function (of) { return of.id === current; })) {
                // Still preserve the current value even if it doesn't exist
                // in the list (e.g. the user deleted the target object_field).
                var $stale = document.createElement('option');
                $stale.value = current;
                $stale.textContent = current + ' (missing)';
                $stale.selected = true;
                $sel.appendChild($stale);
            }
        });
    }

    // ---------------------------------------------------------------
    // Object-template picker modal — searchable list of installed OTs.
    // ---------------------------------------------------------------

    function wireObjectTemplatePicker() {
        // Open buttons live inside hidden property panes; use event
        // delegation on the document so they pick up clicks regardless
        // of pane visibility when wire() ran.
        document.addEventListener('click', function (e) {
            var $btn = e.target.closest('[data-et-open-ot-picker]');
            if ($btn) {
                e.preventDefault();
                openObjectTemplatePicker();
            }
            var $item = e.target.closest('#et-ot-picker-modal .et-ot-picker-item');
            if ($item) {
                e.preventDefault();
                pickObjectTemplate($item);
            }
        });

        var $search = document.getElementById('et-ot-picker-search');
        if ($search) {
            $search.addEventListener('input', function () {
                filterObjectTemplateList($search.value);
            });
        }
    }

    function openObjectTemplatePicker() {
        if (!state.selectedId) { return; }
        var el = findElement(state.selectedId);
        if (!el || el.type !== 'object_field') { return; }
        var $modal = document.getElementById('et-ot-picker-modal');
        var $search = document.getElementById('et-ot-picker-search');
        if ($search) {
            $search.value = '';
            filterObjectTemplateList('');
        }
        if (window.jQuery && $modal) {
            window.jQuery($modal).modal('show');
            if ($search) {
                setTimeout(function () { $search.focus(); }, 150);
            }
        }
    }

    function filterObjectTemplateList(term) {
        term = (term || '').toLowerCase().trim();
        var $items = document.querySelectorAll('#et-ot-picker-list .et-ot-picker-item');
        $items.forEach(function ($item) {
            if (!term) {
                $item.style.display = '';
                return;
            }
            var hay = $item.getAttribute('data-search') || '';
            $item.style.display = hay.indexOf(term) === -1 ? 'none' : '';
        });
    }

    function pickObjectTemplate($item) {
        if (!state.selectedId) { return; }
        var uuid = $item.getAttribute('data-uuid') || '';
        var name = $item.getAttribute('data-name') || '';
        var version = parseInt($item.getAttribute('data-version'), 10) || 0;
        setElementFieldDeep(state.selectedId, 'object_template.uuid', uuid);
        setElementFieldDeep(state.selectedId, 'object_template.name', name);
        setElementFieldDeep(state.selectedId, 'object_template.pinned_version', version);
        if (window.jQuery) {
            var $modal = document.getElementById('et-ot-picker-modal');
            if ($modal) { window.jQuery($modal).modal('hide'); }
        }
        // Refresh the current pane so the readonly display reflects the new pick.
        renderProperties();
    }

    function renderErrors() {
        var $panel = document.getElementById('et-errors');
        if (!$panel) { return; }
        $panel.innerHTML = '';
        if (!state.errors.length) { return; }
        var $ul = h('ul');
        state.errors.forEach(function (err) {
            $ul.appendChild(h('li', {}, String(err)));
        });
        $panel.appendChild(h('div', {'class': 'alert alert-error'},
            h('strong', {}, 'Could not save:'),
            $ul
        ));
    }

    var savedButtonLabel = null;
    function renderSaveButton() {
        var $btn = document.getElementById('et-save-button');
        if (!$btn) { return; }
        if (savedButtonLabel === null) { savedButtonLabel = $btn.textContent; }
        $btn.disabled = !!state.saving;
        $btn.textContent = state.saving ? 'Saving…' : savedButtonLabel;
    }

    // ---------------------------------------------------------------
    // Tiny DOM helper
    // ---------------------------------------------------------------

    function h(tag, attrs) {
        var el = document.createElement(tag);
        if (attrs) {
            Object.keys(attrs).forEach(function (k) {
                var v = attrs[k];
                if (v === null || v === undefined || v === false) { return; }
                el.setAttribute(k, v);
            });
        }
        for (var i = 2; i < arguments.length; i += 1) {
            var child = arguments[i];
            if (child === null || child === undefined || child === false) { continue; }
            if (typeof child === 'string' || typeof child === 'number') {
                el.appendChild(document.createTextNode(String(child)));
            } else {
                el.appendChild(child);
            }
        }
        return el;
    }

    // ---------------------------------------------------------------
    // Wiring — one-time; all property-pane inputs route through here.
    // ---------------------------------------------------------------

    function wire() {
        var bindEnvelope = function (id, field, event) {
            var $el = document.getElementById(id);
            if (!$el) { return; }
            $el.addEventListener(event || 'input', function () {
                var v = $el.type === 'checkbox' ? $el.checked : $el.value;
                setEnvelopeField(field, v);
            });
        };
        bindEnvelope('et-envelope-name', 'name', 'input');
        bindEnvelope('et-envelope-description', 'description', 'input');
        bindEnvelope('et-envelope-distribution', 'distribution', 'change');
        bindEnvelope('et-envelope-active', 'active', 'change');

        document.querySelectorAll('[data-et-add]').forEach(function ($btn) {
            $btn.addEventListener('click', function () {
                addElement($btn.getAttribute('data-et-add'));
            });
        });

        // Generic data-et-field inputs: commit on `change` (blur) so
        // typing into text inputs doesn't cause focus loss via re-render.
        document.querySelectorAll('[data-et-properties-for] [data-et-field]')
            .forEach(function ($i) {
                $i.addEventListener('change', function () {
                    if (!state.selectedId) { return; }
                    var field = $i.getAttribute('data-et-field');
                    var v = $i.type === 'checkbox' ? $i.checked : $i.value;
                    setElementFieldDeep(state.selectedId, field, v);
                    // Attribute category change also re-filters the type
                    // options list. Re-render the pane so the second
                    // dropdown reflects the new category.
                    if (field === 'misp.category') {
                        renderProperties();
                    }
                });
            });

        // CSV fields: commit as array on change.
        document.querySelectorAll('[data-et-properties-for] [data-et-field-csv]')
            .forEach(function ($i) {
                $i.addEventListener('change', function () {
                    if (!state.selectedId) { return; }
                    var field = $i.getAttribute('data-et-field-csv');
                    var arr = $i.value.split(',')
                        .map(function (s) { return s.trim(); })
                        .filter(function (s) { return s.length > 0; });
                    setElementFieldDeep(state.selectedId, field, arr);
                });
            });

        wireObjectTemplatePicker();

        var $save = document.getElementById('et-save-button');
        if ($save) {
            $save.addEventListener('click', function (e) {
                e.preventDefault();
                save();
            });
        }
        var $validate = document.getElementById('et-validate-button');
        if ($validate) {
            $validate.addEventListener('click', function (e) {
                e.preventDefault();
                validate();
            });
        }
    }

    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', function () {
            wire();
            render();
        });
    } else {
        wire();
        render();
    }
})();
