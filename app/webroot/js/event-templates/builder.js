/*
 * MISP Event Templates — default-theme builder (Phase 2.2).
 *
 * Vanilla JS state manager for the template definition (PRD §11
 * intentionally skips Alpine.js on the classic theme). The whole state
 * lives on one object; every mutation calls render() which rebuilds
 * the canvas and properties panel from scratch. This is deliberately
 * simple — the builder is not in a hot path, and imperative rerender
 * keeps the code debuggable without a framework.
 *
 * This commit ships the scaffold with section + text_block elements
 * only. Commit 5 of the Phase-2 plan adds the other element types and
 * per-element-type property partials; commit 6 adds drag-reorder,
 * pickers, and inline server-side validation.
 */
(function () {
    'use strict';

    var cfg = window.ET_BUILDER_CONFIG || null;
    if (!cfg) {
        return; // builder markup not on the page
    }

    // ---------------------------------------------------------------
    // State
    // ---------------------------------------------------------------
    // Canonical shape matches the PRD §7 JSON schema. `envelope` holds
    // the row-level fields the controller expects alongside the
    // `definition` (name, description, distribution, active).
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

    function minimalDefinition() {
        return {
            schema_version: 1,
            uuid: uuidv4(),
            name: '',
            event_defaults: {distribution: 0},
            structure: []
        };
    }

    function cloneDefinition(d) {
        return JSON.parse(JSON.stringify(d));
    }

    function uuidv4() {
        // RFC4122 v4, good enough for client-side id seeds (the server
        // regenerates the row uuid on save anyway via the model).
        if (window.crypto && window.crypto.randomUUID) {
            return window.crypto.randomUUID();
        }
        return 'xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx'.replace(/[xy]/g, function (c) {
            var r = (Math.random() * 16) | 0;
            var v = c === 'x' ? r : (r & 0x3) | 0x8;
            return v.toString(16);
        });
    }

    // Generate a fresh stable element id unique within state.definition.structure.
    function newElementId(prefix) {
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

    // ---------------------------------------------------------------
    // Mutations
    // ---------------------------------------------------------------

    function addElement(type) {
        var el;
        if (type === 'section') {
            el = {
                type: 'section',
                id: newElementId('section'),
                label: 'New section',
                help: ''
            };
        } else if (type === 'text_block') {
            el = {
                type: 'text_block',
                id: newElementId('text'),
                content: ''
            };
        } else {
            return;
        }
        state.definition.structure.push(el);
        state.selectedId = el.id;
        render();
    }

    function removeElement(id) {
        state.definition.structure = state.definition.structure.filter(function (el) {
            return el.id !== id;
        });
        if (state.selectedId === id) {
            state.selectedId = null;
        }
        render();
    }

    function selectElement(id) {
        state.selectedId = id;
        render();
    }

    function setElementField(id, field, value) {
        state.definition.structure = state.definition.structure.map(function (el) {
            if (el.id !== id) { return el; }
            var next = Object.assign({}, el);
            next[field] = value;
            return next;
        });
        render();
    }

    function setEnvelopeField(field, value) {
        state.envelope[field] = value;
        // Don't rerender on every keystroke — just update state. The
        // next render() (on add/select/etc) will pick up the new value.
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

        // The server expects envelope fields + a nested `definition`.
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
                var id = res.data.EventTemplate.id;
                window.location.href = cfg.baseurl + '/event_templates/view/' + id;
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

    // Cached once at wire() time so we can localise the initial label via
    // PHP __() and still restore it correctly after a save failure.
    var savedButtonLabel = null;

    function renderSaveButton() {
        var $btn = document.getElementById('et-save-button');
        if (!$btn) { return; }
        if (savedButtonLabel === null) {
            savedButtonLabel = $btn.textContent;
        }
        if (state.saving) {
            $btn.disabled = true;
            $btn.textContent = 'Saving…';
        } else {
            $btn.disabled = false;
            $btn.textContent = savedButtonLabel;
        }
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
        $canvas.innerHTML = '';
        if (!state.definition.structure.length) {
            $canvas.appendChild(h('div', {'class': 'et-empty'},
                'No elements yet. Use the palette on the left to add a section or text block.'
            ));
            return;
        }
        state.definition.structure.forEach(function (el) {
            $canvas.appendChild(renderCanvasElement(el));
        });
    }

    function renderCanvasElement(el) {
        var selected = el.id === state.selectedId;
        var $row = h('div', {
            'class': 'et-canvas-element' + (selected ? ' selected' : ''),
            'data-element-id': el.id
        });
        $row.addEventListener('click', function (e) {
            if (e.target.closest('.et-delete-button')) { return; }
            selectElement(el.id);
        });

        var typeLabel = ({
            section: 'Section',
            text_block: 'Text block'
        })[el.type] || el.type;

        var summary;
        if (el.type === 'section') {
            summary = el.label || '(untitled section)';
        } else if (el.type === 'text_block') {
            summary = (el.content || '(empty text block)').slice(0, 80);
        } else {
            summary = el.id;
        }

        $row.appendChild(h('div', {'class': 'et-element-header'},
            h('span', {'class': 'et-element-type-badge'}, typeLabel),
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
        var $panel = document.getElementById('et-properties');
        if (!$panel) { return; }
        $panel.innerHTML = '';
        if (!state.selectedId) {
            $panel.appendChild(h('div', {'class': 'et-empty'},
                'Select an element in the canvas to edit its properties.'
            ));
            return;
        }
        var el = findElement(state.selectedId);
        if (!el) {
            state.selectedId = null;
            return;
        }
        $panel.appendChild(h('h4', {}, 'Properties — ' + el.type));
        $panel.appendChild(propField('Stable id', el.id, {disabled: true}));
        if (el.type === 'section') {
            $panel.appendChild(propField('Label', el.label || '', {
                onChange: function (v) { setElementField(el.id, 'label', v); }
            }));
            $panel.appendChild(propField('Help text', el.help || '', {
                onChange: function (v) { setElementField(el.id, 'help', v); },
                multiline: true
            }));
        } else if (el.type === 'text_block') {
            $panel.appendChild(propField('Content (Markdown)', el.content || '', {
                onChange: function (v) { setElementField(el.id, 'content', v); },
                multiline: true,
                rows: 6
            }));
        }
    }

    function propField(label, value, opts) {
        opts = opts || {};
        var id = 'et-prop-' + Math.random().toString(36).slice(2, 8);
        var $label = h('label', {'for': id}, label);
        var $input;
        if (opts.multiline) {
            $input = h('textarea', {
                'id': id,
                'class': 'input-block-level',
                'rows': String(opts.rows || 3),
                'disabled': opts.disabled ? 'disabled' : null
            });
            $input.value = value;
        } else {
            $input = h('input', {
                'id': id,
                'type': 'text',
                'class': 'input-block-level',
                'disabled': opts.disabled ? 'disabled' : null
            });
            $input.value = value;
        }
        if (opts.onChange) {
            // `change` fires on blur — the whole canvas re-renders then,
            // avoiding mid-typing steals of focus.
            $input.addEventListener('change', function () {
                opts.onChange($input.value);
            });
        }
        return h('div', {'class': 'control-group'},
            $label,
            h('div', {'class': 'controls'}, $input)
        );
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

    // ---------------------------------------------------------------
    // Tiny DOM helper (keeps the builder lib-free)
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
    // Wiring
    // ---------------------------------------------------------------

    function wire() {
        var bind = function (id, field, event) {
            var $el = document.getElementById(id);
            if (!$el) { return; }
            $el.addEventListener(event || 'input', function () {
                var v = $el.type === 'checkbox' ? $el.checked : $el.value;
                setEnvelopeField(field, v);
            });
        };
        bind('et-envelope-name', 'name', 'input');
        bind('et-envelope-description', 'description', 'input');
        bind('et-envelope-distribution', 'distribution', 'change');
        bind('et-envelope-active', 'active', 'change');

        document.querySelectorAll('[data-et-add]').forEach(function ($btn) {
            $btn.addEventListener('click', function () {
                addElement($btn.getAttribute('data-et-add'));
            });
        });

        var $save = document.getElementById('et-save-button');
        if ($save) {
            $save.addEventListener('click', function (e) {
                e.preventDefault();
                save();
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
