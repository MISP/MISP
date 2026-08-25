/*
 * MISP Event Templates — Overmind-theme builder (Phase 3.3.1).
 *
 * Alpine.js component owning the builder state. Data shape and the
 * save/validate request bodies are byte-identical to the default-theme
 * builder.js so the backend (controller + EventTemplateValidator +
 * EventTemplateInstantiator) is unchanged. Differences from builder.js:
 *
 *   - State + mutations + computed values live on a single Alpine
 *     component (`etBuilder`). Markup binds via x-model / :value /
 *     @input / @click, no manual DOM scrubbing.
 *   - jQuery UI sortable is gone. Phase 3.3.2 will hook SortableJS into
 *     the canvas.
 *   - The two BS5 modal pickers (object template + multipicker) are
 *     opened via window.bootstrap.Modal. Phase 3.3.3 will replace them
 *     with Tom Select dropdowns.
 *   - Inline error surfacing per element lands in Phase 3.3.4.
 */
(function () {
    'use strict';

    // The shell.ctp emits this asset BEFORE alpine.min.js (so we can
    // register our component factory ahead of Alpine's auto-boot) and
    // BEFORE the inline <script> that sets window.ET_BUILDER_CONFIG.
    // That means cfg isn't readable at module-load time; defer the
    // lookup until the factory runs (i.e. when Alpine instantiates the
    // x-data directive, by which point the body has parsed and the
    // config script has executed).
    function getCfg() {
        return window.ET_BUILDER_CONFIG || {};
    }

    const ELEMENT_TYPES = {
        section: {
            label: 'Section',
            factory: (id) => ({type: 'section', id, label: 'New section', help: ''}),
            summary: (el) => el.label || '(untitled section)'
        },
        text_block: {
            label: 'Text block',
            factory: (id) => ({type: 'text_block', id, content: ''}),
            summary: (el) => (el.content || '(empty text block)').slice(0, 80)
        },
        attribute_field: {
            label: 'Attribute',
            factory: (id) => ({
                type: 'attribute_field', id,
                label: 'New attribute', help: '',
                mandatory: false, repeatable: false,
                misp: {
                    category: '', type: '',
                    to_ids_default: false,
                    comment_template: '', default_value: ''
                }
            }),
            summary: (el) => {
                const label = el.label || '(unnamed)';
                const t = (el.misp && el.misp.type) || '?';
                const c = (el.misp && el.misp.category) || '?';
                return `${label} — ${c}/${t}`;
            }
        },
        object_field: {
            label: 'Object',
            factory: (id) => ({
                type: 'object_field', id,
                label: 'New object', help: '',
                mandatory: false, repeatable: false,
                object_template: {uuid: '', name: '', minimum_version: 0},
                relations: []
            }),
            summary: (el) => {
                const label = el.label || '(unnamed)';
                const ot = el.object_template || {};
                return label + ' — ' + (ot.name || 'no template') +
                    (ot.minimum_version ? ' v' + ot.minimum_version : '');
            }
        },
        tag_field: {
            label: 'Tag',
            factory: (id) => ({
                type: 'tag_field', id,
                label: 'New tag field', help: '',
                mandatory: false, multiple: true,
                restrict_taxonomies: []
            }),
            summary: (el) => el.label || '(unnamed)'
        },
        galaxy_field: {
            label: 'Galaxy',
            factory: (id) => ({
                type: 'galaxy_field', id,
                label: 'New galaxy field', help: '',
                mandatory: false, multiple: false,
                restrict_galaxy_types: []
            }),
            summary: (el) => el.label || '(unnamed)'
        },
        file_field: {
            label: 'File',
            factory: (id) => ({
                type: 'file_field', id,
                label: 'New file field', help: '',
                mandatory: false, repeatable: false,
                as: 'attachment'
            }),
            summary: (el) =>
                (el.label || '(unnamed)') + ' — as ' + (el.as || 'attachment')
        },
        event_report: {
            label: 'Event report',
            factory: (id) => ({
                type: 'event_report', id,
                label: 'New report', help: '',
                mandatory: false,
                default_content: ''
            }),
            summary: (el) => el.label || '(unnamed report)'
        },
        object_reference: {
            label: 'Reference',
            factory: (id) => ({
                type: 'object_reference', id,
                from: '', to: '', relationship_type: '', comment: ''
            }),
            summary: (el) =>
                (el.from || '?') + ' → ' + (el.to || '?') +
                ' (' + (el.relationship_type || '?') + ')'
        }
    };

    const ID_PREFIX = {
        section: 'section', text_block: 'text',
        attribute_field: 'attr', object_field: 'obj',
        tag_field: 'tags', galaxy_field: 'gal',
        file_field: 'file', event_report: 'report',
        object_reference: 'ref'
    };

    function uuidv4() {
        if (window.crypto && window.crypto.randomUUID) {
            return window.crypto.randomUUID();
        }
        return 'xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx'.replace(/[xy]/g, (c) => {
            const r = (Math.random() * 16) | 0;
            const v = c === 'x' ? r : (r & 0x3) | 0x8;
            return v.toString(16);
        });
    }

    function getDeep(obj, path) {
        const parts = path.split('.');
        let cur = obj;
        for (let i = 0; i < parts.length; i += 1) {
            if (cur == null || typeof cur !== 'object') { return undefined; }
            cur = cur[parts[i]];
        }
        return cur;
    }

    function setDeep(obj, path, value) {
        const parts = path.split('.');
        let cur = obj;
        for (let i = 0; i < parts.length - 1; i += 1) {
            if (cur[parts[i]] == null || typeof cur[parts[i]] !== 'object') {
                cur[parts[i]] = {};
            }
            cur = cur[parts[i]];
        }
        cur[parts[parts.length - 1]] = value;
    }

    function clone(o) { return JSON.parse(JSON.stringify(o)); }

    function alpineInit() {
        // ELEMENT_TYPES is closed over; expose only the factory so the
        // component can produce starter elements without re-declaring
        // shape rules.
        window.Alpine.data('etBuilder', () => {
        const cfg = getCfg();
        return {
            envelope: {name: '', description: '', distribution: 0, active: 1, misp_default: 0, exposed: 0},
            definition: {
                schema_version: 1, uuid: '', name: '',
                event_defaults: {distribution: 0}, structure: []
            },
            selectedId: null,
            errors: [],
            saving: false,
            validateStatus: '',
            validateStatusKind: '',
            attrCategories: cfg.attrCategories || {},
            objectTemplates: cfg.objectTemplates || [],
            multipickerSources: cfg.multipickerSources || {},
            objectTemplateRelationCache: {},
            objectTemplateRelations: [],
            objectTemplateRelationsLoading: false,

            init() {
                Object.assign(this.envelope, clone(cfg.envelope || {}));
                this.definition = clone(cfg.definition || this.definition);
                if (!this.definition.uuid) {
                    this.definition.uuid = uuidv4();
                }
                if (!this.definition.event_defaults) {
                    this.definition.event_defaults = {distribution: 0};
                }
                if (!Array.isArray(this.definition.structure)) {
                    this.definition.structure = [];
                }
                this.$nextTick(() => this.attachSortable());
            },

            // ---------- drag-and-drop reorder ----------

            attachSortable() {
                if (typeof window.Sortable === 'undefined') { return; }
                const $canvas = this.$root.querySelector('#et-canvas');
                if (!$canvas) { return; }
                // Sortable holds onto the container and queries its
                // children at drag time — the .et-canvas-element nodes
                // Alpine's <template x-for> emits/removes are picked up
                // automatically. The handle scopes the drag to the ☰
                // span so a click anywhere else on a row still selects.
                window.Sortable.create($canvas, {
                    handle: '.et-drag-handle',
                    draggable: '.et-canvas-element',
                    animation: 150,
                    ghostClass: 'et-sortable-ghost',
                    chosenClass: 'et-sortable-chosen',
                    forceFallback: false,
                    onEnd: (evt) => this.commitReorder($canvas, evt)
                });
            },
            commitReorder($canvas) {
                // After the drop the DOM already reflects the new order.
                // Read the order out of the DOM and rebuild the structure
                // array from the existing elements; Alpine's x-for keyed
                // on el.id then reconciles without re-creating nodes.
                const ids = Array.from(
                    $canvas.querySelectorAll('.et-canvas-element')
                ).map(($e) => $e.getAttribute('data-element-id'));
                if (ids.length !== this.definition.structure.length) {
                    return;
                }
                const byId = {};
                this.definition.structure.forEach((el) => { byId[el.id] = el; });
                const reordered = ids
                    .map((id) => byId[id])
                    .filter((el) => el);
                if (reordered.length !== this.definition.structure.length) {
                    return;
                }
                this.definition.structure = reordered;
            },

            // ---------- computed ----------

            get selected() {
                if (!this.selectedId) { return null; }
                return this.definition.structure.find(
                    (el) => el.id === this.selectedId
                ) || null;
            },
            get selectedType() {
                return this.selected ? this.selected.type : null;
            },
            get hasElements() {
                return this.definition.structure.length > 0;
            },
            get errorsByElementId() {
                const map = {};
                if (!this.errors || !this.errors.length) { return map; }
                const idsByIndex = this.definition.structure.map((el) => el.id);
                this.errors.forEach((err) => {
                    const ids = this._errorElementIds(err, idsByIndex);
                    ids.forEach((id) => {
                        if (!map[id]) { map[id] = []; }
                        map[id].push(err);
                    });
                });
                return map;
            },
            errorsForElement(id) {
                return this.errorsByElementId[id] || [];
            },
            _errorElementIds(err, idsByIndex) {
                // Validator messages that name an element come in four
                // shapes; collect any ids each match yields. The patterns
                // are deliberately narrow to avoid false positives like
                // matching "Network" out of '… in category "Network"'.
                const ids = new Set();
                // [schema] /structure/<N>/...
                const schema = err.match(/\[schema\][^\/]*\/structure\/(\d+)/);
                if (schema) {
                    const idx = parseInt(schema[1], 10);
                    if (idsByIndex[idx]) { ids.add(idsByIndex[idx]); }
                }
                // <type> "<id>": ...   (e.g. attribute_field "foo": …)
                const typed = err.match(/^([a-z_]+) "([^"]+)":/);
                if (typed) { ids.add(typed[2]); }
                // duplicate element id: <id>
                const dup = err.match(/duplicate element id: (\S+)/);
                if (dup) { ids.add(dup[1]); }
                // info_template references unknown field id: <id>
                const info = err.match(
                    /info_template references unknown field id: (\S+)/
                );
                if (info) { ids.add(info[1]); }
                // object_reference (from|to) "<id>" does not point to ...
                const ref = err.match(
                    /object_reference (?:from|to) "([^"]+)" does not point to/
                );
                if (ref) { ids.add(ref[1]); }
                return Array.from(ids);
            },
            get attributeTypeOptions() {
                if (!this.selected || this.selected.type !== 'attribute_field') {
                    return [];
                }
                const cat = (this.selected.misp && this.selected.misp.category) || '';
                return this.attrCategories[cat] || [];
            },
            get objectFieldChoices() {
                return this.definition.structure
                    .filter((e) => e.type === 'object_field')
                    .map((e) => ({id: e.id, label: e.label || e.id}));
            },

            // ---------- canvas summary ----------

            typeLabel(el) {
                return (ELEMENT_TYPES[el.type] && ELEMENT_TYPES[el.type].label) || el.type;
            },
            elementSummary(el) {
                const spec = ELEMENT_TYPES[el.type];
                return spec && spec.summary ? spec.summary(el) : el.id;
            },

            // ---------- mutations ----------

            newElementId(type) {
                const prefix = ID_PREFIX[type] || 'el';
                const existing = {};
                this.definition.structure.forEach((el) => {
                    if (el && el.id) { existing[el.id] = true; }
                });
                let n = this.definition.structure.length + 1;
                let candidate;
                do {
                    candidate = prefix + '_' + n;
                    n += 1;
                } while (existing[candidate]);
                return candidate;
            },
            addElement(type) {
                const spec = ELEMENT_TYPES[type];
                if (!spec) { return; }
                const el = spec.factory(this.newElementId(type));
                this.definition.structure.push(el);
                this.selectedId = el.id;
            },
            removeElement(id) {
                if (!window.confirm('Remove this element?')) { return; }
                this.definition.structure = this.definition.structure.filter(
                    (el) => el.id !== id
                );
                if (this.selectedId === id) { this.selectedId = null; }
            },
            selectElement(id) {
                this.selectedId = id;
                // When an object_field is selected, refresh its relations
                // panel from cache (or kick off a fetch).
                const el = this.selected;
                if (el && el.type === 'object_field') {
                    this.refreshRelationsPanel();
                }
            },

            // ---------- field accessors (dotted path) ----------

            getField(path) {
                if (!this.selected) { return ''; }
                const v = getDeep(this.selected, path);
                return v == null ? '' : v;
            },
            setField(path, value) {
                if (!this.selected) { return; }
                const idx = this.definition.structure.findIndex(
                    (e) => e.id === this.selectedId
                );
                if (idx === -1) { return; }
                const next = clone(this.definition.structure[idx]);
                setDeep(next, path, value);
                this.definition.structure[idx] = next;
                if (path === 'misp.category') {
                    // Clear stale type when the category changes and the
                    // type is no longer valid for it.
                    const types = this.attributeTypeOptions;
                    const cur = (next.misp && next.misp.type) || '';
                    if (cur && types.indexOf(cur) === -1) {
                        setDeep(next, 'misp.type', '');
                        this.definition.structure[idx] = next;
                    }
                }
            },

            // ---------- object_field / object-template picker ----------

            pickObjectTemplate(uuid, name, version) {
                if (!this.selected || this.selected.type !== 'object_field') {
                    return;
                }
                const elementId = this.selectedId;
                this.setField('object_template.uuid', uuid);
                this.setField('object_template.name', name);
                this.setField('object_template.minimum_version',
                    parseInt(version, 10) || 0);
                // Load relations + default to "all selected" — same UX
                // contract as the Phase-2 builder.
                this.ensureRelationsLoaded(uuid).then((rels) => {
                    if (this.selectedId !== elementId) { return; }
                    const idx = this.definition.structure.findIndex(
                        (e) => e.id === elementId
                    );
                    if (idx === -1) { return; }
                    const next = clone(this.definition.structure[idx]);
                    next.relations = rels.map((r) => ({
                        object_relation: r.object_relation
                    }));
                    this.definition.structure[idx] = next;
                    this.objectTemplateRelations = rels;
                });
            },
            ensureRelationsLoaded(uuid) {
                if (!uuid) { return Promise.resolve([]); }
                if (this.objectTemplateRelationCache[uuid]) {
                    return Promise.resolve(this.objectTemplateRelationCache[uuid]);
                }
                this.objectTemplateRelationsLoading = true;
                return fetch(cfg.baseurl + '/object_templates/view/' +
                        encodeURIComponent(uuid), {
                    method: 'GET',
                    credentials: 'same-origin',
                    headers: {
                        'Accept': 'application/json',
                        'X-Requested-With': 'XMLHttpRequest'
                    }
                }).then((r) => {
                    if (!r.ok) { throw new Error('HTTP ' + r.status); }
                    return r.json();
                }).then((data) => {
                    let rels = (data && data.ObjectTemplateElement) || [];
                    rels = rels.map((r) => ({
                        object_relation: (r.object_relation || '').toString(),
                        type: (r.type || '').toString(),
                        description: (r.description || '').toString(),
                        ui_priority: parseInt(r['ui-priority'] || 0, 10)
                    })).filter((r) => r.object_relation !== '');
                    rels.sort((a, b) => {
                        if (b.ui_priority !== a.ui_priority) {
                            return b.ui_priority - a.ui_priority;
                        }
                        return a.object_relation.localeCompare(b.object_relation);
                    });
                    this.objectTemplateRelationCache[uuid] = rels;
                    this.objectTemplateRelationsLoading = false;
                    return rels;
                }).catch((err) => {
                    this.objectTemplateRelationsLoading = false;
                    throw err;
                });
            },
            refreshRelationsPanel() {
                const el = this.selected;
                if (!el || el.type !== 'object_field') {
                    this.objectTemplateRelations = [];
                    return;
                }
                const uuid = (el.object_template && el.object_template.uuid) || '';
                if (!uuid) {
                    this.objectTemplateRelations = [];
                    return;
                }
                if (this.objectTemplateRelationCache[uuid]) {
                    this.objectTemplateRelations = this.objectTemplateRelationCache[uuid];
                    return;
                }
                this.ensureRelationsLoaded(uuid).then((rels) => {
                    if (!this.selected || this.selected.id !== el.id) { return; }
                    this.objectTemplateRelations = rels;
                });
            },
            isRelationSelected(rel) {
                const el = this.selected;
                if (!el || !Array.isArray(el.relations)) { return false; }
                return el.relations.some(
                    (r) => r && r.object_relation === rel
                );
            },
            toggleRelation(rel, on) {
                const el = this.selected;
                if (!el || el.type !== 'object_field') { return; }
                const idx = this.definition.structure.findIndex(
                    (e) => e.id === el.id
                );
                if (idx === -1) { return; }
                const next = clone(el);
                if (!Array.isArray(next.relations)) { next.relations = []; }
                const existingIdx = next.relations.findIndex(
                    (r) => r && r.object_relation === rel
                );
                if (on) {
                    if (existingIdx === -1) {
                        next.relations.push({object_relation: rel});
                    }
                } else if (existingIdx !== -1) {
                    next.relations.splice(existingIdx, 1);
                }
                this.definition.structure[idx] = next;
            },
            selectAllRelations() {
                const el = this.selected;
                if (!el || el.type !== 'object_field') { return; }
                const idx = this.definition.structure.findIndex(
                    (e) => e.id === el.id
                );
                if (idx === -1) { return; }
                const next = clone(el);
                next.relations = this.objectTemplateRelations.map((r) => ({
                    object_relation: r.object_relation
                }));
                this.definition.structure[idx] = next;
            },
            selectNoRelations() {
                const el = this.selected;
                if (!el || el.type !== 'object_field') { return; }
                const idx = this.definition.structure.findIndex(
                    (e) => e.id === el.id
                );
                if (idx === -1) { return; }
                const next = clone(el);
                next.relations = [];
                this.definition.structure[idx] = next;
            },
            currentObjectTemplateMeta() {
                const el = this.selected;
                if (!el || el.type !== 'object_field') { return ''; }
                const uuid = (el.object_template && el.object_template.uuid) || '';
                if (!uuid) { return ''; }
                const ot = this.objectTemplates.find((o) => o.uuid === uuid);
                return ot ? (ot.meta_category || '') : '';
            },

            // ---------- Tom Select pickers ----------
            initEnvelopeDistributionSelect($el) {
                if (!$el) { return; }

                const attach = () => {
                    if (typeof window.initDistributionSelect !== 'function') {
                        return;
                    }
                    window.initDistributionSelect($el.id, (value) => {
                        const level = parseInt(value, 10);
                        if (!isNaN(level) && level !== this.envelope.distribution) {
                            this.envelope.distribution = level;
                        }
                    });
                    const ts = $el.tomselect;
                    if (!ts) { return; }
                    this._distributionTomSelect = ts;

                    ts.setValue(String(this.envelope.distribution), true);
                    this.$watch('envelope.distribution', (value) => {
                        if (ts.getValue() !== String(value)) {
                            ts.setValue(String(value), true);
                        }
                    });
                };

                if (document.readyState === 'loading') {
                    document.addEventListener('DOMContentLoaded', attach, {once: true});
                } else {
                    attach();
                }
            },

            initObjectTemplateSelect($el) {
                if (typeof window.TomSelect === 'undefined') { return; }
                const items = (this.objectTemplates || []).map((ot) => ({
                    value: ot.uuid,
                    text: ot.name + ' (v' + ot.version +
                        ', ' + ot.meta_category + ')',
                    name: ot.name,
                    meta_category: ot.meta_category,
                    description: ot.description || ''
                }));
                this._otTomSelect = new window.TomSelect($el, {
                    valueField: 'value',
                    labelField: 'text',
                    searchField: ['text', 'name', 'meta_category', 'description'],
                    options: items,
                    placeholder: 'Choose an object template…',
                    create: false,
                    maxOptions: 500,
                    onChange: (uuid) => {
                        if (!uuid) { return; }
                        if (!this.selected || this.selected.type !== 'object_field') {
                            return;
                        }
                        if (this.getField('object_template.uuid') === uuid) {
                            return; // programmatic sync, not a user pick
                        }
                        const ot = this.objectTemplates.find((o) => o.uuid === uuid);
                        if (!ot) { return; }
                        this.pickObjectTemplate(uuid, ot.name, ot.version);
                    }
                });
                this.$watch('selectedId', () => this.syncObjectTemplateSelect());
                this.$watch('definition.structure', () =>
                    this.syncObjectTemplateSelect(), {deep: true});
                this.syncObjectTemplateSelect();
            },
            syncObjectTemplateSelect() {
                if (!this._otTomSelect) { return; }
                const cur = (this.selected && this.selected.type === 'object_field')
                    ? (this.getField('object_template.uuid') || '')
                    : '';
                if (this._otTomSelect.getValue() !== cur) {
                    // Second arg = silent; do not fire onChange.
                    this._otTomSelect.setValue(cur, true);
                }
            },

            initMultipicker($el, source, field, placeholder) {
                if (typeof window.TomSelect === 'undefined') { return; }
                const items = (this.multipickerSources[source] || []).map((it) => ({
                    value: it.value,
                    text: it.label,
                    description: it.description || ''
                }));
                const ts = new window.TomSelect($el, {
                    valueField: 'value',
                    labelField: 'text',
                    searchField: ['text', 'description'],
                    options: items,
                    placeholder: placeholder || 'Select…',
                    create: false,
                    plugins: ['remove_button'],
                    maxOptions: 1000,
                    onChange: (vals) => {
                        if (!this.selected) { return; }
                        const arr = Array.isArray(vals)
                            ? vals
                            : (vals ? [vals] : []);
                        const cur = this.getField(field);
                        const sameSet = Array.isArray(cur) &&
                            cur.length === arr.length &&
                            cur.every((v, i) => v === arr[i]);
                        if (sameSet) { return; }
                        this.setField(field, arr);
                    }
                });
                if (!this._multipickerInstances) {
                    this._multipickerInstances = [];
                }
                this._multipickerInstances.push({
                    instance: ts,
                    field,
                    matchType: source === 'taxonomies' ? 'tag_field' : 'galaxy_field'
                });
                const sync = () => this.syncMultipicker(ts, field, source);
                this.$watch('selectedId', sync);
                this.$watch('definition.structure', sync, {deep: true});
                sync();
            },
            syncMultipicker(ts, field, source) {
                if (!ts) { return; }
                const expectedType = source === 'taxonomies'
                    ? 'tag_field' : 'galaxy_field';
                let values = [];
                if (this.selected && this.selected.type === expectedType) {
                    const v = this.getField(field);
                    values = Array.isArray(v) ? v : [];
                }
                const cur = ts.getValue();
                const curArr = Array.isArray(cur) ? cur : (cur ? [cur] : []);
                const sameSet = curArr.length === values.length &&
                    curArr.every((v, i) => v === values[i]);
                if (sameSet) { return; }
                ts.setValue(values, true);
            },

            // ---------- save / validate ----------

            mirrorEnvelopeIntoDefinition() {
                this.definition.name = this.envelope.name;
                if (this.envelope.description) {
                    this.definition.description = this.envelope.description;
                } else {
                    delete this.definition.description;
                }
            },
            extractErrors(data) {
                if (!data) { return ['Unknown error.']; }
                if (Array.isArray(data.errors)) { return data.errors; }
                if (data.errors && typeof data.errors === 'object') {
                    const out = [];
                    Object.keys(data.errors).forEach((field) => {
                        const list = data.errors[field];
                        if (Array.isArray(list)) {
                            list.forEach((msg) =>
                                out.push(field + ': ' + msg));
                        } else {
                            out.push(field + ': ' + list);
                        }
                    });
                    return out;
                }
                if (data.message) { return [data.message]; }
                return ['Unknown error.'];
            },
            save() {
                if (this.saving) { return; }
                this.saving = true;
                this.errors = [];
                this.mirrorEnvelopeIntoDefinition();
                const body = {
                    EventTemplate: {
                        name: this.envelope.name,
                        description: this.envelope.description,
                        distribution: Number(this.envelope.distribution) || 0,
                        active: this.envelope.active ? 1 : 0,
                        misp_default: this.envelope.misp_default ? 1 : 0,
                        exposed: this.envelope.exposed ? 1 : 0,
                        definition: this.definition
                    }
                };
                fetch(cfg.submitUrl, {
                    method: 'POST',
                    credentials: 'same-origin',
                    headers: {
                        'Accept': 'application/json',
                        'Content-Type': 'application/json',
                        'X-Requested-With': 'XMLHttpRequest'
                    },
                    body: JSON.stringify(body)
                }).then((r) => r.json().then((data) => ({status: r.status, data})))
                    .then((res) => {
                        this.saving = false;
                        if (res.status >= 200 && res.status < 300 &&
                                res.data.EventTemplate) {
                            window.location.href = cfg.baseurl +
                                '/event_templates/view/' +
                                res.data.EventTemplate.id;
                            return;
                        }
                        this.errors = this.extractErrors(res.data);
                    }).catch((err) => {
                        this.saving = false;
                        this.errors = ['Network error while saving: ' +
                            (err && err.message ? err.message : err)];
                    });
            },
            validate() {
                this.mirrorEnvelopeIntoDefinition();
                const probe = clone(this.definition);
                this.validateStatus = 'Validating…';
                this.validateStatusKind = '';
                fetch(cfg.baseurl + '/event_templates/validate_definition', {
                    method: 'POST',
                    credentials: 'same-origin',
                    headers: {
                        'Accept': 'application/json',
                        'Content-Type': 'application/json',
                        'X-Requested-With': 'XMLHttpRequest'
                    },
                    body: JSON.stringify(probe)
                }).then((r) => r.json().then((data) => ({status: r.status, data})))
                    .then((res) => {
                        const valid = res.data && res.data.valid;
                        const errs = (res.data && Array.isArray(res.data.errors))
                            ? res.data.errors : [];
                        if (valid) {
                            this.errors = [];
                            this.validateStatus = '✓ Definition is valid.';
                            this.validateStatusKind = 'success';
                        } else {
                            this.errors = errs.length
                                ? errs : ['Definition is invalid.'];
                            this.validateStatus = '✗ ' + this.errors.length +
                                (this.errors.length === 1 ? ' error' : ' errors');
                            this.validateStatusKind = 'error';
                        }
                    }).catch((err) => {
                        this.errors = ['Validation request failed: ' +
                            (err && err.message ? err.message : err)];
                        this.validateStatus = '✗ network error';
                        this.validateStatusKind = 'error';
                    });
            }
        };
        });
    }

    if (window.Alpine) {
        alpineInit();
    } else {
        document.addEventListener('alpine:init', alpineInit);
    }
})();
