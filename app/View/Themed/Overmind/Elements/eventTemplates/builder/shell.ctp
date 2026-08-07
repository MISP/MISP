<?php
    // Load builder-only vendor assets. Gated to this view by virtue of
    // being requested from inside the element (not from the layout).
    //
    // Order matters here: Alpine 3's CDN build auto-boots
    // synchronously the moment its <script> tag executes, and from
    // that point its mutation observer is live — any x-data directive
    // it sees (including the one on this element's root div, parsed
    // shortly afterwards) is processed immediately. So our component
    // factory has to be registered before alpine.min.js executes,
    // which means our script tag has to come first.
    //
    // builder-overmind.js handles this by registering its
    // Alpine.data('etBuilder', …) call inside an 'alpine:init' event
    // listener, which fires when Alpine's auto-boot reaches the
    // event-dispatch step but before the DOM walk.
    echo $this->element('genericElements/assetLoader', [
        'js' => [
            'vendor/sortablejs/Sortable.min',
            'event-templates/builder-overmind',
            'vendor/alpinejs/alpine.min',
        ],
    ]);

    $existing = isset($data['EventTemplate']) ? $data['EventTemplate'] : null;
    $builderMode = $existing ? 'edit' : 'add';
    $submitUrl = $existing
        ? $baseurl . '/event_templates/edit/' . (int)$existing['id']
        : $baseurl . '/event_templates/add';
    $envelope = [
        'name'         => $existing['name'] ?? '',
        'description'  => $existing['description'] ?? '',
        'distribution' => (int)($existing['distribution'] ?? 0),
        'active'       => !empty($existing['active']) ? 1 : ($existing ? 0 : 1),
        'misp_default' => !empty($existing['misp_default']) ? 1 : 0,
        'exposed'      => !empty($existing['exposed']) ? 1 : 0,
    ];
    $initialDefinition = ($existing && is_array($existing['definition'] ?? null))
        ? $existing['definition']
        : [
            'schema_version' => 1,
            'uuid'           => '',
            'name'           => '',
            'event_defaults' => ['distribution' => 0],
            'structure'      => [],
        ];
    $pageTitle = $builderMode === 'edit'
        ? __('Edit Event Template')
        : __('Add Event Template');
    $pageDescription = __(
        'Compose the guided form: drop elements on the canvas, then set '
        . 'their properties on the right. Users filling the template only '
        . 'see the fields you define here.'
    );

    $isModal = !empty($ajax);
    if (!$isModal) {
        $this->set('headerTitle', $pageTitle);
        $this->set('headerDescription', $pageDescription);
        // No paginator here — keep the header's count badge out.
        $this->set('headerCountText', '');
    }

    $distributionLevels = (isset($distributionLevels) && is_array($distributionLevels))
        ? $distributionLevels
        : [
            0 => $this->DistributionLevel->get(0)['label'],
            1 => $this->DistributionLevel->get(1)['label'],
        ];


    $attrCategories = isset($attributeCategoryDefinitions)
        ? $attributeCategoryDefinitions
        : [];
    $objectTemplates = isset($objectTemplatesAvailable)
        ? $objectTemplatesAvailable
        : [];
    $multipickerSources = [
        'taxonomies' => isset($taxonomiesAvailable) ? $taxonomiesAvailable : [],
        'galaxyTypes' => isset($galaxyTypesAvailable) ? $galaxyTypesAvailable : [],
    ];

    $paletteButtons = [
        'section'          => ['label' => __('Section'),          'icon' => 'folder'],
        'text_block'       => ['label' => __('Text block'),       'icon' => 'align-left'],
        'attribute_field'  => ['label' => __('Attribute field'),  'icon' => 'tag'],
        'object_field'     => ['label' => __('Object field'),     'icon' => 'cube'],
        'tag_field'        => ['label' => __('Tag field'),        'icon' => 'tags'],
        'galaxy_field'     => ['label' => __('Galaxy field'),     'icon' => 'globe'],
        'file_field'       => ['label' => __('File field'),       'icon' => 'file'],
        'event_report'     => ['label' => __('Event report'),     'icon' => 'file-alt'],
        'object_reference' => ['label' => __('Object reference'), 'icon' => 'link'],
    ];
    // JSON_HEX_TAG / AMP / APOS / QUOT harden against HTML5 script-data
    // state-machine quirks for content controlled by template authors —
    // labels / help / descriptions inside $initialDefinition + $envelope
    // can otherwise sneak `<!--<script>...` sequences past the script
    // boundary even though `/` is escaped by default.
    $jsonScriptFlags = JSON_HEX_TAG | JSON_HEX_AMP | JSON_HEX_APOS | JSON_HEX_QUOT;
?>
<script>
    // Set BEFORE the x-data div is parsed so that when Alpine's
    // mutation observer picks the div up and instantiates the
    // etBuilder factory, the factory's cfg lookup finds the
    // populated config object.
    window.ET_BUILDER_CONFIG = {
        mode:       <?= json_encode($builderMode, $jsonScriptFlags) ?>,
        submitUrl:  <?= json_encode($submitUrl, $jsonScriptFlags) ?>,
        baseurl:    <?= json_encode($baseurl, $jsonScriptFlags) ?>,
        envelope:   <?= json_encode($envelope, $jsonScriptFlags) ?>,
        definition: <?= json_encode($initialDefinition, $jsonScriptFlags) ?>,
        attrCategories: <?= json_encode($attrCategories, $jsonScriptFlags) ?>,
        objectTemplates: <?= json_encode($objectTemplates, $jsonScriptFlags) ?>,
        multipickerSources: <?= json_encode($multipickerSources, $jsonScriptFlags) ?>
    };
</script>
<style>
[x-cloak] { display: none !important; }
.eventTemplates.builder .et-canvas-element {
    border: 1px solid var(--bs-border-color);
    border-radius: 0.25rem;
    padding: 8px 10px;
    margin-bottom: 6px;
    cursor: pointer;
    background: var(--bs-light);
}
.eventTemplates.builder .et-drag-handle {
    color: #aaa;
    cursor: grab;
    padding: 0 4px;
    user-select: none;
}
.eventTemplates.builder .et-drag-handle:hover { color: #555; }
.eventTemplates.builder .et-drag-handle:active { cursor: grabbing; }
.eventTemplates.builder .et-canvas-element.selected {
    border-color: var(--bs-primary);
    box-shadow: 0 0 0 1px var(--bs-primary);
    background: rgba(var(--bs-primary-rgb), 0.08);
}
.eventTemplates.builder .et-canvas-element.et-sortable-ghost {
    opacity: 0.4;
    border: 1px dashed var(--bs-primary);
    background: rgba(var(--bs-primary-rgb), 0.08);
}
.eventTemplates.builder .et-canvas-element.et-sortable-chosen {
    box-shadow: 0 4px 10px rgba(0,0,0,0.12);
}
.eventTemplates.builder .et-canvas-element.et-has-error {
    border-color: var(--bs-danger);
    box-shadow: 0 0 0 1px var(--bs-danger);
}
.eventTemplates.builder .et-canvas-element.et-has-error.selected {
    box-shadow: 0 0 0 1px var(--bs-danger),
                0 0 0 3px rgba(var(--bs-primary-rgb), 0.25);
}
.eventTemplates.builder .et-element-type-badge {
    background: #eee;
    padding: 2px 6px;
    border-radius: 2px;
    font-size: 11px;
    text-transform: uppercase;
    color: #555;
}
.eventTemplates.builder .et-element-summary { flex: 1; font-weight: 500; }
.eventTemplates.builder .et-element-id { color: #888; font-size: 11px; }
.eventTemplates.builder .et-empty {
    color: #888;
    padding: 20px 0;
    font-style: italic;
    text-align: center;
}
.eventTemplates.builder .et-relations-list label {
    display: block;
    padding: 3px 8px;
    margin: 0;
    border-bottom: 1px solid #f3f3f3;
    cursor: pointer;
    font-size: 12px;
}
.eventTemplates.builder .et-relations-list label:hover { background: #f0f8ff; }
.eventTemplates.builder .et-relations-list input[type=checkbox] {
    margin-right: 6px;
}
.eventTemplates.builder .et-relations-list .et-rel-name { font-weight: 500; }
.eventTemplates.builder .et-relations-list .et-rel-type {
    color: #888; font-size: 11px; margin-left: 6px;
}
</style>

<?php if ($isModal): ?>
<!-- ── MODAL HEADER ─────────────────────────────────────────── -->
<div class="px-4 pt-3 pb-3 d-flex align-items-center justify-content-between"
     style="background:rgba(24,146,177,.06);
            border-bottom:2px solid var(--event, var(--primary));">
    <div>
        <div class="text-uppercase fw-semibold mb-1 text-event"
             style="font-size:.58rem; letter-spacing:.12em; opacity:.85;">
            <?= __('Event Templates') ?>
        </div>
        <h4 class="mb-0 fw-bold d-flex align-items-center gap-2">
            <i class="fas fa-<?= $builderMode === 'edit' ? 'pen-to-square' : 'circle-plus' ?> text-event"
               style="font-size:1.25rem;"></i>
            <?= h($pageTitle) ?>
        </h4>
        <p class="text-muted mb-0" style="font-size:.75rem;">
            <?= h($pageDescription) ?>
        </p>
    </div>
    <span class="fas fa-wand-magic-sparkles text-event"
          style="font-size:2rem; opacity:.5;"></span>
</div>
<?php endif; ?>

<div class="eventTemplates builder <?= $isModal ? 'p-4' : 'container-fluid mt-3' ?>"
     x-data="etBuilder" x-cloak>

    <div class="alert alert-danger" x-show="errors.length">
        <strong><?= __('Could not save:') ?></strong>
        <ul class="mb-0">
            <template x-for="err in errors" :key="err">
                <li x-text="err"></li>
            </template>
        </ul>
    </div>

    <div class="alert alert-warning" x-show="envelope.misp_default">
        <div class="d-flex align-items-start gap-3">
            <i class="fas fa-cube fs-4 mt-1"></i>
            <div>
                <strong><?= __('Library-managed template') ?></strong>
                <div class="small">
                    <?= __('This template is managed by the <code>misp-event-templates</code> submodule. The next <em>Update from library</em> run will overwrite your edits unless you uncheck <em>Library-managed</em> below — that flips this row to a fork and library updates will leave it alone.') ?>
                </div>
            </div>
        </div>
    </div>

    <!-- ── ENVELOPE ───────────────────────────────────────────── -->
    <div class="d-flex flex-column gap-4 mb-4 et-envelope">

        <!-- Template name -->
        <div class="w-100 px-2">
            <div class="d-flex align-items-center gap-2 text-primary fw-bold
                        text-uppercase mb-2"
                 style="font-size:.65rem; letter-spacing:.1em;">
                <?= __('Template Name') ?>
                <span class="badge bg-primary"
                      style="font-size:.55rem; opacity:.8; font-weight:700;">
                    <?= __('REQUIRED') ?>
                </span>
            </div>
            <input type="text" id="et-envelope-name"
                   class="w-100 border-0 bg-transparent fs-5 py-1"
                   style="border-bottom:1px solid #d8dde3 !important; outline:none;"
                   placeholder="<?= __('Spearphishing email triage') ?>"
                   x-model="envelope.name">
        </div>

        <!-- Description -->
        <div class="w-100 px-2">
            <div class="text-primary fw-bold text-uppercase mb-2"
                 style="font-size:.65rem; letter-spacing:.1em;">
                <?= __('Description (Markdown)') ?>
            </div>
            <div class="border rounded px-2 py-2"
                 style="border-color:#d8dde3;">
                <textarea id="et-envelope-description" rows="2"
                          class="w-100 border-0 bg-transparent p-0"
                          style="outline:none; font-size:.925rem; resize:vertical;"
                          placeholder="<?= h(__('What this template is for, and when to use it…')) ?>"
                          x-model="envelope.description"></textarea>
            </div>
        </div>

        <!-- Distribution + flags -->
        <div class="row g-3 px-2">
            <div class="col-md-4">
                <!-- ── DISTRIBUTION ───────────────────────────────────── -->
                <div class="w-100">
                    <div class="text-primary fw-bold text-uppercase mb-2"
                         style="font-size:.65rem; letter-spacing:.1em;">
                        <?= __('Distribution') ?>
                    </div>
                    <select id="et-envelope-distribution" class="form-select"
                            x-init="initEnvelopeDistributionSelect($el)"
                            x-model.number="envelope.distribution">
                        <?php foreach ($distributionLevels as $level => $label): ?>
                            <option value="<?= (int)$level ?>"><?= h($label) ?></option>
                        <?php endforeach; ?>
                    </select>
                </div>
            </div>
            <div class="col-md-8">
                <div class="text-primary fw-bold text-uppercase mb-2"
                     style="font-size:.65rem; letter-spacing:.1em;">
                    <?= __('Options') ?>
                </div>
                <div class="border rounded px-3 py-2 d-flex flex-wrap gap-3"
                     style="border-color:#d8dde3;">
                    <div class="form-check form-switch mb-0">
                        <input class="form-check-input" type="checkbox"
                               id="et-envelope-active"
                               x-model="envelope.active">
                        <label class="form-check-label" for="et-envelope-active"
                               style="font-size:.85rem;">
                            <?= __('Active') ?>
                        </label>
                    </div>
                    <div class="form-check form-switch mb-0"
                         title="<?= h(__('When checked, the template is managed by the misp-event-templates submodule and library updates will overwrite it. Uncheck to fork — your edits will be preserved across library updates.')) ?>">
                        <input class="form-check-input" type="checkbox"
                               id="et-envelope-misp-default"
                               x-model="envelope.misp_default">
                        <label class="form-check-label" for="et-envelope-misp-default"
                               style="font-size:.85rem;">
                            <?= __('Library-managed') ?>
                        </label>
                    </div>
                    <div class="form-check form-switch mb-0"
                         title="<?= h(__('When checked, this template is offered to anonymous community reporters through Draugnet (if the CSIRT runs it with the MISP template source). Off by default — exposing is an explicit opt-in.')) ?>">
                        <input class="form-check-input" type="checkbox"
                               id="et-envelope-exposed"
                               x-model="envelope.exposed">
                        <label class="form-check-label" for="et-envelope-exposed"
                               style="font-size:.85rem;">
                            <?= __('Expose to Draugnet') ?>
                        </label>
                    </div>
                </div>
            </div>
        </div>

    </div>

    <div class="row g-3">

        <!-- PALETTE -->
        <div class="col-lg-2 col-md-3">
            <div class="text-primary fw-bold text-uppercase mb-2 px-2"
                 style="font-size:.65rem; letter-spacing:.1em;">
                <?= __('Add Element') ?>
            </div>
            <div class="card shadow-sm et-palette">
                <div class="card-body">
                    <?php foreach ($paletteButtons as $type => $meta): ?>
                        <button type="button"
                                class="btn btn-sm btn-outline-secondary w-100 mb-2 text-start"
                                @click="addElement('<?= h($type) ?>')">
                            <i class="fas fa-<?= h($meta['icon']) ?> me-2"></i>
                            <?= h($meta['label']) ?>
                        </button>
                    <?php endforeach; ?>
                </div>
            </div>
        </div>

        <!-- CANVAS -->
        <div class="col-lg-5 col-md-4">
            <div class="d-flex align-items-center gap-2 text-primary fw-bold
                        text-uppercase mb-2 px-2"
                 style="font-size:.65rem; letter-spacing:.1em;">
                <?= __('Structure') ?>
                <span class="badge bg-secondary" x-show="hasElements"
                      style="font-size:.55rem; font-weight:700;"
                      x-text="definition.structure.length"></span>
            </div>
            <div class="card shadow-sm">
                <div class="card-body">
                    <div class="et-canvas" id="et-canvas" style="min-height:420px;">
                        <div class="et-empty" x-show="!hasElements">
                            <?= __('No elements yet. Use the palette on the left to add one.') ?>
                        </div>
                        <template x-for="el in definition.structure" :key="el.id">
                            <div class="et-canvas-element"
                                 :class="{
                                     selected: el.id === selectedId,
                                     'et-has-error': errorsForElement(el.id).length
                                 }"
                                 :data-element-id="el.id"
                                 @click.self="selectElement(el.id)">
                                <div class="et-element-header d-flex align-items-center gap-2"
                                     @click="selectElement(el.id)">
                                    <span class="et-drag-handle"
                                          title="<?= __('Drag to reorder') ?>">☰</span>
                                    <span class="et-element-type-badge"
                                          x-text="typeLabel(el)"></span>
                                    <span class="et-element-summary"
                                          x-text="elementSummary(el)"></span>
                                    <code class="et-element-id" x-text="el.id"></code>
                                    <span class="badge bg-danger"
                                          x-show="errorsForElement(el.id).length"
                                          x-text="errorsForElement(el.id).length"
                                          :title="'<?= __('Validation errors on this element') ?>'"></span>
                                    <button type="button"
                                            class="btn btn-sm btn-outline-danger et-delete-button"
                                            title="<?= __('Delete element') ?>"
                                            @click.stop="removeElement(el.id)">
                                        <i class="fas fa-times"></i>
                                    </button>
                                </div>
                                <div class="et-element-errors alert alert-danger py-1 px-2 mt-2 mb-0 small"
                                     x-show="errorsForElement(el.id).length">
                                    <ul class="mb-0 ps-3">
                                        <template x-for="msg in errorsForElement(el.id)"
                                                  :key="msg">
                                            <li x-text="msg"></li>
                                        </template>
                                    </ul>
                                </div>
                            </div>
                        </template>
                    </div>
                </div>
            </div>
        </div>

        <!-- PROPERTIES -->
        <div class="col-lg-5 col-md-5">
            <div class="text-primary fw-bold text-uppercase mb-2 px-2"
                 style="font-size:.65rem; letter-spacing:.1em;">
                <?= __('Properties') ?>
            </div>
            <div class="card shadow-sm et-properties-pane">
                <div class="card-body">
                    <div class="et-empty" x-show="!selectedId">
                        <?= __('Select an element in the canvas to edit its properties.') ?>
                    </div>
                    <div x-show="selectedType === 'section'">
                        <?= $this->element('eventTemplates/builder/properties_section') ?>
                    </div>
                    <div x-show="selectedType === 'text_block'">
                        <?= $this->element('eventTemplates/builder/properties_text_block') ?>
                    </div>
                    <div x-show="selectedType === 'attribute_field'">
                        <?= $this->element('eventTemplates/builder/properties_attribute_field', [
                            'attributeCategoryDefinitions' => $attrCategories,
                        ]) ?>
                    </div>
                    <div x-show="selectedType === 'object_field'">
                        <?= $this->element('eventTemplates/builder/properties_object_field', [
                            'objectTemplatesAvailable' => $objectTemplates,
                        ]) ?>
                    </div>
                    <div x-show="selectedType === 'tag_field'">
                        <?= $this->element('eventTemplates/builder/properties_tag_field') ?>
                    </div>
                    <div x-show="selectedType === 'galaxy_field'">
                        <?= $this->element('eventTemplates/builder/properties_galaxy_field') ?>
                    </div>
                    <div x-show="selectedType === 'file_field'">
                        <?= $this->element('eventTemplates/builder/properties_file_field') ?>
                    </div>
                    <div x-show="selectedType === 'event_report'">
                        <?= $this->element('eventTemplates/builder/properties_event_report') ?>
                    </div>
                    <div x-show="selectedType === 'object_reference'">
                        <?= $this->element('eventTemplates/builder/properties_object_reference') ?>
                    </div>
                </div>
            </div>
        </div>

    </div>

    <!-- ── FOOTER ─────────────────────────────────────────────── -->
    <div class="et-save-bar d-flex justify-content-between align-items-center
                mt-4 pt-3 flex-wrap gap-2"
         style="border-top:1px solid var(--bs-border-color, #dee2e6);">
        <div class="d-flex align-items-center gap-3 flex-wrap text-muted"
             style="font-size:.75rem;">
            <span id="et-validate-status"
                  :class="{
                      'text-success': validateStatusKind === 'success',
                      'text-danger': validateStatusKind === 'error',
                      'text-muted': !validateStatusKind
                  }"
                  x-text="validateStatus"></span>
            <?php if ($existing): ?>
                <a href="<?= h($baseurl . '/event_templates/preview/' . (int)$existing['id']) ?>"
                   target="_blank" rel="noopener"
                   class="text-decoration-none"
                   title="<?= __('Open the user form in a new tab — reflects the last saved version. Save first to preview unsaved changes.') ?>">
                    <i class="fas fa-eye me-1"></i><?= __('Preview the user form') ?>
                </a>
            <?php endif; ?>
        </div>
        <div class="d-flex gap-2">
            <?php if ($isModal): ?>
                <button type="button" class="btn btn-outline-secondary btn-sm"
                        data-bs-dismiss="modal">
                    <i class="fas fa-times me-1"></i><?= __('Discard') ?>
                </button>
            <?php else: ?>
                <a class="btn btn-outline-secondary btn-sm"
                   href="<?= h($existing
                        ? $baseurl . '/event_templates/view/' . (int)$existing['id']
                        : $baseurl . '/event_templates/index') ?>">
                    <i class="fas fa-times me-1"></i><?= __('Cancel') ?>
                </a>
            <?php endif; ?>
            <button type="button" id="et-validate-button"
                    class="btn btn-outline-secondary btn-sm"
                    @click="validate">
                <i class="fas fa-circle-check me-1"></i><?= __('Validate') ?>
            </button>
            <button type="button" id="et-save-button" class="btn btn-primary btn-sm"
                    :disabled="saving" @click="save">
                <i class="fas fa-check me-1"></i>
                <span x-text="saving ? '<?= __('Saving…') ?>' : '<?= __('Save') ?>'"></span>
            </button>
        </div>
    </div>

</div>
