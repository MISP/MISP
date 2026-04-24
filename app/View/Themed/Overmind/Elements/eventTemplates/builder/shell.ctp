<?php
    // Load builder-only vendor assets. Gated to this view by virtue of
    // being requested from inside the element (not from the layout).
    // Alpine.js owns the builder state (Phase 3.3.1); SortableJS is
    // vendored for Phase 3.3.2's drag-and-drop refit and pre-loaded
    // here so 3.3.2 doesn't touch this asset block again.
    echo $this->element('genericElements/assetLoader', [
        'js' => [
            'vendor/sortablejs/Sortable.min',
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
        'object_reference' => ['label' => __('Object reference'), 'icon' => 'link'],
    ];
?>
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
#et-ot-picker-modal .et-ot-picker-item {
    display: block;
    padding: 8px 10px;
    border-bottom: 1px solid #eee;
    color: #333;
    text-decoration: none;
}
#et-ot-picker-modal .et-ot-picker-item:hover {
    background: #f0f8ff;
    text-decoration: none;
}
#et-ot-picker-modal .et-ot-picker-item strong { font-size: 13px; }
#et-ot-picker-modal .et-ot-picker-item .muted {
    color: #999; font-size: 11px; margin-left: 6px;
}
#et-ot-picker-modal .et-ot-picker-item .et-ot-desc {
    color: #666; font-size: 11px; margin-top: 2px;
    max-height: 3em; overflow: hidden;
}
#et-multipicker-modal .et-multipicker-item {
    display: block;
    padding: 6px 10px;
    border-bottom: 1px solid #f3f3f3;
    margin: 0;
    cursor: pointer;
}
#et-multipicker-modal .et-multipicker-item:hover { background: #f0f8ff; }
#et-multipicker-modal .et-multipicker-item input[type=checkbox] {
    margin-right: 8px;
}
#et-multipicker-modal .et-multipicker-label { font-weight: 500; }
#et-multipicker-modal .et-multipicker-desc {
    display: block; color: #888; font-size: 11px; margin-left: 24px;
}
.eventTemplates.builder .et-multipicker-summary { color: #333; }
.eventTemplates.builder .et-multipicker-summary .et-chip {
    display: inline-block;
    background: #eef4fa;
    border: 1px solid #cde1f2;
    border-radius: 3px;
    padding: 1px 6px;
    margin: 0 2px 2px 0;
    font-size: 11px;
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

<div class="eventTemplates builder container-fluid mt-3"
     x-data="etBuilder" x-cloak>

    <h2 class="fw-semibold mb-3"><?= h($pageTitle) ?></h2>

    <div class="alert alert-danger" x-show="errors.length">
        <strong><?= __('Could not save:') ?></strong>
        <ul class="mb-0">
            <template x-for="err in errors" :key="err">
                <li x-text="err"></li>
            </template>
        </ul>
    </div>

    <div class="card mb-3 shadow-sm et-envelope">
        <div class="card-body">
            <div class="row g-3">
                <div class="col-md-6">
                    <label for="et-envelope-name"
                           class="form-label fw-semibold small mb-1">
                        <?= __('Name') ?>
                    </label>
                    <input type="text" id="et-envelope-name"
                           class="form-control bg-light"
                           placeholder="<?= __('Spearphishing email triage') ?>"
                           x-model="envelope.name">
                </div>
                <div class="col-md-3">
                    <label for="et-envelope-distribution"
                           class="form-label fw-semibold small mb-1">
                        <?= __('Distribution') ?>
                    </label>
                    <select id="et-envelope-distribution"
                            class="form-select bg-light"
                            x-model.number="envelope.distribution">
                        <option value="0"><?= __('Org only') ?></option>
                        <option value="1"><?= __('Community') ?></option>
                    </select>
                </div>
                <div class="col-md-3 d-flex align-items-end pb-1">
                    <div class="form-check">
                        <input class="form-check-input" type="checkbox"
                               id="et-envelope-active"
                               x-model="envelope.active">
                        <label class="form-check-label" for="et-envelope-active">
                            <?= __('Active') ?>
                        </label>
                    </div>
                </div>
                <div class="col-12">
                    <label for="et-envelope-description"
                           class="form-label fw-semibold small mb-1">
                        <?= __('Description (Markdown)') ?>
                    </label>
                    <textarea id="et-envelope-description"
                              class="form-control bg-light" rows="2"
                              x-model="envelope.description"></textarea>
                </div>
            </div>
        </div>
    </div>

    <div class="row g-3">

        <!-- PALETTE -->
        <div class="col-lg-2 col-md-3">
            <div class="card shadow-sm et-palette">
                <div class="card-body">
                    <h4 class="h6 fw-semibold mb-3"><?= __('Add element') ?></h4>
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
        <div class="col-lg-6 col-md-5">
            <div class="card shadow-sm">
                <div class="card-body">
                    <div class="et-canvas" id="et-canvas" style="min-height:420px;">
                        <div class="et-empty" x-show="!hasElements">
                            <?= __('No elements yet. Use the palette on the left to add one.') ?>
                        </div>
                        <template x-for="el in definition.structure" :key="el.id">
                            <div class="et-canvas-element"
                                 :class="{ selected: el.id === selectedId }"
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
                                    <button type="button"
                                            class="btn btn-sm btn-outline-danger et-delete-button"
                                            title="<?= __('Delete element') ?>"
                                            @click.stop="removeElement(el.id)">
                                        <i class="fas fa-times"></i>
                                    </button>
                                </div>
                            </div>
                        </template>
                    </div>
                </div>
            </div>
        </div>

        <!-- PROPERTIES -->
        <div class="col-lg-4 col-md-4">
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
                    <div x-show="selectedType === 'object_reference'">
                        <?= $this->element('eventTemplates/builder/properties_object_reference') ?>
                    </div>
                </div>
            </div>
        </div>

    </div>

    <div class="et-save-bar d-flex align-items-center gap-2 mt-3">
        <button type="button" id="et-save-button" class="btn btn-primary"
                :disabled="saving" @click="save">
            <i class="fas fa-check me-1"></i>
            <span x-text="saving ? '<?= __('Saving…') ?>' : '<?= __('Save') ?>'"></span>
        </button>
        <button type="button" id="et-validate-button"
                class="btn btn-outline-secondary"
                @click="validate">
            <i class="fas fa-circle-check me-1"></i><?= __('Validate') ?>
        </button>
        <span id="et-validate-status" class="small ms-2"
              :class="{
                  'text-success': validateStatusKind === 'success',
                  'text-danger': validateStatusKind === 'error',
                  'text-muted': !validateStatusKind
              }"
              x-text="validateStatus"></span>
        <?php if ($existing): ?>
            <a href="<?= h($baseurl . '/event_templates/view/' . (int)$existing['id']) ?>"
               class="btn btn-outline-secondary ms-auto">
                <?= __('Cancel') ?>
            </a>
        <?php else: ?>
            <a href="<?= h($baseurl . '/event_templates/index') ?>"
               class="btn btn-outline-secondary ms-auto">
                <?= __('Cancel') ?>
            </a>
        <?php endif; ?>
    </div>

    <!-- Object-template picker (BS5 modal, Alpine-driven) -->
    <div id="et-ot-picker-modal" class="modal fade" tabindex="-1"
         aria-labelledby="et-ot-picker-title" aria-hidden="true">
        <div class="modal-dialog modal-lg modal-dialog-centered">
            <div class="modal-content">
                <div class="modal-header">
                    <h5 class="modal-title" id="et-ot-picker-title">
                        <?= __('Select an object template') ?>
                    </h5>
                    <button type="button" class="btn-close"
                            data-bs-dismiss="modal" data-dismiss="modal"
                            aria-label="<?= __('Close') ?>"></button>
                </div>
                <div class="modal-body">
                    <input type="text" id="et-ot-picker-search"
                           class="form-control bg-light mb-2"
                           placeholder="<?= __('Filter by name or meta-category…') ?>"
                           x-model="objectTemplateFilter">
                    <div class="border rounded"
                         style="max-height:55vh; overflow-y:auto;">
                        <template x-for="ot in filteredObjectTemplates" :key="ot.uuid">
                            <a href="#" class="et-ot-picker-item"
                               @click.prevent="pickObjectTemplate(ot.uuid, ot.name, ot.version)">
                                <strong x-text="ot.name"></strong>
                                <span class="muted">v<span x-text="ot.version"></span></span>
                                <span class="muted" x-text="ot.meta_category"></span>
                                <div class="et-ot-desc" x-show="ot.description"
                                     x-text="ot.description"></div>
                            </a>
                        </template>
                        <div class="text-muted p-3"
                             x-show="filteredObjectTemplates.length === 0">
                            <em><?= __('No object templates match the filter.') ?></em>
                        </div>
                    </div>
                </div>
                <div class="modal-footer">
                    <button type="button" class="btn btn-outline-secondary"
                            data-bs-dismiss="modal" data-dismiss="modal">
                        <?= __('Cancel') ?>
                    </button>
                </div>
            </div>
        </div>
    </div>

    <!-- Multipicker (BS5 modal, Alpine-driven) -->
    <div id="et-multipicker-modal" class="modal fade" tabindex="-1"
         aria-labelledby="et-multipicker-title" aria-hidden="true">
        <div class="modal-dialog modal-dialog-centered">
            <div class="modal-content">
                <div class="modal-header">
                    <h5 class="modal-title" id="et-multipicker-title"
                        x-text="multipickerTitle"></h5>
                    <button type="button" class="btn-close"
                            data-bs-dismiss="modal" data-dismiss="modal"
                            aria-label="<?= __('Close') ?>"></button>
                </div>
                <div class="modal-body">
                    <input type="text" id="et-multipicker-search"
                           class="form-control bg-light mb-2"
                           placeholder="<?= __('Filter…') ?>"
                           x-model="multipickerFilter">
                    <div class="border rounded"
                         style="max-height:55vh; overflow-y:auto;">
                        <template x-for="it in filteredMultipickerItems" :key="it.value">
                            <label class="et-multipicker-item">
                                <input type="checkbox" :value="it.value"
                                       :checked="!!multipickerSelected[it.value]"
                                       @change="multipickerSelected[it.value] = $event.target.checked">
                                <span class="et-multipicker-label" x-text="it.label"></span>
                                <span class="et-multipicker-desc"
                                      x-show="it.description"
                                      x-text="it.description"></span>
                            </label>
                        </template>
                        <div class="text-muted p-3"
                             x-show="filteredMultipickerItems.length === 0">
                            <em><?= __('No items available.') ?></em>
                        </div>
                    </div>
                </div>
                <div class="modal-footer">
                    <button type="button" class="btn btn-outline-secondary"
                            data-bs-dismiss="modal" data-dismiss="modal">
                        <?= __('Cancel') ?>
                    </button>
                    <button type="button" class="btn btn-primary"
                            id="et-multipicker-apply"
                            @click="applyMultipicker">
                        <?= __('Apply') ?>
                    </button>
                </div>
            </div>
        </div>
    </div>
</div>

<script>
    window.ET_BUILDER_CONFIG = {
        mode:       <?= json_encode($builderMode) ?>,
        submitUrl:  <?= json_encode($submitUrl) ?>,
        baseurl:    <?= json_encode($baseurl) ?>,
        envelope:   <?= json_encode($envelope) ?>,
        definition: <?= json_encode($initialDefinition) ?>,
        attrCategories: <?= json_encode($attrCategories) ?>,
        objectTemplates: <?= json_encode($objectTemplates) ?>,
        multipickerSources: <?= json_encode($multipickerSources) ?>
    };
</script>
<?php
    echo $this->Html->script('event-templates/builder-overmind');
?>
