<?php
    // Load builder-only vendor assets. Gated to this view by virtue of
    // being requested from inside the element (not from the layout).
    // jquery-ui drives the current (Phase-2) drag-and-drop;
    // SortableJS + Alpine.js are vendored for Phase 3.3's refit and
    // loaded here so both JS bundles can coexist once 3.3 lands.
    echo $this->element('genericElements/assetLoader', [
        'js' => [
            'jquery-ui.min',
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
.eventTemplates.builder .et-canvas-element.et-sortable-placeholder {
    border: 1px dashed var(--bs-primary);
    background: rgba(var(--bs-primary-rgb), 0.08);
    height: 34px;
    visibility: visible !important;
}
.eventTemplates.builder .et-canvas-element.ui-sortable-helper {
    opacity: 0.85;
    box-shadow: 0 4px 10px rgba(0,0,0,0.1);
}
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
#et-ot-picker-modal .et-ot-picker-item:hover,
#et-ot-picker-modal .et-ot-picker-item.et-highlight {
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
#et-multipicker-modal label.et-multipicker-item {
    display: block;
    padding: 6px 10px;
    border-bottom: 1px solid #f3f3f3;
    margin: 0;
    cursor: pointer;
}
#et-multipicker-modal label.et-multipicker-item:hover { background: #f0f8ff; }
#et-multipicker-modal label.et-multipicker-item input[type=checkbox] {
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

<div class="eventTemplates builder container-fluid mt-3">

    <h2 class="fw-semibold mb-3"><?= h($pageTitle) ?></h2>

    <div id="et-errors" class="alert alert-danger"
         style="display:none;"></div>

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
                           placeholder="<?= __('Spearphishing email triage') ?>">
                </div>
                <div class="col-md-3">
                    <label for="et-envelope-distribution"
                           class="form-label fw-semibold small mb-1">
                        <?= __('Distribution') ?>
                    </label>
                    <select id="et-envelope-distribution"
                            class="form-select bg-light">
                        <option value="0"><?= __('Org only') ?></option>
                        <option value="1"><?= __('Community') ?></option>
                    </select>
                </div>
                <div class="col-md-3 d-flex align-items-end pb-1">
                    <div class="form-check">
                        <input class="form-check-input" type="checkbox"
                               id="et-envelope-active" checked>
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
                              class="form-control bg-light" rows="2"></textarea>
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
                                data-et-add="<?= h($type) ?>">
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
                    <div class="et-canvas" id="et-canvas" style="min-height:420px;"></div>
                </div>
            </div>
        </div>

        <!-- PROPERTIES -->
        <div class="col-lg-4 col-md-4">
            <div class="card shadow-sm et-properties-pane">
                <div class="card-body">
                    <div id="et-properties-empty" class="et-empty">
                        <?= __('Select an element in the canvas to edit its properties.') ?>
                    </div>
                    <div data-et-properties-for="section" style="display:none;">
                        <?= $this->element('eventTemplates/builder/properties_section') ?>
                    </div>
                    <div data-et-properties-for="text_block" style="display:none;">
                        <?= $this->element('eventTemplates/builder/properties_text_block') ?>
                    </div>
                    <div data-et-properties-for="attribute_field" style="display:none;">
                        <?= $this->element('eventTemplates/builder/properties_attribute_field', [
                            'attributeCategoryDefinitions' => $attrCategories,
                        ]) ?>
                    </div>
                    <div data-et-properties-for="object_field" style="display:none;">
                        <?= $this->element('eventTemplates/builder/properties_object_field', [
                            'objectTemplatesAvailable' => $objectTemplates,
                        ]) ?>
                    </div>
                    <div data-et-properties-for="tag_field" style="display:none;">
                        <?= $this->element('eventTemplates/builder/properties_tag_field') ?>
                    </div>
                    <div data-et-properties-for="galaxy_field" style="display:none;">
                        <?= $this->element('eventTemplates/builder/properties_galaxy_field') ?>
                    </div>
                    <div data-et-properties-for="file_field" style="display:none;">
                        <?= $this->element('eventTemplates/builder/properties_file_field') ?>
                    </div>
                    <div data-et-properties-for="object_reference" style="display:none;">
                        <?= $this->element('eventTemplates/builder/properties_object_reference') ?>
                    </div>
                </div>
            </div>
        </div>

    </div>

    <div class="et-save-bar d-flex align-items-center gap-2 mt-3">
        <button type="button" id="et-save-button" class="btn btn-primary">
            <i class="fas fa-check me-1"></i><?= __('Save') ?>
        </button>
        <button type="button" id="et-validate-button"
                class="btn btn-outline-secondary">
            <i class="fas fa-circle-check me-1"></i><?= __('Validate') ?>
        </button>
        <span id="et-validate-status" class="text-muted small ms-2"></span>
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
</div>

<!-- Object-template picker (BS5 modal) -->
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
                       placeholder="<?= __('Filter by name or meta-category…') ?>">
                <div id="et-ot-picker-list"
                     class="border rounded"
                     style="max-height:55vh; overflow-y:auto;">
                    <?php foreach ($objectTemplates as $ot): ?>
                        <a href="#" class="et-ot-picker-item"
                           data-uuid="<?= h($ot['uuid']) ?>"
                           data-name="<?= h($ot['name']) ?>"
                           data-version="<?= h($ot['version']) ?>"
                           data-meta="<?= h($ot['meta_category']) ?>"
                           data-search="<?= h(strtolower($ot['name'] . ' ' . $ot['meta_category'] . ' ' . $ot['description'])) ?>">
                            <strong><?= h($ot['name']) ?></strong>
                            <span class="muted">v<?= h($ot['version']) ?></span>
                            <span class="muted"><?= h($ot['meta_category']) ?></span>
                            <?php if (!empty($ot['description'])): ?>
                                <div class="et-ot-desc">
                                    <?= h($ot['description']) ?>
                                </div>
                            <?php endif; ?>
                        </a>
                    <?php endforeach; ?>
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

<!-- Multipicker (BS5 modal) — used for taxonomy & galaxy-type restrictions -->
<div id="et-multipicker-modal" class="modal fade" tabindex="-1"
     aria-labelledby="et-multipicker-title" aria-hidden="true">
    <div class="modal-dialog modal-dialog-centered">
        <div class="modal-content">
            <div class="modal-header">
                <h5 class="modal-title" id="et-multipicker-title">
                    <?= __('Select items') ?>
                </h5>
                <button type="button" class="btn-close"
                        data-bs-dismiss="modal" data-dismiss="modal"
                        aria-label="<?= __('Close') ?>"></button>
            </div>
            <div class="modal-body">
                <input type="text" id="et-multipicker-search"
                       class="form-control bg-light mb-2"
                       placeholder="<?= __('Filter…') ?>">
                <div id="et-multipicker-list"
                     class="border rounded"
                     style="max-height:55vh; overflow-y:auto;">
                    <!-- populated by JS on open -->
                </div>
            </div>
            <div class="modal-footer">
                <button type="button" class="btn btn-outline-secondary"
                        data-bs-dismiss="modal" data-dismiss="modal">
                    <?= __('Cancel') ?>
                </button>
                <button type="button" class="btn btn-primary"
                        id="et-multipicker-apply">
                    <?= __('Apply') ?>
                </button>
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
    echo $this->Html->script('event-templates/builder');
?>
