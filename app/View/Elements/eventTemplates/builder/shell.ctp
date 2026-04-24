<?php
    echo $this->element('genericElements/assetLoader', [
        'js' => ['jquery-ui.min'],
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
.eventTemplates.builder { padding: 0 10px 20px 10px; }
.eventTemplates.builder h2 { margin-bottom: 10px; }
.eventTemplates.builder .et-envelope {
    background: #f7f7f7;
    border: 1px solid #ddd;
    border-radius: 4px;
    padding: 12px;
    margin-bottom: 12px;
}
.eventTemplates.builder .et-envelope .control-group { margin-bottom: 6px; }
.eventTemplates.builder .et-grid {
    display: grid;
    grid-template-columns: 200px 1fr 340px;
    gap: 10px;
    min-height: 420px;
}
.eventTemplates.builder .et-palette,
.eventTemplates.builder .et-canvas,
.eventTemplates.builder .et-properties-pane {
    background: #fff;
    border: 1px solid #ddd;
    border-radius: 4px;
    padding: 10px;
}
.eventTemplates.builder .et-palette h4,
.eventTemplates.builder .et-properties-pane h4 { margin-top: 0; }
.eventTemplates.builder .et-palette button { margin-bottom: 6px; width: 100%; text-align: left; }
.eventTemplates.builder .et-canvas-element {
    border: 1px solid #ddd;
    border-radius: 3px;
    padding: 8px 10px;
    margin-bottom: 6px;
    cursor: pointer;
    background: #fbfbfb;
}
.eventTemplates.builder .et-drag-handle {
    color: #aaa;
    cursor: grab;
    font-size: 14px;
    padding: 0 4px;
    user-select: none;
}
.eventTemplates.builder .et-drag-handle:hover { color: #555; }
.eventTemplates.builder .et-drag-handle:active { cursor: grabbing; }
.eventTemplates.builder .et-canvas-element.et-sortable-placeholder {
    border: 1px dashed #08c;
    background: #f0f8ff;
    height: 34px;
    visibility: visible !important;
}
.eventTemplates.builder .et-canvas-element.ui-sortable-helper {
    opacity: 0.85;
    box-shadow: 0 4px 10px rgba(0,0,0,0.1);
}
.eventTemplates.builder .et-canvas-element.selected {
    border-color: #08c;
    box-shadow: 0 0 0 1px #08c;
    background: #f0f8ff;
}
.eventTemplates.builder .et-element-header {
    display: flex;
    align-items: center;
    gap: 8px;
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
.eventTemplates.builder .et-delete-button { padding: 0 6px; line-height: 18px; }
.eventTemplates.builder .et-empty {
    color: #888;
    padding: 20px 0;
    font-style: italic;
    text-align: center;
}
.eventTemplates.builder .et-save-bar { margin-top: 14px; }
.eventTemplates.builder #et-errors:empty { display: none; }
.eventTemplates.builder .et-properties-pane .control-group { margin-bottom: 8px; }
.eventTemplates.builder .et-properties-pane .control-group > label { font-weight: 600; }
.eventTemplates.builder .et-properties-pane .control-group label.checkbox { font-weight: normal; }
.eventTemplates.builder .et-properties-pane .help-block { color: #888; font-size: 11px; }
</style>
<div class="eventTemplates builder form">
    <h2><?php echo h($pageTitle); ?></h2>
    <div id="et-errors"></div>

    <div class="et-envelope">
        <div class="control-group">
            <label for="et-envelope-name"><?php echo __('Name'); ?></label>
            <input type="text" id="et-envelope-name" class="input-block-level"
                   placeholder="<?php echo __('Spearphishing email triage'); ?>">
        </div>
        <div class="control-group">
            <label for="et-envelope-description"><?php echo __('Description (Markdown)'); ?></label>
            <textarea id="et-envelope-description" class="input-block-level" rows="2"></textarea>
        </div>
        <div class="control-group" style="display:flex; gap:12px; align-items:center;">
            <label for="et-envelope-distribution" style="margin:0;"><?php echo __('Distribution'); ?></label>
            <select id="et-envelope-distribution">
                <option value="0"><?php echo __('Org only'); ?></option>
                <option value="1"><?php echo __('Community'); ?></option>
            </select>
            <label class="checkbox inline" for="et-envelope-active">
                <input type="checkbox" id="et-envelope-active" checked>
                <?php echo __('Active'); ?>
            </label>
        </div>
    </div>

    <div class="et-grid">
        <div class="et-palette">
            <h4><?php echo __('Add element'); ?></h4>
            <?php foreach ($paletteButtons as $type => $meta): ?>
                <button type="button" class="btn btn-mini" data-et-add="<?php echo h($type); ?>">
                    <i class="fa fa-<?php echo h($meta['icon']); ?>"></i>
                    <?php echo h($meta['label']); ?>
                </button>
            <?php endforeach; ?>
        </div>

        <div class="et-canvas" id="et-canvas"></div>

        <div class="et-properties-pane">
            <div id="et-properties-empty" class="et-empty">
                <?php echo __('Select an element in the canvas to edit its properties.'); ?>
            </div>
            <div data-et-properties-for="section" style="display:none;">
                <?php echo $this->element('eventTemplates/builder/properties_section'); ?>
            </div>
            <div data-et-properties-for="text_block" style="display:none;">
                <?php echo $this->element('eventTemplates/builder/properties_text_block'); ?>
            </div>
            <div data-et-properties-for="attribute_field" style="display:none;">
                <?php echo $this->element('eventTemplates/builder/properties_attribute_field', [
                    'attributeCategoryDefinitions' => $attrCategories,
                ]); ?>
            </div>
            <div data-et-properties-for="object_field" style="display:none;">
                <?php echo $this->element('eventTemplates/builder/properties_object_field', [
                    'objectTemplatesAvailable' => $objectTemplates,
                ]); ?>
            </div>
            <div data-et-properties-for="tag_field" style="display:none;">
                <?php echo $this->element('eventTemplates/builder/properties_tag_field'); ?>
            </div>
            <div data-et-properties-for="galaxy_field" style="display:none;">
                <?php echo $this->element('eventTemplates/builder/properties_galaxy_field'); ?>
            </div>
            <div data-et-properties-for="file_field" style="display:none;">
                <?php echo $this->element('eventTemplates/builder/properties_file_field'); ?>
            </div>
            <div data-et-properties-for="object_reference" style="display:none;">
                <?php echo $this->element('eventTemplates/builder/properties_object_reference'); ?>
            </div>
        </div>
    </div>

    <div class="et-save-bar">
        <button type="button" id="et-save-button" class="btn btn-primary">
            <?php echo __('Save'); ?>
        </button>
        <button type="button" id="et-validate-button" class="btn">
            <?php echo __('Validate'); ?>
        </button>
        <span id="et-validate-status" style="margin-left:10px;"></span>
        <?php if ($existing): ?>
            <a href="<?php echo h($baseurl . '/event_templates/view/' . (int)$existing['id']); ?>"
               class="btn"><?php echo __('Cancel'); ?></a>
        <?php else: ?>
            <a href="<?php echo h($baseurl . '/event_templates/index'); ?>"
               class="btn"><?php echo __('Cancel'); ?></a>
        <?php endif; ?>
    </div>
</div>

<script>
    window.ET_BUILDER_CONFIG = {
        mode:       <?php echo json_encode($builderMode); ?>,
        submitUrl:  <?php echo json_encode($submitUrl); ?>,
        baseurl:    <?php echo json_encode($baseurl); ?>,
        envelope:   <?php echo json_encode($envelope); ?>,
        definition: <?php echo json_encode($initialDefinition); ?>,
        attrCategories: <?php echo json_encode($attrCategories); ?>,
        objectTemplates: <?php echo json_encode($objectTemplates); ?>
    };
</script>
<?php
    echo $this->Html->script('event-templates/builder');
    echo $this->element('/genericElements/SideMenu/side_menu', [
        'menuList' => 'eventTemplates',
        'menuItem' => $builderMode,
        'id'       => $existing ? (int)$existing['id'] : null,
    ]);
?>
