<?php
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
    grid-template-columns: 200px 1fr 320px;
    gap: 10px;
    min-height: 400px;
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
</style>
<div class="eventTemplates builder">
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
            <button type="button" class="btn btn-mini" data-et-add="section">
                <i class="fa fa-folder"></i> <?php echo __('Section'); ?>
            </button>
            <button type="button" class="btn btn-mini" data-et-add="text_block">
                <i class="fa fa-align-left"></i> <?php echo __('Text block'); ?>
            </button>
            <div style="margin-top:10px; font-size:11px; color:#888;">
                <?php echo __('Attribute / object / tag / galaxy / file / reference element types land in the next builder commit.'); ?>
            </div>
        </div>

        <div class="et-canvas" id="et-canvas"></div>

        <div class="et-properties-pane" id="et-properties"></div>
    </div>

    <div class="et-save-bar">
        <button type="button" id="et-save-button" class="btn btn-primary">
            <?php echo __('Save'); ?>
        </button>
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
        definition: <?php echo json_encode($initialDefinition); ?>
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
