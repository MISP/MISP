<?php
    $tpl = $data['EventTemplate'] ?? array();
    $structure = isset($definition['structure']) && is_array($definition['structure'])
        ? $definition['structure']
        : array();
    $templateDescription = isset($tpl['description']) ? (string)$tpl['description'] : '';
    $templateName = isset($tpl['name']) ? (string)$tpl['name'] : '';
    $specs = isset($objectRelationSpecs) ? $objectRelationSpecs : array();
    $isPreview = !empty($isPreview);
    $templateId = (int)($tpl['id'] ?? 0);
    $viewMode = isset($viewMode) && in_array($viewMode, array('all', 'wizard'), true) ? $viewMode : 'all';

    // object_reference elements never render into the user form — they
    // materialise at instantiation time based on the filled object_fields.
    $renderableTypes = array(
        'section', 'text_block', 'attribute_field', 'object_field',
        'tag_field', 'galaxy_field', 'file_field', 'event_report',
    );
?>
<style>
.event-template-user-form { padding: 0 10px 20px 10px; }
.event-template-user-form .et-preview-banner {
    background: #fff3cd; border: 1px solid #ffeeba; color: #856404;
    padding: 8px 12px; border-radius: 4px; margin-bottom: 12px;
}
.event-template-user-form .et-template-header { margin-bottom: 16px; }
.event-template-user-form .et-template-header h2 { margin-bottom: 6px; }
.event-template-user-form .et-template-description { color: #555; }
.event-template-user-form .et-errors-panel:empty { display: none; }
.event-template-user-form .et-errors-panel ul { margin-bottom: 0; }
.event-template-user-form .et-missing-mandatory {
    background: #f9e6e6; color: #933;
    padding: 6px 10px; border-radius: 3px; margin: 6px 0;
}
.event-template-user-form .et-value.et-invalid {
    border-color: #c33;
    box-shadow: 0 0 0 1px #c33;
}
.event-template-user-form .et-field.et-missing {
    outline: 2px solid #c33;
    outline-offset: 2px;
}
.event-template-user-form .et-object-entry {
    border: 1px solid #e1e1e1;
    border-radius: 3px;
    background: #fff;
    margin-bottom: 6px;
    padding: 0;
}
.event-template-user-form .et-object-entry-header {
    display: flex;
    align-items: center;
    gap: 8px;
    padding: 6px 10px;
    cursor: pointer;
    user-select: none;
}
.event-template-user-form .et-object-entry-header:hover { background: #f5f8fa; }
.event-template-user-form .et-object-toggle {
    background: none;
    border: 0;
    padding: 0;
    cursor: pointer;
    color: #333;
    font-weight: 500;
    display: inline-flex;
    align-items: center;
    gap: 4px;
}
.event-template-user-form .et-object-toggle .et-caret {
    display: inline-block;
    width: 10px;
    transition: transform 0.12s ease;
    color: #888;
}
.event-template-user-form .et-object-entry.et-open .et-object-toggle .et-caret {
    transform: rotate(90deg);
}
.event-template-user-form .et-object-entry.et-open .et-object-entry-title::before {
    content: attr(data-open-label);
}
.event-template-user-form .et-object-filled-indicator {
    font-size: 11px;
    padding: 1px 7px;
    border-radius: 10px;
    background: #efefef;
    color: #888;
    border: 1px solid #e0e0e0;
}
.event-template-user-form .et-object-filled-indicator[data-et-filled-state="filled"] {
    background: #e8f5e9;
    color: #2e7d32;
    border-color: #c8e6c9;
}
.event-template-user-form .et-object-filled-indicator[data-et-filled-state="missing"] {
    background: #fde8e8;
    color: #c62828;
    border-color: #f5c2c2;
}
.event-template-user-form .et-object-entry-body {
    padding: 8px 12px 10px 12px;
    border-top: 1px dashed #e1e1e1;
}
.event-template-user-form .et-section-group {
    background: #fff;
    border: 1px solid #d7dde3;
    border-radius: 5px;
    margin-bottom: 20px;
    box-shadow: 0 1px 2px rgba(0, 0, 0, 0.04);
}
.event-template-user-form .et-section-group + .et-section-group { margin-top: 0; }
.event-template-user-form .et-section-header {
    background: linear-gradient(#f7f9fc, #eef2f6);
    border-bottom: 1px solid #d7dde3;
    border-top-left-radius: 5px;
    border-top-right-radius: 5px;
    padding: 10px 14px;
    position: relative;
}
.event-template-user-form .et-section-header::before {
    content: '';
    position: absolute;
    left: 0; top: 0; bottom: 0;
    width: 4px;
    background: #4a90d9;
    border-top-left-radius: 5px;
    border-bottom-left-radius: 5px;
}
.event-template-user-form .et-section-title {
    margin: 0;
    font-size: 15px;
    font-weight: 600;
    color: #2c3e50;
    line-height: 1.3;
}
.event-template-user-form .et-section-help {
    margin-top: 4px;
    color: #5a6876;
    font-size: 12px;
}
.event-template-user-form .et-section-help p { margin: 0; }
.event-template-user-form .et-section-body {
    padding: 10px 14px 14px 14px;
}
.event-template-user-form .et-section-body > .et-field:first-child { margin-top: 0; }
/* A synthetic "untitled" group (content before the first section) has
   no header — round the body's top corners so the card still looks
   right. */
.event-template-user-form .et-section-group:not(:has(.et-section-header)) .et-section-body {
    border-top-left-radius: 5px;
    border-top-right-radius: 5px;
}
.event-template-user-form .et-view-toggle {
    display: flex;
    justify-content: flex-end;
    align-items: center;
    gap: 8px;
    margin-bottom: 8px;
    color: #555;
    font-size: 12px;
}
.event-template-user-form .et-view-toggle label.checkbox {
    margin: 0;
    display: inline-flex;
    align-items: center;
    gap: 4px;
    cursor: pointer;
    font-weight: 500;
}
.event-template-user-form .et-view-toggle input[type=checkbox] { margin: 0; }
.event-template-user-form .et-wizard-nav { display: none; }
.event-template-user-form.et-mode-wizard .et-wizard-nav {
    display: flex;
    justify-content: space-between;
    align-items: center;
    gap: 8px;
    padding: 8px 14px 12px 14px;
    border-top: 1px dashed #e1e1e1;
    margin-top: 6px;
}
.event-template-user-form .et-wizard-nav .et-step-counter {
    color: #777;
    font-size: 12px;
}
.event-template-user-form.et-mode-wizard .et-section-group { display: none; }
.event-template-user-form.et-mode-wizard .et-section-group.et-step-active { display: block; }
.event-template-user-form.et-mode-wizard .et-save-bar { display: none; }
.event-template-user-form.et-mode-wizard.et-on-last-step .et-save-bar { display: flex; }
</style>
<div class="event-template-user-form form">
    <?php if ($isPreview): ?>
        <div class="et-preview-banner">
            <strong><?php echo __('Preview mode'); ?>.</strong>
            <?php echo __('This is what a template user will see. No submit — use the Instantiate action on an event to run it for real.'); ?>
        </div>
    <?php endif; ?>

    <div class="et-template-header">
        <h2><?php echo h($templateName); ?></h2>
        <?php if ($templateDescription !== ''): ?>
            <div class="et-template-description">
                <?php echo $this->EventTemplateMarkdown->render($templateDescription); ?>
            </div>
        <?php endif; ?>
    </div>

    <div class="et-errors-panel" id="et-user-form-errors"></div>

    <div class="et-view-toggle">
        <label class="checkbox" for="et-wizard-toggle"
               title="<?php echo __('Show one section at a time with previous/next navigation. The choice is remembered for your account.'); ?>">
            <input type="checkbox" id="et-wizard-toggle"
                   <?php echo $viewMode === 'wizard' ? 'checked' : ''; ?>>
            <?php echo __('Step-by-step'); ?>
        </label>
    </div>

    <form id="et-user-form" data-et-template-id="<?php echo (int)$templateId; ?>"
          data-et-instantiate-url="<?php echo h($baseurl . '/event_templates/instantiate/' . $templateId); ?>">
        <?php
            // Pre-pass: group the flat structure list into section
            // buckets so each section + its children render inside a
            // single bordered card. A synthetic lead group holds any
            // content that appears before the first `section` element
            // (allowed by the schema; just rare in practice).
            $groups = array();
            $current = array('section' => null, 'children' => array());
            foreach ($structure as $el) {
                if (!is_array($el) || empty($el['type'])) { continue; }
                if ($el['type'] === 'section') {
                    if (!empty($current['children']) || $current['section'] !== null) {
                        $groups[] = $current;
                    }
                    $current = array('section' => $el, 'children' => array());
                    continue;
                }
                if (!in_array($el['type'], $renderableTypes, true)) { continue; }
                $current['children'][] = $el;
            }
            if (!empty($current['children']) || $current['section'] !== null) {
                $groups[] = $current;
            }
        ?>
        <?php foreach ($groups as $group): ?>
            <section class="et-section-group">
                <?php if ($group['section'] !== null): ?>
                    <?php echo $this->element('eventTemplates/userForm/section', array(
                        'element' => $group['section'],
                    )); ?>
                <?php endif; ?>
                <div class="et-section-body">
                    <?php foreach ($group['children'] as $child): ?>
                        <?php echo $this->element('eventTemplates/userForm/' . $child['type'], array(
                            'element' => $child,
                            'objectRelationSpecs' => $specs,
                        )); ?>
                    <?php endforeach; ?>
                </div>
            </section>
        <?php endforeach; ?>

        <div class="et-save-bar" style="margin-top:18px; display:flex; gap:8px; align-items:center;">
            <?php if ($isPreview): ?>
                <button type="button" class="btn" disabled>
                    <?php echo __('Create event (disabled in preview)'); ?>
                </button>
                <a class="btn"
                   href="<?php echo h($baseurl . '/event_templates/view/' . $templateId); ?>">
                    <?php echo __('Back to template'); ?>
                </a>
            <?php else: ?>
                <button type="button" id="et-user-form-submit" class="btn btn-primary">
                    <?php echo __('Create event'); ?>
                </button>
                <a class="btn"
                   href="<?php echo h($baseurl . '/event_templates/index'); ?>">
                    <?php echo __('Cancel'); ?>
                </a>
                <span id="et-user-form-status" style="color:#666;"></span>
            <?php endif; ?>
        </div>
    </form>
</div>

<div id="et-tag-picker-modal" class="modal hide fade" tabindex="-1" role="dialog" aria-hidden="true">
    <div class="modal-header">
        <button type="button" class="close" data-dismiss="modal" aria-hidden="true">×</button>
        <h3><?php echo __('Select tags'); ?></h3>
    </div>
    <div class="modal-body">
        <div id="et-tag-picker-restriction-hint" style="color:#666; font-size:11px; margin-bottom:6px;"></div>
        <input type="text" id="et-tag-picker-search" class="input-block-level"
               placeholder="<?php echo __('Filter by tag name…'); ?>">
        <div id="et-tag-picker-loading" style="color:#888; padding:10px;">
            <?php echo __('Loading tags…'); ?>
        </div>
        <div id="et-tag-picker-list" style="max-height:420px; overflow-y:auto; border:1px solid #eee; border-radius:3px;">
        </div>
    </div>
    <div class="modal-footer">
        <button type="button" class="btn" data-dismiss="modal">
            <?php echo __('Cancel'); ?>
        </button>
        <button type="button" class="btn btn-primary" id="et-tag-picker-apply">
            <?php echo __('Apply'); ?>
        </button>
    </div>
</div>

<style>
#et-tag-picker-modal { width: 560px; }
#et-tag-picker-modal label.et-tag-picker-item {
    display: block;
    padding: 5px 10px;
    border-bottom: 1px solid #f3f3f3;
    margin: 0;
    cursor: pointer;
}
#et-tag-picker-modal label.et-tag-picker-item:hover { background: #f0f8ff; }
#et-tag-picker-modal label.et-tag-picker-item input[type=checkbox] { margin-right: 8px; }
#et-tag-picker-modal .et-tag-swatch {
    display: inline-block;
    width: 10px; height: 10px;
    border: 1px solid rgba(0,0,0,0.15);
    border-radius: 2px;
    margin-right: 6px;
    vertical-align: baseline;
}
</style>

<div id="et-galaxy-picker-modal" class="modal hide fade" tabindex="-1" role="dialog" aria-hidden="true">
    <div class="modal-header">
        <button type="button" class="close" data-dismiss="modal" aria-hidden="true">×</button>
        <h3><?php echo __('Select galaxy clusters'); ?></h3>
    </div>
    <div class="modal-body">
        <div id="et-galaxy-picker-restriction-hint" style="color:#666; font-size:11px; margin-bottom:6px;"></div>
        <input type="text" id="et-galaxy-picker-search" class="input-block-level"
               placeholder="<?php echo __('Type to search clusters by name or description…'); ?>">
        <div id="et-galaxy-picker-status" style="color:#888; padding:8px 4px; min-height:20px;"></div>
        <div id="et-galaxy-picker-list" style="max-height:420px; overflow-y:auto; border:1px solid #eee; border-radius:3px;">
        </div>
    </div>
    <div class="modal-footer">
        <button type="button" class="btn" data-dismiss="modal">
            <?php echo __('Cancel'); ?>
        </button>
        <button type="button" class="btn btn-primary" id="et-galaxy-picker-apply">
            <?php echo __('Apply'); ?>
        </button>
    </div>
</div>

<style>
#et-galaxy-picker-modal { width: 560px; }
#et-galaxy-picker-modal label.et-galaxy-picker-item {
    display: block;
    padding: 5px 10px;
    border-bottom: 1px solid #f3f3f3;
    margin: 0;
    cursor: pointer;
}
#et-galaxy-picker-modal label.et-galaxy-picker-item:hover { background: #f0f8ff; }
#et-galaxy-picker-modal label.et-galaxy-picker-item input[type=checkbox] { margin-right: 8px; }
#et-galaxy-picker-modal .et-galaxy-picker-name { font-weight: 500; }
#et-galaxy-picker-modal .et-galaxy-picker-type {
    color: #888; font-size: 11px; margin-left: 6px;
}
#et-galaxy-picker-modal .et-galaxy-picker-desc {
    display: block;
    color: #666;
    font-size: 11px;
    margin-left: 24px;
    margin-top: 2px;
    max-height: 3em;
    overflow: hidden;
}
</style>

<?php
    // JSON_HEX_TAG / AMP / APOS / QUOT harden against HTML5 script-data
    // state-machine quirks for any DB-sourced strings landing here.
    $jsonScriptFlags = JSON_HEX_TAG | JSON_HEX_AMP | JSON_HEX_APOS | JSON_HEX_QUOT;
?>
<script>
    window.ET_USER_FORM_CONFIG = {
        baseurl:    <?php echo json_encode($baseurl, $jsonScriptFlags); ?>,
        templateId: <?php echo (int)$templateId; ?>,
        isPreview:  <?php echo $isPreview ? 'true' : 'false'; ?>,
        viewMode:   <?php echo json_encode($viewMode, $jsonScriptFlags); ?>
    };
</script>
<?php
    echo $this->Html->script('event-templates/user_form');
    echo $this->element('/genericElements/SideMenu/side_menu', array(
        'menuList' => 'eventTemplates',
        'menuItem' => $isPreview ? 'preview' : 'instantiate',
        'id'       => $templateId,
    ));
?>
