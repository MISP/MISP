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

    // object_reference elements never render into the user form — they
    // materialise at instantiation time based on the filled object_fields.
    $renderableTypes = array(
        'section', 'text_block', 'attribute_field', 'object_field',
        'tag_field', 'galaxy_field', 'file_field',
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

    <form id="et-user-form" data-et-template-id="<?php echo (int)$templateId; ?>"
          data-et-instantiate-url="<?php echo h($baseurl . '/event_templates/instantiate/' . $templateId); ?>">
        <?php foreach ($structure as $element): ?>
            <?php if (!is_array($element) || empty($element['type'])) { continue; } ?>
            <?php if (!in_array($element['type'], $renderableTypes, true)) { continue; } ?>
            <?php echo $this->element('eventTemplates/userForm/' . $element['type'], array(
                'element' => $element,
                'objectRelationSpecs' => $specs,
            )); ?>
        <?php endforeach; ?>

        <div style="margin-top:18px; display:flex; gap:8px; align-items:center;">
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

<script>
    window.ET_USER_FORM_CONFIG = {
        baseurl:    <?php echo json_encode($baseurl); ?>,
        templateId: <?php echo (int)$templateId; ?>,
        isPreview:  <?php echo $isPreview ? 'true' : 'false'; ?>
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
