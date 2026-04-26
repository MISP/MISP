<?php
    $tpl = $data['EventTemplate'] ?? [];
    $structure = isset($definition['structure']) && is_array($definition['structure'])
        ? $definition['structure']
        : [];
    $templateDescription = isset($tpl['description']) ? (string)$tpl['description'] : '';
    $templateName = isset($tpl['name']) ? (string)$tpl['name'] : '';
    $specs = isset($objectRelationSpecs) ? $objectRelationSpecs : [];
    $isPreview = !empty($isPreview);
    $templateId = (int)($tpl['id'] ?? 0);
    $viewMode = isset($viewMode) && in_array($viewMode, ['all', 'wizard'], true) ? $viewMode : 'all';

    // object_reference elements never render into the user form — they
    // materialise at instantiation time based on the filled object_fields.
    $renderableTypes = [
        'section', 'text_block', 'attribute_field', 'object_field',
        'tag_field', 'galaxy_field', 'file_field', 'event_report',
    ];
?>
<style>
.event-template-user-form .et-value.et-invalid {
    border-color: var(--bs-danger);
    box-shadow: 0 0 0 0.15rem rgba(var(--bs-danger-rgb), 0.25);
}
.event-template-user-form .et-field.et-missing {
    outline: 2px solid var(--bs-danger);
    outline-offset: 2px;
}
.event-template-user-form .et-object-entry.et-open .et-object-toggle .et-caret {
    transform: rotate(90deg);
}
.event-template-user-form .et-object-entry.et-open
    .et-object-entry-title::before { content: attr(data-open-label); }
.event-template-user-form .et-caret {
    display: inline-block;
    width: 10px;
    transition: transform 0.12s ease;
    color: #888;
}
.event-template-user-form
    .et-object-filled-indicator[data-et-filled-state="filled"] {
    background-color: #e8f5e9 !important;
    color: #2e7d32 !important;
    border-color: #c8e6c9 !important;
}
.event-template-user-form
    .et-object-filled-indicator[data-et-filled-state="missing"] {
    background-color: #fde8e8 !important;
    color: #c62828 !important;
    border-color: #f5c2c2 !important;
}
.event-template-user-form .et-view-toggle {
    display: flex;
    justify-content: flex-end;
    align-items: center;
    gap: 6px;
    margin-bottom: 8px;
}
.event-template-user-form .et-wizard-nav { display: none; }
.event-template-user-form.et-mode-wizard .et-wizard-nav {
    display: flex;
    justify-content: space-between;
    align-items: center;
    gap: 8px;
    padding: 8px 16px 14px 16px;
    border-top: 1px dashed var(--bs-border-color);
}
.event-template-user-form.et-mode-wizard .et-wizard-nav .et-step-counter {
    color: var(--bs-secondary);
    font-size: 0.85rem;
}
.event-template-user-form.et-mode-wizard .et-section-group { display: none; }
.event-template-user-form.et-mode-wizard .et-section-group.et-step-active { display: block; }
.event-template-user-form.et-mode-wizard .et-save-bar { display: none !important; }
.event-template-user-form.et-mode-wizard.et-on-last-step .et-save-bar { display: flex !important; }
</style>

<div class="event-template-user-form container mt-3">

    <?php if ($isPreview): ?>
        <div class="alert alert-warning et-preview-banner">
            <strong><?= __('Preview mode') ?>.</strong>
            <?= __('This is what a template user will see. No submit — use the Instantiate action on an event to run it for real.') ?>
        </div>
    <?php endif; ?>

    <div class="et-template-header mb-3">
        <h2 class="fw-semibold mb-2"><?= h($templateName) ?></h2>
        <?php if ($templateDescription !== ''): ?>
            <div class="et-template-description text-muted">
                <?= $this->EventTemplateMarkdown->render($templateDescription) ?>
            </div>
        <?php endif; ?>
    </div>

    <div class="et-errors-panel alert alert-danger"
         id="et-user-form-errors"
         style="display:none;"></div>

    <div class="et-view-toggle">
        <div class="form-check form-switch m-0"
             title="<?= __('Show one section at a time with previous/next navigation. The choice is remembered for your account.') ?>">
            <input class="form-check-input" type="checkbox" role="switch"
                   id="et-wizard-toggle"
                   <?= $viewMode === 'wizard' ? 'checked' : '' ?>>
            <label class="form-check-label small" for="et-wizard-toggle">
                <?= __('Step-by-step') ?>
            </label>
        </div>
    </div>

    <form id="et-user-form"
          data-et-template-id="<?= (int)$templateId ?>"
          data-et-instantiate-url="<?= h($baseurl . '/event_templates/instantiate/' . $templateId) ?>">
        <?php
            // Pre-pass: group the flat structure list into section
            // buckets so each section + its children render inside a
            // single bordered card. A synthetic lead group holds any
            // content that appears before the first `section` element
            // (allowed by the schema; just rare in practice).
            $groups = [];
            $current = ['section' => null, 'children' => []];
            foreach ($structure as $el) {
                if (!is_array($el) || empty($el['type'])) { continue; }
                if ($el['type'] === 'section') {
                    if (!empty($current['children']) || $current['section'] !== null) {
                        $groups[] = $current;
                    }
                    $current = ['section' => $el, 'children' => []];
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
            <section class="et-section-group card mb-3 shadow-sm">
                <?php if ($group['section'] !== null): ?>
                    <?= $this->element('eventTemplates/userForm/section', [
                        'element' => $group['section'],
                    ]) ?>
                <?php endif; ?>
                <div class="et-section-body card-body">
                    <?php foreach ($group['children'] as $child): ?>
                        <?= $this->element('eventTemplates/userForm/' . $child['type'], [
                            'element' => $child,
                            'objectRelationSpecs' => $specs,
                        ]) ?>
                    <?php endforeach; ?>
                </div>
            </section>
        <?php endforeach; ?>

        <div class="et-save-bar d-flex align-items-center gap-2 mt-3">
            <?php if ($isPreview): ?>
                <button type="button" class="btn btn-secondary" disabled>
                    <?= __('Create event (disabled in preview)') ?>
                </button>
                <a class="btn btn-outline-secondary"
                   href="<?= h($baseurl . '/event_templates/view/' . $templateId) ?>">
                    <?= __('Back to template') ?>
                </a>
            <?php else: ?>
                <button type="button" id="et-user-form-submit" class="btn btn-primary">
                    <i class="fas fa-bolt me-1"></i><?= __('Create event') ?>
                </button>
                <a class="btn btn-outline-secondary"
                   href="<?= h($baseurl . '/event_templates/index') ?>">
                    <?= __('Cancel') ?>
                </a>
                <span id="et-user-form-status" class="text-muted small"></span>
            <?php endif; ?>
        </div>
    </form>
</div>

<?php
    // JSON_HEX_TAG / AMP / APOS / QUOT harden against HTML5 script-data
    // state-machine quirks for any DB-sourced strings landing here.
    $jsonScriptFlags = JSON_HEX_TAG | JSON_HEX_AMP | JSON_HEX_APOS | JSON_HEX_QUOT;
?>
<script>
    window.ET_USER_FORM_CONFIG = {
        baseurl:    <?= json_encode($baseurl, $jsonScriptFlags) ?>,
        templateId: <?= (int)$templateId ?>,
        isPreview:  <?= $isPreview ? 'true' : 'false' ?>,
        viewMode:   <?= json_encode($viewMode, $jsonScriptFlags) ?>
    };
</script>
<?php
    // user_form.js handles submit, mandatory-field guard, file
    // upload encoding, and the default-theme tag-picker modal flow.
    // user_form_overmind.js layers Tom Select pickers on top for
    // tag and galaxy fields — values are written into the same
    // hidden .et-value inputs user_form.js already serialises on
    // POST to /instantiate, so the submit path is unchanged.
    echo $this->Html->script('event-templates/user_form');
    echo $this->Html->script('event-templates/user_form_overmind');
?>
