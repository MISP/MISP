<?php
/**
 * Save / edit dashboard template form (PRD §5.4, Phase 4 task 5).
 *
 * Renders inside Layouts/dashboard.ctp (DD-08) — same chrome as the
 * template gallery view. Replaces the v1 modal flow
 * (openGenericModal('/dashboards/saveTemplate/...')) with an in-page
 * surface; the controller's POST handling and REST response shape
 * stay unchanged so the action's wire shape is preserved (Phase 4
 * task 7 wire ratification rides along).
 *
 * Data contract (set by DashboardsController::saveTemplate):
 *   - options: { org_id => [id => label, ...],
 *                role_id => [id => label, ...],
 *                role_perms => [flag => label, ...] }
 *     Each pre-fixed with `0 => "Unrestricted"` so the SQL value 0
 *     round-trips through the dropdown without re-indexing.
 *   - isSiteAdmin (bool): site-admins see the restrict_to_* fields
 *     and the "Default" checkbox; non-site-admins do not (the model
 *     enforces the same gate on save via editableFields).
 *   - isUpdate (bool), updateRef (id|uuid|false): drives the form's
 *     action attribute and the page title.
 *   - request->data['Dashboard']: pre-fill payload when editing.
 */
$baseurl = Configure::read('MISP.baseurl') ?: '';
$existing = isset($this->request->data['Dashboard'])
    ? $this->request->data['Dashboard']
    : array();
$nameVal = isset($existing['name']) ? $existing['name'] : '';
$descVal = isset($existing['description']) ? $existing['description'] : '';
$selectable = !empty($existing['selectable']);
$default = !empty($existing['default']);
$restrictOrg = isset($existing['restrict_to_org_id'])
    ? (int)$existing['restrict_to_org_id']
    : 0;
$restrictRole = isset($existing['restrict_to_role_id'])
    ? (int)$existing['restrict_to_role_id']
    : 0;
$restrictPerm = isset($existing['restrict_to_permission_flag'])
    ? $existing['restrict_to_permission_flag']
    : 0;

$formUrl = '/dashboards/saveTemplate';
if ($isUpdate && !empty($updateRef)) {
    $formUrl .= '/' . rawurlencode($updateRef);
}
?>
<header class="misp-dashboard-header misp-template-form-header">
    <div class="misp-template-gallery-title-block">
        <h1 class="misp-dashboard-title">
            <?= $isUpdate
                ? __('Edit dashboard template')
                : __('Save dashboard template') ?>
        </h1>
        <p class="misp-template-gallery-subtitle">
            <?= $isUpdate
                ? __('Update this template\'s metadata. The widget layout itself is unchanged — use "Save current dashboard as template" to capture a new layout.')
                : __('Save your current dashboard layout as a template that you or other users can reuse.') ?>
        </p>
    </div>
    <div class="misp-dashboard-modecontrols">
        <a href="<?= h($baseurl) ?>/dashboards/listTemplates"
           class="misp-dashboard-btn"
           data-misp-template-form-action="cancel"
           title="<?= __('Return to the template gallery without saving') ?>">
            <?= __('← Back to gallery') ?>
        </a>
    </div>
</header>

<main class="misp-dashboard-page-main misp-template-form-page">
    <section class="misp-template-form-card" aria-labelledby="misp-template-form-title">
        <h2 id="misp-template-form-title" class="visually-hidden">
            <?= $isUpdate
                ? __('Edit dashboard template')
                : __('Save dashboard template') ?>
        </h2>
        <?php
            echo $this->Form->create('Dashboard', array(
                'url' => $formUrl,
                'type' => 'post',
                'novalidate' => true,
                'class' => 'misp-template-form',
                'id' => 'DashboardSaveTemplateForm',
                'inputDefaults' => array(
                    'label' => false,
                    'div' => false,
                    'class' => 'misp-field-input',
                ),
            ));
        ?>

        <div class="misp-template-form-grid">
            <label class="misp-field misp-field--span-2">
                <span class="misp-field-label">
                    <?= __('Template name') ?>
                    <span class="misp-field-required" aria-hidden="true">*</span>
                </span>
                <?= $this->Form->text('name', array(
                    'class' => 'misp-field-input',
                    'value' => $nameVal,
                    'required' => true,
                    'maxlength' => 191,
                    'autofocus' => true,
                    'autocomplete' => 'off',
                    'aria-required' => 'true',
                )) ?>
                <span class="misp-field-help">
                    <?= __('Shown as the card title in the gallery.') ?>
                </span>
            </label>

            <label class="misp-field misp-field--span-2">
                <span class="misp-field-label"><?= __('Description') ?></span>
                <?= $this->Form->textarea('description', array(
                    'class' => 'misp-field-input misp-template-form-textarea',
                    'value' => $descVal,
                    'rows' => 3,
                )) ?>
                <span class="misp-field-help">
                    <?= __('A short blurb explaining what this template is for. Shown under the title in the gallery.') ?>
                </span>
            </label>

            <fieldset class="misp-field misp-field--span-2 misp-template-form-toggles">
                <legend class="visually-hidden"><?= __('Visibility') ?></legend>
                <label class="misp-template-form-toggle">
                    <?= $this->Form->checkbox('selectable', array(
                        'checked' => $selectable,
                        'class' => 'misp-template-form-checkbox',
                    )) ?>
                    <span class="misp-template-form-toggle-label">
                        <span class="misp-field-label"><?= __('Selectable') ?></span>
                        <span class="misp-field-help">
                            <?= __('Allow other users (subject to the restrictions below) to pick this template from their gallery.') ?>
                        </span>
                    </span>
                </label>
                <?php if (!empty($isSiteAdmin)): ?>
                <label class="misp-template-form-toggle">
                    <?= $this->Form->checkbox('default', array(
                        'checked' => $default,
                        'class' => 'misp-template-form-checkbox',
                    )) ?>
                    <span class="misp-template-form-toggle-label">
                        <span class="misp-field-label"><?= __('Default') ?></span>
                        <span class="misp-field-help">
                            <?= __('Promote this template to be the system-wide default for users who have no dashboard saved yet. At most one template can hold this flag — saving with it set will demote any other default.') ?>
                        </span>
                    </span>
                </label>
                <?php endif; ?>
            </fieldset>

            <?php if (!empty($isSiteAdmin)): ?>
            <fieldset class="misp-field misp-field--span-2 misp-template-form-restrict">
                <legend class="misp-template-form-restrict-legend">
                    <?= __('Visibility restrictions (site-admin only)') ?>
                </legend>
                <p class="misp-field-help misp-template-form-restrict-blurb">
                    <?= __('Limit who can pick this template from their gallery. A non-zero value here AND the "Selectable" flag must both be set for the restriction to take effect — restricted templates are always visible to their owner.') ?>
                </p>

                <label class="misp-field">
                    <span class="misp-field-label"><?= __('Restrict to organisation') ?></span>
                    <?= $this->Form->select('restrict_to_org_id', $options['org_id'], array(
                        'class' => 'misp-field-input misp-field-select',
                        'value' => $restrictOrg,
                        'empty' => false,
                    )) ?>
                </label>

                <label class="misp-field">
                    <span class="misp-field-label"><?= __('Restrict to role') ?></span>
                    <?= $this->Form->select('restrict_to_role_id', $options['role_id'], array(
                        'class' => 'misp-field-input misp-field-select',
                        'value' => $restrictRole,
                        'empty' => false,
                    )) ?>
                </label>

                <label class="misp-field">
                    <span class="misp-field-label"><?= __('Restrict to permission flag') ?></span>
                    <?= $this->Form->select('restrict_to_permission_flag', $options['role_perms'], array(
                        'class' => 'misp-field-input misp-field-select',
                        'value' => $restrictPerm,
                        'empty' => false,
                    )) ?>
                </label>
            </fieldset>
            <?php endif; ?>
        </div>

        <footer class="misp-template-form-footer">
            <a href="<?= h($baseurl) ?>/dashboards/listTemplates"
               class="misp-dashboard-btn">
                <?= __('Cancel') ?>
            </a>
            <button type="submit"
                    class="misp-dashboard-btn misp-dashboard-btn-primary"
                    data-misp-template-form-action="submit">
                <?= $isUpdate
                    ? __('Save changes')
                    : __('Save as template') ?>
            </button>
        </footer>

        <?= $this->Form->end() ?>
    </section>
</main>
