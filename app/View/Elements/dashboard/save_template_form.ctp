<?php
/**
 * Save / edit dashboard template — form partial (shared).
 *
 * Extracted from Dashboards/save_template.ctp so the exact same form (fields
 * + CSRF token) renders in BOTH the full-page flow and, layout-less, inside
 * the dashboard slide-in panel (DashboardsController::saveTemplate's AJAX
 * branch → save_template_form_ajax.ctp). Single source of truth for the form.
 *
 * Self-contained: derives its values from $this->request->data plus the
 * controller-set view vars ($options, $isSiteAdmin, $isUpdate, $updateRef) —
 * see DashboardsController::saveTemplate (data contract unchanged).
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
       class="misp-dashboard-btn"
       data-misp-template-form-action="cancel">
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
