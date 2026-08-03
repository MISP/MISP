<?php
/**
 * Inline editor for a single server setting.
 *
 */

if (!empty($setting['redacted'])) {
    $setting['value'] = '*****';
}

$fieldId = 'setting_value_field_' . h($id);
$isSelect = isset($setting['options']) || $setting['type'] === 'boolean';

$fieldOptions = array(
    'label' => false,
    'div' => false,
    'value' => $setting['value'],
    'id' => $fieldId,
    'class' => ($isSelect ? 'form-select form-select-sm' : 'form-control form-control-sm') . ' ss-input',
);

if (isset($setting['options'])) {
    $fieldOptions['options'] = $setting['options'];
} elseif ($setting['type'] === 'boolean') {
    // Labels stay untranslated: they are the literal values the row displays.
    $fieldOptions['options'] = array(0 => 'false', 1 => 'true');
    $fieldOptions['value'] = empty($setting['value']) ? 0 : 1;
} elseif (!empty($setting['bigField'])) {
    $fieldOptions['type'] = 'textarea';
    $fieldOptions['rows'] = 4;
} elseif ($setting['type'] === 'numeric') {
    $fieldOptions['type'] = 'number';
} else {
    $fieldOptions['type'] = 'text';
    $fieldOptions['error'] = array('escape' => false);
}
?>
<?= $this->Form->create('Server', array(
    'class' => 'ss-edit-form d-flex align-items-start gap-1 mt-1',
    'url' => $baseurl . '/servers/serverSettingsEdit/' . $setting['setting'] . '/' . $id . '/1',
    'id' => 'setting_form_' . h($id),
)) ?>
    <div class="flex-grow-1">
        <?= $this->Form->input('value', $fieldOptions) ?>
    </div>
    <button type="submit" class="btn btn-sm btn-success" data-ss-accept
            title="<?= h(__('Save')) ?>" aria-label="<?= h(__('Save')) ?>">
        <i class="fas fa-check"></i>
    </button>
    <button type="button" class="btn btn-sm btn-outline-secondary" data-ss-cancel
            title="<?= h(__('Cancel')) ?>" aria-label="<?= h(__('Cancel')) ?>">
        <i class="fas fa-times"></i>
    </button>
<?= $this->Form->end() ?>
