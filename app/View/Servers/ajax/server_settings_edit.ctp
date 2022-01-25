<?= $this->Form->create('Server', [
    'class' => 'inline-form inline-field-form',
    'url' => $baseurl . '/servers/serverSettingsEdit/' . $setting['setting'] . '/' . $id . '/' . '1',
    'id' => 'setting_' . $subGroup . '_' . $id . '_form',
]); ?>
    <div class="inline-input inline-input-container">
    <div class="inline-input-accept inline-input-button inline-input-passive"><span class="fas fa-check" title="<?= __('Accept');?>" role="button" tabindex="0" aria-label="<?= __('Accept');?>"></span></div>
    <div class="inline-input-decline inline-input-button inline-input-passive"><span class="fas fa-times" title="<?= __('Cancel');?>" role="button" tabindex="0" aria-label="<?= __('Cancel');?>"></span></div>
<?php
if (!empty($setting['redacted'])) {
    $setting['value'] = '*****';
}
if (isset($setting['options'])) {
    echo $this->Form->input('value', array(
        'label' => false,
        'options' => $setting['options'],
        'value' => $setting['value'],
        'class' => 'inline-input',
        'id' => 'setting_' . $subGroup . '_' . $id . '_field',
        'div' => false
    ));
} else if ($setting['type'] === 'boolean') {
    echo $this->Form->input('value', array(
        'label' => false,
        'options' => array(false => 'false', true => 'true'),
        'value' => $setting['value'],
        'class' => 'inline-input',
        'id' => 'setting_' . $subGroup . '_' . $id . '_field',
        'div' => false
    ));
} else {
    $type = 'text';
    if (isset($setting['bigField'])) {
        $type = 'textarea';
    }
    if ($setting['type'] === 'numeric') {
        $type = 'number';
    }
    echo $this->Form->input('value', array(
        'type' => $type,
        'label' => false,
        'value' => $setting['value'],
        'error' => array('escape' => false),
        'class' => 'inline-input',
        'id' => 'setting_' . $subGroup . '_' . $id . '_field',
        'div' => false
    ));
}
?>
    </div>
<?= $this->Form->end();
