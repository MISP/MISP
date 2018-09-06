<?php
    echo $this->Form->create('Server', array('class' => 'inline-form inline-field-form', 'url' => '/servers/serverSettingsEdit/' . $setting['setting'] . '/' . $id . '/' . '1', 'id' => 'setting_' . $subGroup . '_' . $id . '_form'));
?>
    <div class='inline-input inline-input-container'>
    <div class="inline-input-accept inline-input-button inline-input-passive"><span class = "icon-ok" title="<?php echo __('Accept');?>" role="button" tabindex="0" aria-label="<?php echo __('Accept');?>"></span></div>
    <div class="inline-input-decline inline-input-button inline-input-passive"><span class = "icon-remove" title="<?php echo __('Cancel');?>" role="button" tabindex="0" aria-label="<?php echo __('Cancel');?>"></span></div>
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

    } else if ($setting['type'] == 'boolean') {
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
        if (isset($setting['bigField'])) $type = 'textarea';
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
<?php
    echo $this->Form->end();
?>
