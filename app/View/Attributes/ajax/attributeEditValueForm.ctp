
<?php
    echo $this->Form->create('Attribute', array('class' => 'inline-form inline-field-form', 'url' => '/attributes/editField/' . $object['id'], 'id' => 'Attribute_' . $object['id'] . '_value_form', 'default' => false));
?>
    <div class='inline-input inline-input-container'>
    <div class="inline-input-accept inline-input-button inline-input-passive"><span class = "icon-ok" role="button" tabindex="0" aria-label="<?php echo __('Accept change'); ?>"></span></div>
    <div class="inline-input-decline inline-input-button inline-input-passive"><span class = "icon-remove" role="button" tabindex="0" aria-label="<?php echo __('Discard change'); ?>"></span></div>
<?php
    echo $this->Form->input('value', array(
            'type' => 'textarea',
            'label' => false,
            'value' => $object['value'],
            'error' => array('escape' => false),
            'class' => 'inline-input',
            'id' => 'Attribute_' . $object['id'] . '_value_field',
            'div' => false
    ));
?>
    </div>
<?php
    echo $this->Form->end();
?>
