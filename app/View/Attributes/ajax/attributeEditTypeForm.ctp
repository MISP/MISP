<?php
    echo $this->Form->create('Attribute', array('class' => 'inline-form inline-field-form', 'id' => 'Attribute_' . $object['id'] . '_type_form', 'url' => '/attributes/editField/' . $object['id']));
?>
<div class='inline-input inline-input-container'>
    <div class="inline-input-accept inline-input-button inline-input-passive"><span class = "icon-ok" role="button" tabindex="0" aria-label="<?php echo __('Accept change'); ?>"></span></div>
    <div class="inline-input-decline inline-input-button inline-input-passive"><span class = "icon-remove" role="button" tabindex="0" aria-label="<?php echo __('Discard change'); ?>"></span></div>
<?php
    echo $this->Form->input('type', array(
        'options' => array(array_combine($categoryDefinitions[$object['category']]['types'], $categoryDefinitions[$object['category']]['types'])),
        'label' => false,
        'selected' => $object['type'],
        'error' => array('escape' => false),
        'class' => 'inline-input',
        'id' => 'Attribute_' . $object['id'] . '_type_field',
        'div' => false
    ));
    echo $this->Form->end();
?>
</div>
