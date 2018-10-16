<?php
    echo $this->Form->create('Event', array('class' => 'inline-form inline-field-form', 'url' => '/events/quickEdit/' . $event['Event']['id'] . '/' . $field));
?>
<div class='inline-input inline-input-container'>
<div class="inline-input-accept inline-input-button inline-input-passive"><span class = "icon-ok" title="<?php echo __('Accept');?>" role="button" tabindex="0" aria-label="<?php echo __('Accept');?>"></span></div>
<div class="inline-input-decline inline-input-button inline-input-passive"><span class = "icon-remove" title="<?php echo __('Cancel');?>" role="button" tabindex="0" aria-label="<?php echo __('Cancel');?>"></span></div>
<?php
    echo $this->Form->input('category', array(
        'options' => array(array_combine($typeCategory[$object['type']], $typeCategory[$object['type']])),
        'label' => false,
        'selected' => $object['category'],
        'error' => array('escape' => false),
        'class' => 'inline-input',
        'id' => 'Attribute_' . $object['id'] . '_category_field',
        'div' => false
    ));
    echo $this->Form->end();
?>
</div>
