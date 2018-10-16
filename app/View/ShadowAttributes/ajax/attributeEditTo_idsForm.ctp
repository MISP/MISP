<?php
    echo $this->Form->create('ShadowAttribute', array('class' => 'inline-form inline-field-form', 'id' => 'Attribute' . '_' . $object['id'] . '_to_ids_form', 'url' => '/shadow_attributes/editField/' . $object['id']));
?>
    <div class='inline-input inline-input-container'>
    <div class="inline-input-accept inline-input-button inline-input-passive"><span class = "icon-ok" title="<?php echo __('Accept');?>" role="button" tabindex="0" aria-label="<?php echo __('Accept');?>"></span></div>
    <div class="inline-input-decline inline-input-button inline-input-passive"><span class = "icon-remove" title="<?php echo __('Discard');?>" role="button" tabindex="0" aria-label="<?php echo __('Discard');?>"></span></div>
<?php
    $current = 0;
    if ($object['to_ids']) $current = 1;
    echo $this->Form->input('to_ids', array(
            'options' => array(0 => 'No', 1 => 'Yes'),
            'label' => false,
            'selected' => $current,
            'class' => 'inline-input',
            'id' => 'ShadowAttribute' . '_' . $object['id'] . '_to_ids_field',
            'div' => false
    ));
    echo $this->Form->end();
?>
</div>
