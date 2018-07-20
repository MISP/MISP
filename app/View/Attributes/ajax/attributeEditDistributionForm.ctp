<?php
    echo $this->Form->create('Attribute', array('class' => 'inline-form inline-field-form', 'id' => 'Attribute_' . $object['id'] . '_distribution_form', 'url' => '/attributes/editField/' . $object['id']));
?>
<div class='inline-input inline-input-container'>
    <div class="inline-input-accept inline-input-button inline-input-passive"><span class = "icon-ok" role="button" tabindex="0" aria-label="<?php echo __('Accept change'); ?>"></span></div>
    <div class="inline-input-decline inline-input-button inline-input-passive"><span class = "icon-remove" role="button" tabindex="0" aria-label="<?php echo __('Discard change'); ?>"></span></div>
    <?php
        echo $this->Form->input('distribution', array(
                'options' => array($distributionLevels),
                'label' => false,
                'selected' => $object['distribution'],
                'error' => array('escape' => false),
                'class' => 'inline-input',
                'id' => 'Attribute_' . $object['id'] . '_distribution_field',
                'div' => false
        ));
        echo $this->Form->end();
    ?>
</div>
