<?php
	echo $this->Form->create('ShadowAttribute', array('class' => 'inline-form inline-field-form', 'id' => 'ShadowAttribute_' . $object['id'] . '_value_form', 'action' => 'editField', 'default' => false));
?>
	<div class='inline-input inline-input-container'>	
	<div class="inline-input-accept inline-input-button inline-input-passive"><span class = "icon-ok"></span></div>	
	<div class="inline-input-decline inline-input-button inline-input-passive"><span class = "icon-remove"></span></div>	
<?php 
	echo $this->Form->input('value', array(
			'type' => 'textarea',
			'label' => false,
			'value' => h($object['value']),
			'error' => array('escape' => false),
			'class' => 'inline-input',
			'id' => 'ShadowAttribute_' . $object['id'] . '_value_field',
			'div' => false
	));
?>
	</div>
<?php 
	echo $this->Form->end();
?>
