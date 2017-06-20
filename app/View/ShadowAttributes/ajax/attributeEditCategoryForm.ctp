<?php
	echo $this->Form->create('ShadowAttribute', array('class' => 'inline-form inline-field-form', 'id' => 'ShadowAttribute_' . $object['id'] . '_category_form', 'url' => '/shadow_attributes/editField/' . $object['id']));
?>
<div class='inline-input inline-input-container'>
<div class="inline-input-accept inline-input-button inline-input-passive"><span class = "icon-ok" title="Accept" role="button" tabindex="0" aria-label="Accept"></span></div>
<div class="inline-input-decline inline-input-button inline-input-passive"><span class = "icon-remove" title="Discard" role="button" tabindex="0" aria-label="Discard"></span></div>
<?php
	echo $this->Form->input('category', array(
		'options' => array(array_combine($typeCategory[$object['type']], $typeCategory[$object['type']])),
		'label' => false,
		'selected' => $object['category'],
		'error' => array('escape' => false),
		'class' => 'inline-input',
		'id' => 'ShadowAttribute_' . $object['id'] . '_category_field',
		'div' => false
	));
	echo $this->Form->end();
?>
</div>
