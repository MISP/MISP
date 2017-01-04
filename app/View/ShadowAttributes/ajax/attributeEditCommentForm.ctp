<?php
	echo $this->Form->create('ShadowAttribute', array('class' => 'inline-form inline-field-form', 'id' => 'ShadowAttribute_' . $object['id'] . '_comment_form', 'url' => '/shadow_attributes/editField/' . $object['id']));
?>
	<div class='inline-input inline-input-container'>
	<div class="inline-input-accept inline-input-button inline-input-passive"><span class = "icon-ok"></span></div>
	<div class="inline-input-decline inline-input-button inline-input-passive"><span class = "icon-remove"></span></div>
		<?php
			echo $this->Form->input('comment', array(
					'type' => 'textarea',
					'label' => false,
					'value' => $object['comment'],
					'error' => array('escape' => false),
					'class' => 'inline-input',
					'id' => 'ShadowAttribute' . '_' . $object['id'] . '_comment_field',
					'div' => false
			));
			echo $this->Form->end();
?>
	</div>
<?php
	echo $this->Form->end();
?>
