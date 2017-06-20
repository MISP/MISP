<?php
	echo $this->Form->create('Attribute', array('class' => 'inline-form inline-field-form', 'id' => 'Attribute_' . $object['id'] . '_comment_form', 'url' => '/attributes/editField/' . $object['id']));
?>
	<div class='inline-input inline-input-container'>
	<div class="inline-input-accept inline-input-button inline-input-passive"><span class = "icon-ok" role="button" tabindex="0" aria-label="Accept change"></span></div>
	<div class="inline-input-decline inline-input-button inline-input-passive"><span class = "icon-remove" role="button" tabindex="0" aria-label="Discard change"></span></div>
		<?php
			echo $this->Form->input('comment', array(
					'type' => 'textarea',
					'label' => false,
					'value' => $object['comment'],
					'error' => array('escape' => false),
					'class' => 'inline-input',
					'id' => 'Attribute' . '_' . $object['id'] . '_comment_field',
					'div' => false
			));
			echo $this->Form->end();
?>
	</div>
<?php
	echo $this->Form->end();
?>
