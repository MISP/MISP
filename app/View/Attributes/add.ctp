
<div class="attributes form">
<?php echo $this->Form->create('Attribute');?>
	<fieldset>
		<legend><?php echo __('Add Attribute'); ?></legend>
	<?php
		echo $this->Form->hidden('event_id');
		echo $this->Form->input('category', array(
		        'between' => $this->Html->div('forminfo', '', array('id'=> 'AttributeCategoryDiv')),
		        ));
		echo $this->Form->input('type', array(
		        'between' => $this->Html->div('forminfo', '', array('id'=> 'AttributeTypeDiv')),
		        ));
		if ('true' == Configure::read('CyDefSIG.sync')) {
		    echo $this->Form->input('private', array(
		        'before' => $this->Html->div('forminfo', isset($attr_descriptions['private']['formdesc']) ? $attr_descriptions['private']['formdesc'] : $attr_descriptions['private']['desc']),
		));
		}
		echo $this->Form->input('to_ids', array(
		    		'checked' => true,
		    		'before' => $this->Html->div('forminfo', isset($attr_descriptions['signature']['formdesc']) ? $attr_descriptions['signature']['formdesc'] : $attr_descriptions['signature']['desc']),
		        	'label' => 'IDS Signature?'
		));
		echo $this->Form->input('value', array(
		            'type' => 'textarea',
					'error' => array('escape' => false),
		));
		echo $this->Form->input('batch_import', array(
				    'type' => 'checkbox',
					'after' => $this->Html->div('forminfo', 'Create multiple attributes one per line'),
		));

		// link an onchange event to the form elements
		$this->Js->get('#AttributeType')->event('change', 'showFormInfo("#AttributeType")');
		$this->Js->get('#AttributeCategory')->event('change', 'showFormInfo("#AttributeCategory")');
	?>
	</fieldset>
<?php echo $this->Form->end(__('Submit'));?>
</div>
<div class="actions">
	<ul>
        <?php echo $this->element('actions_menu'); ?>
    </ul>
</div>
<script type="text/javascript">

var formInfoValues = new Array();
<?php 
	foreach ($type_definitions as $type => $def) {
		$info = isset($def['formdesc']) ? $def['formdesc'] : $def['desc'];
		echo "formInfoValues['$type'] = \"$info\";\n";
	}
	
	foreach ($category_definitions as $category => $def) {
		$info = isset($def['formdesc']) ? $def['formdesc'] : $def['desc'];
		echo "formInfoValues['$category'] = \"$info\";\n";
	}
?>

function showFormInfo(id) {
	idDiv = id+'Div';
	// LATER use nice animations
	//$(idDiv).hide('fast');
	// change the content
	var value = $(id).val();    // get the selected value
	$(idDiv).html(formInfoValues[value]);    // search in a lookup table

	// show it again
	$(idDiv).fadeIn('slow');
}

// hide the formInfo things
$('#AttributeTypeDiv').hide();
$('#AttributeCategoryDiv').hide();

</script>
<?php echo $this->Js->writeBuffer(); // Write cached scripts ?>
