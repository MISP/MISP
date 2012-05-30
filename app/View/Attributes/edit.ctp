<div class="attributes form">
<?php echo $this->Form->create('Attribute');?>
	<fieldset>
		<legend><?php echo __('Edit Attribute'); ?></legend>
	<?php
		echo $this->Form->input('id');
		echo $this->Form->input('category', array('between' => $this->Html->div('forminfo', '', array('id'=> 'AttributeCategoryDiv'))));
		if($attachment) {
		    echo $this->Form->hidden('type', array('between' => $this->Html->div('forminfo', '', array('id'=> 'AttributeTypeDiv'))));
		    echo "<BR>Type: ".$this->Form->value('Attribute.type');
		} else {
    		echo $this->Form->input('type', array('between' => $this->Html->div('forminfo', '', array('id'=> 'AttributeTypeDiv'))));
		}
		if ('true' == Configure::read('CyDefSIG.sync')) {
		    echo $this->Form->input('private', array(
		            'before' => $this->Html->div('forminfo', isset($attr_descriptions['private']['formdesc']) ? $attr_descriptions['private']['formdesc'] : $attr_descriptions['private']['desc']),
		    ));
		}
		echo $this->Form->input('to_ids', array(
		    		'before' => $this->Html->div('forminfo', isset($attr_descriptions['signature']['formdesc']) ? $attr_descriptions['private']['formdesc'] : $attr_descriptions['private']['desc']),
		        	'label' => 'IDS Signature?'
		));
		if($attachment) {
		    echo $this->Form->hidden('value');
		    echo "<BR>Value: ".$this->Form->value('Attribute.value');
		} else {
		    echo $this->Form->input('value', array(
		            'type' => 'textarea',
					'error' => array('escape' => false),
		));
		}
		$this->Js->get('#AttributeType')->event('change', 'showFormInfo("#AttributeType")');
		$this->Js->get('#AttributeCategory')->event('change', 'showFormInfo("#AttributeCategory")');
		?>
	</fieldset>
<?php echo $this->Form->end(__('Submit'));?>
</div>
<div class="actions">
	<ul>
	    <li><?php echo $this->Form->postLink(__('Delete'), array('action' => 'delete', $this->Form->value('Attribute.id')), null, __('Are you sure you want to delete # %s?', $this->Form->value('Attribute.id'))); ?></li>
	    <li>&nbsp;</li>
		<?php echo $this->element('actions_menu'); ?>
	</ul>
</div>

<script type="text/javascript">



var formInfoValues = new Array();
<?php
	foreach ($type_definitions as $type => $def) {
		$info = isset($def['formdesc']) ? $def['formdesc'] : $def['desc'];
		// as we output JS code we need to add slashes
		echo "formInfoValues['".addslashes($type)."'] = \"".addslashes($info)."\";\n";
	}

	foreach ($category_definitions as $category => $def) {
		$info = isset($def['formdesc']) ? $def['formdesc'] : $def['desc'];
		// as we output JS code we need to add slashes
		echo "formInfoValues['".addslashes($category)."'] = \"".addslashes($info)."\";\n";
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
