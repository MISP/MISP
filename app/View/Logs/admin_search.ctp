<div class="logs form">
<?php echo $this->Form->create('Log');?>
	<fieldset>
		<legend><?php echo __('Search Log'); ?></legend>
	<?php
		echo $this->Form->input('email', array( 'label' => 'Email'));
		if ($orgRestriction == false) {
			echo $this->Form->input('org', array( 'label' => 'Org'));
		}
		echo $this->Form->input('action', array('between' => $this->Html->div('forminfo', '', array('id' => 'LogActionDiv'))));
		echo $this->Form->input('title', array( 'label' => 'Title'));
		echo $this->Form->input('change', array( 'label' => 'Change'));
	?>
	</fieldset>
<?php echo $this->Form->end(__('Search', true));?>
</div>
<div class="actions">
	<ul>
        <?php echo $this->element('actions_menu'); ?>
	</ul>
</div>
<script type="text/javascript">
var formInfoValues = new Array();
<?php
foreach ($actionDefinitions as $action => $def) {
	$info = isset($def['formdesc']) ? $def['formdesc'] : $def['desc'];
	echo "formInfoValues['$action'] = \"$info\";\n";
}
$this->Js->get('#LogAction')->event('change', 'showFormInfo("#LogAction")');
?>
formInfoValues['ALL'] = '';

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
$('#LogActionDiv').hide();

</script>
<?php echo $this->Js->writeBuffer();