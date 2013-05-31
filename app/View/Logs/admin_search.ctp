<div class="logs form">
<?php echo $this->Form->create('Log');?>
	<fieldset>
		<legend>Search Logs</legend>
	<?php
		echo $this->Form->input('email', array( 'label' => 'Email'));
		if ($orgRestriction == false) {
			echo $this->Form->input('org', array( 'label' => 'Org'));
		}
		echo $this->Form->input('action', array(
				'between' => $this->Html->div('forminfo', '', array('id' => 'LogActionDiv')),
				'div' => 'input clear'));
		echo $this->Form->input('title', array(
				'label' => 'Title',
				'div' => 'input clear'));
		echo $this->Form->input('change', array('label' => 'Change'));
	?>
	</fieldset>
<?php
echo $this->Form->button('Search', array('class' => 'btn btn-primary'));
echo $this->Form->end();
?>
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
<?php echo $this->Js->writeBuffer(); ?>
<div class="actions">
	<ul class="nav nav-list">
		<li ><?php echo $this->Html->link('List Logs', array('admin' => true, 'action' => 'index'));?></li>
		<li class="active"><?php echo $this->Html->link('Search Logs', array('admin' => true, 'action' => 'search'));?></li>
	</ul>
</div>