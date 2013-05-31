<div class="logs form">
<?php echo $this->Form->create('Log', array('novalidate'=>true));?>
	<fieldset>
		<legend><?php echo __('Search Log'); ?></legend>
	<?php
		echo $this->Form->input('email', array( 'label' => 'Email'));
		if ($orgRestriction == false) {
			echo $this->Form->input('org', array( 'label' => 'Organisation'));
		}
		echo $this->Form->input('action');
		echo $this->Form->input('title');
		echo $this->Form->input('change');
	?>
	</fieldset>
<?php echo $this->Form->button(__('Submit'), array('class' => 'btn btn-primary'));
echo $this->Form->end();?>
</div>
<div class="actions">
	<ul>
		<li><?php echo $this->Html->link(__('List Logs', true), array('controller' => 'logs', 'action' => 'index', 'admin' => true)); ?> </li>
		<li><?php echo $this->Html->link(__('Search Logs', true), array('controller' => 'logs', 'action' => 'admin_search', 'admin' => true)); ?> </li>
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