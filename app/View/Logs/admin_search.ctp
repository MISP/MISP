<div class="logs form">
<?php echo $this->Form->create('Log');?>
	<fieldset>
		<legend><?php echo __('Search Log'); ?></legend>
	<?php
		echo $this->Form->input('keyword_email', array( 'label' => 'Email'));
		echo $this->Form->input('keyword_org', array( 'label' => 'Org'));
	echo $this->Form->input('keyword_action', array( 'label' => 'Action'));
		echo $this->Form->input('keyword_title', array( 'label' => 'Title'));
		echo $this->Form->input('keyword_change', array( 'label' => 'Change'));
		//echo $this->Form->input('type', array('between' => $this->Html->div('forminfo', '', array('id'=> 'LogTypeDiv'))));
		//echo $this->Form->input('category', array('between' => $this->Html->div('forminfo', '', array('id'=> 'LogCategoryDiv'))));
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
/*
	foreach ($type_definitions as $type => $def) {
		$info = isset($def['formdesc']) ? $def['formdesc'] : $def['desc'];
		echo "formInfoValues['$type'] = \"$info\";\n";
	}
	
	foreach ($category_definitions as $category => $def) {
		$info = isset($def['formdesc']) ? $def['formdesc'] : $def['desc'];
		echo "formInfoValues['$category'] = \"$info\";\n";
	}
	$this->Js->get('#LogType')->event('change', 'showFormInfo("#LogType")');
	$this->Js->get('#LogCategory')->event('change', 'showFormInfo("#LogCategory")');
*/
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
//$('#LogTypeDiv').hide();
//$('#LogCategoryDiv').hide();

</script>
<?php echo $this->Js->writeBuffer(); // Write cached scripts ?>
