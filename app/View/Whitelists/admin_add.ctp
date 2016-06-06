<div class="whitelist form">
<?php echo $this->Form->create('Whitelist');?>
	<fieldset>
		<legend>Add Signature Whitelist</legend>
	<?php
		echo $this->Form->input('name', array(
			'class' => 'input-xxlarge'
		));

	?>
	</fieldset>
<?php
echo $this->Form->button('Add', array('class' => 'btn btn-primary'));
echo $this->Form->end();
?>
</div>
<?php
	echo $this->element('side_menu', array('menuList' => 'whitelist', 'menuItem' => 'add'));
?>
