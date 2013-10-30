<div class="whitelist form">
<?php echo $this->Form->create('Whitelist');?>
	<fieldset>
		<legend>Edit Signature Whitelist</legend>
	<?php
		echo $this->Form->input('id');
		echo $this->Form->input('name', array(
			'class' => 'input-xxlarge'
		));
	?>
	</fieldset>
<?php echo $this->Form->end(__('Submit'));?>
</div>
<?php 
	echo $this->element('side_menu', array('menuList' => 'whitelist', 'menuItem' => 'edit', 'id' => $this->Form->value('Whitelist.id')));
?>