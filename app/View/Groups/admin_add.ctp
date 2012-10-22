<div class="groups form">
<?php echo $this->Form->create('Group');?>
	<fieldset>
		<legend><?php echo __('Admin Add Group'); ?></legend>
	<?php
		echo $this->Form->input('name');
		echo $this->Form->input('perm_add');
		echo $this->Form->input('perm_modify');
		echo $this->Form->input('perm_publish');
		echo $this->Form->input('perm_full');
	?>
	</fieldset>
<?php echo $this->Form->end(__('Submit'));?>
</div>
<div class="actions">
	<ul>
		<?php echo $this->element('actions_menu'); ?>
	</ul>
</div>
