<div class="groups form">
<?php echo $this->Form->create('Group');?>
	<fieldset>
		<legend><?php echo __('Admin Edit Role'); ?></legend>
	<?php
		echo $this->Form->input('name');?>
	<fieldset>
		<legend><?php echo __('Permission'); ?></legend>
		<?php
		echo $this->Form->input('perm_add', array('label' => 'add'));
		echo $this->Form->input('perm_modify', array('label' => 'modify'));
		echo $this->Form->input('perm_publish', array('label' => 'publish'));
		echo $this->Form->input('perm_full', array('label' => 'full'));
	?>
	</fieldset>
	</fieldset>
<?php echo $this->Form->end(__('Submit'));?>
</div>
<div class="actions">
	<ul>
		<?php echo $this->element('actions_menu'); ?>
	</ul>
</div>
