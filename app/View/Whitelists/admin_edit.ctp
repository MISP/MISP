<div class="whitelist form">
<?php echo $this->Form->create('Whitelist');?>
	<fieldset>
		<legend><?php echo __('Edit Signature Whitelist'); ?></legend>
	<?php
		echo $this->Form->input('id');
		echo $this->Form->input('name');
	?>
	</fieldset>
<?php echo $this->Form->end(__('Submit'));?>
</div>
<div class="actions">
	<ul>
		<li><?php echo $this->Form->postLink(__('Delete Whitelist'), array('admin' => true, 'action' => 'delete', $this->Form->value('Whitelist.id')), null, __('Are you sure you want to delete # %s?', $this->Form->value('Whitelist.id')));?></li>
		<li>&nbsp;</li>
		<?php echo $this->element('actions_menu');?>
	</ul>
</div>