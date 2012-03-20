<div class="signatures form">
<?php echo $this->Form->create('Signature');?>
	<fieldset>
		<legend><?php echo __('Edit Signature'); ?></legend>
	<?php
		echo $this->Form->input('id');
		echo $this->Form->input('type');
		echo $this->Form->input('value');
		echo $this->Form->input('to_ids');
	?>
	</fieldset>
<?php echo $this->Form->end(__('Submit'));?>
</div>
<div class="actions">
	<ul>
	    <li><?php echo $this->Form->postLink(__('Delete'), array('action' => 'delete', $this->Form->value('Signature.id')), null, __('Are you sure you want to delete # %s?', $this->Form->value('Signature.id'))); ?></li>
	    <li>&nbsp;</li>
		<?php echo $this->element('actions_menu'); ?>
	</ul>
</div>

