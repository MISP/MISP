<div class="signatures form">
<?php echo $this->Form->create('Signature');?>
	<fieldset>
		<legend><?php __('Edit Signature'); ?></legend>
	<?php
		echo $this->Form->input('id');
		echo $this->Form->hidden('event_id');
		echo $this->Form->input('type');
		echo $this->Form->input('value');
	?>
	</fieldset>
<?php echo $this->Form->end(__('Submit', true));?>
</div>
<div class="actions">
	<h3><?php __('Actions'); ?></h3>
	<ul>

		<li><?php echo $this->Html->link(__('Delete', true), array('action' => 'delete', $this->Form->value('Signature.id')), null, sprintf(__('Are you sure you want to delete # %s?', true), $this->Form->value('Signature.id'))); ?></li>
		<li>&nbsp;</li>
        <?php echo $this->element('actions_menu'); ?>
	</ul>
</div>
