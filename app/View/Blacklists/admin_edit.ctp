<div class="whitelist form">
<?php echo $this->Form->create('Blacklist');?>
	<fieldset>
		<legend><?php echo __('Edit Import Blacklist'); ?></legend>
	<?php
		echo $this->Form->input('id');
		echo $this->Form->input('name');
	?>
	</fieldset>
<?php echo $this->Form->end(__('Submit'));?>
</div>
<div class="actions">
	<ul>
		<li><?php echo $this->Form->postLink(__('Delete Blacklist'), array('admin' => true, 'action' => 'delete', $this->Form->value('Blacklist.id')), null, __('Are you sure you want to delete # %s?', $this->Form->value('Blacklist.id')));?></li>
	</ul>
</div>